//! Tests for resources removed by the delete operation, ported from
//! delete_resources and delete_only_create_resources of runtime-tools.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use oci_spec::runtime::{
    LinuxBuilder, LinuxPidsBuilder, LinuxResourcesBuilder, ProcessBuilder, Spec, SpecBuilder,
};
use test_framework::{ConditionalTest, TestGroup, TestResult, test_result};

use crate::tests::cgroups::get_process_cgroup_path;
use crate::tests::lifecycle::ContainerLifecycle;
use crate::utils::test_utils::CGROUP_ROOT;
use crate::utils::{get_container_pid, is_cgroup_v2};

const STATE_TIMEOUT: Duration = Duration::from_secs(10);

fn create_spec(cgroups_path: &Path) -> Result<Spec> {
    SpecBuilder::default()
        .process(
            ProcessBuilder::default()
                .args(vec!["true".to_string()])
                .build()
                .context("failed to build process spec")?,
        )
        .linux(
            LinuxBuilder::default()
                .cgroups_path(cgroups_path)
                .resources(
                    LinuxResourcesBuilder::default()
                        .pids(
                            LinuxPidsBuilder::default()
                                .limit(1000)
                                .build()
                                .context("failed to build pids spec")?,
                        )
                        .build()
                        .context("failed to build resources spec")?,
                )
                .build()
                .context("failed to build linux spec")?,
        )
        .build()
        .context("failed to build spec")
}

fn into_result(result: TestResult, action: &str) -> Result<()> {
    match result {
        TestResult::Failed(err) => Err(err.context(format!("failed to {action} container"))),
        _ => Ok(()),
    }
}

/// Runs the container through create, start and delete.
/// `post_create` is called with the pid of the container process after create.
fn run_lifecycle(
    container: &ContainerLifecycle,
    spec: Spec,
    post_create: &dyn Fn(i32) -> Result<()>,
) -> Result<()> {
    into_result(container.create_with_spec(spec), "create")?;
    let pid = get_container_pid(container.get_id(), container.get_project_path())?;
    post_create(pid)?;
    into_result(container.start(), "start")?;
    into_result(
        container.wait_for_state("stopped", STATE_TIMEOUT),
        "wait for",
    )?;
    into_result(container.delete(), "delete")
}

fn cleanup(container: &ContainerLifecycle) {
    let _ = container.kill();
    let _ = container.delete();
}

/// Deleting a container MUST delete the resources that were created during
/// the create step.
fn delete_resources_test() -> TestResult {
    let cgroups_path = PathBuf::from("/runtime-test/delete_resources");
    let expected_cgroup = Path::new(CGROUP_ROOT).join("runtime-test/delete_resources");
    let container = ContainerLifecycle::new();
    let spec = test_result!(create_spec(&cgroups_path));

    let result = run_lifecycle(&container, spec, &|pid| {
        let cgroup = get_process_cgroup_path(pid)?;
        if cgroup != expected_cgroup {
            bail!("container is placed in {cgroup:?}, expected {expected_cgroup:?}");
        }
        Ok(())
    });
    if let Err(err) = result {
        cleanup(&container);
        return TestResult::Failed(err);
    }

    if expected_cgroup.exists() {
        return TestResult::Failed(anyhow!(
            "cgroup {expected_cgroup:?} created by create still exists after delete"
        ));
    }
    TestResult::Passed
}

/// Resources associated with the container, but not created by this
/// container, MUST NOT be deleted.
fn delete_only_create_resources_test() -> TestResult {
    let cgroups_path = PathBuf::from("/runtime-test/delete_only_create_resources");
    // a cgroup created by the test, not by the runtime
    let preexisting_cgroup =
        Path::new(CGROUP_ROOT).join("runtime-test/delete_only_create_resources_preexisting");
    test_result!(
        fs::create_dir_all(&preexisting_cgroup)
            .with_context(|| format!("failed to create {preexisting_cgroup:?}"))
    );

    let container = ContainerLifecycle::new();
    let spec = test_result!(create_spec(&cgroups_path));
    let result = run_lifecycle(&container, spec, &|pid| {
        // move the container process into the preexisting cgroup
        let procs = preexisting_cgroup.join("cgroup.procs");
        fs::write(&procs, pid.to_string())
            .with_context(|| format!("failed to move pid {pid} into {procs:?}"))
    });
    if let Err(err) = result {
        cleanup(&container);
        let _ = fs::remove_dir(&preexisting_cgroup);
        return TestResult::Failed(err);
    }

    let exists = preexisting_cgroup.exists();
    let _ = fs::remove_dir(&preexisting_cgroup);
    if !exists {
        return TestResult::Failed(anyhow!(
            "cgroup {preexisting_cgroup:?} not created by the container was deleted"
        ));
    }
    TestResult::Passed
}

pub fn get_delete_resources_tests() -> TestGroup {
    let mut tg = TestGroup::new("delete_resources");
    tg.add(vec![
        Box::new(ConditionalTest::new(
            "delete_resources",
            Box::new(is_cgroup_v2),
            Box::new(delete_resources_test),
        )),
        Box::new(ConditionalTest::new(
            "delete_only_create_resources",
            Box::new(is_cgroup_v2),
            Box::new(delete_only_create_resources_test),
        )),
    ]);
    tg
}
