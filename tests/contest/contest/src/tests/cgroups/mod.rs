use std::fs;
use std::path::Component::RootDir;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use oci_spec::runtime::{LinuxBuilder, LinuxResources, Spec, SpecBuilder};
use test_framework::{TestResult, test_result};

use crate::utils::test_outside_container;
use crate::utils::test_utils::{CGROUP_ROOT, check_container_created};
pub mod cpu;
pub mod devices;
pub mod hugetlb;
pub mod memory;
pub mod pids;
pub mod relative;

pub fn cleanup_v2() -> Result<()> {
    remove_test_cgroups(Path::new("/sys/fs/cgroup/runtime-test"))?;

    // A relative cgroupsPath may be placed relative to the cgroup of the runtime
    // or its parent (runc does the latter), which is inherited from this process
    if let Ok(self_cgroup) = get_process_cgroup_path(std::process::id() as i32) {
        for base in self_cgroup.ancestors().take(2) {
            if base.starts_with(CGROUP_ROOT) && base != Path::new(CGROUP_ROOT) {
                remove_test_cgroups(&base.join("runtime-test"))?;
            }
        }
    }

    Ok(())
}

fn remove_test_cgroups(runtime_test: &Path) -> Result<()> {
    if runtime_test.exists() {
        let _: Result<Vec<_>, _> = fs::read_dir(runtime_test)
            .with_context(|| format!("failed to read {runtime_test:?}"))?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|e| e.is_dir())
            .map(fs::remove_dir)
            .collect();

        fs::remove_dir(runtime_test)
            .with_context(|| format!("failed to delete {runtime_test:?}"))?;
    }

    Ok(())
}

pub fn attach_controller(cgroup_root: &Path, cgroup_path: &Path, controller: &str) -> Result<()> {
    let mut current_path = cgroup_root.to_path_buf();

    let mut components = cgroup_path
        .components()
        .filter(|c| c.ne(&RootDir))
        .peekable();

    write_controller(&current_path, controller)?;
    while let Some(component) = components.next() {
        current_path.push(component);
        if components.peek().is_some() {
            write_controller(&current_path, controller)?;
        }
    }

    Ok(())
}

fn write_controller(cgroup_path: &Path, controller: &str) -> Result<()> {
    let controller_file = cgroup_path.join("cgroup.subtree_control");
    fs::write(controller_file, format!("+{controller}"))
        .with_context(|| format!("failed to attach {controller} controller to {cgroup_path:?}"))
}

/// Returns the absolute path of the cgroup v2 directory which the given
/// process belongs to, resolved from /proc/<pid>/cgroup.
///
/// A relative cgroupsPath is interpreted relative to a runtime-determined
/// location, so tests must not compute the actual path by themselves.
pub fn get_process_cgroup_path(pid: i32) -> Result<PathBuf> {
    let proc_cgroup = format!("/proc/{pid}/cgroup");
    let content = fs::read_to_string(&proc_cgroup)
        .with_context(|| format!("failed to read {proc_cgroup}"))?;
    let Some(cgroup_path) = content.lines().find_map(|line| line.strip_prefix("0::")) else {
        bail!("no cgroup v2 entry found in {proc_cgroup}: {content:?}");
    };
    Ok(Path::new(CGROUP_ROOT).join(cgroup_path.trim().trim_start_matches('/')))
}

/// Reads an interface file in the given cgroup directory and returns its trimmed content
pub fn read_cgroup_file(cgroup_path: &Path, cgroup_file: &str) -> Result<String> {
    let path = cgroup_path.join(cgroup_file);
    let content = fs::read_to_string(&path).with_context(|| format!("failed to read {path:?}"))?;
    Ok(content.trim().to_owned())
}

/// Creates a spec placing the container in the given cgroupsPath with the given resources
pub fn create_cgroup_spec(cgroups_path: &Path, resources: LinuxResources) -> Result<Spec> {
    SpecBuilder::default()
        .linux(
            LinuxBuilder::default()
                .cgroups_path(cgroups_path)
                .resources(resources)
                .build()
                .context("failed to build linux spec")?,
        )
        .build()
        .context("failed to build spec")
}

/// Creates a container in the given cgroupsPath with the given resources, and
/// calls `check` with the actual cgroup directory of the container.
///
/// For an absolute cgroupsPath the directory must be `<cgroup root>/<cgroupsPath>`.
/// For a relative one it must end with cgroupsPath, as the base location is
/// determined by the runtime.
pub fn test_cgroup_resources(
    cgroups_path: &Path,
    resources: LinuxResources,
    check: &dyn Fn(&Path) -> Result<()>,
) -> TestResult {
    let spec = test_result!(create_cgroup_spec(cgroups_path, resources));
    test_outside_container(&spec, &|data| {
        test_result!(check_container_created(&data));
        let Some(pid) = data.state.as_ref().and_then(|s| s.pid) else {
            return TestResult::Failed(anyhow!("container pid is not available"));
        };
        let actual_path = test_result!(get_process_cgroup_path(pid));

        let stripped = cgroups_path.strip_prefix("/").unwrap_or(cgroups_path);
        let placed_correctly = if cgroups_path.is_absolute() {
            actual_path == Path::new(CGROUP_ROOT).join(stripped)
        } else {
            actual_path.ends_with(stripped)
        };
        if !placed_correctly {
            return TestResult::Failed(anyhow!(
                "container is placed in {actual_path:?}, which does not match cgroupsPath {cgroups_path:?}"
            ));
        }

        test_result!(check(&actual_path));
        TestResult::Passed
    })
}
