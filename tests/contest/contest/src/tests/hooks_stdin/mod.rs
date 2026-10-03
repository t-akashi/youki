use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use oci_spec::runtime::{Hook, HookBuilder, HooksBuilder, ProcessBuilder, Spec, SpecBuilder};
use test_framework::{Test, TestGroup, TestResult, test_result};

use crate::utils::{
    CreateOptions, LifecycleStatus, State, WaitTarget, create_container, delete_container,
    generate_uuid, get_container_pid, is_runtime_runc, kill_container, prepare_bundle, set_config,
    start_container, wait_for_state,
};

const ANNOTATION_KEY: &str = "org.opencontainers.runtime-tools";
const ANNOTATION_VALUE: &str = "hook stdin test";
const HOOKS: [&str; 3] = ["prestart", "poststart", "poststop"];

const STATE_WAIT_TIMEOUT: Duration = Duration::from_secs(10);
const STATE_POLL_INTERVAL: Duration = Duration::from_millis(100);

// A hook which saves the state passed over stdin to the given file
fn save_stdin_hook(output_file: &Path) -> Hook {
    HookBuilder::default()
        .path("/bin/sh")
        .args(vec![
            "sh".to_string(),
            "-c".to_string(),
            format!("cat > {}", output_file.display()),
        ])
        .build()
        .expect("could not build hook")
}

fn create_spec(output_dir: &Path) -> Result<Spec> {
    let output_file = |hook: &str| output_dir.join(hook);

    SpecBuilder::default()
        .process(
            ProcessBuilder::default()
                .args(vec!["true".to_string()])
                .build()
                .context("failed to build process spec")?,
        )
        .annotations(HashMap::from([(
            ANNOTATION_KEY.to_string(),
            ANNOTATION_VALUE.to_string(),
        )]))
        .hooks(
            HooksBuilder::default()
                .prestart(vec![save_stdin_hook(&output_file("prestart"))])
                .poststart(vec![save_stdin_hook(&output_file("poststart"))])
                .poststop(vec![save_stdin_hook(&output_file("poststop"))])
                .build()
                .context("failed to build hooks")?,
        )
        .build()
        .context("failed to build spec")
}

fn wait_for(id: &str, dir: &Path, target: WaitTarget) -> Result<()> {
    wait_for_state(id, dir, target, STATE_WAIT_TIMEOUT, STATE_POLL_INTERVAL)
}

/// Runs the container through create, start and delete, and returns the pid
/// of the container process.
fn run_lifecycle(id: &str, dir: &Path) -> Result<i32> {
    // Do not wait for the output of create, as the container process inherits
    // and keeps its stdout/stderr open until it exits.
    let status = create_container(id, dir, &CreateOptions::default())?.wait()?;
    if !status.success() {
        bail!("failed to create container: {status}");
    }
    wait_for(id, dir, WaitTarget::Status(LifecycleStatus::Created))?;
    let pid = get_container_pid(id, dir)?;

    let output = start_container(id, dir)?.wait_with_output()?;
    if !output.status.success() {
        bail!(
            "failed to start container: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    wait_for(id, dir, WaitTarget::Status(LifecycleStatus::Stopped))?;

    let output = delete_container(id, dir)?.wait_with_output()?;
    if !output.status.success() {
        bail!(
            "failed to delete container: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    wait_for(id, dir, WaitTarget::Deleted)?;
    Ok(pid)
}

fn check_hook_state(
    output_dir: &Path,
    hook: &str,
    id: &str,
    bundle: &Path,
    pid: i32,
) -> Result<Vec<String>> {
    let path = output_dir.join(hook);
    let data = fs::read_to_string(&path)
        .with_context(|| format!("failed to read the stdin of {hook} hook saved in {path:?}"))?;
    let state: State = serde_json::from_str(&data)
        .with_context(|| format!("failed to parse the stdin of {hook} hook: {data}"))?;

    let mut errors = vec![];
    if state.id != id {
        errors.push(format!(
            "wrong container ID {:?}, expected {id:?}",
            state.id
        ));
    }
    if state.bundle.canonicalize().ok().as_deref() != Some(bundle) {
        errors.push(format!(
            "wrong bundle {:?}, expected {bundle:?}",
            state.bundle
        ));
    }
    if hook != "poststop" && state.pid != Some(pid) {
        errors.push(format!("wrong pid {:?}, expected {pid}", state.pid));
    }
    let expected_annotations =
        HashMap::from([(ANNOTATION_KEY.to_string(), ANNOTATION_VALUE.to_string())]);
    if state.annotations.as_ref() != Some(&expected_annotations) {
        errors.push(format!(
            "wrong annotations {:?}, expected {expected_annotations:?}",
            state.annotations
        ));
    }
    // The original runtime-tools test expects "created" for prestart, as it
    // was written when prestart hooks were called by the start operation.
    // The current runtime-spec calls them as part of the create operation,
    // so the container is still "creating" at that time.
    let expected_status = match hook {
        "prestart" => Some("creating"),
        // runc passes "created" to poststart hooks
        "poststart" if is_runtime_runc() => Some("created"),
        "poststart" => Some("running"),
        _ => None,
    };
    match expected_status {
        Some(expected) if state.status != expected => errors.push(format!(
            "wrong status {:?}, expected {expected:?}",
            state.status
        )),
        None if state.status.is_empty() => errors.push("status should not be empty".to_string()),
        _ => {}
    }

    Ok(errors
        .into_iter()
        .map(|err| format!("{hook} hook: {err}"))
        .collect())
}

/// The state of the container MUST be passed to hooks over stdin.
fn hooks_stdin_test() -> TestResult {
    let id = generate_uuid().to_string();
    let project = test_result!(prepare_bundle());
    let output_dir = project.path();
    let bundle = test_result!(
        output_dir
            .join("bundle")
            .canonicalize()
            .context("failed to canonicalize bundle path")
    );
    let spec = test_result!(create_spec(output_dir));
    test_result!(set_config(&project, &spec));

    let pid = match run_lifecycle(&id, output_dir) {
        Ok(pid) => pid,
        Err(err) => {
            let _ = kill_container(&id, output_dir).map(|mut c| c.wait());
            let _ = delete_container(&id, output_dir).map(|mut c| c.wait());
            return TestResult::Failed(err);
        }
    };

    let mut errors = vec![];
    for hook in HOOKS {
        errors.extend(test_result!(check_hook_state(
            output_dir, hook, &id, &bundle, pid
        )));
    }
    if errors.is_empty() {
        TestResult::Passed
    } else {
        TestResult::Failed(anyhow!(
            "the state of the container MUST be passed to hooks over stdin:\n{}",
            errors.join("\n")
        ))
    }
}

pub fn get_hooks_stdin_tests() -> TestGroup {
    let mut tg = TestGroup::new("hooks_stdin");
    tg.add(vec![Box::new(Test::new(
        "hooks_stdin",
        Box::new(hooks_stdin_test),
    ))]);
    tg
}
