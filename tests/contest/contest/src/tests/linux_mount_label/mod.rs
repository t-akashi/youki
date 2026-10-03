//! Test for linux.mountLabel, ported from linux_mount_label of runtime-tools.

use std::path::Path;

use anyhow::{Context, Result};
use oci_spec::runtime::{LinuxBuilder, ProcessBuilder, Spec, SpecBuilder};
use test_framework::{ConditionalTest, TestGroup, TestResult, test_result};

use crate::utils::test_utils::CreateOptions;
use crate::utils::{is_runtime_runc, test_inside_container};

const MOUNT_LABEL: &str = "system_u:object_r:svirt_sandbox_file_t:s0:c715,c811";

fn create_spec(default_masked_paths: bool) -> Result<Spec> {
    let mut linux = LinuxBuilder::default().mount_label(MOUNT_LABEL);
    if !default_masked_paths {
        // As in runtime-tools, no masked or readonly paths are set
        linux = linux.masked_paths(vec![]).readonly_paths(vec![]);
    }

    SpecBuilder::default()
        .process(
            ProcessBuilder::default()
                .args(vec!["runtimetest".to_string(), "mount_label".to_string()])
                .build()
                .context("failed to build process spec")?,
        )
        .linux(linux.build().context("failed to build linux spec")?)
        .build()
        .context("failed to build spec")
}

/// A container with linux.mountLabel set MUST be created. When SELinux is
/// enabled, runtimetest also checks the label of the mounts.
fn mount_label_test() -> TestResult {
    let spec = test_result!(create_spec(false));
    test_inside_container(&spec, &CreateOptions::default(), &|_| Ok(()))
}

/// Same as mount_label_test, but with the default masked paths, which
/// include directories masked by tmpfs. The mount label must not make
/// masking them fail when SELinux is disabled.
fn mount_label_with_masked_paths_test() -> TestResult {
    let spec = test_result!(create_spec(true));
    test_inside_container(&spec, &CreateOptions::default(), &|_| Ok(()))
}

fn is_selinux_enabled() -> bool {
    Path::new("/sys/fs/selinux/enforce").exists()
}

// runc applies "context=" to mounts such as /dev even when SELinux is
// disabled, so the container cannot be created in that case.
fn can_run() -> bool {
    !is_runtime_runc() || is_selinux_enabled()
}

pub fn get_mount_label_test() -> TestGroup {
    let mut tg = TestGroup::new("mount_label");
    tg.add(vec![
        Box::new(ConditionalTest::new(
            "mount_label",
            Box::new(can_run),
            Box::new(mount_label_test),
        )),
        Box::new(ConditionalTest::new(
            "mount_label_with_masked_paths",
            Box::new(can_run),
            Box::new(mount_label_with_masked_paths_test),
        )),
    ]);
    tg
}
