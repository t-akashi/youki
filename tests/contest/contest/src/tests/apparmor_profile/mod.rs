//! Test for process.apparmorProfile, ported from
//! linux_process_apparmor_profile of runtime-tools.

use std::fs;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};
use oci_spec::runtime::{ProcessBuilder, Spec, SpecBuilder};
use tempfile::TempDir;
use test_framework::{ConditionalTest, TestGroup, TestResult, test_result};

use crate::utils::test_utils::CreateOptions;
use crate::utils::{has_command, test_inside_container};

const PROFILE_NAME: &str = "youki-contest-apparmor-profile";

// A permissive profile which allows runtimetest to run. Abstractions are not
// included so that it does not depend on the files installed on the host.
fn profile_content() -> String {
    format!(
        "profile {PROFILE_NAME} flags=(attach_disconnected,mediate_deleted) {{\n  \
         file,\n  capability,\n  network,\n  signal,\n  ptrace,\n  unix,\n  \
         mount,\n  umount,\n  pivot_root,\n}}\n"
    )
}

/// An AppArmor profile loaded for the test, and removed on drop
struct LoadedProfile {
    _dir: TempDir,
    path: std::path::PathBuf,
}

impl LoadedProfile {
    fn load() -> Result<Self> {
        let dir = tempfile::tempdir().context("failed to create a temporary directory")?;
        let path = dir.path().join(PROFILE_NAME);
        fs::write(&path, profile_content()).with_context(|| format!("failed to write {path:?}"))?;
        run_apparmor_parser(&["--replace", "--skip-cache"], &path)?;
        Ok(Self { _dir: dir, path })
    }
}

impl Drop for LoadedProfile {
    fn drop(&mut self) {
        let _ = run_apparmor_parser(&["--remove"], &self.path);
    }
}

fn run_apparmor_parser(args: &[&str], profile: &Path) -> Result<()> {
    let output = Command::new("apparmor_parser")
        .args(args)
        .arg(profile)
        .output()
        .context("failed to run apparmor_parser")?;
    if !output.status.success() {
        bail!(
            "apparmor_parser {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

fn create_spec() -> Result<Spec> {
    SpecBuilder::default()
        .process(
            ProcessBuilder::default()
                .args(vec![
                    "runtimetest".to_string(),
                    "apparmor_profile".to_string(),
                ])
                .apparmor_profile(PROFILE_NAME)
                .build()
                .context("failed to build process spec")?,
        )
        .build()
        .context("failed to build spec")
}

/// The runtime MUST apply process.apparmorProfile to the container process.
/// runtimetest checks the profile from /proc/self/attr.
fn apparmor_profile_test() -> TestResult {
    let _profile = test_result!(LoadedProfile::load());
    let spec = test_result!(create_spec());
    test_inside_container(&spec, &CreateOptions::default(), &|_| Ok(()))
}

fn is_apparmor_enabled() -> bool {
    fs::read_to_string("/sys/module/apparmor/parameters/enabled")
        .is_ok_and(|enabled| enabled.starts_with('Y'))
        && has_command("apparmor_parser")
}

pub fn get_apparmor_profile_test() -> TestGroup {
    let mut tg = TestGroup::new("apparmor_profile");
    tg.add(vec![Box::new(ConditionalTest::new(
        "apparmor_profile",
        Box::new(is_apparmor_enabled),
        Box::new(apparmor_profile_test),
    ))]);
    tg
}
