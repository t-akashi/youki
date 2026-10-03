//! Tests for device cgroup rules (linux.resources.devices) on cgroup v2,
//! ported from linux_cgroups_devices and linux_cgroups_relative_devices
//! of runtime-tools.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use oci_spec::runtime::{
    LinuxBuilder, LinuxDevice, LinuxDeviceBuilder, LinuxDeviceCgroup, LinuxDeviceCgroupBuilder,
    LinuxDeviceType, LinuxResourcesBuilder, ProcessBuilder, Spec, SpecBuilder,
};
use test_framework::{ConditionalTest, TestGroup, TestResult, test_result};

use crate::utils::test_utils::CreateOptions;
use crate::utils::{is_cgroup_v2, is_runtime_runc, test_inside_container};

// youki enforces device rules on cgroup v2 only when built with the
// `cgroupsv2_devices` feature, which is not enabled by default (nor by
// `just youki-release` used in CI), and the runtime cannot report whether it
// is enabled. Without the feature, linux.resources.devices is silently
// ignored. So the tests are opt-in for youki: set this variable to "1" when
// the runtime under test is built with the feature.
const CGROUPSV2_DEVICES_ENV: &str = "CONTEST_CGROUPSV2_DEVICES";

// On cgroup v2, device rules are enforced by an eBPF program and cannot be read
// back from the cgroup filesystem. Instead, device nodes are created with
// linux.devices and runtimetest checks inside the container that read/write
// access to each of them is permitted or denied according to the rules.

fn device_rule(
    allow: bool,
    typ: LinuxDeviceType,
    major: Option<i64>,
    minor: Option<i64>,
    access: &str,
) -> Result<LinuxDeviceCgroup> {
    let mut builder = LinuxDeviceCgroupBuilder::default()
        .allow(allow)
        .typ(typ)
        .access(access);
    if let Some(major) = major {
        builder = builder.major(major);
    }
    if let Some(minor) = minor {
        builder = builder.minor(minor);
    }
    builder
        .build()
        .context("failed to build device cgroup rule")
}

fn device_node(path: &str, typ: LinuxDeviceType, major: i64, minor: i64) -> Result<LinuxDevice> {
    LinuxDeviceBuilder::default()
        .path(path)
        .typ(typ)
        .major(major)
        .minor(minor)
        .file_mode(0o666u32)
        .build()
        .context("failed to build device")
}

fn create_spec(cgroups_path: &Path) -> Result<Spec> {
    // Same rules as runtime-tools, preceded by "deny all"
    let rules = vec![
        device_rule(false, LinuxDeviceType::A, None, None, "rwm")?,
        device_rule(true, LinuxDeviceType::C, Some(10), Some(229), "rwm")?,
        device_rule(true, LinuxDeviceType::B, Some(8), Some(20), "rw")?,
        device_rule(true, LinuxDeviceType::B, Some(10), Some(200), "r")?,
    ];
    let devices = vec![
        device_node("/dev/cgtest_c_10_229", LinuxDeviceType::C, 10, 229)?,
        device_node("/dev/cgtest_b_8_20", LinuxDeviceType::B, 8, 20)?,
        device_node("/dev/cgtest_b_10_200", LinuxDeviceType::B, 10, 200)?,
        // not allowed by any rule. 240-254 are reserved for local/experimental
        // use, so no driver is expected; a driver like /dev/port (1:4) would
        // deny access by capability instead of by the device cgroup.
        device_node("/dev/cgtest_c_240_0", LinuxDeviceType::C, 240, 0)?,
    ];

    SpecBuilder::default()
        .process(
            ProcessBuilder::default()
                .args(vec![
                    "runtimetest".to_string(),
                    "cgroup_devices".to_string(),
                ])
                .build()
                .context("failed to build process spec")?,
        )
        .linux(
            LinuxBuilder::default()
                .cgroups_path(cgroups_path)
                .devices(devices)
                .resources(
                    LinuxResourcesBuilder::default()
                        .devices(rules)
                        .build()
                        .context("failed to build resources spec")?,
                )
                .build()
                .context("failed to build linux spec")?,
        )
        .build()
        .context("failed to build spec")
}

fn test_devices(cgroups_path: &Path) -> TestResult {
    let spec = test_result!(create_spec(cgroups_path));
    test_inside_container(&spec, &CreateOptions::default(), &|_| Ok(()))
}

fn can_run() -> bool {
    is_cgroup_v2()
        && (is_runtime_runc() || std::env::var(CGROUPSV2_DEVICES_ENV).is_ok_and(|v| v == "1"))
}

pub fn get_test_group() -> TestGroup {
    let mut test_group = TestGroup::new("cgroup_v2_devices");

    test_group.add(vec![
        Box::new(ConditionalTest::new(
            "test_devices_absolute",
            Box::new(can_run),
            Box::new(|| test_devices(Path::new("/runtime-test/test_devices_absolute"))),
        )),
        Box::new(ConditionalTest::new(
            "test_devices_relative",
            Box::new(can_run),
            Box::new(|| test_devices(&PathBuf::from("runtime-test/test_devices_relative"))),
        )),
    ]);

    test_group
}
