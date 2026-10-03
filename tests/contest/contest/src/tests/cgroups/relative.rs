//! Tests for resources applied to a cgroup given by a relative cgroupsPath,
//! ported from linux_cgroups_relative_{pids,memory,cpus} of runtime-tools.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use libcgroups::v2::controller_type::ControllerType;
use oci_spec::runtime::{
    LinuxCpuBuilder, LinuxMemoryBuilder, LinuxPidsBuilder, LinuxResourcesBuilder,
};
use test_framework::{ConditionalTest, TestGroup, TestResult, assert_result_eq, test_result};

use super::{read_cgroup_file, test_cgroup_resources};
use crate::utils::is_cgroup_v2_with_controller;
use crate::utils::test_utils::CGROUP_ROOT;

// SPEC: "If the value is relative, the runtime MAY interpret the path relative to
// a runtime-determined location in the cgroups hierarchy". youki (cgroupfs driver)
// places it under the cgroup root, while runc places it under its own cgroup.
// The tests therefore resolve the actual cgroup from /proc/<pid>/cgroup.
fn relative_cgroups_path(name: &str) -> PathBuf {
    PathBuf::from("runtime-test").join(name)
}

/// Tests that a pids limit is applied with a relative cgroupsPath
fn test_relative_pids() -> TestResult {
    let limit: i64 = 1000;
    let resources = test_result!(
        LinuxResourcesBuilder::default()
            .pids(test_result!(
                LinuxPidsBuilder::default()
                    .limit(limit)
                    .build()
                    .context("failed to build pids spec")
            ))
            .build()
            .context("failed to build resources spec")
    );

    test_cgroup_resources(
        &relative_cgroups_path("test_relative_pids"),
        resources,
        &|path| assert_cgroup_file(path, "pids.max", &limit.to_string()),
    )
}

/// Tests that memory limit and reservation are applied with a relative cgroupsPath
fn test_relative_memory() -> TestResult {
    let limit: i64 = 50593792;
    let reservation: i64 = 25296896;
    let resources = test_result!(
        LinuxResourcesBuilder::default()
            .memory(test_result!(
                LinuxMemoryBuilder::default()
                    .limit(limit)
                    .reservation(reservation)
                    .build()
                    .context("failed to build memory spec")
            ))
            .build()
            .context("failed to build resources spec")
    );

    test_cgroup_resources(
        &relative_cgroups_path("test_relative_memory"),
        resources,
        &|path| {
            assert_cgroup_file(path, "memory.max", &limit.to_string())?;
            assert_cgroup_file(path, "memory.low", &reservation.to_string())
        },
    )
}

/// Tests that cpu quota and period are applied with a relative cgroupsPath
fn test_relative_cpu() -> TestResult {
    let quota: i64 = 50000;
    let period: u64 = 100000;
    let resources = test_result!(
        LinuxResourcesBuilder::default()
            .cpu(test_result!(
                LinuxCpuBuilder::default()
                    .quota(quota)
                    .period(period)
                    .build()
                    .context("failed to build cpu spec")
            ))
            .build()
            .context("failed to build resources spec")
    );

    test_cgroup_resources(
        &relative_cgroups_path("test_relative_cpu"),
        resources,
        &|path| assert_cgroup_file(path, "cpu.max", &format!("{quota} {period}")),
    )
}

/// Tests that cpuset cpus and mems are applied with a relative cgroupsPath
fn test_relative_cpuset() -> TestResult {
    let cpus = "0-1";
    let mems = "0";
    let resources = test_result!(
        LinuxResourcesBuilder::default()
            .cpu(test_result!(
                LinuxCpuBuilder::default()
                    .cpus(cpus)
                    .mems(mems)
                    .build()
                    .context("failed to build cpu spec")
            ))
            .build()
            .context("failed to build resources spec")
    );

    test_cgroup_resources(
        &relative_cgroups_path("test_relative_cpuset"),
        resources,
        &|path| {
            assert_cgroup_file(path, "cpuset.cpus", cpus)?;
            assert_cgroup_file(path, "cpuset.mems", mems)
        },
    )
}

fn assert_cgroup_file(cgroup_path: &Path, cgroup_file: &str, expected: &str) -> Result<()> {
    let actual = read_cgroup_file(cgroup_path, cgroup_file)?;
    assert_result_eq!(expected, actual.as_str(), "unexpected {cgroup_file}")
}

/// Parses a cpu or memory node list such as "0-3,5" of cpuset
fn parse_cpuset_list(list: &str) -> Vec<u32> {
    list.split(',')
        .filter(|s| !s.is_empty())
        .flat_map(|range| match range.split_once('-') {
            Some((start, end)) => match (start.parse::<u32>(), end.parse::<u32>()) {
                (Ok(start), Ok(end)) => (start..=end).collect(),
                _ => vec![],
            },
            None => range.parse::<u32>().into_iter().collect(),
        })
        .collect()
}

fn effective_cpuset_contains(cgroup_file: &str, ids: &[u32]) -> bool {
    match read_cgroup_file(Path::new(CGROUP_ROOT), cgroup_file) {
        Ok(list) => {
            let available = parse_cpuset_list(&list);
            ids.iter().all(|id| available.contains(id))
        }
        Err(_) => false,
    }
}

fn can_run_cpuset() -> bool {
    is_cgroup_v2_with_controller(ControllerType::CpuSet)
        && effective_cpuset_contains("cpuset.cpus.effective", &[0, 1])
        && effective_cpuset_contains("cpuset.mems.effective", &[0])
}

pub fn get_test_group() -> TestGroup {
    let mut test_group = TestGroup::new("cgroup_v2_relative");

    test_group.add(vec![
        Box::new(ConditionalTest::new(
            "test_relative_pids",
            Box::new(|| is_cgroup_v2_with_controller(ControllerType::Pids)),
            Box::new(test_relative_pids),
        )),
        Box::new(ConditionalTest::new(
            "test_relative_memory",
            Box::new(|| is_cgroup_v2_with_controller(ControllerType::Memory)),
            Box::new(test_relative_memory),
        )),
        Box::new(ConditionalTest::new(
            "test_relative_cpu",
            Box::new(|| is_cgroup_v2_with_controller(ControllerType::Cpu)),
            Box::new(test_relative_cpu),
        )),
        Box::new(ConditionalTest::new(
            "test_relative_cpuset",
            Box::new(can_run_cpuset),
            Box::new(test_relative_cpuset),
        )),
    ]);

    test_group
}

#[cfg(test)]
mod tests {
    use super::parse_cpuset_list;

    #[test]
    fn test_parse_cpuset_list() {
        assert_eq!(parse_cpuset_list("0-3,5"), vec![0, 1, 2, 3, 5]);
        assert_eq!(parse_cpuset_list("0"), vec![0]);
        assert!(parse_cpuset_list("").is_empty());
    }
}
