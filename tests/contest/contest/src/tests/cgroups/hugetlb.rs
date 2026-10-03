//! Tests for hugetlb limits on cgroup v2, ported from
//! linux_cgroups_hugetlb and linux_cgroups_relative_hugetlb of runtime-tools.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use libcgroups::v2::controller_type::ControllerType;
use oci_spec::runtime::{LinuxHugepageLimitBuilder, LinuxResourcesBuilder};
use test_framework::{ConditionalTest, TestGroup, TestResult, test_result};

use super::{read_cgroup_file, test_cgroup_resources};
use crate::tests::tlb::get_tlb_sizes;
use crate::utils::is_cgroup_v2_with_controller;

// The amount does not matter as long as it is accepted. Use 2GiB as in runtime-tools.
const LIMIT: i64 = 2 * (1 << 30);

/// Tests that a hugetlb limit is written to hugetlb.<size>.max for each
/// supported page size
fn test_hugetlb_limit(cgroups_path: &Path) -> TestResult {
    let page_sizes = get_tlb_sizes();
    let limits = test_result!(
        page_sizes
            .iter()
            .map(|size| {
                LinuxHugepageLimitBuilder::default()
                    .page_size(size)
                    .limit(LIMIT)
                    .build()
                    .context("failed to build hugepage limit")
            })
            .collect::<Result<Vec<_>>>()
    );
    let resources = test_result!(
        LinuxResourcesBuilder::default()
            .hugepage_limits(limits)
            .build()
            .context("failed to build resources spec")
    );

    test_cgroup_resources(cgroups_path, resources, &|path| {
        for size in &page_sizes {
            let cgroup_file = format!("hugetlb.{size}.max");
            let actual = read_cgroup_file(path, &cgroup_file)?;
            if actual != LIMIT.to_string() {
                bail!("unexpected {cgroup_file}: expected {LIMIT}, got {actual}");
            }
        }
        Ok(())
    })
}

fn can_run() -> bool {
    is_cgroup_v2_with_controller(ControllerType::HugeTlb)
        && Path::new("/sys/kernel/mm/hugepages").is_dir()
        && !get_tlb_sizes().is_empty()
}

pub fn get_test_group() -> TestGroup {
    let mut test_group = TestGroup::new("cgroup_v2_hugetlb");

    test_group.add(vec![
        Box::new(ConditionalTest::new(
            "test_hugetlb_limit_absolute",
            Box::new(can_run),
            Box::new(|| test_hugetlb_limit(Path::new("/runtime-test/test_hugetlb_limit_absolute"))),
        )),
        Box::new(ConditionalTest::new(
            "test_hugetlb_limit_relative",
            Box::new(can_run),
            Box::new(|| {
                test_hugetlb_limit(&PathBuf::from("runtime-test/test_hugetlb_limit_relative"))
            }),
        )),
    ]);

    test_group
}
