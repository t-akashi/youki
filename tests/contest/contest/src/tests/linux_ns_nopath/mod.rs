use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, anyhow};
use oci_spec::runtime::{
    LinuxBuilder, LinuxIdMappingBuilder, LinuxNamespaceBuilder, LinuxNamespaceType, Spec,
    SpecBuilder,
};
use test_framework::{Test, TestGroup, TestResult, test_result};

use crate::utils::test_outside_container;
use crate::utils::test_utils::check_container_created;

// Namespaces under /proc/<pid>/ns to be compared, and their types in the spec
const NAMESPACES: [(&str, LinuxNamespaceType); 7] = [
    ("cgroup", LinuxNamespaceType::Cgroup),
    ("ipc", LinuxNamespaceType::Ipc),
    ("mnt", LinuxNamespaceType::Mount),
    ("net", LinuxNamespaceType::Network),
    ("pid", LinuxNamespaceType::Pid),
    ("user", LinuxNamespaceType::User),
    ("uts", LinuxNamespaceType::Uts),
];

fn create_spec() -> Result<Spec> {
    let namespaces = NAMESPACES
        .iter()
        .map(|(_, typ)| {
            LinuxNamespaceBuilder::default()
                .typ(*typ)
                .build()
                .context("failed to build namespace")
        })
        .collect::<Result<Vec<_>>>()?;

    // a user namespace requires uid/gid mappings to create a container
    let id_mapping = LinuxIdMappingBuilder::default()
        .host_id(1000u32)
        .container_id(0u32)
        .size(1000u32)
        .build()
        .context("failed to build id mapping")?;

    SpecBuilder::default()
        .linux(
            LinuxBuilder::default()
                .namespaces(namespaces)
                .uid_mappings(vec![id_mapping])
                .gid_mappings(vec![id_mapping])
                .build()
                .context("failed to build linux spec")?,
        )
        .build()
        .context("failed to build spec")
}

fn read_ns_link(pid: &str, ns: &str) -> Result<PathBuf> {
    let path = format!("/proc/{pid}/ns/{ns}");
    fs::read_link(&path).with_context(|| format!("failed to read namespace link {path}"))
}

/// A new namespace MUST be created for each namespace type in the spec
/// which has no path specified.
fn ns_nopath_test() -> TestResult {
    let host_namespaces = test_result!(
        NAMESPACES
            .iter()
            .map(|(ns, _)| read_ns_link("self", ns))
            .collect::<Result<Vec<_>>>()
    );
    let spec = test_result!(create_spec());

    test_outside_container(&spec, &|data| {
        test_result!(check_container_created(&data));
        let pid = match data.state.as_ref().and_then(|s| s.pid) {
            Some(pid) => pid.to_string(),
            None => return TestResult::Failed(anyhow!("container pid is not available")),
        };

        let mut errors = vec![];
        for ((ns, _), host_ns) in NAMESPACES.iter().zip(&host_namespaces) {
            let container_ns = test_result!(read_ns_link(&pid, ns));
            if &container_ns == host_ns {
                errors.push(format!("{ns} ({})", container_ns.display()));
            }
        }
        if errors.is_empty() {
            TestResult::Passed
        } else {
            TestResult::Failed(anyhow!(
                "container shares namespaces with the host although no path was specified: {}",
                errors.join(", ")
            ))
        }
    })
}

pub fn get_ns_nopath_tests() -> TestGroup {
    let mut tg = TestGroup::new("ns_nopath");
    tg.add(vec![Box::new(Test::new(
        "ns_nopath",
        Box::new(ns_nopath_test),
    ))]);
    tg
}
