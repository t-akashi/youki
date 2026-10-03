use anyhow::{Context, Result, anyhow};
use oci_spec::runtime::{
    LinuxBuilder, LinuxNamespace, LinuxNamespaceBuilder, LinuxNamespaceType, Spec, SpecBuilder,
    get_default_namespaces,
};
use test_framework::{Test, TestGroup, TestResult, test_result};

use crate::utils::test_outside_container;

// Pairs of (namespace type under test, name of a namespace of a different type in /proc/self/ns)
const CASES: [(&str, LinuxNamespaceType, &str); 7] = [
    ("cgroup", LinuxNamespaceType::Cgroup, "ipc"),
    ("ipc", LinuxNamespaceType::Ipc, "mnt"),
    ("mnt", LinuxNamespaceType::Mount, "net"),
    ("net", LinuxNamespaceType::Network, "pid"),
    ("pid", LinuxNamespaceType::Pid, "user"),
    ("user", LinuxNamespaceType::User, "uts"),
    ("uts", LinuxNamespaceType::Uts, "cgroup"),
];

fn create_spec(typ: LinuxNamespaceType, wrong_ns: &str) -> Result<Spec> {
    let wrong_ns_path = format!("/proc/self/ns/{wrong_ns}");
    let mut namespaces: Vec<LinuxNamespace> = get_default_namespaces()
        .into_iter()
        .filter(|ns| ns.typ() != typ)
        .collect();
    namespaces.push(
        LinuxNamespaceBuilder::default()
            .typ(typ)
            .path(wrong_ns_path)
            .build()
            .context("failed to build namespace")?,
    );

    SpecBuilder::default()
        .linux(
            LinuxBuilder::default()
                .namespaces(namespaces)
                .build()
                .context("failed to build linux spec")?,
        )
        .build()
        .context("failed to build spec")
}

/// The runtime MUST generate an error if the namespace path is not associated
/// with a namespace of the specified type.
fn check_ns_path_type(typ: LinuxNamespaceType, wrong_ns: &str) -> TestResult {
    let spec = test_result!(create_spec(typ, wrong_ns));
    test_outside_container(&spec, &|data| match &data.create_result {
        Ok(status) if status.success() => TestResult::Failed(anyhow!(
            "container creation unexpectedly succeeded with {wrong_ns} namespace path for {typ:?} namespace"
        )),
        Ok(_) => TestResult::Passed,
        Err(err) => TestResult::Failed(anyhow!("failed to execute create command: {err}")),
    })
}

pub fn get_ns_path_type_tests() -> TestGroup {
    let mut tg = TestGroup::new("ns_path_type");
    for (name, typ, wrong_ns) in CASES {
        tg.add(vec![Box::new(Test::new(
            name,
            Box::new(move || check_ns_path_type(typ, wrong_ns)),
        ))]);
    }
    tg
}
