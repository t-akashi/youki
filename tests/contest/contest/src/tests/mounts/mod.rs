//! Test for mounts with various types, options and propagation modes,
//! ported from mounts of runtime-tools.

use std::path::PathBuf;

use anyhow::{Context, Result};
use oci_spec::runtime::{Mount, ProcessBuilder, Spec, SpecBuilder, get_default_mounts};
use test_framework::{Test, TestGroup, TestResult, test_result};

use crate::utils::test_inside_container;
use crate::utils::test_utils::CreateOptions;

// (destination, type, source, options) as in runtime-tools
const MOUNTS: [(&str, Option<&str>, &str, &[&str]); 11] = [
    ("/tmp/test-shared", Some("tmpfs"), "tmpfs", &["shared"]),
    ("/tmp/test-slave", Some("tmpfs"), "tmpfs", &["slave"]),
    ("/tmp/test-private", Some("tmpfs"), "tmpfs", &["private"]),
    ("/mnt/etc-shared", None, "/etc", &["bind", "shared"]),
    ("/mnt/etc-rshared", None, "/etc", &["rbind", "rshared"]),
    ("/mnt/etc-slave", None, "/etc", &["bind", "slave"]),
    ("/mnt/etc-rslave", None, "/etc", &["rbind", "rslave"]),
    ("/mnt/etc-private", None, "/etc", &["bind", "private"]),
    ("/mnt/etc-rprivate", None, "/etc", &["rbind", "rprivate"]),
    ("/mnt/etc-unbindable", None, "/etc", &["bind", "unbindable"]),
    (
        "/mnt/etc-runbindable",
        None,
        "/etc",
        &["rbind", "runbindable"],
    ),
];

fn create_spec() -> Result<Spec> {
    let mut mounts = get_default_mounts();
    for (destination, typ, source, options) in MOUNTS {
        let mut mount = Mount::default();
        mount
            .set_destination(PathBuf::from(destination))
            .set_typ(typ.map(String::from))
            .set_source(Some(PathBuf::from(source)))
            .set_options(Some(options.iter().map(|o| o.to_string()).collect()));
        mounts.push(mount);
    }

    SpecBuilder::default()
        .mounts(mounts)
        .process(
            ProcessBuilder::default()
                .args(vec!["runtimetest".to_string(), "mounts".to_string()])
                .build()
                .context("failed to build process spec")?,
        )
        .build()
        .context("failed to build spec")
}

/// The runtime MUST mount entries in the listed order.
/// runtimetest checks that every mount exists in order.
fn mounts_test() -> TestResult {
    let spec = test_result!(create_spec());
    test_inside_container(&spec, &CreateOptions::default(), &|_| Ok(()))
}

pub fn get_mounts_test() -> TestGroup {
    let mut tg = TestGroup::new("mounts");
    tg.add(vec![Box::new(Test::new("mounts", Box::new(mounts_test)))]);
    tg
}
