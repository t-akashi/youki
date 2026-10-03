//! Test for a container created from a default config, ported from
//! default of runtime-tools.

use anyhow::{Context, Result};
use oci_spec::runtime::{ProcessBuilder, Spec, SpecBuilder};
use test_framework::{Test, TestGroup, TestResult, test_result};

use crate::utils::test_inside_container;
use crate::utils::test_utils::CreateOptions;

fn create_spec() -> Result<Spec> {
    SpecBuilder::default()
        .process(
            ProcessBuilder::default()
                .args(vec!["runtimetest".to_string(), "default".to_string()])
                .build()
                .context("failed to build process spec")?,
        )
        .build()
        .context("failed to build spec")
}

/// A container created from a default config passes the runtimetest
/// validations, such as process, user, hostname, default filesystems,
/// symlinks and devices, mounts, masked and readonly paths.
fn default_test() -> TestResult {
    let spec = test_result!(create_spec());
    test_inside_container(&spec, &CreateOptions::default(), &|_| Ok(()))
}

pub fn get_default_test() -> TestGroup {
    let mut tg = TestGroup::new("default");
    tg.add(vec![Box::new(Test::new("default", Box::new(default_test)))]);
    tg
}
