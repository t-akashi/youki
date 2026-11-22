use seccomp::seccomp::{SeccompError, SeccompProgramPlan};

// This is a Podman source profile, not the OCI section that Podman writes
// after resolving includes/excludes against the container's capabilities.
// In particular, it still contains both ALLOW and ERRNO rules for bpf.
// Refuse the conflict instead of depending on the order of those rules.
#[test]
fn unresolved_podman_profile_is_rejected() {
    let spec: oci_spec::runtime::LinuxSeccomp =
        serde_json::from_str(include_str!("fixtures/podman.json")).unwrap();
    assert!(matches!(SeccompProgramPlan::try_from(spec),
        Err(SeccompError::Unsupported(message)) if message.contains("conflicting actions")));
}
