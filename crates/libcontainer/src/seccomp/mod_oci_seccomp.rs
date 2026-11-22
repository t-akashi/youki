use std::os::fd::IntoRawFd;
use std::os::unix::io;

use oci_seccomp::instruction::Arch;
pub use oci_seccomp::seccomp::SeccompError;
use oci_seccomp::seccomp::{Seccomp, SeccompProgramPlan};
use oci_spec::runtime::{LinuxSeccomp, LinuxSeccompAction};

type Result<T> = std::result::Result<T, SeccompError>;

#[tracing::instrument(level = "trace", skip(seccomp))]
pub fn initialize_seccomp(seccomp: &LinuxSeccomp) -> Result<Option<io::RawFd>> {
    let plan = SeccompProgramPlan::try_from(seccomp.clone())?;
    if plan.arc != Arch::native()? {
        return Err(SeccompError::Unsupported(
            "profile does not include the host ABI".into(),
        ));
    }
    let mut filter = Seccomp::new();
    filter.set_flags(plan.flags.clone());
    filter.filters = Vec::try_from(plan)?;
    // libcontainer sets no_new_privs at the point required by the OCI spec.
    // Only a filter installed with NEW_LISTENER returns a descriptor.
    Ok(filter.apply()?.map(IntoRawFd::into_raw_fd))
}

pub fn is_notify(seccomp: &LinuxSeccomp) -> bool {
    seccomp
        .syscalls()
        .iter()
        .flatten()
        .any(|syscall| syscall.action() == LinuxSeccompAction::ScmpActNotify)
}
