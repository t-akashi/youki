use oci_spec::runtime::{
    LinuxSeccomp, LinuxSeccompAction,
};
use std::os::fd::IntoRawFd;
use std::os::unix::io;

use oci_seccomp::seccomp::*;
pub use oci_seccomp::seccomp::SeccompError;

type Result<T> = std::result::Result<T, SeccompError>;

// Debug
use std::fs::OpenOptions;
use std::io::Write;
use std::mem::size_of_val;
use std::slice;
use oci_seccomp::instruction::Instruction;

fn dump_filter(path: &str, filter: &[Instruction]) -> std::io::Result<()> {
    let bytes: &[u8] = unsafe {
        slice::from_raw_parts(filter.as_ptr() as *const u8, size_of_val(filter))
    };

    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;
    f.write_all(bytes)?;
    Ok(())
}

#[tracing::instrument(level = "trace", skip(seccomp))]
pub fn initialize_seccomp(seccomp: &LinuxSeccomp) -> Result<Option<io::RawFd>> {
    let inst_data = SeccompProgramPlan::try_from(seccomp.clone())?;
    let mut seccomp = Seccomp::new();
    // TODO: Do we need set NEW_LISTERNER flag manually if seccomp::is_notify(seccomp)?
    eprintln!("init_seccomp, set_flags: {:?}", inst_data.flags);
    if !inst_data.flags.is_empty() {
        seccomp.set_flags(inst_data.flags.clone());
    }
    seccomp.filters = Vec::try_from(inst_data)?;
    let _ = dump_filter("/tmp/filter.prog", &seccomp.filters);
    let fd = match seccomp.apply() {
        // TODO: check is_notify()?
        Ok(notify_fd) => Some(notify_fd.into_raw_fd()),
        Err(e) => return Err(e),
    };
    Ok(fd)

    // In order to use the SECCOMP_SET_MODE_FILTER operation, either the calling
    // thread must have the CAP_SYS_ADMIN capability in its user namespace, or
    // the thread must already have the no_new_privs bit set.
    // Ref: https://man7.org/linux/man-pages/man2/seccomp.2.html
    /*
    ctx.load()
        .map_err(|err| SeccompError::LoadContext { source: err })?;

    let fd = if is_notify(seccomp) {
        Some(
            ctx.get_notify_fd()
                .map_err(|err| SeccompError::GetNotifyId { source: err })?,
        )
    } else {
        None
    };

    Ok(fd)
    */
}

pub fn is_notify(seccomp: &LinuxSeccomp) -> bool {
    seccomp
        .syscalls()
        .iter()
        .flatten()
        .any(|syscall| syscall.action() == LinuxSeccompAction::ScmpActNotify)
}
