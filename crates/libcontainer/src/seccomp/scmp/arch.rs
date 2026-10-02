use std::str::FromStr;

use syscalls::{aarch64, arm, x86, x86_64};
use youki_seccomp::instruction::{
    AUDIT_ARCH_AARCH64, AUDIT_ARCH_ARM, AUDIT_ARCH_I386, AUDIT_ARCH_X86_64, X32_SYSCALL_BIT,
};

use super::error::{Result, SeccompError};
use super::types::ScmpArch;

/// Properties of a supported architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ArchInfo {
    pub arch: ScmpArch,
    /// `AUDIT_ARCH_*` value found in `seccomp_data.arch`.
    pub audit: u32,
    /// Whether syscall arguments are 64 bits wide.
    pub is_64bit: bool,
}

/// Returns the properties of `arch` (which must not be `Native`).
pub(super) fn info(arch: ScmpArch) -> Result<ArchInfo> {
    let (audit, is_64bit) = match arch {
        ScmpArch::X8664 => (AUDIT_ARCH_X86_64, true),
        // x32 shares AUDIT_ARCH_X86_64 and is distinguished by X32_SYSCALL_BIT.
        ScmpArch::X32 => (AUDIT_ARCH_X86_64, true),
        ScmpArch::X86 => (AUDIT_ARCH_I386, false),
        ScmpArch::Aarch64 => (AUDIT_ARCH_AARCH64, true),
        ScmpArch::Arm => (AUDIT_ARCH_ARM, false),
        _ => return Err(SeccompError::UnsupportedArch(arch)),
    };
    Ok(ArchInfo {
        arch,
        audit,
        is_64bit,
    })
}

/// x32 syscalls whose numbers differ from x86_64 ones.
/// See arch/x86/entry/syscalls/syscall_64.tbl in the kernel.
const X32_SPECIFIC: &[(&str, u32)] = &[
    ("rt_sigaction", 512),
    ("rt_sigreturn", 513),
    ("ioctl", 514),
    ("readv", 515),
    ("writev", 516),
    ("recvfrom", 517),
    ("sendmsg", 518),
    ("recvmsg", 519),
    ("execve", 520),
    ("ptrace", 521),
    ("rt_sigpending", 522),
    ("rt_sigtimedwait", 523),
    ("rt_sigqueueinfo", 524),
    ("sigaltstack", 525),
    ("timer_create", 526),
    ("mq_notify", 527),
    ("kexec_load", 528),
    ("waitid", 529),
    ("set_robust_list", 530),
    ("get_robust_list", 531),
    ("vmsplice", 532),
    ("move_pages", 533),
    ("preadv", 534),
    ("pwritev", 535),
    ("rt_tgsigqueueinfo", 536),
    ("recvmmsg", 537),
    ("sendmmsg", 538),
    ("process_vm_readv", 539),
    ("process_vm_writev", 540),
    ("setsockopt", 541),
    ("getsockopt", 542),
    ("io_setup", 543),
    ("io_submit", 544),
    ("execveat", 545),
    ("preadv2", 546),
    ("pwritev2", 547),
];

/// Resolves the syscall number of `name` on `arch` (which must not be
/// `Native`). Returns `None` if the syscall doesn't exist on the architecture.
pub(super) fn resolve(arch: ScmpArch, name: &str) -> Option<u32> {
    match arch {
        ScmpArch::X8664 => x86_64::Sysno::from_str(name).ok().map(|s| s.id() as u32),
        ScmpArch::X32 => X32_SPECIFIC
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, nr)| *nr)
            .or_else(|| x86_64::Sysno::from_str(name).ok().map(|s| s.id() as u32))
            .map(|nr| nr | X32_SYSCALL_BIT),
        ScmpArch::X86 => x86::Sysno::from_str(name).ok().map(|s| s.id() as u32),
        ScmpArch::Aarch64 => aarch64::Sysno::from_str(name).ok().map(|s| s.id() as u32),
        ScmpArch::Arm => arm::Sysno::from_str(name).ok().map(|s| s.id() as u32),
        _ => None,
    }
}

/// Looks up `name` in the syscall tables of all supported architectures and
/// returns the interned name.
pub(super) fn lookup_name(name: &str) -> Option<&'static str> {
    x86_64::Sysno::from_str(name)
        .map(|s| s.name())
        .or_else(|_| x86::Sysno::from_str(name).map(|s| s.name()))
        .or_else(|_| aarch64::Sysno::from_str(name).map(|s| s.name()))
        .or_else(|_| arm::Sysno::from_str(name).map(|s| s.name()))
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve() {
        assert_eq!(resolve(ScmpArch::X8664, "read"), Some(0));
        assert_eq!(resolve(ScmpArch::X8664, "getcwd"), Some(79));
        assert_eq!(resolve(ScmpArch::X86, "getcwd"), Some(183));
        assert_eq!(resolve(ScmpArch::X32, "read"), Some(X32_SYSCALL_BIT));
        assert_eq!(resolve(ScmpArch::X32, "ioctl"), Some(514 | X32_SYSCALL_BIT));
        assert_eq!(resolve(ScmpArch::Aarch64, "read"), Some(63));
        assert_eq!(resolve(ScmpArch::Arm, "getcwd"), Some(183));
        // aarch64 has no open(2).
        assert_eq!(resolve(ScmpArch::Aarch64, "open"), None);
        assert_eq!(resolve(ScmpArch::X8664, "socketcall"), None);
        assert_eq!(resolve(ScmpArch::X86, "socketcall"), Some(102));
    }

    #[test]
    fn test_info() {
        assert!(info(ScmpArch::X8664).unwrap().is_64bit);
        assert!(!info(ScmpArch::X86).unwrap().is_64bit);
        assert!(info(ScmpArch::Riscv64).is_err());
        assert!(info(ScmpArch::Native).is_err());
    }
}
