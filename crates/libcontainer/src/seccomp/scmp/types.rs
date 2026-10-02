use youki_seccomp::instruction::{
    SECCOMP_RET_ALLOW, SECCOMP_RET_ERRNO, SECCOMP_RET_KILL_PROCESS, SECCOMP_RET_KILL_THREAD,
    SECCOMP_RET_LOG, SECCOMP_RET_MASK, SECCOMP_RET_TRACE, SECCOMP_RET_TRAP, SECCOMP_RET_USER_NOTIF,
};

use super::arch;
use super::error::{Result, SeccompError};

/// Action taken when a filter rule matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScmpAction {
    KillProcess,
    KillThread,
    Trap,
    Notify,
    Errno(i32),
    Trace(u16),
    Log,
    Allow,
}

impl ScmpAction {
    /// Returns the value returned by the BPF program for this action.
    pub(super) fn to_ret(self) -> u32 {
        match self {
            Self::KillProcess => SECCOMP_RET_KILL_PROCESS,
            Self::KillThread => SECCOMP_RET_KILL_THREAD,
            Self::Trap => SECCOMP_RET_TRAP,
            Self::Notify => SECCOMP_RET_USER_NOTIF,
            Self::Errno(errno) => SECCOMP_RET_ERRNO | (errno as u32 & SECCOMP_RET_MASK),
            Self::Trace(msg) => SECCOMP_RET_TRACE | u32::from(msg),
            Self::Log => SECCOMP_RET_LOG,
            Self::Allow => SECCOMP_RET_ALLOW,
        }
    }
}

/// Architectures known to libseccomp. Only a subset is supported by this
/// implementation, see [`ScmpFilterContext::add_arch`](super::ScmpFilterContext::add_arch).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScmpArch {
    Native,
    X86,
    X8664,
    X32,
    Arm,
    Aarch64,
    Loongarch64,
    M68k,
    Mips,
    Mips64,
    Mips64N32,
    Mipsel,
    Mipsel64,
    Mipsel64N32,
    Ppc,
    Ppc64,
    Ppc64Le,
    S390,
    S390X,
    Parisc,
    Parisc64,
    Riscv64,
    Sh,
    Sheb,
}

impl ScmpArch {
    /// Resolves `Native` into the architecture this binary is built for.
    pub(super) fn resolve_native(self) -> Result<Self> {
        match self {
            Self::Native if cfg!(target_arch = "x86_64") => Ok(Self::X8664),
            Self::Native if cfg!(target_arch = "aarch64") => Ok(Self::Aarch64),
            Self::Native if cfg!(target_arch = "x86") => Ok(Self::X86),
            Self::Native if cfg!(target_arch = "arm") => Ok(Self::Arm),
            Self::Native => Err(SeccompError::UnsupportedArch(self)),
            arch => Ok(arch),
        }
    }
}

/// Comparison operator for a syscall argument.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScmpCompareOp {
    NotEqual,
    Less,
    LessOrEqual,
    Equal,
    GreaterEqual,
    Greater,
    /// `(arg & mask) == datum`, the inner value is the mask.
    MaskedEqual(u64),
}

/// A comparison of a syscall argument against a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ScmpArgCompare {
    pub(super) arg: u32,
    pub(super) op: ScmpCompareOp,
    pub(super) datum: u64,
}

impl ScmpArgCompare {
    #[must_use]
    pub const fn new(arg: u32, op: ScmpCompareOp, datum: u64) -> Self {
        Self { arg, op, datum }
    }
}

/// A syscall identified by name. The number is resolved per architecture
/// when the filter is compiled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ScmpSyscall {
    name: &'static str,
}

impl ScmpSyscall {
    /// Looks up a syscall by name. It succeeds if the syscall exists on any
    /// supported architecture, like libseccomp does for pseudo syscalls.
    pub fn from_name(name: &str) -> Result<Self> {
        arch::lookup_name(name)
            .map(|name| Self { name })
            .ok_or_else(|| SeccompError::UnknownSyscall(name.to_string()))
    }

    pub(super) fn name(&self) -> &'static str {
        self.name
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_action_to_ret() {
        assert_eq!(ScmpAction::Allow.to_ret(), 0x7fff_0000);
        assert_eq!(ScmpAction::Errno(libc::EPERM).to_ret(), 0x0005_0001);
        assert_eq!(ScmpAction::Trace(0x1234).to_ret(), 0x7ff0_1234);
        assert_eq!(ScmpAction::KillThread.to_ret(), 0);
    }

    #[test]
    fn test_syscall_from_name() {
        assert!(ScmpSyscall::from_name("getcwd").is_ok());
        // i386 only syscall is accepted, as libseccomp does.
        assert!(ScmpSyscall::from_name("socketcall").is_ok());
        assert!(ScmpSyscall::from_name("no_such_syscall").is_err());
    }
}
