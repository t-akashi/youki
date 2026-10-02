use std::cell::Cell;
use std::collections::HashSet;
use std::os::unix::io::{IntoRawFd, RawFd};

use libc::c_ulong;
use youki_seccomp::seccomp::Seccomp;

use super::compiler::{self, Rule};
use super::error::{Result, SeccompError};
use super::types::{ScmpAction, ScmpArch, ScmpArgCompare, ScmpSyscall};

const SECCOMP_FILTER_FLAG_TSYNC: c_ulong = 1 << 0;
const SECCOMP_FILTER_FLAG_LOG: c_ulong = 1 << 1;
const SECCOMP_FILTER_FLAG_SPEC_ALLOW: c_ulong = 1 << 2;
const SECCOMP_FILTER_FLAG_NEW_LISTENER: c_ulong = 1 << 3;
const SECCOMP_FILTER_FLAG_TSYNC_ESRCH: c_ulong = 1 << 4;
const SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV: c_ulong = 1 << 5;

/// Maximum number of syscall arguments.
const MAX_ARGS: usize = 6;

/// A seccomp filter under construction, compatible with
/// `libseccomp::ScmpFilterContext` for the subset used by youki.
#[derive(Debug)]
pub struct ScmpFilterContext {
    default_action: ScmpAction,
    bad_arch_action: ScmpAction,
    archs: Vec<ScmpArch>,
    rules: Vec<Rule>,
    ctl_nnp: bool,
    ctl_tsync: bool,
    ctl_log: bool,
    ctl_ssb: bool,
    ctl_waitkill: bool,
    notify_fd: Cell<Option<RawFd>>,
}

impl ScmpFilterContext {
    /// Creates a filter with `default_action` for the native architecture.
    pub fn new(default_action: ScmpAction) -> Result<Self> {
        let native = ScmpArch::Native.resolve_native()?;
        Ok(Self {
            default_action,
            // Same as the default of libseccomp.
            bad_arch_action: ScmpAction::KillThread,
            archs: vec![native],
            rules: vec![],
            ctl_nnp: true,
            ctl_tsync: false,
            ctl_log: false,
            ctl_ssb: false,
            ctl_waitkill: false,
            notify_fd: Cell::new(None),
        })
    }

    /// Adds an architecture. Adding an existing one is not an error.
    pub fn add_arch(&mut self, arch: ScmpArch) -> Result<&mut Self> {
        let arch = arch.resolve_native()?;
        super::arch::info(arch)?;
        if !self.archs.contains(&arch) {
            self.archs.push(arch);
        }
        Ok(self)
    }

    pub fn add_rule<S: Into<ScmpSyscall>>(
        &mut self,
        action: ScmpAction,
        syscall: S,
    ) -> Result<&mut Self> {
        self.add_rule_conditional(action, syscall, &[])
    }

    /// Adds a rule which matches when all the `comparators` match.
    pub fn add_rule_conditional<S: Into<ScmpSyscall>>(
        &mut self,
        action: ScmpAction,
        syscall: S,
        comparators: &[ScmpArgCompare],
    ) -> Result<&mut Self> {
        if action == self.default_action {
            return Err(SeccompError::ActionIsDefault(action));
        }
        if comparators.len() > MAX_ARGS {
            return Err(SeccompError::TooManyArgs(comparators.len()));
        }
        let mut seen = HashSet::new();
        for cmp in comparators {
            if cmp.arg as usize >= MAX_ARGS {
                return Err(SeccompError::InvalidArgIndex(cmp.arg));
            }
            if !seen.insert(cmp.arg) {
                return Err(SeccompError::DuplicateArgIndex(cmp.arg));
            }
        }
        self.rules.push(Rule {
            action,
            syscall: syscall.into(),
            comparators: comparators.to_vec(),
        });
        Ok(self)
    }

    /// Sets whether `load` sets the no_new_privs bit (defaults to true).
    pub fn set_ctl_nnp(&mut self, state: bool) -> Result<&mut Self> {
        self.ctl_nnp = state;
        Ok(self)
    }

    pub fn set_ctl_tsync(&mut self, state: bool) -> Result<&mut Self> {
        self.ctl_tsync = state;
        Ok(self)
    }

    pub fn set_ctl_log(&mut self, state: bool) -> Result<&mut Self> {
        self.ctl_log = state;
        Ok(self)
    }

    pub fn set_ctl_ssb(&mut self, state: bool) -> Result<&mut Self> {
        self.ctl_ssb = state;
        Ok(self)
    }

    pub fn set_ctl_waitkill(&mut self, state: bool) -> Result<&mut Self> {
        self.ctl_waitkill = state;
        Ok(self)
    }

    fn has_notify(&self) -> bool {
        self.default_action == ScmpAction::Notify
            || self.rules.iter().any(|r| r.action == ScmpAction::Notify)
    }

    fn filter_flags(&self) -> c_ulong {
        let mut flags = 0;
        if self.ctl_log {
            flags |= SECCOMP_FILTER_FLAG_LOG;
        }
        if self.ctl_ssb {
            flags |= SECCOMP_FILTER_FLAG_SPEC_ALLOW;
        }
        if self.ctl_tsync {
            flags |= SECCOMP_FILTER_FLAG_TSYNC;
        }
        if self.has_notify() {
            flags |= SECCOMP_FILTER_FLAG_NEW_LISTENER;
            // TSYNC and NEW_LISTENER are exclusive unless TSYNC_ESRCH is set.
            if self.ctl_tsync {
                flags |= SECCOMP_FILTER_FLAG_TSYNC_ESRCH;
            }
            // WAIT_KILLABLE_RECV is only valid with NEW_LISTENER.
            if self.ctl_waitkill {
                flags |= SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV;
            }
        }
        flags
    }

    /// Compiles the filter and loads it into the kernel.
    pub fn load(&self) -> Result<()> {
        let filters = compiler::compile(
            self.default_action,
            self.bad_arch_action,
            &self.archs,
            &self.rules,
        )?;

        if self.ctl_nnp {
            prctl::set_no_new_privileges(true)
                .map_err(|errno| SeccompError::SetNoNewPrivs(nix::Error::from_raw(errno)))?;
        }

        let flags = self.filter_flags();
        let seccomp = Seccomp { filters, flags };
        // `into_raw_fd` keeps the fd open: the ownership is passed to the
        // caller via `get_notify_fd`, as libseccomp does.
        let fd = seccomp
            .apply()
            .map_err(|err| SeccompError::Load(err.to_string()))?
            .into_raw_fd();
        if flags & SECCOMP_FILTER_FLAG_NEW_LISTENER != 0 {
            self.notify_fd.set(Some(fd));
        }
        Ok(())
    }

    /// Returns the notification fd of the loaded filter.
    pub fn get_notify_fd(&self) -> Result<RawFd> {
        self.notify_fd.get().ok_or(SeccompError::NoNotifyFd)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seccomp::scmp::ScmpCompareOp;

    #[test]
    fn test_add_rule_validation() {
        let mut ctx = ScmpFilterContext::new(ScmpAction::Allow).unwrap();
        let getcwd = ScmpSyscall::from_name("getcwd").unwrap();
        assert!(matches!(
            ctx.add_rule(ScmpAction::Allow, getcwd),
            Err(SeccompError::ActionIsDefault(_))
        ));
        let cmp = |arg| ScmpArgCompare::new(arg, ScmpCompareOp::Equal, 0);
        assert!(matches!(
            ctx.add_rule_conditional(ScmpAction::Log, getcwd, &[cmp(6)]),
            Err(SeccompError::InvalidArgIndex(6))
        ));
        assert!(matches!(
            ctx.add_rule_conditional(ScmpAction::Log, getcwd, &[cmp(1), cmp(1)]),
            Err(SeccompError::DuplicateArgIndex(1))
        ));
        assert!(
            ctx.add_rule_conditional(ScmpAction::Log, getcwd, &[cmp(0), cmp(1)])
                .is_ok()
        );
        assert!(ctx.add_arch(ScmpArch::Native).is_ok());
        assert!(ctx.add_arch(ScmpArch::X86).is_ok());
        assert!(matches!(
            ctx.add_arch(ScmpArch::S390X),
            Err(SeccompError::UnsupportedArch(_))
        ));
    }

    #[test]
    fn test_filter_flags() {
        let mut ctx = ScmpFilterContext::new(ScmpAction::Allow).unwrap();
        ctx.set_ctl_tsync(true).unwrap();
        ctx.set_ctl_waitkill(true).unwrap();
        assert_eq!(ctx.filter_flags(), SECCOMP_FILTER_FLAG_TSYNC);

        let getcwd = ScmpSyscall::from_name("getcwd").unwrap();
        ctx.add_rule(ScmpAction::Notify, getcwd).unwrap();
        assert_eq!(
            ctx.filter_flags(),
            SECCOMP_FILTER_FLAG_TSYNC
                | SECCOMP_FILTER_FLAG_NEW_LISTENER
                | SECCOMP_FILTER_FLAG_TSYNC_ESRCH
                | SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV
        );
    }
}
