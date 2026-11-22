use core::fmt;
use std::collections::{HashMap, HashSet};
use std::mem::MaybeUninit;
use std::os::fd::OwnedFd;
use std::os::raw::{c_long, c_uint, c_ulong, c_ushort, c_void};
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::str::FromStr;

use anyhow::Result;
use nix::errno::Errno;
use nix::libc::{
    SECCOMP_FILTER_FLAG_LOG, SECCOMP_FILTER_FLAG_NEW_LISTENER, SECCOMP_FILTER_FLAG_SPEC_ALLOW,
    SECCOMP_FILTER_FLAG_TSYNC, SECCOMP_FILTER_FLAG_TSYNC_ESRCH,
    SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV, SECCOMP_SET_MODE_FILTER,
};
use nix::{ioctl_readwrite, ioctl_write_ptr, libc};
use oci_spec::runtime::{
    Arch as OciSpecArch, LinuxSeccomp, LinuxSeccompAction, LinuxSeccompArg, LinuxSeccompFilterFlag,
    LinuxSeccompOperator,
};

use crate::instruction::{Arch, Instruction, SECCOMP_IOC_MAGIC, *};

#[derive(Debug, thiserror::Error)]
pub enum SeccompError {
    #[error("Failed to apply seccomp rules: {0}")]
    Apply(String),
    #[error("valid indices are 0–5")]
    InvalidArgumentSize,
    #[error("Can't ScmpActNotify to default action")]
    InvalidDefaultAction,
    #[error("Can't filter to write system call")]
    InvalidSystemCall,
    #[error("unsupported seccomp configuration: {0}")]
    Unsupported(String),
    #[error("seccomp filter has {0} instructions; expected 1..=4096")]
    InvalidProgramSize(usize),
    #[error("seccomp thread synchronization failed for thread {0}")]
    ThreadSync(c_long),
}

pub struct Seccomp {
    pub filters: Vec<Instruction>,
    pub flags: c_ulong,
}

impl Default for Seccomp {
    fn default() -> Self {
        Seccomp::new()
    }
}

impl Seccomp {
    pub fn new() -> Self {
        Seccomp {
            filters: Vec::new(),
            flags: 0,
        }
    }

    pub fn set_flags(&mut self, flags: Vec<c_ulong>) {
        for flag in flags {
            self.flags |= flag;
        }
    }

    /// Install on the calling thread. The caller controls no_new_privs.
    /// Only NEW_LISTENER produces an owned descriptor; ordinary success is 0.
    pub fn apply(&self) -> Result<Option<NotifyFd>, SeccompError> {
        if self.filters.is_empty() || self.filters.len() > 4096 {
            return Err(SeccompError::InvalidProgramSize(self.filters.len()));
        }
        let mut flags = self.flags;
        if flags & SECCOMP_FILTER_FLAG_NEW_LISTENER != 0 {
            if flags & SECCOMP_FILTER_FLAG_TSYNC != 0 {
                // A positive TSYNC failure is a thread id, not a listener fd.
                flags |= SECCOMP_FILTER_FLAG_TSYNC_ESRCH;
            }
        } else {
            // Like libseccomp, ignore the listener-only flag without a listener.
            flags &= !SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV;
        }
        let mut prog = Filters {
            len: self.filters.len() as c_ushort,
            filter: self.filters.as_ptr(),
        };
        let result = unsafe {
            seccomp(
                SECCOMP_SET_MODE_FILTER,
                flags,
                &mut prog as *mut _ as *mut c_void,
            )
        };
        Errno::result(result).map_err(|e| SeccompError::Apply(e.to_string()))?;
        if self.flags & SECCOMP_FILTER_FLAG_NEW_LISTENER != 0 {
            Ok(Some(unsafe { NotifyFd::from_raw_fd(result as RawFd) }))
        } else if result != 0 {
            Err(SeccompError::ThreadSync(result))
        } else {
            Ok(None)
        }
    }
}

#[derive(Debug)]
pub struct NotifyFd {
    fd: OwnedFd,
}

impl FromRawFd for NotifyFd {
    unsafe fn from_raw_fd(fd: RawFd) -> Self {
        NotifyFd {
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
        }
    }
}

impl IntoRawFd for NotifyFd {
    fn into_raw_fd(self) -> RawFd {
        self.fd.into_raw_fd()
    }
}

impl AsRawFd for NotifyFd {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl NotifyFd {
    pub fn success(&self, v: i64, notify_id: u64) -> nix::Result<()> {
        let mut resp = SeccompNotifResp {
            id: notify_id,
            val: v,
            error: 0,
            flags: 0,
        };

        unsafe { seccomp_notif_ioctl_send(self.as_raw_fd(), &mut resp as *mut _)? };

        Ok(())
    }
}

// TODO: Rename
#[repr(C)]
#[derive(Debug)]
pub struct SeccompData {
    pub nr: libc::c_int,
    pub arch: u32,
    pub instruction_pointer: u64,
    pub args: [u64; 6],
}

#[repr(C)]
#[derive(Debug)]
pub struct SeccompNotif {
    pub id: u64,
    pub pid: u32,
    pub flags: u32,
    pub data: SeccompData,
}

#[repr(C)]
#[derive(Debug)]
pub struct SeccompNotifResp {
    pub id: u64,
    pub val: i64,
    pub error: i32,
    pub flags: u32,
}

#[repr(C)]
#[derive(Debug)]
pub struct SeccompNotifSizes {
    pub seccomp_notif: u16,
    pub seccomp_notif_resp: u16,
    pub seccomp_data: u16,
}

#[repr(C)]
#[derive(Debug)]
pub struct SeccompNotifAddfd {
    pub id: u64,
    pub flags: u32,
    pub srcfd: u32,
    pub newfd: u32,
    pub newfd_flags: u32,
}

ioctl_readwrite!(seccomp_notif_ioctl_recv, SECCOMP_IOC_MAGIC, 0, SeccompNotif);
ioctl_readwrite!(
    seccomp_notif_ioctl_send,
    SECCOMP_IOC_MAGIC,
    1,
    SeccompNotifResp
);
ioctl_write_ptr!(seccomp_notif_ioctl_id_valid, SECCOMP_IOC_MAGIC, 2, u64);
ioctl_write_ptr!(
    seccomp_notif_ioctl_addfd,
    SECCOMP_IOC_MAGIC,
    3,
    SeccompNotifAddfd
);

pub struct Notification<'f> {
    pub notif: SeccompNotif,
    pub fd: &'f NotifyFd,
}

impl<'f> fmt::Debug for Notification<'f> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.notif, f)
    }
}

#[warn(mismatched_lifetime_syntaxes)]
impl NotifyFd {
    pub fn recv(&self) -> nix::Result<Notification<'_>> {
        let mut res = MaybeUninit::zeroed();
        let notif = unsafe {
            seccomp_notif_ioctl_recv(self.as_raw_fd(), res.as_mut_ptr())?;
            res.assume_init()
        };

        Ok(Notification { notif, fd: self })
    }
}

unsafe fn seccomp(op: c_uint, flags: c_ulong, args: *mut c_void) -> c_long {
    unsafe { libc::syscall(libc::SYS_seccomp, op, flags, args) }
}

#[repr(C)]
struct Filters {
    pub len: c_ushort,
    pub filter: *const Instruction,
}

fn get_syscall_number(arc: &Arch, name: &str) -> Option<u64> {
    match arc {
        Arch::X86 => match syscalls::x86_64::Sysno::from_str(name) {
            Ok(syscall) => Some(syscall as u64),
            Err(_) => None,
        },
        Arch::AArch64 => match syscalls::aarch64::Sysno::from_str(name) {
            Ok(syscall) => Some(syscall as u64),
            Err(_) => None,
        },
    }
}

// This wrapper type is used to implement the `From` trait while avoiding the orphan rule's restrictions.
pub struct SeccompActionWrapper(pub LinuxSeccompAction);

impl From<SeccompActionWrapper> for u32 {
    fn from(wrapped_action: SeccompActionWrapper) -> Self {
        // Extracts the wrapped LinuxSeccompAction
        let action = wrapped_action.0;
        match action {
            LinuxSeccompAction::ScmpActKill => SECCOMP_RET_KILL_THREAD,
            LinuxSeccompAction::ScmpActTrap => SECCOMP_RET_TRAP,
            LinuxSeccompAction::ScmpActErrno => SECCOMP_RET_ERRNO,
            LinuxSeccompAction::ScmpActTrace => SECCOMP_RET_TRACE,
            LinuxSeccompAction::ScmpActAllow => SECCOMP_RET_ALLOW,
            LinuxSeccompAction::ScmpActKillProcess => SECCOMP_RET_KILL_PROCESS,
            LinuxSeccompAction::ScmpActNotify => SECCOMP_RET_USER_NOTIF,
            LinuxSeccompAction::ScmpActLog => SECCOMP_RET_LOG,
            LinuxSeccompAction::ScmpActKillThread => SECCOMP_RET_KILL_THREAD,
        }
    }
}

impl From<LinuxSeccompOperator> for SeccompCompareOp {
    fn from(op: LinuxSeccompOperator) -> Self {
        match op {
            LinuxSeccompOperator::ScmpCmpNe => SeccompCompareOp::NotEqual,
            LinuxSeccompOperator::ScmpCmpLt => SeccompCompareOp::LessThan,
            LinuxSeccompOperator::ScmpCmpLe => SeccompCompareOp::LessOrEqual,
            LinuxSeccompOperator::ScmpCmpEq => SeccompCompareOp::Equal,
            LinuxSeccompOperator::ScmpCmpGe => SeccompCompareOp::GreaterOrEqual,
            LinuxSeccompOperator::ScmpCmpGt => SeccompCompareOp::GreaterThan,
            LinuxSeccompOperator::ScmpCmpMaskedEq => SeccompCompareOp::MaskedEqual,
        }
    }
}

fn check_seccomp(seccomp: &LinuxSeccomp) -> Result<(), SeccompError> {
    // We don't support notify as default action. After the seccomp filter is
    // created with notify, the container process will have to communicate the
    // returned fd to another process. Therefore, we need the write syscall or
    // otherwise, the write syscall will be block by the seccomp filter causing
    // the container process to hang. `runc` also disallow notify as default
    // action.
    // Note: read and close syscall are also used, because if we can
    // successfully write fd to another process, the other process can choose to
    // handle read/close syscall and allow read and close to proceed as
    // expected.
    if seccomp.default_action() == LinuxSeccompAction::ScmpActNotify {
        // Todo: consider need to porting SeccompError
        return Err(SeccompError::InvalidDefaultAction);
    }

    if let Some(syscalls) = seccomp.syscalls() {
        for syscall in syscalls {
            if syscall.action() == LinuxSeccompAction::ScmpActNotify {
                for name in syscall.names() {
                    if name == "write" {
                        return Err(SeccompError::InvalidSystemCall);
                    }
                }
            }
        }
    }

    Ok(())
}

/// A rule's syscall tests share an argument block. Conditional branches stay
/// within 254 instructions; a 32-bit JA skips the complete argument block.
fn build_syscall_section(rule: &Rule) -> Result<Vec<Instruction>, SeccompError> {
    let mut body = Vec::new();
    let mut failures = Vec::new();
    for arg in &rule.args {
        emit_comparison(&mut body, &mut failures, arg)?;
    }
    body.push(Instruction::stmt(BPF_RET | BPF_K, rule.action));
    let end = body.len();
    for at in failures {
        body[at].multiuse_field = (end - at - 1) as u32;
    }
    let mut out = Vec::new();
    for chunk in rule.syscall.chunks(254) {
        // A previous rule/argument block may have left an argument in A.
        out.push(Instruction::stmt(
            BPF_LD | BPF_W | BPF_ABS,
            seccomp_data_nr_offset().into(),
        ));
        for (i, nr) in chunk.iter().enumerate() {
            out.push(Instruction::jump(
                BPF_JEQ | BPF_K,
                (chunk.len() - i) as u8,
                0,
                *nr as u32,
            ));
        }
        out.push(Instruction::stmt(BPF_JMP | BPF_JA, body.len() as u32));
        out.extend_from_slice(&body);
        if out.len() > 4096 {
            return Err(SeccompError::InvalidProgramSize(out.len()));
        }
    }
    Ok(out)
}

/// On success, continue to the next comparison. On failure, a patched JA
/// skips the rule's action. OCI argument comparisons are unsigned 64-bit.
fn emit_comparison(
    out: &mut Vec<Instruction>,
    failures: &mut Vec<usize>,
    arg: &LinuxSeccompArg,
) -> Result<(), SeccompError> {
    let index = u8::try_from(arg.index()).map_err(|_| SeccompError::InvalidArgumentSize)?;
    let offset = u32::from(seccomp_data_args_offset(index)?);
    let hi = (arg.value() >> 32) as u32;
    let lo = arg.value() as u32;
    let fail = |out: &mut Vec<Instruction>, failures: &mut Vec<usize>| {
        failures.push(out.len());
        out.push(Instruction::stmt(BPF_JMP | BPF_JA, 0));
    };
    match arg.op() {
        LinuxSeccompOperator::ScmpCmpEq | LinuxSeccompOperator::ScmpCmpMaskedEq => {
            let masked = arg.op() == LinuxSeccompOperator::ScmpCmpMaskedEq;
            let value = if masked {
                arg.value_two().unwrap_or(0)
            } else {
                arg.value()
            };
            for (off, shift) in [(offset + 4, 32), (offset, 0)] {
                out.push(Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, off));
                if masked {
                    out.push(Instruction::stmt(
                        BPF_ALU | BPF_AND | BPF_K,
                        (arg.value() >> shift) as u32,
                    ));
                }
                out.push(Instruction::jump(
                    BPF_JEQ | BPF_K,
                    1,
                    0,
                    (value >> shift) as u32,
                ));
                fail(out, failures);
            }
        }
        LinuxSeccompOperator::ScmpCmpNe => {
            out.push(Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, offset + 4));
            out.push(Instruction::jump(BPF_JEQ | BPF_K, 0, 3, hi));
            out.push(Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, offset));
            out.push(Instruction::jump(BPF_JEQ | BPF_K, 0, 1, lo));
            fail(out, failures);
        }
        op => {
            let greater = matches!(
                op,
                LinuxSeccompOperator::ScmpCmpGt | LinuxSeccompOperator::ScmpCmpGe
            );
            let low_op = match op {
                LinuxSeccompOperator::ScmpCmpGt | LinuxSeccompOperator::ScmpCmpLe => BPF_JGT,
                _ => BPF_JGE,
            };
            out.push(Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, offset + 4));
            out.push(Instruction::jump(BPF_JEQ | BPF_K, 2, 0, hi));
            out.push(Instruction::jump(
                BPF_JGT | BPF_K,
                if greater { 4 } else { 0 },
                if greater { 0 } else { 4 },
                hi,
            ));
            fail(out, failures);
            out.push(Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, offset));
            out.push(Instruction::jump(
                low_op | BPF_K,
                u8::from(greater),
                u8::from(!greater),
                lo,
            ));
            fail(out, failures);
        }
    }
    Ok(())
}

#[derive(Debug, Default)]
pub struct SeccompProgramPlan {
    pub arc: Arch,
    pub def_action: u32,
    pub flags: Vec<c_ulong>,
    pub rules: Vec<Rule>,
}

impl TryFrom<SeccompProgramPlan> for Vec<Instruction> {
    type Error = SeccompError;
    fn try_from(plan: SeccompProgramPlan) -> Result<Self, SeccompError> {
        let mut out = gen_validate(&plan.arc);
        for rule in &plan.rules {
            out.extend(build_syscall_section(rule)?);
            if out.len() >= 4096 {
                return Err(SeccompError::InvalidProgramSize(out.len() + 1));
            }
        }
        out.push(Instruction::stmt(BPF_RET | BPF_K, plan.def_action));
        Ok(out)
    }
}

fn action_value(action: LinuxSeccompAction, data: Option<u32>) -> Result<u32, SeccompError> {
    let base = u32::from(SeccompActionWrapper(action));
    if matches!(
        action,
        LinuxSeccompAction::ScmpActErrno | LinuxSeccompAction::ScmpActTrace
    ) {
        let value = data.unwrap_or(libc::EPERM as u32);
        if value > SECCOMP_RET_MASK {
            return Err(SeccompError::Unsupported(format!(
                "action data {value} exceeds 16 bits"
            )));
        }
        Ok(base | value)
    } else {
        Ok(base)
    }
}

impl TryFrom<LinuxSeccomp> for SeccompProgramPlan {
    type Error = SeccompError;
    fn try_from(seccomp: LinuxSeccomp) -> Result<Self, SeccompError> {
        check_seccomp(&seccomp)?;
        let native = Arch::native()?;
        let mut selected = None;
        for arch in seccomp.architectures().iter().flatten() {
            let arch = match arch {
                OciSpecArch::ScmpArchNative => native,
                OciSpecArch::ScmpArchX86_64 => Arch::X86,
                OciSpecArch::ScmpArchAarch64 => Arch::AArch64,
                other => return Err(SeccompError::Unsupported(format!("architecture {other:?}"))),
            };
            if selected.is_some_and(|previous| previous != arch) {
                return Err(SeccompError::Unsupported("multiple syscall ABIs".into()));
            }
            selected = Some(arch);
        }
        let mut plan = Self {
            arc: selected.unwrap_or(native),
            def_action: action_value(seccomp.default_action(), seccomp.default_errno_ret())?,
            ..Default::default()
        };
        for flag in seccomp.flags().iter().flatten() {
            plan.flags.push(match flag {
                LinuxSeccompFilterFlag::SeccompFilterFlagLog => SECCOMP_FILTER_FLAG_LOG,
                LinuxSeccompFilterFlag::SeccompFilterFlagTsync => SECCOMP_FILTER_FLAG_TSYNC,
                LinuxSeccompFilterFlag::SeccompFilterFlagSpecAllow => {
                    SECCOMP_FILTER_FLAG_SPEC_ALLOW
                }
                LinuxSeccompFilterFlag::SeccompFilterFlagWaitKillableRecv => {
                    SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV
                }
            });
        }
        // Reject action conflicts until their libseccomp precedence is implemented.
        let mut actions = HashMap::new();
        for entry in seccomp.syscalls().iter().flatten() {
            let action = action_value(entry.action(), entry.errno_ret())?;
            if action == plan.def_action {
                continue;
            }
            let args = entry.args().clone().unwrap_or_default();
            let mut seen = HashSet::new();
            let mut duplicate = false;
            for arg in &args {
                if arg.index() > 5 {
                    return Err(SeccompError::InvalidArgumentSize);
                }
                duplicate |= !seen.insert(arg.index());
            }
            let mut numbers = Vec::new();
            for name in entry.names() {
                let Some(nr) = get_syscall_number(&plan.arc, name) else {
                    eprintln!("seccomp: no syscall number for {name:?}");
                    continue;
                };
                if actions.insert(nr, action).is_some_and(|old| old != action) {
                    return Err(SeccompError::Unsupported(format!(
                        "conflicting actions for {name}"
                    )));
                }
                numbers.push(nr);
            }
            numbers.sort_unstable();
            numbers.dedup();
            if numbers.is_empty() {
                continue;
            }
            if action == SECCOMP_RET_USER_NOTIF
                && !plan.flags.contains(&SECCOMP_FILTER_FLAG_NEW_LISTENER)
            {
                plan.flags.push(SECCOMP_FILTER_FLAG_NEW_LISTENER);
            }
            // Match libcontainer/runc: distinct indexes are ANDed; repeated
            // indexes cause each comparison to be added as a separate rule.
            if duplicate {
                for arg in args {
                    plan.rules.push(Rule {
                        syscall: numbers.clone(),
                        action,
                        args: vec![arg],
                    });
                }
            } else {
                plan.rules.push(Rule {
                    syscall: numbers,
                    action,
                    args,
                });
            }
        }
        Ok(plan)
    }
}

#[derive(Debug, Default)]
pub struct Rule {
    pub syscall: Vec<u64>,
    pub action: u32,
    pub args: Vec<LinuxSeccompArg>,
}
