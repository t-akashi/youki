use super::types::{ScmpAction, ScmpArch};

#[derive(Debug, thiserror::Error)]
pub enum SeccompError {
    #[error("architecture {0:?} is not supported")]
    UnsupportedArch(ScmpArch),
    #[error("unknown syscall: {0}")]
    UnknownSyscall(String),
    #[error("invalid argument index {0}, valid indices are 0-5")]
    InvalidArgIndex(u32),
    #[error("argument index {0} is compared more than once in a rule")]
    DuplicateArgIndex(u32),
    #[error("too many argument comparisons: {0}")]
    TooManyArgs(usize),
    #[error("rule action {0:?} is the same as the default action")]
    ActionIsDefault(ScmpAction),
    #[error("seccomp filter is too large: {0} instructions")]
    FilterTooLarge(usize),
    #[error("jump offset {0} is out of range")]
    JumpOutOfRange(usize),
    #[error("failed to set no_new_privs")]
    SetNoNewPrivs(#[source] nix::Error),
    #[error("failed to load seccomp filter: {0}")]
    Load(String),
    #[error("seccomp notify fd is not available")]
    NoNotifyFd,
}

pub type Result<T> = std::result::Result<T, SeccompError>;
