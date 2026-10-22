#[cfg(feature = "seccomp")]
mod mod_libseccomp;

#[cfg(feature = "seccomp")]
pub use mod_libseccomp::*;
