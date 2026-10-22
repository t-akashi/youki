#[cfg(all(feature = "seccomp", not(feature = "oci_seccomp")))]
mod mod_libseccomp;
#[cfg(all(feature = "seccomp", not(feature = "oci_seccomp")))]
pub use mod_libseccomp::*;

#[cfg(all(feature = "seccomp", feature = "oci_seccomp"))]
mod mod_oci_seccomp;
#[cfg(all(feature = "seccomp", feature = "oci_seccomp"))]
pub use mod_oci_seccomp::*;
