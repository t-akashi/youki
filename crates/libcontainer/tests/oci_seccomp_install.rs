#![cfg(feature = "oci_seccomp")]

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::process::Command;

use libcontainer::seccomp::initialize_seccomp;
use oci_spec::runtime::LinuxSeccomp;
use serde_json::json;

#[test]
fn installs_the_oci_backend_and_returns_only_real_listener_fds() {
    if let Ok(mode) = std::env::var("YOUKI_OCI_BACKEND_TEST_WORKER") {
        unsafe {
            libc::alarm(10);
        }
        prctl::set_no_new_privileges(true).unwrap();
        let notify = mode == "notify";
        let spec: LinuxSeccomp = serde_json::from_value(json!({
            "defaultAction":"SCMP_ACT_ALLOW", "syscalls":[{
                "names":["getpid"],
                "action":if notify {"SCMP_ACT_NOTIFY"} else {"SCMP_ACT_ERRNO"},
                "errnoRet":99,
                "args":[{"index":0,"op":"SCMP_CMP_EQ","value":8}]
            }]
        }))
        .unwrap();
        let fd = initialize_seccomp(&spec).unwrap();
        if notify {
            let fd = unsafe { OwnedFd::from_raw_fd(fd.expect("listener descriptor")) };
            assert!(
                std::fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd()))
                    .unwrap()
                    .to_string_lossy()
                    .contains("seccomp")
            );
            drop(fd);
        } else {
            assert_eq!(fd, None);
            assert_eq!(unsafe { libc::syscall(libc::SYS_getpid, 8u64) }, -1);
            assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(99));
            assert!(unsafe { libc::syscall(libc::SYS_getpid, 7u64) } > 0);
        }
        unsafe {
            libc::_exit(0);
        }
    }
    for mode in ["plain", "notify"] {
        let result = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "installs_the_oci_backend_and_returns_only_real_listener_fds",
                "--nocapture",
            ])
            .env("YOUKI_OCI_BACKEND_TEST_WORKER", mode)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{mode}: {}\n{}",
            result.status,
            String::from_utf8_lossy(&result.stderr)
        );
    }
}

#[test]
fn rejects_a_foreign_only_profile_before_installation() {
    let foreign = if cfg!(target_arch = "x86_64") {
        "SCMP_ARCH_AARCH64"
    } else {
        "SCMP_ARCH_X86_64"
    };
    let spec: LinuxSeccomp = serde_json::from_value(json!({
        "defaultAction":"SCMP_ACT_ALLOW", "architectures":[foreign]
    }))
    .unwrap();
    assert!(
        initialize_seccomp(&spec)
            .unwrap_err()
            .to_string()
            .contains("host ABI")
    );
}
