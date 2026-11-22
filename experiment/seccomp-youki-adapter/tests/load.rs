use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::process::Command;

use libcontainer::seccomp::{LibseccompBackend, SeccompBackend, initialize_seccomp_with};
use oci_seccomp_youki_adapter::OciSeccompBackend;
use oci_spec::runtime::LinuxSeccomp;
use serde_json::json;

// Swap backends at the same call site, with precisely the same OCI section.
// Each installation is confined to a disposable child process.
#[test]
fn interchangeable_backends_through_3873() {
    if let Ok(mode) = std::env::var("OCI_SECCOMP_TRAIT_WORKER") {
        unsafe {
            libc::alarm(10);
            assert_eq!(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), 0);
        }
        let notify = mode.ends_with("notify");
        let spec: LinuxSeccomp = serde_json::from_value(json!({
            "defaultAction":"SCMP_ACT_ALLOW", "syscalls":[{
                "names":["getpid"],
                "action":if notify {"SCMP_ACT_NOTIFY"} else {"SCMP_ACT_ERRNO"},
                "errnoRet":99,
                "args":[{"index":0,"op":"SCMP_CMP_EQ","value":8}]
            }]
        }))
        .unwrap();
        let backend: &dyn SeccompBackend = if mode.starts_with("oci") {
            &OciSeccompBackend
        } else {
            &LibseccompBackend
        };
        let fd = initialize_seccomp_with(backend, &spec).unwrap();
        if notify {
            let fd = unsafe { OwnedFd::from_raw_fd(fd.expect("listener descriptor")) };
            assert!(
                std::fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd()))
                    .unwrap()
                    .to_string_lossy()
                    .contains("seccomp")
            );
        } else {
            assert_eq!(fd, None);
            assert_eq!(unsafe { libc::syscall(libc::SYS_getpid, 8u64) }, -1);
            assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(99));
            assert!(unsafe { libc::syscall(libc::SYS_getpid, 7u64) } > 0);
        }
        unsafe { libc::_exit(0) };
    }
    for mode in [
        "oci-plain",
        "libseccomp-plain",
        "oci-notify",
        "libseccomp-notify",
    ] {
        let result = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "interchangeable_backends_through_3873",
                "--nocapture",
            ])
            .env("OCI_SECCOMP_TRAIT_WORKER", mode)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{mode}: {}\n{}\n{}",
            result.status,
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
    }
}
