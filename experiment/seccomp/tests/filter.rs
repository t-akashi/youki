use std::os::fd::AsRawFd;
use std::process::Command;
use std::sync::{Arc, Barrier, mpsc};

use nix::libc;
use seccomp::instruction::*;
use seccomp::seccomp::{NotifyFd, Seccomp, SeccompError, SeccompProgramPlan};
use serde_json::json;

fn filter(value: serde_json::Value) -> Seccomp {
    let spec: oci_spec::runtime::LinuxSeccomp = serde_json::from_value(value).unwrap();
    let plan = SeccompProgramPlan::try_from(spec).unwrap();
    let mut filter = Seccomp::new();
    filter.set_flags(plan.flags.clone());
    filter.filters = plan.try_into().unwrap();
    filter
}

fn worker(mode: &str) {
    // Every filter is installed in a subprocess. A broken notification path
    // must fail the test instead of waiting forever.
    unsafe {
        libc::alarm(10);
    }
    prctl::set_no_new_privileges(true).unwrap();
    match mode {
        "plain" | "wait-without-listener" => {
            let input = std::fs::File::open("/dev/null").unwrap();
            assert_eq!(unsafe { libc::dup2(input.as_raw_fd(), 0) }, 0);
            let mut f = filter(json!({"defaultAction":"SCMP_ACT_ALLOW", "syscalls":[{
                "names":["getpid"],"action":"SCMP_ACT_ERRNO","errnoRet":99,
                "args":[{"index":0,"op":"SCMP_CMP_EQ","value":8}]
            }]}));
            if mode == "wait-without-listener" {
                f.flags |= libc::SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV;
            }
            assert!(f.apply().unwrap().is_none());
            assert_ne!(
                unsafe { libc::fcntl(0, libc::F_GETFD) },
                -1,
                "stdin was closed"
            );
            assert_eq!(unsafe { libc::syscall(libc::SYS_getpid, 8u64) }, -1);
            assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(99));
            assert!(unsafe { libc::syscall(libc::SYS_getpid, 7u64) } > 0);
        }
        "notify" => {
            let (sender, receiver) = mpsc::channel::<NotifyFd>();
            // Started before the caller is filtered, so the supervisor is not filtered.
            let supervisor = std::thread::spawn(move || {
                let fd = receiver.recv().unwrap();
                let request = fd.recv().unwrap().notif;
                assert_eq!(request.data.nr, libc::SYS_getpid as i32);
                fd.success(4242, request.id).unwrap();
            });
            let f = filter(json!({"defaultAction":"SCMP_ACT_ALLOW", "syscalls":[{
                "names":["getpid"],"action":"SCMP_ACT_NOTIFY"
            }]}));
            sender
                .send(f.apply().unwrap().expect("listener fd"))
                .unwrap();
            assert_eq!(unsafe { libc::syscall(libc::SYS_getpid) }, 4242);
            supervisor.join().unwrap();
        }
        "notify-tsync" => {
            let mut f = filter(json!({"defaultAction":"SCMP_ACT_ALLOW", "syscalls":[{
                "names":["getpid"],"action":"SCMP_ACT_NOTIFY"
            }]}));
            f.flags |= libc::SECCOMP_FILTER_FLAG_TSYNC;
            let fd = f.apply().unwrap().expect("listener fd");
            // No call needing a response after this install. Verify the fd is real.
            assert_ne!(unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) }, -1);
            drop(fd);
        }
        "tsync-failure" => {
            let ready = Arc::new(Barrier::new(2));
            let finish = Arc::new(Barrier::new(2));
            let (r, f) = (ready.clone(), finish.clone());
            let divergent = std::thread::spawn(move || {
                let own = filter(json!({"defaultAction":"SCMP_ACT_ALLOW"}));
                assert!(own.apply().unwrap().is_none());
                r.wait();
                f.wait();
            });
            ready.wait();
            let mut f = filter(json!({"defaultAction":"SCMP_ACT_ALLOW"}));
            f.flags |= libc::SECCOMP_FILTER_FLAG_TSYNC;
            let result = f.apply();
            finish.wait();
            divergent.join().unwrap();
            assert!(matches!(result,Err(SeccompError::ThreadSync(tid)) if tid>0));
        }
        _ => unreachable!(),
    }
    unsafe {
        libc::_exit(0);
    }
}

#[test]
fn filter_installation_and_notifications() {
    if let Ok(mode) = std::env::var("YOUKI_SECCOMP_TEST_WORKER") {
        worker(&mode);
    }
    for mode in [
        "plain",
        "wait-without-listener",
        "notify",
        "notify-tsync",
        "tsync-failure",
    ] {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "filter_installation_and_notifications",
                "--nocapture",
            ])
            .env("YOUKI_SECCOMP_TEST_WORKER", mode)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{mode}: {}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn invalid_program_lengths_are_rejected_before_the_syscall() {
    for len in [0, 4097, 65537] {
        let f = Seccomp {
            filters: vec![Instruction::stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW); len],
            flags: 0,
        };
        assert!(matches!(f.apply(),Err(SeccompError::InvalidProgramSize(n)) if n==len));
    }
}
