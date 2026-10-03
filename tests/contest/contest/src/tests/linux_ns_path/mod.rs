use std::fs;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use nix::sys::signal::{Signal, killpg};
use nix::unistd::Pid;
use oci_spec::runtime::{
    LinuxBuilder, LinuxNamespace, LinuxNamespaceBuilder, LinuxNamespaceType, Spec, SpecBuilder,
    get_default_namespaces,
};
use test_framework::{ConditionalTest, TestGroup, TestResult, test_result};

use crate::utils::test_utils::check_container_created;
use crate::utils::{has_command, test_outside_container};

const NS_WAIT_TIMEOUT: Duration = Duration::from_secs(3);
const NS_WAIT_INTERVAL: Duration = Duration::from_millis(200);

// (namespace name in /proc/<pid>/ns, namespace type, option of unshare(1))
const CASES: [(&str, LinuxNamespaceType, &str); 5] = [
    ("ipc", LinuxNamespaceType::Ipc, "--ipc"),
    ("mnt", LinuxNamespaceType::Mount, "--mount"),
    ("net", LinuxNamespaceType::Network, "--net"),
    ("pid", LinuxNamespaceType::Pid, "--pid"),
    ("uts", LinuxNamespaceType::Uts, "--uts"),
];

/// An `unshare` process holding new namespaces, killed with its children on drop.
struct UnshareProcess {
    child: Child,
}

impl UnshareProcess {
    fn spawn(unshare_opt: &str) -> Result<Self> {
        // Use unshare(1) as a mount namespace cannot be unshared from
        // a multithreaded program. It runs in its own process group so that
        // unshare and its forked child can be killed at once.
        let child = Command::new("unshare")
            .args([unshare_opt, "--fork", "sleep", "10000"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
            .context("failed to run unshare")?;
        Ok(Self { child })
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }
}

impl Drop for UnshareProcess {
    fn drop(&mut self) {
        let _ = killpg(Pid::from_raw(self.child.id() as i32), Signal::SIGKILL);
        let _ = self.child.wait();
    }
}

fn read_ns_link(path: &str) -> Result<PathBuf> {
    fs::read_link(path).with_context(|| format!("failed to read namespace link {path}"))
}

/// Waits until the unshare process switches to a new namespace and returns
/// the path of the namespace.
fn wait_for_new_namespace(unshare_pid: u32, ns: &str) -> Result<String> {
    let host_ns = read_ns_link(&format!("/proc/self/ns/{ns}"))?;
    // Unsharing a pid namespace does not move the process itself into the
    // new namespace, but its children. pid_for_children of the unshare
    // process refers to the new one.
    let unshare_ns_path = if ns == "pid" {
        format!("/proc/{unshare_pid}/ns/pid_for_children")
    } else {
        format!("/proc/{unshare_pid}/ns/{ns}")
    };

    let start = Instant::now();
    loop {
        match read_ns_link(&unshare_ns_path) {
            Ok(unshare_ns) if unshare_ns != host_ns => return Ok(unshare_ns_path),
            Ok(_) | Err(_) if start.elapsed() < NS_WAIT_TIMEOUT => sleep(NS_WAIT_INTERVAL),
            Ok(unshare_ns) => bail!(
                "unshare process did not switch to a new {ns} namespace: {}",
                unshare_ns.display()
            ),
            Err(err) => return Err(err),
        }
    }
}

fn create_spec(typ: LinuxNamespaceType, ns_path: &str) -> Result<Spec> {
    let mut namespaces: Vec<LinuxNamespace> = get_default_namespaces()
        .into_iter()
        .filter(|ns| ns.typ() != typ)
        .collect();
    namespaces.push(
        LinuxNamespaceBuilder::default()
            .typ(typ)
            .path(ns_path)
            .build()
            .context("failed to build namespace")?,
    );

    SpecBuilder::default()
        .linux(
            LinuxBuilder::default()
                .namespaces(namespaces)
                .build()
                .context("failed to build linux spec")?,
        )
        .build()
        .context("failed to build spec")
}

/// The runtime MUST place the container process in the namespace
/// specified by the path.
fn ns_path_test(ns: &str, typ: LinuxNamespaceType, unshare_opt: &str) -> TestResult {
    let unshare = test_result!(UnshareProcess::spawn(unshare_opt));
    let unshare_ns_path = test_result!(wait_for_new_namespace(unshare.pid(), ns));
    let unshare_ns = test_result!(read_ns_link(&unshare_ns_path));
    let spec = test_result!(create_spec(typ, &unshare_ns_path));

    test_outside_container(&spec, &|data| {
        test_result!(check_container_created(&data));
        let pid = match data.state.as_ref().and_then(|s| s.pid) {
            Some(pid) => pid,
            None => return TestResult::Failed(anyhow!("container pid is not available")),
        };
        let container_ns = test_result!(read_ns_link(&format!("/proc/{pid}/ns/{ns}")));
        if container_ns == unshare_ns {
            TestResult::Passed
        } else {
            TestResult::Failed(anyhow!(
                "container is not in the {ns} namespace given by path: expected {}, found {}",
                unshare_ns.display(),
                container_ns.display()
            ))
        }
    })
}

pub fn get_ns_path_tests() -> TestGroup {
    let mut tg = TestGroup::new("ns_path");
    for (ns, typ, unshare_opt) in CASES {
        tg.add(vec![Box::new(ConditionalTest::new(
            ns,
            Box::new(|| has_command("unshare")),
            Box::new(move || ns_path_test(ns, typ, unshare_opt)),
        ))]);
    }
    tg
}
