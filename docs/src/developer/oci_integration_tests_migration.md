# Migrating OCI integration tests to contest

This page is a development record of the effort to re-implement the
[runtime-tools](./e2e/runtime_tools.md) validation tests (written in Go) as
[contest](./e2e/rust_oci_test.md) test cases (written in Rust). It describes
the current status, the implementation policy, the rationale behind it and the
remaining work.

## Background and goal

`scripts/oci_integration_tests.sh` runs a subset of the Go validation tests
located in `tests/oci-runtime-tests/src/github.com/opencontainers/runtime-tools/validation`.
Some of them have already been re-implemented in contest
(`tests/contest/contest/`) and are commented out in the script, but several of
the cases still enabled in the script turned out to have an equivalent contest
test as well.

The goal is:

1. Identify the cases that are already covered by contest and drop them from
   the script.
2. Implement the remaining cases in contest.
3. Eventually empty the `test_cases` list in `oci_integration_tests.sh` and
   remove the dependency on the Go test suite from CI.

## Status

### A. Already covered by contest (only the script needs updating)

| Go test | contest group | Notes |
|---|---|---|
| create | `create` (`lifecycle/container_create.rs`) | empty_id / valid_id / duplicate_id |
| state | `state` (`state/state_test.rs`) | without_id / nonexistent / created |
| kill_no_effect | `kill_no_effect` | |
| killsig | `killsig` | same signal set (TERM, USR1, USR2) |
| prestart / prestart_fail | `prestart` / `prestart_fail` | |
| poststart / poststart_fail | `poststart` / `poststart_fail` | |
| poststop / poststop_fail | `poststop` / `poststop_fail` | `poststop_fail` checks youki's current behavior, see runtime-spec#1309 |
| process_capabilities | `process_capabilities` | grants all capabilities and validates them with runtimetest |

### B. Partially covered (needs additional tests)

| Go test | Existing contest test | Missing |
|---|---|---|
| mounts | `mount_propagation` (bind/rbind with shared/slave/private variants) | tmpfs with propagation flags, `unbindable` / `runbindable` |
| linux_cgroups_relative_pids | `cgroup_v2_pids` (absolute path only) | relative `cgroupsPath` |
| linux_cgroups_relative_memory | `cgroup_v2_memory` (absolute path only) | relative `cgroupsPath` |
| linux_cgroups_relative_cpus | `cgroup_v2_cpu` (absolute path only) | relative `cgroupsPath`, cpuset `cpus` / `mems` |

### C. Not covered yet (new tests)

| Go test | What it checks |
|---|---|
| default | the default config passes the full set of runtimetest validations |
| delete_resources | resources created at `create` are removed at `delete` |
| delete_only_create_resources | resources not created by the container are not removed at `delete` |
| hooks_stdin | the container state is passed to hooks over stdin |
| linux_cgroups_devices / linux_cgroups_relative_devices | `linux.resources.devices` rules (absolute / relative path) |
| linux_cgroups_relative_hugetlb | hugetlb limits with a relative path |
| linux_mount_label | `linux.mountLabel` |
| linux_ns_nopath | namespaces without a path are newly created |
| linux_ns_path | joining existing namespaces via path |
| linux_ns_path_type | a namespace path of the wrong type must be rejected |

### D. Cases already excluded from the script

| Go test | Reason for exclusion | Plan |
|---|---|---|
| linux_process_apparmor_profile | requires a profile named `acme_secure_profile` to be loaded on the host | **Port it.** contest has no AppArmor test yet. The Go test only checks that `<rootfs>/etc/apparmor.d/<profile>` does not exist, which validates almost nothing. The Rust version loads a minimal profile with `apparmor_parser`, checks `/proc/self/attr/current` (or `attr/apparmor/current`) inside the container, and unloads the profile afterwards. Skipped when AppArmor is not available. |
| linux_cgroups_blkio / linux_cgroups_relative_blkio | checks features removed in Linux 5.0; runc fails too | Out of scope |
| misc_props | runc fails too | contest already has `misc_props` |
| start | runc fails too (#56) | Out of scope for now; the spec items (start without ID, start on a non-`created` container, unset process) are a candidate for a follow-up |
| others (hooks, pidfile, linux_ns_itype, ...) | already implemented in contest | — |

## Implementation policy

### cgroup v2 only

contest dropped its cgroup v1 tests (#3727) and the CI runners use cgroup v2.
The cgroup helpers of runtime-tools (`util.ValidateLinuxResources*`,
`cgroups.FindCgroup`) only support cgroup v1, so on CI those Go tests report
"cgroupv2 is not supported yet" and are effectively skipped. Porting them
verbatim would bring back v1-only code nobody runs. Instead, each test is
re-implemented to check the intent of the spec on cgroup v2:

- Relative `cgroupsPath` is resolved by the runtime (the result differs between
  the cgroupfs and systemd managers), so the actual cgroup of the container is
  looked up from `/proc/<pid>/cgroup` instead of being computed by the test.
- Options that have no cgroup v2 equivalent (`swappiness`, `kernel`,
  `kernelTCP`, `disableOOMKiller`) are not tested.
- Device rules are enforced with eBPF on cgroup v2 and cannot be read back from
  the cgroup filesystem, so they are validated by trying to access device nodes
  from inside the container (allowed access succeeds, denied access fails with
  `EPERM`).

### Environment dependent tests

contest already supports conditional tests:
`test_framework::ConditionalTest` takes a predicate, and when it returns
`false` the test is reported as `Skipped`. `scripts/contest.sh` only fails on
`not ok`, so skipped tests do not break CI. Existing predicates include the
cgroup `can_run()` helpers (`is_cgroup_v2_with_controller`, `cgroup_has_file`),
`check_hugetlb`, `check_numa`, `criu_installed`, and `!is_runtime_runc()` for
known runc differences.

No test is currently conditional on AppArmor or SELinux. youki itself does not
support SELinux yet (it only adds `context=` to mounts when `/sys/fs/selinux`
exists). The following predicates are added under
`tests/contest/contest/src/utils/`:

| Predicate | Condition | Used by |
|---|---|---|
| `is_apparmor_enabled()` | `/sys/module/apparmor/parameters/enabled` is `Y` and `apparmor_parser` is found | linux_process_apparmor_profile |
| `is_selinux_enabled()` | `/sys/fs/selinux/enforce` exists | label check of linux_mount_label |
| `has_command("unshare")` | found with `which` | linux_ns_path |
| `has_hugepages()` | `/sys/kernel/mm/hugepages/*` exists and hugetlb controller is enabled | relative hugetlb |
| `has_min_cpus(n)` | from `cpuset.cpus.effective` | cpuset part of relative cpus |

Environment dependent checks must always be wrapped in `ConditionalTest` so that
they are skipped instead of failing.

### Code structure

- One Go test maps to one module `tests/contest/contest/src/tests/<name>/mod.rs`
  exposing `get_<name>_test(s)() -> TestGroup`, registered in `tests/mod.rs` and
  `main.rs`. cgroup tests go under `tests/cgroups/`.
- Validation inside the container is done with `utils::test_inside_container`
  and a new subcommand of runtimetest (`tests/contest/runtimetest/src/`).
  Validation from the host is done with `utils::test_outside_container`.
- Reuse existing helpers: `tests::lifecycle::ContainerLifecycle`,
  `utils::{prepare_bundle, set_config, create_container, start_container, delete_container, wait_for_state, get_state}`,
  `tests::hooks::{get_hook_output_path, write_log_hook, delete_hook_output_file}`.
- When a case is ported, move it to the "already been implemented in contest"
  block of `scripts/oci_integration_tests.sh` and update the checklist below.
- Keep each ported case in its own commit.

### Notes on deviations from the Go tests

- **hooks_stdin, status passed to prestart hooks**: the Go test expects
  `created`. It was written for runtime-spec v1.0.x, where prestart hooks were
  called by the `start` operation. The current runtime-spec calls them as part
  of the `create` operation, before the container reaches `created`, so both
  youki and runc pass `creating`. The contest version expects `creating`.
  Note that the Go `hooks_stdin.t` reports `not ok` for this against the
  current youki when run locally, so the CI job running it (`just test-oci`
  in `e2e.yaml`) may be failing, or the case may be skipped there; this needs
  to be confirmed by reviewers. If reviewers prefer to keep the original
  expectation (`created`), youki fails this test and the runtime should be
  fixed instead.
- **hooks_stdin, status passed to poststart hooks**: youki passes `running`
  as expected, while runc passes `created`. This is accepted only when
  `RUNTIME_KIND=runc`.

## Steps

### Step 0: housekeeping

- [x] Add this document.
- [x] Move the cases in table A to the "already implemented" block of
      `oci_integration_tests.sh`.

### Step 1: small and independent tests

- [x] linux_ns_path_type (`ns_path_type`): set `/proc/self/ns/<wrong type>` as
      the path for each namespace type and expect `create` to fail. Unlike the
      Go test, it does not start an `unshare` process, as the Go test never
      used it.
- [x] linux_ns_nopath (`ns_nopath`): create all namespaces without a path (with uid/gid
      mappings for the user namespace) and check that every
      `/proc/<pid>/ns/*` inode differs from the host's.
- [x] linux_ns_path (`ns_path`): start `unshare <opt> --fork sleep` in its own process
      group, join its namespace by path (using `pid_for_children` for pid) and
      compare inodes.
- [x] hooks_stdin (`hooks_stdin`): prestart/poststart/poststop hooks save
      their stdin; check id, bundle, pid (except poststop), annotations and
      status. See the note below on the expected status of prestart.

### Step 2: cgroup v2

- [ ] Relative `cgroupsPath` for pids / memory / cpu, plus cpuset `cpus` /
      `mems`.
- [ ] delete_resources: the cgroup created by the runtime is removed after
      `delete`.
- [ ] delete_only_create_resources: a cgroup created by the test, into which
      the container process is moved, is kept after `delete`.
- [ ] hugetlb: `hugetlb.<size>.max` for each available page size, absolute and
      relative path.
- [ ] devices: deny-all plus allow rules (c 10:229 rwm, b 8:20 rw,
      b 10:200 r), validated from inside the container, absolute and relative
      path.

### Step 3: larger or environment dependent tests

- [ ] mounts: add tmpfs with propagation flags and unbindable/runbindable to
      `mount_propagation`.
- [ ] default: runtimetest `validate_default` combining the existing
      validations with default symlinks, default filesystems, default devices
      and `spec.mounts` presence and order.
- [ ] linux_mount_label: the container starts with `mountLabel` set; the
      `security.selinux` label of bind mounts is checked only when SELinux is
      enabled.
- [ ] linux_process_apparmor_profile: see table D; conditional on
      `is_apparmor_enabled()`.

### Step 4: wrap up

- [ ] Once `test_cases` is empty, propose how to handle `just test-oci` and the
      CI workflow (removing the script needs agreement with the maintainers).
- [ ] Consider porting the spec items of `start` as a follow-up.

## Verification

- `cargo fmt` and `cargo clippy` for contest and runtimetest.
- `just contest` and `just contest-list` show the new groups.
- `just test-contest <group>` passes with youki and
  `just validate-contest-runc <group>` passes with runc, which validates the
  test itself.
- Conditional tests are reported as skipped, not as `not ok`, on environments
  that do not meet the condition.
- `scripts/oci_integration_tests.sh` keeps passing after each step.
