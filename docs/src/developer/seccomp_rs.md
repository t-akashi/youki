# seccomp-rs (experimental)

`seccomp-rs` is an experimental, pure Rust seccomp backend for libcontainer.
It lets youki build seccomp filters without the C library
[libseccomp](https://github.com/seccomp/libseccomp), which makes static builds
(e.g. with musl) easier. See also
[issue #2724](https://github.com/youki-dev/youki/issues/2724).

The backend is a drop-in replacement for the subset of the
[`libseccomp` crate](https://crates.io/crates/libseccomp) API that youki uses.
The code that converts the OCI seccomp profile
(`crates/libcontainer/src/seccomp/mod.rs`) is the same for both backends. Only
its imports change.

## Usage

The backend is chosen by cargo features.

| crate        | feature      | backend                                                |
| ------------ | ------------ | ------------------------------------------------------ |
| libcontainer | `libseccomp` | libseccomp crate (default)                             |
| libcontainer | `seccomp-rs` | pure Rust backend                                      |
| libcontainer | `seccomp`    | internal umbrella feature, enabled by either backend   |
| youki        | `seccomp`    | enables `libcontainer/libseccomp`                      |
| youki        | `seccomp-rs` | enables `libcontainer/seccomp-rs`                      |

If both backends are enabled, `seccomp-rs` is used. Code outside the seccomp
module is gated by `#[cfg(feature = "seccomp")]`, so it doesn't depend on which
backend is selected.

```console
# build youki without libseccomp
$ cargo build -p youki --no-default-features --features v1,v2,systemd,seccomp-rs
$ ./target/debug/youki info | grep seccomp
seccomp: builtin (seccomp-rs)

# run the seccomp tests with the pure Rust backend only
$ cargo test -p libcontainer --lib --no-default-features \
    --features v1,v2,systemd,seccomp-rs -- seccomp

# run the tests with both backends, including the differential tests
$ cargo test -p libcontainer --lib --features seccomp-rs -- seccomp
```

## Architecture

```text
crates/libcontainer/src/seccomp/
├── mod.rs            OCI LinuxSeccomp -> rules (shared by both backends)
└── scmp/             libseccomp-compatible API (seccomp-rs)
    ├── mod.rs        public re-exports
    ├── error.rs      error::SeccompError
    ├── types.rs      ScmpAction, ScmpArch, ScmpCompareOp, ScmpArgCompare, ScmpSyscall
    ├── arch.rs       supported architectures, syscall name -> number
    ├── compiler.rs   rules -> classic BPF program (+ test-only BPF interpreter)
    ├── context.rs    ScmpFilterContext (rule database, load)
    └── difftest.rs   differential tests against libseccomp (test only)

experiment/seccomp/   low-level parts reused by scmp
    instruction/      Instruction (sock_filter), BPF_*, SECCOMP_RET_*, AUDIT_ARCH_*,
                      seccomp_data offsets
    seccomp.rs        Seccomp { filters, flags }::apply() -> seccomp(2)
```

Backend selection in `seccomp/mod.rs`:

```rust
#[cfg(feature = "seccomp-rs")]
mod scmp;

#[cfg(not(feature = "seccomp-rs"))]
use libseccomp as backend;
#[cfg(feature = "seccomp-rs")]
use scmp as backend;

use backend::{ScmpAction, ScmpArch, ScmpArgCompare, ScmpCompareOp, ScmpFilterContext, ScmpSyscall};
```

libcontainer uses the `seccomp` crate in `experiment/seccomp` as a path
dependency, renamed to `youki-seccomp` so that its name doesn't clash with the
`seccomp` feature or the `crate::seccomp` module. Only its low-level parts are
reused. `SeccompProgramPlan` and `Rule` from that crate are not used, because
they can only hold one action and one argument comparison.

### API subset

| API | Notes |
| --- | --- |
| `ScmpFilterContext::new(default)` | The native architecture is added automatically. |
| `add_arch(arch)` | Adding an architecture that is already present is not an error. Unsupported architectures return `UnsupportedArch`. |
| `add_rule(action, syscall)` / `add_rule_conditional(action, syscall, &[cmp])` | Comparisons are ANDed. Each rule allows at most 6 comparisons, argument index 0-5, and each index at most once. Using the default action returns an error. |
| `set_ctl_nnp/tsync/log/ssb/waitkill(bool)` | Filter attributes. `nnp` defaults to `true`, as in libseccomp. |
| `load()` | Compiles the filter, sets no_new_privs if `nnp` is true, then calls `seccomp(SECCOMP_SET_MODE_FILTER)`. |
| `get_notify_fd()` | Returns the listener fd if the filter has a `Notify` rule. The fd is not closed by the context. |
| `ScmpSyscall::from_name(name)` | Succeeds if any supported architecture knows the name, like libseccomp's pseudo syscalls. Numbers are resolved for each architecture at compile time. |
| `ScmpArgCompare::new(arg, op, datum)` | `MaskedEqual(mask)` means `(arg & mask) == datum`, the same as the libseccomp crate. |

### Rule semantics

These follow libseccomp, and the differential tests check them:

- For each syscall, conditional rules are checked first, in the order they
  were added (OR, the first match wins). Then the unconditional rule applies,
  and if there is none, the default action.
- If several unconditional rules with different actions are added for the same
  syscall, the **first one wins** and the rest are ignored silently. The moby
  profile depends on this: `clone3` has both `ALLOW` and `ERRNO(ENOSYS)`.
- A syscall that doesn't exist on an architecture is skipped for that
  architecture.
- Argument comparisons are unsigned and 64 bits wide. On 32-bit architectures
  (x86, arm) only the lower 32 bits are compared.
- If the architecture doesn't match, or an x32 syscall arrives while x32 isn't
  in the filter, the bad-arch action (`KillThread`, libseccomp's default) is
  returned.

### Generated BPF program

```text
    ld  [arch]
    ; for each AUDIT_ARCH value
    jeq #AUDIT_ARCH, +1, +0
    ja  next_arch
    ld  [nr]
    ; x86_64 only: nr >= X32_SYSCALL_BIT -> x32 section (or bad arch)
    ; unconditional rules, grouped by action, chunks of <= 254 syscalls
    jeq #nr_0, ret_a, +0
    ...
    ja  after
ret_a:
    ret #action
after:
    ; syscalls with conditional rules
    jeq #nr, +1, +0
    ja  next_syscall
    <argument checks of rule 0, jump to next_rule on mismatch>
    ret #action_0
next_rule:
    ...
    ret #unconditional_action_or_default
next_syscall:
    ...
    ret #default
next_arch:
    ...
    ret #bad_arch
```

- The program is emitted by a small assembler with labels.
  - Conditional jumps (`jt`/`jf`, 8 bits) only target nearby labels.
  - Long jumps always use `BPF_JA`, which has a 32-bit offset, so large
    profiles don't overflow jump offsets.
  - An offset that is still out of range returns `JumpOutOfRange`.
  - A program longer than `BPF_MAXINSNS` (4096) returns `FilterTooLarge`.
- A 64-bit comparison checks the upper word first, then the lower word.
  `MaskedEqual` applies `BPF_ALU|BPF_AND` to each word before the compare.
- Filter flags:
  - `LOG`, `SPEC_ALLOW` and `TSYNC` come from the context attributes.
  - `NEW_LISTENER` is added only when there is a `Notify` rule.
  - When `NEW_LISTENER` is set, `TSYNC_ESRCH` is added together with `TSYNC`,
    and `WAIT_KILLABLE_RECV` is applied (it is invalid without a listener).

### Supported architectures

| ScmpArch  | AUDIT_ARCH          | syscall table                                          |
| --------- | ------------------- | ------------------------------------------------------ |
| `X8664`   | `AUDIT_ARCH_X86_64` | `syscalls::x86_64`                                     |
| `X32`     | `AUDIT_ARCH_X86_64` | x86_64 numbers \| `X32_SYSCALL_BIT`, x32-specific numbers 512-547 |
| `X86`     | `AUDIT_ARCH_I386`   | `syscalls::x86`                                        |
| `Aarch64` | `AUDIT_ARCH_AARCH64`| `syscalls::aarch64`                                    |
| `Arm`     | `AUDIT_ARCH_ARM`    | `syscalls::arm`                                        |

`Native` resolves to the architecture of the build target (x86_64, aarch64,
x86 or arm). Other architectures are rejected by `add_arch()`.

## Testing

- **Unit tests** (`scmp/{types,arch,context,compiler}.rs`): a minimal classic BPF
  interpreter runs the generated programs on synthetic `seccomp_data`. The
  tests cover:
  - every operator at 64-bit boundary values, on 64-bit and 32-bit
    architectures
  - AND within a rule and OR across rules
  - bad-arch and x32 handling
  - more than 254 syscalls with the same action
  - the instruction limit
- **Differential tests** (`scmp/difftest.rs`, built only when both backends are
  enabled): they build the same profile with libseccomp (`export_bpf`) and with
  seccomp-rs, run both programs in the interpreter, and assert they return the
  same value. The inputs are every syscall number (also x32 numbers and a
  foreign architecture) plus argument values around each comparison datum.
  Profiles covered:
  - the moby fixture
  - an all-operator profile
  - conflicting unconditional rules
- **Existing tests** in `seccomp/mod.rs` (`test_basic`, `test_moby`,
  `test_seccomp_notify`, ...) load the filter into the kernel in a child
  process. They pass with either backend.

## Out of scope

- Architectures other than x86_64, x86, x32, aarch64 and arm (mips, ppc, s390,
  riscv64, loongarch64, ...).
- The multiplexed `socketcall(2)` and `ipc(2)` syscalls on x86. A rule on
  `socket` only matches the direct syscall, while libseccomp also adds the
  multiplexed form.
- libseccomp APIs that youki doesn't use: the notification receive/respond API
  (youki only passes the fd on), syscall priorities, changing the bad-arch
  action, binary-tree optimization, `export_bpf`/`export_pfc`, `add_rule_exact`.

## Remaining issues / TODO

- [ ] **E2E tests**: run the `tests/contest` seccomp and seccomp_notify tests,
  and the runtime-tools tests, with a youki binary built with `seccomp-rs`.
- [ ] **Static musl build**: build and run a static musl binary without
  libseccomp.
- [ ] **Publishing**: libcontainer depends on `experiment/seccomp` through a
  path dependency with no version, so `cargo publish` of libcontainer fails.
  Possible fixes:
  - move the low-level parts into a workspace crate (e.g. `crates/`), or
    vendor them into libcontainer;
  - align its dependency versions with the workspace (it still uses nix 0.29
    and oci-spec 0.9, so duplicate versions get built).
- [ ] **Clean up `experiment/seccomp`**: drop or fix `SeccompProgramPlan`/`Rule`
  (single action, `MaskedEqual` implemented with `BPF_JSET`, `unwrap()` on
  unknown syscalls), and `NotifyFd`'s `Drop` that calls `close().unwrap()`. The
  current wrapper avoids that `Drop` with `into_raw_fd()`.
- [ ] **Possible bug in `translate_op` (both backends)**: for
  `SCMP_CMP_MASKED_EQ`, youki passes `valueTwo` as the mask and `value` as the
  datum. runc and Docker use `value` as the mask and `valueTwo` as the datum.
  With the moby profile's `clone` rule (`value: 2114060288`, no `valueTwo`) the
  condition becomes `(arg & 0) == 0x7E020000`, which never matches. This needs
  confirmation and a separate fix.
- [ ] **Overlapping conditional rules**: when conditional rules for one syscall
  overlap, seccomp-rs picks the first one added. libseccomp merges rules into
  a decision tree, so the results can differ for overlapping conditions with
  different actions. This case isn't in the differential tests yet.
- [ ] **Datum wider than 32 bits on 32-bit architectures**: the upper bits are
  ignored silently. libseccomp's exact behavior should be checked.
- [ ] **Program size**: the layout is linear. Large profiles with many
  architectures and conditional rules may hit `BPF_MAXINSNS` earlier than with
  libseccomp's optimized output. A binary search over syscall numbers would
  help.
- [ ] **Syscall tables**: names come from the `syscalls` crate (0.6.18).
  Syscalls newer than that crate are reported as unknown and skipped (with a
  warning), while an up-to-date libseccomp would know them.
- [ ] **Default backend**: decide when `seccomp-rs` can become the default and
  when the libseccomp backend can be removed.
- [ ] **Flaky test (unrelated?)**: running the libseccomp-backend `seccomp` and
  `process::fork` tests together once hung in a forked child that was waiting
  on a futex with no seccomp filter loaded. That looks like a
  fork-in-a-multithreaded-test deadlock. The tests pass when run separately.
  Not yet checked against the code before this change.
