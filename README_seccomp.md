# Use the OCI compiler with a calculated policy

Heimdall can continue calculating the OCI policy while this compiler builds
the static filter. `experiment/seccomp-youki-adapter` demonstrates the swap
through the existing `SeccompBackend` trait in
[youki#3873](https://github.com/youki-dev/youki/pull/3873), pinned to commit
`c14cf83587d71791db706ea5b7c8aa0f4ce152ba`. The adapter changes no trait methods.
Static and graph filtering remain separate implementations; this example
demonstrates the static compiler.

```console
cargo test --manifest-path experiment/seccomp-youki-adapter/Cargo.toml --locked
cargo run --manifest-path experiment/seccomp-youki-adapter/Cargo.toml --locked -- /path/to/calculated.oci.json
```

The command reads an OCI `LinuxSeccomp` section and compiles it. The test
swaps the adapter and libseccomp at the same `initialize_seccomp_with` call
site, checking syscall decisions and notification descriptors in disposable
children. The example has its own Cargo workspace because this branch's
libcontainer predates #3873. It needs libseccomp development files for the
PR's default backend. Compiler diagnostics are preserved in the source of
the existing `LoadProgram` error variant.

## Build this branch's Youki integration

Build Youki with the backend selected:

```console
cargo build -p youki --no-default-features --features v2,oci_seccomp --locked
```

The backend compiles an OCI `LinuxSeccomp` section into classic BPF. Policy
creation stays with the caller. It accepts calculated syscall lists and
argument restrictions in the same format as manually written OCI profiles.

Run the compiler and installation tests from the repository root:

```console
cargo test -p seccomp --locked
cargo test -p libcontainer --no-default-features --features v2,oci_seccomp --locked --test oci_seccomp_install
```

The compiler tests exercise all seven unsigned 64-bit comparisons, both
supported architectures, multiple conditions, rule fall-through, long jumps,
and libseccomp decision comparisons. Kernel tests run only in disposable
subprocesses, with a timeout for notification failures. They require Linux
with seccomp notification support; listener + TSYNC requires Linux 5.7 or later.
The caller still controls `no_new_privs`, as on Youki's libseccomp path.

## Current scope and gaps

- One x86_64 or aarch64 ABI per program. An omitted architecture means native;
  installation rejects a foreign-only profile. Other ABIs and multi-ABI
  profiles are explicitly rejected until dispatch and syscall translation
  are implemented.
- All conditions on distinct argument indexes must hold. Repeated indexes
  follow libcontainer/runc's convention: add each condition as a separate
  rule. Masked equality is `(argument & value) == valueTwo` on all 64 bits.
  An expected value with bits outside the mask therefore never matches;
  this differs from libseccomp's normalization of such values.
- Rules whose action equals the default are omitted, matching libcontainer.
  Multiple nondefault actions for one syscall are rejected; reproducing
  libseccomp's rule-merging/precedence behavior remains work to do.
- Syscall names absent from the selected architecture's table are reported
  and skipped. Table completeness and future kernel additions need review.
- The input is the final OCI section, not a raw Docker/Podman source profile
  containing capability-dependent `includes`/`excludes` and `archMap` fields.
  Those must be resolved by the container frontend first.
- `Seccomp::apply` returns `None` for ordinary installation and `Some(fd)`
  only for a new notification listener. The experimental `Rule` type now
  retains a vector of OCI argument conditions instead of one condition.
- This branch's Youki binary selects the compiler through `oci_seccomp`.
  The separate adapter example exercises the proposed #3873 interface.
- Heimdall's compiler automatically allows its four base calls
  (`restart_syscall`, `rt_sigreturn`, `exit`, `exit_group`). This compiler
  follows the supplied OCI policy, so a calculated profile must include
  those rules if that behavior is intended. Heimdall's x86_64 wasm-host
  profile already includes all four. This compiler returns ENOSYS for x32
  syscall numbers on x86_64; Heimdall's compiler kills the process.

## Manual container check

With the built binary registered as Podman's `youki` runtime, the existing
`experiment/seccomp/tests/fixtures/test-seccomp.json` should:

- return errno 99 for `mkdir`/`mkdirat`;
- kill the process for `chmod` variants;
- return errno 97 for `socket(AF_INET6, ...)` (argument 0 equals 10), while
  other socket domains retain the ALLOW default;
- run and log `uname`, subject to the host's seccomp audit configuration.

```console
podman run --rm --runtime youki --security-opt seccomp=./experiment/seccomp/tests/fixtures/test-seccomp.json alpine mkdir /tmp/x
```

The backend no longer writes an unconditional `/tmp/filter.prog` debug file.
