use std::io::{Read, Seek, SeekFrom};

use oci_spec::runtime::LinuxSeccomp;
use seccomp::instruction::*;
use seccomp::seccomp::{Rule, SeccompError, SeccompProgramPlan};
use serde_json::{Value, json};

fn compile(value: Value) -> Vec<Instruction> {
    let spec: LinuxSeccomp = serde_json::from_value(value).unwrap();
    SeccompProgramPlan::try_from(spec)
        .unwrap()
        .try_into()
        .unwrap()
}

fn spec(arch: &str, rules: Value) -> Value {
    json!({"defaultAction":"SCMP_ACT_ERRNO", "defaultErrnoRet":1,
        "architectures":[arch], "syscalls":rules})
}

fn cmp(index: u32, op: &str, value: u64, two: u64) -> Value {
    json!({"index":index, "op":op, "value":value, "valueTwo":two})
}

fn rule(names: Value, args: Value) -> Value {
    json!({"names":names, "action":"SCMP_ACT_ALLOW", "args":args})
}

// Execute complete programs rather than asserting individual jump offsets.
fn run(program: &[Instruction], nr: u32, arch: u32, args: [u64; 6]) -> u32 {
    let mut data = [0u8; 64];
    data[..4].copy_from_slice(&nr.to_le_bytes());
    data[4..8].copy_from_slice(&arch.to_le_bytes());
    for (i, arg) in args.iter().enumerate() {
        data[16 + 8 * i..24 + 8 * i].copy_from_slice(&arg.to_le_bytes());
    }
    let (mut pc, mut accumulator) = (0usize, 0u32);
    for _ in 0..4096 {
        let insn = program.get(pc).expect("jump outside program");
        pc += 1;
        let k = insn.multiuse_field;
        match insn.code {
            0x20 => {
                accumulator =
                    u32::from_le_bytes(data[k as usize..k as usize + 4].try_into().unwrap())
            }
            0x54 => accumulator &= k,
            0x05 => pc += k as usize,
            0x15 | 0x25 | 0x35 | 0x45 => {
                let yes = match insn.code {
                    0x15 => accumulator == k,
                    0x25 => accumulator > k,
                    0x35 => accumulator >= k,
                    _ => accumulator & k != 0,
                };
                pc += usize::from(if yes {
                    insn.offset_jump_true
                } else {
                    insn.offset_jump_false
                });
            }
            0x06 => return k,
            other => panic!("unsupported test-interpreter opcode {other:#x}"),
        }
    }
    panic!("program did not terminate")
}

const ARCHES: [(&str, u32, u32, u32); 2] = [
    ("SCMP_ARCH_X86_64", AUDIT_ARCH_X86_64, 39, 110),
    ("SCMP_ARCH_AARCH64", AUDIT_ARCH_AARCH64, 172, 173),
];
const VALUES: [u64; 10] = [
    0,
    1,
    7,
    8,
    9,
    u32::MAX as u64,
    1 << 32,
    (1 << 32) + 8,
    1 << 63,
    u64::MAX,
];
const OPS: [&str; 7] = [
    "SCMP_CMP_EQ",
    "SCMP_CMP_NE",
    "SCMP_CMP_LT",
    "SCMP_CMP_LE",
    "SCMP_CMP_GT",
    "SCMP_CMP_GE",
    "SCMP_CMP_MASKED_EQ",
];

fn matches(op: &str, input: u64, value: u64, two: u64) -> bool {
    match op {
        "SCMP_CMP_EQ" => input == value,
        "SCMP_CMP_NE" => input != value,
        "SCMP_CMP_LT" => input < value,
        "SCMP_CMP_LE" => input <= value,
        "SCMP_CMP_GT" => input > value,
        "SCMP_CMP_GE" => input >= value,
        _ => input & value == two,
    }
}

#[test]
fn all_operators_match_unsigned_64_bit_semantics_on_both_architectures() {
    for (name, arch, nr, _) in ARCHES {
        for op in OPS {
            for value in VALUES {
                let two = value & 0x8000_0001_0000_0002;
                for index in 0..6 {
                    let program = compile(spec(
                        name,
                        json!([rule(json!(["getpid"]), json!([cmp(index, op, value, two)]))]),
                    ));
                    let mut inputs = VALUES.to_vec();
                    inputs.extend([value.wrapping_sub(1), value.wrapping_add(1), two]);
                    let mut seed = value ^ 0xa138_4462_ead0_3457;
                    for _ in 0..64 {
                        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                        inputs.push(seed);
                    }
                    for input in inputs {
                        let mut args = [0; 6];
                        args[index as usize] = input;
                        let expected = if matches(op, input, value, two) {
                            SECCOMP_RET_ALLOW
                        } else {
                            SECCOMP_RET_ERRNO | 1
                        };
                        assert_eq!(
                            run(&program, nr, arch, args),
                            expected,
                            "{name} {op} index={index} value={value:#x} input={input:#x}"
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn masked_eq_checks_value_two_and_both_halves() {
    for (name, arch, nr, _) in ARCHES {
        for (mask, two) in [(3, 2), (0x100000003, 0x100000002), (0, 0), (3, 4)] {
            let program = compile(spec(
                name,
                json!([rule(
                    json!(["getpid"]),
                    json!([cmp(0, "SCMP_CMP_MASKED_EQ", mask, two)])
                )]),
            ));
            for input in [0, 1, 2, 3, 4, 0x100000002, 0x200000002] {
                let expected = if input & mask == two {
                    SECCOMP_RET_ALLOW
                } else {
                    SECCOMP_RET_ERRNO | 1
                };
                assert_eq!(run(&program, nr, arch, [input, 0, 0, 0, 0, 0]), expected);
            }
        }
    }
}

#[test]
fn distinct_arguments_are_anded_and_each_syscall_name_gets_the_conditions() {
    for (name, arch, nr, other) in ARCHES {
        let program = compile(spec(
            name,
            json!([rule(
                json!(["getpid", "getppid"]),
                json!([
                    cmp(0, "SCMP_CMP_EQ", 8, 0),
                    cmp(5, "SCMP_CMP_MASKED_EQ", 3, 2)
                ])
            )]),
        ));
        for call in [nr, other] {
            for a in [7, 8, 9] {
                for b in [0, 2, 3, 6] {
                    let expected = if a == 8 && b & 3 == 2 {
                        SECCOMP_RET_ALLOW
                    } else {
                        SECCOMP_RET_ERRNO | 1
                    };
                    assert_eq!(run(&program, call, arch, [a, 0, 0, 0, 0, b]), expected);
                }
            }
        }
    }
}

#[test]
fn repeated_argument_indexes_follow_libcontainers_separate_rule_behavior() {
    for (name, arch, nr, _) in ARCHES {
        let program = compile(spec(
            name,
            json!([rule(
                json!(["getpid"]),
                json!([
                    cmp(0, "SCMP_CMP_EQ", 8, 0),
                    cmp(0, "SCMP_CMP_EQ", 9, 0),
                    cmp(1, "SCMP_CMP_EQ", 3, 0)
                ])
            )]),
        ));
        for (a, b) in [(8, 0), (9, 0), (1, 3), (1, 0)] {
            let expected = if a == 8 || a == 9 || b == 3 {
                SECCOMP_RET_ALLOW
            } else {
                SECCOMP_RET_ERRNO | 1
            };
            assert_eq!(run(&program, nr, arch, [a, b, 0, 0, 0, 0]), expected);
        }
    }
}

#[test]
fn failed_conditions_do_not_poison_later_rules_or_syscall_numbers() {
    for (name, arch, nr, other) in ARCHES {
        let program = compile(spec(
            name,
            json!([
                rule(json!(["getpid"]), json!([cmp(0, "SCMP_CMP_EQ", 8, 0)])),
                rule(json!(["getppid"]), json!([])),
                rule(json!(["getpid"]), json!([cmp(0, "SCMP_CMP_EQ", 9, 0)]))
            ]),
        ));
        for (call, a, allowed) in [
            (nr, 8, true),
            (nr, 9, true),
            (nr, 7, false),
            (other, 7, true),
            (nr, other as u64, false),
        ] {
            assert_eq!(
                run(&program, call, arch, [a, 0, 0, 0, 0, 0]),
                if allowed {
                    SECCOMP_RET_ALLOW
                } else {
                    SECCOMP_RET_ERRNO | 1
                }
            );
        }
    }
}

#[test]
fn long_syscall_lists_and_long_argument_blocks_have_valid_jumps() {
    for count in [251, 252, 253, 254, 255, 256, 600] {
        let plan = SeccompProgramPlan {
            arc: Arch::X86,
            def_action: SECCOMP_RET_ERRNO | 1,
            flags: vec![],
            rules: vec![Rule {
                syscall: (0..count).collect(),
                action: SECCOMP_RET_ALLOW,
                args: vec![serde_json::from_value(cmp(0, "SCMP_CMP_EQ", 8, 0)).unwrap(); 40],
            }],
        };
        let p: Vec<Instruction> = plan.try_into().unwrap();
        for nr in 0..=count as u32 {
            for a in [7, 8] {
                let expected = if nr < count as u32 && a == 8 {
                    SECCOMP_RET_ALLOW
                } else {
                    SECCOMP_RET_ERRNO | 1
                };
                assert_eq!(run(&p, nr, AUDIT_ARCH_X86_64, [a, 0, 0, 0, 0, 0]), expected);
            }
            assert_eq!(
                run(&p, nr, AUDIT_ARCH_AARCH64, [8, 0, 0, 0, 0, 0]),
                SECCOMP_RET_KILL_PROCESS
            );
        }
    }
}

#[test]
fn architecture_guard_is_independent_of_default_and_x32_is_x86_only() {
    for (name, arch, _, _) in ARCHES {
        let mut s = spec(name, json!([]));
        s["defaultAction"] = json!("SCMP_ACT_ALLOW");
        let p = compile(s);
        assert_eq!(run(&p, 39, 0x40000003, [0; 6]), SECCOMP_RET_KILL_PROCESS);
        assert_eq!(
            run(&p, X32_SYSCALL_BIT, arch, [0; 6]),
            if arch == AUDIT_ARCH_X86_64 {
                SECCOMP_RET_ERRNO | 38
            } else {
                SECCOMP_RET_ALLOW
            }
        );
    }
}

#[test]
fn errno_and_trace_preserve_their_data_and_default_to_eperm() {
    for action in ["SCMP_ACT_ERRNO", "SCMP_ACT_TRACE"] {
        let base = if action == "SCMP_ACT_ERRNO" {
            SECCOMP_RET_ERRNO
        } else {
            SECCOMP_RET_TRACE
        };
        for value in [None, Some(0), Some(42), Some(65535)] {
            let mut s = spec("SCMP_ARCH_X86_64", json!([]));
            s["defaultAction"] = json!(action);
            s.as_object_mut().unwrap().remove("defaultErrnoRet");
            if let Some(v) = value {
                s["defaultErrnoRet"] = json!(v);
            }
            assert_eq!(
                run(&compile(s), 39, AUDIT_ARCH_X86_64, [0; 6]),
                base | value.unwrap_or(1)
            );
            let mut entry = json!({"names":["getpid"],"action":action});
            if let Some(v) = value {
                entry["errnoRet"] = json!(v);
            }
            let mut s = spec("SCMP_ARCH_X86_64", json!([entry]));
            s["defaultAction"] = json!("SCMP_ACT_ALLOW");
            assert_eq!(
                run(&compile(s), 39, AUDIT_ARCH_X86_64, [0; 6]),
                base | value.unwrap_or(1)
            );
        }
    }
}

#[test]
fn unsupported_configuration_is_rejected_before_installation() {
    let mut cases = Vec::new();
    for index in [6, 256, 65536] {
        cases.push(spec(
            "SCMP_ARCH_X86_64",
            json!([rule(
                json!(["getpid"]),
                json!([cmp(index, "SCMP_CMP_EQ", 0, 0)])
            )]),
        ));
    }
    cases.push(spec("SCMP_ARCH_X86", json!([])));
    let mut multi = spec("SCMP_ARCH_X86_64", json!([]));
    multi["architectures"] = json!(["SCMP_ARCH_X86_64", "SCMP_ARCH_AARCH64"]);
    cases.push(multi);
    cases.push(spec(
        "SCMP_ARCH_X86_64",
        json!([
            rule(json!(["getpid"]),json!([])), {"names":["getpid"],"action":"SCMP_ACT_TRAP"}
        ]),
    ));
    let mut bad_data = spec("SCMP_ARCH_X86_64", json!([]));
    bad_data["defaultErrnoRet"] = json!(65536);
    cases.push(bad_data);
    for s in cases {
        assert!(
            SeccompProgramPlan::try_from(
                serde_json::from_value::<LinuxSeccomp>(s.clone()).unwrap()
            )
            .is_err(),
            "accepted {s}"
        );
    }
    let plan = SeccompProgramPlan {
        arc: Arch::X86,
        def_action: SECCOMP_RET_ALLOW,
        flags: vec![],
        rules: vec![Rule {
            syscall: (0..5000).collect(),
            action: SECCOMP_RET_ERRNO | 1,
            args: vec![],
        }],
    };
    assert!(matches!(
        Vec::<Instruction>::try_from(plan),
        Err(SeccompError::InvalidProgramSize(_))
    ));
}

#[test]
fn native_architecture_and_listener_flags_are_selected_explicitly() {
    let s = json!({"defaultAction":"SCMP_ACT_ALLOW","syscalls":[{"names":["getpid"],"action":"SCMP_ACT_NOTIFY"}]});
    let plan =
        SeccompProgramPlan::try_from(serde_json::from_value::<LinuxSeccomp>(s).unwrap()).unwrap();
    assert_eq!(plan.arc, Arch::native().unwrap());
    assert!(
        plan.flags
            .contains(&nix::libc::SECCOMP_FILTER_FLAG_NEW_LISTENER)
    );
}

#[test]
fn decisions_match_libseccomp_for_each_operator() {
    use libseccomp::{ScmpAction, ScmpArgCompare, ScmpCompareOp, ScmpFilterContext, ScmpSyscall};
    let (name, arch, nr, _) = if Arch::native().unwrap() == Arch::X86 {
        ARCHES[0]
    } else {
        ARCHES[1]
    };
    for op in OPS {
        for value in VALUES {
            let two = value & 0x8000_0001_0000_0002;
            let ours = compile(spec(
                name,
                json!([rule(json!(["getpid"]), json!([cmp(0, op, value, two)]))]),
            ));
            let mut ctx = ScmpFilterContext::new(ScmpAction::Errno(1)).unwrap();
            let compare = match op {
                "SCMP_CMP_EQ" => ScmpCompareOp::Equal,
                "SCMP_CMP_NE" => ScmpCompareOp::NotEqual,
                "SCMP_CMP_LT" => ScmpCompareOp::Less,
                "SCMP_CMP_LE" => ScmpCompareOp::LessOrEqual,
                "SCMP_CMP_GT" => ScmpCompareOp::Greater,
                "SCMP_CMP_GE" => ScmpCompareOp::GreaterEqual,
                _ => ScmpCompareOp::MaskedEqual(value),
            };
            ctx.add_rule_conditional(
                ScmpAction::Allow,
                ScmpSyscall::from_name("getpid").unwrap(),
                &[ScmpArgCompare::new(
                    0,
                    compare,
                    if op == "SCMP_CMP_MASKED_EQ" {
                        two
                    } else {
                        value
                    },
                )],
            )
            .unwrap();
            let mut file = tempfile::tempfile().unwrap();
            ctx.export_bpf(&file).unwrap();
            file.seek(SeekFrom::Start(0)).unwrap();
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes).unwrap();
            let reference: Vec<Instruction> = bytes
                .chunks_exact(8)
                .map(|b| Instruction {
                    code: u16::from_ne_bytes(b[..2].try_into().unwrap()),
                    offset_jump_true: b[2],
                    offset_jump_false: b[3],
                    multiuse_field: u32::from_ne_bytes(b[4..8].try_into().unwrap()),
                })
                .collect();
            for input in
                VALUES
                    .into_iter()
                    .chain([value.wrapping_sub(1), value.wrapping_add(1), two])
            {
                let args = [input, 0, 0, 0, 0, 0];
                assert_eq!(
                    run(&ours, nr, arch, args),
                    run(&reference, nr, arch, args),
                    "{op} value={value:#x} input={input:#x}"
                );
            }
        }
    }
}
