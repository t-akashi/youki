//! Compiles seccomp rules into a classic BPF program.
//!
//! Layout of the generated program:
//!
//! ```text
//!     ld  arch
//!     ; for each AUDIT_ARCH value
//!     jeq AUDIT_ARCH, +1, +0
//!     ja  next_arch
//!     ld  nr
//!     ; x86_64 only: dispatch x32 (nr >= X32_SYSCALL_BIT) and x86_64 sections
//!     ; unconditional rules, grouped by action in chunks of up to 254 syscalls
//!     jeq nr_0, ret_a, +0
//!     ...
//!     ja  after
//! ret_a:
//!     ret action
//! after:
//!     ; syscalls with conditional rules
//!     jeq nr, +1, +0
//!     ja  next_syscall
//!     <argument checks of rule 0, jump to next_rule on mismatch>
//!     ret action_0
//! next_rule:
//!     ...
//!     ret unconditional action or default action
//! next_syscall:
//!     ...
//!     ret default
//! next_arch:
//!     ...
//!     ret bad_arch
//! ```
//!
//! Conditional jumps only target nearby labels; long jumps always use
//! `BPF_JA`, whose offset is 32 bits wide.

use std::collections::BTreeMap;

use youki_seccomp::instruction::{
    AUDIT_ARCH_X86_64, BPF_ABS, BPF_ALU, BPF_AND, BPF_JA, BPF_JEQ, BPF_JGE, BPF_JGT, BPF_K, BPF_LD,
    BPF_RET, BPF_W, Instruction, X32_SYSCALL_BIT, seccomp_data_arch_offset,
    seccomp_data_args_offset, seccomp_data_nr_offset,
};

use super::arch::{self, ArchInfo};
use super::error::{Result, SeccompError};
use super::types::{ScmpAction, ScmpArch, ScmpArgCompare, ScmpCompareOp, ScmpSyscall};

/// Maximum number of instructions in a BPF program (BPF_MAXINSNS).
const BPF_MAXINSNS: usize = 4096;
/// Maximum number of syscalls compared in a chunk, so that the offset of the
/// jump to the shared return stays within 8 bits.
const CHUNK_SIZE: usize = 254;

/// A filter rule. An empty `comparators` means an unconditional rule.
#[derive(Debug, Clone)]
pub(super) struct Rule {
    pub action: ScmpAction,
    pub syscall: ScmpSyscall,
    pub comparators: Vec<ScmpArgCompare>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Label(usize);

#[derive(Debug, Clone, Copy)]
enum Target {
    Next,
    Label(Label),
}

#[derive(Debug)]
enum Item {
    Stmt {
        code: u16,
        k: u32,
    },
    Jump {
        code: u16,
        k: u32,
        jt: Target,
        jf: Target,
    },
    Ja(Label),
    Bind(Label),
}

/// A tiny assembler resolving forward jumps to labels.
#[derive(Debug, Default)]
struct Assembler {
    items: Vec<Item>,
    labels: usize,
}

impl Assembler {
    fn label(&mut self) -> Label {
        self.labels += 1;
        Label(self.labels - 1)
    }

    fn bind(&mut self, label: Label) {
        self.items.push(Item::Bind(label));
    }

    fn stmt(&mut self, code: u16, k: u32) {
        self.items.push(Item::Stmt { code, k });
    }

    fn load(&mut self, offset: u8) {
        self.stmt(BPF_LD | BPF_W | BPF_ABS, offset.into());
    }

    fn ret(&mut self, action: ScmpAction) {
        self.stmt(BPF_RET | BPF_K, action.to_ret());
    }

    fn jump(&mut self, code: u16, k: u32, jt: Target, jf: Target) {
        self.items.push(Item::Jump {
            code: code | BPF_K,
            k,
            jt,
            jf,
        });
    }

    fn ja(&mut self, label: Label) {
        self.items.push(Item::Ja(label));
    }

    fn assemble(self) -> Result<Vec<Instruction>> {
        let mut positions = vec![None; self.labels];
        let mut pos = 0;
        for item in &self.items {
            match item {
                Item::Bind(label) => positions[label.0] = Some(pos),
                _ => pos += 1,
            }
        }
        if pos > BPF_MAXINSNS {
            return Err(SeccompError::FilterTooLarge(pos));
        }

        // All jumps are forward, so the offset is `target - (pc + 1)`.
        let offset = |pc: usize, label: Label| -> usize {
            positions[label.0].expect("unbound label") - (pc + 1)
        };
        let short = |pc: usize, target: Target| -> Result<u8> {
            match target {
                Target::Next => Ok(0),
                Target::Label(label) => {
                    let off = offset(pc, label);
                    u8::try_from(off).map_err(|_| SeccompError::JumpOutOfRange(off))
                }
            }
        };

        let mut prog = Vec::with_capacity(pos);
        for item in &self.items {
            let pc = prog.len();
            match *item {
                Item::Bind(_) => {}
                Item::Stmt { code, k } => prog.push(Instruction::stmt(code, k)),
                Item::Jump { code, k, jt, jf } => {
                    prog.push(Instruction::jump(code, short(pc, jt)?, short(pc, jf)?, k))
                }
                Item::Ja(label) => {
                    prog.push(Instruction::jump(BPF_JA, 0, 0, offset(pc, label) as u32))
                }
            }
        }
        Ok(prog)
    }
}

/// Rules applied to a single syscall number on an architecture.
#[derive(Debug, Default)]
struct SyscallRules<'a> {
    conditional: Vec<(ScmpAction, &'a [ScmpArgCompare])>,
    unconditional: Option<ScmpAction>,
}

/// Compiles `rules` into a BPF program.
pub(super) fn compile(
    default_action: ScmpAction,
    bad_arch_action: ScmpAction,
    archs: &[ScmpArch],
    rules: &[Rule],
) -> Result<Vec<Instruction>> {
    let infos = archs
        .iter()
        .map(|&arch| arch::info(arch))
        .collect::<Result<Vec<_>>>()?;

    // Group the architectures sharing the same AUDIT_ARCH value (x86_64 and x32).
    let mut groups: Vec<(u32, Vec<ArchInfo>)> = vec![];
    for info in infos {
        match groups.iter_mut().find(|(audit, _)| *audit == info.audit) {
            Some((_, members)) => members.push(info),
            None => groups.push((info.audit, vec![info])),
        }
    }

    let mut asm = Assembler::default();
    asm.load(seccomp_data_arch_offset());
    for (audit, members) in &groups {
        let next_arch = asm.label();
        let section = asm.label();
        asm.jump(BPF_JEQ, *audit, Target::Label(section), Target::Next);
        asm.ja(next_arch);
        asm.bind(section);
        asm.load(seccomp_data_nr_offset());

        if *audit == AUDIT_ARCH_X86_64 {
            let x86_64 = members.iter().find(|i| i.arch == ScmpArch::X8664);
            let x32 = members.iter().find(|i| i.arch == ScmpArch::X32);
            let section_64 = asm.label();
            let section_x32 = asm.label();
            asm.jump(
                BPF_JGE,
                X32_SYSCALL_BIT,
                Target::Next,
                Target::Label(section_64),
            );
            match x32 {
                Some(_) => asm.ja(section_x32),
                None => asm.ret(bad_arch_action),
            }
            asm.bind(section_64);
            match x86_64 {
                Some(info) => compile_arch(&mut asm, info, default_action, rules)?,
                None => asm.ret(bad_arch_action),
            }
            asm.bind(section_x32);
            if let Some(info) = x32 {
                compile_arch(&mut asm, info, default_action, rules)?;
            }
        } else {
            compile_arch(&mut asm, &members[0], default_action, rules)?;
        }
        asm.bind(next_arch);
    }
    asm.ret(bad_arch_action);

    asm.assemble()
}

/// Emits the section of a single architecture. The syscall number must be in
/// the accumulator.
fn compile_arch(
    asm: &mut Assembler,
    info: &ArchInfo,
    default_action: ScmpAction,
    rules: &[Rule],
) -> Result<()> {
    let mut syscalls: BTreeMap<u32, SyscallRules> = BTreeMap::new();
    for rule in rules {
        // Skip syscalls which don't exist on this architecture.
        let Some(nr) = arch::resolve(info.arch, rule.syscall.name()) else {
            continue;
        };
        let entry = syscalls.entry(nr).or_default();
        if rule.comparators.is_empty() {
            // Like libseccomp, the first unconditional rule wins and later
            // ones for the same syscall are ignored.
            match entry.unconditional {
                Some(existing) if existing != rule.action => tracing::debug!(
                    syscall = rule.syscall.name(),
                    ?existing,
                    ignored = ?rule.action,
                    "ignore conflicting seccomp rule"
                ),
                Some(_) => {}
                None => entry.unconditional = Some(rule.action),
            }
        } else {
            entry
                .conditional
                .push((rule.action, rule.comparators.as_slice()));
        }
    }

    // Syscalls with unconditional rules only, grouped by action.
    let mut by_action: Vec<(ScmpAction, Vec<u32>)> = vec![];
    for (&nr, entry) in &syscalls {
        if let (true, Some(action)) = (entry.conditional.is_empty(), entry.unconditional) {
            match by_action.iter_mut().find(|(a, _)| *a == action) {
                Some((_, nrs)) => nrs.push(nr),
                None => by_action.push((action, vec![nr])),
            }
        }
    }
    for (action, nrs) in &by_action {
        for chunk in nrs.chunks(CHUNK_SIZE) {
            let ret = asm.label();
            let after = asm.label();
            for &nr in chunk {
                asm.jump(BPF_JEQ, nr, Target::Label(ret), Target::Next);
            }
            asm.ja(after);
            asm.bind(ret);
            asm.ret(*action);
            asm.bind(after);
        }
    }

    // Syscalls with conditional rules.
    for (&nr, entry) in syscalls.iter().filter(|(_, e)| !e.conditional.is_empty()) {
        let body = asm.label();
        let next_syscall = asm.label();
        asm.jump(BPF_JEQ, nr, Target::Label(body), Target::Next);
        asm.ja(next_syscall);
        asm.bind(body);
        for (action, comparators) in &entry.conditional {
            let next_rule = asm.label();
            for cmp in comparators.iter() {
                compile_comparator(asm, info.is_64bit, cmp, next_rule)?;
            }
            asm.ret(*action);
            asm.bind(next_rule);
        }
        asm.ret(entry.unconditional.unwrap_or(default_action));
        asm.bind(next_syscall);
    }

    asm.ret(default_action);
    Ok(())
}

/// Emits an argument comparison falling through on match and jumping to
/// `fail` on mismatch. Arguments are compared as unsigned values; on 32-bit
/// architectures only the lower 32 bits are compared.
fn compile_comparator(
    asm: &mut Assembler,
    is_64bit: bool,
    cmp: &ScmpArgCompare,
    fail: Label,
) -> Result<()> {
    let index = u8::try_from(cmp.arg).map_err(|_| SeccompError::InvalidArgIndex(cmp.arg))?;
    let lo_offset =
        seccomp_data_args_offset(index).map_err(|_| SeccompError::InvalidArgIndex(cmp.arg))?;
    // All supported architectures are little endian.
    let hi_offset = lo_offset + 4;
    let (datum_hi, datum_lo) = ((cmp.datum >> 32) as u32, cmp.datum as u32);
    let fail = Target::Label(fail);
    let next = Target::Next;

    if !is_64bit {
        asm.load(lo_offset);
        match cmp.op {
            ScmpCompareOp::Equal => asm.jump(BPF_JEQ, datum_lo, next, fail),
            ScmpCompareOp::NotEqual => asm.jump(BPF_JEQ, datum_lo, fail, next),
            ScmpCompareOp::Greater => asm.jump(BPF_JGT, datum_lo, next, fail),
            ScmpCompareOp::GreaterEqual => asm.jump(BPF_JGE, datum_lo, next, fail),
            ScmpCompareOp::Less => asm.jump(BPF_JGE, datum_lo, fail, next),
            ScmpCompareOp::LessOrEqual => asm.jump(BPF_JGT, datum_lo, fail, next),
            ScmpCompareOp::MaskedEqual(mask) => {
                asm.stmt(BPF_ALU | BPF_AND | BPF_K, mask as u32);
                asm.jump(BPF_JEQ, datum_lo, next, fail);
            }
        }
        return Ok(());
    }

    match cmp.op {
        ScmpCompareOp::Equal => {
            asm.load(hi_offset);
            asm.jump(BPF_JEQ, datum_hi, next, fail);
            asm.load(lo_offset);
            asm.jump(BPF_JEQ, datum_lo, next, fail);
        }
        ScmpCompareOp::NotEqual => {
            let ok = asm.label();
            asm.load(hi_offset);
            asm.jump(BPF_JEQ, datum_hi, next, Target::Label(ok));
            asm.load(lo_offset);
            asm.jump(BPF_JEQ, datum_lo, fail, next);
            asm.bind(ok);
        }
        ScmpCompareOp::Greater | ScmpCompareOp::GreaterEqual => {
            let ok = asm.label();
            asm.load(hi_offset);
            asm.jump(BPF_JGT, datum_hi, Target::Label(ok), next);
            asm.jump(BPF_JEQ, datum_hi, next, fail);
            asm.load(lo_offset);
            let code = if cmp.op == ScmpCompareOp::Greater {
                BPF_JGT
            } else {
                BPF_JGE
            };
            asm.jump(code, datum_lo, next, fail);
            asm.bind(ok);
        }
        ScmpCompareOp::Less | ScmpCompareOp::LessOrEqual => {
            let ok = asm.label();
            asm.load(hi_offset);
            asm.jump(BPF_JGT, datum_hi, fail, next);
            asm.jump(BPF_JEQ, datum_hi, next, Target::Label(ok));
            asm.load(lo_offset);
            // a < d  <=>  !(a >= d),  a <= d  <=>  !(a > d)
            let code = if cmp.op == ScmpCompareOp::Less {
                BPF_JGE
            } else {
                BPF_JGT
            };
            asm.jump(code, datum_lo, fail, next);
            asm.bind(ok);
        }
        ScmpCompareOp::MaskedEqual(mask) => {
            asm.load(hi_offset);
            asm.stmt(BPF_ALU | BPF_AND | BPF_K, (mask >> 32) as u32);
            asm.jump(BPF_JEQ, datum_hi, next, fail);
            asm.load(lo_offset);
            asm.stmt(BPF_ALU | BPF_AND | BPF_K, mask as u32);
            asm.jump(BPF_JEQ, datum_lo, next, fail);
        }
    }
    Ok(())
}

/// A minimal classic BPF interpreter for testing seccomp programs.
#[cfg(test)]
pub(super) mod interp {
    use youki_seccomp::instruction::{
        BPF_ABS, BPF_ALU, BPF_AND, BPF_JA, BPF_JEQ, BPF_JGE, BPF_JGT, BPF_JMP, BPF_JSET, BPF_K,
        BPF_LD, BPF_RET, BPF_W, Instruction,
    };

    /// Input of a seccomp program (`struct seccomp_data`).
    #[derive(Debug, Clone, Copy, Default)]
    pub struct Data {
        pub nr: u32,
        pub arch: u32,
        pub args: [u64; 6],
    }

    impl Data {
        fn bytes(&self) -> [u8; 64] {
            let mut buf = [0u8; 64];
            buf[0..4].copy_from_slice(&self.nr.to_le_bytes());
            buf[4..8].copy_from_slice(&self.arch.to_le_bytes());
            for (i, arg) in self.args.iter().enumerate() {
                buf[16 + i * 8..24 + i * 8].copy_from_slice(&arg.to_le_bytes());
            }
            buf
        }
    }

    /// Runs `prog` against `data` and returns the value of `BPF_RET`.
    pub fn run(prog: &[Instruction], data: &Data) -> u32 {
        let bytes = data.bytes();
        let mut acc: u32 = 0;
        let mut pc = 0;
        loop {
            let inst = &prog[pc];
            let k = inst.multiuse_field;
            pc += 1;
            match inst.code {
                c if c == BPF_LD | BPF_W | BPF_ABS => {
                    let off = k as usize;
                    acc = u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap());
                }
                c if c == BPF_ALU | BPF_AND | BPF_K => acc &= k,
                c if c == BPF_JMP | BPF_JA => pc += k as usize,
                c if c == BPF_RET | BPF_K => return k,
                c if c & 0x07 == BPF_JMP => {
                    let cond = match c & 0xf0 {
                        BPF_JEQ => acc == k,
                        BPF_JGT => acc > k,
                        BPF_JGE => acc >= k,
                        BPF_JSET => acc & k != 0,
                        _ => panic!("unsupported jump: {c:#x}"),
                    };
                    pc += if cond {
                        inst.offset_jump_true
                    } else {
                        inst.offset_jump_false
                    } as usize;
                }
                c => panic!("unsupported instruction: {c:#x}"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use youki_seccomp::instruction::{AUDIT_ARCH_AARCH64, AUDIT_ARCH_I386};

    use super::interp::{Data, run};
    use super::*;

    const DEFAULT: ScmpAction = ScmpAction::Errno(libc::EPERM);
    const BAD_ARCH: ScmpAction = ScmpAction::KillThread;

    fn sc(name: &str) -> ScmpSyscall {
        ScmpSyscall::from_name(name).unwrap()
    }

    fn rule(action: ScmpAction, name: &str, comparators: &[ScmpArgCompare]) -> Rule {
        Rule {
            action,
            syscall: sc(name),
            comparators: comparators.to_vec(),
        }
    }

    fn data(arch: u32, nr: u32, args: [u64; 6]) -> Data {
        Data { nr, arch, args }
    }

    fn x86_64(nr: u32) -> Data {
        data(AUDIT_ARCH_X86_64, nr, [0; 6])
    }

    #[test]
    fn test_unconditional() {
        let prog = compile(
            DEFAULT,
            BAD_ARCH,
            &[ScmpArch::X8664],
            &[
                rule(ScmpAction::Allow, "getcwd", &[]),
                rule(ScmpAction::Errno(libc::EAGAIN), "mkdir", &[]),
            ],
        )
        .unwrap();
        assert_eq!(run(&prog, &x86_64(79)), ScmpAction::Allow.to_ret());
        assert_eq!(
            run(&prog, &x86_64(83)),
            ScmpAction::Errno(libc::EAGAIN).to_ret()
        );
        assert_eq!(run(&prog, &x86_64(0)), DEFAULT.to_ret());
        // Other architectures and the x32 ABI are rejected.
        assert_eq!(
            run(&prog, &data(AUDIT_ARCH_I386, 183, [0; 6])),
            BAD_ARCH.to_ret()
        );
        assert_eq!(run(&prog, &x86_64(79 | X32_SYSCALL_BIT)), BAD_ARCH.to_ret());
    }

    #[test]
    fn test_multiple_archs() {
        let prog = compile(
            DEFAULT,
            BAD_ARCH,
            &[
                ScmpArch::X8664,
                ScmpArch::X86,
                ScmpArch::X32,
                ScmpArch::Aarch64,
                ScmpArch::Arm,
            ],
            &[rule(ScmpAction::Allow, "getcwd", &[])],
        )
        .unwrap();
        let allow = ScmpAction::Allow.to_ret();
        assert_eq!(run(&prog, &x86_64(79)), allow);
        assert_eq!(run(&prog, &x86_64(79 | X32_SYSCALL_BIT)), allow);
        assert_eq!(run(&prog, &data(AUDIT_ARCH_I386, 183, [0; 6])), allow);
        assert_eq!(run(&prog, &data(AUDIT_ARCH_AARCH64, 17, [0; 6])), allow);
        assert_eq!(
            run(&prog, &data(AUDIT_ARCH_AARCH64, 79, [0; 6])),
            DEFAULT.to_ret()
        );
        assert_eq!(run(&prog, &data(0x1234, 79, [0; 6])), BAD_ARCH.to_ret());
    }

    #[test]
    fn test_many_syscalls() {
        // More than CHUNK_SIZE syscalls with the same action.
        let names: Vec<&str> = (0..450)
            .filter_map(|nr| syscalls::x86_64::Sysno::new(nr).map(|s| s.name()))
            .collect();
        assert!(names.len() > CHUNK_SIZE);
        let rules: Vec<Rule> = names
            .iter()
            .map(|name| rule(ScmpAction::Allow, name, &[]))
            .collect();
        let prog = compile(DEFAULT, BAD_ARCH, &[ScmpArch::X8664], &rules).unwrap();
        for name in names {
            let nr = arch::resolve(ScmpArch::X8664, name).unwrap();
            assert_eq!(
                run(&prog, &x86_64(nr)),
                ScmpAction::Allow.to_ret(),
                "{name}"
            );
        }
        assert_eq!(run(&prog, &x86_64(1000)), DEFAULT.to_ret());
    }

    #[test]
    fn test_too_large() {
        // Each conditional syscall costs at least 7 instructions per arch.
        let names: Vec<&str> = (0..450)
            .filter_map(|nr| syscalls::x86_64::Sysno::new(nr).map(|s| s.name()))
            .collect();
        let cmp = ScmpArgCompare::new(0, ScmpCompareOp::Equal, 1);
        let rules: Vec<Rule> = names
            .iter()
            .map(|name| rule(ScmpAction::Allow, name, &[cmp, cmp]))
            .collect();
        assert!(matches!(
            compile(DEFAULT, BAD_ARCH, &[ScmpArch::X8664], &rules),
            Err(SeccompError::FilterTooLarge(_))
        ));
    }

    #[test]
    fn test_conflicting_rule() {
        let prog = compile(
            DEFAULT,
            BAD_ARCH,
            &[ScmpArch::X8664],
            &[
                rule(ScmpAction::Allow, "getcwd", &[]),
                rule(ScmpAction::Log, "getcwd", &[]),
            ],
        )
        .unwrap();
        assert_eq!(run(&prog, &x86_64(79)), ScmpAction::Allow.to_ret());
    }

    fn reference(op: ScmpCompareOp, arg: u64, datum: u64, is_64bit: bool) -> bool {
        let (arg, datum, mask) = match op {
            ScmpCompareOp::MaskedEqual(mask) if !is_64bit => {
                (arg as u32 as u64, datum as u32 as u64, mask as u32 as u64)
            }
            ScmpCompareOp::MaskedEqual(mask) => (arg, datum, mask),
            _ if !is_64bit => (arg as u32 as u64, datum as u32 as u64, 0),
            _ => (arg, datum, 0),
        };
        match op {
            ScmpCompareOp::Equal => arg == datum,
            ScmpCompareOp::NotEqual => arg != datum,
            ScmpCompareOp::Greater => arg > datum,
            ScmpCompareOp::GreaterEqual => arg >= datum,
            ScmpCompareOp::Less => arg < datum,
            ScmpCompareOp::LessOrEqual => arg <= datum,
            ScmpCompareOp::MaskedEqual(_) => arg & mask == datum,
        }
    }

    #[test]
    fn test_comparators() {
        let datums = [0u64, 5, 0x1_0000_0005, 0xffff_ffff, u64::MAX];
        let mut values = vec![];
        for d in datums {
            for delta in [-0x1_0000_0000i128, -1, 0, 1, 0x1_0000_0000] {
                let v = d as i128 + delta;
                if (0..=u64::MAX as i128).contains(&v) {
                    values.push(v as u64);
                }
            }
        }
        let ops = [
            ScmpCompareOp::Equal,
            ScmpCompareOp::NotEqual,
            ScmpCompareOp::Greater,
            ScmpCompareOp::GreaterEqual,
            ScmpCompareOp::Less,
            ScmpCompareOp::LessOrEqual,
            ScmpCompareOp::MaskedEqual(0xff00_0000_00ff),
        ];
        for (arch, audit, nr) in [
            (ScmpArch::X8664, AUDIT_ARCH_X86_64, 41),
            (ScmpArch::X86, AUDIT_ARCH_I386, 359),
        ] {
            let is_64bit = arch::info(arch).unwrap().is_64bit;
            for op in ops {
                for datum in datums {
                    let cmp = ScmpArgCompare::new(2, op, datum);
                    let prog = compile(
                        DEFAULT,
                        BAD_ARCH,
                        &[arch],
                        &[rule(ScmpAction::Allow, "socket", &[cmp])],
                    )
                    .unwrap();
                    for &value in &values {
                        let mut args = [0; 6];
                        args[2] = value;
                        let expected = if reference(op, value, datum, is_64bit) {
                            ScmpAction::Allow.to_ret()
                        } else {
                            DEFAULT.to_ret()
                        };
                        assert_eq!(
                            run(&prog, &data(audit, nr, args)),
                            expected,
                            "{arch:?} {op:?} datum={datum:#x} value={value:#x}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn test_conditional_rules() {
        let eq = |arg, datum| ScmpArgCompare::new(arg, ScmpCompareOp::Equal, datum);
        let prog = compile(
            DEFAULT,
            BAD_ARCH,
            &[ScmpArch::X8664],
            &[
                // AND within a rule.
                rule(ScmpAction::Errno(1), "socket", &[eq(0, 1), eq(1, 2)]),
                // OR across rules.
                rule(ScmpAction::Errno(2), "socket", &[eq(0, 3)]),
                rule(ScmpAction::Log, "socket", &[]),
                rule(ScmpAction::Allow, "getcwd", &[]),
            ],
        )
        .unwrap();
        let socket = |a0, a1| data(AUDIT_ARCH_X86_64, 41, [a0, a1, 0, 0, 0, 0]);
        assert_eq!(run(&prog, &socket(1, 2)), ScmpAction::Errno(1).to_ret());
        assert_eq!(run(&prog, &socket(3, 2)), ScmpAction::Errno(2).to_ret());
        assert_eq!(run(&prog, &socket(1, 3)), ScmpAction::Log.to_ret());
        assert_eq!(run(&prog, &x86_64(79)), ScmpAction::Allow.to_ret());
        assert_eq!(run(&prog, &x86_64(0)), DEFAULT.to_ret());
    }
}
