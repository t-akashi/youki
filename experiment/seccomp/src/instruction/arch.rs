use nix::errno::Errno::ENOSYS;

use crate::instruction::{Instruction, *};
use crate::seccomp::SeccompError;

#[derive(Clone, Copy, PartialEq, Debug, Default)]
pub enum Arch {
    #[default]
    X86,
    AArch64,
}

impl Arch {
    pub fn native() -> Result<Self, SeccompError> {
        if cfg!(target_arch = "x86_64") {
            Ok(Self::X86)
        } else if cfg!(target_arch = "aarch64") {
            Ok(Self::AArch64)
        } else {
            Err(SeccompError::Unsupported("host architecture".into()))
        }
    }
}

/// A fixed-size architecture guard: no offset depends on the rule count.
pub fn gen_validate(arc: &Arch) -> Vec<Instruction> {
    let arch = match arc {
        Arch::X86 => AUDIT_ARCH_X86_64,
        Arch::AArch64 => AUDIT_ARCH_AARCH64,
    };
    let mut out = vec![
        Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, seccomp_data_arch_offset().into()),
        Instruction::jump(BPF_JEQ | BPF_K, 1, 0, arch),
        Instruction::stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        Instruction::stmt(BPF_LD | BPF_W | BPF_ABS, seccomp_data_nr_offset().into()),
    ];
    if *arc == Arch::X86 {
        out.push(Instruction::jump(BPF_JGE | BPF_K, 0, 1, X32_SYSCALL_BIT));
        out.push(Instruction::stmt(
            BPF_RET | BPF_K,
            SECCOMP_RET_ERRNO | ENOSYS as u32,
        ));
    }
    out
}
