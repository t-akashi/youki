//! Use this branch's compiler through the existing trait in youki PR #3873.
//! The caller supplies its calculated OCI policy; libcontainer loads the result.

use compiler::instruction::{Arch, Instruction};
use compiler::seccomp::SeccompProgramPlan;
use libcontainer::seccomp::{CompiledSeccomp, SeccompBackend, SeccompError, SockFilter};
use oci_spec::runtime::LinuxSeccomp;

pub struct OciSeccompBackend;

impl SeccompBackend for OciSeccompBackend {
    fn name(&self) -> &'static str {
        "oci-seccomp"
    }

    fn compile(&self, spec: &LinuxSeccomp) -> Result<CompiledSeccomp, SeccompError> {
        let (program, flags, wants_listener) = compile_program(spec).map_err(|source| {
            // Preserve the compiler's diagnostic in the existing error chain.
            SeccompError::LoadProgram {
                source: std::io::Error::new(std::io::ErrorKind::InvalidInput, source),
            }
        })?;
        Ok(CompiledSeccomp::from_program(
            program,
            flags,
            wants_listener,
        ))
    }
}

pub fn compile_program(
    spec: &LinuxSeccomp,
) -> Result<(Vec<SockFilter>, u32, bool), compiler::seccomp::SeccompError> {
    let plan = SeccompProgramPlan::try_from(spec.clone())?;
    if plan.arc != Arch::native()? {
        return Err(compiler::seccomp::SeccompError::Unsupported(
            "profile does not include the host ABI".into(),
        ));
    }
    let flags = plan.flags.iter().fold(0, |bits, flag| bits | *flag) as u32;
    let listener_flag = libc::SECCOMP_FILTER_FLAG_NEW_LISTENER as u32;
    let instructions: Vec<Instruction> = plan.try_into()?;
    let program = instructions
        .into_iter()
        .map(|i| SockFilter {
            code: i.code,
            jt: i.offset_jump_true,
            jf: i.offset_jump_false,
            k: i.multiuse_field,
        })
        .collect();
    Ok((program, flags & !listener_flag, flags & listener_flag != 0))
}
