use libcontainer::seccomp::SeccompBackend;
use oci_seccomp_youki_adapter::{OciSeccompBackend, compile_program};
use oci_spec::runtime::LinuxSeccomp;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args_os()
        .nth(1)
        .ok_or("usage: oci-seccomp-youki-adapter <calculated-oci-seccomp.json>")?;
    let spec: LinuxSeccomp = serde_json::from_slice(&std::fs::read(path)?)?;
    let (program, _, _) = compile_program(&spec)?;
    let compiled = OciSeccompBackend.compile(&spec)?;
    println!(
        "{}: {} instructions, flags={}, listener={}",
        OciSeccompBackend.name(),
        program.len(),
        compiled.flags,
        compiled.wants_listener
    );
    Ok(())
}
