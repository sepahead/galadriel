#![forbid(unsafe_code)]

//! Private-pipe monitor executable. It accepts no endpoint or executable selector.

use ::ncp_local::local::{serve_local, LocalCode, LocalError};
use galadriel_local_adapter::ncp_local::local_owner;

fn launch() -> Result<(), LocalError> {
    let mut args = std::env::args_os().skip(1);
    let flag = args.next();
    let run = args.next();
    let generation_flag = args.next();
    let generation = args.next();
    if flag.as_deref() != Some(std::ffi::OsStr::new("--run-id"))
        || generation_flag.as_deref() != Some(std::ffi::OsStr::new("--generation"))
        || args.next().is_some()
    {
        return Err(LocalError(LocalCode::InvalidInput));
    }
    let run = run.and_then(|value| value.into_string().ok());
    let generation = generation.and_then(|value| value.into_string().ok());
    let mut owner = local_owner(
        run.ok_or(LocalError(LocalCode::InvalidInput))?,
        generation.ok_or(LocalError(LocalCode::InvalidInput))?,
    )?;
    serve_local(
        &mut owner,
        &mut std::io::stdin().lock(),
        &mut std::io::stdout().lock(),
    )
}

fn main() -> std::process::ExitCode {
    match launch() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            std::process::ExitCode::FAILURE
        }
    }
}
