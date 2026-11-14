#![forbid(unsafe_code)]

//! `galadriel-ncp-loop assess RUN_DIR`: assess the innovations of a CREBAIN NCP 2 loop run.
//!
//! It prints one JSON report and opens no listener, network connection, or subprocess.

use galadriel_local_adapter::ncp_loop::assess_run;
use std::path::Path;

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [command, run] = args.as_slice() else {
        eprintln!("usage: galadriel-ncp-loop assess RUN_DIR");
        return std::process::ExitCode::from(2);
    };
    if command != "assess" {
        eprintln!("usage: galadriel-ncp-loop assess RUN_DIR");
        return std::process::ExitCode::from(2);
    }
    match assess_run(Path::new(run)) {
        Ok(report) => {
            println!("{report}");
            std::process::ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("galadriel-ncp-loop: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}
