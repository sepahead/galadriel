#![forbid(unsafe_code)]
//! Render the build-identified CREBAIN drone categorical-MGW study as JSON.

use galadriel_justify::crebain_mgw::{
    bundled_crebain_drone_mgw_fixture, format_crebain_drone_mgw_markdown,
    run_crebain_drone_mgw_study,
};
use std::ffi::OsString;
use std::io::{self, Write};

#[derive(Debug)]
enum OutputFormat {
    Json,
    Markdown,
}

#[derive(Debug)]
enum Command {
    Run(OutputFormat),
    Help,
}

const USAGE: &str = "usage: galadriel-crebain-mgw [--format json|markdown]\n\
default: json. The bundled exact CREBAIN fixture is always used";

fn parse_command(arguments: &[OsString]) -> Result<Command, String> {
    match arguments {
        [] => Ok(Command::Run(OutputFormat::Json)),
        [flag, format] if flag == "--format" && format == "json" => {
            Ok(Command::Run(OutputFormat::Json))
        }
        [flag, format] if flag == "--format" && format == "markdown" => {
            Ok(Command::Run(OutputFormat::Markdown))
        }
        [flag] if flag == "--help" || flag == "-h" => Ok(Command::Help),
        _ => Err(USAGE.to_string()),
    }
}

fn run_main() -> Result<(), String> {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    let format = match parse_command(&arguments)? {
        Command::Help => {
            return write_stdout(USAGE.as_bytes(), "write CREBAIN drone MGW help");
        }
        Command::Run(format) => format,
    };
    let study = run_crebain_drone_mgw_study(bundled_crebain_drone_mgw_fixture())
        .map_err(|error| error.to_string())?;
    let rendered = match format {
        OutputFormat::Json => serde_json::to_vec_pretty(&study)
            .map_err(|error| format!("encode CREBAIN drone MGW evidence: {error}"))?,
        OutputFormat::Markdown => format_crebain_drone_mgw_markdown(&study).into_bytes(),
    };
    write_stdout(&rendered, "write CREBAIN drone MGW evidence")
}

fn write_stdout(bytes: &[u8], context: &str) -> Result<(), String> {
    let stdout = io::stdout();
    let mut output = io::BufWriter::new(stdout.lock());
    if let Err(error) = output.write_all(bytes) {
        if error.kind() == io::ErrorKind::BrokenPipe {
            return Ok(());
        }
        return Err(format!("{context}: {error}"));
    }
    if let Err(error) = output.write_all(b"\n") {
        if error.kind() == io::ErrorKind::BrokenPipe {
            return Ok(());
        }
        return Err(format!("{context}: {error}"));
    }
    output
        .flush()
        .or_else(|error| {
            if error.kind() == io::ErrorKind::BrokenPipe {
                Ok(())
            } else {
                Err(error)
            }
        })
        .map_err(|error| format!("flush CREBAIN drone MGW output: {error}"))
}

fn main() {
    if let Err(error) = run_main() {
        eprintln!("error: {error}");
        std::process::exit(2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn help_is_a_successful_command_not_an_error_path() {
        assert!(matches!(
            parse_command(&args(&["--help"])),
            Ok(Command::Help)
        ));
        assert!(matches!(parse_command(&args(&["-h"])), Ok(Command::Help)));
    }

    #[test]
    fn only_the_two_declared_renderers_are_accepted() {
        assert!(matches!(
            parse_command(&args(&["--format", "json"])),
            Ok(Command::Run(OutputFormat::Json))
        ));
        assert!(matches!(
            parse_command(&args(&["--format", "markdown"])),
            Ok(Command::Run(OutputFormat::Markdown))
        ));
        assert!(parse_command(&args(&["--format", "yaml"]))
            .expect_err("undeclared renderer must fail")
            .starts_with("usage:"));
    }
}
