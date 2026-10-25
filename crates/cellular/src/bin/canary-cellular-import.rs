//! Import a `rayhunter-check` JSON document and print the CANARY reports it
//! contains.
//!
//!     canary-cellular-import <rayhunter.json>

use std::path::Path;
use std::process::ExitCode;

use canary_cellular::rayhunter_import::import_report;

fn main() -> ExitCode {
    const USAGE: &str = "usage: canary-cellular-import <rayhunter.json>";

    let mut args = std::env::args().skip(1);
    let Some(json_path) = args.next() else {
        eprintln!("{USAGE}");
        return ExitCode::FAILURE;
    };
    if let Some(extra) = args.next() {
        eprintln!("error: unexpected extra argument {extra:?}");
        eprintln!("{USAGE}");
        return ExitCode::FAILURE;
    }

    match import_report(Path::new(&json_path)) {
        Ok(reports) => {
            println!("{reports:#?}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}
