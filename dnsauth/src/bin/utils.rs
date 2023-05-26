#![warn(
    clippy::semicolon_if_nothing_returned,
    missing_copy_implementations,
    missing_debug_implementations,
    noop_method_call,
    rust_2018_idioms,
    trivial_casts,
    trivial_numeric_casts,
    unreachable_pub,
    unused_extern_crates,
    unused_import_braces,
    unused_lifetimes,
    unused_qualifications,
    variant_size_differences
)]

use color_eyre::eyre::{bail, Result};
use dnsauth::definitions::{FuzzCaseId, FuzzResult, FuzzResultSet};
use misc_utils::fs;
use std::path::PathBuf;

#[derive(clap::Parser)]
#[allow(variant_size_differences)]
enum CliArgs {
    /// Print a FuzzCase or FuzzResult
    Inspect(InspectArgs),
}

#[derive(clap::Parser)]
struct PostFuzzerArgs {
    /// Output log of the fuzzer
    log: PathBuf,
    /// Output directory to write the analysis files
    outdir: PathBuf,
}

#[derive(clap::Parser)]
struct StatsArgs {
    /// Output log of the fuzzer
    log: PathBuf,
}

#[derive(clap::Parser)]
struct CompareArgs {
    /// Only print FuzzResults which differ after normalization
    #[clap(long = "diff")]
    diff: bool,
    /// Process all FuzzResuls, overrides `ids`
    #[clap(long = "all")]
    all: bool,
    /// Print the full diff and do not abbreviate it
    ///
    /// By default only the changed fields and surrounding context is shown.
    #[clap(long = "full")]
    full: bool,
    /// Left fuzzer output log
    left: PathBuf,
    /// Right fuzzer output log
    right: PathBuf,
    /// Full or partial IDs of FuzzCases to print detailed
    ids: Vec<FuzzCaseId>,
}

#[derive(clap::Parser)]
struct GenerateFuzzSuiteArgs {
    /// File to create with the FuzzSuite data
    output: PathBuf,
}

#[derive(clap::Parser)]
struct InspectArgs {
    /// File to display
    file: PathBuf,
}

fn main() -> Result<()> {
    color_eyre::install()?;
    env_logger::init();

    let cli_args: CliArgs = clap::Parser::parse();
    match cli_args {
        CliArgs::Inspect(args) => run_inspect(args),
    }
}

fn run_inspect(InspectArgs { file }: InspectArgs) -> Result<(), color_eyre::Report> {
    let data = fs::read(file)?;
    if let Ok(fuzz_result) = postcard::from_bytes::<FuzzResultSet>(&data) {
        println!("{fuzz_result:#?}");
    } else if let Ok(fuzz_result) = postcard::from_bytes::<FuzzResult>(&data) {
        println!("{fuzz_result:#?}");
    } else if let Ok(fuzz_suite) = postcard::from_bytes::<dnsauth::definitions::FuzzSuite>(&data) {
        println!("{fuzz_suite:#?}");
    } else {
        bail!("Could not parse file as FuzzResultSet, FuzzResult, or FuzzSuite");
    }
    Ok(())
}
