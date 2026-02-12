//! CLI entrypoint for frankenlibc conformance tooling.

use std::fs;
use std::path::PathBuf;

use clap::{Parser, Subcommand};

use frankenlibc_conformance::{
    build_traceability_artifact, capture_memcpy_fixture_set, render_diff_report,
    render_verification_markdown, verify_memcpy_fixture_set,
};

/// CLI for traceability/diff tooling around frankenlibc conformance.
#[derive(Debug, Parser)]
#[command(name = "glibc-rust-conformance")]
#[command(about = "Conformance tooling for frankenlibc")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

/// Supported CLI subcommands.
#[derive(Debug, Subcommand)]
enum Command {
    /// Emit a traceability artifact to markdown/json files.
    Traceability {
        /// Output markdown path.
        #[arg(long)]
        output_md: PathBuf,
        /// Output json path.
        #[arg(long)]
        output_json: PathBuf,
    },
    /// Render diff report between expected and actual text values.
    Diff {
        /// Expected text payload.
        #[arg(long)]
        expected: String,
        /// Actual text payload.
        #[arg(long)]
        actual: String,
    },
    /// Capture host libc memcpy fixture set.
    Capture {
        /// Output fixture path.
        #[arg(long)]
        output: PathBuf,
    },
    /// Verify frankenlibc preview memcpy against a fixture set.
    Verify {
        /// Input fixture path.
        #[arg(long)]
        fixture: PathBuf,
        /// Output markdown report path.
        #[arg(long)]
        report_md: PathBuf,
        /// Output json report path.
        #[arg(long)]
        report_json: PathBuf,
    },
}

fn main() -> std::io::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Traceability {
            output_md,
            output_json,
        } => {
            let artifact = build_traceability_artifact();
            fs::write(output_md, artifact.markdown)?;
            fs::write(output_json, artifact.json)?;
        }
        Command::Diff { expected, actual } => {
            let report = render_diff_report(&expected, &actual);
            println!("{report}");
        }
        Command::Capture { output } => {
            let fixture = capture_memcpy_fixture_set();
            let body = serde_json::to_string_pretty(&fixture)?;
            fs::write(output, body)?;
        }
        Command::Verify {
            fixture,
            report_md,
            report_json,
        } => {
            let fixture_body = fs::read_to_string(fixture)?;
            let fixture_set = serde_json::from_str(&fixture_body).map_err(std::io::Error::other)?;
            let report = verify_memcpy_fixture_set(&fixture_set);
            fs::write(report_md, render_verification_markdown(&report))?;
            fs::write(report_json, serde_json::to_string_pretty(&report)?)?;
        }
    }

    Ok(())
}
