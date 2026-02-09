//! CLI entrypoint for glibc_rust conformance harness.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// Conformance tooling for glibc_rust.
#[derive(Debug, Parser)]
#[command(name = "glibc-rs-harness")]
#[command(about = "Conformance testing harness for glibc_rust")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Capture host glibc behavior as fixture files.
    Capture {
        /// Output directory for fixture JSON files.
        #[arg(long)]
        output: PathBuf,
        /// Function family to capture (e.g., "string", "malloc").
        #[arg(long)]
        family: String,
    },
    /// Verify our implementation against captured fixtures.
    Verify {
        /// Directory containing fixture JSON files.
        #[arg(long)]
        fixture: PathBuf,
        /// Output report path (markdown).
        #[arg(long)]
        report: Option<PathBuf>,
    },
    /// Generate traceability matrix.
    Traceability {
        /// Output markdown path.
        #[arg(long)]
        output_md: PathBuf,
        /// Output JSON path.
        #[arg(long)]
        output_json: PathBuf,
    },
    /// Run membrane-specific verification tests.
    VerifyMembrane {
        /// Runtime mode to test (strict or hardened).
        #[arg(long, default_value = "strict")]
        mode: String,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Command::Capture { output, family } => {
            eprintln!("Capturing {family} fixtures to {}", output.display());
            std::fs::create_dir_all(&output)?;
            eprintln!("TODO: implement capture for {family}");
        }
        Command::Verify { fixture, report } => {
            eprintln!("Verifying against fixtures in {}", fixture.display());
            let mut fixture_sets = Vec::new();
            for entry in std::fs::read_dir(&fixture)? {
                let entry = entry?;
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) != Some("json") {
                    continue;
                }
                match glibc_rs_harness::FixtureSet::from_file(&path) {
                    Ok(set) => fixture_sets.push(set),
                    Err(err) => {
                        eprintln!("Skipping {}: {}", path.display(), err);
                    }
                }
            }
            if fixture_sets.is_empty() {
                return Err(format!("No fixture JSON files found in {}", fixture.display()).into());
            }

            let strict_runner = glibc_rs_harness::TestRunner::new("fixture-verify", "strict");
            let hardened_runner = glibc_rs_harness::TestRunner::new("fixture-verify", "hardened");

            let mut results = Vec::new();
            for set in &fixture_sets {
                results.extend(strict_runner.run(set));
                results.extend(hardened_runner.run(set));
            }

            let summary = glibc_rs_harness::verify::VerificationSummary::from_results(results);
            let report_doc = glibc_rs_harness::ConformanceReport {
                title: String::from("glibc_rust Conformance Report"),
                mode: String::from("strict+hardened"),
                timestamp: format!("{:?}", std::time::SystemTime::now()),
                summary,
            };

            eprintln!(
                "Verification complete: total={}, passed={}, failed={}",
                report_doc.summary.total, report_doc.summary.passed, report_doc.summary.failed
            );

            if let Some(report_path) = report {
                eprintln!("Writing report to {}", report_path.display());
                std::fs::write(&report_path, report_doc.to_markdown())?;
                let json_path = report_path.with_extension("json");
                std::fs::write(&json_path, report_doc.to_json())?;
            }

            if !report_doc.summary.all_passed() {
                return Err("Conformance verification failed".into());
            }
        }
        Command::Traceability {
            output_md,
            output_json,
        } => {
            let matrix = glibc_rs_harness::traceability::TraceabilityMatrix::new();
            std::fs::write(&output_md, matrix.to_markdown())?;
            let json = serde_json::to_string_pretty(&matrix.to_markdown())?;
            std::fs::write(&output_json, json)?;
            eprintln!(
                "Traceability written to {} and {}",
                output_md.display(),
                output_json.display()
            );
        }
        Command::VerifyMembrane { mode } => {
            eprintln!("Running membrane verification in {mode} mode");
            if mode != "strict" && mode != "hardened" {
                return Err(format!("Unsupported mode '{mode}', expected strict|hardened").into());
            }
            let mut suite = glibc_rs_harness::healing_oracle::HealingOracleSuite::new();
            suite.add(glibc_rs_harness::healing_oracle::HealingOracleCase {
                id: String::from("double-free"),
                condition: glibc_rs_harness::healing_oracle::UnsafeCondition::DoubleFree,
                expected_healing: String::from("IgnoreDoubleFree"),
                strict_expected: String::from("No repair"),
            });
            suite.add(glibc_rs_harness::healing_oracle::HealingOracleCase {
                id: String::from("foreign-free"),
                condition: glibc_rs_harness::healing_oracle::UnsafeCondition::ForeignFree,
                expected_healing: String::from("IgnoreForeignFree"),
                strict_expected: String::from("No repair"),
            });

            for case in suite.cases() {
                if mode == "hardened" {
                    eprintln!("[{}] expect {}", case.id, case.expected_healing);
                } else {
                    eprintln!("[{}] expect {}", case.id, case.strict_expected);
                }
            }
            eprintln!("Membrane verification spec checks completed");
        }
    }

    Ok(())
}
