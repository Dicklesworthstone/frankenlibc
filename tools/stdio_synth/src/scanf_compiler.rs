//! scanf grammar validator / compiler entrypoint.
//!
//! This is the first vertical slice of the scanf synthesis path: it loads and
//! validates the formal grammar, reports the supported conversion families, and
//! keeps the CLI contract stable for follow-on table generation work.

use clap::Parser;
use std::path::PathBuf;
use stdio_synth::ScanfGrammar;

#[derive(Parser, Debug)]
#[command(name = "scanf-compile")]
#[command(about = "Validate scanf grammar and prepare for table generation")]
struct Args {
    /// Path to scanf_grammar.json
    #[arg(short, long, default_value = "spec/scanf_grammar.json")]
    grammar: PathBuf,

    /// Only validate grammar, don't emit an output artifact
    #[arg(long)]
    validate_only: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    eprintln!("[scanf-compile] Loading grammar from {:?}", args.grammar);
    let grammar = ScanfGrammar::load(&args.grammar)?;

    eprintln!(
        "[scanf-compile] Grammar v{}: {} conversions, {} length modifiers, assignment suppression {}",
        grammar.version,
        grammar.conversion.len(),
        grammar.length_modifier.len(),
        if grammar.assignment_suppression {
            "enabled"
        } else {
            "disabled"
        }
    );

    let mut conversions = grammar.conversion.keys().cloned().collect::<Vec<_>>();
    conversions.sort();
    eprintln!(
        "[scanf-compile] Supported conversions: {}",
        conversions.join(" ")
    );

    if let Some(scanset) = grammar.scanset {
        eprintln!(
            "[scanf-compile] Scanset support: negation={}, ranges={}, leading ]={}",
            scanset.supports_negation,
            scanset.supports_ranges,
            scanset.first_char_may_be_closing_bracket
        );
    }

    if args.validate_only {
        eprintln!("[scanf-compile] Validation complete");
    } else {
        eprintln!("[scanf-compile] Validation complete; table emission is the next slice");
    }

    Ok(())
}
