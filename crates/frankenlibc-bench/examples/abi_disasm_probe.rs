//! Ask the SHIPPED object what the compiler actually emitted.
//!
//! WHY THIS EXISTS. Two `memrchr` levers were shipped, measured and reverted in
//! one session (docs/NEGATIVE_EVIDENCE.md, 9bbc62f69 and eb7f8e89c) and neither
//! produced movement. The second was `#[inline]` on the core function, and its
//! result is AMBIGUOUS by construction: `#[inline]` is a hint, so a null ratio
//! cannot distinguish "the cross-crate call was never the cost" from "LLVM
//! declined the hint and the emitted code never changed". A wall-clock number
//! cannot answer that question and no amount of quiet window will make it.
//!
//! Disassembly answers it in one command, needs no privileges, no counters and no
//! quiet host — but `rch` refuses non-compilation commands, so `objdump` cannot be
//! pointed at a worker directly. A `cargo run` example CAN be, and what it spawns
//! is its own business. That is the whole trick here.
//!
//! WHAT IT REPORTS, and deliberately nothing more: for each requested exported
//! symbol, the instruction count of its body and every `call` target inside it. A
//! delegating wrapper that was NOT inlined shows a `call` to a Rust-mangled
//! `frankenlibc_core::…` symbol; one that WAS inlined shows the callee's
//! instructions inline and no such call. This makes no claim about speed.
//!
//!     cargo run --profile release -p frankenlibc-bench --features abi-bench \
//!         --example abi_disasm_probe -- memrchr strnlen
//!
//! With no arguments it probes a default set of delegating string wrappers.

use std::process::Command;

/// Wrappers whose core delegate is the open question (bd-abi-core-inline-boundary-nmjdud).
const DEFAULT_SYMBOLS: &[&str] = &["memrchr", "memchr", "strnlen", "strlen"];

fn shared_object() -> String {
    let dir = std::env::var("FRANKENLIBC_BENCH_TARGET_DIR")
        .or_else(|_| std::env::var("CARGO_TARGET_DIR"))
        .unwrap_or_else(|_| "target".to_owned());
    format!("{dir}/release/libfrankenlibc_abi.so")
}

fn main() {
    let object = shared_object();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let symbols: Vec<&str> = if args.is_empty() {
        DEFAULT_SYMBOLS.to_vec()
    } else {
        args.iter().map(String::as_str).collect()
    };

    // Say which object was read and how big it is, so a row can never be quoted
    // against an artifact nobody can identify.
    match std::fs::metadata(&object) {
        Ok(meta) => println!("DISASM_OBJECT path={object} bytes={}", meta.len()),
        Err(error) => {
            println!("DISASM_UNAVAILABLE path={object} reason={error}");
            std::process::exit(2);
        }
    }

    let tool = Command::new("objdump").arg("--version").output();
    match tool {
        Ok(out) if out.status.success() => {
            let first = String::from_utf8_lossy(&out.stdout);
            println!(
                "DISASM_TOOL objdump={}",
                first.lines().next().unwrap_or("unknown")
            );
        }
        // Not a silent skip: without the tool this probe proves nothing, and a
        // run that printed only headers would look like a clean negative.
        _ => {
            println!("DISASM_UNAVAILABLE reason=objdump_not_runnable");
            std::process::exit(2);
        }
    }

    for symbol in symbols {
        let out = Command::new("objdump")
            .args(["-d", &format!("--disassemble={symbol}"), &object])
            .output()
            .expect("run objdump");
        let text = String::from_utf8_lossy(&out.stdout);

        // objdump prints a header block then one line per instruction; instruction
        // lines carry a tab-separated mnemonic after the byte column.
        let body: Vec<&str> = text
            .lines()
            .skip_while(|line| !line.contains(&format!("<{symbol}>:")))
            .skip(1)
            .take_while(|line| !line.trim().is_empty())
            .collect();

        if body.is_empty() {
            println!("DISASM_SYMBOL symbol={symbol} status=not_found_in_object");
            continue;
        }

        let instructions = body.len();
        let calls: Vec<String> = body
            .iter()
            .filter(|line| line.contains("\tcall"))
            .map(|line| {
                line.split('<')
                    .nth(1)
                    .map(|tail| tail.trim_end_matches('>').trim().to_owned())
                    .unwrap_or_else(|| "indirect".to_owned())
            })
            .collect();

        let core_calls = calls
            .iter()
            .filter(|target| target.contains("frankenlibc_core"))
            .count();

        println!(
            "DISASM_SYMBOL symbol={symbol} instructions={instructions} calls={} \
             calls_into_core={core_calls} targets={:?}",
            calls.len(),
            calls
        );
    }
}
