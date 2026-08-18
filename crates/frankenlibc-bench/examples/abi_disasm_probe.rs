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
//!
//! # NOT YET TRUSTWORTHY — read before using its output
//!
//! Two observations from its first session say the parsing or the build is not
//! yet sound, and neither is explained:
//!
//! 1. On a freshly built object `memrchr` and `memchr` report IDENTICAL bodies
//!    (337 instructions, 19 calls, 0 into core) differing only in one `_DYNAMIC`
//!    offset, while on an earlier object they differed (349/19/2 against
//!    337/19/0). Two symmetric wrappers COULD legitimately compile to the same
//!    shape, but identical counts are equally consistent with the block
//!    boundaries below picking up the wrong function: `--disassemble=SYM` does
//!    not promise exactly one function, and the `take_while` on a blank line is
//!    an assumption about objdump's layout, not a documented contract.
//! 2. Two runs of the SAME source produced objects of different sizes
//!    (21622800 and 21622776 bytes), so the build is not reproducible run to run
//!    — plausibly `codegen-units = 16` in the default release profile, but
//!    unverified.
//!
//! Until both are settled, treat a `calls_into_core` number here as a lead and
//! not as evidence, and do not put one in a ledger row. What IS established is
//! the plumbing: `objdump` can be reached on a worker through `cargo run`, and
//! the object is now built and identified by SHA-256 before it is read.

use std::collections::BTreeMap;
use std::process::Command;

/// Wrappers whose core delegate is the open question (bd-abi-core-inline-boundary-nmjdud).
const DEFAULT_SYMBOLS: &[&str] = &["memrchr", "memchr", "strnlen", "strlen"];

/// The target directory the shipped cdylib is read from AND built into.
///
/// Both must be the same directory or the probe rebuilds one artifact and
/// disassembles another — which is precisely what happened on the first attempt
/// to fix the staleness: the inner `cargo build` inherited no `CARGO_TARGET_DIR`
/// (the outer invocation unsets it and passes `--config build.target-dir`
/// instead), so it built into the overlay's default `target/` while this probe
/// went on reading `/data/tmp/cargo-target-frankenlibc`. The SHA-256 was
/// unchanged across a source revert, which is the only reason the mistake was
/// visible at all.
fn target_dir() -> String {
    std::env::var("FRANKENLIBC_BENCH_TARGET_DIR")
        .or_else(|_| std::env::var("CARGO_TARGET_DIR"))
        .unwrap_or_else(|_| "target".to_owned())
}

fn shared_object() -> String {
    format!("{}/release/libfrankenlibc_abi.so", target_dir())
}

/// Name the callee of one `call` line, resolving GOT slots through relocations.
///
/// A direct call renders as `call <mangled_name>`. An INDIRECT call through the
/// GOT renders as `call *0x..(%rip)` with a trailing `# 0x<slot> <_DYNAMIC+0x..>`
/// comment, because no symbol covers the GOT slot itself. The first version of
/// this probe read the `<...>` label and so reported every such call as
/// `_DYNAMIC+0x1cd0` -- which then failed the `contains("frankenlibc_core")`
/// test and was counted as NOT a call into core. That is the wrong way to be
/// wrong: an indirect call is precisely the interposable, non-inlinable case
/// this probe exists to find, so it must be named, not discarded.
fn resolve_call_target(line: &str, got: &BTreeMap<u64, String>) -> String {
    if let Some(comment) = line.split('#').nth(1) {
        let slot = comment.trim().trim_start_matches("0x");
        let slot = slot.split_whitespace().next().unwrap_or_default();
        if let Ok(address) = u64::from_str_radix(slot, 16) {
            return match got.get(&address) {
                Some(symbol) => format!("GOT:{symbol}"),
                None => format!("GOT:unresolved@{address:#x}"),
            };
        }
    }
    line.split('<')
        .nth(1)
        .map(|tail| tail.trim_end_matches('>').trim().to_owned())
        .unwrap_or_else(|| "indirect".to_owned())
}

/// Map every dynamic relocation slot address to the symbol it binds.
///
/// `objdump -R` prints `<offset> <type> <symbol>`; the offset is the GOT slot
/// address that appears in the disassembly comment, so this is what turns an
/// anonymous slot back into a callee name.
/// Every defined symbol as `(address, size, name)`, sorted by address.
///
/// Used to name an address that no relocation names -- specifically an ifunc
/// resolver, which `objdump -R` reports only as `*ABS*+0x<addr>`.
fn symbol_table(object: &str) -> Vec<(u64, u64, String)> {
    let Ok(out) = Command::new("nm").args(["-S", "--defined-only", object]).output() else {
        return Vec::new();
    };
    let mut table: Vec<(u64, u64, String)> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let value = u64::from_str_radix(fields.next()?, 16).ok()?;
            let size = u64::from_str_radix(fields.next()?, 16).ok()?;
            let _kind = fields.next()?;
            Some((value, size, fields.next()?.to_owned()))
        })
        .collect();
    table.sort_by_key(|(address, _, _)| *address);
    table
}

/// Name the function containing `address`, or `None` if no symbol covers it.
fn symbol_at(table: &[(u64, u64, String)], address: u64) -> Option<&str> {
    let index = table.partition_point(|(start, _, _)| *start <= address);
    let (start, size, name) = table.get(index.checked_sub(1)?)?;
    (address < start + size.max(&1)).then_some(name.as_str())
}

fn relocation_map(object: &str) -> BTreeMap<u64, String> {
    let mut map = BTreeMap::new();
    let Ok(out) = Command::new("objdump").args(["-R", object]).output() else {
        return map;
    };
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let mut fields = line.split_whitespace();
        let (Some(offset), Some(kind), Some(symbol)) =
            (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        if let Ok(address) = u64::from_str_radix(offset, 16) {
            // The TYPE is kept, not discarded. Both R_X86_64_IRELATIVE (a real
            // ifunc, resolver-dispatched) and R_X86_64_RELATIVE (an ordinary
            // GOT-indirect call to a locally defined function) print their
            // target as `*ABS*+0x<addr>`, so the address alone cannot tell them
            // apart -- and calling the second one "ifunc" would misname the
            // mechanism while the numbers stayed right.
            let symbol = symbol.trim_end_matches("@GLIBC_2.2.5");
            map.insert(address, format!("{kind} {symbol}"));
        }
    }
    map
}

/// `(st_value, st_size)` for a defined symbol, read from the symbol table.
///
/// `nm -S --defined-only` prints `<value> <size> <type> <name>` for sized
/// definitions. The size is the whole point: it turns "disassemble near this
/// name and guess where it ends" into an exact range, which is what makes two
/// adjacent wrappers distinguishable from each other.
fn symbol_bounds(object: &str, symbol: &str) -> Option<(u64, u64)> {
    let out = Command::new("nm")
        .args(["-S", "--defined-only", object])
        .output()
        .ok()?;
    String::from_utf8_lossy(&out.stdout).lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        let value = u64::from_str_radix(fields.next()?, 16).ok()?;
        let size = u64::from_str_radix(fields.next()?, 16).ok()?;
        let _kind = fields.next()?;
        (fields.next()? == symbol).then_some((value, size))
    })
}

fn main() {
    let object = shared_object();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let symbols: Vec<&str> = if args.is_empty() {
        DEFAULT_SYMBOLS.to_vec()
    } else {
        args.iter().map(String::as_str).collect()
    };

    // BUILD THE CDYLIB FIRST. `cargo run --example` builds the example and the abi
    // RLIB; the cdylib is a separate target nothing in that command requires, and
    // the target dir persists per worker — so reading it without rebuilding
    // disassembles whatever the last run happened to leave there. That is exactly
    // how incumbent_coverage_ab measured a stale object for four conversions
    // (bd-incumbent-stale-fl-artifact-pph3a1), and this probe reproduced the same
    // mistake on its first outing: two runs of DIFFERENT source trees reported
    // byte-identical results because both read one leftover artifact.
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
    let build = Command::new(&cargo)
        .args(["build", "--quiet", "--profile", "release", "-p", "frankenlibc-abi"])
        // Same directory this probe reads from — see `target_dir`.
        .env("CARGO_TARGET_DIR", target_dir())
        .status()
        .expect("build the FrankenLibC cdylib");
    assert!(build.success(), "cdylib build failed");

    // Identify the object by CONTENT, not by path or size. Two builds of different
    // source can share a size; only the hash settles which one is on disk, and a
    // probe whose output cannot be tied to an artifact proves nothing.
    let bytes = match std::fs::read(&object) {
        Ok(bytes) => bytes,
        Err(error) => {
            println!("DISASM_UNAVAILABLE path={object} reason={error}");
            std::process::exit(2);
        }
    };
    let digest = <sha2::Sha256 as sha2::Digest>::digest(&bytes);
    let mut hex = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut hex, "{byte:02x}").expect("write hex");
    }
    println!(
        "DISASM_OBJECT path={object} bytes={} sha256={hex}",
        bytes.len()
    );

    // `nm` is preflighted for the same reason `objdump` is: `symbol_bounds`
    // returns None when the tool is missing, which would print
    // `status=not_in_symbol_table` for EVERY symbol and read like a clean
    // finding that none of them exist. A missing tool must look like a missing
    // tool.
    match Command::new("nm").arg("--version").output() {
        Ok(out) if out.status.success() => {
            let first = String::from_utf8_lossy(&out.stdout);
            println!("DISASM_TOOL nm={}", first.lines().next().unwrap_or("unknown"));
        }
        _ => {
            println!("DISASM_UNAVAILABLE reason=nm_not_runnable");
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

    let table = symbol_table(&object);
    // An IRELATIVE relocation names no symbol -- `objdump -R` prints only
    // `*ABS*+0x<resolver>`. Mapping that address back through the symbol table
    // is what distinguishes "this call vanished into core" from "this call is
    // an ifunc dispatch", which are opposite answers to the inlining question.
    let got: BTreeMap<u64, String> = relocation_map(&object)
        .into_iter()
        .map(|(slot, symbol)| {
            let (kind, target) = symbol.split_once(' ').unwrap_or(("?", &symbol));
            let resolved = target
                .strip_prefix("*ABS*+0x")
                .and_then(|hex| u64::from_str_radix(hex, 16).ok())
                .and_then(|address| symbol_at(&table, address))
                .map(|name| format!("{kind}:{name}"));
            let kind = kind.to_owned();
            (slot, resolved.unwrap_or_else(|| format!("{kind}:{target}")))
        })
        .collect();
    println!(
        "DISASM_RELOCATIONS slots={} symbols={}",
        got.len(),
        table.len()
    );

    for symbol in symbols {
        // Bounds come from the ELF symbol table, not from objdump's textual
        // layout. The first version searched the disassembly for `<symbol>:` and
        // read to the next blank line -- an assumption about formatting rather
        // than a contract, since `--disassemble=SYM` does not promise exactly one
        // function -- and it reported `memrchr` and `memchr` with byte-identical
        // bodies. `st_value`/`st_size` let the range be stated instead of guessed.
        let Some((address, size)) = symbol_bounds(&object, symbol) else {
            println!("DISASM_SYMBOL symbol={symbol} status=not_in_symbol_table");
            continue;
        };
        let out = Command::new("objdump")
            .args([
                "-d",
                &format!("--start-address=0x{address:x}"),
                &format!("--stop-address=0x{:x}", address + size),
                &object,
            ])
            .output()
            .expect("run objdump");
        let text = String::from_utf8_lossy(&out.stdout);

        // Instruction lines look like `  <hex addr>:\t<bytes>\t<mnemonic> ...`;
        // headers and the section banner carry no tabs.
        let body: Vec<&str> = text
            .lines()
            .filter(|line| line.contains(":\t") && line.matches('\t').count() >= 2)
            .collect();

        if body.is_empty() {
            println!(
                "DISASM_SYMBOL symbol={symbol} status=empty_range addr={address:#x} size={size}"
            );
            continue;
        }

        let instructions = body.len();
        let calls: Vec<String> = body
            .iter()
            .filter(|line| line.contains("\tcall"))
            .map(|line| resolve_call_target(line, &got))
            .collect();

        let core_calls = calls
            .iter()
            .filter(|target| target.contains("frankenlibc_core"))
            .count();

        // Counted separately because an indirect call is a different cost and a
        // different hazard from a direct one: it cannot be inlined, and it is
        // interposable, which is the mechanism behind both the PLT-tax vein and
        // the interposed-symbol recursion class.
        let indirect_calls = calls
            .iter()
            .filter(|target| target.starts_with("GOT:"))
            .count();

        println!(
            "DISASM_SYMBOL symbol={symbol} addr={address:#x} size={size} \
             instructions={instructions} calls={} calls_into_core={core_calls} \
             indirect_calls={indirect_calls} targets={:?}",
            calls.len(),
            calls
        );
    }
}
