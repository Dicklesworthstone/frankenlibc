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
fn resolve_call_target(
    line: &str,
    got: &BTreeMap<u64, String>,
    sections: &[(String, u64, u64)],
) -> String {
    if let Some(comment) = line.split('#').nth(1) {
        // fall through to slot resolution below
        let slot = comment.trim().trim_start_matches("0x");
        let slot = slot.split_whitespace().next().unwrap_or_default();
        if let Ok(address) = u64::from_str_radix(slot, 16) {
            let section = section_of(sections, address);
            return match got.get(&address) {
                Some(symbol) => format!("[{section}]{symbol}"),
                None => format!("[{section}]unresolved@{address:#x}"),
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
/// The set of symbols in `.dynsym` -- i.e. the ones that are INTERPOSABLE.
///
/// This is the discriminating fact for the inlining question. A call to a
/// symbol another object could replace at load time must stay an indirect call
/// through the GOT, and LLVM may not inline through it, no matter what
/// `#[inline]` the callee carries. So "is this core symbol exported?" and "why
/// did #[inline] change nothing?" are the same question.
/// Section headers as `(name, address, size)`, for locating a slot address.
///
/// Which section a call's target slot lives in names the MECHANISM. `.got` is
/// the linker's own global offset table -- a codegen/relocation decision.
/// `.data.rel.ro` is an ordinary initialised static holding a function pointer
/// -- i.e. a dispatch table the source wrote on purpose. Same instruction, two
/// different explanations, and only the section tells them apart.
fn sections(object: &str) -> Vec<(String, u64, u64)> {
    let Ok(out) = Command::new("objdump").args(["-h", object]).output() else {
        return Vec::new();
    };
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let _index: u32 = fields.next()?.parse().ok()?;
            let name = fields.next()?.to_owned();
            let size = u64::from_str_radix(fields.next()?, 16).ok()?;
            let address = u64::from_str_radix(fields.next()?, 16).ok()?;
            Some((name, address, size))
        })
        .collect()
}

/// Every section whose address range covers `address`, joined -- NOT the first.
///
/// `.tbss` is allocated but occupies no file space, so its address range
/// OVERLAPS the section that follows it. A first-match scan therefore reports
/// `.tbss` for slots that cannot possibly live there (a thread-local BSS
/// section cannot hold a load-time-relocated call slot), which is what the
/// first version of this did for every slot in every symbol. Joining all
/// matches keeps the overlap visible instead of resolving it by accident.
fn section_of(sections: &[(String, u64, u64)], address: u64) -> String {
    let matches: Vec<&str> = sections
        .iter()
        .filter(|(_, start, size)| address >= *start && address < start + size)
        .map(|(name, _, _)| name.as_str())
        .collect();
    if matches.is_empty() {
        return "?".to_owned();
    }
    matches.join("|")
}

fn dynamic_symbols(object: &str) -> std::collections::BTreeSet<String> {
    let Ok(out) = Command::new("nm").args(["-D", "--defined-only", object]).output() else {
        return Default::default();
    };
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|line| line.split_whitespace().nth(2).map(str::to_owned))
        .collect()
}

/// Parse one `nm -S --defined-only` line into `(value, size, name)`.
///
/// `nm -S` prints `<value> <size> <type> <name>` ONLY for symbols that carry a
/// size; for the rest it prints `<value> <type> <name>` and the size column is
/// simply absent. A parser that assumes the four-field form silently fails on
/// the three-field one -- which is why `strcpy` and `strncpy` were reported as
/// `not_in_symbol_table`, a clean-looking negative for symbols that are present.
/// Size 0 here means "unknown", and the caller substitutes the distance to the
/// next symbol.
fn parse_nm_line(line: &str) -> Option<(u64, u64, String)> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    match fields.as_slice() {
        [value, size, _type, name] => Some((
            u64::from_str_radix(value, 16).ok()?,
            u64::from_str_radix(size, 16).ok()?,
            (*name).to_owned(),
        )),
        [value, _type, name] => {
            Some((u64::from_str_radix(value, 16).ok()?, 0, (*name).to_owned()))
        }
        _ => None,
    }
}

fn symbol_table(object: &str) -> Vec<(u64, u64, String)> {
    let Ok(out) = Command::new("nm").args(["-S", "--defined-only", object]).output() else {
        return Vec::new();
    };
    let mut table: Vec<(u64, u64, String)> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(parse_nm_line)
        .collect();
    table.sort_by_key(|(address, _, _)| *address);

    // Fill in unknown sizes from the distance to the next symbol, so a sizeless
    // definition still yields a disassemblable range instead of dropping out.
    for index in 0..table.len() {
        if table[index].1 == 0 {
            if let Some((next, _, _)) = table.get(index + 1) {
                table[index].1 = next.saturating_sub(table[index].0);
            }
        }
    }
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
fn symbol_bounds(table: &[(u64, u64, String)], symbol: &str) -> Option<(u64, u64)> {
    table
        .iter()
        .find(|(_, _, name)| name == symbol)
        .map(|(address, size, _)| (*address, *size))
}

fn main() {
    let object = shared_object();
    let args: Vec<String> = std::env::args().skip(1).collect();
    // `--version-script=PATH` links the cdylib through that script, which is the
    // ONLY way to observe the deployed export surface from here: build.rs applies
    // version_scripts/libc.map only under --features standalone,owned-unwind-stub,
    // and that feature set currently fails its own policy gate (bd-haor6r), so the
    // deployed configuration cannot be built at all. Passing the script directly
    // asks the narrower question -- what would this script export? -- without
    // needing the policy gate to pass.
    //
    // Note this forces a full rebuild: RUSTFLAGS is part of cargo's fingerprint.
    // The flags from .cargo/config.toml are repeated here because setting the
    // RUSTFLAGS env var REPLACES them rather than appending, and dropping
    // +avx2,+fma would silently change the codegen under test.
    // `--rustflags=...` rebuilds the cdylib with extra flags before disassembling
    // it, which is how a CODEGEN question gets asked directly -- e.g. does
    // -Zdefault-visibility=protected turn the GOT-indirect abi->core calls into
    // direct ones (bd-kuevs7).
    //
    // A LINK-time flag does NOT work here and the failure is worth recording:
    // `--version-script=` was tried first and broke the build, because RUSTFLAGS
    // reaches every crate including build scripts, and serde_core's build script
    // cannot link against a version script naming symbols it does not define.
    // Scoping a link arg to just the cdylib needs --target plumbing (which also
    // moves the artifact path) or build.rs's cargo:rustc-cdylib-link-arg.
    let extra_rustflags: Option<&str> = args
        .iter()
        .find_map(|arg| arg.strip_prefix("--rustflags="));
    let symbols: Vec<&str> = if args.is_empty() {
        DEFAULT_SYMBOLS.to_vec()
    } else {
        args.iter()
            .map(String::as_str)
            .filter(|arg| !arg.starts_with("--rustflags="))
            .collect()
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
    let mut command = Command::new(&cargo);
    command
        .args(["build", "--quiet", "--profile", "release", "-p", "frankenlibc-abi"])
        // Same directory this probe reads from — see `target_dir`.
        .env("CARGO_TARGET_DIR", target_dir());
    if let Some(extra) = extra_rustflags {
        // The flags from .cargo/config.toml are repeated because setting the
        // RUSTFLAGS env var REPLACES them rather than appending, and silently
        // dropping +avx2,+fma would change the codegen under test.
        let flags = format!("-Z threads=4 -Ctarget-feature=+avx2,+fma {extra}");
        println!("DISASM_RUSTFLAGS value={flags:?}");
        command.env("RUSTFLAGS", flags);
    }
    let build = command.status().expect("build the FrankenLibC cdylib");
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
    let section_headers = sections(&object);
    let exported = dynamic_symbols(&object);
    println!(
        "DISASM_RELOCATIONS slots={} symbols={} dynamic_symbols={}",
        got.len(),
        table.len(),
        exported.len()
    );

    for symbol in symbols {
        // Bounds come from the ELF symbol table, not from objdump's textual
        // layout. The first version searched the disassembly for `<symbol>:` and
        // read to the next blank line -- an assumption about formatting rather
        // than a contract, since `--disassemble=SYM` does not promise exactly one
        // function -- and it reported `memrchr` and `memchr` with byte-identical
        // bodies. `st_value`/`st_size` let the range be stated instead of guessed.
        let Some((address, size)) = symbol_bounds(&table, symbol) else {
            // Name the near-misses. "Not in the symbol table" is a claim about
            // absence, and absence is the one result that should never be taken
            // on trust -- the same name may be defined with a prefix, a version
            // suffix, or not at all, and those are different facts.
            let near: Vec<&str> = table
                .iter()
                .filter(|(_, _, name)| name.contains(symbol))
                .map(|(_, _, name)| name.as_str())
                .take(6)
                .collect();
            // Whether it is EXPORTED is a separate fact from whether it is
            // defined in .symtab, and for a libc symbol it is the one that
            // decides if a program can call it at all.
            println!(
                "DISASM_SYMBOL symbol={symbol} status=not_in_symbol_table \
                 in_dynsym={} near={near:?}",
                exported.contains(symbol)
            );
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
            .map(|line| resolve_call_target(line, &got, &section_headers))
            .collect();

        let core_calls = calls
            .iter()
            .filter(|target| target.contains("frankenlibc_core"))
            .count();

        // Of the core callees reached indirectly, how many are exported? A
        // nonzero count here IS the reason the call could not be direct.
        let interposable_core_calls = calls
            .iter()
            .filter(|target| target.starts_with('[') && target.contains("frankenlibc_core"))
            .filter_map(|target| target.rsplit(':').next())
            .filter(|name| exported.contains(*name))
            .count();

        // Counted separately because an indirect call is a different cost and a
        // different hazard from a direct one: it cannot be inlined, and it is
        // interposable, which is the mechanism behind both the PLT-tax vein and
        // the interposed-symbol recursion class.
        let indirect_calls = calls
            .iter()
            .filter(|target| target.starts_with('['))
            .count();

        // Which ARCHITECTURE this wrapper uses, which is not visible from its
        // source or its name. `calls_into_core=0` does not mean the kernel was
        // inlined -- release is lto=false and the core fns carry no #[inline],
        // so cross-crate inlining was never available. It means the wrapper
        // reaches its work some other way, and for strlen/memcpy that way is an
        // abi-local raw lane that never enters frankenlibc_core at all.
        // Classified by the callee's CRATE, not by name patterns. The first
        // version matched a hand-written list (`raw_lane`, `simd_dispatch`, ...)
        // and so reported `class=neither` for strcmp, memset, memcmp, memmove,
        // wcslen and wcscmp -- every one of which does call an abi-local kernel
        // (`scan_strcmp`, `raw_memset_bytes`, ...) under a name I had not
        // guessed. A missing pattern looked exactly like a missing call.
        let lane_calls = calls
            .iter()
            .filter(|target| target.contains("frankenlibc_abi"))
            .count();
        let class = match (core_calls, lane_calls) {
            (0, 0) => "neither",
            (0, _) => "abi_lane",
            (_, 0) => "core_delegating",
            (_, _) => "both",
        };
        // in_dynsym is printed for EVERY symbol, not only absent ones, so that
        // any run carries its own positive control: if the .dynsym reader were
        // broken it would report false everywhere, and a false on one symbol
        // would be indistinguishable from a real finding about that symbol.
        println!(
            "DISASM_CLASS symbol={symbol} class={class} in_dynsym={} core={core_calls} lane={lane_calls} \
             ",
            exported.contains(symbol)
        );
        println!(
            "DISASM_CLASS2 symbol={symbol} class={class} core={core_calls} lane={lane_calls} \
             indirect={indirect_calls} instructions={instructions} size={size}"
        );

        println!(
            "DISASM_SYMBOL symbol={symbol} addr={address:#x} size={size} \
             instructions={instructions} calls={} calls_into_core={core_calls} \
             indirect_calls={indirect_calls} interposable_core_calls={interposable_core_calls} \
             targets={:?}",
            calls.len(),
            calls
        );
    }
}
