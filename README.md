# FrankenLibC

<div align="center">
  <img src="docs/assets/images/franken_libc_illustration.webp" alt="FrankenLibC illustration" width="720">
</div>

<div align="center">

![version](https://img.shields.io/badge/version-0.1.0-2f6feb)
![rust](https://img.shields.io/badge/rust-nightly-f74c00)
![platform](https://img.shields.io/badge/platform-linux-181717)
![license](https://img.shields.io/badge/license-MIT%20with%20rider-8a2be2)

</div>

**A clean-room Rust libc project that can interpose on glibc today for a meaningful but still incomplete workload set, applies a Transparent Safety Membrane at the ABI boundary, and incrementally replaces unsafe libc behavior with native Rust implementations and raw-syscall paths.**

There is no curl installer or package-manager release yet. The current fast path is:

```bash
git clone https://github.com/Dicklesworthstone/frankenlibc.git
cd FrankenLibC
cargo build -p frankenlibc-abi --release
LD_PRELOAD="$PWD/target/release/libfrankenlibc_abi.so" /bin/echo "hello from FrankenLibC"
```

Deployment details, runtime knobs, and Gentoo/Portage operations are collected in [`DEPLOYMENT.md`](/data/projects/frankenlibc/DEPLOYMENT.md).

## TL;DR

### The Problem

glibc is enormous, security-critical, and written in a language that cannot enforce memory safety at the ABI boundary. Existing Linux software still expects glibc-compatible symbols, calling conventions, and process semantics.

### The Solution

FrankenLibC puts a **Transparent Safety Membrane (TSM)** behind a glibc-shaped ABI. Every libc entrypoint can validate, sanitize, repair, deny, and audit before handing control to safe Rust code, raw Linux syscalls, or, where the project is not done yet, a constrained host-glibc call-through.

### Why Use FrankenLibC?

Current source of truth: `tests/conformance/reality_report.v1.json`.

| Why it matters | Current state |
|---|---|
| Large classified ABI surface | `4119` exported symbols classified |
| Native ownership is already broad | `3705 Implemented` + `414 RawSyscall` = `100.0%` native coverage |
| No exported stubs right now | `0 Stub` |
| Interposition is already usable on many workloads | `target/release/libfrankenlibc_abi.so` via `LD_PRELOAD`, with broader smoke and hardened-mode stability still in progress |
| Hardened mode exists now | `FRANKENLIBC_MODE=hardened` |
| Verification is first-class | harness CLI, conformance fixtures, maintenance gates, smoke scripts, perf scripts |
| Runtime math is live code | `frankenlibc-membrane/src/runtime_math/` contains active control kernels, not just design docs |

## Quick Example

```bash
# 1. Build the interpose artifact
cargo build -p frankenlibc-abi --release

# 2. Inspect the current symbol reality
cargo run -p frankenlibc-harness --bin harness -- reality-report \
  --support-matrix support_matrix.json \
  --output /tmp/frankenlibc-reality.json

# 3. Run something small in strict mode
LD_PRELOAD="$PWD/target/release/libfrankenlibc_abi.so" /bin/echo strict

# 4. Run the same idea in hardened mode
FRANKENLIBC_MODE=hardened \
LD_PRELOAD="$PWD/target/release/libfrankenlibc_abi.so" /bin/echo hardened

# 5. Run the membrane verification campaign
cargo run -p frankenlibc-harness --bin harness -- verify-membrane \
  --mode both \
  --output /tmp/healing_oracle.json

# 6. Check support-matrix maintenance drift
bash scripts/check_support_matrix_maintenance.sh

# 7. Run the preload smoke suite
TIMEOUT_SECONDS=10 bash scripts/ld_preload_smoke.sh
```

## Concrete Case Studies

These examples show the kind of work FrankenLibC is meant to support.

### Case study 1: unsafe legacy binary, no relink budget

You have a prebuilt C or C++ binary, you do not want to rebuild it, and you want a safer libc boundary for experiments:

```bash
FRANKENLIBC_MODE=hardened \
LD_PRELOAD="$PWD/target/release/libfrankenlibc_abi.so" \
./legacy_binary
```

Why it helps:

- no relink step
- no source-code rewrite requirement
- explicit artifact path
- membrane and verification tooling can be layered around the run

### Case study 2: documentation drift after a symbol promotion

You convert a symbol from `WrapsHostLibc` or `GlibcCallThrough` to `Implemented`, but you need to know whether reports still agree:

```bash
bash scripts/check_support_matrix_maintenance.sh
```

This catches one of the standard failure modes in replacement-library work: code and status claims drifting apart.

### Case study 3: hardened-mode semantics as an engineering question

Instead of arguing abstractly about whether hardened mode "works," the repo has an explicit membrane verification path:

```bash
cargo run -p frankenlibc-harness --bin harness -- verify-membrane \
  --mode both \
  --output /tmp/healing_oracle.json
```

That fits the project well: behavior captured as an artifact rather than asserted in prose.

## Design Philosophy

### 1. ABI first

This project is only interesting if existing binaries can talk to it. The ABI boundary is the contract: symbol names, calling conventions, version scripts, `errno`, mode semantics, and process-level behavior.

### 2. Safety at the edge

Unsafe C inputs are not trusted. The TSM sits at the libc boundary and classifies pointers, regions, fds, and contexts before anything meaningful happens.

### 3. Native replacement by pressure, not by vanity

The project does not pretend the whole world is already reimplemented. Each exported symbol is explicitly classified as `Implemented`, `RawSyscall`, `WrapsHostLibc`, `GlibcCallThrough`, or `Stub`, and the matrix is machine-checked.

### 4. Clean-room over translation

The codebase is not a line-by-line Rust port of glibc. Behavior is driven by contracts, fixtures, and verification artifacts rather than transliterating legacy C.

### 5. Evidence beats rhetoric

Support claims, mode semantics, fixture coverage, drift checks, smoke tests, and release gates all live in code and machine-generated artifacts. The README should summarize them, not replace them.

## Design Invariants

These invariants are meant to hold as the codebase grows:

| Invariant | Why it exists |
|---|---|
| Safety interpretation only gets more restrictive with new evidence | avoids optimistic reclassification after suspicious observations |
| Runtime mode is process-wide and immutable after startup | keeps behavior deterministic and analyzable |
| Hardened repairs are deterministic | makes behavior replayable and auditable |
| Every exported symbol must be explicitly classified | prevents silent unknown-support zones |
| Documentation and machine artifacts are expected to agree | drift is treated as a bug, not a cosmetic issue |
| Clean-room implementation remains the rule | keeps the project from degenerating into line-by-line translation |

## Comparison

| Dimension | glibc | musl | Sanitizers around glibc | FrankenLibC |
|---|---|---|---|---|
| Production Linux compatibility target | Native | Requires relink / different libc target | Native glibc only | Interpose-first, replacement later |
| Memory-safe implementation goal | No | No | No | Yes for native paths |
| Runtime repair mode | No | No | No | Yes, `hardened` |
| Per-symbol implementation census | No | No | No | Yes, `support_matrix.json` |
| Host-glibc dependency today | N/A | No | Yes | Yes for the current interpose deployment model |
| Raw syscall fallback paths | Internal | Internal | No | Explicit taxonomy |
| Auditable structured verification artifacts | Limited | Limited | Limited | Core workflow |

## Current State

Current source of truth: `tests/conformance/support_matrix_maintenance_report.v1.json`.

Declared replacement level claim: **L0 — Interpose**.

| Status | Count | % | Meaning |
|---|---:|---:|---|
| `Implemented` | 3705 | 90% | Native ABI-backed Rust-owned behavior |
| `RawSyscall` | 414 | 10% | ABI path delegates directly to Linux syscalls |
| `WrapsHostLibc` | 0 | 0% | Native wrapper that still calls host libc symbols internally |
| `GlibcCallThrough` | 0 | 0% | No direct host-glibc symbol call-through remains in the current classified surface |
| `Stub` | 0 | 0% | No exported stubs in the current classified surface |

Total currently classified exports: **4119**.
Current native coverage (`Implemented + RawSyscall`): **100.0%**.

Source of truth: `tests/conformance/reality_report.v1.json` (generated `2026-02-18T04:49:26Z`).

Reality snapshot: total_exported=4119, implemented=3705, raw_syscall=414, wraps_host_libc=0, glibc_call_through=0, stub=0.

In practice:

- The current shipping artifact is the **interpose** shared library: `target/release/libfrankenlibc_abi.so`.
- The future **replace** artifact (`libfrankenlibc_replace.so`) is still planned, not done.
- The classified symbol surface no longer reports direct `GlibcCallThrough` or `WrapsHostLibc` symbols, but the current shipping artifact is still an interpose-first preload library rather than a full standalone libc replacement.
- Canonical checked smoke artifact: `tests/conformance/ld_preload_smoke_summary.v1.json` (run `20260404T011731Z`, checked April 4, 2026) reports 58 passes / 0 fails / 6 skips overall, with strict 29/0/3 and hardened 29/0/3 across the curated preload smoke battery.
- The six skips are the optional `sqlite3`, `redis-cli`, and `nginx` probes across both modes. That checked curated battery is green; broader production hardening, release-claim closure, and non-curated workload stability are still tracked separately.

## Threat Model

FrankenLibC focuses on the kinds of failures that become visible at the libc boundary.

| In scope | Why it matters |
|---|---|
| Invalid pointers and regions passed into libc calls | libc is a high-frequency choke point for memory-unsafe programs |
| Allocation misuse visible through libc APIs | allocator corruption, double-free, and temporal misuse often surface here |
| Invalid or ambiguous stdio / `_IO_*` state transitions | stream state is complex and historically bug-prone |
| Boundary-level integrity failures | fingerprints, canaries, ownership checks, and bounds checks can detect misuse before it silently compounds |
| Drift between implementation claims and actual behavior | the repo treats stale support claims as a real correctness problem |

| Out of scope | Why |
|---|---|
| Arbitrary application logic bugs | the project operates at the libc boundary, not as a whole-program verifier |
| Kernel correctness | raw-syscall paths still rely on kernel behavior |
| Bugs that never cross a libc path | if libc is never involved, the membrane never gets a chance to classify the event |
| Full standalone replacement today | that remains a staged future milestone |

## Support Taxonomy Deep Dive

The status taxonomy is the control system for the project’s staged migration.

| Status | Meaning | Artifact implications |
|---|---|---|
| `Implemented` | FrankenLibC owns the symbol behavior natively | valid for interpose and eventual replace |
| `RawSyscall` | FrankenLibC owns the ABI path and goes straight to Linux syscalls | valid for interpose and eventual replace |
| `WrapsHostLibc` | native wrapper that still calls host libc symbols internally | valid for interpose only |
| `GlibcCallThrough` | symbol still depends on host glibc | valid for interpose only |
| `Stub` | deterministic fallback contract without full implementation | currently absent from the exported surface |

Why this taxonomy exists:

- it distinguishes real ownership from temporary delegation
- it prevents “mostly implemented” from being vague
- it makes interpose and replace claims mechanically checkable
- it gives every symbol promotion a precise meaning

## What We Have Actually Built

The project is no longer just an architecture sketch. Today’s repo contains:

| Area | What exists now |
|---|---|
| ABI boundary | A large `extern "C"` surface in `crates/frankenlibc-abi`, including native stdio, string, math, allocator, resolver, locale, and syscall-facing entrypoints |
| Safety membrane | Validation, healing, metrics, runtime policy, runtime math controllers, and pointer-safety infrastructure in `crates/frankenlibc-membrane` |
| Safe semantic kernels | Safe Rust implementations in `crates/frankenlibc-core` for string, stdio, math, ctype, malloc, locale, pthread, resolver, and more |
| Verification harness | A dedicated CLI in `crates/frankenlibc-harness` for fixture capture, verification, traceability, reality reports, membrane verification, evidence compliance, and runtime-math snapshots |
| Conformance assets | Fixture packs, maintenance reports, smoke tests, golden snapshots, release gates, and drift-check scripts under `tests/` and `scripts/` |
| Bench infrastructure | Criterion benches in `crates/frankenlibc-bench` plus perf scripts and baselines in `scripts/` |

It is useful to think of FrankenLibC as three things at once:

1. A libc interposition artifact you can run today on many workloads, with broader stabilization still underway.
2. A memory-safety and repair substrate at the libc ABI edge.
3. A verification-heavy engineering program for turning more of glibc into native Rust without hiding the unfinished parts.

## Why This Is Useful In Practice

FrankenLibC is useful anywhere the libc boundary is the last realistic place to impose safety or observability without rewriting the whole program.

| Scenario | Why FrankenLibC helps |
|---|---|
| Legacy C/C++ binaries | `LD_PRELOAD` lets you experiment without relinking the program |
| Security testing | `hardened` mode can expose and constrain unsafe behavior that would otherwise corrupt memory silently |
| Compatibility research | The support matrix and reality reports make it explicit which symbols are owned natively vs still delegated |
| Differential verification | The harness can compare FrankenLibC behavior against host glibc fixture packs |
| Replacement-library R&D | The taxonomy and gating model support gradual movement from interpose to standalone replace |
| Observability and evidence | Structured reports and maintenance artifacts make the project auditable instead of anecdotal |

FrankenLibC treats libc replacement as a staged engineering problem with explicit measurements, evidence, and safety goals.

## Installation

### 1. Build from source

Requirements:

- Linux
- Rust nightly with `rustfmt` and `clippy`
- A normal Cargo toolchain; this repo is a Rust workspace, not a mixed package-manager project

```bash
git clone https://github.com/Dicklesworthstone/frankenlibc.git
cd FrankenLibC
rustup toolchain install nightly
cargo build -p frankenlibc-abi --release
```

Output:

```bash
target/release/libfrankenlibc_abi.so
```

### 2. Install into a local prefix

```bash
install -d "$HOME/.local/lib/frankenlibc"
install -m 755 target/release/libfrankenlibc_abi.so "$HOME/.local/lib/frankenlibc/"
LD_PRELOAD="$HOME/.local/lib/frankenlibc/libfrankenlibc_abi.so" /bin/echo hello
```

### 3. System-style install for experiments

```bash
sudo install -d /usr/lib/frankenlibc
sudo install -m 755 target/release/libfrankenlibc_abi.so /usr/lib/frankenlibc/
LD_PRELOAD=/usr/lib/frankenlibc/libfrankenlibc_abi.so /bin/echo hello
```

### What does not exist yet

- No curl installer
- No Homebrew formula
- No crates.io install path for the interpose library
- No distro packages

## Why libc Replacement Is Hard

Replacing libc is hard for reasons that compound:

| Difficulty | Why it matters |
|---|---|
| ABI stability | existing binaries expect exact symbol names, calling conventions, versioning, and process semantics |
| Undefined behavior pressure | libc is where many unsafe programs hand ambiguous or invalid state to the runtime |
| Startup coupling | early process initialization is unforgiving and sensitive to ordering assumptions |
| Threading semantics | concurrency surfaces are subtle even before compatibility constraints are added |
| Locale and iconv breadth | these areas involve huge semantic surfaces, not just a handful of functions |
| Loader behavior | `dlopen`/`dlsym` and dynamic linking are globally coupled to the process |
| Performance pressure | libc is hot-path infrastructure, so correctness improvements cannot ignore latency entirely |

Those constraints are why FrankenLibC is staged, report-heavy, and explicit about what is real today versus merely planned.

## Quick Start

### 1. Build the library

```bash
cargo build -p frankenlibc-abi --release
```

### 2. Build the harness and inspect the classified surface

```bash
cargo run -p frankenlibc-harness --bin harness -- reality-report \
  --support-matrix support_matrix.json \
  --output /tmp/frankenlibc-reality.json
cat /tmp/frankenlibc-reality.json
```

### 3. Run strict mode

```bash
LD_PRELOAD="$PWD/target/release/libfrankenlibc_abi.so" /bin/ls
```

### 4. Run hardened mode

```bash
FRANKENLIBC_MODE=hardened \
LD_PRELOAD="$PWD/target/release/libfrankenlibc_abi.so" /bin/ls
```

### 5. Run the default repo gates

```bash
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

### 6. Run the conformance and smoke tooling

```bash
bash scripts/check_support_matrix_maintenance.sh
bash scripts/check_c_fixture_suite.sh
TIMEOUT_SECONDS=10 bash scripts/ld_preload_smoke.sh
```

## Worked Call Flows

These are simplified end-to-end sketches, but they reflect the intended structure of the system.

### `malloc` / `free`

```text
C caller
  ->
ABI entrypoint
  ->
runtime policy decision
  ->
membrane ownership / temporal checks
  ->
allocator path in core
  ->
evidence / metrics update
  ->
pointer or failure returned
```

Allocator surfaces are among the highest-risk parts of libc, and temporal safety and ownership checks are meaningful here, not decorative.

### `memcpy` / string-family writes

```text
C caller
  ->
ABI boundary
  ->
pointer and region classification
  ->
size / bounds policy
  ->
strict: allow or compat-fail
    or
hardened: clamp / truncate / deny
  ->
native string kernel
```

String and memory APIs are both ubiquitous and dangerous; this is where hardened-mode repair stops being abstract.

### `fopen` / `fread` / `fwrite`

```text
C caller
  ->
stdio or io_internal ABI entrypoint
  ->
stream lookup and buffering policy
  ->
native stdio path or syscall-facing path
  ->
seek / flush / stat / internal _IO_* compatibility behavior
  ->
evidence and support reports keep the claims honest
```

The stdio and internal `_IO_*` surfaces are large enough that progress must be made incrementally and audited symbol by symbol.

## Common Commands

This repo is a workspace with a library artifact plus a verification harness. The most useful commands are:

| Workflow | Command | What it does |
|---|---|---|
| Build interpose library | `cargo build -p frankenlibc-abi --release` | Produces `libfrankenlibc_abi.so` |
| Workspace correctness gate | `cargo check --workspace --all-targets` | Compile validation |
| Lint gate | `cargo clippy --workspace --all-targets -- -D warnings` | Lint validation |
| Test gate | `cargo test --workspace` | Unit + integration coverage |
| Repo CI gate | `bash scripts/ci.sh` | Project-standard default gate |
| Support-matrix drift check | `bash scripts/check_support_matrix_maintenance.sh` | Regenerates and validates maintenance report |
| Preload smoke test | `bash scripts/ld_preload_smoke.sh` | Real program interposition smoke |
| C fixture suite | `bash scripts/check_c_fixture_suite.sh` | Integration-fixture validation |
| Reality report | `cargo run -p frankenlibc-harness --bin harness -- reality-report --support-matrix support_matrix.json --output /tmp/reality.json` | Machine-readable current-state summary |
| Fixture verification | `cargo run -p frankenlibc-harness --bin harness -- verify --fixture tests/conformance/fixtures --report /tmp/conformance.md` | Replays fixture packs |
| Membrane verification | `cargo run -p frankenlibc-harness --bin harness -- verify-membrane --mode both --output /tmp/healing.json` | Runs strict/hardened healing oracle |
| Benchmarking | `cargo bench -p frankenlibc-bench` | Benchmarks library hot paths |

Interpretation note:

- Passing fixture, oracle, or CVE-pattern scripts is evidence about the membrane and targeted scenarios.
- That is not automatically end-to-end proof that FrankenLibC would have prevented the corresponding exploit in an arbitrary upstream program build.
- `LD_PRELOAD`-based deployment claims do not apply to setuid/setgid binaries because the loader ignores `LD_PRELOAD` there.

## Performance Model

Performance matters because libc is on the hot path of almost every process. The project therefore tries to stage work so cheap, high-signal checks happen first and expensive reasoning is reserved for cases that deserve it.

Typical ordering rationale:

1. trivial null / immediate-fail checks
2. thread-local cache before global metadata
3. bloom-style plausibility before expensive ownership lookup
4. arena and integrity validation once plausibility is established
5. bounds and policy checks once the object is believed to be real

The ordering preserves three properties:

- fast paths stay fast
- suspicious paths get deeper scrutiny
- hardened mode costs more only when the extra scrutiny is justified

## Configuration

The important runtime knob is `FRANKENLIBC_MODE`. The broader environment inventory is machine-generated in `tests/conformance/runtime_env_inventory.v1.json`.

Example operator shell setup:

```bash
# Runtime behavior
export FRANKENLIBC_MODE=hardened          # strict | hardened
export FRANKENLIBC_LOG=/tmp/franken.jsonl # optional structured runtime log

# Build / verification convenience
export FRANKENLIBC_LIB="$PWD/target/release/libfrankenlibc_abi.so"
export FRANKENLIBC_EXTENDED_GATES=0
export FRANKENLIBC_E2E_SEED=42
export FRANKENLIBC_E2E_STRESS_ITERS=5

# Example invocation
LD_PRELOAD="$FRANKENLIBC_LIB" /bin/echo configured
```

Environment inventory:

| Variable | Default | Notes |
|---|---|---|
| `FRANKENLIBC_MODE` | `strict` | Process-wide immutable mode selection |
| `FRANKENLIBC_LOG` | unset | Structured runtime log path |
| `FRANKENLIBC_LIB` | unset | Tooling override for the built interpose library |
| `FRANKENLIBC_EXTENDED_GATES` | `0` | Enables heavier CI / perf / snapshot gates |
| `FRANKENLIBC_E2E_SEED` | `42` | Deterministic seed for some E2E workflows |
| `FRANKENLIBC_E2E_STRESS_ITERS` | `5` | Stress iteration count for E2E scripts |
| `FRANKENLIBC_BENCH_PIN` | `0` | Benchmark-only CPU pinning control |
| `FRANKENLIBC_CLOSURE_CONTRACT_PATH` | `tests/conformance/closure_contract.v1.json` | Closure-contract gate input override |
| `FRANKENLIBC_CLOSURE_LEVEL` | auto | Closure gate target level override (`L0`..`L3`) |
| `FRANKENLIBC_CLOSURE_LOG` | `/tmp/frankenlibc_closure_contract.log.jsonl` | Closure gate evidence log destination |
| `FRANKENLIBC_HOOKS_LOADED` | `0` | Internal Gentoo hook bootstrap guard |
| `FRANKENLIBC_LOG_DIR` | `/var/log/frankenlibc/portage` | Gentoo hook directory root for generated logs |
| `FRANKENLIBC_LOG_FILE` | unset | Tooling alias path that is exported into `FRANKENLIBC_LOG` |
| `FRANKENLIBC_PACKAGE` | unset | Internal Gentoo package/atom context annotation |
| `FRANKENLIBC_PACKAGE_BLOCKLIST` | `sys-libs/glibc sys-apps/shadow` | Blocks LD_PRELOAD injection for sensitive Gentoo packages |
| `FRANKENLIBC_PERF_ALLOW_TARGET_VIOLATION` | `1` | Perf gate policy knob for target-budget enforcement |
| `FRANKENLIBC_PERF_ENABLE_KERNEL_SUITE` | `0` | Enables the additional kernel perf suite branch |
| `FRANKENLIBC_PERF_MAX_LOAD_FACTOR` | `0.85` | Host load cutoff for overloaded perf-run skipping |
| `FRANKENLIBC_PERF_MAX_REGRESSION_PCT` | `15` | Allowed perf regression threshold percentage |
| `FRANKENLIBC_PERF_SKIP_OVERLOADED` | `1` | Skips perf gate on overloaded hosts |
| `FRANKENLIBC_PHASE` | unset | Internal Gentoo phase label for hook/session logs |
| `FRANKENLIBC_PHASE_ACTIVE` | unset/`0` | Internal flag for balanced Gentoo hook teardown |
| `FRANKENLIBC_PHASE_ALLOWLIST` | `src_test pkg_test` | Limits which Gentoo phases activate FrankenLibC |
| `FRANKENLIBC_PORTAGE_ENABLE` | `1` | Global kill-switch for Gentoo Portage hooks |
| `FRANKENLIBC_PORTAGE_LOG` | `/tmp/frankenlibc-portage-hooks.log` | Gentoo hook decision log path |
| `FRANKENLIBC_RELEASE_SIMULATE_FAIL_GATE` | empty | Release dry-run test knob for injecting a named failing gate |
| `FRANKENLIBC_SKIP_STATIC` | `1` | Skips preload during static-libs Gentoo builds |
| `FRANKENLIBC_STARTUP_PHASE0` | `0` | Startup path gate for the phase-0 `__libc_start_main` flow |
| `FRANKENLIBC_TMPDIR` | unset | Tooling temp-root override, falling back to `TMPDIR` then `/tmp` |

## Architecture

```text
                  C process
                      |
                      v
    +--------------------------------------------+
    | glibc-shaped extern "C" ABI                |
    | crates/frankenlibc-abi                     |
    +--------------------------------------------+
                      |
                      v
    +--------------------------------------------+
    | Transparent Safety Membrane                |
    | crates/frankenlibc-membrane                |
    |                                            |
    | null -> tls -> bloom -> arena              |
    |      -> fingerprint -> canary              |
    |      -> bounds -> policy                   |
    +--------------------------------------------+
                      |
            +---------+---------+
            |                   |
            v                   v
    +------------------+  +----------------------+
    | Native Rust      |  | Raw syscall veneers  |
    | kernels          |  | mostly unistd/io/... |
    | frankenlibc-core |  +----------------------+
    +------------------+
            |
            v
    +--------------------------------------------+
    | Verification and evidence                  |
    | crates/frankenlibc-harness                 |
    | tests/, scripts/, reports                  |
    +--------------------------------------------+
```

## Why libc Is the Choke Point

FrankenLibC is built on the idea that libc is one of the highest-leverage places to impose safety and observability on legacy Unix software.

Why this boundary is attractive:

- almost every nontrivial program crosses it constantly
- many memory and resource bugs surface there even when they originate elsewhere
- it is close enough to real behavior to matter, but abstract enough to instrument systematically
- `LD_PRELOAD` gives an immediate deployment story for experiments

Libc is not a total solution, but it is a strategically valuable intervention point.

## What FrankenLibC Is Not

To avoid the wrong mental model:

- it is not yet a full standalone libc replacement
- it is not just a hardened allocator
- it is not just an `LD_PRELOAD` trick with no deeper architecture
- it is not a kernel sandbox
- it is not a whole-program verifier
- it is not “done” simply because native coverage is high on the classified surface

## Pointer-Safety Model

The membrane’s pointer-safety model is a composition of several checks, not a single oracle.

| Concern | Mechanism |
|---|---|
| ownership plausibility | bloom filter and metadata lookup |
| temporal safety | generational arena and lifetime tracking |
| integrity | fingerprints and canaries |
| bounds | region and size checks |
| suspicious state transitions | policy classification and runtime decision routing |
| unsafe-but-repairable behavior | deterministic healing actions |

Most real memory-unsafety incidents are mixed failures, not single clean categories. A useful system needs ownership, temporal, integrity, and bounds reasoning to cooperate.

## How The Transparent Safety Membrane Works

The membrane is the main architectural idea in the project. Instead of trusting raw C pointers because the caller crossed an ABI boundary, FrankenLibC treats the ABI boundary as the place where unsafe information must be classified.

Typical validation path:

```text
incoming pointer / region / fd / mode / context
    ->
null check
    ->
thread-local cache
    ->
bloom filter ownership precheck
    ->
arena / metadata lookup
    ->
fingerprint and canary validation
    ->
bounds / state checks
    ->
Allow | Repair | Deny
```

The classification outcome determines strict vs hardened behavior:

| Mode | Membrane behavior |
|---|---|
| `strict` | preserve compatibility-oriented behavior for supported paths; no repair rewrites |
| `hardened` | apply deterministic repair or denial instead of allowing corruption to continue |

Examples of repair actions already modeled in the code:

- clamp a size to known allocation bounds
- truncate a string write with a guaranteed trailing NUL
- ignore a double-free instead of corrupting allocator state
- treat invalid realloc patterns as a safe malloc path
- switch to a safer semantic variant when policy demands it

## Algorithms And Design Choices

FrankenLibC is unusually explicit about the algorithms it uses. Some of the important ones are:

| Mechanism | Where it shows up | Why it exists |
|---|---|---|
| Safety-state lattice | `crates/frankenlibc-membrane/src/lattice.rs` | Gives a monotone way to reason about pointer/state degradation |
| Galois-connection modeling | `crates/frankenlibc-membrane/src/galois.rs` | Bridges flat C semantics and richer internal safety semantics |
| Generational arena | `arena.rs` | Temporal-safety tracking, especially UAF detection |
| Fingerprints + canaries | `fingerprint.rs` | Allocation-integrity checks with low-overhead metadata |
| Bloom filters | `bloom.rs` | Cheap pointer-ownership precheck before expensive validation |
| TLS validation cache | `tls_cache.rs` | Keeps common validation paths out of global contention |
| Runtime policy routing | `runtime_policy.rs` and membrane runtime math | Lets the boundary choose between fast/full/repair/deny styles of behavior |
| Fixture-driven conformance | harness + `tests/conformance/fixtures` | Lets behavior claims be compared against host libc concretely |

Each of these solves a specific pressure point in libc replacement:

- compatibility pressure
- safety pressure
- performance pressure
- observability pressure
- staged-migration pressure

## Runtime Math Controllers

The `runtime_math/` tree encodes runtime decision logic for validation depth, risk handling, admissibility, and control under pressure.

Representative families already present in the repo:

| Family | Examples |
|---|---|
| Risk / sequential testing | `risk.rs`, `eprocess.rs`, `cvar.rs`, `conformal.rs`, `changepoint.rs` |
| Control / routing | `bandit.rs`, `control.rs`, `pareto.rs`, `design.rs`, `admm_budget.rs` |
| Consistency / coherence | `cohomology.rs`, `higher_topos.rs`, `grothendieck_glue.rs`, `hodge_decomposition.rs` |
| Statistical drift / anomaly detection | `kernel_mmd.rs`, `wasserstein_drift.rs`, `matrix_concentration.rs`, `transfer_entropy.rs` |
| Certified safety machinery | `hji_reachability.rs`, `sos_barrier.rs`, `sos_invariant.rs`, `mean_field_game.rs` |

Offline proofs and synthesis can be heavyweight, but runtime behavior must stay compact and deterministic. The codebase ships controller kernels and evidence structures, not theorem provers in the hot path.

## Replacement Strategy

FrankenLibC is deliberately staged.

| Stage | Meaning |
|---|---|
| Interpose now | Replace selected behavior behind `LD_PRELOAD`, while allowing explicit host call-throughs where still necessary |
| Expand native ownership | Convert more `WrapsHostLibc` / `GlibcCallThrough` symbols into `Implemented` or `RawSyscall` |
| Enforce artifact contracts | Use maintenance and replacement gates so interpose vs replace claims do not drift |
| Standalone replace later | Eliminate host-glibc dependencies for the replacement artifact |

This staged model is why the symbol taxonomy matters so much. Without a machine-readable map of what is native and what is still delegated, a project like this would quickly become impossible to reason about honestly.

### Workspace map

| Path | Purpose |
|---|---|
| `crates/frankenlibc-membrane` | TSM validation pipeline, healing policy, runtime math controllers |
| `crates/frankenlibc-core` | Safe Rust semantic implementations |
| `crates/frankenlibc-abi` | `extern "C"` boundary and the interpose shared library |
| `crates/frankenlibc-harness` | Fixture capture, verification, reporting, evidence tooling |
| `crates/frankenlibc-bench` | Criterion benches |
| `crates/frankenlibc-fixture-exec` | Helper for fixture execution |
| `tests/conformance` | Canonical reports, fixture packs, maintenance artifacts |
| `tests/integration` | Integration tests against produced artifacts |
| `tests/runtime_math` | Runtime math golden artifacts |
| `tests/gentoo` | Gentoo ecosystem validation assets |
| `scripts` | Drift gates, smoke tests, reports, release checks, perf tooling |

## Subsystem Tour

The repo is large enough that it helps to know where the major surfaces live.

| Subsystem | Where to look | What it covers |
|---|---|---|
| String and memory APIs | `crates/frankenlibc-core/src/string/` and `crates/frankenlibc-abi/src/string_abi.rs` | `mem*`, `str*`, and related bootstrap string surface |
| Stdio | `crates/frankenlibc-core/src/stdio/`, `crates/frankenlibc-abi/src/stdio_abi.rs`, `crates/frankenlibc-abi/src/io_internal_abi.rs` | file streams, buffered I/O, internal `_IO_*` bridges |
| Allocator and pointer safety | `malloc/` in core plus `arena.rs`, `fingerprint.rs`, `ptr_validator.rs` in membrane | allocator behavior, ownership tracking, corruption detection |
| Threading | `crates/frankenlibc-core/src/pthread/` and `crates/frankenlibc-abi/src/pthread_abi.rs` | pthread entrypoints, synchronization primitives, thread lifecycle |
| Resolver / networking | `resolv/`, `inet/`, `socket_abi.rs`, `resolv_abi.rs` | DNS/bootstrap resolver and network-facing ABI surface |
| Locale and iconv | `locale/`, `iconv/`, `locale_abi.rs`, `iconv_abi.rs` | locale setup, conversion, and early internationalization surface |
| Runtime math | `crates/frankenlibc-membrane/src/runtime_math/` | risk, control, anomaly detection, and runtime decision kernels |
| Verification harness | `crates/frankenlibc-harness/` | fixture verification, reports, evidence compliance, snapshots |

### If you only read four code areas

Read these first:

1. `crates/frankenlibc-abi/`
2. `crates/frankenlibc-membrane/`
3. `crates/frankenlibc-core/`
4. `crates/frankenlibc-harness/`

That is the runtime stack from ABI boundary to semantic implementation to verification.

## Subsystem Status Dashboard

This table is intentionally qualitative. Exact numeric truth still belongs in the canonical artifacts and support matrix.

| Subsystem | Current state | Main value today | Main gap |
|---|---|---|---|
| `string` | strong native ownership | bootstrap string and memory surface is real and testable | full breadth and parity closure |
| `stdio` | actively expanding | native stdio plus incremental `_IO_*` promotions are landing | full internal libio-style closure |
| `malloc` | meaningful native substrate | allocator + membrane temporal/integrity reasoning already exist | broader replacement maturity and stress closure |
| `pthread` | partial but real | native pthread surface exists and is growing | full closure beyond bootstrap/common primitives |
| `resolver` | partial native path | resolver/bootstrap networking work is live | complete NSS / retry / cache / poisoning closure |
| `locale` | partial native path | locale bootstrap semantics exist | broad locale and collation completeness |
| `iconv` | partial native path | explicit conversion work is present | full encoding breadth |
| `loader / dlfcn` | strategically hard | boundary and policy framing exist | replacement-ready dynamic loader story |
| `startup` | partial / staged | startup work is recognized and tracked | full bootstrap and secure-mode closure |
| `runtime_math` | extensive code presence | live controller and evidence machinery exists | continued integration discipline and proof-quality closure |

### Hard-Parts Truth Table

- `startup`: `IMPLEMENTED_PARTIAL` — implemented scope: phase-0 startup fixture path (`__libc_start_main`, `__frankenlibc_startup_phase0`, snapshot invariants). Deferred scope: full `csu`/TLS init-order hardening and secure-mode closure campaign.
- `threading`: `IN_PROGRESS` — implemented scope: runtime-math threading routing and selected pthread semantics are live, including lifecycle and rwlock native routing. Deferred scope: close lifecycle/TLS stress beads.
- `resolver`: `IMPLEMENTED_PARTIAL` — implemented scope: bootstrap numeric resolver ABI (`getaddrinfo`, `freeaddrinfo`, `getnameinfo`, `gai_strerror`). Deferred scope: full retry/cache/poisoning hardening campaign.
- `nss`: `IMPLEMENTED_PARTIAL` — implemented scope: passwd/group APIs are exported as `Implemented` via `pwd_abi`/`grp_abi`. Deferred scope: hosts/backend breadth plus NSS concurrency/cache-coherence closure.
- `locale`: `IMPLEMENTED_PARTIAL` — implemented scope: bootstrap `setlocale`/`localeconv` C/POSIX path. Deferred scope: catalog, collation, and transliteration parity expansion.
- `iconv`: `IMPLEMENTED_PARTIAL` — implemented scope: phase-1 `iconv_open`/`iconv`/`iconv_close` conversions for UTF-8/ISO-8859-1/UTF-16LE/UTF-32 with deterministic strict+hardened fixtures; codec scope/exclusions are locked in `tests/conformance/iconv_codec_scope_ledger.v1.json`. Deferred scope: full `iconvdata` breadth and deterministic table-generation closure.

### Runtime modes

| Mode | Purpose | Behavior |
|---|---|---|
| `strict` | Compatibility-first | No repair rewrites; prefer ABI-compatible failures |
| `hardened` | Safety-first | Repairs or denies unsafe patterns and emits evidence |

### Healing actions

`crates/frankenlibc-membrane/src/heal.rs` currently defines:

- `ClampSize`
- `TruncateWithNull`
- `IgnoreDoubleFree`
- `IgnoreForeignFree`
- `ReallocAsMalloc`
- `ReturnSafeDefault`
- `UpgradeToSafeVariant`

## Verification Model

The project is organized around verification artifacts:

- `support_matrix.json`: per-symbol status taxonomy
- `tests/conformance/support_matrix_maintenance_report.v1.json`: canonical maintenance snapshot
- `tests/conformance/fixtures/`: host-libc fixture packs
- `tests/runtime_math/golden/`: runtime math snapshot goldens
- `scripts/check_*.sh`: drift, closure, smoke, and policy gates

Each artifact or gate answers a specific question:

| Question | Artifact or gate |
|---|---|
| "What symbols are currently native?" | `support_matrix.json` |
| "Did documentation or status drift?" | `check_support_matrix_maintenance.sh` |
| "Does behavior still match captured expectations?" | fixture verification via harness and conformance scripts |
| "Does interposition still work on real binaries?" | `ld_preload_smoke.sh` and integration tests |
| "Did runtime-math behavior drift?" | snapshot goldens and linkage checks |
| "Are release claims internally coherent?" | closure / release gate scripts |

## How To Evaluate Current Maturity

If you want to judge the project seriously, do not rely on adjectives in the README. Use the artifacts and gates.

| Question | Best place to look |
|---|---|
| How much of the exported surface is native? | `support_matrix.json` and the maintenance report |
| Is a symbol really implemented or still delegated? | `support_matrix.json` |
| Does the repo still reconcile code and docs? | maintenance and drift gates |
| Does interposition work on actual programs? | smoke scripts and integration tests |
| Does hardened mode have explicit evidence paths? | membrane verification and JSON/JSONL outputs |
| Is the project honest about release readiness? | closure and release gate scripts |

For a fast maturity check, this is a good sequence:

```bash
bash scripts/check_support_matrix_maintenance.sh
bash scripts/check_c_fixture_suite.sh
TIMEOUT_SECONDS=10 bash scripts/ld_preload_smoke.sh
bash scripts/check_release_gate.sh
```

## Testing Strategy By Layer

It is easier to understand the repo’s verification model if you split tests by layer instead of by tool name.

| Layer | Typical location | What it is trying to prove |
|---|---|---|
| Core unit tests | `frankenlibc-core` modules | semantic correctness of safe Rust implementations |
| ABI tests | `crates/frankenlibc-abi/tests/` | exported entrypoints behave correctly at the boundary |
| Membrane tests | membrane tests and harness membrane verification | validation, healing, metrics, and decision behavior |
| Fixture verification | `tests/conformance/fixtures/` plus harness `verify` | behavior matches captured host-libc expectations where claimed |
| Integration / smoke | `tests/integration/`, smoke scripts | real processes still run through the interpose artifact |
| Runtime-math snapshot tests | `tests/runtime_math/golden/`, snapshot gates | controller outputs do not drift silently |
| Release / closure gates | `scripts/check_*release*`, `check_closure_*` | top-level project claims remain internally consistent |

Representative verification flows:

```bash
# Support-matrix maintenance
bash scripts/check_support_matrix_maintenance.sh

# Fixture pipeline
bash scripts/check_conformance_fixture_pipeline.sh

# LD_PRELOAD smoke
TIMEOUT_SECONDS=10 bash scripts/ld_preload_smoke.sh

# Runtime math snapshots
bash scripts/snapshot_gate.sh

# Release / closure-oriented checks
bash scripts/check_closure_contract.sh
bash scripts/check_release_gate.sh
```

## Verification Artifact Catalog

The repo has many report artifacts. This table maps them to the questions they answer.

| Artifact | Role |
|---|---|
| `support_matrix.json` | Per-symbol source of truth for implementation taxonomy |
| `tests/conformance/support_matrix_maintenance_report.v1.json` | Canonical maintenance snapshot derived from the support matrix |
| `tests/conformance/fixtures/` | Host-libc fixture corpus used for differential verification |
| `tests/conformance/c_fixture_spec.json` | Integration-fixture coverage contract |
| `tests/conformance/runtime_env_inventory.v1.json` | Machine-generated inventory of documented `FRANKENLIBC_*` environment variables |
| `tests/runtime_math/golden/` | Golden snapshots for runtime-math behavior |
| `target/conformance/*.json` and `*.jsonl` | Generated local evidence from harness runs and maintenance gates |

The project artifacts fall into three categories:

- claims about what exists
- evidence about what happened
- gates that compare the two

Keeping those categories separate helps when reading the repo.

## Artifact Matrix

| Artifact or class | Produced by | Used by | Purpose |
|---|---|---|---|
| `support_matrix.json` | maintained in repo + verified by scripts | harness, docs, maintenance gates | symbol-classification source of truth |
| maintenance report | maintenance generator and gate | tests, docs, drift checks | canonical snapshot of support status |
| fixture packs | capture and fixture tooling | harness verification | differential behavior checking |
| smoke logs and JSONL evidence | smoke scripts and harness runs | humans and gates | operational evidence from real executions |
| runtime-math goldens | snapshot tooling | snapshot and linkage gates | detect controller drift |
| docs source-of-truth map + trace | `scripts/generate_docs_env_mismatch_report.py` | docs gate, review workflow | tie README/architecture/deployment/security/API/troubleshooting surfaces to owners and refresh triggers |
| closure / release artifacts | closure and release scripts | release-oriented checks | keep product-level claims coherent |

## Evidence Lifecycle

Implementation changes in FrankenLibC are expected to leave an evidence trail.

Typical lifecycle:

```text
code change
  ->
symbol classification change or semantic change
  ->
canonical artifact refresh
  ->
targeted tests and gates
  ->
smoke / fixture / maintenance evidence
  ->
release and closure reconciliation
```

Without that loop, a project like this drifts into self-deception quickly.

Documentation governance follows the same rule. `tests/conformance/docs_source_of_truth_map.v1.json`
and `tests/conformance/docs_source_of_truth_trace.v1.jsonl` are the canonical map from major
documentation surfaces to backing artifacts, owners, and refresh triggers. Run
`bash scripts/check_docs_env_mismatch.sh` after changing either the prose or its evidence sources.

## Road To Standalone Replace

## Interpose Artifact vs Replace Artifact

These two ideas should not be conflated.

| Artifact | What it means |
|---|---|
| interpose artifact | `libfrankenlibc_abi.so`, loaded with `LD_PRELOAD`, and still dependent on host glibc as the deployment environment |
| replace artifact | future standalone libc artifact with no host-glibc deployment dependency |

The interpose artifact is valuable now because it enables:

- experimentation on existing binaries
- workload shadowing
- hardened-mode studies
- incremental symbol promotion

The replace artifact matters later because it raises the bar from “interpose safely” to “own libc behavior fully enough to stop depending on host glibc.”

### Today

- interpose shared library exists
- host glibc is still part of the deployment story because the shipping artifact is interpose-first, even though the current symbol matrix no longer reports `GlibcCallThrough` or `WrapsHostLibc` rows
- support taxonomy is machine-checked
- hardened mode and verification flows are already live

### Next

- keep the matrix-clean classification honest while closing the broader preload, hardened-mode, and artifact-packaging gaps
- keep maintenance artifacts synchronized as each promotion lands
- tighten replacement gates so "replace-ready" is mechanically enforced, not socially assumed

### End state

- standalone replacement artifact exists as a real product, not a README promise
- `Implemented` and `RawSyscall` are sufficient for the replacement artifact
- the project can make stronger deployment claims without hand-waving over unresolved host dependencies

This progression explains why the project has so many reports and gates: they are how a staged libc replacement stays honest.

## Deployment And Usage Patterns

Different readers will care about different ways of using the project.

| Pattern | What it looks like |
|---|---|
| local experiment | build `libfrankenlibc_abi.so` and run one program under `LD_PRELOAD` |
| hardened investigation | run suspicious workloads with `FRANKENLIBC_MODE=hardened` and collect evidence |
| CI validation | use maintenance, fixture, smoke, and release gates to keep claims coherent |
| ecosystem validation | use the Gentoo-oriented scripts and fixtures to stress larger build/test surfaces |
| subsystem research | work one family at a time and promote symbols from call-through to native ownership |

## Current Hard Parts

The remaining hard areas are difficult for real systems reasons, not because they were forgotten.

| Hard part | Why it is hard |
|---|---|
| loader / `dlfcn` | dynamic linking and symbol resolution are globally coupled to process behavior |
| full pthread closure | concurrency bugs are subtle and ABI compatibility matters at the scheduling and lifecycle level |
| locale breadth | locale behavior is wide, stateful, and historically intricate |
| iconv breadth | codec coverage is a large-scale data and semantics problem |
| startup / bootstrap | initialization order is unforgiving and highly coupled to platform assumptions |
| full standalone replace | removing the last host-glibc dependencies is a product milestone, not just a symbol-count milestone |

## Suggested Reading Order

If you want to understand the project deeply instead of just using it, this order works well:

1. `README.md`
2. `AGENTS.md`
3. `support_matrix.json`
4. `crates/frankenlibc-abi/`
5. `crates/frankenlibc-membrane/`
6. `crates/frankenlibc-core/`
7. `crates/frankenlibc-harness/`
8. `tests/conformance/`
9. `scripts/check_*.sh`

That sequence mirrors how the project itself works:

- claimed surface
- actual ABI boundary
- safety substrate
- semantic kernels
- verification and drift control

## Troubleshooting

### `LD_PRELOAD` does nothing

Check that you built the ABI crate in release mode and are pointing at the actual `.so`:

```bash
test -f target/release/libfrankenlibc_abi.so
```

### `cargo` fails because the toolchain is wrong

This repo uses nightly Rust:

```bash
rustup toolchain install nightly
rustup override set nightly
```

### A README claim and a machine artifact disagree

Trust the machine artifact. The most useful current files are:

- `support_matrix.json`
- `tests/conformance/support_matrix_maintenance_report.v1.json`
- `tests/conformance/runtime_env_inventory.v1.json`

### Hardened mode does not appear to log anything

Set a log path explicitly:

```bash
FRANKENLIBC_LOG=/tmp/franken.jsonl \
FRANKENLIBC_MODE=hardened \
LD_PRELOAD="$PWD/target/release/libfrankenlibc_abi.so" /bin/echo test
```

### A drift gate fails after touching symbol classifications

You probably updated code or `support_matrix.json` without refreshing a canonical artifact. Start here:

```bash
bash scripts/check_support_matrix_maintenance.sh
```

## Limitations

- The current production artifact is the **interpose** shared library, not a full standalone libc replacement.
- Host glibc is still part of the deployment story because the shipping artifact is still `LD_PRELOAD` interposition, not a standalone libc drop-in.
- The checked curated preload smoke battery is green in both strict and hardened modes, but broader production hardening and release-claim closure are still in progress; use the canonical smoke artifact and gates rather than paraphrased README prose when the exact status matters.
- Hardened mode exists, has targeted validation/oracle coverage, and has a checked green curated smoke run; that is still not a blanket production-readiness claim for arbitrary workloads.
- Performance is not yet a settled success story; strict-mode perf regressions still show up in smoke/perf gates and must be measured rather than assumed away.
- The README can summarize current reality, but the canonical truth still lives in generated reports and gates.
- Linux is the real target. Multi-architecture and full replacement stories are still active work.
- Many verification scripts exist because this is an active research-heavy codebase, not a polished end-user product.

## Glossary

| Term | Meaning in this repo |
|---|---|
| TSM | Transparent Safety Membrane |
| `Implemented` | Symbol path is natively owned in FrankenLibC |
| `RawSyscall` | Symbol path goes directly to Linux syscalls rather than host glibc |
| `WrapsHostLibc` | Native wrapper that still calls host libc symbols internally |
| `GlibcCallThrough` | Symbol still depends on host glibc for behavior |
| `strict` | Compatibility-first runtime mode |
| `hardened` | Repair/deny-capable runtime mode |
| reality report | Generated report summarizing current classified symbol state |
| maintenance report | Canonical artifact used to detect support-matrix drift |
| interpose artifact | `libfrankenlibc_abi.so`, used via `LD_PRELOAD` |
| replace artifact | Planned standalone libc artifact with no host-glibc call-throughs |

## FAQ

### Is FrankenLibC a drop-in replacement for glibc today?

No. The practical artifact today is `libfrankenlibc_abi.so` used via `LD_PRELOAD`, and even that broad interpose story is still being stabilized. Full standalone replacement remains planned.

### Does it already implement a lot of symbols natively?

Yes. The current classified surface is 4119 symbols, with 3705 `Implemented` and 414 `RawSyscall`.

### Do the CVE validation scripts prove FrankenLibC would have prevented famous exploits in real projects?

No. They provide targeted evidence for specific bug patterns and synthetic scenarios, which is useful, but weaker than an end-to-end proof against a real vulnerable upstream build. In particular, `LD_PRELOAD` claims do not apply to setuid/setgid binaries, so those cases need a different deployment story.

### What does hardened mode actually do?

It allows the membrane to repair or deny unsafe patterns instead of just propagating failures, while recording evidence about what happened.

### Is this a clean-room reimplementation?

Yes. The architecture and implementation are spec-first and verification-driven rather than line-by-line glibc translation.

### Is runtime math real code or just naming theater?

Real code. The `frankenlibc-membrane/src/runtime_math/` tree is large and live, and the repo includes snapshot and linkage gates around it.

### Should I trust the README or the generated reports?

The generated reports. The README is a guide; the source of truth is the code plus the canonical artifacts under `tests/conformance/`.

### Why not just use musl?

musl solves a different problem. FrankenLibC is trying to preserve a glibc-shaped compatibility story while adding safety, classification, and staged replacement machinery.

### Why not just use ASan or UBSan?

Sanitizers are extremely useful, but they are development instrumentation. FrankenLibC is aimed at boundary-level safety and observability for deployed binaries and replacement-libc research.

### Why not just harden malloc and stop there?

Because libc risk is broader than allocation alone. String APIs, stdio, resolver paths, locale/iconv behavior, threading, startup, and loader behavior all matter.

### Why are there so many JSON and JSONL artifacts?

Because this project is designed to reconcile implementation claims, evidence, and release readiness mechanically rather than socially.

### Why does native coverage not automatically mean “done”?

Because standalone replacement depends not just on counts, but on which symbols remain delegated, which subsystems remain strategically hard, and whether the artifact-level guarantees are actually satisfied.

## Appendix: Important Files

| File or path | Why it matters |
|---|---|
| `README.md` | top-level project overview |
| `AGENTS.md` | repo operating rules and architectural expectations for agents |
| `support_matrix.json` | per-symbol implementation taxonomy |
| `Cargo.toml` | workspace definition and top-level dependencies |
| `crates/frankenlibc-abi/` | ABI boundary and interpose shared library |
| `crates/frankenlibc-membrane/` | safety membrane, healing, runtime math |
| `crates/frankenlibc-core/` | safe semantic kernels |
| `crates/frankenlibc-harness/` | verification and evidence tooling |
| `tests/conformance/` | canonical reports, fixtures, and generated truth artifacts |
| `tests/runtime_math/golden/` | runtime-math golden snapshots |
| `scripts/check_support_matrix_maintenance.sh` | one of the highest-signal drift gates in the repo |
| `scripts/ld_preload_smoke.sh` | real-program interposition smoke validation |
| `scripts/check_release_gate.sh` | release-claim coherence gate |

## Allocator Architecture

The custom allocator in `crates/frankenlibc-core/src/malloc/` is a production-grade, membrane-integrated design with three tiers.

### Size-Class System

**32 size classes** span from 16 bytes to 32,768 bytes:

| Bin range | Increment | Sizes |
|---|---|---|
| 0 -- 7 | 16 bytes | 16, 32, 48, 64, 80, 96, 112, 128 |
| 8 -- 15 | 32 bytes | 160, 192, 224, 256, 288, 320, 352, 384 |
| 16 -- 23 | 64 bytes | 448, 512, 640, 768, 896, 1024, 1280, 1536 |
| 24 -- 31 | 128+ bytes | up to 32,768 |

Each size class is backed by **64 KB slabs**, and every individual allocation carries **64 bytes of per-object overhead** (fingerprint header + trailing canary + alignment padding).

### Thread-Local Magazine Cache

Each thread maintains a **magazine-based cache** with a LIFO stack of free objects per size class:

- **64 objects per class per thread**, up to **2,048 cached objects** per thread across all 32 classes
- Thread-local alloc/free stays entirely lock-free until a magazine overflows or drains
- Overflow spills back to the sharded central allocator

This design means that steady-state allocation patterns on a single thread never touch shared state at all.

### Large Allocation Path

Requests exceeding 32 KB bypass the slab system entirely:

- Routed to a dedicated `LargeAllocator` backed by `mmap`
- Page-aligned (4096-byte boundaries) with explicit base/mapped-size/user-size tracking
- Base address starts at `0x1_0000_0000` to prevent confusion with small-allocation address ranges

### Membrane Integration

Every allocation flows through the membrane before returning a pointer:

- 20-byte SipHash fingerprint header prepended to each allocation
- 8-byte trailing canary appended after the user region
- The generational arena records ownership, generation counter, and safety state
- Double-free and use-after-free are caught by generation mismatch and quarantine queue membership

## Printf Engine And Stdio Internals

### Printf Format Engine

The printf implementation in `crates/frankenlibc-core/src/stdio/` is a complete safe-Rust engine, not a wrapper around libc's `vsnprintf`.

**Supported format directives:**

- All POSIX conversion specifiers: `%d`, `%i`, `%u`, `%o`, `%x`, `%X`, `%f`, `%F`, `%e`, `%E`, `%g`, `%G`, `%a`, `%A`, `%c`, `%s`, `%p`, `%n`, `%%`
- All flags: `-` (left-justify), `+` (force sign), ` ` (space sign), `#` (alternate form), `0` (zero pad)
- Width and precision: literal values and `*` (from-argument) for both
- All length modifiers: `hh`, `h`, `l`, `ll`, `z`, `t`, `j`, `L`

**Design invariant:** no single format specifier can produce more than `width + precision + 64` bytes. This bounds memory growth from format strings and prevents a class of denial-of-service where a crafted format string causes unbounded allocation.

Arguments are dispatched through a `FormatArg` enum (`SignedInt(i64)`, `UnsignedInt(u64)`, `Float(f64)`, `Char(u8)`) with string arguments handled out-of-band as byte slices.

### Buffering Subsystem

Stdio buffering follows POSIX semantics with three modes:

| Mode | Constant | Behavior |
|---|---|---|
| Fully buffered | `_IOFBF` (0) | Flush on buffer overflow |
| Line buffered | `_IOLBF` (1) | Flush on newline (`\n`) |
| Unbuffered | `_IONBF` (2) | No buffering; immediate write-through |

The default buffer size is **8192 bytes** (`BUFSIZ`). The implementation enforces POSIX's requirement that `setvbuf` cannot be called after I/O has started on a stream; mode is monotonically locked after the first operation.

Line-buffered writes use a reverse scan (`rposition`) to find the last newline, flushing through that point and retaining the remainder. The `unget()` path supports pushing a single byte back for `ungetc` semantics.

## ABI Layer In Detail

The `crates/frankenlibc-abi/src/` directory contains **39 ABI module files**, each covering a distinct POSIX or glibc function family. Together they export the symbols defined in a **4,466-line GNU ld version script** (`version_scripts/libc.map`) under the `GLIBC_2.2.5` version tag.

### Function Families

| Module | Surface |
|---|---|
| `string_abi.rs` | `memcpy`, `memmove`, `memset`, `strlen`, `strcmp`, `strchr`, `strstr`, and 30+ more |
| `wchar_abi.rs` | `wcscpy`, `wcslen`, `wmemcpy`, `wcstol`, `wcrtomb`, `mbrtowc`, and 40+ more |
| `stdio_abi.rs` | `printf`, `fprintf`, `fopen`, `fclose`, `fread`, `fwrite`, and the full `_IO_*` bridge surface |
| `stdlib_abi.rs` | `malloc`, `free`, `calloc`, `realloc`, `qsort`, `bsearch`, `strtol`, `atoi`, and more |
| `malloc_abi.rs` | Arena-integrated allocation with fingerprint and canary enforcement |
| `math_abi.rs` | `sin`, `cos`, `sqrt`, `exp`, `log`, `pow`, `atan2`, `fma`, and the full libm surface |
| `pthread_abi.rs` | `pthread_create`, `pthread_join`, mutex, condvar, rwlock, barriers, TLS |
| `socket_abi.rs` | `socket`, `connect`, `bind`, `listen`, `accept`, `send`, `recv`, and more |
| `signal_abi.rs` | `signal`, `sigaction`, `kill`, `raise`, `pause`, `sigprocmask` |
| `time_abi.rs` | `time`, `gettimeofday`, `clock_gettime`, `strftime`, `localtime` |
| `io_abi.rs` / `io_internal_abi.rs` | `dup`, `dup2`, `pipe`, `fcntl`, `ioctl`, internal syscall layer |
| `unistd_abi.rs` / `process_abi.rs` | `read`, `write`, `close`, `lseek`, `fork`, `execve`, `wait`, `exit` |
| `resolv_abi.rs` / `inet_abi.rs` | DNS resolution, `inet_aton`, `inet_ntoa`, `htons`, `ntohs` |
| `locale_abi.rs` / `iconv_abi.rs` | `setlocale`, `localeconv`, `iconv_open`, `iconv`, `iconv_close` |
| `dirent_abi.rs` | `opendir`, `readdir`, `closedir`, `scandir` |
| `dlfcn_abi.rs` | `dlopen`, `dlsym`, `dlclose`, `dlerror`, `dladdr` |
| `setjmp_abi.rs` | `setjmp`, `longjmp` with TSM instrumentation |
| `fenv_abi.rs` | `fegetround`, `fesetround`, `fegetenv`, `fesetenv` |
| `termios_abi.rs` | `tcgetattr`, `tcsetattr`, `tcdrain` |
| `fortify_abi.rs` | `__stack_chk_fail`, `__stack_chk_guard` (stack-smashing protector) |
| `startup_abi.rs` | `__libc_start_main`, `__cxa_atexit`, `__cxa_finalize` |
| `c11threads_abi.rs` | C11 thread API (`thrd_create`, `thrd_join`, etc.) |
| `stdbit_abi.rs` | C23 bit manipulation (`stdc_*` functions) |
| `mmap_abi.rs` | `mmap`, `munmap`, `mprotect`, `msync` |
| `rpc_abi.rs` | RPC function stubs |

### The Validate-Delegate Pattern

Every ABI entrypoint follows a five-step pattern:

```text
1. runtime_policy::decide()   -- membrane consults risk, mode, and context
2. check for Deny             -- blocked calls return EPERM immediately
3. validate inputs            -- core-layer checks on arguments
4. delegate                   -- call safe Rust kernel or raw syscall
5. runtime_policy::observe()  -- record outcome for metrics and healing
```

This pattern is not advisory. It is structurally enforced: the ABI module files are minimal glue, and the real work happens in the membrane and core layers.

## Membrane Implementation Details

### Generational Arena

The arena in `crates/frankenlibc-membrane/src/arena.rs` tracks every live allocation:

| Parameter | Value |
|---|---|
| Quarantine capacity | **64 MB** (`QUARANTINE_MAX_BYTES`) |
| Shard count | **16** (`NUM_SHARDS`, power-of-two for hash distribution) |
| Per-allocation metadata | raw base, user base, user size, generation (`u32`), `SafetyState` |
| UAF detection | generation counter mismatch -- probability 1.0 for same-slot reuse |
| Temporal lifecycle | Live -> Freed -> Quarantine -> Recycle |

Freed allocations enter a quarantine queue before their memory is recycled. This window makes use-after-free detectable even if the slot is reused, because the generation counter will have incremented.

### Fingerprint And Canary System

Each allocation is bracketed by integrity metadata:

```text
[20-byte fingerprint header][user data region][8-byte trailing canary]
```

The fingerprint header contains:

| Field | Size | Content |
|---|---|---|
| Hash | 8 bytes | SipHash-2-4 of allocation metadata |
| Generation | 4 bytes | Current generation counter |
| Allocation size | 8 bytes | User-requested size as `u64` (supports allocations > 4 GiB) |

The trailing canary is derived from the same SipHash computation. Corruption of either the header or canary signals tampering or buffer overflow. The probability of an undetected collision is bounded by 2^-64 (SipHash collision probability).

### Bloom Filter

The ownership bloom filter in `bloom.rs` provides O(1) "is this pointer ours?" pre-checks:

| Parameter | Value |
|---|---|
| Expected items | **1,000,000** (`DEFAULT_EXPECTED_ITEMS`) |
| Target false positive rate | **0.1%** (`DEFAULT_FP_RATE = 0.001`) |
| Optimal hash count | `k = (m/n) * ln(2)`, clamped to **[1, 16]** |
| Bit storage | Atomic `u64` array for thread-safe concurrent access |
| False negative rate | **0.0%** -- if a pointer was inserted, the bloom filter will always confirm it |

The bloom filter sits early in the validation pipeline because it can reject most non-owned pointers before touching the arena or fingerprint logic.

### Safety-State Lattice Structure

The 8-state lattice in `lattice.rs` has a **diamond structure** where `Readable` and `Writable` are incomparable:

```text
        Valid (6)
       /         \
Readable (5)  Writable (4)
       \         /
     Quarantined (3)
            |
         Freed (2)
            |
        Invalid (1)
            |
        Unknown (0)
```

- **Join** (new evidence arrives): always moves toward the more restrictive conclusion
- **Meet** (what is known to be safe): always moves toward the most permissive valid conclusion
- Both operations are commutative, associative, and idempotent
- State transitions are **monotonically downward** on new negative evidence; once a pointer is classified as `Freed`, it cannot return to `Valid`

### Galois Connection

The Galois connection in `galois.rs` formalizes the relationship between C's flat pointer model and the membrane's rich safety model:

- **Alpha (abstraction):** maps a raw C pointer + context into a `PointerAbstraction` with safety state, allocation base, remaining bytes, and generation
- **Gamma (concretization):** maps the abstract safety state back into a `ConcreteAction` (`Proceed`, `Heal`, `Deny`)
- **Soundness guarantee:** `gamma(alpha(c)) >= c` -- the safe interpretation is always at least as permissive as what a correct program needs

## Build-Time Verification

### Membrane Build Script

The membrane crate's `build.rs` (1,012 lines) performs substantial compile-time verification:

**Sum-of-Squares (SOS) Certificate Generation:**

Three polynomial invariant certificates are synthesized and verified at build time:

| Certificate | What it proves |
|---|---|
| Fragmentation | Allocator fragmentation stays within budget bounds |
| Thread Safety | Concurrent access patterns satisfy safety constraints |
| Size Class | Size-class routing satisfies allocation invariants |

Each certificate undergoes:
1. Gram matrix construction
2. PSD (positive semi-definite) verification via Cholesky decomposition with tolerance `1e-9`
3. Polynomial identity verification for barrier budget bounds
4. Artifact generation as Rust `const` values and JSON soundness reports

**Memory Model Barrier Audit:**

The build script scans source files for atomic operations and verifies minimum barrier coverage:

| Source file | Expected atomic sites | Domain |
|---|---|---|
| `ptr_validator.rs` | 4 | TSM |
| `arena.rs` | 2 | TSM |
| `tls_cache.rs` | 2 | TSM |
| `config.rs` | 15 | TSM |
| `metrics.rs` | 2 | TSM |
| `pthread/cond.rs` | 29 | futex |
| **Total minimum** | **20+** | |

If any source file has fewer atomic sites than expected, the build fails. This prevents silent removal of synchronization barriers during refactoring.

### ABI Build Script

The ABI crate's `build.rs` links the GNU ld version script (`libc.map`) into non-debug, non-fuzz `cdylib` builds when the script is present. Debug and fuzz builds skip version-script linking to avoid conflicts with rustc's generated export list; native packaging checks that need the versioned `libc.so` link the `staticlib` with `cc` using `libc.map` (see `scripts/check_setjmp_native.sh`).

## Harness CLI Reference

The verification harness (`cargo run -p frankenlibc-harness --bin harness`) supports these subcommands:

| Subcommand | Purpose | Key outputs |
|---|---|---|
| `capture` | Record host glibc behavior as fixture JSON | Per-family fixture files |
| `verify` | Replay fixtures against FrankenLibC and compare | Markdown conformance report |
| `traceability` | Map fixtures to POSIX/C11 spec sections | Markdown + JSON traceability matrix |
| `reality-report` | Machine-readable snapshot of classified symbol state | JSON reality report |
| `posix-conformance-report` | Coverage report across symbols and spec sections | `posix_conformance_report.current.v1.json` |
| `posix-obligation-report` | Obligation traceability across unit + C fixtures | `posix_obligation_matrix.current.v1.json` |
| `errno-edge-report` | Errno and edge-case prioritization | `errno_edge_report.current.v1.json` |
| `verify-membrane` | Strict/hardened healing oracle verification | JSON healing evidence |

Each subcommand produces structured artifacts that can be diffed, tracked in version control, or consumed by downstream gates.

## Test And Fixture Infrastructure

### C Integration Fixtures

The `tests/integration/` directory contains **16 C test programs** that are compiled against the produced `libfrankenlibc_abi.so` and exercised during integration testing:

| Fixture | What it exercises |
|---|---|
| `fixture_malloc.c` / `fixture_malloc_stress.c` | Allocation correctness and concurrent stress |
| `fixture_string.c` | String function behavior parity |
| `fixture_stdio.c` / `fixture_stdio_printf.c` | Stream I/O and printf formatting |
| `fixture_socket.c` | Network socket operations |
| `fixture_pthread.c` / `fixture_pthread_mutex_adversarial.c` | Threading and adversarial mutex contention |
| `fixture_setjmp_nested.c` / `fixture_setjmp_edges.c` | Non-local jump edge cases |
| `fixture_ctype.c` | Character classification |
| `fixture_math.c` | Math function accuracy |
| `fixture_nss.c` | Name service switch |
| `fixture_io.c` | File descriptor operations |
| `fixture_startup.c` | Program initialization sequence |
| `link_test.c` | Symbol linkage validation |

### JSON Conformance Corpus

The `tests/conformance/fixtures/` directory contains **40+ JSON fixture families**, each capturing input/output pairs from host glibc. Representative families:

- **Allocator:** `allocator`, `stdlib_conversion`, `stdlib_numeric`, `stdlib_sort`
- **String:** `string_ops`, `string_memory_full`, `strlen_strict`, `string_strtok`, `memcpy_strict`
- **Wide string:** `wide_string`, `wide_memory`, `wide_string_ops`
- **Character/errno:** `ctype_ops`, `errno_ops`
- **Math:** `math_ops`
- **Threading:** `pthread_thread`, `pthread_mutex`, `pthread_tls_keys`
- **I/O:** `socket_ops`, `poll_ops`, `inet_ops`, `resolver`, `dirent_ops`
- **Process:** `process_ops`, `spawn_exec_ops`, `signal_ops`, `setjmp_ops`
- **System:** `time_ops`, `termios_ops`, `locale_ops`, `resource_ops`, `virtual_memory_ops`, `sysv_ipc_ops`
- **Loader:** `dlfcn_ops`, `elf_loader`, `backtrace_ops`
- **Membrane-specific:** `membrane_mode_split`, `pressure_sensing`

These fixtures serve as the ground truth for differential verification: FrankenLibC's output for the same inputs must match glibc's behavior where conformance is claimed.

## CI And Automation Scripts

The `scripts/` directory contains **148 shell scripts** organized by purpose:

### Core Validation Gates

| Script | What it checks |
|---|---|
| `ci.sh` | Project-standard default CI gate |
| `check_support_matrix_maintenance.sh` | Support-matrix drift detection |
| `check_c_fixture_suite.sh` | C integration fixture execution |
| `check_conformance_fixture_pipeline.sh` | Full conformance pipeline |
| `ld_preload_smoke.sh` | Real-program interposition smoke |
| `check_e2e_suite.sh` | End-to-end testing |
| `check_allocator_e2e.sh` | Concurrent alloc/free + glibc diff check |

### Specialized Quality Checks

| Script | What it checks |
|---|---|
| `check_cve_uaf_validation.sh` | Use-after-free detection for known CVE patterns |
| `check_cve_heap_overflow_validation.sh` | Heap overflow detection for known CVE patterns |
| `check_anytime_valid_monitor.sh` | Sequential testing monitor correctness |
| `check_changepoint_drift.sh` | Bayesian change-point detection |
| `check_pressure_sensing.sh` | Runtime pressure sensing |
| `check_regression_detector.sh` | Performance regression detection |
| `check_perf_baseline.sh` / `check_perf_regression_gate.sh` | Performance baseline and gating |
| `check_math_governance.sh` / `check_math_retirement.sh` | Runtime math module lifecycle |
| `check_iconv_table_generation.sh` | Encoding table generation |
| `check_runtime_math_linkage_proofs.sh` | Runtime math linkage integrity |

### Release And Packaging

| Script | What it checks |
|---|---|
| `check_release_gate.sh` | Release-claim coherence |
| `check_release_dossier.sh` | Release dossier completeness |
| `check_closure_contract.sh` | Closure contract enforcement |
| `check_packaging.sh` | Packaging artifact correctness |
| `snapshot_gate.sh` | Runtime math golden snapshot integrity |

Every claim about the system (symbol ownership, conformance, performance, security) has a corresponding machine-checkable gate.

## Concurrency Primitives In The Membrane

The membrane includes several lock-free and wait-free synchronization primitives beyond what `parking_lot` provides:

| Primitive | Location | Purpose |
|---|---|---|
| SeqLock | `seqlock.rs` (825 lines) | Optimistic read-side concurrency for frequently-read, rarely-written metadata |
| RCU | `rcu.rs` (952 lines) | Read-copy-update for membership data structures that are read on every call |
| EBR | `ebr.rs` | Epoch-based reclamation for safe deferred freeing of shared metadata |

These exist because the membrane is called on every libc entrypoint. Global locks would create unacceptable contention under multithreaded workloads. The TLS validation cache (1,024-entry direct-mapped) is the first line of defense, and these primitives handle the cases where the cache misses and shared state must be consulted.

## Formal Property Summary

The project is explicit about which formal properties it claims and at what confidence level:

| Property | Mechanism | Confidence |
|---|---|---|
| Monotonic safety degradation | Lattice join is commutative, associative, idempotent; states only decrease | Proven by construction |
| Galois soundness | `gamma(alpha(c)) >= c` for all C operations | Proven by construction |
| Allocation integrity | P(undetected corruption) <= 2^-64 | Bounded by SipHash collision probability |
| Use-after-free detection | Generation counter mismatch on same-slot reuse | Probability 1.0 |
| Buffer overflow detection | Trailing canary corruption | P(miss) <= 2^-64 |
| Bloom filter soundness | Zero false negatives | By construction (all insertions are remembered) |
| Healing completeness | Every libc function has defined healing for every class of invalid input | Enforced by policy table coverage |
| SOS certificate validity | Fragmentation, thread safety, and size-class invariants | Verified at build time via Cholesky decomposition |
| Memory model barrier coverage | Minimum atomic site counts per source file | Enforced at build time by `build.rs` audit |

## Threading: Futex-Backed Synchronization

The pthread implementation in `crates/frankenlibc-core/src/pthread/` is a clean-room futex-backed design, not a wrapper around glibc's NPTL.

### Mutex

Three mutex types are supported: `NORMAL` (0), `RECURSIVE` (1), and `ERRORCHECK` (2). Each mutex is modeled as a five-state contract machine:

| State | Meaning |
|---|---|
| `Uninitialized` | Not yet initialized |
| `Unlocked` | Initialized, no owner |
| `LockedBySelf` | Current thread holds the lock |
| `LockedByOther` | Another thread holds the lock |
| `Destroyed` | Post-destroy, all operations fail |

The fast path is a single CAS on the uncontended case. When contended, the implementation classifies the wait via bounded spin before falling through to `FUTEX_WAIT` / `FUTEX_WAKE` with `FUTEX_PRIVATE_FLAG` (0x80). Unlock always wakes at least one waiter. Error reporting follows POSIX: `EBUSY` on double-init, `EPERM` on unlock-by-other, `EDEADLK` on recursive `ERRORCHECK` lock.

### Condition Variables

Condvars use a 20-byte internal layout (fits within the 48-byte `pthread_cond_t` on x86_64). Internal state consists of a sequence counter, associated mutex pointer, and waiter count.

Two clock modes are supported: `CLOCK_REALTIME` (default) and `CLOCK_MONOTONIC`. Timed waits use `FUTEX_WAIT_BITSET` with `FUTEX_BITSET_MATCH_ANY` (0xFFFF_FFFF) and `FUTEX_CLOCK_REALTIME` (256). Signal increments the sequence counter and wakes one waiter; broadcast wakes all.

### Read-Write Locks

Three preference modes: `PREFER_READER_NP` (0, default), `PREFER_WRITER_NP` (1), and `PREFER_WRITER_NONRECURSIVE_NP` (2). Unknown kinds are sanitized to the default.

## Runtime Policy Engine

Every ABI entrypoint consults `runtime_policy::decide()` before doing real work. The policy engine is where mode semantics, membrane decisions, and runtime math come together.

### Mode Resolution

The process-wide mode is resolved exactly once from `FRANKENLIBC_MODE`:

| Env value | Resolved mode |
|---|---|
| `hardened`, `repair`, `tsm`, `full` | Hardened |
| anything else (including unset) | Strict |

Resolution uses a compare-and-swap state machine: `UNRESOLVED` (0) -> `RESOLVING` (255) -> `STRICT` (1) / `HARDENED` (2) / `OFF` (3). Reentrant calls during resolution return a passthrough decision so the process can finish initializing.

### The decide() Call

```text
decide(family, ptr_or_addr, size, is_startup, is_null_likely, context_flags)
  -> (RuntimeKernelSnapshot, RuntimeDecision)
```

`ApiFamily` classifies the call site: `Process`, `Memory`, `String`, `Alloc`, `Stdio`, `Socket`, `Thread`, `Signal`, and others. The returned `RuntimeDecision` contains a `MembraneAction` (`Allow`, `Check`, `Deny`, or a specific healing directive) and a `ValidationProfile` indicating how deep the membrane should inspect.

After the call completes, `observe(family, profile, latency, denied)` feeds the outcome back into the runtime math kernel for sequential monitoring and threshold adjustment.

## Conformal Risk Engine

The standalone risk engine in `crates/frankenlibc-membrane/src/risk_engine.rs` implements online conformal risk control for adaptive validation depth.

### Nonconformity Scoring

Every pointer or region is scored along three axes:

| Axis | Score contribution |
|---|---|
| Alignment deviation | `(6 - alignment) * 33` (range 0--198) |
| Size anomaly | zero -> 200, >1 MB -> 250, >64 KB -> 150, small -> leading zeros |
| Pointer entropy | Unusual bit-count -> 200, otherwise 0 |

The final score is capped at 1000. Scores below `fast_threshold` skip expensive validation entirely; scores above `full_threshold` trigger exhaustive checks.

### Calibration

The engine maintains a 256-entry circular buffer of recent scores. Thresholds are calibrated as quantiles of this empirical distribution:

- `fast_threshold`: the (1 - alpha) quantile, where alpha defaults to 0.01 (1% target false-skip rate)
- `full_threshold`: a higher quantile for triggering deep inspection

An e-process monitor accumulates evidence on the log scale. When the e-process exceeds 10.0, the engine enters alarm mode and forces full validation on every call until the evidence subsides. Recalibration happens periodically based on call volume.

## Thompson Sampling Check Oracle

The check oracle in `crates/frankenlibc-membrane/src/check_oracle.rs` uses Thompson sampling to learn the optimal ordering of validation stages at runtime.

### Validation Stages

| Stage | Cost | Can reject early? | Can accept early? |
|---|---|---|---|
| Null | 1 ns | yes | no |
| TlsCache | 5 ns | no | yes |
| Bloom | 10 ns | yes | no |
| Arena | 30 ns | yes | no |
| Fingerprint | 20 ns | yes | no |
| Canary | 10 ns | yes | no |
| Bounds | 5 ns | no | no |

### Adaptive Ordering

Each stage maintains a Beta(alpha, beta) distribution initialized to Beta(1,1) (uniform prior). After each validation call, the stage that caused early termination gets its alpha incremented (success); stages that ran but did not terminate get beta incremented (failure).

Every 128 calls, the oracle recomputes the optimal ordering by sampling from each stage's posterior and ranking by expected information gain per nanosecond. The ordering is packed into a single `u64` (4 bits per stage) for cache-friendly storage.

Over time, the oracle converges to an ordering that puts the cheapest high-rejection stages first, minimizing expected validation latency for the observed workload.

## Healing Oracle

The healing oracle in `crates/frankenlibc-harness/src/healing_oracle.rs` verifies hardened-mode repairs by deliberately triggering unsafe conditions and checking that the membrane handles them correctly.

### Test Matrix

Seven categories of unsafe behavior are tested:

| Condition | What it triggers | Expected healing action |
|---|---|---|
| `NullPointer` | Null dereference through libc | `ReturnSafeDefault` |
| `UseAfterFree` | Read/write after free | `ReturnSafeDefault` |
| `DoubleFree` | Free the same pointer twice | `IgnoreDoubleFree` |
| `BufferOverflow` | Write past allocation boundary | `TruncateWithNull` (e.g. requested=64, truncated=63) |
| `ForeignFree` | Free a pointer not from our allocator | `IgnoreForeignFree` |
| `BoundsExceeded` | Size argument exceeds allocation | `ClampSize` (e.g. requested=4096, clamped=1024) |
| `ReallocFreed` | Realloc a previously freed pointer | `ReallocAsMalloc` (e.g. size=256) |

The oracle runs 14 test cases across `string` (strlen, strcmp, strcpy, strncpy, memmove, memcpy) and `malloc` (free, cfree, realloc, reallocarray) families, in both strict and hardened modes. Results are emitted as JSON with a per-case breakdown of expected vs. observed healing actions.

## Process Startup

`__libc_start_main` runs before `main()` and controls process initialization, making it a high-value target for validation. FrankenLibC's implementation in `startup_abi.rs` uses a multi-checkpoint validation envelope.

### Startup Sequence

```text
1. membrane gate           -- runtime_policy::decide(ApiFamily::Process)
2. validate main pointer   -- null check, EINVAL + Deny on failure
3. validate argv pointer   -- null check, EINVAL + Deny on failure
4. scan argv vector        -- count entries up to MAX_STARTUP_SCAN, detect unterminated
5. validate argc bound     -- argv_count >= normalized_argc
6. scan envp vector        -- same count validation
7. scan auxv vector        -- parse key/value pairs, detect truncation
8. classify secure mode    -- via classify_secure_mode(&auxv_pairs)
9. call init hook
10. call main(argc, argv, envp)
11. call fini hook
12. call rtld_fini hook
```

If validation fails at any checkpoint, the startup policy decides whether to deny (abort) or fall back to the host glibc's `__libc_start_main` via `dlvsym_next()`, trying version symbols `GLIBC_2.34`, `GLIBC_2.2.5`, and `GLIBC_2.17` in priority order.

Program name globals (`program_invocation_name`, `__progname`) are stored as `AtomicPtr` values extracted from `argv[0]`.

## setjmp/longjmp: Guarded Non-Local Jumps

`setjmp` and `longjmp` are inherently unsafe at the ABI level. FrankenLibC's implementation adds guard metadata to make corruption and misuse detectable.

### Jump Buffer Layout

The 128-byte `JmpBuf` (16 x `u64`) reserves the first six slots for membrane metadata:

| Slot | Content |
|---|---|
| 0 | Magic: `0x4652414E4B454E31` (ASCII "FRANKEN1") |
| 1 | Context ID (unique per capture) |
| 2 | Generation (re-entrance counter) |
| 3 | Owner thread ID |
| 4 | Mode tag (`0x5354524943540001` for strict, `0x4841524445450002` for hardened) |
| 5 | Guard (rotated XOR checksum of slots 0--4) |

### Validation Before longjmp

Before restoring, `phase1_longjmp_restore()` checks:

1. Magic and non-zero metadata (catches uninitialized buffers)
2. Mode tag matches current process mode
3. Current thread owns the buffer (catches cross-thread longjmp)
4. Guard checksum validates (catches buffer corruption)

Failure produces a typed error (`UninitializedContext`, `ForeignContext`, `CorruptedContext`, `ModeMismatch`) rather than silent undefined behavior.

POSIX requires that `longjmp(env, 0)` behaves as if `setjmp` returned 1. The implementation normalizes this before the restore path.

## DNS Resolver: Numeric-First, File-Based

The resolver in `crates/frankenlibc-core/src/resolv/` takes a conservative bootstrap approach: no network I/O, no NSS plugins, no recursive resolution.

### Resolution Order

1. Parse the address as IPv4 or IPv6 literal (returns immediately if it is one)
2. Search `/etc/hosts` for a matching hostname or alias
3. Search `/etc/services` for port/protocol mapping
4. If none match, return `EAI_NONAME` (-2)

Network-based DNS resolution is explicitly out of scope for the bootstrap resolver. This is a deliberate design choice: the resolver that runs inside libc itself should not open sockets or depend on external services during early process initialization. A full NSS/DNS backend is a future milestone.

## errno In Rust

Thread-local `errno` is easy to get wrong. The implementation in `crates/frankenlibc-core/src/errno/` uses Rust's `thread_local!` with a `Cell<i32>`:

- `__errno_location()` returns a pointer to the current thread's errno cell
- `get_errno()` / `set_errno()` for internal Rust code
- 50+ standard error constants (EPERM, ENOENT, EINTR, EIO, ENOMEM, EACCES, EINVAL, EDEADLK, ENOSYS, EOVERFLOW, etc.)
- `strerror_message()` does a static string lookup; unmapped codes return "Unknown error"

errno is per-thread state that C programs expect to survive across function calls. A global instead of thread-local implementation, or one that is not stable across FFI boundaries, will break real programs.

## Smoke Test Harness

The smoke test (`scripts/ld_preload_smoke.sh`) verifies that real programs work under interposition. It runs actual binaries and compares their behavior against a baseline.

## Packaging Contracts

The release interpose artifact is built with `cargo build -p frankenlibc-abi --release` and emitted at `target/release/libfrankenlibc_abi.so`. The planned standalone replacement artifact is named `libfrankenlibc_replace.so`.

Interpose deployment uses `LD_PRELOAD=target/release/libfrankenlibc_abi.so <program>`. Hardened interpose deployment uses `FRANKENLIBC_MODE=hardened LD_PRELOAD=target/release/libfrankenlibc_abi.so <program>`.

`Implemented` + `RawSyscall` symbols apply to both artifacts.
`WrapsHostLibc` + `GlibcCallThrough` + `Stub` symbols apply to `Interpose` only.

### Programs Tested

| Category | Examples |
|---|---|
| Coreutils | `/bin/ls -la /tmp`, `/bin/cat /etc/hosts`, `/bin/echo`, `/usr/bin/env`, `/bin/sort`, `/usr/bin/wc` |
| Integration fixtures | `tests/integration/link_test.c` (compiled and run) |
| Dynamic runtimes | `python3 -c 'print(1)'`, `busybox uname -a` |
| Optional services | `sqlite3 :memory:`, `redis-cli --version`, `nginx -v` |
| Stress | Repeated iterations of the above (configurable, default 5) |

### Failure Classification

Each test case produces a classified failure signature:

| Signature | Meaning |
|---|---|
| `startup_timeout` | Process did not exit within `TIMEOUT_SECONDS` (rc 124/125) |
| `startup_segv` | Segmentation fault (signal 11) |
| `startup_abort` | Abort (signal 6) |
| `startup_symbol_lookup_error` | Missing or incompatible symbol |
| `startup_loader_missing_library` | Dynamic library not found |
| `startup_glibc_version_mismatch` | Version symbol mismatch |
| `startup_strict_parity_mismatch` | Baseline and preload outputs differ |
| `startup_perf_regression` | Latency ratio exceeds budget (default: 2x) |
| `startup_valgrind_error` | Valgrind detected memory errors |

Each case collects baseline and preload stdout/stderr, a metadata bundle (mode, exit code, failure signature, `/proc/self/maps`), and latency measurements in nanoseconds with a computed latency ratio.

## Support Matrix Structure

The `support_matrix.json` file is the machine-readable source of truth for the project's implementation claims. Its structure:

```json
{
  "version": 2,
  "total_exported": 4119,
  "taxonomy": {
    "Implemented": "Native Rust, no host libc dependency",
    "RawSyscall": "Direct syscall marshaling",
    "WrapsHostLibc": "Native wrapper that still calls host libc symbols internally",
    "GlibcCallThrough": "Delegates to host glibc",
    "Stub": "Deterministic failure contract"
  },
  "symbols": [
    {
      "symbol": "_Exit",
      "status": "RawSyscall",
      "module": "unistd_abi",
      "perf_class": "O1",
      "strict_semantics": true,
      "hardened_semantics": true,
      "default_stub": false
    }
  ]
}
```

Every exported symbol has a classification, an owning ABI module, a performance class, and boolean flags for strict and hardened semantic coverage. The maintenance scripts compare this file against the actual symbols in the compiled `.so` and flag any drift as a build failure.

## How LD_PRELOAD Interposition Works

For readers unfamiliar with the mechanism: `LD_PRELOAD` tells the Linux dynamic linker to load a shared library before any others. When a program calls `malloc`, `strlen`, or any libc function, the linker resolves the symbol to FrankenLibC's implementation first. For symbols that FrankenLibC does not own yet, the project may still delegate to host glibc through constrained host-resolution and call-through paths.

FrankenLibC is already usable for many experiments without relinking anything: same binary, same kernel, same file system, different libc implementation behind the ABI boundary. That should not be confused with a claim that the full broad smoke matrix is already stable.

Limitations of interposition:

- Functions called internally within glibc (where the linker has already bound the symbol) are not intercepted
- Some startup-critical paths run before `LD_PRELOAD` takes effect
- `LD_PRELOAD` is ignored for setuid/setgid binaries (kernel security policy)
- The interpose library must export symbols with the correct version tags to match what binaries expect

The version script (`crates/frankenlibc-abi/version_scripts/libc.map`) handles the last point by exporting symbols under the `GLIBC_2.2.5` version tag, which is what most dynamically linked Linux binaries expect.

### dlfcn Boundary Policy

Interpose (`L0/L1`): `dlopen`, `dlsym`, `dlclose`, and `dlerror` stay inside FrankenLibC's native phase-1 loader boundary for supported handles and exported symbols.

Hardened invalid `dlopen` flags heal to `RTLD_NOW` before local phase-1 resolution.

Replacement (`L2/L3`) forbids direct host `dlopen`/`dlsym`/`dlclose` fallback paths; any residual call-through is a release-blocking gate failure.

## About Contributions

> *About Contributions:* Please don't take this the wrong way, but I do not accept outside contributions for any of my projects. I simply don't have the mental bandwidth to review anything, and it's my name on the thing, so I'm responsible for any problems it causes; thus, the risk-reward is highly asymmetric from my perspective. I'd also have to worry about other "stakeholders," which seems unwise for tools I mostly make for myself for free. Feel free to submit issues, and even PRs if you want to illustrate a proposed fix, but know I won't merge them directly. Instead, I'll have Claude or Codex review submissions via `gh` and independently decide whether and how to address them. Bug reports in particular are welcome. Sorry if this offends, but I want to avoid wasted time and hurt feelings. I understand this isn't in sync with the prevailing open-source ethos that seeks community contributions, but it's the only way I can move at this velocity and keep my sanity.

## License

FrankenLibC is available under the terms in [LICENSE](LICENSE), currently `MIT License (with OpenAI/Anthropic Rider)`.
