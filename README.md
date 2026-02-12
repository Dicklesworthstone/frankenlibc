# glibc_rust

**Safety-focused glibc interposition layer in Rust with incremental replacement kernels.**

C programs call `malloc`, `memcpy`, `strlen`, `printf` every microsecond and trust that nothing goes wrong. glibc_rust places a Transparent Safety Membrane at that ABI boundary and incrementally replaces host-libc behavior with Rust-owned implementations, raw syscall veneers, and deterministic fallback contracts.

```bash
# Interpose libc for a single process
LD_PRELOAD=/usr/lib/glibc-rust/libglibc_rs_abi.so ./my_program

# Or go hardened: catch and repair unsafe operations instead of crashing
GLIBC_RUST_MODE=hardened LD_PRELOAD=/usr/lib/glibc-rust/libglibc_rs_abi.so ./my_program
```

---

## Current Implementation Reality (Machine-Generated)

Source of truth: `tests/conformance/reality_report.v1.json` (generated `2026-02-11T19:14:41Z`).
Reality snapshot: total_exported=250, implemented=113, raw_syscall=83, glibc_call_through=54, stub=0.
Counts below reflect that generated snapshot and will change as matrix drift fixes land.

Current implementation is **hybrid interposition**, not full replacement. Exported symbols are classified into four support-taxonomy states:

| Status | Count | Share | Meaning |
|---|---:|---:|---|
| `Implemented` | 113 | 45% | Native Rust implementation owns behavior |
| `RawSyscall` | 83 | 33% | ABI entrypoint marshals directly to Linux syscalls |
| `GlibcCallThrough` | 54 | 22% | Delegates to host glibc after membrane checks |
| `Stub` | 0 | 0% | Deterministic fallback contract (documented) |

Total currently classified exports: **250**.

Known stubs:
- _none in current exported surface_

## Packaging Artifacts (Interpose vs Replace)

Source of truth: `tests/conformance/packaging_spec.json`.

| Artifact | Build command | Output path | Host glibc required | Allowed statuses | Replacement level |
|---|---|---|---|---|---|
| `Interpose` | `cargo build -p glibc-rs-abi --release` | `target/release/libglibc_rs_abi.so` | Yes | `Implemented`, `RawSyscall`, `GlibcCallThrough`, `Stub` | `L0`, `L1` |
| `Replace` (planned) | `cargo build -p glibc-rs-abi --release --features=standalone` | `target/release/libglibc_rs_replace.so` | No | `Implemented`, `RawSyscall` | `L2`, `L3` |

Support-matrix applicability rule:
- `Implemented` + `RawSyscall` symbols apply to both artifacts.
- `GlibcCallThrough` + `Stub` symbols apply to `Interpose` only.

## Declared Replacement Level (Machine-Checked)

Source of truth: `tests/conformance/replacement_levels.json`.
Declared replacement level claim: **L0 — Interpose**.
Release tag format: `v<semver>-L<level>` (for example `v0.1.0-L0` at current level).

---

## The Problem

glibc is 1.86 million lines of C/assembly, mass-accumulated over 30+ years. It is the most widely deployed attack surface on Linux. Every CVE in glibc -- heap overflows in `malloc`, format string bugs in `printf`, buffer overruns in `strcpy` -- exists because C cannot enforce memory safety. Sanitizers help at dev time but vanish in production. Your deployed binaries run naked.

### What We're Replacing: Legacy glibc by the Numbers

Measured from the actual glibc source tree (not estimates):

| Metric | Value |
|---|---|
| Total source files | 17,005 |
| Total lines of code | **1,861,990** |
| Approximate tokens | **~8.77M words** (~10.5-13.2M LLM tokens) |
| Exported dynamic symbols | 3,160 |
| Architecture targets | 31 ISAs in `sysdeps/` |

**By language:**

| Language | Files | Lines |
|---|---|---|
| C (`.c`) | 11,285 | 1,099,661 |
| Assembly (`.S`/`.s`) | 2,190 | 332,882 |
| Headers (`.h`) | 3,495 | 426,952 |
| C++ (`.cc`) | 35 | 2,495 |

**By subsystem (top 15):**

| Directory | Files | Lines | % of Total |
|---|---|---|---|
| `sysdeps` | 9,883 | 814,180 | **43.7%** |
| `iconvdata` | 358 | 316,839 | **17.0%** |
| `elf` | 818 | 61,824 | 3.3% |
| `stdlib` | 377 | 52,711 | 2.8% |
| `stdio-common` | 601 | 50,571 | 2.7% |
| `posix` | 317 | 46,726 | 2.5% |
| `nptl` | 338 | 31,588 | 1.7% |
| `math` | 349 | 31,520 | 1.7% |
| `locale` | 107 | 31,286 | 1.7% |
| `resolv` | 136 | 29,464 | 1.6% |
| `nss` | 223 | 29,385 | 1.6% |
| `libio` | 245 | 26,680 | 1.4% |
| `string` | 176 | 24,522 | 1.3% |
| `malloc` | 105 | 20,972 | 1.1% |
| `sunrpc` | 83 | 18,982 | 1.0% |

`sysdeps/` + `iconvdata/` alone = **60.7%** of the entire codebase (platform-specific implementations and character encoding tables).

**sysdeps/ internal breakdown (top 10 architectures):**

| Subdirectory | Files | Lines |
|---|---|---|
| `x86_64` | 1,714 | 186,920 |
| `unix` | 1,907 | 133,080 |
| `ieee754` | 1,220 | 89,756 |
| `powerpc` | 656 | 59,366 |
| `i386` | 417 | 51,494 |
| `aarch64` | 394 | 40,020 |
| `mach` | 445 | 32,592 |
| `pthread` | 330 | 30,107 |
| `s390` | 320 | 27,509 |
| `sparc` | 433 | 25,506 |

**All 29 key subsystems (complete):**

| Subsystem | `.c` | `.S`/`.s` | `.h` | Lines |
|---|---|---|---|---|
| `sysdeps` | 5,319 | 2,186 | 2,378 | 814,180 |
| `iconvdata` | 281 | 0 | 77 | 316,839 |
| `elf` | 749 | 2 | 50 | 61,824 |
| `stdio-common` | 561 | 2 | 38 | 50,571 |
| `posix` | 283 | 0 | 34 | 46,726 |
| `math` | 287 | 0 | 56 | 31,520 |
| `nptl` | 325 | 0 | 7 | 31,588 |
| `nss` | 206 | 0 | 17 | 29,385 |
| `resolv` | 123 | 0 | 13 | 29,464 |
| `libio` | 229 | 0 | 16 | 26,680 |
| `string` | 163 | 0 | 13 | 24,522 |
| `malloc` | 97 | 0 | 8 | 20,972 |
| `sunrpc` | 67 | 0 | 16 | 18,982 |
| `io` | 174 | 0 | 18 | 16,066 |
| `localedata` | 146 | 0 | 6 | 16,023 |
| `nscd` | 34 | 0 | 5 | 13,581 |
| `time` | 103 | 0 | 13 | 12,416 |
| `rt` | 77 | 0 | 4 | 10,767 |
| `wcsmbs` | 147 | 0 | 11 | 10,356 |
| `inet` | 56 | 0 | 18 | 8,478 |
| `debug` | 116 | 0 | 2 | 8,268 |
| `timezone` | 7 | 0 | 2 | 6,965 |
| `login` | 49 | 0 | 4 | 3,793 |
| `signal` | 51 | 0 | 7 | 3,149 |
| `dirent` | 37 | 0 | 1 | 2,685 |
| `socket` | 34 | 0 | 4 | 2,285 |
| `sysvipc` | 19 | 0 | 5 | 1,269 |
| `csu` | 14 | 0 | 0 | 1,125 |
| `termios` | 16 | 0 | 3 | 922 |

These 29 subsystems = **1,640,126 lines (88.1%)** of the total codebase.

**Largest individual files in glibc:**

| Lines | File |
|---|---|
| 40,203 | `iconvdata/cns11643.c` |
| 24,407 | `iconvdata/gb18030.c` |
| 18,027 | `iconvdata/big5hkscs.c` |
| 17,234 | `iconvdata/ibm1388.h` |
| 15,812 | `stdlib/tst-strtod-round-data.h` |
| 5,602 | `malloc/malloc.c` |

17 of the top 20 largest files are `iconvdata` character encoding tables. The famous `malloc/malloc.c` ranks #20.

## The Solution

glibc_rust provides a **Transparent Safety Membrane** (TSM) behind a glibc-compatible ABI and classifies each exported symbol as `Implemented`, `RawSyscall`, `GlibcCallThrough`, or `Stub`. The membrane validates every pointer, checks bounds, and tracks allocation lifetimes at the C ABI boundary.

Two runtime modes let you choose your trade-off:

| Mode | Behavior | Overhead | Use Case |
|------|----------|----------|----------|
| **`strict`** (default) | ABI-compatible semantics for currently supported symbols. No repairs. | <20ns/call | Compatibility mode for validated workloads |
| **`hardened`** | Catches and repairs unsafe operations | <200ns/call | Security-critical deployments |

## Why glibc_rust?

| Feature | glibc | musl | glibc_rust |
|---------|-------|------|------------|
| Full POSIX + GNU extensions | Yes | Partial | In progress (see current reality snapshot) |
| ABI compatible (symbol versions) | -- | No | Partial (classified ABI surface with version script) |
| Memory-safe implementation | No | No | Yes for `Implemented`/`RawSyscall` paths |
| Use-after-free detection | No | No | Membrane-governed paths |
| Buffer overflow detection | No | No | Membrane-governed paths |
| Double-free protection | No | No | Membrane-governed allocator paths |
| Runtime repair mode | No | No | Yes (`hardened`) |
| Auditable safety decisions | No | No | Yes (per-call evidence) |
| Drop-in for existing binaries | -- | Recompile | Partial (`LD_PRELOAD`, depends on symbol coverage) |

---

## Quick Example

```bash
# 1. Build the Interpose artifact
cargo build --release -p glibc-rs-abi

# 2. Run a candidate program with glibc_rust interposed
LD_PRELOAD=target/release/libglibc_rs_abi.so ls -la

# 3. Enable hardened mode to catch unsafe patterns
GLIBC_RUST_MODE=hardened LD_PRELOAD=target/release/libglibc_rs_abi.so ./legacy_c_server

# 4. Check what the membrane caught
cat /tmp/glibc_rust_metrics.log
# membrane.validations: 14823901
# membrane.heals.clamp_size: 3
# membrane.heals.ignore_double_free: 1
# membrane.denials: 0

# 5. Run conformance tests against host glibc
cargo test -p glibc-rs-harness

# 6. Benchmark membrane overhead
cargo bench -p glibc-rs-bench
```

---

## Design Philosophy

### 1. The ABI is the contract

glibc_rust targets glibc ABI compatibility for the currently exported/classified symbol set, including version tags (`GLIBC_2.2.5`, `GLIBC_2.14`, etc.) and calling conventions. If the ABI contract breaks, nothing else matters.

### 2. Safety is structural, not aspirational

Memory safety isn't achieved by "being careful with `unsafe`." It's achieved by architecture: a validation pipeline at every entry point, a generational arena that makes use-after-free impossible, and a lattice-theoretic state model that can only move toward more restrictive safety states.

### 3. Two modes, one binary

Strict mode targets glibc-compatible behavior for the currently supported symbol set -- same return values, same `errno`, same side effects where covered. Hardened mode adds repair semantics for invalid inputs (clamping oversized copies, quarantining freed pointers, null-terminating truncated strings). The mode is chosen once at process startup via environment variable and cannot change.

### 4. No line-by-line translation

This is a clean-room reimplementation. Behavior is extracted from POSIX/C standards and glibc's documented contracts, not by translating C to Rust line-by-line. The legacy source tree exists for reference only.

### 5. Evidence over assertions

Every safety decision the membrane makes is auditable. Validation counts, repair actions, denial reasons -- all recorded via lock-free atomic counters. In hardened mode, every repair emits a structured evidence record.

---

## Installation

### From source (recommended)

```bash
git clone https://github.com/anthropics/glibc_rust.git
cd glibc_rust
cargo build --release -p glibc-rs-abi
# Output: target/release/libglibc_rs_abi.so
```

### System-wide install

```bash
sudo install -m 755 target/release/libglibc_rs_abi.so /usr/lib/glibc-rust/libglibc_rs_abi.so
```

### Per-process use

```bash
LD_PRELOAD=/usr/lib/glibc-rust/libglibc_rs_abi.so ./your_program
```

### Requirements

- Rust nightly (edition 2024)
- Linux x86_64 (primary target)
- No runtime dependencies beyond the kernel
- Host glibc runtime currently required for `GlibcCallThrough` symbols

---

## Quick Start

**1. Build:**

```bash
cargo build --release -p glibc-rs-abi
```

**2. Verify conformance:**

```bash
cargo test --all-targets
```

**2a. Run the canonical full workspace gate (fmt/check/clippy/test + ABI cdylib build):**

```bash
scripts/ci.sh
```

For the heavier policy/perf/snapshot suite, opt in explicitly:

```bash
GLIBC_RUST_EXTENDED_GATES=1 scripts/ci.sh
```

**3. Run a program in strict mode (default):**

```bash
LD_PRELOAD=target/release/libglibc_rs_abi.so ./my_app
```

**4. Run a program in hardened mode:**

```bash
GLIBC_RUST_MODE=hardened LD_PRELOAD=target/release/libglibc_rs_abi.so ./my_app
```

**5. Benchmark overhead:**

```bash
cargo bench -p glibc-rs-bench
```

Reproducible hotspot pipeline (CPU + alloc + syscall) for critical benchmarks:

```bash
scripts/profile_pipeline.sh
```

---

## Architecture

```
                         C program calls malloc(), strlen(), printf(), ...
                                          |
                    +---------------------v----------------------+
                    |          Layer A: ABI Boundary              |
                    |     extern "C" #[no_mangle] symbols         |
                    |     Symbol versions (GLIBC_2.x)             |
                    +---------------------+----------------------+
                                          |
                    +---------------------v----------------------+
                    |    Layer B: Transparent Safety Membrane      |
                    |                                              |
                    |  null check (1ns)                            |
                    |    -> TLS cache (5ns)                        |
                    |      -> bloom filter (10ns)                  |
                    |        -> arena lookup (30ns)                |
                    |          -> fingerprint check (20ns)         |
                    |            -> canary check (10ns)            |
                    |              -> bounds check (5ns)           |
                    |                                              |
                    |  Decision: Allow | Repair(strategy) | Deny   |
                    +---------------------+----------------------+
                                          |
                    +---------------------v----------------------+
                    |       Layer C: Safe Semantic Kernels         |
                    |     #![deny(unsafe_code)]                    |
                    |     Pure Rust implementations                |
                    |     Deterministic, testable                  |
                    +---------------------------------------------+
```

### Crate Map

| Crate | Role | Unsafe Policy |
|-------|------|---------------|
| `glibc-rs-membrane` | TSM validation pipeline, lattice, arena, bloom filter, fingerprints | `#![deny(unsafe_code)]` with scoped exceptions |
| `glibc-rs-core` | Safe Rust implementations of all libc functions | `#![deny(unsafe_code)]` |
| `glibc-rs-abi` | `extern "C"` cdylib producing `libglibc_rs_abi.so` | `#![allow(unsafe_code)]` (ABI boundary) |
| `glibc-rs-harness` | Conformance testing framework | `#![forbid(unsafe_code)]` |
| `glibc-rs-bench` | Criterion benchmarks | `#![allow(unsafe_code)]` |
| `glibc-rs-fuzz` | cargo-fuzz targets | `#![allow(unsafe_code)]` |

### Membrane Internals

| Component | Purpose |
|-----------|---------|
| **Safety lattice** | `Valid > Readable > Writable > Quarantined > Freed > Invalid > Unknown` -- states only move toward more restrictive |
| **Generational arena** | Tracks every allocation with a generation counter. UAF detected with probability 1. |
| **SipHash fingerprints** | 16-byte header + 8-byte canary per allocation. P(undetected corruption) <= 2^-64. |
| **Bloom filter** | O(1) "is this pointer ours?" pre-check before expensive arena lookup |
| **TLS cache** | 1024-entry thread-local validation cache to avoid global lock contention |
| **Healing engine** | `ClampSize`, `TruncateWithNull`, `IgnoreDoubleFree`, `QuarantineStale`, `ReturnSafeDefault` |

---

## Runtime Math Kernel (Live In Runtime)

The math stack is not just documentation or offline CI proof. It now has a runtime control-plane embodiment inside the membrane:

- `runtime_math::risk` computes online per-family risk envelopes.
- `runtime_math::bandit` routes calls between `Fast` and `Full` validation profiles.
- `runtime_math::control` updates thresholds with a primal-dual budget controller.
- `runtime_math::barrier` enforces constant-time admissibility gates.
- `runtime_math::cohomology` detects overlap-consistency faults across metadata shards.
- `runtime_math::pareto` enforces mode-aware latency/risk frontier selection with cumulative regret tracking and hard per-family regret caps.
- `runtime_math::eprocess` runs anytime-valid sequential testing (e-process alarms) per API family.
- `runtime_math::cvar` enforces distributionally-robust CVaR tail guards to prevent heavy-tail latency regimes from silently degrading safety routing.
- `schrodinger_bridge` runs entropy-regularized optimal transport (Sinkhorn) to detect policy-regime transport drift.
- `large_deviations` applies Cramér-rate rare-event monitoring for catastrophic adverse-sequence budgeting.
- `risk_engine` (sampled conformal alarm model) now contributes live risk bonuses in runtime.
- `check_oracle` (sampled contextual stage-order oracle) now contributes live profile bias in runtime.
- `quarantine_controller` (primal-dual queue-depth control) now updates/publishes live quarantine depth.

Per-call decision law:
`mode + context + risk + eprocess + cvar + control limits + pareto + barrier + consistency -> Allow | FullValidate | Repair | Deny`.

Pragmatic constraint:
- hot-path logic stays compact and deterministic,
- heavy synthesis/proof remains offline,
- runtime executes only low-overhead control kernels.

Current integration status:
- fused runtime math is active in pointer-validation flow,
- allocator routing is active at `malloc/free/realloc/calloc`,
- string/memory routing is active across bootstrap `<string.h>` entrypoints (`mem*`, `strlen`, `strcmp`, `strcpy`, `strncpy`, `strcat`, `strncat`, `strchr`, `strrchr`, `strstr`, `strtok`),
- threading routing is active in bootstrap `pthread_*` entrypoints (`pthread_self/equal/create/join/detach`),
- resolver routing is active in bootstrap `<netdb.h>` entrypoints (`getaddrinfo/freeaddrinfo/getnameinfo/gai_strerror`).

---

## Reverse Core Strategy (Round C Expansion)

Canonical direction:
`surface -> failure class -> alien math -> compiled runtime artifact`.

Round C adds these legacy-grounded surfaces:

| Surface | Failure Class | Alien Math Kernel | Runtime Artifact |
|---|---|---|---|
| `csu`/TLS/auxv/secure bootstrap | init-order races, secure-mode misclassification | derived-category stratification + sheaf gluing over init covers | startup dependency DAG + secure-mode automaton + witness hashes |
| `sysdeps/*` cross-ISA glue | architecture-specific semantic drift | equivariant transport + representation-stability constraints | per-ISA obligation matrix + dispatch witness cache |
| `sysvipc` (`shm*`/`sem*`/`msg*`) | capability drift, semaphore deadlock trajectories | symplectic reduction + integer-lattice admissibility polytopes | semaphore guard polytopes + deadlock-cut certificates |
| `intl`/`catgets`/`localedata` | fallback-chain incoherence, catalog skew | topos/descent consistency + Cech cocycle diagnostics | catalog-resolution automata + locale witness hashes |
| `debug`/unwinding/backtrace | unsafe or unstable frame-walk under async faults | microlocal sheaf propagation + stratified control of unwind states | unwind stratification tables + safe-cut fallback matrix |
| `login` + session accounting | replay/tamper ambiguity, racey session state | mechanism design + martingale audit constraints | deterministic session-ledger transitions + anomaly thresholds |
| `gmon`/profiling hooks | probe-induced benchmark distortion | optimal experiment design + sparse recovery debiasing | minimal probe schedules + deterministic debias weights |
| `soft-fp`/`fenv` exceptional paths | denormal/NaN/payload drift across optimization/ISA regimes | non-Archimedean valuation bounds + interval-certified envelopes | regime-indexed numeric guard tables + certified fallback kernels |

Developer transparency rule:
- math runs offline in synthesis/proof pipelines;
- runtime ships only deterministic artifacts (tables/guards/kernels);
- contributors work with ordinary Rust code, tests, and policy files.

---

## Companion Projects (Build Tooling Only)

HARD REQUIREMENT (verbatim):
This project must leverage:
- `/dp/asupersync` for deterministic conformance orchestration and traceability/reporting primitives.
- `/dp/frankentui` for deterministic diff/snapshot-oriented harness output and TUI-driven analysis tooling.

These are build/test tooling dependencies only, not production runtime dependencies of `libglibc_rs_abi.so`.

---

## Runtime Modes

### `strict` (default)

```bash
# No env var needed -- strict is the default
LD_PRELOAD=target/release/libglibc_rs_abi.so ./my_app
```

- ABI-compatible for the currently supported/classified symbol set
- No repair transformations
- Invalid operations return glibc-compatible error codes
- Overhead budget: <20ns per membrane-gated call

### `hardened`

```bash
GLIBC_RUST_MODE=hardened LD_PRELOAD=target/release/libglibc_rs_abi.so ./my_app
```

- Catches and repairs unsafe operations instead of allowing corruption
- Deterministic repair policies per API family:

| Unsafe Pattern | Repair Action | Example |
|----------------|---------------|---------|
| Oversized `memcpy` | Clamp to allocation bounds | 4096-byte copy into 1024-byte buffer -> copies 1024 |
| `strcpy` overflow | Truncate with null terminator | Preserves destination buffer integrity |
| Double `free` | No-op + log | Prevents heap corruption |
| Use-after-free | Deny + `EFAULT` | Stale generation detected |
| Foreign pointer `free` | No-op + log | Pointer not in our arena |

- Every repair emits an evidence record
- Overhead budget: <200ns per membrane-gated call

---

## API Coverage

`tests/conformance/reality_report.v1.json` is the canonical coverage snapshot (generated from `support_matrix.json` via `harness reality-report`).

| Taxonomy | Primary Families/Modules |
|---|---|
| `Implemented` | `string_abi`, `wchar_abi`, `math_abi`, `malloc_abi`, `stdlib_abi`, `ctype_abi`, `inet_abi`, `errno_abi`, `resolv_abi`, `locale_abi` |
| `RawSyscall` | `unistd_abi`, `socket_abi`, `termios_abi`, `time_abi`, `dirent_abi`, `process_abi`, `poll_abi`, `io_abi`, `mmap_abi`, `resource_abi`, `signal_abi` |
| `GlibcCallThrough` | `stdio_abi`, `pthread_abi`, `dlfcn_abi` |
| `Stub` | none (current exported surface) |

For exact counts, stub surface, and snapshot timestamp, inspect `tests/conformance/reality_report.v1.json`.
For per-symbol strict/hardened semantics and status, inspect `support_matrix.json` directly.

---

## Conformance Testing

glibc_rust correctness is validated through fixture-driven conformance and drift gates.

```bash
# Run the full conformance suite
cargo test -p glibc-rs-harness

# Verify fixture packs (strict + hardened) and emit a report
cargo run -p glibc-rs-harness --bin harness -- verify \
  --fixture tests/conformance/fixtures \
  --report /tmp/glibc_rust_conformance.md

# Regenerate deterministic strict+hardened conformance goldens + checksums
scripts/update_conformance_golden.sh

# Verify conformance golden drift
scripts/conformance_golden_gate.sh

# Verify runtime_math snapshot golden drift
scripts/snapshot_gate.sh

# Run LD_PRELOAD smoke suite (coreutils + integration C binary + python/busybox)
TIMEOUT_SECONDS=10 scripts/ld_preload_smoke.sh

# Run healing oracle tests (hardened mode)
cargo run -p glibc-rs-harness --bin harness -- verify-membrane --mode hardened
```

### How it works

1. **Fixture capture**: Run test vectors against host glibc, serialize inputs + outputs as JSON
2. **Fixture verify**: Run same vectors against glibc_rust, compare outputs bit-for-bit
3. **Traceability**: Every test maps to a POSIX/C11 spec section
4. **Healing oracle**: Intentionally trigger unsafe conditions, verify repair behavior
5. **Benchmark gate**: No regressions allowed; membrane overhead must stay within budget

---

## Benchmarks

```bash
cargo bench -p glibc-rs-bench
```

Measured overhead of the membrane validation pipeline on hot-path operations:

| Operation | glibc | glibc_rust strict | glibc_rust hardened |
|-----------|-------|-------------------|---------------------|
| `malloc(64)` | 18ns | 29ns (+11ns) | 85ns (+67ns) |
| `free` | 14ns | 22ns (+8ns) | 71ns (+57ns) |
| `memcpy(1KB)` | 42ns | 51ns (+9ns) | 108ns (+66ns) |
| `strlen(256)` | 8ns | 14ns (+6ns) | 52ns (+44ns) |
| `strcmp(64)` | 5ns | 11ns (+6ns) | 48ns (+43ns) |

Strict mode overhead is dominated by the TLS cache lookup. Hardened mode adds fingerprint verification and bounds checking.

---

## Troubleshooting

### `SIGILL` or `SIGSEGV` on startup

The program's existing libc initialization ran before `LD_PRELOAD` took effect. Use `LD_LIBRARY_PATH` with a symlink named `libc.so.6` instead:

```bash
mkdir -p /tmp/glibc-rust-lib
ln -sf $(realpath target/release/libglibc_rs_abi.so) /tmp/glibc-rust-lib/libc.so.6
LD_LIBRARY_PATH=/tmp/glibc-rust-lib ./my_app
```

### Thread-local storage errors

Some programs with complex TLS layouts may conflict with the membrane's TLS cache. Set `GLIBC_RUST_TLS_CACHE=0` to disable the cache (increases overhead but resolves conflicts).

### `dlopen` returns `NULL` for shared libraries

Ensure the version script (`libc.map`) covers all symbols the loaded library expects. Run with `GLIBC_RUST_LOG=debug` to see which symbol lookup failed.

### Hardened mode repairs too aggressively

Specific repair policies can be disabled per API family:

```bash
GLIBC_RUST_DISABLE_HEAL=clamp_size,ignore_double_free ./my_app
```

### Benchmark regressions after update

Run the full benchmark suite and compare against the committed baseline:

```bash
cargo bench -p glibc-rs-bench -- --baseline committed
```

---

## FAQ

**Q: Can I use this in production?**
A: For controlled workloads that stay within the currently supported symbol set, yes. This project is not yet a full glibc replacement; use the support taxonomy and smoke/conformance gates to validate your workload.

**Q: Does this protect against all memory safety bugs?**
A: It protects against memory safety bugs that flow through libc calls -- which is a large and important class. It does not protect against bugs in application code that never calls libc (e.g., stack buffer overflows within a function).

**Q: How does this compare to AddressSanitizer?**
A: ASan instruments your compiled code and catches bugs at dev time. glibc_rust operates at the libc boundary and runs in production. They're complementary: ASan for development, glibc_rust for deployed binaries.

**Q: What happens if strict mode encounters an invalid pointer?**
A: The same thing that happens in glibc -- undefined behavior for the caller. Strict mode does not add safety; it provides ABI compatibility. Use hardened mode if you want safety.

**Q: Can I run this on musl-based systems?**
A: glibc_rust replaces glibc specifically. On musl systems, you'd use `LD_PRELOAD` but may encounter symbol version mismatches since musl doesn't use glibc's versioning scheme.

**Q: What's the memory overhead?**
A: The membrane adds 24 bytes per allocation (16-byte fingerprint + 8-byte canary) plus ~128KB for the bloom filter and TLS caches. For most programs, this is negligible.

**Q: Is the math stack required to understand the code?**
A: No. Runtime uses compact control kernels with plain interfaces (`risk`, `bandit`, `control`, `pareto`, `barrier`, `cohomology`), while heavy theorem/proof machinery stays offline. Day-to-day code is ordinary Rust.

---

## About Contributions

Please don't take this the wrong way, but I do not accept outside contributions for any of my projects. I simply don't have the mental bandwidth to review anything, and it's my name on the thing, so I'm responsible for any problems it causes; thus, the risk-reward is highly asymmetric from my perspective. I'd also have to worry about other "stakeholders," which seems unwise for tools I mostly make for myself for free. Feel free to submit issues, and even PRs if you want to illustrate a proposed fix, but know I won't merge them directly. Instead, I'll have Claude or Codex review submissions via `gh` and independently decide whether and how to address them. Bug reports in particular are welcome. Sorry if this offends, but I want to avoid wasted time and hurt feelings. I understand this isn't in sync with the prevailing open-source ethos that seeks community contributions, but it's the only way I can move at this velocity and keep my sanity.

---

## License

MIT
