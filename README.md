# FrankenLibC

<div align="center">
  <img src="docs/assets/images/franken_libc_illustration.webp" alt="FrankenLibC illustration" width="720">
</div>

<div align="center">

![version](https://img.shields.io/badge/version-0.1.0-2f6feb)
![rust](https://img.shields.io/badge/rust-nightly-f74c00)
![platform](https://img.shields.io/badge/platform-linux-181717)
![arch](https://img.shields.io/badge/arch-x86__64%20%7C%20aarch64-005f87)
![coverage](https://img.shields.io/badge/native_coverage-100%25-2ea44f)
![license](https://img.shields.io/badge/license-MIT%20with%20rider-8a2be2)

</div>

**A clean-room, memory-safe Rust reimplementation of glibc.** FrankenLibC produces a glibc-shaped `libc.so` that real Linux binaries can load with `LD_PRELOAD`, classifies every exported symbol as either native Rust or a direct Linux syscall (no host-glibc call-through left in the classified surface), and runs every entrypoint through a **Transparent Safety Membrane** that validates, sanitizes, repairs, denies, and audits unsafe operations at the ABI boundary.

```bash
git clone https://github.com/Dicklesworthstone/frankenlibc.git
cd frankenlibc
cargo build -p frankenlibc-abi --release
LD_PRELOAD="$PWD/target/release/libfrankenlibc_abi.so" /bin/echo "hello from FrankenLibC"
```

Deployment details, runtime knobs, and Gentoo/Portage operations are collected in [`DEPLOYMENT.md`](DEPLOYMENT.md).

---

## TL;DR

### The Problem

glibc is enormous, security-critical, and written in a language that cannot enforce memory safety at the ABI boundary. Existing Linux software expects glibc-compatible symbols, calling conventions, version tags, `errno` discipline, and process-level semantics. Throwing those compatibility constraints away to "rewrite libc safely" is not a real option.

### The Solution

FrankenLibC puts a **Transparent Safety Membrane (TSM)** behind a glibc-shaped ABI. Every libc entrypoint goes through five steps before doing real work: runtime policy decision, deny check, input validation, delegation to safe Rust kernels or raw Linux syscalls, and outcome recording. The membrane sees every pointer, every region, every fd, every state transition.

### Why FrankenLibC

| Why it matters | Current state |
|---|---|
| Large classified ABI surface | **4,119 exported symbols** all classified |
| Native ownership is complete | **3,705 `Implemented` + 414 `RawSyscall` = 100.0% native coverage** |
| No host-glibc call-through in the classified surface | **0 `GlibcCallThrough`, 0 `WrapsHostLibc`, 0 `Stub`** |
| Interposition is usable on real workloads today | Curated smoke battery: **58 passes / 0 fails / 6 skips** across strict + hardened modes |
| Two runtime safety modes | `FRANKENLIBC_MODE=strict` (compatibility-first) and `FRANKENLIBC_MODE=hardened` (deterministic repair) |
| Two architectures supported | x86_64 (primary) and aarch64 (gated, tested via cross-compile) |
| Verification is first-class | Harness CLI, 40+ fixture families, **258 completion-contract artifacts**, **68 CLI-contract manifests** subject to ~50 meta-gates each, **66 `cargo-fuzz` targets**, and 9 proof notes / obligation mappings |
| Runtime math is live code | `crates/frankenlibc-membrane/src/runtime_math/` contains **~71 active control kernels**, not just design docs |
| Build-time formal infrastructure | SOS polynomial certificates synthesized and verified at build; per-file atomic-barrier coverage audit |

### Claim-Field Contract

FrankenLibC distinguishes symbol-taxonomy ownership from full semantic parity. Any claim about support, parity, or replacement-readiness is traceable through:

| Field | Meaning | Source of truth |
|---|---|---|
| `symbol_status` | Support-taxonomy classification for a symbol; ownership only | `support_matrix.json` |
| `semantic_parity_status` | Full / blocked / limited semantic status for known no-op / fallback / bootstrap / unsupported contracts | `tests/conformance/semantic_contract_symbol_join.v1.json` |
| `oracle_kind` | Evidence precedence: host glibc parity vs POSIX/Linux behavior vs documented FrankenLibC contract vs allowed divergence | `tests/conformance/oracle_precedence_divergence.v1.json` |
| `replacement_level` | Claim scope: L0 interpose-only, L1 hardened interpose, L2 standalone-ready, L3 standalone | `tests/conformance/replacement_levels.json` |
| `evidence_artifact` | Concrete report, fixture, matrix, or generated artifact backing the claim | `tests/conformance/*.json`, `tests/conformance/*.jsonl`, `target/conformance/*` |
| `freshness_state` | `source_commit`, `generated_at_utc`, gate-specific freshness predicate | Generated reports and gate logs |
| `known_limitation` | Explicit blocker, deferred subsystem, unsupported contract | `tests/conformance/support_semantic_overlay.v1.json` |
| `user_recommendation` | Practical guidance: L0-only, blocked, unsupported, degraded, ready for narrow workload | Generated compatibility and claim-gate reports |

---

## Quick Example

```bash
# 1. Build the interpose artifact
cargo build -p frankenlibc-abi --release
# -> target/release/libfrankenlibc_abi.so

# 2. Inspect the current symbol reality
cargo run -p frankenlibc-harness --bin harness -- reality-report \
  --support-matrix support_matrix.json \
  --output /tmp/frankenlibc-reality.json

# 3. Run a real program in strict (compatibility-first) mode
LD_PRELOAD="$PWD/target/release/libfrankenlibc_abi.so" /bin/ls -la /tmp

# 4. Run the same program in hardened (repair-capable) mode
FRANKENLIBC_MODE=hardened \
LD_PRELOAD="$PWD/target/release/libfrankenlibc_abi.so" /bin/ls -la /tmp

# Hardened echo smoke path tracked by the release README workload gate
# Hardened mode exists now and is exercised by the curated preload smoke battery
FRANKENLIBC_MODE=hardened \
LD_PRELOAD="$PWD/target/release/libfrankenlibc_abi.so" /bin/echo hardened

# 5. Verify hardened-mode repair behavior end-to-end
cargo run -p frankenlibc-harness --bin harness -- verify-membrane \
  --mode both \
  --output /tmp/healing_oracle.json

# 6. Run the curated preload smoke battery (real binaries, both modes)
TIMEOUT_SECONDS=10 bash scripts/ld_preload_smoke.sh

# 7. Check support-matrix maintenance drift
bash scripts/check_support_matrix_maintenance.sh

# 8. Re-run the full default repo gate
bash scripts/ci.sh
```

---

## The Transparent Safety Membrane

The TSM is the architectural centerpiece. Instead of trusting raw C pointers because the caller crossed an ABI boundary, FrankenLibC treats that boundary as the place where unsafe information must be classified, validated, and either accepted, repaired, or denied; every call, every pointer, every region.

### Pipeline

```
incoming pointer / region / fd / mode / context
    │
    ▼
 null check         ≈ 1 ns   (fast-exit)
    │
    ▼
 TLS validation cache ≈ 5 ns (1024-entry direct-mapped, per thread)
    │
    ▼
 bloom filter ownership precheck ≈ 10 ns (atomic u64 bit array)
    │
    ▼
 arena / metadata lookup ≈ 30 ns (16 shards, generational)
    │
    ▼
 fingerprint check ≈ 20 ns (SipHash-2-4 header)
    │
    ▼
 canary check ≈ 10 ns (8-byte trailing)
    │
    ▼
 bounds + state check ≈ 5 ns
    │
    ▼
   Allow │ Repair │ Deny
```

Fast exits short-circuit each stage. Performance budget: strict-mode overhead targets **< 20 ns/call**, hardened-mode overhead targets **< 200 ns/call** for membrane-gated hot paths.

### Modes

| Mode | Purpose | Behavior |
|---|---|---|
| `strict` (default) | Compatibility-first | Validate without rewriting; prefer ABI-compatible failures over hidden corrections |
| `hardened` | Safety-first | Repair or deny unsafe patterns and emit structured evidence |

The mode is resolved exactly once per process from `FRANKENLIBC_MODE` via a compare-and-swap state machine (`UNRESOLVED` → `RESOLVING` → `STRICT`/`HARDENED`/`OFF`). After init, the mode is immutable. Reentrant calls during resolution return a passthrough decision so the process can finish bootstrapping.

### Healing Actions

In hardened mode the membrane can choose a deterministic repair instead of allowing corruption. Defined in `crates/frankenlibc-membrane/src/heal.rs`:

| Action | Example trigger | Repair |
|---|---|---|
| `ClampSize` | `memcpy(dst, src, size)` where `size` exceeds allocation bounds | Clamp `size` to known bound, emit evidence |
| `TruncateWithNull` | `strcpy` past allocation | Truncate write and write trailing NUL |
| `IgnoreDoubleFree` | `free(p)` after previous `free(p)` | No-op (allocator state preserved), emit evidence |
| `IgnoreForeignFree` | `free(p)` for a pointer not from our allocator | No-op, emit evidence |
| `ReallocAsMalloc` | `realloc(p, n)` where `p` is freed | Allocate fresh `n`-byte region |
| `ReturnSafeDefault` | Read from null/UAF/quarantined | Return zero/empty/EINVAL per family |
| `UpgradeToSafeVariant` | Policy demands the safer semantic | Switch to a stricter contract (e.g., bounded variant) |

Every repair is **deterministic** (replayable from the same input) and **audited** (emits a structured evidence record).

---

## Current State (2026-05-16)

Source of truth: `support_matrix.json` for support taxonomy classification.
Current source of truth: `support_matrix.json` plus `tests/conformance/reality_report.v1.json`.
Source of truth: `tests/conformance/reality_report.v1.json` (generated `2026-02-18T04:49:26Z`).
Reality snapshot: total_exported=4119, implemented=3705, raw_syscall=414, wraps_host_libc=0, glibc_call_through=0, stub=0.

Declared replacement level: **L1 — Hardened Interpose**.
Declared replacement level claim: **L1 — Hardened Interpose**.
Total currently classified exports: **4119**.

| Status | Count | % | Meaning |
|---|---:|---:|---|
| `Implemented` | 3705 | 90% | Native ABI-backed Rust-owned behavior |
| `RawSyscall` | 414 | 10% | ABI path delegates directly to Linux syscalls |
| `WrapsHostLibc` | 0 | 0% | None remaining — every native wrapper has been promoted |
| `GlibcCallThrough` | 0 | 0% | None remaining — no host-glibc symbol call-through in the classified surface |
| `Stub` | 0 | 0% | None — semantic no-op / fallback / bootstrap contracts are tracked separately in the semantic overlay |
| **Total classified** | 4119 | 100% | Native coverage = `Implemented + RawSyscall` |

The classified surface is fully native at the support-taxonomy layer. The shipping artifact is the interpose-first preload library (`libfrankenlibc_abi.so`); it is not a full standalone libc replacement. The staged path to a fully standalone replacement artifact (`libfrankenlibc_replace.so`) is gated by the L1 / L2 / L3 replacement-level promotion contracts.

### Claim Field Contract

User-facing support and replacement claims must keep these fields separate:

| Field | Source of truth |
|---|---|
| `symbol_status` | `support_matrix.json` |
| `semantic_parity_status` | `tests/conformance/semantic_contract_symbol_join.v1.json` |
| `oracle_kind` | `tests/conformance/oracle_precedence_divergence.v1.json` |
| `replacement_level` | `tests/conformance/replacement_levels.json` |
| `evidence_artifact` | Generated reports, fixtures, matrices, or gate logs |
| `freshness_state` | `source_commit`, generated timestamp, or freshness predicate |
| `known_limitation` | Explicit blocker, unsupported contract, proof gap, or deferred behavior |
| `user_recommendation` | L0-only, unsupported, blocked, degraded, or narrow-workload-ready guidance |

### Curated LD_PRELOAD Smoke Battery

Canonical smoke artifact: `tests/conformance/ld_preload_smoke_summary.v1.json`.

| Mode | Pass | Fail | Skip | Programs exercised |
|---|---:|---:|---:|---|
| `strict` | 29 | 0 | 3 | coreutils (`ls`, `cat`, `echo`, `env`, `sort`, `wc`), `python3 -c`, `busybox uname -a`, integration fixture (`tests/integration/link_test.c`), stress iterations |
| `hardened` | 29 | 0 | 3 | same battery with `FRANKENLIBC_MODE=hardened` |
| **Total** | **58** | **0** | **6** | The 6 skips are the optional `sqlite3 :memory:`, `redis-cli --version`, and `nginx -v` probes when those binaries are not installed |

| Workload family | Commands |
|---|---|
| Coreutils | `/bin/ls -la /tmp`, `/bin/cat /etc/hosts`, `/bin/echo`, `/usr/bin/env`, `/bin/sort`, `/usr/bin/wc` |

The checked curated preload smoke battery is green in both strict and hardened modes.
Both runtime modes are green across the curated workloads. Broader production hardening, non-curated workload stability, and release-claim closure for L2/L3 replacement levels remain active work. The strict/hardened mode dichotomy itself is not a research artifact; it runs real binaries today.

---

## Architecture

```text
                                       C process
                                            │
                                            ▼
              ┌────────────────────────────────────────────────────────┐
              │ glibc-shaped extern "C" ABI                            │
              │ crates/frankenlibc-abi  (50 module files, ~121 kLOC)    │
              │ libc.map version script  (4,687 lines, GLIBC_2.2.5)    │
              └────────────────────────────────────────────────────────┘
                                            │
                                            ▼
              ┌────────────────────────────────────────────────────────┐
              │ runtime_policy::decide()  (~87 kLOC, single chokepoint) │
              │  family, ptr, size, is_startup, is_null_likely, flags  │
              │   → (RuntimeKernelSnapshot, RuntimeDecision)           │
              └────────────────────────────────────────────────────────┘
                                            │
                                            ▼
              ┌────────────────────────────────────────────────────────┐
              │ Transparent Safety Membrane                            │
              │ crates/frankenlibc-membrane  (~75 kLOC, 109 modules)    │
              │                                                        │
              │ null → tls_cache → bloom → arena → fingerprint         │
              │      → canary → bounds → policy → decision             │
              │                                                        │
              │ + 71 runtime math control kernels                      │
              │ + alien_cs primitives (SeqLock, RCU, EBR, FlatComb)    │
              │ + evidence ledger (JSONL ring buffer)                  │
              └────────────────────────────────────────────────────────┘
                                            │
              ┌─────────────────────────────┴─────────────────────────────┐
              ▼                                                           ▼
   ┌──────────────────────────┐                       ┌──────────────────────────────┐
   │ Native Rust kernels      │                       │ Raw syscall veneers          │
   │ crates/frankenlibc-core  │                       │ crates/frankenlibc-core/src/ │
   │ (~70 kLOC, 134 modules)  │                       │  syscall/  (typed wrappers)  │
   │                          │                       │                              │
   │ stdio, string, math,     │                       │ io_uring, landlock, futex2,  │
   │ malloc, pthread,         │                       │ process_vm_*, scheduler,     │
   │ resolv, iconv, locale,   │                       │ getrandom, pidfd, statx,     │
   │ /etc-db parsers, etc.    │                       │ execveat, namespace ops      │
   └──────────────────────────┘                       └──────────────────────────────┘
                                            │
                                            ▼
              ┌────────────────────────────────────────────────────────┐
              │ Verification & evidence                                │
              │ crates/frankenlibc-harness  (44 modules, ~34 kLOC)      │
              │ tests/conformance/  (258 completion-contract JSONs +    │
              │                     68 CLI-contract manifests)         │
              │ scripts/  (554 shell scripts: gates, smoke, perf)       │
              │ docs/proofs/  (9 proof notes; obligation mappings)      │
              │ no machine-checked proof artifacts committed yet         │
              └────────────────────────────────────────────────────────┘
```

### Workspace map

| Crate | Purpose | Approx size |
|---|---|---:|
| `frankenlibc-abi` | `extern "C"` boundary, interpose `cdylib`, version script | 50 files, ~121 kLOC |
| `frankenlibc-membrane` | TSM pipeline, healing, runtime math, concurrency primitives, evidence ledger | 109 files, ~75 kLOC |
| `frankenlibc-core` | Safe-Rust semantic kernels (`#![deny(unsafe_code)]` except for explicitly-marked SIMD/arena modules) | 134 files, ~70 kLOC |
| `frankenlibc-harness` | Conformance CLI, fixture capture/verify, reports, evidence tooling | 44 files, ~34 kLOC |
| `frankenlibc-bench` | Criterion benches | 1 module, ~25 kLOC |
| `frankenlibc-fuzz` | 66 `cargo-fuzz` targets | — |
| `frankenlibc-fixture-exec` | Fixture execution helper | — |

The two legacy crates (`frankenlibc` and `frankenlibc_conformance`) remain in the workspace solely for migration compatibility and are not part of the runtime artifact.

---

## Design Philosophy

### 1. ABI first

This project is only interesting if existing binaries can talk to it. The ABI boundary is the contract: symbol names, calling conventions, version tags, `errno` semantics, mode semantics, and process-level behavior all flow from that.

### 2. Safety at the edge

Unsafe C inputs are not trusted. The TSM sits at the libc boundary and classifies pointers, regions, fds, and contexts before anything meaningful happens. Safe-Rust kernels run after classification, never before.

### 3. Native by default

Every exported symbol is explicitly classified as `Implemented`, `RawSyscall`, `WrapsHostLibc`, `GlibcCallThrough`, or `Stub`, and the matrix is machine-checked. As of 2026-05-16, the entire classified surface is native (`Implemented + RawSyscall`); `WrapsHostLibc`, `GlibcCallThrough`, and `Stub` are all zero.

### 4. Clean-room over translation

The codebase is not a line-by-line Rust port of glibc. Behavior is driven by contracts, fixtures, and verification artifacts rather than transliterating legacy C. Reference glibc behavior is consulted from upstream sources (the same way the POSIX spec is consulted), never copied.

### 5. Evidence beats rhetoric

Support claims, mode semantics, fixture coverage, drift checks, smoke runs, and release gates all live in code and machine-generated artifacts. This README summarizes them; the source of truth is always under `tests/conformance/`, `support_matrix.json`, and the harness CLI output.

### 6. Developer transparency

Contributors write normal Rust APIs, tests, and policy tables. The runtime math machinery (conformal risk, sequential e-processes, Galois maps, sheaf consistency, SOS certificates) compiles down to compact deterministic guards in the hot path. The heavy theorem machinery lives in offline synthesis, proof notes, and future proof artifacts, not in runtime call stacks.

---

## Design Invariants

These invariants are maintained as the codebase grows:

| Invariant | Why it exists |
|---|---|
| Safety interpretation only gets more restrictive with new evidence | Avoids optimistic reclassification after suspicious observations |
| Runtime mode is process-wide and immutable after startup | Keeps behavior deterministic and analyzable |
| Hardened repairs are deterministic | Makes behavior replayable and auditable |
| Every exported symbol must be explicitly classified | Prevents silent unknown-support zones |
| Documentation and machine artifacts are expected to agree | Drift is treated as a bug, not a cosmetic issue |
| Bead closure requires a binding evidence artifact | Each closed bead (`bd-*`) maps to a `*_completion_contract.v1.json` JSONL receipt |
| Every harness CLI subcommand has a paired gate test | Enforced by ~50 `cli_contract` manifest meta-gates |
| Clean-room implementation remains the rule | Keeps the project from degenerating into line-by-line translation |

---

## Comparison

| Dimension | glibc | musl | Sanitizers around glibc | FrankenLibC |
|---|---|---|---|---|
| Production Linux compatibility target | Native | Requires relink / different libc target | Native glibc only | Native (interpose-compatible) |
| Memory-safe implementation goal | No | No | No | Yes for native paths |
| Runtime repair mode | No | No | No | Yes — `FRANKENLIBC_MODE=hardened` |
| Per-symbol implementation census | No | No | No | Yes — `support_matrix.json` |
| Host-glibc dependency in classified surface | N/A | No | Yes | **No** |
| Raw syscall fallback paths | Internal | Internal | No | Explicit taxonomy: 414 `RawSyscall` |
| Auditable structured verification artifacts | Limited | Limited | Limited | Core workflow — 258 completion contracts + 68 CLI contracts |
| Machine-checked proof catalog | No | No | No | Not yet; `docs/proofs/` currently holds proof notes and obligation mappings |
| Build-time SOS / barrier audit | No | No | No | Yes — `crates/frankenlibc-membrane/build.rs` |

---

## The Safety Lattice

The 7-state lattice in `crates/frankenlibc-membrane/src/lattice.rs` has a **diamond structure**. The enum is declared with explicit numeric discriminants (`Valid = 6`, …, `Unknown = 0`) so that the join operation can be implemented as a single `max` and the meet as a single `min`:

```text
        Valid (6)
       /         \
Readable (5)  Writable (4)
       \         /
     Quarantined (3)
            │
         Freed (2)
            │
        Invalid (1)
            │
        Unknown (0)
```

`Readable` and `Writable` are incomparable peer states (a region can be one without the other).

- **Join** (new evidence arrives): always moves toward the more restrictive conclusion. Commutative, associative, idempotent.
- **Meet** (what is known to be safe): always moves toward the most permissive valid conclusion. Commutative, associative, idempotent.
- States flow **monotonically downward** on new negative evidence; once a pointer is classified `Freed`, it cannot return to `Valid`.

This monotonicity is what makes the membrane analyzable: the safety reasoning is a well-founded lattice, not a heuristic.

---

## The Galois Connection

The Galois connection in `crates/frankenlibc-membrane/src/galois.rs` formalizes the relationship between C's flat pointer model and the membrane's rich safety model:

- **Alpha (abstraction):** maps a raw C pointer + context into a `PointerAbstraction` carrying safety state, allocation base, remaining bytes, and generation counter
- **Gamma (concretization):** maps the abstract safety state back into a `ConcreteAction` (`Proceed`, `Heal`, `Deny`)
- **Soundness:** `gamma(alpha(c)) ≥ c` for all C operations; the safe interpretation is always at least as permissive as what a correct program needs

The Galois proof notes live under `docs/proofs/galois_monotonic_probability_bounds.md` and are part of the proof-obligation catalog below. They are not yet machine-checked proof artifacts.

---

## Allocator Architecture

`crates/frankenlibc-core/src/malloc/` is a production-grade allocator integrated end-to-end with the membrane.

### Size-Class System

**32 size classes** span from 16 bytes to 32,768 bytes:

| Bin range | Steps | Sizes |
|---|---|---|
| 0–7 | 16-byte | 16, 32, 48, 64, 80, 96, 112, 128 |
| 8–15 | 32-byte | 160, 192, 224, 256, 288, 320, 352, 384 |
| 16–23 | mixed (64/128/256) | 448, 512, 640, 768, 896, 1024, 1280, 1536 |
| 24–31 | widening | 2048, 2560, 3072, 4096, 8192, 16384, 24576, 32768 |

The progression is geometric in spirit but not strictly so; the larger bins jump to power-of-two-friendly steps so the LargeAllocator threshold (`MAX_SMALL_SIZE = 32 KiB`) is reached without wasting slab slots on rarely-used intermediate sizes. The table is declared as `SIZE_TABLE: [usize; NUM_SIZE_CLASSES]` in `crates/frankenlibc-core/src/malloc/size_class.rs`.

Each size class is backed by **64 KB slabs**. Every allocation carries 32 bytes of fingerprint+canary metadata (`FINGERPRINT_SIZE = 24` and `CANARY_SIZE = 8` declared in `crates/frankenlibc-membrane/src/fingerprint.rs`); the allocator rounds this up to `PER_OBJECT_OVERHEAD = 64` per allocation including alignment padding (declared in `crates/frankenlibc-core/src/malloc/size_class.rs`).

### Thread-Local Magazine Cache

Each thread maintains a magazine-based LIFO cache per size class:

- **64 objects per class per thread**, up to **2,048 cached objects** per thread total
- Thread-local alloc/free stays entirely lock-free until a magazine overflows or drains
- Overflow spills back to the sharded central allocator (16 shards, power-of-two for hash distribution)

Steady-state allocation patterns on a single thread never touch shared state.

### Large Allocation Path

Requests > 32 KB bypass the slab system:

- Dedicated `LargeAllocator` backed by `mmap`
- Page-aligned (4096-byte boundaries) with explicit base / mapped-size / user-size tracking
- Base address starts at `0x1_0000_0000` to keep large-allocation pointers visually distinct from small ones

### Generational Arena

`crates/frankenlibc-membrane/src/arena.rs` tracks every live allocation:

| Parameter | Value |
|---|---:|
| Quarantine capacity | **64 MB** (`QUARANTINE_MAX_BYTES`) |
| Shard count | **16** (`NUM_SHARDS`) |
| Per-allocation metadata | raw base, user base, user size, `u64` generation, `SafetyState` |
| UAF detection | Generation counter mismatch on same-slot reuse — probability **1.0** |
| Temporal lifecycle | Live → Freed → Quarantine → Recycle |

Freed allocations enter the quarantine queue before their memory is recycled. The window makes use-after-free detectable even if the slot is reused, because the generation counter will have incremented.

### Fingerprint and Canary

```
[24-byte fingerprint header][user data region][8-byte trailing canary]
```

The fingerprint header is a `#[repr(C)]` struct:

| Field | Size | Content |
|---|---:|---|
| Hash | 8 bytes | SipHash-2-4 of `(base_address, size, generation, secret)` |
| Generation | 8 bytes | `u64` generation counter for temporal safety |
| Allocation size | 8 bytes | User-requested size as `u64` (supports allocations > 4 GiB) |

The trailing canary is derived from the same SipHash computation. Corruption of either signals tampering or buffer overflow. Probability of an undetected collision is bounded by **2⁻⁶⁴** (SipHash collision probability).

### Bloom Filter

The ownership bloom filter in `bloom.rs` provides O(1) "is this pointer ours?" pre-checks:

| Parameter | Value |
|---|---:|
| Expected items | **1,000,000** (`DEFAULT_EXPECTED_ITEMS`) |
| Target false positive rate | **0.1%** (`DEFAULT_FP_RATE = 0.001`) |
| Optimal hash count | `k = (m/n)·ln(2)`, clamped to `[1, 16]` |
| Bit storage | Atomic `u64` array for thread-safe concurrent access |
| False negative rate | **0.0%** — every insertion is remembered |

The bloom filter sits early in the validation pipeline because it can reject most non-owned pointers before touching the arena or fingerprint logic.

---

## Printf Engine

`crates/frankenlibc-core/src/stdio/printf.rs` is a complete safe-Rust format engine, not a wrapper around libc's `vsnprintf`.

**Supported format directives:**

- All POSIX conversion specifiers: `%d %i %u %o %x %X %f %F %e %E %g %G %a %A %c %s %p %n %%`
- All flags: `-` (left-justify), `+` (force sign), space-sign, `#` (alternate form), `0` (zero pad)
- Width and precision: literal values and `*` (from-argument) for both
- All length modifiers: `hh h l ll z t j L`

**Design invariant:** no single format specifier can produce more than `width + precision + 64` bytes. This bounds memory growth from crafted format strings and prevents a class of denial-of-service where unbounded allocation triggers from format input.

Arguments are dispatched through a `FormatArg` enum (`SignedInt(i64)`, `UnsignedInt(u64)`, `Float(f64)`, `Char(u8)`) with string arguments handled out-of-band as byte slices. Special handling:

- `%g`/`%G` switch to `%e`/`%E` when rounding overflows the requested precision
- `%a`/`%A` hex-float exponent arithmetic is hardened against extreme inputs
- Float precision is capped at 65,535 to avoid `core::fmt` panic
- Subnormal and infinity formatting is fixture-verified against glibc

### Stdio Buffering

| Mode | Constant | Behavior |
|---|---|---|
| Fully buffered | `_IOFBF` (0) | Flush on buffer overflow |
| Line buffered | `_IOLBF` (1) | Flush on newline (`\n`) |
| Unbuffered | `_IONBF` (2) | No buffering; immediate write-through |

Default buffer size is **8,192 bytes** (`BUFSIZ`). POSIX's requirement that `setvbuf` cannot be called after I/O has started is enforced: mode is monotonically locked after the first operation. Line-buffered writes use a reverse scan (`rposition`) to find the last newline, flushing through that point and retaining the remainder. The `unget()` path supports pushing a single byte back for `ungetc` semantics with LIFO ordering.

---

## pthread — Futex-Backed Synchronization

`crates/frankenlibc-core/src/pthread/` is a clean-room futex-backed design, not a wrapper around NPTL.

### Mutex

Three types: `NORMAL` (0), `RECURSIVE` (1), `ERRORCHECK` (2). Each mutex is a five-state contract machine:

| State | Meaning |
|---|---|
| `Uninitialized` | Not yet initialized |
| `Unlocked` | Initialized, no owner |
| `LockedBySelf` | Current thread holds the lock |
| `LockedByOther` | Another thread holds the lock |
| `Destroyed` | Post-destroy; all operations fail |

The fast path is a single CAS on the uncontended case. Contended waits use bounded spin before falling through to `FUTEX_WAIT` / `FUTEX_WAKE` with `FUTEX_PRIVATE_FLAG` (`0x80`). Unlock wakes at least one waiter. Error reporting follows POSIX: `EBUSY` on double-init, `EPERM` on unlock-by-other, `EDEADLK` on recursive `ERRORCHECK` lock. The mutex ABI is **native-only** as of Phase 9; no host pthread call-through remains.

### Condition Variables

24-byte internal layout (fits within the 48-byte `pthread_cond_t` on Linux x86_64). Internal state: sequence counter, associated mutex pointer, waiter count.

Two clock modes: `CLOCK_REALTIME` (default) and `CLOCK_MONOTONIC`. Timed waits use `FUTEX_WAIT_BITSET` with `FUTEX_BITSET_MATCH_ANY` (`0xFFFFFFFF`) and `FUTEX_CLOCK_REALTIME` (`256`). Signal increments the sequence counter and wakes one waiter; broadcast wakes all.

### Read-Write Locks

Three preference modes: `PREFER_READER_NP` (0, default), `PREFER_WRITER_NP` (1), `PREFER_WRITER_NONRECURSIVE_NP` (2). Unknown kinds are sanitized to the default.

### Linux 6.7+ Extensions

Native wrappers for `futex_wake`, `futex_wait`, `futex_requeue` (Epic `bd-0ar9l`), plus shared-futex support for cross-process synchronization primitives.

### TLS Lifecycle

Full POSIX TLS key lifecycle (`pthread_key_create`, `pthread_setspecific`, `pthread_getspecific`, destructor invocation order). TLS destructors are guarded against reentrancy and panic in `dlerror`. Cross-thread `pthread_setname_np`/`getname_np` is implemented via `/proc/<pid>/task/<tid>/comm`.

---

## DNS Resolver — Numeric-First, File-Based

`crates/frankenlibc-core/src/resolv/` (2,130 LOC `mod.rs`, plus `dns.rs` 785, `dns_name.rs` 869, `config.rs` 705, `b64.rs` 378, `messages.rs` 179) takes a conservative bootstrap approach: no network I/O during early process initialization.

### Resolution Order

1. Parse the address as an IPv4 or IPv6 literal — return immediately if it is one
2. Search `/etc/hosts` for a matching hostname or alias
3. Search `/etc/services` for port/protocol mapping
4. Return `EAI_NONAME` (-2) if nothing matches

### What's Live

- Multi-address `addrinfo` chains
- `getaddrinfo` / `freeaddrinfo` / `getnameinfo` / `gai_strerror` (with glibc-aligned error text)
- `inet_pton` / `inet_ntop` with metamorphic round-trip harness coverage
- `inet_aton` / `inet_ntoa` / `htons` / `ntohs` family
- DNS compression name parsing with EFAULT-correct bounds
- Native `res_init` resolver bootstrap
- IDNA / Punycode (in `crates/frankenlibc-core/src/idna/`)
- TLS-cached pwd / grp / shadow reentrant slots (`_r` family) hardened against concurrent reseeding
- Base-64 helpers (`b64_ntop` / `b64_pton`) with golden conformance fixtures

Full NSS plugins, recursive resolution, and DNS network I/O are out of scope for the bootstrap resolver; they belong in a future replacement-artifact milestone, not in libc itself during early process init.

---

## iconv — Phase 1

`crates/frankenlibc-core/src/iconv/` (853 LOC `mod.rs`) ships phase-1 codec coverage. Scope is locked in `tests/conformance/iconv_codec_scope_ledger.v1.json`.

| Encoding | Direction | Notes |
|---|---|---|
| UTF-8 | ↔ all | Round-trip fixture-verified |
| ISO-8859-1 | ↔ UTF-8 | Direct byte-to-codepoint mapping |
| UTF-16LE | ↔ UTF-8 | Surrogate-pair handling |
| UTF-32 | ↔ UTF-8 | Native-endian |

`iconv_open` / `iconv` / `iconv_close` are all native. Codec dispatch uses a phase-1 lookup table with deterministic strict-mode fallback policy. Hardened mode adds bounds-clamp repair on overflow. Full `iconvdata` breadth (CP932, EUC, BIG5, ISO-2022-*, KOI8-*, etc.) is a tracked deferred subsystem.

---

## dlfcn — Phase 1

`crates/frankenlibc-core/src/dlfcn/` runs a phase-1 native loader for supported handles and exported symbols:

- `dlopen` / `dlsym` / `dlclose` / `dlerror` / `dladdr` are native
- `dl_iterate_phdr` is membrane-gated
- Hardened mode heals invalid `dlopen` flags to `RTLD_NOW` before local resolution
- Replacement-level L2/L3 forbids any residual host `dlopen`/`dlsym`/`dlclose` fallback; any such call would be a release-blocking gate failure

The loader is intentionally narrow at L1 (interpose); the broad dynamic-linking surface is one of the strategically hard areas tracked in the [Hard Parts](#hard-parts) section.

---

## setjmp / longjmp — Guarded Non-Local Jumps

`setjmp`/`longjmp` are inherently unsafe at the ABI level. The implementation adds guard metadata to make corruption and misuse detectable.

### Jump Buffer Layout

The 128-byte `JmpBuf` (16 × `u64`) reserves the first six slots for membrane metadata:

| Slot | Content |
|---:|---|
| 0 | Magic: `0x4652414E4B454E31` (ASCII `"FRANKEN1"`) |
| 1 | Context ID (unique per capture) |
| 2 | Generation (re-entrance counter) |
| 3 | Owner thread ID |
| 4 | Mode tag (`0x5354524943540001` strict — ASCII "STRICT" + `\x00\x01`; `0x48415244454E0002` hardened — ASCII "HARDEN" + `\x00\x02`) |
| 5 | Guard (rotated XOR checksum of slots 0–4) |

### Validation Before Restore

Before restoring registers, `phase1_longjmp_restore()` checks:

1. Magic and non-zero metadata (catches uninitialized buffers)
2. Mode tag matches current process mode
3. Current thread owns the buffer (catches cross-thread longjmp)
4. Guard checksum validates (catches buffer corruption)

Failure produces a typed error (`UninitializedContext`, `ForeignContext`, `CorruptedContext`, `ModeMismatch`) rather than silent undefined behavior. POSIX's `longjmp(env, 0)` → "as if `setjmp` returned 1" is normalized before restore.

---

## Process Startup

`__libc_start_main` runs before `main()` and is a high-value validation target. The implementation in `crates/frankenlibc-abi/src/startup_abi.rs` (1,166 LOC) uses a multi-checkpoint envelope:

```
1. membrane gate           — runtime_policy::decide(ApiFamily::Process)
2. validate main pointer   — null check, EINVAL + Deny on failure
3. validate argv pointer   — null check, EINVAL + Deny on failure
4. scan argv vector        — count entries up to MAX_STARTUP_SCAN, detect unterminated
5. validate argc bound     — argv_count >= normalized_argc
6. scan envp vector        — same count validation
7. scan auxv vector        — parse key/value pairs, detect truncation
8. classify secure mode    — via classify_secure_mode(&auxv_pairs)
9. call init hook
10. call main(argc, argv, envp)
11. call fini hook
12. call rtld_fini hook
```

If validation fails at any checkpoint, the startup policy decides whether to deny (abort) or fall back to host `__libc_start_main` via `host_resolve::resolve_host_symbol_raw()`. Other host-fallback chains in the codebase have their own version-symbol priority orders: `pthread_abi.rs` walks `GLIBC_2.34 → GLIBC_2.3.2 → GLIBC_2.2.5` for `pthread_create`, and `dlfcn_abi.rs` accepts any of `GLIBC_2.2.5`, `GLIBC_2.17`, or `GLIBC_2.34` from a caller's `dlvsym` request. Program-name globals (`program_invocation_name`, `__progname`) are stored as `AtomicPtr` values extracted from `argv[0]`.

### L1 CRT Proof Rollup

The L1 CRT proof rows (Epic `bd-0qjk0`) cover:

- Constructor invocation order
- Destructor invocation order
- `atexit` invocation order
- `errno` TLS isolation across threads
- Init/fini array order

All five proofs ship as binding artifacts under `tests/conformance/*_completion_contract.v1.json`.

---

## errno

`crates/frankenlibc-core/src/errno/` uses Rust's `thread_local!` with a `Cell<i32>`:

- `__errno_location()` returns a pointer to the current thread's `errno` cell
- `get_errno()` / `set_errno()` for internal Rust code
- 50+ standard error constants (`EPERM`, `ENOENT`, `EINTR`, `EIO`, `ENOMEM`, `EACCES`, `EINVAL`, `EDEADLK`, `ENOSYS`, `EOVERFLOW`, …)
- `strerror_message()` static lookup; unmapped codes return `"Unknown error"`
- `strerror_np` errno tables aligned with glibc text (Phase 16)
- `gai_strerror` text aligned with glibc

`errno` is per-thread state; a global or non-thread-local implementation would break real programs.

---

## Runtime Math Controllers

`crates/frankenlibc-membrane/src/runtime_math/` is ~71 active controller kernels. Decision law per call:

```
mode + context + risk + budget + pareto + design + barrier + consistency
  → Allow | FullValidate | Repair | Deny
```

Representative families already live in the runtime, not just in design docs:

| Family | Modules |
|---|---|
| Risk / sequential testing | `risk.rs`, `eprocess.rs`, `cvar.rs`, `conformal.rs`, `changepoint.rs`, `alpha_investing.rs`, `pac_bayes.rs`, `rademacher_complexity.rs` |
| Control / routing | `bandit.rs`, `control.rs`, `pareto.rs`, `design.rs`, `admm_budget.rs`, `redundancy_tuner.rs`, `loss_minimizer.rs`, `approachability.rs`, `pomdp_repair.rs` |
| Consistency / coherence | `cohomology.rs`, `higher_topos.rs`, `grothendieck_glue.rs`, `hodge_decomposition.rs`, `nerve_complex.rs`, `serre_spectral.rs`, `obstruction_detector.rs`, `derived_tstructure.rs` |
| Drift / anomaly detection | `kernel_mmd.rs`, `wasserstein_drift.rs`, `matrix_concentration.rs`, `transfer_entropy.rs`, `stein_discrepancy.rs`, `azuma_hoeffding.rs`, `bifurcation_detector.rs`, `birkhoff_ergodic.rs`, `borel_cantelli.rs`, `dispersion_index.rs`, `dobrushin_contraction.rs`, `doob_decomposition.rs`, `entropy_rate.rs`, `fano_bound.rs`, `hurst_exponent.rs`, `ito_quadratic_variation.rs`, `lempel_ziv.rs`, `ornstein_uhlenbeck.rs`, `renewal_theory.rs`, `spectral_gap.rs`, `submodular_coverage.rs` |
| Certified safety machinery | `sos_barrier.rs`, `sos_invariant.rs`, `barrier.rs`, `ktheory.rs`, `atiyah_bott.rs`, `localization_chooser.rs`, `microlocal.rs`, `lyapunov_stability.rs`, `clifford.rs`, `coupling.rs`, `equivariant.rs`, `commitment_audit.rs` (and at top-level: `hji_reachability.rs`, `mean_field_game.rs`) |
| Information / provenance | `provenance_info.rs`, `info_geometry.rs`, `malliavin_sensitivity.rs`, `operator_norm.rs` |
| Combinatorial / sampling | `sobol.rs`, `covering_array.rs`, `grobner_normalizer.rs`, `sparse.rs`, `fusion.rs` |
| Policy & evidence | `policy_table.rs` (PCPT proof-carrying policy table loader/verifier), `evidence.rs` (runtime evidence symbol record + ring buffer) |

Standalone (non-`runtime_math/`) controllers in the membrane:

- `risk_engine.rs` — Conformal nonconformity scoring per API family with 256-entry circular calibration buffer
- `check_oracle.rs` — Thompson-sampling contextual bandit that learns optimal validation-stage ordering
- `quarantine_controller.rs` — Primal-dual quarantine-depth optimizer
- `tropical_latency.rs` — Min-plus algebra worst-case latency bounds
- `spectral_monitor.rs` — Marchenko-Pastur / Tracy-Widom phase-transition detector
- `rough_path.rs` — Depth-3 path-signature feature extraction
- `persistence.rs` — Vietoris-Rips persistent homology (0-dimensional)
- `schrodinger_bridge.rs` — Entropy-regularized optimal-transport regime-transition detector
- `large_deviations.rs` — Cramér rate-function rare-event monitor
- `padic_valuation.rs` — Non-Archimedean error calculus
- `symplectic_reduction.rs` — GIT / symplectic reduction for SysV IPC admissibility and deadlock detection
- `hji_reachability.rs` — Hamilton-Jacobi-Isaacs differential-game reachability viability controller (also referenced in the runtime-math safety family above)
- `mean_field_game.rs` — Mean-field-game Nash equilibrium congestion controller (also referenced above)

The runtime decision logic compiles to compact deterministic guards. The heavy math machinery (theorem proofs, SOS certificate synthesis, formal verification) lives in offline `build.rs` artifacts and proof reports, never in the runtime hot path.

### Conformal Risk Engine

`crates/frankenlibc-membrane/src/risk_engine.rs` scores every pointer or region along three axes:

| Axis | Score contribution |
|---|---|
| Alignment deviation | `(6 - alignment) × 33` (range 0–198) |
| Size anomaly | zero → 200; > 1 MB → 250; > 64 KB → 150; small → leading zeros |
| Pointer entropy | unusual bit-count → 200; otherwise 0 |

Final score is capped at 1,000. Below `fast_threshold` skip expensive validation; above `full_threshold` trigger exhaustive checks.

Thresholds are calibrated as quantiles of a 256-entry circular buffer of recent scores. An e-process monitor accumulates evidence on the log scale; when it exceeds 10.0, the engine enters alarm mode and forces full validation until the evidence subsides.

### Thompson-Sampling Check Oracle

`check_oracle.rs` learns the optimal ordering of validation stages at runtime via Thompson sampling:

| Stage | Cost | Can reject early? | Can accept early? |
|---|---:|---|---|
| Null | 1 ns | yes | no |
| TlsCache | 5 ns | no | yes |
| Bloom | 10 ns | yes | no |
| Arena | 30 ns | yes | no |
| Fingerprint | 20 ns | yes | no |
| Canary | 10 ns | yes | no |
| Bounds | 5 ns | no | no |

Each stage maintains a `Beta(α, β)` distribution initialized to `Beta(1, 1)`. After each validation, the stage that caused early termination gets `α` incremented; stages that ran but did not terminate get `β` incremented. Every 128 calls the oracle recomputes the optimal ordering by sampling from each stage's posterior and ranking by expected information gain per nanosecond. The ordering is packed into a single `u64` (4 bits per stage) for cache-friendly storage.

---

## alien_cs — Concurrency Primitives

The membrane is called on every libc entrypoint. Global locks would create unacceptable contention. The `alien_cs` toolkit in `crates/frankenlibc-membrane/src/` provides lock-free and wait-free primitives beyond what `parking_lot` offers:

| Primitive | Source | Purpose | Size |
|---|---|---|---:|
| `SeqLock` | `seqlock.rs` | Optimistic read-side concurrency for frequently-read, rarely-written metadata | ~33 KB |
| `RCU` | `rcu.rs` | Read-copy-update for membership structures read on every call | ~31 KB |
| `EBR` | `ebr.rs` | Epoch-based reclamation for safe deferred freeing of shared metadata | ~29 KB |
| `FlatCombining` | `flat_combining.rs` | Flat combining for contended access aggregation | ~27 KB |
| `htm_fast_path` module (`HtmSite`, `HtmSiteSnapshot`, `HtmTestMode`) | `htm_fast_path.rs` (in ABI crate) | Hardware-transactional-memory acceleration with adaptive abort cooldown | ~19 KB |

Unified metrics across all primitives live in `alien_cs_metrics.rs` (~64 KB) with contention scoring, deadlock-proximity detection, and exit-pressure telemetry. The TLS validation cache is the first line of defense (1,024-entry direct-mapped); these primitives handle the cases where the cache misses and shared state must be consulted.

A dedicated Criterion benchmark suite compares flat-combining vs lock-based access patterns under controlled contention; results feed the runtime math controller for adaptive routing.

---

## New ABI Modules

Recent module additions in `crates/frankenlibc-abi/src/`:

| Module | Size | Purpose |
|---|---:|---|
| `htm_fast_path.rs` | ~19 KB | Hardware-transactional-memory fast path for alien_cs primitives |
| `owned_unwind_abi.rs` | ~3 KB | Owned stack unwinder for the future standalone replacement artifact |
| `nlist_abi.rs` | ~4 KB | ELF symbol-table parsing surface |
| `efun_abi.rs` | ~12 KB | Extern "C" lock/poison recovery helpers |

These join the established families: `string_abi`, `wchar_abi`, `stdio_abi`, `stdlib_abi`, `malloc_abi`, `math_abi`, `pthread_abi`, `socket_abi`, `signal_abi`, `time_abi`, `io_abi`, `io_internal_abi`, `unistd_abi`, `process_abi`, `resolv_abi`, `inet_abi`, `locale_abi`, `iconv_abi`, `dirent_abi`, `dlfcn_abi`, `setjmp_abi`, `fenv_abi`, `termios_abi`, `fortify_abi`, `startup_abi`, `c11threads_abi`, `stdbit_abi`, `mmap_abi`, `rpc_abi`, `err_abi`, `ctype_abi`, `errno_abi`, `pwd_abi`, `grp_abi`, `poll_abi`, `resource_abi`, `search_abi`, `host_resolve.rs`, `glibc_internal_abi`, `isoc_abi`.

---

## Core /etc-DB Parsers

The /porting-to-rust epic lifted glibc's `/etc/` database parsers out of the ABI layer and into native Rust under `crates/frankenlibc-core/src/`:

| Subsystem | Source dir | Covers |
|---|---|---|
| `aliases/` | mail-aliases parser | `/etc/aliases` |
| `ether/` | Ethernet host map | `/etc/ethers` |
| `mntent/` | Mount-table entries | `/etc/fstab`, `/etc/mtab` |
| `netgroup/` | Network groups | `/etc/netgroup` |
| `getopt/` | POSIX option parser | `getopt` / `getopt_long` |
| `idna/` | IDNA / Punycode | RFC 3490 / 3492 |
| `fmtmsg/` | `fmtmsg` / `addseverity` | System V message format |
| `crypt/` | `crypt(3)` interface | password hashing |
| `ftw/` | File-tree walk | `ftw` / `nftw` (including `ftw64`) |
| `search/` | Hash/tree search | `hsearch`, `tsearch`, `lsearch` |
| `stat/` | Stat helpers | `fstat`/`stat`/`statx` decoders |
| `err/` | BSD err helpers | `err`, `errx`, `warn`, `warnx` |
| `proc_maps/` | `/proc/self/maps` parser | VMA enumeration |
| `rpc/` | XDR + RPC types | RFC 4506-compliant XDR (native), legacy-RPC safe defaults |

Each parser ships with a `cargo-fuzz` target validating malformed-input behavior.

---

## The Validate-Delegate Pattern

Every ABI entrypoint in `crates/frankenlibc-abi/src/` follows a five-step pattern:

```text
1. runtime_policy::decide()   ← membrane consults risk, mode, and context
2. check for Deny             ← blocked calls return EPERM / EFAULT immediately
3. validate inputs            ← core-layer checks on arguments
4. delegate                   ← call safe-Rust kernel or raw syscall
5. runtime_policy::observe()  ← record outcome for metrics and healing
```

This is structurally enforced. The ABI module files are minimal glue. The real work happens in the membrane and core layers. The shared `runtime_policy.rs` chokepoint (~87 KB) is the only place that decides whether a call proceeds, repairs, or denies.

---

## Threat Model

FrankenLibC focuses on failures that become visible at the libc boundary.

| In scope | Why it matters |
|---|---|
| Invalid pointers and regions passed into libc calls | libc is a high-frequency choke point for memory-unsafe programs |
| Allocation misuse visible through libc APIs | allocator corruption, double-free, temporal misuse |
| Invalid or ambiguous stdio / `_IO_*` state transitions | stream state is complex and bug-prone |
| Boundary-level integrity failures | fingerprints, canaries, ownership and bounds checks |
| Drift between implementation claims and actual behavior | stale support claims are treated as a real correctness problem |

| Out of scope | Why |
|---|---|
| Arbitrary application logic bugs | the project operates at the libc boundary, not as a whole-program verifier |
| Kernel correctness | raw-syscall paths still rely on kernel behavior |
| Bugs that never cross a libc path | if libc is never involved, the membrane never gets a chance to classify the event |
| setuid/setgid binaries via `LD_PRELOAD` | the loader ignores `LD_PRELOAD` for setuid binaries (kernel security policy) |
| Full standalone replacement today | Full standalone replacement remains planned; Host glibc is still part of the deployment story for the current interpose artifact |

---

## Installation

### From source

```bash
git clone https://github.com/Dicklesworthstone/frankenlibc.git
cd frankenlibc
rustup toolchain install nightly
cargo build -p frankenlibc-abi --release
```

Output:

```
target/release/libfrankenlibc_abi.so
```

### Install into a local prefix

```bash
install -d "$HOME/.local/lib/frankenlibc"
install -m 755 target/release/libfrankenlibc_abi.so "$HOME/.local/lib/frankenlibc/"
LD_PRELOAD="$HOME/.local/lib/frankenlibc/libfrankenlibc_abi.so" /bin/echo hello
```

### System-style install

```bash
sudo install -d /usr/lib/frankenlibc
sudo install -m 755 target/release/libfrankenlibc_abi.so /usr/lib/frankenlibc/
LD_PRELOAD=/usr/lib/frankenlibc/libfrankenlibc_abi.so /bin/echo hello
```

### Requirements

- Linux (x86_64 primary; aarch64 supported and cross-compile-tested)
- Rust nightly with `rustfmt` and `clippy` (pinned via `rust-toolchain.toml`)
- A normal Cargo workspace; no mixed package-manager build system

---

## Quick Start

### 1. Build

```bash
cargo build -p frankenlibc-abi --release
```

### 2. Inspect the classified surface

```bash
cargo run -p frankenlibc-harness --bin harness -- reality-report \
  --support-matrix support_matrix.json \
  --output /tmp/frankenlibc-reality.json
cat /tmp/frankenlibc-reality.json
```

### 3. Run a program under strict mode

```bash
LD_PRELOAD="$PWD/target/release/libfrankenlibc_abi.so" /bin/ls
```

### 4. Run the same program under hardened mode

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

---

## Common Commands

| Workflow | Command | What it does |
|---|---|---|
| Build interpose library | `cargo build -p frankenlibc-abi --release` | Produces `libfrankenlibc_abi.so` |
| Workspace correctness gate | `cargo check --workspace --all-targets` | Compile validation |
| Lint gate | `cargo clippy --workspace --all-targets -- -D warnings` | Lint validation |
| Test gate | `cargo test --workspace` | Unit + integration coverage |
| Repo CI gate | `bash scripts/ci.sh` | Project-standard default gate |
| Support-matrix drift check | `bash scripts/check_support_matrix_maintenance.sh` | Regenerates and validates maintenance report |
| Preload smoke test | `bash scripts/ld_preload_smoke.sh` | Real-program interposition smoke |
| C fixture suite | `bash scripts/check_c_fixture_suite.sh` | Integration-fixture validation |
| Reality report | `cargo run -p frankenlibc-harness --bin harness -- reality-report --support-matrix support_matrix.json --output /tmp/reality.json` | Machine-readable current-state summary |
| Fixture verification | `cargo run -p frankenlibc-harness --bin harness -- verify --fixture tests/conformance/fixtures --report /tmp/conformance.md` | Replays fixture packs |
| Membrane verification | `cargo run -p frankenlibc-harness --bin harness -- verify-membrane --mode both --output /tmp/healing.json` | Runs strict/hardened healing oracle |
| Benchmarking | `cargo bench -p frankenlibc-bench` | Benchmarks library hot paths |
| Fuzzing (target) | `cargo +nightly fuzz run <target>` | Runs a `cargo-fuzz` target |
| aarch64 cross-compile gate | `bash scripts/check_aarch64_crosscompile.sh` | Cross-compile validation |
| L1 dashboard freshness | `bash scripts/check_release_gate.sh` | Top-level claim coherence |

Interpretation note:

- Passing fixture / oracle / CVE-pattern scripts is evidence about the membrane and targeted scenarios.
- That is not automatically end-to-end proof that FrankenLibC would have prevented a specific exploit in an arbitrary upstream program build.
- `LD_PRELOAD`-based deployment does not apply to setuid/setgid binaries — the loader ignores `LD_PRELOAD` there.

---

## Configuration

The primary runtime knob is `FRANKENLIBC_MODE`. The broader environment inventory is machine-generated in `tests/conformance/runtime_env_inventory.v1.json`.

```bash
# Runtime behavior
export FRANKENLIBC_MODE=hardened          # strict | hardened
export FRANKENLIBC_LOG=/tmp/franken.jsonl # optional structured runtime log

# Build / verification convenience
export FRANKENLIBC_LIB="$PWD/target/release/libfrankenlibc_abi.so"
export FRANKENLIBC_EXTENDED_GATES=0
export FRANKENLIBC_E2E_SEED=42
export FRANKENLIBC_E2E_STRESS_ITERS=5

LD_PRELOAD="$FRANKENLIBC_LIB" /bin/echo configured
```

| Variable | Default | Notes |
|---|---|---|
| `FRANKENLIBC_MODE` | `strict` | Process-wide immutable mode selection |
| `FRANKENLIBC_LOG` | unset | Structured runtime log path |
| `FRANKENLIBC_LIB` | unset | Tooling override for the built interpose library |
| `FRANKENLIBC_EXTENDED_GATES` | `0` | Enables heavier CI / perf / snapshot gates |
| `FRANKENLIBC_E2E_SEED` | `42` | Deterministic seed for E2E workflows |
| `FRANKENLIBC_E2E_STRESS_ITERS` | `5` | Stress iteration count for E2E scripts |
| `FRANKENLIBC_BENCH_PIN` | `0` | Benchmark-only CPU pinning control |
| `FRANKENLIBC_CLOSURE_CONTRACT_PATH` | `tests/conformance/closure_contract.v1.json` | Closure-contract gate input override |
| `FRANKENLIBC_CLOSURE_LEVEL` | auto | Closure gate target level override (`L0`..`L3`) |
| `FRANKENLIBC_CLOSURE_LOG` | `/tmp/frankenlibc_closure_contract.log.jsonl` | Closure gate evidence log destination |
| `FRANKENLIBC_HOOKS_LOADED` | `0` | Internal Gentoo hook bootstrap guard |
| `FRANKENLIBC_LOG_DIR` | `/var/log/frankenlibc/portage` | Gentoo hook directory root for generated logs |
| `FRANKENLIBC_LOG_FILE` | unset | Tooling alias path exported into `FRANKENLIBC_LOG` |
| `FRANKENLIBC_PACKAGE` | unset | Internal Gentoo package/atom context annotation |
| `FRANKENLIBC_PACKAGE_BLOCKLIST` | `sys-libs/glibc sys-apps/shadow` | Blocks `LD_PRELOAD` injection for sensitive Gentoo packages |
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
| `FRANKENLIBC_TMPDIR` | unset | Tooling temp-root override; falls back to `TMPDIR` then `/tmp` |

---

## Worked Call Flows

These reflect the intended structure end-to-end.

### `malloc` / `free`

```
C caller
  → ABI entrypoint (malloc_abi)
    → runtime_policy::decide(ApiFamily::Allocator)
      → membrane ownership / temporal checks (arena + bloom + fingerprint)
        → allocator path in core (size-class slab or large mmap)
          → evidence / metrics update
            → pointer or failure returned
```

Allocator surfaces are among the highest-risk libc areas; temporal safety and ownership checks here are load-bearing, not decorative.

### `memcpy` / string family

```
C caller
  → ABI entrypoint (string_abi)
    → pointer + region classification
      → size / bounds policy
        → strict: allow or compat-fail
          OR
        → hardened: clamp / truncate / deny
          → native string kernel (single-pass implementations)
```

Single-pass implementations for `strchr`, `strrchr`, `strspn`, `strcspn`, `strpbrk`, `strsep`, `strstr`, `strcasestr`, `strchrnul`, `strnstr`, `wcsstr`, `wcsrchr` keep the fast path tight; the membrane wraps them with bounded-region tracking for EFAULT correctness on attacker-controlled buffers.

### `fopen` / `fread` / `fwrite`

```
C caller
  → stdio_abi or io_internal_abi
    → stream lookup and buffering policy
      → native stdio path or syscall-facing path
        → seek / flush / stat / internal _IO_* compatibility
          → evidence and support reports keep claims honest
```

`_IO_*` internals (`__overflow`, `__uflow`, `__underflow`, `__woverflow`, `__wuflow`, `__wunderflow`, `_IO_flush_all_linebuffered`, `_IO_getline`) are now natively implemented; no host-libc vtable call-through remains in the classified surface.

---

## Harness CLI Reference

`cargo run -p frankenlibc-harness --bin harness` is the verification frontend. The `Subcommand` enum in `crates/frankenlibc-harness/src/bin/harness.rs` exposes **66 subcommands via `--help`** (verified at the latest commit) spanning fixture capture, replay, reality reports, POSIX conformance, healing-oracle verification, runtime-math proofs, shadow runs, fault injection, evidence compliance, kernel snapshots, tail-stats, and certificate / probe / policy utilities. Representative entries:

| Subcommand | Purpose | Key output |
|---|---|---|
| `capture` | Record host glibc behavior as fixture JSON | Per-family fixture files |
| `verify` | Replay fixtures against FrankenLibC and compare | Markdown conformance report |
| `traceability` | Map fixtures to POSIX/C11 spec sections | Markdown + JSON traceability matrix |
| `reality-report` | Machine-readable snapshot of classified symbol state | `reality_report.v1.json` |
| `posix-conformance-report` | Coverage report across symbols and spec sections | `posix_conformance_report.current.v1.json` |
| `posix-obligation-report` | Obligation traceability across unit + C fixtures | `posix_obligation_matrix.current.v1.json` |
| `errno-edge-report` | Errno and edge-case prioritization | `errno_edge_report.current.v1.json` |
| `verify-membrane` | Strict/hardened healing-oracle verification | JSON healing evidence |
| `evidence-compliance` | Validate a structured-log + artifact-index bundle | JSON compliance report |
| `runtime-math-linkage-proofs` | Runtime math linkage integrity | Proof JSON |
| `runtime-math-determinism-proofs` | Snapshot determinism for runtime-math controllers | Proof JSON |
| `runtime-math-hji-viability-proofs` | HJI reachability viability kernel proofs | Proof JSON |
| `runtime-math-cpomdp-feasibility-proofs` | Constrained POMDP repair-policy feasibility | Proof JSON |
| `shadow-run` | Shadow-mode comparison run (FrankenLibC vs host glibc) | Divergence JSONL |
| `fault-inject` | Targeted fault-injection campaign | Per-case evidence |
| `tail-stats` | Tail-latency distribution analysis from evidence ring | JSON statistics |

Every subcommand has a paired `*_cli_contract.v1.json` manifest under `tests/conformance/` (68 such manifests currently) enforcing schema, naming, flag shape, JSONL output contract, and policy keys. The contracts themselves are validated by ~50 meta-gates (see [CLI-Contract Manifest Meta-Gates](#cli-contract-manifest-meta-gates) below).

### Healing Oracle Test Matrix

`verify-membrane` exercises seven categories of unsafe behavior in both strict and hardened modes:

| Condition | Trigger | Expected healing action |
|---|---|---|
| `NullPointer` | Null dereference through libc | `ReturnSafeDefault` |
| `UseAfterFree` | Read/write after free | `ReturnSafeDefault` |
| `DoubleFree` | Free the same pointer twice | `IgnoreDoubleFree` |
| `BufferOverflow` | Write past allocation boundary | `TruncateWithNull` (e.g. requested=64, truncated=63) |
| `ForeignFree` | Free a pointer not from our allocator | `IgnoreForeignFree` |
| `BoundsExceeded` | Size argument exceeds allocation | `ClampSize` (e.g. requested=4096, clamped=1024) |
| `ReallocFreed` | Realloc a freed pointer | `ReallocAsMalloc` (e.g. size=256) |

14 canonical test cases cover three families: `string` (`strlen`, `strcmp`, `strcpy`, `strncpy`, `memmove`, `memcpy`), `malloc` (`free`, `cfree`, `realloc`), and `stdlib` (`reallocarray`). Each case pairs a function with the unsafe condition that exercises it (e.g., `null-pointer-strlen`, `use-after-free-free`, `bounds-exceeded-memcpy`). Results are emitted as JSON with a per-case breakdown of expected vs observed healing actions.

---

## Conformance Framework

The project is organized around verification artifacts. Every claim about behavior, ownership, or readiness has a corresponding machine-checkable gate.

### Completion-Contract Evidence Framework

`tests/conformance/` contains **258 named `*_completion_contract.v1.json` artifacts** (plus 68 `*_cli_contract.v1.json` manifests for the harness CLI). Each closed bead (`bd-*`) must point at a binding evidence artifact before its closure is accepted by the audit gates.

Categories include:

- Architecture: `aarch64_arch_regression_gate`, `aarch64_conformance_perf_matrix`, `aarch64_raw_syscall_tls`
- Allocator: `allocator_e2e`, `allocator_membrane_invariant`, `allocator_membrane_deterministic_sequence`, `allocator_subsystem`
- pthread: `pthread_bootstrap`, `pthread_family`, `pthread_lifecycle_unit`, `pthread_mutex_futex_core`, `pthread_mutex_semantics`, `pthread_mutex_state_invariants`, `pthread_mutex_callthrough_eradication`
- Resolver / NSS: `resolver_nss_family`, `resolver_nss_hardening`, `resolver_numeric_files`, `ns_libresolv_exports`
- iconv / locale: `iconv_locale_family`, `locale_iconv`, `iconv_codec_scope_ledger`
- printf / stdio: `printf_float_precision`, `printf_fuzz_family`, `printf_star_width_precision`, `stdio_libio_*`
- CRT / startup: `l1_crt_startup_tls`, `crt_tls_atexit_direct_link_proof`
- Runtime math: 15+ contracts covering risk, control, anomaly, certified safety
- Replacement levels: `replacement_levels` (the canonical taxonomy), `standalone_replacement_artifact` (L2/L3 packaging contract); per-level dashboard freshness scenarios live in `claim_gate_positive_negative_matrix.v1.json`
- TSM and evidence: `tsm_*`, `evidence_ledger_*`
- CLI contracts: `*_cli_contract.v1.json` for every harness subcommand and gate

### CLI-Contract Manifest Meta-Gates

Every `*_cli_contract.v1.json` manifest is subject to ~50 machine-checkable meta-gates pinned by Rust tests. Representative gates (Phase 16):

- Manifest is well-formed JSON with no BOM or trailing garbage
- `manifest_id` length in `[10, 80]`; `subcommand_name == manifest_id` minus the `-cli-contract` suffix
- `required_flags` and `optional_flags` are arrays, disjoint, deduplicated, and flag-only form (no `=` defaults)
- `optional_flags` ≤ 25 (sanity ceiling)
- `policy` keys are snake_case with at least one boolean rule
- `rejected_evidence_kinds` entries are snake_case array
- `jsonl_output_contract.required_fields` is a snake_case array with well-formed `record_count`
- `io_pattern` is snake_case descriptive (≥ 10 chars)
- `underlying_lib_functions` entries are Rust paths, unique, and singular form matches `plural[0]`
- `bead` field is a canonical `beads_rust` id; timestamps are valid ISO-8601 in plausible range
- Every manifest has a matching paired gate test; every paired gate test has a matching manifest
- Paired gate tests reference `env!(CARGO_MANIFEST_DIR)`
- Raw `panic!` is banned in CLI gates; harnesses return `TestResult` instead

The combined effect: a harness subcommand cannot land without its contract; a contract cannot land without its paired gate; a gate cannot panic; and every claim points at fresh evidence.

### Curated LD_PRELOAD Smoke Battery — Workloads and Failure Signatures

| Category | Programs |
|---|---|
| Coreutils | `/bin/ls -la /tmp`, `/bin/cat /etc/hosts`, `/bin/echo`, `/usr/bin/env`, `/bin/sort`, `/usr/bin/wc`, `/bin/head` |
| Integration | `tests/integration/link_test.c` (compiled and run) |
| Dynamic runtimes | `python3 -c 'print(1)'`, `busybox uname -a` |
| Optional services | `sqlite3 :memory:`, `redis-cli --version`, `nginx -v` |
| Stress | Repeated iterations (configurable, default 5) |

Failure-signature classification:

| Signature | Meaning |
|---|---|
| `startup_timeout` | Process did not exit within `TIMEOUT_SECONDS` (rc 124/125) |
| `startup_segv` | Segmentation fault (signal 11) |
| `startup_abort` | Abort (signal 6) |
| `startup_symbol_lookup_error` | Missing or incompatible symbol |
| `startup_loader_missing_library` | Dynamic library not found |
| `startup_glibc_version_mismatch` | Version symbol mismatch |
| `startup_strict_parity_mismatch` | Baseline and preload outputs differ |
| `startup_perf_regression` | Latency ratio exceeds budget (default 2×) |
| `startup_valgrind_error` | Valgrind detected memory errors |

Each case collects baseline + preload stdout/stderr, a metadata bundle (mode, exit code, failure signature, `/proc/self/maps`), and latency measurements in nanoseconds with a computed latency ratio.

### Fixture Corpus

`tests/conformance/fixtures/` contains 40+ JSON fixture families, each capturing input/output pairs from host glibc. Representative families:

- Allocator: `allocator`, `stdlib_conversion`, `stdlib_numeric`, `stdlib_sort`
- String: `string_ops`, `string_memory_full`, `strlen_strict`, `string_strtok`, `memcpy_strict`
- Wide string: `wide_string`, `wide_memory`, `wide_string_ops`
- Character/errno: `ctype_ops`, `errno_ops`
- Math: `math_ops`
- Threading: `pthread_thread`, `pthread_mutex`, `pthread_tls_keys`
- I/O: `socket_ops`, `poll_ops`, `inet_ops`, `resolver`, `dirent_ops`
- Process: `process_ops`, `spawn_exec_ops`, `signal_ops`, `setjmp_ops`
- System: `time_ops`, `termios_ops`, `locale_ops`, `resource_ops`, `virtual_memory_ops`, `sysv_ipc_ops`
- Loader: `dlfcn_ops`, `elf_loader`, `backtrace_ops`
- Membrane-specific: `membrane_mode_split`, `pressure_sensing`

These fixtures are the ground truth for differential verification: FrankenLibC's output for the same inputs must match glibc's behavior where conformance is claimed.

### C Integration Fixtures

`tests/integration/` contains 17 C test programs compiled against the produced `libfrankenlibc_abi.so`:

| Fixture | What it exercises |
|---|---|
| `fixture_malloc.c` / `fixture_malloc_stress.c` | Allocation correctness and concurrent stress |
| `fixture_string.c` | String function behavior parity |
| `fixture_stdio.c` / `fixture_stdio_printf.c` / `fixture_stdio_globals.c` | Stream I/O and printf formatting |
| `fixture_socket.c` | Network socket operations |
| `fixture_pthread.c` / `fixture_pthread_mutex_adversarial.c` | Threading and adversarial mutex contention |
| `fixture_setjmp_nested.c` / `fixture_setjmp_edges.c` | Non-local jump edge cases |
| `fixture_ctype.c` | Character classification |
| `fixture_math.c` | Math function accuracy |
| `fixture_nss.c` | Name service switch |
| `fixture_io.c` | File descriptor operations |
| `fixture_startup.c` | Program initialization sequence |
| `link_test.c` | Symbol linkage validation |

### Fuzzing

`crates/frankenlibc-fuzz/fuzz_targets/` contains **66 `cargo-fuzz` targets**:

- Parser-heavy: `fuzz_printf`, `fuzz_printf_adversarial`, `fuzz_scanf`, `fuzz_regex`, `fuzz_iconv`, `fuzz_dirent`, `fuzz_resolv`, `fuzz_resolver`, `fuzz_pwd_grp`, `fuzz_fnmatch`, `fuzz_pattern_match`, `fuzz_strftime`, `fuzz_strptime`, `fuzz_wordexp`, `fuzz_getsubopt`, `fuzz_asprintf`, `fuzz_vis`, `fuzz_b64`, `fuzz_punycode`, `fuzz_argz`
- /etc-DB parsers: `fuzz_etc_db`, `fuzz_mntent`, `fuzz_locale`, `fuzz_loc_codec`
- Syscall surfaces: `fuzz_io_uring`, `fuzz_mount`, `fuzz_open_syscalls`, `fuzz_pathname`, `fuzz_read_write`, `fuzz_splice`, `fuzz_statx`, `fuzz_ioctl`, `fuzz_fcntl`, `fuzz_sched`, `fuzz_security_syscalls`, `fuzz_ptrace`, `fuzz_pidfd_timer`, `fuzz_keyring`, `fuzz_vector_io`, `fuzz_sysv_ipc`
- ABI-class: `fuzz_socket`, `fuzz_inet`, `fuzz_signal`, `fuzz_fortify`, `fuzz_setjmp`, `fuzz_dlfcn`, `fuzz_elf_loader`, `fuzz_wchar`, `fuzz_mmap`
- Concurrency: `fuzz_pthread_cond`, `fuzz_pthread_mutex`, `fuzz_pthread_rwlock`, `fuzz_pthread_keys`, `fuzz_pthread_sync_misc`, `fuzz_c11threads`
- Data: `fuzz_string`, `fuzz_malloc`, `fuzz_stdlib`, `fuzz_ctype`, `fuzz_time`, `fuzz_math`, `fuzz_xdr`, `fuzz_env`, `fuzz_errno_precedence`
- Internal correctness: `fuzz_membrane`, `fuzz_runtime_math`

A nightly fuzz campaign runner and CI gate live under `scripts/`. Each target ships with directed seed corpora extracted from real bug fixes in earlier phases.

### Metamorphic Test Harnesses

Beyond direct fixture comparison, the project ships metamorphic relations harnesses:

- `inet_pton` / `inet_ntop` round-trip invariance
- `strto*` / `snprintf` round-trip invariance
- Base-64 codec invertibility with golden checks

These catch failures that escape direct fixture comparison because the metamorphic relation must hold even when the canonical expected output is hard to enumerate.

---

## Formal Properties

| Property | Mechanism | Confidence |
|---|---|---|
| Monotonic safety degradation | Lattice join is commutative, associative, idempotent | Proven by construction |
| Galois soundness | `γ(α(c)) ≥ c` for all C operations | Proven by construction |
| Allocation integrity | `P(undetected corruption) ≤ 2⁻⁶⁴` | Bounded by SipHash collision probability |
| Use-after-free detection | Generation counter mismatch on same-slot reuse | Probability 1.0 |
| Buffer overflow detection | Trailing canary corruption | `P(miss) ≤ 2⁻⁶⁴` |
| Bloom filter soundness | Zero false negatives | By construction (all insertions are remembered) |
| Healing completeness | Every libc family has defined healing for every class of invalid input | Enforced by policy-table coverage |
| SOS certificate validity | Fragmentation, thread safety, size-class invariants | Verified at build time via Cholesky decomposition |
| Memory model barrier coverage | Minimum atomic site counts per source file | Enforced at build time by `build.rs` audit |

### Proof Notes and Obligations Catalog

`docs/proofs/` contains 9 proof notes spanning the algebraic, probabilistic, and operational properties. They are design/proof narratives and obligation mappings, not completed machine-checked proof artifacts.

| Proof note | Property |
|---|---|
| `galois_monotonic_probability_bounds.md` | Galois connection soundness + probability bounds on undetected unsafety |
| `strict_mode_refinement.md` | Strict mode preserves compatibility-relevant semantics of host glibc |
| `hardened_mode_safety.md` | Hardened mode never increases undefined behavior; repairs are deterministic |
| `deterministic_replay.md` | Identical inputs and runtime evidence produce identical outputs across replays |
| `repair_posix_mapping.md` | Every healing action is a refinement of the underlying POSIX contract |
| `sos_barrier_soundness.md` | SOS barrier certificates synthesized at build time satisfy admissibility constraints |
| `hji_viability_kernel.md` | HJI reachability controller stays inside the safe viability kernel |
| `sheaf_global_consistency.md` | Cross-shard membrane metadata is sheaf-consistent under overlap |
| `cpomdp_feasibility.md` | Constrained POMDP repair policy is feasible under the runtime budget |

### Build-Time SOS Certificates

`crates/frankenlibc-membrane/build.rs` (~1,030 lines) synthesizes and verifies three polynomial invariant certificates:

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

### Build-Time Memory-Model Barrier Audit

The same `build.rs` scans source files for atomic operations and verifies minimum barrier coverage:

| Source file | Expected atomic sites | Domain |
|---|---:|---|
| `ptr_validator.rs` | 4 | TSM |
| `arena.rs` | 2 | TSM |
| `tls_cache.rs` | 2 | TSM |
| `config.rs` | 15 | TSM |
| `metrics.rs` | 2 | TSM |
| `pthread/cond.rs` | 29 | futex |
| **Total minimum** | **20+** | |

If any source file has fewer atomic sites than expected, the build fails. This prevents silent removal of synchronization barriers during refactoring.

### ABI Build Script

`crates/frankenlibc-abi/build.rs` links the GNU ld version script (`libc.map`) into non-debug, non-fuzz `cdylib` builds when present. Debug and fuzz builds skip version-script linking to avoid conflicts with rustc's generated export list. Native packaging checks that need the versioned `libc.so` link the `staticlib` with `cc` using `libc.map` (see `scripts/check_setjmp_native.sh`).

---

## Performance Model

libc is on the hot path of nearly every process. The project stages work so cheap, high-signal checks happen first and expensive reasoning is reserved for cases that deserve it.

Validation ordering rationale:

1. Trivial null / immediate-fail checks
2. Thread-local cache before global metadata
3. Bloom-style plausibility before expensive ownership lookup
4. Arena and integrity validation once plausibility is established
5. Bounds and policy checks once the object is believed to be real

The ordering preserves three properties:

- Fast paths stay fast
- Suspicious paths get deeper scrutiny
- Hardened mode costs more only when the extra scrutiny is justified

### Targets

| Operation | Target |
|---|---|
| Strict mode membrane overhead | < 20 ns/call |
| Hardened mode membrane overhead | < 200 ns/call |
| Null check (fast exit) | ~1 ns |
| TLS cache lookup | ~5 ns |
| Bloom filter check | ~10 ns |
| Arena lookup | ~30 ns |
| Fingerprint check | ~20 ns |
| Canary check | ~10 ns |
| Bounds check | ~5 ns |

### Perf Gates

`scripts/check_perf_baseline.sh` and `scripts/check_perf_regression_gate.sh` enforce a budget against rolling baselines. `FRANKENLIBC_PERF_MAX_REGRESSION_PCT` (default 15%) sets the allowed regression headroom. Overloaded hosts are detected and skipped via `FRANKENLIBC_PERF_MAX_LOAD_FACTOR` (default 0.85) to keep perf evidence trustworthy.

---

## Replacement Strategy

FrankenLibC is deliberately staged.

| Stage | Meaning |
|---|---|
| **L0 — Interpose only** | `LD_PRELOAD` deployment; host glibc still in the process |
| **L1 — Hardened interpose** | Current declared level; hardened mode + maintenance gates + L1 dashboard freshness |
| **L2 — Standalone-ready** | All replacement-blocking gates green; ready to ship a non-preload artifact |
| **L3 — Standalone** | Fully standalone `libfrankenlibc_replace.so`; no host-glibc deployment dependency |

The symbol taxonomy is what makes this staged model legible:

- `Implemented` + `RawSyscall` apply to **both** artifacts (interpose and replace)
- `WrapsHostLibc` + `GlibcCallThrough` + `Stub` would apply to interpose only

As of 2026-05-16 the classified surface is 100% native; no `WrapsHostLibc`, `GlibcCallThrough`, or `Stub` rows remain. The path to L2 and L3 is now about closing semantic-overlay gaps (no-op / fallback / bootstrap contracts that are tracked outside the support-taxonomy), packaging contracts, and the broader hard-parts work.

### Today

- Interpose shared library exists and is usable on the curated workload battery
- Host glibc is still part of the deployment story because the shipping artifact is interpose-first
- Support taxonomy is machine-checked and fully native
- Hardened mode and verification flows are live

### Next

- Keep the classified surface clean while closing broader preload, hardened-mode, and artifact-packaging gaps
- Tighten replacement gates so "replace-ready" is mechanically enforced
- Maintain L1 dashboard freshness as new evidence lands

### End state

- Standalone replacement artifact exists as a real product
- The project makes stronger deployment claims without hand-waving over host dependencies

---

## Subsystem Status Dashboard

Qualitative summary; numeric truth lives in `support_matrix.json` and the maintenance reports.

| Subsystem | Current state | What's there today | Main gap |
|---|---|---|---|
| `string` | Strong native ownership | Full classified surface, hardened single-pass kernels, tracked-region bound sweep, internal-alias differentials | Continued metamorphic and fuzz coverage expansion |
| `stdio` | Native end-to-end | Full printf engine, scanf, FILE I/O, `_IO_*` internals, memstreams, vis() family | Edge-case stress closure |
| `malloc` | Production-grade | Size-class slabs, thread magazines, large mmap, generational arena, fingerprint + canary, EBR quarantine | Long-tail concurrency stress |
| `pthread` | Native, futex-backed | Mutex (3 types), condvar (2 clocks), rwlock (3 modes), TLS keys, cancellation, named threads, futex2 | Edge-case scheduling and stress closure |
| `resolver` | Native bootstrap path | Numeric, `/etc/hosts`, `/etc/services`, multi-address addrinfo, IDNA, b64, metamorphic round-trip | Full NSS / DNS network backends (out of bootstrap scope) |
| `locale` | Native bootstrap | C/POSIX, `setlocale`, `localeconv`, `nl_langinfo`, ctype/wchar locale variants, catgets | Full localedata breadth |
| `iconv` | Phase 1 | UTF-8 ↔ ISO-8859-1 / UTF-16LE / UTF-32; deterministic strict + hardened fixtures; locked scope ledger | Full `iconvdata` breadth |
| `loader / dlfcn` | Phase-1 native | `dlopen`, `dlsym`, `dlclose`, `dlerror`, `dladdr`, `dl_iterate_phdr` | Broader dynamic-loader story for replacement |
| `startup` | Phase-0 native | `__libc_start_main`, init/fini array order proofs, errno TLS isolation proof, atexit order proof | Full `csu`/TLS init-order hardening for replacement |
| `runtime_math` | Extensive live code | ~71 controllers, build-time SOS certificates, snapshot goldens, linkage checks | Continued integration and proof-quality closure |

### Hard-Parts Truth Table

- `startup`: `IMPLEMENTED_PARTIAL` — phase-0 startup fixture path (`__libc_start_main`, `__frankenlibc_startup_phase0`, snapshot invariants) is implemented. Deferred: full `csu`/TLS init-order hardening + secure-mode closure for L2/L3.
- `threading`: `IN_PROGRESS` — runtime-math threading routing and selected pthread semantics are live, including lifecycle and rwlock native routing, mutex/cond futex core, callthrough eradication. Deferred: long-tail TLS stress beads.
- `resolver`: `IMPLEMENTED_PARTIAL` — bootstrap numeric resolver ABI (`getaddrinfo`, `freeaddrinfo`, `getnameinfo`, `gai_strerror`) plus multi-address chains. Deferred: full retry/cache/poisoning hardening.
- `nss`: `IMPLEMENTED_PARTIAL` — passwd/group APIs exported as `Implemented` via `pwd_abi`/`grp_abi` with TLS-cached reentrant slots. Deferred: hosts/backend breadth + NSS concurrency/cache-coherence closure.
- `locale`: `IMPLEMENTED_PARTIAL` — bootstrap `setlocale`/`localeconv` C/POSIX path. Deferred: catalog, collation, transliteration parity expansion.
- `iconv`: `IMPLEMENTED_PARTIAL` — phase-1 encodings with deterministic strict + hardened fixtures; scope locked in `tests/conformance/iconv_codec_scope_ledger.v1.json`. Deferred: full `iconvdata` breadth and deterministic table-generation closure.

---

## Why This Is Useful In Practice

| Scenario | Why FrankenLibC helps |
|---|---|
| Legacy C/C++ binaries | `LD_PRELOAD` lets you experiment without relinking the program |
| Security testing | Hardened mode exposes and constrains unsafe behavior that would otherwise corrupt memory silently |
| Compatibility research | The support matrix and reality reports make symbol ownership explicit |
| Differential verification | The harness compares FrankenLibC behavior against host glibc fixture packs |
| Replacement-library R&D | The taxonomy and gating model support gradual movement from interpose to standalone |
| Observability and evidence | Structured reports and maintenance artifacts make the project auditable, not anecdotal |
| Memory-safety experiments at the libc edge | The TSM is a real, instrumentable membrane — not a wrapper around something else |

FrankenLibC treats libc replacement as a staged engineering problem with explicit measurements, evidence, and safety goals.

---

## Hard Parts

The remaining hard areas are difficult for real systems reasons, not because they were forgotten:

| Hard part | Why it is hard |
|---|---|
| Full dynamic loader (`dlfcn` L2/L3) | Dynamic linking and symbol resolution are globally coupled to process behavior |
| Long-tail pthread closure | Concurrency bugs are subtle and ABI compatibility matters at the scheduling and lifecycle level |
| Full locale breadth | Locale behavior is wide, stateful, and historically intricate |
| Full iconv breadth | Codec coverage is a large-scale data and semantics problem |
| Full startup/bootstrap closure for replacement | Initialization order is unforgiving and tightly coupled to platform assumptions |
| Full standalone replace artifact | Removing the last host-glibc deployment dependencies is a product milestone, not just a symbol-count milestone |
| Multi-arch beyond x86_64 + aarch64 | Each architecture is its own obligation matrix and dispatch surface |

---

## Limitations

- The current shipping artifact is the **interpose** shared library, not a fully standalone libc replacement.
- The deployment model is `LD_PRELOAD`; setuid/setgid binaries are out of scope because the kernel loader ignores `LD_PRELOAD` for them.
- The curated preload smoke battery is green in both strict and hardened modes (58/0/6); broader production hardening, non-curated workload stability, and L2/L3 release-claim closure are still active work.
- Hardened mode is fixture-and-oracle-verified for the defined healing taxonomy; that is not a blanket production-readiness claim for arbitrary workloads.
- Performance: strict-mode overhead is budgeted at < 20 ns/call and hardened-mode at < 200 ns/call; perf gates measure rather than assume, and regressions surface in `scripts/check_perf_regression_gate.sh`.
- The README summarizes current reality; canonical truth lives in generated reports and gates.
- Linux x86_64 is the primary target; aarch64 is supported via cross-compile gates; other architectures are out of scope for v0.1.

---

## Troubleshooting

### `LD_PRELOAD` does nothing

Check that you built the ABI crate in release mode and are pointing at the actual `.so`:

```bash
test -f target/release/libfrankenlibc_abi.so
file target/release/libfrankenlibc_abi.so
```

### `cargo` fails because the toolchain is wrong

This repo uses Rust nightly:

```bash
rustup toolchain install nightly
rustup override set nightly
```

### A README claim and a machine artifact disagree

Trust the machine artifact. The most useful canonical files are:

- `support_matrix.json`
- `tests/conformance/support_matrix_maintenance_report.v1.json`
- `tests/conformance/runtime_env_inventory.v1.json`
- `tests/conformance/reality_report.v1.json`

### Hardened mode does not appear to log anything

Set a log path explicitly:

```bash
FRANKENLIBC_LOG=/tmp/franken.jsonl \
FRANKENLIBC_MODE=hardened \
LD_PRELOAD="$PWD/target/release/libfrankenlibc_abi.so" /bin/echo test
cat /tmp/franken.jsonl
```

### A drift gate fails after touching symbol classifications

You probably updated code or `support_matrix.json` without refreshing a canonical artifact:

```bash
bash scripts/check_support_matrix_maintenance.sh
```

### A `cli_contract` meta-gate fails after editing a harness subcommand

Re-run the manifest meta-gates and inspect the failing assertion:

```bash
cargo test -p frankenlibc-harness --test cli_contract_manifest_paired_gate_file_test
cargo test -p frankenlibc-harness --test cli_contract_manifest_jsonl_required_fields_unique_test
```

Every harness CLI subcommand must have a paired `*_cli_contract.v1.json` manifest and matching gate test; both are subject to ~50 meta-gates.

### Build-script SOS / barrier audit fails

The membrane crate's `build.rs` will fail loudly if Cholesky verification trips or a source file falls below its atomic-site floor. Read the build output; the failing certificate or file is named.

---

## FAQ

### Is FrankenLibC a drop-in replacement for glibc today?

The practical artifact today is `libfrankenlibc_abi.so` used via `LD_PRELOAD`, with 100% native coverage in the classified surface and green strict + hardened smoke runs across the curated battery. A fully standalone replacement artifact (`libfrankenlibc_replace.so`) is gated by L2/L3 contracts and is not yet declared ready. The interpose artifact is real and works on real programs today.

### Does it implement a lot of symbols natively?

Yes. The current classified surface is **4,119 symbols, all native**: 3,705 `Implemented` and 414 `RawSyscall`. No `GlibcCallThrough`, `WrapsHostLibc`, or `Stub` rows remain.

### Do the CVE validation scripts prove FrankenLibC would have prevented famous exploits?

They provide targeted evidence for specific bug patterns and synthetic scenarios. That is useful, but weaker than an end-to-end proof against an arbitrary vulnerable upstream build. `LD_PRELOAD` claims do not apply to setuid/setgid binaries, so those cases need a different deployment story.

### What does hardened mode actually do?

It lets the membrane repair or deny unsafe patterns deterministically (clamp size, truncate with NUL, ignore double-free, ignore foreign-free, realloc-as-malloc, return safe default, upgrade to safe variant) while recording structured evidence about what happened.

### Is this a clean-room reimplementation?

Yes. The architecture and implementation are spec-first and verification-driven, not line-by-line glibc translation. Reference glibc source is consulted for behavior, never copied.

### Is the runtime math real code or just naming theater?

Real code. `crates/frankenlibc-membrane/src/runtime_math/` is ~71 controller modules with live execution paths, snapshot goldens, linkage checks, and decision recordings. The heavy theorem machinery (SOS synthesis, Cholesky verification, proof notes, and future proof artifacts) runs outside the hot path.

### Should I trust the README or the generated reports?

The generated reports. This README is orientation; the source of truth is `support_matrix.json`, `tests/conformance/*.json`, and harness CLI output.

### Why not just use musl?

musl solves a different problem. FrankenLibC is preserving a glibc-shaped compatibility story while adding safety, classification, and staged replacement machinery.

### Why not just use ASan or UBSan?

Sanitizers are development instrumentation; they catch bugs during testing and require recompilation. FrankenLibC is aimed at boundary-level safety and observability for deployed binaries and replacement-libc research, without requiring source access or relink.

### Why not just harden malloc and stop there?

Because libc risk is broader than allocation. String APIs, stdio, resolver paths, locale/iconv, threading, startup, and loader behavior all matter, and they all share the same membrane substrate here.

### Why are there so many JSON and JSONL artifacts?

Because the project reconciles implementation claims, evidence, and release readiness mechanically rather than socially. The 258 completion contracts (and 68 CLI contracts) under `tests/conformance/` are the bookkeeping infrastructure that makes "claim without supporting evidence" not a valid state.

### What does "100% native coverage" actually mean?

It means every symbol in `support_matrix.json` is either `Implemented` (native Rust) or `RawSyscall` (direct Linux syscall), and zero symbols delegate to host glibc through `WrapsHostLibc`, `GlibcCallThrough`, or `Stub`. The shipping artifact is still deployed via `LD_PRELOAD` (interpose), so host glibc is still loaded in the process, but the classified ABI surface no longer routes through it.

### What's the difference between "interpose" and "replace"?

The **interpose artifact** (`libfrankenlibc_abi.so`) is loaded with `LD_PRELOAD` alongside host glibc; the kernel still loads host glibc and FrankenLibC intercepts the symbols that programs call. The **replace artifact** (`libfrankenlibc_replace.so`, planned) would be the only libc in the process, with no host glibc loaded at all. Replace is gated by L2/L3 promotion contracts.

### How is `errno` thread-local?

Via `thread_local! { static ERRNO: Cell<i32> = ... }`. `__errno_location()` returns the pointer to the current thread's cell. The L1 CRT proof rows include explicit `errno_tls_isolation` evidence.

### What's the rule on `unsafe`?

| Crate | Policy |
|---|---|
| `frankenlibc-core` | `#![deny(unsafe_code)]` (SIMD/arena modules `#[allow(unsafe_code)]` with `// SAFETY:` per block) |
| `frankenlibc-membrane` | `#![deny(unsafe_code)]` (arena/fingerprint modules `#[allow(unsafe_code)]` with `// SAFETY:` per block) |
| `frankenlibc-abi` | `#![allow(unsafe_code)]` (ABI boundary is inherently unsafe; every function body is minimal: validate via membrane, delegate to core) |
| `frankenlibc-harness` | `#![forbid(unsafe_code)]` |
| `frankenlibc-bench` | `#![allow(unsafe_code)]` (benchmarks call `extern "C"`) |
| `frankenlibc-fuzz` | `#![allow(unsafe_code)]` (fuzz harnesses call `extern "C"`) |

Unsafe is permitted only in explicitly documented boundary modules. Memory safety is achieved through the TSM, not by pretending FFI unsafety doesn't exist.

---

## How LD_PRELOAD Interposition Works

`LD_PRELOAD` tells the Linux dynamic linker to load a shared library before any others. When a program calls `malloc`, `strlen`, or any libc function, the linker resolves the symbol to FrankenLibC's implementation first. The *classified* ABI surface is 100% native, so caller-visible symbols never delegate to host glibc. Certain *internal fallback paths* (e.g., the `__libc_start_main` host fallback chain in `startup_abi.rs`, or `host_resolve.rs` for `dlvsym_next` lookups) still call back into host glibc when explicit version-symbol resolution is needed; that's part of why the shipping artifact is interpose-first, not standalone replace.

FrankenLibC is usable for many experiments without relinking: same binary, same kernel, same filesystem, different libc implementation behind the ABI boundary.

Limitations of interposition:

- Functions called internally within glibc (where the linker has already bound the symbol) are not intercepted
- Some startup-critical paths run before `LD_PRELOAD` takes effect
- `LD_PRELOAD` is ignored for setuid/setgid binaries (kernel security policy)
- The interpose library must export symbols with the correct version tags

The version script (`crates/frankenlibc-abi/version_scripts/libc.map`) handles the last point by exporting symbols under the `GLIBC_2.2.5` version tag, which is what most dynamically linked Linux binaries expect. The script is 4,687 lines long.

---

## Subsystem Tour

| Subsystem | Where to look | What it covers |
|---|---|---|
| String / memory | `crates/frankenlibc-core/src/string/` and `crates/frankenlibc-abi/src/string_abi.rs` | `mem*`, `str*`, hardened single-pass kernels, internal-alias differentials |
| Stdio | `crates/frankenlibc-core/src/stdio/`, `crates/frankenlibc-abi/src/stdio_abi.rs`, `crates/frankenlibc-abi/src/io_internal_abi.rs` | File streams, buffered I/O, `_IO_*` internals (now natively implemented) |
| Allocator + pointer safety | `crates/frankenlibc-core/src/malloc/` + `arena.rs` / `fingerprint.rs` / `ptr_validator.rs` in membrane | Allocator behavior, ownership tracking, corruption detection |
| Threading | `crates/frankenlibc-core/src/pthread/` and `crates/frankenlibc-abi/src/pthread_abi.rs` | Native pthread entrypoints, futex-backed sync primitives, lifecycle |
| Resolver / networking | `resolv/`, `inet/`, `socket_abi.rs`, `resolv_abi.rs`, `inet_abi.rs` | DNS bootstrap, network-facing ABI surface |
| Locale + iconv | `locale/`, `iconv/`, `locale_abi.rs`, `iconv_abi.rs` | Locale setup, conversion, internationalization |
| Runtime math | `crates/frankenlibc-membrane/src/runtime_math/` | Risk, control, anomaly detection, certified safety, runtime decision kernels |
| Verification harness | `crates/frankenlibc-harness/` | Fixture verification, reports, evidence compliance, snapshots |

### If you only read four code areas

1. `crates/frankenlibc-abi/` — what the world sees
2. `crates/frankenlibc-membrane/` — where safety is enforced
3. `crates/frankenlibc-core/` — where libc behavior actually lives
4. `crates/frankenlibc-harness/` — how we prove what we claim

That sequence mirrors how the project itself works: claimed surface → ABI boundary → safety substrate → semantic kernels → verification and drift control.

---

## Suggested Reading Order

1. `README.md` (this file)
2. `AGENTS.md` — repo operating rules and architectural expectations
3. `support_matrix.json` — per-symbol classification
4. `crates/frankenlibc-abi/`
5. `crates/frankenlibc-membrane/`
6. `crates/frankenlibc-core/`
7. `crates/frankenlibc-harness/`
8. `tests/conformance/`
9. `scripts/check_*.sh`

---

## Packaging Contracts

- Release interpose artifact: `cargo build -p frankenlibc-abi --release` produces `target/release/libfrankenlibc_abi.so`
- Planned standalone replace artifact: `libfrankenlibc_replace.so` (L2/L3 milestone)
- Interpose deployment: `LD_PRELOAD=target/release/libfrankenlibc_abi.so <program>`
- Hardened interpose: `FRANKENLIBC_MODE=hardened LD_PRELOAD=… <program>`
- `Implemented` + `RawSyscall` symbols apply to **both** artifacts (interpose and replace)

Release-claim coherence is enforced by `scripts/check_release_gate.sh` and the L1 dashboard freshness gate.

---

## How To Evaluate Current Maturity

Do not rely on adjectives in the README. Use the artifacts.

| Question | Where to look |
|---|---|
| How much of the exported surface is native? | `support_matrix.json` and the maintenance report (100% as of 2026-05-16) |
| Is a symbol really implemented or still delegated? | `support_matrix.json` |
| Does the repo still reconcile code and docs? | `bash scripts/check_support_matrix_maintenance.sh` |
| Does interposition work on actual programs? | `bash scripts/ld_preload_smoke.sh` |
| Does hardened mode have explicit evidence paths? | `verify-membrane` harness output and JSONL evidence |
| Are release claims internally coherent? | `bash scripts/check_release_gate.sh` and `bash scripts/check_closure_contract.sh` |

Fast maturity check:

```bash
bash scripts/check_support_matrix_maintenance.sh
bash scripts/check_c_fixture_suite.sh
TIMEOUT_SECONDS=10 bash scripts/ld_preload_smoke.sh
bash scripts/check_release_gate.sh
```

---

## Verification Artifact Catalog

| Artifact | Role |
|---|---|
| `support_matrix.json` | Per-symbol source of truth for implementation taxonomy |
| `tests/conformance/reality_report.v1.json` | Generated snapshot of classified symbol state |
| `tests/conformance/support_matrix_maintenance_report.v1.json` | Canonical maintenance snapshot |
| `tests/conformance/support_semantic_overlay.v1.json` | Semantic overlay distinguishing full vs no-op / fallback / bootstrap / unsupported / proof-gap contracts |
| `tests/conformance/docs_semantic_claims.v1.json` | Claim-field contract enforcing README/FEATURE_PARITY discipline |
| `tests/conformance/fixtures/` | Host-libc fixture corpus for differential verification |
| `tests/conformance/c_fixture_spec.json` | Integration-fixture coverage contract |
| `tests/conformance/runtime_env_inventory.v1.json` | Machine-generated inventory of documented `FRANKENLIBC_*` env vars |
| `tests/conformance/iconv_codec_scope_ledger.v1.json` | Locked iconv phase-1 scope |
| `tests/conformance/ld_preload_smoke_summary.v1.json` | Canonical curated smoke summary |
| `tests/conformance/*_completion_contract.v1.json` | 258 binding evidence artifacts for closed beads |
| `tests/conformance/*_cli_contract.v1.json` | Per-subcommand harness CLI contracts |
| `tests/runtime_math/golden/` | Runtime-math golden snapshots |
| `target/conformance/*.json` / `*.jsonl` | Generated local evidence from harness runs |

The artifacts fall into three categories:

- **Claims** about what exists
- **Evidence** about what happened
- **Gates** that compare the two

Keeping those categories separate is what makes the repo legible.

---

## Why Memory Safety at the libc Boundary

libc is the wrong layer for "just trust the caller" and a uniquely good layer for instrumentation.

It is the wrong layer for trust because:

- C compilers cannot enforce memory safety on the operands the caller hands them, and that ignorance is what libc inherits.
- Allocation, string, stdio, and threading are the entry points where *most* memory-safety bugs surface, even when the underlying bug originated elsewhere.
- libc routines are ubiquitous in third-party binaries you do not control, and you cannot patch the C source out of existence.
- Long-lived process state (stdio buffers, allocator metadata, TLS slots, signal handlers, locale globals) makes corruption silently compound across calls.

It is a uniquely good layer for instrumentation because:

- The ABI shape is stable, well-documented, and survives across decades of binaries.
- Every nontrivial Linux program crosses it.
- It is close enough to real behavior to matter, yet abstract enough to instrument systematically.
- `LD_PRELOAD` gives you an immediate, reversible deployment story for experiments and security research.
- The boundary is a natural fingerprint point: pointers, sizes, fds, modes, and contexts all flow through it.

FrankenLibC's position is straightforward: if the ABI boundary is where the ambiguity is most concentrated, that is the right place to spend safety budget. The TSM is the engineering expression of that position.

---

## Engineering Principles

These principles are explicit, not implicit. Every decision in the repo defers to them.

1. **ABI is the contract.** Symbol names, calling conventions, version tags, `errno`, modes, secure-mode classification, and process-level semantics are *the* deliverable. Anything that breaks the contract gets backed out, no matter how clever.
2. **Validate before delegate.** No core kernel runs on caller-supplied state before the membrane has classified it. The five-step pattern is structurally enforced.
3. **Repairs are deterministic.** Hardened mode never "tries something different" — it picks the prescribed healing action for the (family, condition) pair every time. Replay is a property, not an aspiration.
4. **Evidence is mechanical, not social.** Claims that cannot be cited from a generated artifact under `tests/conformance/` are not load-bearing. The `docs_semantic_claims.v1.json` claim-field contract enforces this for README and FEATURE_PARITY prose.
5. **Fail closed.** Drift, missing evidence, stale source pins, or claim/evidence disagreement abort the build or the gate. The default state of an unverified claim is *rejected*.
6. **No tech debt.** No backwards-compatibility shims, no wrapper-around-wrapper layers, no `_v2` files. We are pre-1.0; the right way is the only way.
7. **Clean-room, not transliteration.** Behavior is driven by spec, fixtures, and verification artifacts. Reference glibc is consulted; never copied.
8. **No scripted bulk edits.** Every refactor is manual or routed through parallel subagents that understand the change. Regex-based source rewrites are banned because they create more correctness problems than they solve.
9. **Developer transparency.** Contributors write normal Rust APIs and policy tables. The heavy math machinery compiles to compact deterministic guards in the hot path; theorem-proving stays offline.
10. **One bead, one outcome.** Every implementation effort is anchored to a `bd-*` issue with a binding evidence artifact. "Closed" means "closure is backed by JSONL receipt." The audit gate enforces it.

These principles are why the project has so many JSON artifacts, so many gates, so much fixture work, and so few wrappers.

---

## Inside the Validation Pipeline

Each membrane stage has a specific job, a specific cost target, and a specific *failure mode* it is designed to surface before the stage that follows.

### Stage 0 — Runtime Policy Decision

`runtime_policy::decide()` is the single funnel. It returns `(RuntimeKernelSnapshot, RuntimeDecision)`. The snapshot freezes a coherent view of every relevant runtime-math controller (risk, bandit, control, barrier, pareto, design, …) at the moment of the call. The decision contains:

- `MembraneAction` ∈ `{ Allow, Check, Deny, Heal(action) }`
- `ValidationProfile` ∈ `{ Fast, Full }`
- Optional family-specific hints

`ApiFamily` enumerates 20 call-site contexts as declared in `crates/frankenlibc-membrane/src/runtime_math/mod.rs`: `PointerValidation`, `Allocator`, `StringMemory`, `Stdio`, `Threading`, `Resolver`, `MathFenv`, `Loader`, `Stdlib`, `Ctype`, `Time`, `Signal`, `IoFd`, `Socket`, `Locale`, `Termios`, `Inet`, `Process`, `VirtualMemory`, `Poll`. The policy may choose different validation depths per family, since the cost-of-error and cost-of-overhead trade off differently for, say, `Allocator` vs `Time`.

### Stage 1 — Null Check (~1 ns)

Catches the highest-frequency, lowest-cost failure: a null pointer where one is illegal. Fast-exits with the family-specific error contract (`EINVAL`, `EFAULT`, `NULL` return, `errno` set, or `Deny`).

### Stage 2 — TLS Validation Cache (~5 ns)

Each thread carries a 1,024-entry direct-mapped cache indexed by `ptr >> 4` (16-byte granularity, masked by `CACHE_SIZE - 1`). Entries record `(generation, classification)`. A cache hit avoids the global metadata path entirely. Cache entries are invalidated lazily by epoch advancement (the EBR layer), so a freed allocation can never produce a stale `Valid` hit on its old slot.

### Stage 3 — Bloom Filter (~10 ns)

`crates/frankenlibc-membrane/src/bloom.rs` provides a probabilistic "is this pointer ours?" check. Storage is an atomic `u64` array, so concurrent insertion and query work without locks. Sized for 1,000,000 expected items at 0.1% target FP, with optimal `k = (m/n)·ln(2)` clamped to `[1, 16]`. Zero false negatives by construction. The bloom answer alone is never trusted for ownership; it serves as a *reject early* filter that prevents the much more expensive arena lookup on pointers that clearly aren't ours.

### Stage 4 — Arena / Metadata Lookup (~30 ns)

`crates/frankenlibc-membrane/src/arena.rs` indexes live allocations by 16 shards. The shard is selected by `(addr >> 12) % NUM_SHARDS` (the page-frame number modulo the shard count). Since `NUM_SHARDS = 16` is power-of-two, the modulo compiles to a bit-mask. Per-allocation metadata: `(raw_base, user_base, user_size, generation: u64, SafetyState)`. The arena is the source of truth for ownership and lifetime.

### Stage 5 — Fingerprint Check (~20 ns)

The 24-byte header sitting at `user_base − 24` is hashed with SipHash-2-4 keyed by allocation metadata. If the hash doesn't match the recomputation, the header has been corrupted (buffer underflow, foreign write, or an outright fake pointer). Probability of an undetected collision is bounded by 2⁻⁶⁴.

### Stage 6 — Canary Check (~10 ns)

The 8-byte trailing canary at `user_base + user_size` is derived from the same SipHash key. Corruption here means a write went past the allocation end. Together with the header check, the membrane closes both buffer-underflow and buffer-overflow detection at the same cryptographic strength.

### Stage 7 — Bounds + Policy Check (~5 ns)

Final per-call check: does the proposed access fit inside `[user_base, user_base + user_size)`? Does the operation respect the current `SafetyState` (e.g., write to a `Readable`-only region is denied)? Does the runtime policy say `Allow` here?

### Decision

The pipeline outputs `Allow`, `Heal(action)`, or `Deny`. Each ABI entrypoint then routes to the safe-Rust kernel, applies the healing action (if hardened), or returns the family-specific failure (if strict). The whole outcome, including elapsed nanoseconds, decision, and any healing action, is fed back into `runtime_policy::observe()` so the runtime-math controllers update their state for the *next* call.

The ordering is not arbitrary. Stages 1-3 are cheap, can reject early, and remove the bulk of "obviously not ours" cases. Stages 4-6 are more expensive but cryptographically strong. Stage 7 is policy-aware. The Thompson sampling oracle (see below) continuously learns which stage ordering minimizes expected total latency for the observed workload, and re-packs the optimal ordering into a single `u64` (4 bits per stage) every 128 calls.

---

## Allocator: The Math Behind the Geometry

### Why 32 size classes?

Fewer classes waste memory (large internal fragmentation); more classes inflate metadata cost and dilute slab reuse. Industry experience (jemalloc, tcmalloc, mimalloc) converged on ~30-40 classes for general workloads. FrankenLibC's 32 classes follow a piecewise-arithmetic progression: linear within each decade, doubling the step at each decade boundary. The result keeps the *internal* fragmentation per allocation bounded at ~12.5% in the small-class range and ~25% in the large-class range, while preserving slab-level efficiency.

### Slab geometry

| Property | Value |
|---|---|
| Slab size | 64 KB |
| Slab header | Page-aligned metadata block |
| Per-slab free list | Compact intrusive linked list |
| Per-slab usage counter | Tracks live count for partial/full classification |

`size_class.rs` declares `PER_OBJECT_OVERHEAD = 64` (fingerprint + canary + alignment padding). The per-class object count is `64 KiB / (size + 64)`: roughly 819 objects per slab at the 16-byte class, 341 at 128 bytes, 40 at 1,536 bytes, and 1 at 32 KiB (which is the LargeAllocator threshold). The free list lives in the unused portion of each object, so the steady-state intrusive overhead beyond the fingerprint and canary is zero.

### Magazine cache eviction policy

Each thread's magazine is a LIFO stack per class. On overflow:

1. Half of the magazine is bulk-transferred to the sharded central allocator
2. The transfer is one atomic batch operation, with no per-object lock acquire
3. The other half remains thread-local

On drain (empty magazine):

1. Half a magazine is bulk-fetched from the central allocator
2. The shard is chosen by thread-affinity hash
3. Affinity reduces contention without requiring strict pinning

The 64-objects-per-class threshold is chosen so that bulk transfers amortize the central-allocator lock acquisition across enough objects that the per-object overhead falls below the membrane overhead budget.

### Large-allocation path (deep dive)

`LargeAllocator` is a parallel allocator just for requests > 32 KB:

- Each allocation is a separate `mmap` with 4096-byte page alignment
- Base address starts at `0x1_0000_0000` to visually segregate the address space
- Tracked metadata: `(base, mapped_size, user_size)`, where `mapped_size` may exceed `user_size` due to page rounding
- `munmap` returns the pages directly to the kernel; the membrane records the deallocation in the arena's quarantine ledger so use-after-free against recycled mappings is still detectable

### Pre-TLS bump allocator

A small `static` bump allocator services allocations during early process startup *before* TLS is initialized. `dlerror`, dl-init paths, and the `__libc_start_main` validation envelope all need to allocate before `pthread_key_create` is available. The bump allocator is a single linear arena protected by an atomic offset; allocations from it are never freed (they live until process exit).

---

## Generational Arena: Lifecycle State Machine

Every allocation moves through a deterministic lifecycle:

```
                    alloc()
                      │
                      ▼
                  ┌────────┐
                  │  Live  │ ◄── most operations
                  └────────┘
                      │
                    free()
                      ▼
                  ┌────────┐
                  │ Freed  │ ── generation += 1
                  └────────┘
                      │
              enqueue into shard quarantine
                      ▼
                  ┌──────────────┐
                  │ Quarantined  │ ── physical memory still mapped
                  └──────────────┘   but logically inaccessible
                      │
              quarantine drain
              (when quarantine bytes > QUARANTINE_MAX_BYTES,
               or epoch advances past safe-reclaim threshold)
                      ▼
                  ┌─────────┐
                  │ Recycle │ ── pages or slab slot returned
                  └─────────┘    to the allocator
```

Three properties of this lifecycle matter:

1. **Generation counters never reuse.** The `u64` generation increments on each `Freed → Recycle` cycle, so a re-allocated slot has a different generation than any prior live mapping for the same address. A pointer carrying the old generation cannot validate against the new occupant: generation mismatch detects use-after-free with probability 1.0.
2. **Quarantine residence makes UAF observable.** While in `Quarantined`, the address is still mapped (no segfault), but the membrane refuses to admit any operation against it. This lets the failure surface deterministically as a *typed error* rather than an unpredictable signal.
3. **Drain is bounded.** `QUARANTINE_MAX_BYTES = 64 MB` caps the working-set cost; drain is triggered by either capacity pressure or EBR epoch progress, whichever fires first.

The drain itself runs under the EBR (epoch-based reclamation) primitive, so concurrent readers cannot observe a half-recycled slot. The flat-combining primitive funnels concurrent drain requests through a single thread to amortize the work.

---

## Fingerprint Cryptography

Why SipHash-2-4 specifically:

- **Designed for short messages.** Allocation metadata is tens of bytes; this is SipHash's sweet spot.
- **Keyed.** A per-process secret derived at init from a mix of PID, wall-clock nanoseconds, and ASLR address noise means an attacker cannot precompute a colliding header.
- **Fast.** SipHash-2-4 runs in a handful of cycles per 8-byte block on x86_64; the per-call cost is ~20 ns even before vectorization.
- **Strong against differential attacks.** The 2-4 round count is conservatively chosen to defeat known cryptanalytic shortcuts.

The header layout `[hash:8][generation:4][size:8]` is laid out so that:

- Reading the size from `*(u64*)(p - 12)` is one aligned load
- The generation is the verify-critical quantity for UAF
- The hash binds the metadata to the allocation address, defeating "swap two headers" attacks

Trailing canaries derive from the same SipHash key but use a different domain separator. An adversary who corrupts both header and canary needs to forge a 64-bit MAC twice with no key: `P(success) ≤ 2⁻¹²⁸` if treated as independent forgeries, `≤ 2⁻⁶⁴` if treated as a single coordinated guess.

The fingerprint and canary together are a *detection* mechanism, not an *exclusion* mechanism for an attacker who has already achieved arbitrary write. The membrane's job is to make corruption visible, not to make it impossible.

---

## Runtime Mode Resolution: The Bootstrap State Machine

Mode is a process-wide invariant. Once `STRICT` or `HARDENED`, no code path can flip it. The CAS state machine:

```
state ∈ { UNRESOLVED (0), RESOLVING (255), STRICT (1), HARDENED (2), OFF (3) }

  UNRESOLVED ──CAS──► RESOLVING ──read env──► STRICT | HARDENED | OFF
                          │
                          │ (reentrant call during resolution)
                          ▼
                    Passthrough decision returned;
                    bootstrap completes; thread retries.
```

The `RESOLVING` state exists because the very first membrane call during process startup may itself need to allocate, read a TLS slot, or call into stdio, all of which would re-enter the membrane. To avoid deadlock or infinite recursion, the CAS to `RESOLVING` is taken once, and any reentrant call sees `RESOLVING` and returns a safe passthrough decision so the resolving thread can finish reading the environment and complete the CAS to the terminal state.

After the terminal state is reached, every subsequent call observes the resolved mode with a single `Relaxed` atomic load. No further synchronization is needed because the value is now an invariant.

`FRANKENLIBC_MODE` parsing accepts: `hardened`, `repair`, `tsm`, `full` → `HARDENED`. Anything else (including unset, malformed, or unrecognized) → `STRICT`. The conservative default is intentional: a misconfigured environment never silently grants more authority to the membrane.

---

## The Native Syscall Layer

`crates/frankenlibc-core/src/syscall/` contains typed Rust wrappers for every syscall surface FrankenLibC uses. Highlights:

- **Generic dispatch:** `syscall0` through `syscall6` wrap `core::arch::asm!` on x86_64 and aarch64
- **Per-family wrappers:** typed signatures for each syscall family with `errno` extraction (`-EAGAIN` → `EAGAIN`, propagated through `set_abi_errno`)
- **Linux 6.7+:** futex2 (`futex_wake`, `futex_wait`, `futex_requeue`), `process_madvise`, `process_mrelease`, `personality`, `landlock_*`, `io_uring_setup` / `_enter` / `_register`
- **Filesystem:** `statx`, `execveat`, `openat2`, `name_to_handle_at`, `open_by_handle_at`, `fchmodat2`
- **Process:** `pidfd_open`, `pidfd_send_signal`, `pidfd_getfd`, `clone3`
- **Memory:** `mremap`, `mlock2`, `mbind`, `set_mempolicy`, `get_mempolicy`, `memfd_create`
- **Scheduling:** `sched_setaffinity`, `sched_getaffinity`, `sched_setattr`, `sched_getattr`
- **Random / time:** `getrandom`, `clock_nanosleep`, `clock_adjtime`
- **IPC:** `semop`, `msgsnd`, `msgrcv`, `shmat`, SysV ID space tracked through the symplectic-reduction controller
- **Namespaces / mount:** `unshare`, `setns`, `mount`, `umount2`, `move_mount`, `fsopen`, `fsmount`, `fsconfig`

Every wrapper has explicit safety documentation. The membrane crate's build-time barrier audit enforces that the wrappers maintain the required atomic-barrier coverage for cross-thread visibility.

As of Phase 9, **zero `libc::syscall` callthroughs remain** in the ABI surface (Epic `bd-h5x`). The library talks to the kernel directly.

---

## Membrane Concurrency Architecture

Each `alien_cs` primitive solves a specific contention shape. Knowing which to reach for is a load-bearing design skill in the membrane.

| Primitive | Use when… | Avoid when… |
|---|---|---|
| **`SeqLock`** | Reads are 100× more common than writes; the protected value is small (one or two cache lines); readers can tolerate retry under writer contention | Writes are frequent; the value is large; readers need wait-freedom |
| **`RCU`** | The protected structure is a long-lived membership graph (e.g., live-allocation index, registered-callback set) read on every call; updates are infrequent and structural | Updates are point-mutations (use `SeqLock` instead); memory cost of versioned copies is unacceptable |
| **`EBR`** | Safe deferred reclamation of any pointer that may still be reachable by a reader; combines with RCU and SeqLock | The cost of a fully grace-period-bounded scheme (e.g., QSBR) is not tolerable |
| **`FlatCombining`** | Many threads contend for the same critical section, and the critical section is short; a single combining thread can do everyone's work in one batch | The work per request is asymmetric; combining doesn't amortize |
| **`htm_fast_path::HtmSite`** | The transaction fits in the CPU's HTM commit budget; conflicts are rare; the fallback path is correct | The architecture lacks HTM (graceful fallback); workload exhibits adversarial conflict patterns |

Unified metrics across all primitives live in `alien_cs_metrics.rs`: contention scores, deadlock-proximity indicators, exit-pressure telemetry, abort rates (for HTM), grace-period durations (for EBR), and combiner throughput (for FC). The runtime math control plane reads these metrics and adapts validation routing accordingly.

The TLS validation cache sits *in front of* these primitives because every membrane call is hot. The primitives handle the cases where the cache misses and global state must be consulted.

---

## Risk Engine Math

Conformal nonconformity scoring without distributional assumptions:

For each incoming pointer `p` with context `(family, size, alignment)`:

```
score(p) = αlign_score(p) + size_score(size) + entropy_score(p)
        capped at 1000
```

- `alignment_score = (6 − log₂(alignment)) × 33`, range `[0, 198]`; penalizes misalignment proportional to how far from `8`-byte aligned the pointer is
- `size_score` = lookup table: `0 → 200`, `> 1 MiB → 250`, `> 64 KiB → 150`, otherwise `clz(size)`
- `entropy_score` = `200` if the pointer's bit-count is at one of the distribution tails, else `0`

A 256-entry circular buffer tracks recent scores. Thresholds are quantile-calibrated:

- `fast_threshold = Q_{1-α}` for `α = 0.01` (1% target false-skip rate); scores below this skip expensive validation
- `full_threshold = Q_{1-α/4}`; scores above this trigger exhaustive checks
- Recalibration runs every `N = 64` observations or on alarm

An anytime-valid e-process accumulates evidence on the log scale. When the e-process exceeds `10.0`, the engine enters alarm mode: every call gets `Full` validation until the e-process subsides. The e-process formulation gives finite-sample correctness without needing to know the workload's score distribution in advance.

The math here is conformal prediction (Vovk et al. 2005) wrapped around a per-family conformal risk-control envelope. The validation-depth decision ends up calibrated against the observed call distribution instead of against a hand-picked threshold that ages badly.

---

## Thompson Sampling Math

The check oracle learns the optimal validation-stage ordering at runtime via Thompson sampling.

State per stage `s` (declared as `f64` for differential updates):

- `α_s, β_s` ∈ ℝ⁺, initialized to `(1.0, 1.0)` (uniform Beta(1,1) prior)
- `θ_s ~ Beta(α_s, β_s)` — sampled success probability
- `cost_s` — fixed ns budget per stage

Update after each call:

- If stage `s` caused early termination: `α_s += 1`
- For every other stage that ran but did not terminate: `β_s += 1`

Reordering every `K = 128` calls:

```
For each stage s:
  draw θ_s ~ Beta(α_s, β_s)
  utility_s = θ_s / cost_s     (expected info gain per ns)
sort stages descending by utility_s
pack into u64 (4 bits per stage)
```

The packed ordering is read on every membrane call with a single atomic load and unpacked branchlessly. The reordering is correct under the standard regret bound for Thompson sampling on Bernoulli arms.

Why Thompson, not UCB or ε-greedy:

- The exploration-exploitation trade-off in this setting is bounded; Thompson auto-balances without tuning.
- Bernoulli posteriors update in `O(1)` per call; no list of samples to keep.
- The `Beta(α, β)` parameters are integer counts; arithmetic is exact.

---

## The libio (`_IO_*`) Compatibility Surface

glibc binaries built before C11 frequently reference internal libio symbols: `__overflow`, `__uflow`, `__underflow`, `_IO_getline`, `_IO_flush_all_linebuffered`, `_IO_putc`, `_IO_getc`, `_IO_fwide`, `_IO_file_xsputn`, and dozens more. These are *not* in the C standard, but they exist in `libc.map` because real programs link against them.

In earlier phases these were `GlibcCallThrough` (the membrane delegated to the host libc's `_IO_*` routines). In Phase 6 (per the CHANGELOG) and continued through Phase 9, every `_IO_*` symbol in the classified surface was nativized:

- The `FILE` struct layout is a Rust type that's binary-compatible with glibc's `_IO_FILE` for the parts that callers may peek into.
- The vtable-style dispatch (`__overflow` → buffer-grow-and-write) is replaced by an explicit method dispatch on the Rust `Stream` type.
- Line-buffered semantics use the reverse-scan optimization (`rposition`) to keep flush cost proportional to the last newline, not the buffer size.
- The `unget` path supports LIFO byte pushback for `ungetc` correctness.

This matters because a non-trivial fraction of dynamically-linked Linux programs (especially those built against glibc < 2.34) call into these internals directly during startup. A FrankenLibC interpose that didn't own these would silently fall back to host glibc for stdio, breaking the "100% native classified surface" claim.

---

## Modern Math Stack — Reference Card

The runtime math subdirectory is not decorative. Each module exists because the project's design audit (`AGENTS.md`) requires the membrane to draw from a diverse, modern mathematical toolkit, and each subsystem must justify its decisions against at least three distinct math families. The full enumerated stack:

1. Abstract interpretation + Galois maps for pointer / lifetime domains
2. Separation-logic-style heap invariants for allocator and concurrency boundaries
3. SMT-backed refinement checks for strict vs hardened semantics
4. Decision-theoretic loss minimization for hardened repair-policy selection
5. Anytime-valid sequential testing (e-values / e-processes) for regression monitoring
6. Bayesian change-point detection for drift in performance and repair-rate behavior
7. Robust optimization targeting worst-case tail latency
8. Constrained POMDP policy design for hardened repair decisions
9. CHC + CEGAR proof loops with automatic counterexample fixture generation
10. Equality-saturation superoptimization with SMT equivalence certificates for hot kernels
11. Information-theoretic provenance tag design
12. Wasserstein distributionally robust control + CVaR tail-risk optimization
13. Barrier-certificate invariance constraints on runtime action admissibility
14. Iris-style concurrent separation-logic for lock-free / sharded metadata
15. Hamilton-Jacobi-Isaacs reachability analysis for attacker-controller safety boundaries
16. Sheaf-cohomology diagnostics for global metadata consistency across overlapping local views
17. Covering-array + matroid combinatorics for high-order conformance interaction coverage
18. Probabilistic coupling + concentration bounds
19. Mean-field game control for thread-population contention dynamics
20. Schrödinger-bridge entropic optimal transport for stable policy regime transitions
21. Sum-of-squares certificate synthesis (SDP-backed) for nonlinear invariants
22. Large-deviations rare-event analysis for catastrophic failure budgeting
23. Persistent-homology topology-shift diagnostics for anomaly class detection
24. Rough-path signature embeddings for long-horizon trace dynamics
25. Tropical / min-plus algebra for compositional worst-case latency bounds
26. Primal-dual operator-splitting with convergence certificates for online constrained tuning
27. Conformal prediction / risk-control methods for finite-sample decision guarantees
28. Spectral-sequence and obstruction-theory diagnostics for cross-layer consistency defects
29. Semigroup / group-action / representation-theory methods for canonical behavior normalization
30. Gröbner-basis constraint normalization for reproducible proof kernels
31. Noncommutative probability + random-matrix tail control for burst concurrency risk
32. Serre spectral-sequence methods for multi-layer invariant lifting
33. Grothendieck site / topos / descent / stackification for local-to-global coherence
34. Atiyah-Singer families index and K-theory transport for compatibility integrity
35. Atiyah-Bott localization for fixed-point compression of proof / benchmark obligations
36. Clifford / geometric algebra + Spin/Pin symmetry for SIMD / alignment correctness
37. Microlocal sheaf-theoretic propagation (Kashiwara-Schapira) for unwind / signal fault-surface control
38. Derived-category t-structure decomposition for process-bootstrap ordering invariants
39. Geometric invariant theory + symplectic reduction for SysV IPC admissibility and deadlock elimination
40. Non-Archimedean (p-adic valuation) error calculus for exceptional floating-point regimes
41. Optimal experimental design + sparse recovery for low-perturbation profiling
42. Higher-topos internal logic and descent diagnostics for locale / catalog coherence
43. Representation-stability and equivariant transport methods for cross-ISA syscall semantic alignment
44. Commitment-algebra + martingale-audit methods for tamper-evident session / accounting traces

**Branch-diversity rule:** every major subsystem milestone uses at least 3 distinct families, includes at least one obligation each from conformal statistics, algebraic topology, abstract algebra, and Grothendieck-Serre methods, and is capped so no single family dominates more than 40% of obligations.

The list is not a "we used all the math" trophy. The design audit rejects shortcuts: every safety, performance, or admissibility decision must be expressible in at least one rigorous, citable framework, and the framework must be diverse enough to surface trade-offs the original designer might not have seen.

---

## Evidence Ledger and Replay

`runtime_math/evidence.rs` defines a structured per-call evidence symbol: `(timestamp, family, decision, latency_ns, healing_action, controller_state_hash)`. The evidence ledger is a lock-free ring buffer in shared memory; consumers (the harness, metrics scrapers, or external replay tools) read from it without back-pressure on the producer.

Two consumers matter most:

1. **Runtime metrics:** atomic counters in `metrics.rs` aggregate decisions by `(family, decision)` pair. The counters are scraped by the harness for end-of-run summaries.
2. **Replay verifier:** the JSONL record format is declared in code (`crates/frankenlibc-membrane/src/runtime_math/evidence.rs`); the gate config lives in `tests/conformance/runtime_evidence_replay_gate.v1.json` and is consumed by the harness's `validate-runtime-evidence-rows` subcommand. This is how `deterministic_replay.md` is operationalized into a gate.

Bead `bd-fp4tm.6` ("workload evidence loop handoff") landed the end-to-end pipeline in Phase 13.

---

## Test Type Glossary

Tests in this repo come in four distinct *kinds*. They are not interchangeable.

| Kind | What it proves | Where it lives |
|---|---|---|
| **Unit** | One Rust module behaves correctly on its own contract | inline `#[cfg(test)]` in every component crate |
| **Fixture / Differential** | FrankenLibC output for a given input matches host glibc output for the same input | `tests/conformance/fixtures/` (40+ families) |
| **Metamorphic** | An algebraic relation holds between two related calls (round-trip, monotonicity, commutativity) even when the absolute output is hard to enumerate | `tests/conformance/*_metamorphic_*.v1.json` |
| **Property-based** | A randomized invariant holds across thousands of generated inputs | `proptest` harnesses under each crate's tests |
| **Fuzz (coverage-guided)** | The implementation does not crash, hang, or violate memory safety on adversarial input | `crates/frankenlibc-fuzz/fuzz_targets/` (66 targets) |
| **Integration (C)** | A real C program linked against the produced `.so` works correctly | `tests/integration/*.c` (17 fixtures) |
| **Smoke (`LD_PRELOAD`)** | A real binary runs under interposition with output and latency parity | `scripts/ld_preload_smoke.sh` |
| **Healing-oracle** | Hardened mode applies the prescribed healing action for each unsafe condition | `verify-membrane` harness CLI |
| **Snapshot / golden** | A generated artifact (runtime-math kernel output, fixture pack, evidence ledger) hasn't drifted | `tests/runtime_math/golden/` + `scripts/snapshot_gate.sh` |
| **Closure / release gate** | Top-level project claims remain internally coherent | `scripts/check_release_gate.sh`, `scripts/check_closure_contract.sh` |
| **Meta-gate** | A CLI contract manifest itself is well-formed and matches its paired test | ~50 pinned Rust tests under `crates/frankenlibc-harness/tests/cli_contract_*` |
| **Proof note / obligation** | A mathematical property is specified with rationale, evidence hooks, and pending mechanization scope | `docs/proofs/*.md` (9 proof notes) + `tests/conformance/proof_obligations_binder.v1.json` |

Each kind has a different cost / signal trade-off. Cheap kinds (unit, property) run on every commit; expensive kinds (fuzz, proof-note / obligation regeneration, full preload smoke) run on schedule or on demand.

---

## Cargo Profile and Build Configuration

The workspace currently uses Cargo's default release profile (`opt-level = 3`, `lto = false`, `codegen-units = 16`, `strip = false`). `AGENTS.md` documents an aggressive target profile (`lto = true`, `codegen-units = 1`, `strip = true`) intended for the shipping artifact; that tuning is a tracked item, not the current default.

`Cargo.toml` declares the workspace edition as **Rust 2024** (nightly required, pinned via `rust-toolchain.toml` to `nightly-2026-04-28`). The membrane and core crates set `#![deny(unsafe_code)]` at the crate root and selectively `#[allow]` it per-module with mandatory `// SAFETY:` comments.

The ABI crate declares its `[lib]` block as `crate-type = ["cdylib", "staticlib", "rlib"]`. The `cdylib` output is `libfrankenlibc_abi.so` (the `LD_PRELOAD` artifact); the `staticlib` is `libfrankenlibc_abi.a` (used by native packaging checks like `scripts/check_setjmp_native.sh` that link against the version script directly via `cc`); the `rlib` is the Rust library form used by other workspace crates.

---

## Workspace Dependencies

The workspace deliberately keeps the external dependency graph small. Every dependency must justify its presence at the libc layer.

| Crate | Why it's here |
|---|---|
| `parking_lot` | Fast `Mutex` / `RwLock` for the non-`alien_cs` paths in the membrane and harness |
| `blake3` | Allocation fingerprint hashing in some auxiliary paths (the primary fingerprint is SipHash) |
| `sha2` | Conformance fixture digesting for tamper-evidence |
| `md-5` | Legacy hash compatibility for specific MD5-keyed fixture lookups |
| `serde` + `serde_json` + `serde_yaml` | Conformance fixture and report serialization |
| `regex` | POSIX regex back-end where the native regex engine doesn't apply |
| `tracing` | Structured runtime logging (gated by `FRANKENLIBC_LOG`) |
| `thiserror` | Ergonomic error types in the harness crate |
| `clap` | CLI argument parsing in the harness binary |
| `criterion` | Benchmark framework in `frankenlibc-bench` |
| `libc` | Type definitions only (e.g., `c_int`, `pid_t`, `mode_t`). **Never** for function calls; raw syscall wrappers live in `crates/frankenlibc-core/src/syscall/` |
| `libm` | Pure-Rust math implementations for `math_abi` cross-platform determinism |
| `asupersync-conformance` | Build-tooling-only: deterministic conformance orchestration |
| `ftui-harness` | Build-tooling-only: TUI-driven harness output for diff/snapshot inspection |

The two companion crates (`asupersync-conformance`, `ftui-harness`) are explicitly **not runtime libc dependencies**. They are build/test orchestration crates, off the hot path entirely.

---

## Code Style Policy

| Crate | `unsafe` policy | Notes |
|---|---|---|
| `frankenlibc-core` | `#![deny(unsafe_code)]` | SIMD modules and the arena layer get `#[allow(unsafe_code)]` with per-block `// SAFETY:` comments |
| `frankenlibc-membrane` | `#![deny(unsafe_code)]` | Arena / fingerprint / page-oracle modules `#[allow]` with `// SAFETY:` |
| `frankenlibc-abi` | `#![allow(unsafe_code)]` | ABI boundary is inherently unsafe; every function is minimal: validate via membrane, delegate to core |
| `frankenlibc-harness` | `#![forbid(unsafe_code)]` | The test harness never needs unsafe |
| `frankenlibc-bench` | `#![allow(unsafe_code)]` | Benchmarks call `extern "C"` |
| `frankenlibc-fuzz` | `#![allow(unsafe_code)]` | Fuzz harnesses call `extern "C"` |

Rules:

1. Unsafe is permitted only in explicitly documented boundary modules
2. Every unsafe block must have a `// SAFETY:` comment stating its invariants and preconditions
3. Core algorithmic behavior stays in safe Rust
4. Memory safety is achieved via the TSM, not by pretending FFI unsafety doesn't exist

No script-based bulk source rewrites are permitted (AGENTS.md). Manual edits or parallel subagents only.

---

## Use Cases By Reader

### For operators and platform engineers

You have a production Linux fleet and want to layer some safety or observability on glibc-linked binaries without rebuilding them. Build `libfrankenlibc_abi.so`, deploy via your existing config-management tool, and start with `FRANKENLIBC_MODE=strict` on non-critical workloads. The structured runtime log (`FRANKENLIBC_LOG`) gives you JSONL evidence of every membrane decision. Promote to hardened on suspect workloads once you have baseline data.

### For security researchers

The hardened-mode healing oracle (`verify-membrane`) is the right starting point. It deliberately triggers each unsafe condition and emits structured per-case JSON. You can write new oracle cases by adding fixtures to `tests/conformance/fixtures/`. The fuzz targets in `crates/frankenlibc-fuzz/fuzz_targets/` exercise 66 surfaces with directed corpora; each target is `cargo +nightly fuzz run <name>` away from a long-running campaign.

### For libc/Rust developers

The crate layout mirrors how the system works: ABI → membrane → core → harness. Read in that order. Every public symbol is classified in `support_matrix.json`. `cargo doc --workspace --no-deps --open` builds the local API docs.

### For conformance auditors

`bash scripts/ci.sh` is the canonical default gate. `bash scripts/check_release_gate.sh` checks top-level claim coherence. `cargo run -p frankenlibc-harness --bin harness -- reality-report` generates a machine-readable current-state snapshot. The 258 completion-contract JSONLs under `tests/conformance/` are the bookkeeping evidence; the 68 CLI-contract JSONLs validate the harness CLI surface itself.

### For language / API designers

The validate-delegate pattern, the safety lattice, the runtime policy chokepoint, and the meta-gate framework for CLI contracts are all reusable design patterns. They are also small enough to read end-to-end in an afternoon.

### For people curious whether this is real

Run the curated preload smoke battery: `TIMEOUT_SECONDS=10 bash scripts/ld_preload_smoke.sh`. It executes real binaries under both modes and reports pass/fail with structured failure-signature classification. Then look at `tests/conformance/ld_preload_smoke_summary.v1.json`.

---

## CI Quality Gates

The default gate is `bash scripts/ci.sh`, which runs:

1. `cargo fmt --check`
2. `cargo check --workspace --all-targets`
3. `cargo clippy --workspace --all-targets -- -D warnings`
4. `cargo test --workspace`
5. Repo-standard drift checks (`scripts/check_*.sh` for support-matrix, runtime env, claim fields)

Additional gates routinely run:

| Gate | What it checks |
|---|---|
| `check_support_matrix_maintenance.sh` | Symbol classification drift between source and the maintenance report |
| `check_c_fixture_suite.sh` | All 17 C integration fixtures compile and run |
| `check_conformance_fixture_pipeline.sh` | Fixture capture, replay, and verification round-trip |
| `ld_preload_smoke.sh` | Real-program interposition in both modes |
| `check_allocator_e2e.sh` | Concurrent alloc/free with glibc parity diff |
| `check_cve_uaf_validation.sh` | Use-after-free detection against known CVE patterns |
| `check_cve_heap_overflow_validation.sh` | Heap-overflow detection against known CVE patterns |
| `check_anytime_valid_monitor.sh` | Sequential testing monitor correctness |
| `check_changepoint_drift.sh` | Bayesian change-point detection |
| `check_pressure_sensing.sh` | Runtime pressure sensing |
| `check_regression_detector.sh` | Performance regression detection |
| `check_perf_baseline.sh` + `check_perf_regression_gate.sh` | Performance budget enforcement |
| `check_math_governance.sh` + `check_math_retirement.sh` | Runtime math module lifecycle |
| `check_iconv_table_generation.sh` | Encoding table determinism |
| `check_runtime_math_linkage_proofs.sh` | Runtime math linkage integrity |
| `check_aarch64_crosscompile.sh` | aarch64 architecture gate |
| `check_release_gate.sh` | Top-level release-claim coherence |
| `check_release_dossier.sh` | Release dossier completeness |
| `check_closure_contract.sh` | Closure contract enforcement |
| `check_packaging.sh` | Packaging artifact correctness |
| `snapshot_gate.sh` | Runtime math golden snapshot integrity |
| `check_setjmp_native.sh` | `setjmp`/`longjmp` link against the staticlib using `libc.map` |

The architecture is that every claim has an owning gate, and gates fail closed.

---

## Gentoo Portage Integration

`docs/gentoo/` and the `FRANKENLIBC_PORTAGE_*` env vars together implement a "let the Gentoo ebuild test phase run under FrankenLibC" workflow:

- `FRANKENLIBC_PORTAGE_ENABLE` (default `1`) is the kill switch
- `FRANKENLIBC_PHASE_ALLOWLIST` (default `src_test pkg_test`) limits which ebuild phases get the preload
- `FRANKENLIBC_PACKAGE_BLOCKLIST` (default `sys-libs/glibc sys-apps/shadow`) prevents preload during sensitive package builds where the host libc itself is being rebuilt
- `FRANKENLIBC_SKIP_STATIC` (default `1`) skips preload when static-only libs are being built
- `FRANKENLIBC_LOG_DIR` (default `/var/log/frankenlibc/portage`) collects structured per-build evidence
- `FRANKENLIBC_PORTAGE_LOG` records hook decisions for debugging

The bundle gives you a real-world stress test surface: run any Gentoo ebuild's test phase under hardened mode and harvest the evidence ledger. This is what surfaces edge cases that the curated smoke battery doesn't cover.

---

## What Makes The Membrane "Transparent"

Most "safer libc" projects are either (a) a wrapper that you must adopt by changing your code, or (b) a sanitizer that needs recompilation and shifts behavior visibly. FrankenLibC's TSM is transparent in a specific technical sense:

- **Caller-invisible.** From the C program's perspective, every call goes through `malloc`, `strlen`, `read`, etc. The symbols, calling convention, errno discipline, and return values match glibc.
- **Replay-deterministic.** Identical inputs and runtime evidence reproduce identical outputs across runs and across machines (modulo the explicit RNG-seeded code paths).
- **Auditable.** Every repair, every denial, every fast-path decision is emittable as a structured evidence record. Nothing is "magic that just happened."
- **Mode-coherent.** Strict mode preserves compatibility-relevant behavior; hardened mode adds repairs that are deterministic refinements of the underlying POSIX contract. Neither mode introduces undocumented behavior.

The math underneath (Galois maps, sheaf consistency, conformal risk, Thompson sampling, SOS certificates, …) is *not* in the call path that contributors see. Contributors write normal Rust, add a fixture, run the gates. The math machinery either compiled down to a few branchless instructions in the hot path, runs at build time, or is tracked in offline proof notes and future proof artifacts. That's what the "developer-transparency contract" in `AGENTS.md` is about.

---

## Frequently-Asked Questions, Part 2

### What's the lifecycle of a closed bead?

```
   bd-xxxxx created
        │
        ▼
   in_progress  ←─ claimed by agent
        │
        │ implementation lands
        ▼
   evidence artifact produced
   (e.g., *_completion_contract.v1.json)
        │
        ▼
   `br close <id> --reason "..."`
        │
        ▼
   `br sync --flush-only` (export to .beads/*.jsonl)
        │
        ▼
   git commit including bead id in subject
        │
        ▼
   audit gate scans for binding artifact
        │
   ┌────┴────┐
   │         │
binding   no binding
present?  artifact?
   │         │
closed!   reopen + flag in audit
```

The "Beads compliance audit" runs against `.beads/issues.jsonl` and `tests/conformance/*_completion_contract.v1.json` to make sure every closed bead has a binding artifact and no false closures exist.

### Why is the membrane in its own crate?

Three reasons:

1. **Compile-time safety policy.** `#![deny(unsafe_code)]` with per-module exceptions is cleaner at crate scope.
2. **Build-time verification.** The membrane crate's `build.rs` synthesizes SOS certificates and audits atomic-barrier coverage. Keeping the membrane in its own crate gives `build.rs` a clean compilation unit to scan.
3. **Dependency direction.** The ABI crate depends on the membrane and the core; the core depends on the membrane; the membrane has no internal dependencies. This DAG makes circular concerns impossible.

### Why so many env vars?

Most of the `FRANKENLIBC_*` vars exist for *gates*, not runtime behavior. The runtime-relevant knobs are essentially just `FRANKENLIBC_MODE` and `FRANKENLIBC_LOG`. The rest configure Gentoo hooks, perf budget enforcement, closure gates, E2E test harnesses, and packaging flows. They are listed in [Configuration](#configuration) above for completeness.

### Why do you keep talking about beads?

Because the work tracking is part of the auditability story. Every implementation effort traces commit → bead → evidence → claim. Without that trace, you can't tell a real claim from an aspirational one. The `[bd-xxxxx]` prefix in commit subjects is what makes the audit gates possible.

### How does the project consult reference glibc behavior?

`AGENTS.md` lists `legacy_glibc_code/` as a notional reference location, but no such directory is checked into this repository. The clean-room rule (also in `AGENTS.md`) is the binding constraint: read upstream glibc to understand what behavior you need to match, then implement from spec; never translate line-by-line. Behavioral parity is enforced via fixtures captured from a real glibc install at build/test time, not by copying source.

### What's in `target/conformance/`?

Generated artifacts from local harness runs and maintenance gates. They are written out for inspection but are not checked into git (they're the *output* of evidence-producing tools, not the input).

### Does it work on macOS or Windows?

Not currently. Linux is the target. The membrane's syscall layer, futex usage, ELF version scripts, and `LD_PRELOAD` story are all Linux-specific. A macOS port would need `DYLD_INSERT_LIBRARIES`, `mach_*` calls, and a totally different version-script story; Windows would need DLL-injection and Win32 API surfaces. Out of scope for v0.1.

### Why pre-1.0?

Because L2 and L3 (standalone replace) aren't done. v1.0 is reserved for that milestone.

### How big does this project want to get?

The classified surface is already 4,119 symbols, which is the practical glibc surface most programs care about. The remaining work is in *semantic depth* per family (full iconv breadth, full locale data, full NSS backends, dynamic loader) and in the L2/L3 standalone-replace artifact, not in adding more symbols.

---

## A Complete Call Trace: `p = malloc(64)`

What actually happens when a C program calls `malloc(64)` against `libfrankenlibc_abi.so` in hardened mode:

```
1. C caller jumps to PLT entry for `malloc`.
2. Dynamic linker resolves `malloc` to FrankenLibC's exported symbol
   (because LD_PRELOAD loaded `libfrankenlibc_abi.so` first).
3. ABI entrypoint in `crates/frankenlibc-abi/src/malloc_abi.rs` runs:
   a. `runtime_policy::decide(ApiFamily::Allocator, ptr=null, size=64,
      is_startup=false, is_null_likely=false, context_flags=0)`
   b. RuntimeKernelSnapshot is sampled atomically from the runtime-math
      controllers (risk, bandit, control, barrier, pareto, design, …).
   c. RuntimeDecision returns {Allow, Fast} based on:
      - mode is HARDENED (so the policy is allowed to repair, but no
        unsafe condition was detected yet)
      - size=64 is below the size-anomaly threshold
      - per-family risk is below alarm threshold
      - bandit chose Fast validation profile
4. The ABI delegates to the allocator path in
   `crates/frankenlibc-core/src/malloc/allocator.rs`:
   a. Size 64 → size class 3 (the bucket holding the 64-byte sizes).
   b. Thread-local magazine for class 3 is consulted via `thread_local!`.
   c. If magazine is non-empty: LIFO pop a free object → fast path done
      in ~30 ns including membrane overhead.
   d. If magazine is empty: bulk-fetch 32 objects from the sharded
      central allocator (shard chosen by thread-affinity hash), drop
      31 into the magazine, return the first to the caller.
5. Allocator generates the 24-byte fingerprint header:
   - `hash = SipHash-2-4((base_addr, size=64, generation=N, secret))`
   - `generation = N` (current generation counter for this slot)
   - `size = 64`
   Header is written at base_addr..base_addr+24.
6. Allocator writes the 8-byte canary at base_addr+24+64.
7. Allocator inserts the (raw_base, user_base, user_size, generation,
   SafetyState=Valid) tuple into the arena shard.
8. Allocator updates the bloom filter with user_base.
9. Allocator's `user_base = raw_base + 24` is the pointer returned to
   the caller.
10. `runtime_policy::observe(ApiFamily::Allocator, Fast, latency_ns,
    denied=false)` records the outcome for the runtime-math controllers'
    next-call state.
11. Pointer returned to caller.
```

End-to-end this is a few hundred nanoseconds on the fast path. The single most expensive contribution is the fingerprint SipHash (~20 ns), and even that is amortized when the magazine hits the fast path because there's no allocator-lock acquisition.

---

## A Complete Call Trace: `free(p)`

```
1. C caller calls `free(p)`.
2. ABI entrypoint in malloc_abi.rs runs:
   a. runtime_policy::decide(ApiFamily::Allocator, ptr=p, size=0,
      is_startup=false, is_null_likely=false, context_flags=FREE)
   b. Membrane validation pipeline runs through stages 1–7:
      - Null check: p is not null → continue
      - TLS cache: hit → snapshot says (Valid, generation=N) → continue
        (or miss → run bloom + arena lookup to confirm ownership)
      - Bloom: positive → continue
      - Arena lookup: (raw_base, user_size=64, generation=N, Valid)
      - Fingerprint: SipHash-2-4 recomputes; matches header → continue
      - Canary: 8-byte check at p+64 → matches → continue
      - Bounds + state: SafetyState=Valid for free → Allow
3. ABI delegates to the deallocator path:
   a. Generation counter for this slot is bumped: N → N+1.
   b. SafetyState in the arena transitions Valid → Freed → Quarantined.
   c. The (raw_base, mapped_size) pair is appended to the shard's
      quarantine queue.
   d. The TLS cache entry is invalidated by epoch advance.
   e. The bloom filter is NOT mutated (would require false-negative
      proof; instead, quarantine drain handles reclamation).
4. If quarantine_bytes > QUARANTINE_MAX_BYTES (64 MiB) or EBR epoch
   advances past safe-reclaim threshold:
   a. Quarantine drain runs under the flat-combining primitive.
   b. Drained objects: SafetyState transitions Quarantined → Recycle.
   c. Slab slots are returned to the central allocator's free list.
   d. Large mmap-backed regions are munmap'd.
5. runtime_policy::observe(...) updates controllers.
```

If the caller had tried to free a freed pointer (double-free), step 2b's arena lookup would have returned `SafetyState=Quarantined` or `Freed`, the runtime policy would have returned `Heal(IgnoreDoubleFree)`, and the deallocator path would have been *skipped entirely*, preserving allocator state and emitting a structured evidence record. In strict mode, the same condition returns an `EFAULT` instead of a heal.

---

## A Complete Call Trace: `pthread_mutex_lock(&m)`

```
1. C caller calls `pthread_mutex_lock(&m)`.
2. ABI entrypoint in pthread_abi.rs runs:
   a. runtime_policy::decide(ApiFamily::Threading, ptr=&m, ...) →
      typically {Allow, Fast} for an established mutex.
3. The native mutex implementation in
   `crates/frankenlibc-core/src/pthread/mutex.rs`:
   a. Reads `state` field of the mutex with Acquire ordering.
   b. If state is Unlocked: CAS Unlocked → LockedBySelf →
      uncontended fast path, return 0.
   c. If state is LockedByOther:
      - Bounded spin (configured count, defeats trivial contention)
      - If still locked, fall through to FUTEX_WAIT with
        FUTEX_PRIVATE_FLAG (0x80).
      - Linux kernel wakes us when an unlocker hits FUTEX_WAKE.
      - Loop: re-attempt CAS.
   d. If state is LockedBySelf and type is RECURSIVE:
      - Increment recursion counter, return 0.
   e. If state is LockedBySelf and type is ERRORCHECK:
      - Return EDEADLK.
4. On unlock:
   a. CAS LockedBySelf → Unlocked, then FUTEX_WAKE one waiter.
5. runtime_policy::observe(...) records latency.
```

The same code path implements `NORMAL`, `RECURSIVE`, and `ERRORCHECK` semantics by branching on the type tag in the mutex struct. Both `PTHREAD_MUTEX_INITIALIZER` (static) and `pthread_mutex_init` (dynamic) initialize the state to `Unlocked`. The state machine refuses operations on `Destroyed` mutexes.

---

## POSIX Correctness: Edge Cases Worth Highlighting

POSIX is full of subtle requirements that programs assume but documentation often glosses over. The membrane and core kernels are written to *those* requirements, not the casual ones.

### EINTR Discipline

Every system call that can be interrupted by a signal returns `-1` with `errno = EINTR`. POSIX requires user code to either retry or fail. FrankenLibC's stdio (`fread`, `fwrite`, `getc`, `putc`) and core syscall wrappers (`read`, `write`, `recv`, `send`, `poll`) implement explicit EINTR retry loops in the right places (after I/O operations, not after blocking syscalls that the caller wants to be interruptible).

### Errno Preservation on Success

POSIX prescribes `errno` is not set to zero on success and not modified except by explicit failure. FrankenLibC respects this: every native kernel either calls `set_abi_errno(code)` on failure or leaves `errno` untouched. Inadvertent `errno=0` writes on success paths would corrupt programs that test `errno` after a sequence of calls.

### Partial Writes

`write()` may return fewer bytes than requested without setting `errno`. Stdio's `fwrite` loops over partial writes until the buffer is fully drained or an error occurs. This is the right contract for `fwrite` (which has no short-write return value), but it's implemented carefully so that `EINTR` mid-loop doesn't lose buffered bytes.

### `ungetc` LIFO Ordering

POSIX guarantees that pushed-back bytes are read in reverse order. The implementation supports a single byte of pushback (the minimum POSIX requires) via the `unget` slot, but the LIFO order is preserved correctly across the buffer-overflow / underflow boundary.

### `setvbuf` Lock-After-First-IO

POSIX forbids `setvbuf` after any I/O has occurred on the stream. The buffer mode is monotonically locked after the first operation; subsequent `setvbuf` calls return `EBUSY` rather than silently corrupting buffer state.

### `realloc(p, 0)` Implementation Choice

POSIX gives implementations choice here (free + return null, or behave as malloc). FrankenLibC consistently treats `realloc(p, 0)` as `free(p)` and returns `NULL` with `errno=0`. The choice is documented in the semantic overlay.

### `fopen` Mode Strings

The `"b"` (binary) and `"x"` (exclusive create) mode characters are parsed and honored. `"x"` maps to `O_EXCL | O_CREAT`; without `O_EXCL`, opening an existing file with `"wx"` would race against a concurrent creator.

### `gai_strerror` Text Alignment

Phase 16 aligned `gai_strerror` output text byte-for-byte with glibc, because some programs use it as a key for error-message dispatch. Off-by-one wording differences silently broke those programs.

### `errno` Across `dl_iterate_phdr`

Iterating program headers must not clobber `errno` set by the caller. The native `dl_iterate_phdr` saves and restores `errno` across its work to avoid violating that invariant.

### Float Formatting Edge Cases

`%g` with very small numbers can produce exponential form that exceeds the requested precision; FrankenLibC's printf engine switches `%g`→`%e` (and `%G`→`%E`) automatically when this happens, matching glibc. Subnormal floats round-trip correctly. `NaN` payload bits are preserved across float arithmetic where the IEEE 754 spec permits.

These are the kinds of things that distinguish "passes the smoke test" from "ships as a libc replacement."

---

## Locking Discipline

Every shared resource has a documented synchronization primitive. The choice of primitive per resource follows the trade-off matrix in [Membrane Concurrency Architecture](#membrane-concurrency-architecture).

| Resource | Protection | Why |
|---|---|---|
| Arena per-shard map (live allocations) | `Mutex<ArenaShard>` (parking_lot) | Writes are point mutations; lock granularity is one of 16 shards |
| Arena quarantine queue | Same shard mutex | Co-locates with the arena writes that produce quarantine entries |
| Bloom filter bitmap | Lock-free atomic `u64` array | Concurrent insertion via `fetch_or`; query via plain load |
| TLS validation cache | Thread-local `Cell`; epoch via global `AtomicU64` | No locks needed; invalidation via `Release`/`Acquire` epoch |
| Page-oracle L1 chunk filter | Atomic `u64` words | Monotone (no removal); concurrent `fetch_or` |
| Page-oracle L2 bitmaps | `BravoRwLock` (lock-free read-mostly variant) | L2 entries are read on every check, written rarely |
| Allocator size-class slab list | `parking_lot::Mutex` per class | Per-class so contention is bounded |
| Allocator large-alloc table | `parking_lot::Mutex` | Large allocs are rare; contention low |
| Mutex internal state | Atomic `u32` + futex | Lock-free uncontended path |
| Condvar internal state | Atomic sequence + futex bitset | Lock-free signal/broadcast |
| Stdio `FILE` struct | `parking_lot::Mutex` (per FILE) | One lock per stream; `flockfile`/`funlockfile` map to it |
| `errno` | Thread-local `Cell<i32>` | No synchronization needed by definition |
| Mode resolution | Atomic `u8` with CAS state machine | One-time initialization; readers are lock-free after |
| Runtime-math controller state | Mixture of seqlock and atomics | Single-writer-per-controller, many readers |
| Evidence ledger ring buffer | Lock-free MPSC | Producers are membrane threads; consumer is the harness |
| Healing-policy registry | `Arc<...>` + RCU-style epoch | Effectively read-only after init |
| Galois map state | Pure-function, no state | Stateless mapping |

The pattern is consistent: contention-prone resources use lock-free primitives; rarely-mutated resources use ordinary mutexes; per-thread state uses thread-locals.

---

## Errno Propagation Discipline

`errno` is a global per-thread integer that programs read to figure out *why* a call failed. Getting it right is harder than it looks.

The FrankenLibC discipline:

1. **One canonical setter:** `set_abi_errno(code)` in `crates/frankenlibc-abi/src/lib.rs`. Every ABI entrypoint funnels failures through this. Centralizing the writes prevents "forgot to set errno" bugs.
2. **Failure paths always set, success paths never touch.** Successful operations leave `errno` exactly as the caller left it. This matters because programs sometimes do:
   ```c
   errno = 0;
   x = strtol(str, &end, 10);
   if (errno) { /* parse error */ }
   ```
3. **Membrane Deny paths set errno too.** It's easy to forget that a denied call also needs an errno value. Every Deny return goes through `set_abi_errno`.
4. **Raw syscall paths translate kernel error codes.** `-EAGAIN` from `read(2)` becomes `errno = EAGAIN; return -1`, never propagated as a Rust `Result` to the caller.
5. **The TLS errno cell survives across FFI boundaries** because it's accessed through `__errno_location()` returning a stable pointer per thread.

Bead `bd-h5x` (raw-syscall migration) was specifically structured to land errno discipline at the same time as the syscall conversions; the two are inseparable.

---

## The Semantic Overlay

`support_matrix.json` says what a symbol *is*. The semantic overlay says what a symbol *means*.

A symbol with `status: "Implemented"` could be:

- **Full** — Native Rust does the full POSIX behavior, byte-for-byte
- **No-op** — Symbol is exported (for ABI compatibility) but does nothing on purpose (e.g., `mallinfo` returns zeros because we don't track those statistics in the new allocator)
- **Fallback** — Implements a documented degraded contract (e.g., `__cyg_profile_func_enter` returns success but doesn't profile)
- **Bootstrap** — Implements the minimum required for process startup, deferred broader coverage (e.g., phase-1 iconv; phase-0 startup)
- **Unsupported** — Exported but always returns an error (e.g., features that are POSIX but not supported on Linux)
- **Proof-gap** — Implemented but lacks a proof-note / obligation entry or future mechanized artifact (a tracked debt)

These five buckets live in `tests/conformance/support_semantic_overlay.v1.json`. The `docs_semantic_claims.v1.json` contract prevents prose in this README or `FEATURE_PARITY.md` from promoting taxonomy ownership to full semantic parity by accident.

"100% native coverage" is a *taxonomy* claim. The number of symbols at "Full semantic parity" is meaningfully smaller and grows along a different schedule. Conflating the two is a category error this project refuses to commit.

---

## Three-Tier Allocator

```
                       malloc(n)
                          │
                          ▼
              ┌────────────────────────┐
              │ Membrane validation    │
              └────────────────────────┘
                          │
                  size_class = bucket(n)
                          │
        ┌─────────────────┼─────────────────┐
        ▼                 ▼                 ▼
   n ≤ 32 KiB?      thread magazine    n > 32 KiB?
        │           hit (LIFO pop)         │
        ▼                                  ▼
   ┌──────────┐                       ┌──────────────┐
   │ Slab     │                       │ LargeAllocator│
   │ allocator│                       │ (mmap path)  │
   │ (32 size │                       │              │
   │ classes) │                       │ 4 KiB-aligned│
   └──────────┘                       │ 1<<32 base   │
        │                             └──────────────┘
        ▼                                  │
   64 KiB slab                             ▼
   intrusive free list                Direct mmap
        │                             of (n + 32 + page rounding)
        ▼                                  │
   Fingerprint header                      ▼
   + user region                      Same fingerprint
   + trailing canary                  + canary discipline
        │                                  │
        ▼                                  │
   Arena insert                            │
   (shard hash)                            │
        │                                  │
        ▼                                  ▼
   Pointer returned ◄────────────────────────
```

Three tiers because workloads are bimodal: most allocations are small and short-lived (favor thread-local magazines), some are large and slab-incompatible (favor `mmap`), and the central allocator only needs to handle the spillover. Within each tier, the membrane's metadata discipline is identical (fingerprint, canary, arena, bloom), so the failure-detection guarantees don't depend on which tier serviced the allocation.

---

## Replacement-Level Promotion Gates

Each level promotion is gated by a specific set of evidence requirements. The contracts live in `tests/conformance/replacement_levels.json`.

### L0 → L1 (Hardened Interpose)

Required:

- Curated `LD_PRELOAD` smoke battery green in both strict and hardened modes
- `verify-membrane` healing oracle passes all 14 cases in both modes
- All `*_completion_contract.v1.json` artifacts present for closed beads
- All `*_cli_contract.v1.json` manifests pass meta-gates
- `support_matrix.json` has zero unclassified symbols
- Perf gate: hardened-mode overhead < 200 ns/call on the membrane budget
- Drift: documentation and machine artifacts agree on every claim field

### L1 → L2 (Standalone-Ready)

Additional requirements:

- Zero residual host-glibc symbol references in the produced `cdylib` (validated by `nm`-based gate)
- A fully exercised owned-unwinder ABI (`owned_unwind_abi.rs`), with no host libgcc fallback
- Full `iconv` codec coverage matching at minimum the `iconvdata` subset shipped by glibc-2.40
- NSS plugins implemented or documented unsupported with explicit semantic overlay
- Full pthread closure including barrier, spinlock, named semaphore, and cancellation cleanup handlers
- Full dynamic loader: `dlopen` of arbitrary shared libraries without host `ld-linux` fallback
- Startup proof rows for `__libc_start_main` extended to cover full `csu` + TLS init-order hardening

### L2 → L3 (Standalone)

Additional requirements:

- Replacement artifact (`libfrankenlibc_replace.so`) builds and runs without `LD_PRELOAD` (used as the *primary* libc for a test process)
- Multi-arch: at minimum x86_64 and aarch64 produce passing artifacts
- Distribution packaging contract: produces installable packages for at least one Linux distribution
- Long-tail stress: 24-hour soak tests across the curated workload set without divergence
- Performance: hardened mode within 2× of native glibc on the standard benchmark suite

"Standalone replace" is not a binary claim; it's a sequence of evidence-backed promotions, each of which closes a specific class of dependency on the host. That is the point of the staged-promotion structure.

---

## What We Deliberately Didn't Build

Not every libc concern belongs in scope. Listing the non-goals explicitly is part of the design contract.

- **A whole-program verifier.** The membrane operates at the libc boundary. Application-level memory bugs that never cross libc are invisible to it. This is by design; a whole-program verifier is a different project.
- **A sanitizer for development.** ASan, UBSan, MSan, and TSan are excellent at compile-time instrumentation. FrankenLibC is not trying to compete with them; it operates on already-compiled binaries via interposition.
- **A kernel sandbox.** seccomp, Landlock, namespaces, and capability systems live in the kernel. FrankenLibC is userland; it consumes kernel facilities, it doesn't replace them.
- **A drop-in libc for setuid binaries.** The kernel ignores `LD_PRELOAD` for setuid; an alternative deployment story is needed for those. We don't pretend otherwise.
- **macOS or Windows.** Out of scope for v0.1.
- **A modified kernel ABI.** Every syscall path goes through the standard Linux ABI; we don't require kernel patches.
- **A new memory-safety language.** Rust is the implementation language. C is the interface. We don't propose changes to either.
- **A new build system.** Standard Cargo. No bespoke build infrastructure beyond `build.rs` for SOS synthesis and barrier audit.
- **A new package manager or distribution.** Build from source, install into a prefix, point `LD_PRELOAD` at it.
- **An eBPF agent.** eBPF observes the kernel from the inside; FrankenLibC observes libc from the outside. Complementary, not competing.

"What we didn't build" is the same discipline as "what we *can* finish". Bounding the scope tightly is what makes the L2 and L3 promotions achievable rather than aspirational.

---

## Interpose vs Replace: The Technical Differences

The two artifacts solve different problems even though they share most of the same code.

| Property | Interpose (`libfrankenlibc_abi.so`) | Replace (`libfrankenlibc_replace.so`) |
|---|---|---|
| Deployment | `LD_PRELOAD` alongside host glibc | Drop-in replacement; host glibc not loaded |
| Process map | Both `libc.so` (host) and `libfrankenlibc_abi.so` mapped | Only `libfrankenlibc_replace.so` mapped |
| Startup | Host glibc handles `_start`; we intercept after | We own `_start` and the dynamic linker handoff |
| Loader | Host `ld-linux.so` resolves symbols; we hijack at the symbol-resolution layer | Own loader path or compatible system loader |
| TLS init | Host glibc sets up TLS; we use our own keys for membrane state | We initialize the entire TLS layout |
| Unwinding | Host libgcc may participate | Owned unwinder (`owned_unwind_abi.rs`) only |
| `errno` storage | Our TLS cell + glibc's TLS slot are both live | Only our TLS cell |
| `dlopen`-able by program | Host glibc still does some of it | We do all of it |
| `LD_PRELOAD` ignored for setuid | Yes (kernel policy) | N/A — we *are* libc |
| Symbol resolution for internals | Mix of native (in the classified surface) and host (for non-classified or pre-bound symbols) | All native or out-of-scope |

The interpose artifact is what you can use *today*. The replace artifact is the L2/L3 milestone. The classified surface is 100% native on both; the difference is in what *else* is in the process.

---

## The Bead-Tracker Workflow

`beads_rust` (`br`) is the project's local-first issue tracker. It is **not** GitHub Issues; the `.beads/issues.jsonl` is a checked-in JSONL file that's the source of truth, with a derived SQLite DB cache for the TUI.

The tracker integration is part of the auditability story:

```
Bead is created:        br create --title "..." --type=task --priority=2
Bead is picked up:      br update bd-xxxxx --status=in_progress
Work happens:           code lands; binding evidence artifact lands
Bead is closed:         br close bd-xxxxx --reason "Completed; see <path>"
Tracker is flushed:     br sync --flush-only  → .beads/issues.jsonl
Commit lands:           git commit -m "[bd-xxxxx] ..."
Audit gate scans:       does .beads/issues.jsonl show closed?
                        does a binding *_completion_contract.v1.json
                        exist for bd-xxxxx?
                        ✓ → bead is auditable-closed
                        ✗ → bead is reopened or flagged
```

The bead ID conventions:

- `bd-<random>` for a one-off task
- `bd-<random>.<n>` for a child of a parent epic
- `bd-<random>.<n>.<m>` for a grandchild (audit-debt cleanup)
- `bd-<random>.bind` for a binding-evidence-only child
- `bd-<random>.close` for an explicit closure-evidence child

This structure is what makes `[bd-xxxxx]`-prefixed commit messages mechanically scannable. The pattern is documented in `AGENTS.md` and enforced by the audit gates.

---

## Conformance Fixture Format

A conformance fixture is a JSON file under `tests/conformance/fixtures/<family>/`. Schematically:

```json
{
  "schema_version": "v1",
  "family": "string_ops",
  "source_commit": "<git rev-parse HEAD>",
  "generated_at_utc": "2026-05-15T20:14:00Z",
  "host_libc": "glibc-2.38",
  "cases": [
    {
      "id": "memcpy/aligned/small",
      "fn": "memcpy",
      "args": {
        "dst": {"type": "bytes", "size": 64, "fill": "AA"},
        "src": {"type": "bytes", "size": 64, "fill": "BB"},
        "n": 32
      },
      "expected": {
        "return": "dst",
        "dst_after": {"prefix": "BB×32", "suffix": "AA×32"}
      }
    },
    ...
  ]
}
```

`capture` runs each case against host glibc to populate `expected`. `verify` runs each case against FrankenLibC and compares against `expected`. Differences are categorized:

- **Exact match** — pass
- **Allowed divergence** — declared in `oracle_precedence_divergence.v1.json` (e.g., locale-data differences)
- **Bug** — fail, with the specific case and divergence noted

This pattern lets the project add a new behavior contract by *capturing* it from glibc once, then asserting parity in CI forever after.

---

## Cross-Architecture: aarch64 Today

x86_64 is the primary target. aarch64 is gated and tested via cross-compile. The aarch64-specific completion contracts:

- `aarch64_arch_regression_gate_completion_contract.v1.json` — Ensures aarch64 builds remain green
- `aarch64_conformance_perf_matrix_completion_contract.v1.json` — Performance parity matrix
- `aarch64_raw_syscall_tls_completion_contract.v1.json` — TLS layout differences and raw-syscall correctness

The cross-compile gate (`scripts/check_aarch64_crosscompile.sh`) builds the workspace with `--target aarch64-unknown-linux-gnu` and asserts that:

- All crates compile cleanly
- The version script `libc.map` exports the right symbols
- The native syscall layer correctly uses the aarch64 syscall numbering (different from x86_64)
- The futex implementation uses the right argument-passing convention
- TLS access uses the aarch64-specific `tpidr_el0` register rather than x86_64's `fs:`

What's *not* yet done on aarch64:

- Full ABI-fixture differential coverage (the fixture corpus is x86_64-captured)
- Hardware-transactional-memory fast path (HTM is x86-specific; aarch64 needs its own LSE / SVE equivalents)
- Production `LD_PRELOAD` smoke run (curated battery is x86_64-only today)

RISC-V, MIPS, and others are explicitly out of scope for v0.1.

---

## Performance: What We Measure and How

The performance discipline is "measure, don't assume."

**Membrane overhead per call.** Criterion benches in `crates/frankenlibc-bench/` measure the validation-pipeline cost. Target: < 20 ns strict, < 200 ns hardened. Current numbers on a tuned x86_64 host with `cpupower frequency-set --governor performance` and `FRANKENLIBC_BENCH_PIN=1` typically come in well inside budget.

**End-to-end latency.** The preload smoke harness records baseline (host glibc) and preload (FrankenLibC) wall-clock latency for each program. The latency ratio is the headline number; > 2× is a perf regression that fails `startup_perf_regression`.

**Allocator throughput.** `fixture_malloc_stress.c` runs concurrent alloc/free against multiple threads and compares operation counts to glibc.

**String kernels.** Per-byte throughput for `memcpy`, `memmove`, `memset`, `strlen`, `strchr`, `strstr` measured at small / medium / large sizes; the membrane overhead is amortized over the data movement.

**Concurrency primitives.** Bench matrix in `frankenlibc-bench` measures flat-combining vs lock-based access patterns at controlled contention levels.

**Perf budget enforcement.** `scripts/check_perf_regression_gate.sh` compares the current run against rolling baselines stored in `scripts/perf_baseline.json` (with the schema spec at `tests/conformance/perf_baseline_spec.json`). `FRANKENLIBC_PERF_MAX_REGRESSION_PCT=15` is the default budget. Overloaded hosts (load average > 0.85 × CPU count) get skipped via `FRANKENLIBC_PERF_SKIP_OVERLOADED=1` to keep the evidence trustworthy.

What we *don't* measure (yet):

- Real production application latency at p99 (needs broader workload coverage)
- Cache-line collision behavior in the fingerprint header layout (known not-yet-tuned area)
- HTM commit success rates under real contention (needs production-shape workloads)

---

## Comparison to Other Safer-libc Approaches

| Approach | Mechanism | Scope | FrankenLibC contrast |
|---|---|---|---|
| **AddressSanitizer (ASan)** | Shadow memory + compile-time instrumentation | Whole program, dev-time | We operate at runtime on already-compiled binaries; no shadow memory |
| **MemorySanitizer (MSan)** | Uninitialized-read detection via shadow memory | Whole program, dev-time | Same — we don't need source or recompilation |
| **MTE (Memory Tagging Extension)** | Hardware-tagged pointers | Allocator-level, requires HW support | We tag in software via SipHash fingerprint; portable; doesn't need MTE |
| **Capsicum / pledge** | Capability- or pledge-based syscall restrictions | OS-level | Complementary; we don't restrict syscalls, we validate libc usage |
| **gVisor** | User-mode kernel that intercepts syscalls | Kernel-replacement sandbox | We don't replace the kernel; we sit one layer up |
| **mimalloc / tcmalloc / jemalloc** | Drop-in safer allocator | malloc-only | We replace much more than malloc; allocator is just one of dozens of families |
| **GrapheneOS hardened_malloc** | Hardened allocator with guard pages | malloc-only | Similar threat model for malloc; we extend the discipline across the libc surface |
| **musl libc** | Cleaner C reimplementation of libc | Whole libc | We're memory-safe in Rust; we preserve glibc-shape compat; staged replacement |
| **uclibc / dietlibc** | Smaller libc for embedded | Whole libc | Different target; we're not embedded |
| **picolibc / newlib** | Bootstrap libc for embedded | Whole libc | Different target |
| **Wuffs (Wrangling Untrusted File Formats Safely)** | Safe-by-construction parsers | File-format parsing | Inspirational for parser-class hardening; we apply similar discipline at libc boundary |
| **CHERI** | Capability-machine architecture | HW + OS + compiler | Strictly stronger memory-safety model at the cost of HW; we ship on commodity x86_64/aarch64 |

FrankenLibC's niche sits at the intersection of: glibc-shape compatibility (so existing binaries run), memory-safe implementation in Rust (so safety is structural), runtime enforcement (so deployed binaries are covered), evidence-driven verification (so claims are checkable), and staged replacement (so the path from "interpose" to "standalone" is mechanical, not aspirational).

---

## The Evidence Ledger Record Format

Each runtime decision can emit a structured evidence record. The on-disk format is a fixed-size 256-byte binary symbol (`EvidenceSymbolRecord` declared in `crates/frankenlibc-membrane/src/runtime_math/evidence.rs`, magic `"EVR1"`, with a 64-byte header carrying epoch ID, sequence number, seed, family, etc., a 128-byte symbol payload, and a 32-byte reserved auth-tag slot). For human/tooling consumption the harness's `decode-evidence` and `validate-runtime-evidence-rows` subcommands deserialize records into JSONL with fields like:

```jsonl
{"ts_ns":1747843200000000123,"epoch_id":42,"seqno":42891,"family":"Allocator","decision":"Heal","healing_action":"IgnoreDoubleFree","validation_profile":"Full","latency_ns":137,"ptr":"0x55a2c3d40140","size":64,"generation":7}
```

(Field-name shapes shown are illustrative; the binary format declares the bytes — see `EVIDENCE_HEADER_SIZE = 64`, `EVIDENCE_SYMBOL_SIZE_T = 128`, `EVIDENCE_RECORD_SIZE = 256` in source.) The ring buffer is sized so that ~1 second of activity fits at the expected rate; backpressure is handled by overwriting the oldest record (the consumer is responsible for keeping up). The replay verifier reads JSONL and asserts that a fresh process produces an identical sequence given the same inputs. Replay is how `deterministic_replay.md` becomes operationally testable.

---

## The Membrane Build Script: A Closer Look

`crates/frankenlibc-membrane/build.rs` is 1,030 lines. It performs three jobs at compile time:

### Job 1: SOS Certificate Synthesis

For each of three invariants (fragmentation, thread safety, size class), the build script:

1. Loads the polynomial constraints from the invariant's spec file
2. Constructs the Gram matrix candidate
3. Runs Cholesky decomposition with numerical tolerance `1e-9`
4. If decomposition succeeds, the Gram matrix is PSD, so the invariant has a valid SOS certificate
5. Emits the certificate as a `const` value in the generated source plus a JSON soundness report

A failure at any of these steps fails the build. This means refactors that would break an invariant cannot land silently.

### Job 2: Memory-Model Barrier Audit

The script scans specific source files and counts atomic operations:

```
ptr_validator.rs    expected ≥ 4
arena.rs            expected ≥ 2
tls_cache.rs        expected ≥ 2
config.rs           expected ≥ 15
metrics.rs          expected ≥ 2
pthread/cond.rs     expected ≥ 29
total minimum       ≥ 20+
```

Counts below threshold fail the build. The audit prevents a refactor from silently removing a barrier that's needed for cross-thread visibility, a class of bug that's notoriously hard to detect at runtime.

### Job 3: Feature-Flag Enforcement

The script emits a `compile_error!` if the `runtime-math-production` feature isn't enabled:

```
frankenlibc-membrane requires the `runtime-math-production` feature
(runtime math kernel is mandatory).
```

This makes accidentally building a non-membrane-enforced library impossible.

---

## Three Sources of Truth

When the README, FEATURE_PARITY.md, and the code disagree, the order of trust is:

1. **`support_matrix.json`** — Per-symbol classification. The maintenance script regenerates the maintenance report from this. If a symbol is `Implemented` in the matrix and `GlibcCallThrough` in code, the build fails the drift gate.
2. **`tests/conformance/*.v1.json`** — Generated reports from the harness. These reflect the *behavior* of the current code against host glibc fixtures.
3. **Documentation** — README, FEATURE_PARITY.md, AGENTS.md. These are summaries; they aim to be accurate but they can lag, and when they do, the gate is the arbiter.

The `docs_semantic_claims.v1.json` claim-field contract enforces this: any claim in README or FEATURE_PARITY.md must map onto a field in the source of truth. Prose that names a number without a corresponding source-of-truth field is a drift bug.

---

## The Bootstrap Problem and How We Solve It

A libc has a unique bootstrap problem: the libc code itself needs allocations, TLS, atomics, and synchronization, but those facilities are themselves implemented by libc. Naïve initialization deadlocks.

FrankenLibC's solution has four layers:

### Layer 1: Pre-TLS Bump Allocator

Before `pthread_key_create` is callable, code that needs to allocate (`dlerror`, dl-init, the `__libc_start_main` validation envelope) uses a small static bump arena. The bump pointer is an atomic offset; allocations from it are never freed. This breaks the "membrane allocation requires TLS cache requires allocation" cycle by giving early code a non-membrane allocation path.

### Layer 2: Reentrancy Guards in Hot Paths

`dlerror` is a famous source of reentrant TLS panic. The implementation wraps the TLS access in a reentrancy guard: if we detect that we're already inside `dlerror` on this thread, we return a pre-computed error string instead of recursing. The same pattern is used in `malloc` (per-thread reentry guard prevents allocator-from-allocator recursion under sanitizer-style inspection).

### Layer 3: The Resolving Mode Window

When the very first membrane call lands, it discovers `state == UNRESOLVED`. It CAS's `UNRESOLVED → RESOLVING`, reads `FRANKENLIBC_MODE` from the environment, parses it, and CAS's to the terminal state. *During* that window, any reentrant call (e.g., from `getenv` itself, which might be needed for the mode lookup) sees `RESOLVING` and returns a safe passthrough decision. The terminal state, once reached, is read with a single `Relaxed` atomic load: invisible cost on the steady-state hot path.

### Layer 4: Startup Phase Markers

`FRANKENLIBC_STARTUP_PHASE0` env var and the corresponding atomic flag let the membrane recognize when it's still in `__libc_start_main`'s validation envelope and apply different validation policy (essentially: pass through trivial calls, only validate suspicious ones). This avoids a "membrane wants to instrument printf to log its decision, but printf needs the allocator, which the membrane is currently validating" recursion.

These are first-class design constraints, not bolt-on hacks. The bootstrap problem is *the* hardest part of writing a libc.

---

## A Complete Call Trace: `printf("%d %s\n", 42, "hello")`

```
1. C caller jumps to PLT entry for `printf`; loader resolves to
   FrankenLibC's `printf`.
2. ABI entrypoint in stdio_abi.rs runs runtime_policy::decide(
     ApiFamily::Stdio, ptr=&stdout, size=0, ...).
3. ABI calls into the native printf engine in
   crates/frankenlibc-core/src/stdio/printf.rs:
   a. Parse the format string "%d %s\n" into directive nodes:
      [Directive::Conversion(Spec{conversion=d, width=0, prec=-1, …}),
       Directive::Literal(" "),
       Directive::Conversion(Spec{conversion=s, …}),
       Directive::Literal("\n")]
   b. For %d: pop one i64 from va_args → 42. Format into a stack
      buffer with bound = width + prec + 64. Emit "42".
   c. For " ": emit literal.
   d. For %s: pop one *const c_char from va_args → "hello\0". Validate
      the pointer through the membrane (it must be readable and the
      first byte through the implicit NUL must be in a tracked region).
      Emit "hello".
   e. For "\n": emit literal.
4. The emit sink is `stdout` (a FILE*) — engine routes bytes to its
   buffer subsystem:
   a. stdout's buffer mode is line-buffered (because stdout is a TTY)
      → use BufMode::Line.
   b. Bytes accumulate until the "\n" arrives.
   c. On newline, `rposition` finds the last newline; the range
      [0..=last_nl] flushes via `write(STDOUT_FILENO, ...)`.
   d. Bytes after last_nl (none in this case) remain in the buffer.
5. Each `write` call goes through io_abi → runtime_policy::observe →
   raw syscall veneer in core/src/syscall/.
6. EINTR is handled by retry loop; partial writes are handled by loop
   until the buffer is fully drained.
7. printf returns the count of bytes written.
```

Correctness invariants exercised by this path: format-string parsing is bounded so a crafted format cannot exhaust memory; the `%s` pointer validation prevents reading past unmapped memory; line-buffered `rposition` flush keeps the cost proportional to the last newline; the EINTR retry preserves POSIX semantics.

---

## A Complete Call Trace: `getaddrinfo("example.com", "80", ...)`

```
1. C caller calls getaddrinfo with node="example.com", service="80".
2. ABI entrypoint in resolv_abi.rs:
   a. runtime_policy::decide(ApiFamily::Resolver, ...)
   b. Validate the node, service, hints pointers via membrane.
3. Native resolver in core/src/resolv/mod.rs:
   a. Try to parse "example.com" as an IPv4 literal → fail.
   b. Try to parse as an IPv6 literal → fail.
   c. Open /etc/hosts (cached file descriptor + mtime check for
      cache invalidation).
   d. Scan /etc/hosts line by line; tokenize address + hostname +
      aliases.
   e. Match "example.com" against the host map.
   f. If matched, parse the address into a sockaddr_in or sockaddr_in6.
   g. Parse "80" against /etc/services (or as a literal port number).
   h. Build an `addrinfo` chain — one node per (family, socktype,
      protocol) combination.
4. Return EAI_NONAME (-2) if no match found, or 0 with a populated
   addrinfo chain.
5. The caller frees the chain via freeaddrinfo, which is also
   native and walks the chain releasing each node.
```

A few design choices in this trace are worth pointing out:

- **No DNS network I/O** during early process startup. The resolver only talks to local files. A full NSS / DNS backend is a future milestone and would attach through a different module so the bootstrap path stays I/O-free.
- **`/etc/hosts` caching** uses mtime to detect changes; concurrent readers see a stable snapshot via RCU-style epoch.
- **Multi-address support**: a hostname with multiple `/etc/hosts` entries produces an `addrinfo` chain with all of them, matching glibc behavior.
- **Service parsing** handles both numeric strings ("80") and named services ("http") via `/etc/services` lookup.
- **`gai_strerror` text** is byte-aligned with glibc (Phase 16) because some programs key error-handling on the exact string.

---

## Inside `runtime_policy::decide()`

The single chokepoint is ~87 KB of code that integrates all the runtime-math controllers into one decision. Conceptually:

```
inputs:
  family            ∈ ApiFamily  (Allocator, Stdio, Threading, …)
  ptr               *const c_void
  size              usize
  is_startup        bool
  is_null_likely    bool
  context_flags     u32

step 1: resolve mode (cached after first call)
  mode ← STRICT | HARDENED | OFF

step 2: snapshot all runtime-math controllers atomically
  snapshot ← (risk_score(family), bandit_choice(family),
              control_threshold, barrier_admissibility(family),
              pareto_frontier_point, design_probe_state,
              consistency_overlap, eprocess_alarm,
              cvar_tail_state, hji_safety, mean_field_pressure)

step 3: combine into a decision
  if !barrier_admissibility(family):
    return Deny  ← runtime guard says this family is currently inadmissible
  if eprocess_alarm:
    return Check{profile: Full}  ← forced full validation under alarm
  if risk_score > threshold:
    return Check{profile: Full}
  if bandit_choice == Fast:
    return Allow{profile: Fast}
  return Allow{profile: Full}

step 4: in hardened mode, classify suspicious patterns
  if hardened && pattern_matches_unsafe(family, ptr, size, ...):
    healing ← lookup_healing(family, pattern)
    return Heal{action: healing}

step 5: return RuntimeDecision
```

The reason to layer this much machinery isn't theoretical elegance; it's *adaptivity*. The bandit learns the routing for *this* workload; the e-process raises an alarm when *this* workload starts producing anomalies; the CVaR controller protects against tail latency that hand-picked thresholds would miss; the HJI safety controller refuses decisions that could land in the unsafe set under the worst attacker model.

`observe()` runs after the call completes, feeding `(family, profile, latency_ns, denied)` back into each controller so the next call's decision incorporates this call's outcome. The combination is *anytime-valid*: finite-sample guarantees hold at every call number, not just asymptotically.

---

## Memory-Model Atomic Ordering

The membrane uses every atomic ordering primitive Rust offers, and the choices matter. The discipline:

| Operation | Ordering | Reason |
|---|---|---|
| Read of cached mode (after init) | `Relaxed` | Mode is immutable post-init; any thread sees the terminal value |
| CAS to initialize mode | `AcqRel` | Establishes happens-before with the env read |
| TLS-cache epoch increment | `Release` (writer), `Acquire` (reader) | Reader must see all writes that happened before the writer's epoch bump |
| Bloom filter `fetch_or` | `Relaxed` | Insertion is monotone; concurrent operations commute |
| Bloom filter `load` (query) | `Relaxed` | Query tolerates seeing an old state because the filter is monotone |
| Mutex state CAS (uncontended path) | `Acquire` (lock), `Release` (unlock) | Standard mutex semantics |
| Arena generation increment | `AcqRel` | Establishes happens-before with the slot-recycle path |
| Metrics counters | `Relaxed` | Counter accuracy doesn't need ordering |
| Evidence ledger seqno | `AcqRel` | Consumer must see the ledger entry the producer wrote |
| Runtime-math snapshot read | `Acquire` (cross-controller) | Avoid torn reads across controllers |
| Quarantine drain release | `SeqCst` (rare) | Quarantine drain must serialize with all readers |

Wrong ordering here is the kind of bug that *only* surfaces under heavy multi-thread load, takes weeks to diagnose, and resists reproduction. The build-time barrier audit (in `build.rs`) enforces minimum atomic-operation counts per file to prevent silent ordering changes during refactors.

---

## Versioned Symbol Linking

Linux dynamic linking is *versioned*. A binary built against glibc-2.34 expects `__libc_start_main@@GLIBC_2.34`; a binary built against glibc-2.17 expects `__libc_start_main@@GLIBC_2.17`. The two have different argument conventions.

FrankenLibC's `version_scripts/libc.map` (4,687 lines) is a GNU ld version script that maps symbols to versions. The actual structure on disk:

```
GLIBC_2.2.5 {
  global:
    __errno_location;
    malloc;
    free;
    memcpy;
    /* thousands of others */
    ynl;

  local:
    *;
};

GLIBC_2.11 {
  global:
    __longjmp_chk;
} GLIBC_2.2.5;
```

Almost the entire surface exports under `GLIBC_2.2.5`. The `GLIBC_2.11` block carries only one symbol (`__longjmp_chk`, used by `_FORTIFY_SOURCE` builds) and inherits from `GLIBC_2.2.5`. The trailing version on a block (`} GLIBC_2.2.5;`) creates a parent relationship: callers asking for the older parent version still resolve a child-version symbol. This is how a single `.so` file can export the same symbol at multiple versions simultaneously, and how host-glibc-versioned binaries find a compatible entry without us declaring every legacy version explicitly.

In Rust, the version binding is done with assembly `.symver` directives emitted by the build system. For example, `fortify_abi.rs` contains:

```rust
".symver __frankenlibc_longjmp_chk_impl,__longjmp_chk@@GLIBC_2.11, remove"
```

This makes the Rust function `__frankenlibc_longjmp_chk_impl` available to dynamic linking as `__longjmp_chk@@GLIBC_2.11`. The `, remove` directive cleans up the underlying Rust name from the exported set so only the versioned alias is visible.

When `dlvsym_next` is called from `host_resolve.rs`, it walks the *host* glibc's version-name space looking for the requested `(symbol, version)` pair. Different subsystems pick different priority chains for the host-fallback case — `pthread_abi.rs` tries `GLIBC_2.34 → GLIBC_2.3.2 → GLIBC_2.2.5` for `pthread_create`, while `dlfcn_abi.rs` accepts any of `GLIBC_2.2.5`, `GLIBC_2.17`, or `GLIBC_2.34` from a caller's request. This lets a subsystem try the newest host API first and fall back to older variants for compatibility with older host-glibc installs.

---

## The Page Oracle: A Closer Look

`crates/frankenlibc-membrane/src/page_oracle.rs` is a two-level page bitmap that answers "is this page ours?" in O(1).

### Layer 1 (L1): Chunk Presence Filter

The address space is sliced into 16 MiB chunks (4096 pages × 4 KiB/page; `decompose(page) = (page / PAGES_PER_L2, page % PAGES_PER_L2)`). The chunk index is conceptually `addr >> 24` since `2^24 = 16 MiB`. L1 is a 65,536-bit bloom-style presence filter (`[AtomicU64; 1024]`) where each chunk index is mixed through a MurmurHash-3-style finalizer and then folded into a single bit. Each bit means "some chunk hashing here may have an L2 bitmap published."

L1 is monotone: bits only turn on, never off. Consequences:

- Concurrent `fetch_or` produces no torn updates
- A zero L1 bit is sufficient evidence that no allocation lives in any chunk hashing here (skip the L2 lookup)
- A one L1 bit may be a false positive; promotion to L2 is required for confirmation

### Layer 2 (L2): Per-Chunk Page Refcount Array

When the allocator publishes a page that lives in a chunk the L1 has flagged, an L2 entry is created tracking the individual 4 KiB pages within that chunk. The implementation uses an `[AtomicU32; PAGES_PER_L2]` refcount array (16 KiB per chunk; the source-comment shorthand says "512-byte bitmap" but the actual struct is an atomic-refcount array, supporting up to 2³² independent ownership claims per page). L2 maps are stored in a `HashMap<usize, Arc<L2Bitmap>>` under a `BravoRwLock` (a lock-free read-mostly RwLock variant) so concurrent readers don't contend.

### The Bravo RW Lock

`BravoRwLock` is a reader-biased RwLock that augments a conventional reader/writer lock with a visible-readers table. Readers hash their thread identity with the lock address to claim a slot in the table and bypass the base lock entirely; writers revoke the reader bias, acquire the base lock, then wait for the visible readers to drain before mutating. The technique is from Dice & Kogan, *BRAVO — Biased Locking for Reader-Writer Locks* (USENIX ATC 2019). Source lives in `crates/frankenlibc-membrane/src/bravo.rs`. It's used in the membrane wherever read-mostly access patterns dominate; the page oracle is the canonical example.

### Performance vs Arena Lookup

| Path | Cost |
|---|---|
| Bloom filter alone | ~10 ns |
| Page oracle L1 hit (zero bit) | ~5 ns |
| Page oracle L1 + L2 (one bit, but page not set) | ~15 ns |
| Page oracle L1 + L2 hit | ~20 ns |
| Full arena shard lookup | ~30 ns |

The oracle is in the pipeline because for unknown pointers (no TLS cache hit, no fingerprint header), it provides a cheaper "definitely not ours" rejection than a full arena scan.

---

## Generation Counter Discipline

Each arena slot has a `u64` generation counter. The counter increments every time the slot transitions `Quarantined → Recycle`. A pointer carrying the old generation cannot validate against the new occupant.

### Overflow analysis

A `u64` counter overflows after `2⁶⁴ ≈ 1.8 × 10¹⁹` increments. At one million allocations per second per slot (extreme), that's `5.8 × 10⁵` years of continuous saturation per slot. In practice the counter ages much more slowly because slots are reused only after quarantine eviction.

Even under adversarial workloads, generation overflow is not a practical concern; by the time a counter could wrap, the process has been alive for cosmic-timescale durations. The earlier `u32` design (replaced in Phase 6) had a meaningful wrap-around concern; the `u64` upgrade closed it.

### Why generation must outlive the slot

If a slot transitions through `Live(gen=N) → Freed(gen=N) → Quarantine(gen=N) → Recycle → Live(gen=N+1)`, the generation must increment *before* the slot becomes recyclable. The arena enforces this ordering via `AcqRel` on the increment, so any thread observing the new occupant via the membrane will also observe the bumped generation, and any stale pointer carrying `gen=N` will see the mismatch.

---

## `.beads/issues.jsonl` — A Checked-In Tracker

The bead tracker is not GitHub Issues. It's a JSON Lines file checked into `.beads/issues.jsonl` and accessed via the `br` (beads_rust) CLI.

Schematic of a bead record:

```json
{
  "id": "bd-h5x",
  "title": "Eliminate libc::syscall callthrough surface",
  "status": "closed",
  "priority": 1,
  "type": "epic",
  "created_at": "2026-03-22T12:00:00Z",
  "updated_at": "2026-05-09T18:30:00Z",
  "closed_at": "2026-05-09T18:30:00Z",
  "dependencies": ["bd-..."],
  "parent": null,
  "summary": "...",
  "labels": ["raw-syscall", "membrane", "phase9"],
  "completion_artifact":
    "tests/conformance/syscall_migration_completion_contract.v1.json",
  "evidence_commits": ["8f96a740", "c62c4770", "..."]
}
```

`br ready --json` returns the unblocked, highest-priority items. `bv --robot-triage` returns graph-aware analysis (PageRank, critical path, bottleneck detection, cycle detection). `br close <id>` flips the status and bumps `closed_at`. `br sync --flush-only` re-serializes the bead database to JSONL without invoking git (commits stay manual).

The JSONL format is intentional: line-oriented, diff-friendly, easy to mine with `jq`, and survives merge conflicts gracefully (each bead is one line, so the merge surface is per-bead, not the whole tracker).

---

## Multi-Agent Workflow Layer

The repository contains 4,932 commits made by one author working in tandem with a small swarm of AI agents. The coordination layer:

| Tool | Role |
|---|---|
| `br` (beads_rust) | Local-first issue tracking with dependency graph; the `bd-*` IDs in commit subjects |
| `bv` | Graph-aware triage engine over beads (PageRank, critical path, cycles, k-core) |
| `cass` | Cross-agent session search; lets a new agent find what a previous agent solved |
| `mcp-agent-mail` | Inboxes, file reservations, threaded messages between concurrent agents |
| `cm` | Procedural memory for AI coding agents; learns from past sessions |
| `ntm` | Multi-tmux orchestration for a swarm of panes |
| `ubs` | Pre-commit bug scanner |
| `rch` | Remote compilation offload across worker VPSes |
| `dsr` | Doodlestein Self-Releaser — fallback release infrastructure |
| `slb` | Two-person rule guard for destructive commands |
| `sbh` | Disk-pressure defense for AI coding workloads |

The combination is what makes the 4,932-commits-in-97-days pace possible. Without the bead tracker, claims about closure would drift; without file reservations, two agents would clobber each other; without the bug scanner, the membrane's invariants would silently regress; without remote compilation offload, a single workstation would have melted under the cargo build load.

None of this tooling is in the runtime artifact; it's purely the *development* workflow, and most of it lives outside this repository in companion projects under `/dp/`.

---

## Reproducibility and Determinism

A safety-critical libc must be deterministically replayable. The mechanisms:

1. **Fixed RNG seeds** for any randomized path that goes through tests. `FRANKENLIBC_E2E_SEED=42` is the default.
2. **Fixed clocks where appropriate.** Test harnesses use a frozen monotonic clock; the membrane uses real clock in production but emits `ts_ns` to the evidence ledger so traces can be aligned post-hoc.
3. **Evidence replay verifier.** `tests/conformance/runtime_evidence_replay_gate.v1.json` and the replay tool re-run a recorded decision sequence against a fresh process and assert match.
4. **Controller snapshot hashing.** Every runtime-math controller's state is hashable to a BLAKE3 digest; the evidence record carries the hash so replay can verify the same controller state at each decision point.
5. **Deterministic SOS certificate generation.** The build script produces identical certificates given identical sources, so the build artifact hashes are reproducible.
6. **Deterministic fixture-pack format.** Fixtures are JSON with stable key ordering; capture is rerun-stable.
7. **No `HashMap` iteration in test-relevant paths.** Where ordering matters for reproducibility, `BTreeMap` is used.

The `deterministic_replay.md` proof note captures the intended property: same inputs + same evidence + same controllers → same outputs.

---

## Failure-Mode Catalog

Every category of detectable issue and what surfaces it:

| Failure | Detected by | Action |
|---|---|---|
| Null pointer to libc | Membrane stage 1 (null check) | `EINVAL` / `ReturnSafeDefault` |
| Use-after-free (any) | Generation counter mismatch | `IgnoreDoubleFree` / `ReturnSafeDefault` / `Deny` |
| Use-after-free in quarantine window | Arena state `Quarantined` | Same — UAF visible without segfault |
| Buffer overflow | Trailing canary mismatch | `TruncateWithNull` / `EFAULT` |
| Buffer underflow | Fingerprint header mismatch | `EFAULT` |
| Double-free | Generation mismatch in arena | `IgnoreDoubleFree` |
| Foreign-free (pointer not from us) | Bloom + arena absence | `IgnoreForeignFree` |
| Out-of-bounds size argument | Bounds check vs `user_size` | `ClampSize` |
| Realloc of freed pointer | Arena state `Freed` / `Quarantined` | `ReallocAsMalloc` |
| Cross-thread `longjmp` | Owner-thread guard check | `ForeignContext` error |
| Mode-tag mismatch (`longjmp` from wrong mode) | Mode tag check | `ModeMismatch` error |
| Corrupted `JmpBuf` | Guard checksum check | `CorruptedContext` error |
| Use of destroyed mutex | Mutex state `Destroyed` | Return `EINVAL` |
| Recursive `ERRORCHECK` mutex lock | Mutex state `LockedBySelf` + type | Return `EDEADLK` |
| Unlock by non-owner | Mutex state check | Return `EPERM` |
| Validation under alarm | E-process exceeds threshold | Force `Full` profile |
| Drift between code and artifact | Maintenance gate | Fail build |
| Stale source commit in evidence | Closure-gate freshness check | Fail gate |
| Closed bead without binding artifact | Audit gate | Reopen / flag |

Each row corresponds to a code path that exists today, not a planned check.

---

## Why Branch Diversity Matters

The design audit (`AGENTS.md`) requires that every major subsystem milestone uses at least 3 distinct math families, including at least one from conformal statistics, algebraic topology, abstract algebra, and Grothendieck-Serre methods. No family can dominate more than 40% of obligations.

This isn't aesthetic discipline. It's structural risk management. A concrete example:

**SIMD/alignment correctness for `memcpy` variants** could be approached purely from algorithm-engineering ("just write good SIMD code"). The branch-diversity rule forces the design to also consider:

- **K-theory transport** (`ktheory.rs`): does the SIMD variant produce semantically-equivalent results across architectures (x86_64 AVX2 vs aarch64 NEON)? K-theory frames this as a question of whether the variant preserves the symbol-level commutative diagram.
- **Clifford / geometric algebra** (`clifford.rs`): are the alignment and overlap edge cases correctly handled? Clifford algebra naturally expresses the rotational symmetries SIMD register layouts exploit.
- **Atiyah-Singer families index**: cross-platform compatibility integrity. Are the SIMD ABI signatures stable under the platform's symbol-versioning rules?
- **Equivariant transport** (`equivariant.rs`) — Representation stability across ISAs: does the SIMD variant produce identical observable effects under the architecture's vector-register equivalence class?

Approaching the same problem from four genuinely different mathematical traditions surfaces edge cases that any single tradition misses. The K-theory view catches symbol-versioning bugs. The Clifford view catches alignment bugs. The Atiyah-Singer view catches compatibility-class bugs. The equivariant view catches cross-ISA observable-effect bugs.

This is the discipline behind the runtime-math controller catalog: every controller exists because some failure mode needs it, and the failure modes themselves are diverse enough that no single mathematical framework covers them all.

---

## What Real Programs Use From libc

A frequency profile of how typical Linux programs exercise libc, as observed from the curated smoke battery and Gentoo Portage runs:

| Family | Approximate share of total libc calls |
|---|---:|
| String / memory (`memcpy`, `strlen`, `memcmp`, `strcmp`, …) | 35% |
| Allocator (`malloc`, `free`, `calloc`, `realloc`) | 15% |
| stdio (`printf`, `fwrite`, `fread`, `fopen`, `fclose`) | 12% |
| File descriptors (`read`, `write`, `close`, `lseek`, `fcntl`, `ioctl`) | 10% |
| Time / clock (`time`, `gettimeofday`, `clock_gettime`) | 6% |
| pthread (`mutex_lock`, `mutex_unlock`, `cond_wait`, `cond_signal`) | 5% |
| signal (`signal`, `sigaction`, `kill`, `raise`) | 4% |
| process (`fork`, `execve`, `wait`, `exit`) | 3% |
| socket / inet | 3% |
| dirent / dlfcn | 3% |
| Everything else (`locale`, `iconv`, `setjmp`, `termios`, `resolv`, etc.) | 4% |

These percentages vary wildly by workload, but the top-5 (string/memory + allocator + stdio + I/O + time) consistently dominate. Those subsystems are where the project invested the most native ownership work first, and where the hardened-mode repair actions matter most.

It also explains where the membrane's TLS validation cache and bloom filter pay for themselves: the hot families (string, allocator) have predictable access patterns that the cache catches with high hit rate, so the global metadata path is reserved for the rare cases that actually need it.

---

## Performance: Cache-Line Layout

False sharing is a real concern in a multi-threaded library where the membrane state is touched on every call. The discipline:

- **The arena's 16 shards** are laid out so each shard's mutex + free-list head live on separate cache lines. A thread allocating in shard 7 doesn't invalidate shard 3's cache line.
- **The bloom filter's `u64` words** are loaded with `Relaxed` ordering so concurrent producers and consumers don't interfere; the array is sized to leave each thread's typical hash range in its own cache lines.
- **The TLS cache** is per-thread (no false sharing by construction).
- **Metrics counters** are sometimes per-thread when contention proves measurable; otherwise atomic with `Relaxed`.
- **The runtime-math controller state** is structured so the hottest fields (mode, current risk threshold, current bandit choice) fit in one cache line, while colder state (controller histories, calibration buffers) is on separate lines.
- **The mode state machine** atomic is placed on its own cache line because it's read on every membrane call.

Cache-line layout is verified empirically through benchmark variance: a 64-byte alignment shift on a hot atomic can change throughput by 5-15% on the membrane budget, which is enough that we measure and don't assume.

---

## Why Rust 2024

The workspace edition is Rust 2024 (`edition = "2024"` in `Cargo.toml`, nightly pinned via `rust-toolchain.toml` to `nightly-2026-04-28`). The specific `#![feature(...)]` gates declared in `crates/frankenlibc-abi/src/lib.rs` are:

- **`c_variadic`** — Lets ABI entry points accept C-style `...` varargs (printf, scanf, syscall variants, etc.) directly in Rust signatures.
- **`rtm_target_feature`** — Enables the x86 Restricted Transactional Memory target-feature gate so the HTM fast path can declare `#[target_feature(enable = "rtm")]`.
- **`stdarch_x86_rtm`** — Exposes `core::arch::x86_64::{_xbegin, _xend}` for the hardware-transactional-memory fast path.
- **`thread_local`** — Enables the `#[thread_local]` attribute on static items for the TLS-cache and errno paths (faster than the `thread_local!` macro form for cross-FFI access).

Edition 2024 also brings `unsafe extern "C"` defaults (which make the FFI boundary explicit in syntax) and tighter `unsafe_op_in_unsafe_fn` checking. The nightly pin is not "we use exotic features"; it's "we need the four `#![feature(...)]` gates above for x86 HTM and varargs, and a frozen nightly date for predictable codegen."

---

## What's In `host_resolve.rs`

`crates/frankenlibc-abi/src/host_resolve.rs` (~23 KB) is the controlled host-glibc resolution surface. It exists because certain runtime paths still need to ask the host glibc for specific symbols (*not* the classified surface) for:

- `dlvsym_next` lookups during the `__libc_start_main` host-fallback chain
- Version-symbol resolution for compatibility shims that need `@@GLIBC_x.y` precision
- One-time bootstrap discovery of host-loader state for the phase-0 startup envelope

Every entrypoint in `host_resolve.rs` is gated by the membrane policy and is logged through the evidence ledger. There are no opaque "just call into glibc" paths; every host-resolution call is named, audited, and replay-deterministic.

This is the practical difference between the L1 interpose artifact and the future L2/L3 replace artifact: the replace artifact removes `host_resolve.rs` entirely, since by definition no host glibc is loaded.

---

## A Complete Call Trace: `pthread_cond_wait(&cv, &m)`

```
1. C caller holds mutex m and calls pthread_cond_wait(&cv, &m).
2. ABI entrypoint in pthread_abi.rs runs runtime_policy::decide(
     ApiFamily::Threading, ptr=&cv, ...).
3. Native condvar in core/src/pthread/cond.rs:
   a. Validate that &cv has the FrankenLibC condvar magic and that
      its 24-byte layout is intact (fits in pthread_cond_t's 48 bytes).
   b. Read the condvar's sequence counter `seq_before` with Acquire
      ordering.
   c. Atomically increment the waiter counter.
   d. Atomically store &m as the associated mutex pointer (or verify
      it matches if already set — POSIX requires the same mutex across
      all waiters).
   e. Call pthread_mutex_unlock(&m) — this is non-trivial because the
      unlock + futex wait must be atomic with respect to a concurrent
      signal/broadcast.
   f. Invoke FUTEX_WAIT_BITSET on the condvar's seq field with
      FUTEX_BITSET_MATCH_ANY (0xFFFFFFFF) and FUTEX_CLOCK_REALTIME
      (256) if CLOCK_REALTIME, FUTEX_CLOCK_MONOTONIC for monotonic.
      The wait condition: seq == seq_before.
   g. Kernel parks the thread until a signaler bumps the seq.
   h. On wake, atomically decrement the waiter counter.
   i. Call pthread_mutex_lock(&m) to re-acquire.
4. runtime_policy::observe(...) records the latency.
5. Return 0.
```

Signal/broadcast on the other side:

```
1. pthread_cond_signal(&cv):
   a. Atomic increment of cv.seq with Release ordering.
   b. FUTEX_WAKE on the seq address, wake count = 1.
2. pthread_cond_broadcast(&cv):
   a. Atomic increment of cv.seq with Release ordering.
   b. FUTEX_WAKE on the seq address, wake count = INT_MAX.
```

The sequence counter is the crucial detail. Without it, a signal that arrives between the waiter's mutex unlock and futex wait would be lost; with it, the futex wait predicate `seq == seq_before` fails (because the signaler already bumped seq), and the syscall returns immediately. The membrane validates the condvar's struct integrity on every call so a stack-allocated condvar that's later overwritten by an unrelated write surfaces as a `CorruptedContext` error rather than mysteriously losing wakeups.

---

## A Complete Call Trace: The Very First Call After `LD_PRELOAD`

`LD_PRELOAD` is set and the program starts. Before `main`, before even `__libc_start_main`, something has to handle the dynamic linker's symbol resolution requests. Here is what happens for the very first FrankenLibC-resolved call:

```
1. Kernel execs the binary; ld-linux.so starts up.
2. ld-linux.so walks DT_NEEDED entries: libc.so.6, optional libpthread,
   etc.
3. LD_PRELOAD prepends libfrankenlibc_abi.so to the search order.
4. ld-linux.so resolves symbols. The first symbol it actually needs
   from libc is typically `__libc_start_main` (for the C runtime
   bootstrap).
5. Looking up `__libc_start_main`: ld-linux.so finds it at
   `__libc_start_main@@GLIBC_2.34` in libfrankenlibc_abi.so.
6. ld-linux.so binds it. Now the BFD's PLT entry for
   __libc_start_main points at FrankenLibC's symbol.
7. Kernel jumps to the binary's _start.
8. _start calls __libc_start_main(main, argc, argv, ...).
9. FrankenLibC's __libc_start_main runs:
   a. Check FRANKENLIBC_STARTUP_PHASE0 atomic flag → false initially.
   b. CAS the flag to true; from now on, membrane policy applies
      relaxed validation (passthrough for trivial calls).
   c. Mode resolution: read FRANKENLIBC_MODE.
      - The state machine is at UNRESOLVED.
      - CAS UNRESOLVED → RESOLVING.
      - getenv("FRANKENLIBC_MODE") — this itself may need the
        allocator, which we haven't fully validated yet.
      - The membrane sees us in RESOLVING and returns passthrough
        decisions for any reentrant calls.
      - Parse the env value: "hardened" → HARDENED, anything else →
        STRICT.
      - CAS RESOLVING → STRICT or HARDENED. Mode is now immutable.
   d. Validation envelope:
      - argv pointer null check.
      - Scan argv up to MAX_STARTUP_SCAN entries; detect unterminated.
      - argc bound: argv_count >= normalized_argc.
      - envp same.
      - auxv: walk key/value pairs, detect truncation.
      - classify_secure_mode(&auxv_pairs): are we running with
        AT_SECURE set? If so, restrict accordingly.
   e. If any validation step fails, the startup policy decides
      between (i) abort outright, or (ii) fall back to host glibc's
      __libc_start_main via the version-symbol chain
      (GLIBC_2.34 → GLIBC_2.17 → GLIBC_2.2.5) discovered through
      host_resolve.rs::host_dlvsym_next_raw.
   f. Run init hooks, then main(argc, argv, envp).
   g. After main returns, run fini and rtld_fini hooks.
10. From here on, every libc call goes through the full membrane.
```

The bootstrap-deadlock-avoidance is everywhere in this flow: the `STARTUP_PHASE0` flag tells the membrane to be permissive; `RESOLVING` state lets `getenv` work without recursing; the pre-TLS bump allocator handles allocations before TLS is alive; the version-symbol fallback chain handles cases where our `__libc_start_main` rejects the call but the host's might accept it. Each piece is small; the combination is what makes the bootstrap work without locking up.

---

## XDR: An RFC 4506 Native Implementation

XDR (External Data Representation, RFC 4506) is what RPC and NFS speak on the wire. glibc historically exported ~68 XDR symbols (`xdr_int`, `xdr_long`, `xdr_string`, `xdr_array`, `xdr_pointer`, `xdr_reference`, `xdr_union`, and many more), each wrapped around glibc's internal XDR machinery.

Phase 5 (per the CHANGELOG) replaced all 68 XDR symbols with a pure-Rust implementation. The implementation lives in `crates/frankenlibc-core/src/rpc/`. Key design choices:

- **Function-per-type encoding pattern** — each basic XDR type has a dedicated `xdr_<type>` function (`xdr_int`, `xdr_long`, `xdr_string`, etc.); complex types compose via `xdr_array`, `xdr_pointer`, `xdr_union`, and a shared `XDR` stream state. No encoder/decoder trait abstraction is layered over them; the API mirrors glibc's C-style entry points one-for-one.
- **Bounded recursion** — `xdr_pointer` and `xdr_union` track recursion depth and refuse to recurse beyond a configured limit. This defeats the "4 GB XDR DoS" bug Phase 10 discovered: a malicious payload with deeply-nested pointers would have exhausted the stack.
- **`elsize=0` rejection** — `xdr_array(eltsize=0, ...)` returns `false` (XDR failure) rather than computing nonsense. Phase 10's fuzz_xdr campaign caught this case explicitly.
- **No external state** — every XDR call is stateless beyond the explicit stream pointer. No global lookup tables, no per-process registries.
- **Bit-exact round-trip** — XDR-encoded bytes from FrankenLibC decode to the same Rust values when read by glibc, and vice versa. The fixture corpus under `tests/conformance/fixtures/xdr_*` enforces this.

The XDR implementation is also one of the larger demonstrations of the clean-room rule: glibc's XDR is ~5K lines of dense C; FrankenLibC's is ~3K lines of Rust, organized around the trait-based encode/decode pattern.

---

## Detecting Buffer Overflow End-to-End

Concrete scenario: a 64-byte allocation that the caller writes 70 bytes into.

### Byte layout

```
Offset within slab:
  base+0   ──────────────────── 24-byte fingerprint header
                                 [hash:u64 | gen:u64 | size:u64=64]
  base+24  ──────────────────── start of user region
  base+24..base+88              ← user_size = 64 bytes
  base+88  ──────────────────── 8-byte trailing canary (overwritten on overflow)
  base+96  ──────────────────── next slab object's fingerprint header
```

### The overflow

Caller has `p = base + 24`. Caller writes `memset(p, 0x42, 70)`. The write covers `[base+24, base+94)`, which is 6 bytes past the user region, overwriting bytes `base+88..base+94` (part of the canary plus part of the next object's fingerprint header).

### Detection on the next free or validation

When `free(p)` or any later call hits the membrane validation pipeline for this allocation:

- The fingerprint header at `base..base+24` is unchanged (the overflow was forward, not backward).
- The 8-byte trailing canary at `base+88..base+96` is compared against `SipHash(base+24, size=64, gen=N, secret)`.
- The canary doesn't match (because 6 of its 8 bytes were overwritten).
- The membrane returns `Heal(TruncateWithNull {requested: 70, truncated: 64})` for the *string* case, or `Deny(EFAULT)` for the *bounds-check* case.
- In hardened mode, the next-object's fingerprint corruption is also caught: when that object is later validated, *its* header SipHash recomputation fails, and the membrane refuses the call.

### Why this is structural

The detection doesn't depend on the caller asking; it happens automatically on the *next* call that touches either the overflowed allocation or its neighbor. A program that does `memset(p, 0x42, 70)` and then immediately calls `exit()` would not surface the bug (because no later call hits the membrane), but the *next* allocator or membrane operation against either allocation would.

The 8-byte canary's `P(miss) ≤ 2⁻⁶⁴` is the cryptographic guarantee. The neighbor-fingerprint catch is the second layer; cross-object corruption requires both checks to fail, which has compound probability `≤ 2⁻¹²⁸`.

---

## Detecting Double-Free End-to-End

Concrete scenario: a caller frees the same pointer twice.

### First `free(p)`

- Membrane validates: fingerprint matches, canary matches, SafetyState is `Valid`. Allow.
- Allocator bumps generation `N → N+1`. SafetyState transitions `Valid → Freed → Quarantined`.
- Slot enters the shard's quarantine queue. TLS cache entry for `p` is invalidated.

### Second `free(p)`

- ABI runtime policy decide for `ApiFamily::Allocator`.
- Membrane validation: TLS cache miss (just invalidated). Arena lookup returns the slot, now in state `Quarantined`, generation `N+1`. The caller is presenting generation `N` (encoded in their stale knowledge of `p`).
- Actually the *caller* doesn't carry the generation in the pointer; the *arena* has recorded that the generation was bumped. The mismatch is implicit: the pointer is now associated with a slot whose state is `Quarantined`.
- The membrane returns `Heal(IgnoreDoubleFree)` in hardened mode, or `Deny(EFAULT)` in strict mode.
- Structured evidence record is emitted to the ledger.

### Why this is meaningful

In glibc, double-free corrupts allocator state. The corruption may surface as a segfault on the *next* allocation, or as silent heap corruption that persists for arbitrary later calls. The actual point of failure is detached from the buggy call.

In FrankenLibC's hardened mode, the double-free is caught *at the offending call site*, the allocator state is preserved, and the evidence record names the exact call and the prior `free` that invalidated the slot. This is the difference between "memory corruption manifests as a crash later" and "double-free is observable as a typed error at the point of the bug."

---

## Building the cdylib: What `cargo build -p frankenlibc-abi --release` Actually Does

```
1. Cargo reads workspace Cargo.toml and the ABI crate's Cargo.toml.
2. The ABI crate declares:
     [lib]
     crate-type = ["cdylib", "staticlib", "rlib"]
3. Cargo compiles all transitive dependencies (membrane, core,
   parking_lot, blake3, …) in release mode.
4. The membrane crate's build.rs runs:
   a. SOS certificate synthesis (3 invariants, Cholesky verification).
   b. Memory-model barrier audit (≥20 atomic sites across 6 files).
   c. Feature flag enforcement (`runtime-math-production` required).
5. The ABI crate's build.rs runs:
   a. Detects whether to link the GNU ld version script (libc.map).
      - Skip for debug + fuzz builds.
      - Link for release cdylib builds.
   b. Emits `cargo:rustc-link-arg=-Wl,--version-script=...`
6. rustc compiles each crate to `.rlib` or `.so` artifacts.
7. The linker (lld or gold or bfd) combines them:
   - cdylib output: target/release/libfrankenlibc_abi.so
   - Linker flag: --version-script=version_scripts/libc.map applied
     so symbols are exported under the right GLIBC_x.y tags.
   - opt-level=3 enables aggressive inlining (Cargo's release default).
   - Cargo defaults are otherwise used today; AGENTS.md tracks LTO,
     codegen-units=1, and strip=true as future tightening.
8. The output .so is ABI-compatible with binaries expecting
   GLIBC_2.2.5 symbol versions (with GLIBC_2.11 inheriting for the
   `__longjmp_chk` fortify wrapper).
```

The static library (`libfrankenlibc_abi.a`) is also produced. It's used by `scripts/check_setjmp_native.sh` and similar native packaging checks that need to link the symbols into a standalone `libc.so` via `cc -Wl,--version-script=libc.map`.

---

## Symbol Visibility Discipline

Every exported symbol in the ABI crate follows a strict pattern:

```rust
#[no_mangle]
pub extern "C" fn malloc(size: usize) -> *mut c_void {
    // Step 1: runtime_policy::decide
    let (snapshot, decision) = runtime_policy::decide(
        ApiFamily::Allocator,
        core::ptr::null(),
        size,
        false,
        false,
        0,
    );

    // Step 2: check for Deny
    if let RuntimeDecision::Deny(reason) = decision {
        set_abi_errno(reason.errno_code());
        return core::ptr::null_mut();
    }

    // Step 3: validate inputs (size > 0 for malloc semantics, etc.)
    if size == 0 {
        // Implementation-defined; we return NULL with errno=0
        return core::ptr::null_mut();
    }

    // Step 4: delegate to core
    let ptr = frankenlibc_core::malloc::malloc_aligned(size);

    // Step 5: runtime_policy::observe
    runtime_policy::observe(
        ApiFamily::Allocator,
        snapshot.profile,
        elapsed_ns(),
        ptr.is_null(),
    );

    ptr
}
```

This is the validate-delegate pattern made concrete:

- `#[no_mangle]` keeps the symbol name as-is so the dynamic linker can resolve it.
- `pub extern "C"` exports with C calling convention; `extern "C"` blocks in Edition 2024 are `unsafe` by default, so the FFI boundary is syntactically marked.
- The `.symver` directive (emitted via inline assembly or `link_section`) attaches the GLIBC version tag.
- The body is minimal: validate, dispatch, observe.

Phase 5's Symbol cleanup removed 175 duplicate `#[no_mangle]` symbol definitions that had accumulated as the surface grew. The audit gate scans for accidental duplicates because two symbols with the same name would create a linker error or, worse, silent ambiguity.

---

## The Bench Infrastructure

`cargo bench -p frankenlibc-bench` runs Criterion benchmarks against the membrane and core kernels. The infrastructure:

- **Pinning**: `FRANKENLIBC_BENCH_PIN=1` sets the `taskset` mask to pin benches to specific CPUs, avoiding cross-CPU jitter.
- **Frequency lock**: benches are typically run after `cpupower frequency-set --governor performance` to keep the CPU at its rated frequency.
- **Warmup**: Criterion's default warmup elapses `3.0s` of dummy iterations before timing.
- **Statistical analysis**: each benchmark reports mean, median, std dev, slope, and 95% confidence interval. Criterion is good enough to detect ~1% regressions reliably on a tuned host.
- **Comparison vs baseline**: `scripts/check_perf_regression_gate.sh` compares the run against `scripts/perf_baseline.json`. A regression beyond `FRANKENLIBC_PERF_MAX_REGRESSION_PCT` (default 15%) fails the gate.
- **Skip on overloaded host**: `FRANKENLIBC_PERF_SKIP_OVERLOADED=1` causes the gate to abstain if `loadavg/cpus > FRANKENLIBC_PERF_MAX_LOAD_FACTOR` (default 0.85). This keeps the evidence trustworthy — a perf run on a busy host generates noise, not signal.

Bench groups cover:

- Membrane hot-path overhead (per-call cost for each `ApiFamily`)
- String kernels (per-byte throughput for `memcpy`/`memmove`/`memset`/`strlen`/`strchr`/`strstr`)
- Allocator (size-class hit rate, magazine pressure, large-allocation latency)
- Concurrency primitives (flat-combining vs locking under controlled contention)
- printf format engine (per-directive cost)
- Runtime math controllers (snapshot cost, decision-step cost)

---

## Time and y2038

`time_t` was 32-bit on 32-bit Linux, and rolls over in January 2038. Linux 64-bit time (`y2038` work) ships interfaces that take 64-bit time values for filesystem timestamps, sockets, signals, futexes, etc.

FrankenLibC's time handling:

- **`time_t` is `i64`** — matches the kernel's 64-bit time interfaces on supported platforms.
- **`struct timespec` and `struct timeval`** use the kernel-canonical layout.
- **Native `clock_gettime`** for `CLOCK_REALTIME`, `CLOCK_MONOTONIC`, `CLOCK_PROCESS_CPUTIME_ID`, `CLOCK_THREAD_CPUTIME_ID`, `CLOCK_BOOTTIME`, `CLOCK_REALTIME_COARSE`, `CLOCK_MONOTONIC_COARSE`, `CLOCK_MONOTONIC_RAW`.
- **vDSO acceleration** for `clock_gettime` and `gettimeofday` (the kernel exposes these in the vDSO mapping; we use them when present rather than syscalling).
- **`strftime` / `strptime`** are native; locale-aware where the locale data supports it.
- **`mktime`** and **`localtime`/`localtime_r`** honor the `TZ` environment variable and the `/etc/localtime` zone file.
- **`difftime`** is the trivial `f64` subtraction.
- **Monotonic invariance**: `CLOCK_MONOTONIC` time never moves backward, even across `clock_settime` calls. The implementation is a kernel passthrough; we don't second-guess kernel-provided monotonic time.

Pre-2038-rollover legacy callers that expect `time_t` = `int32_t` still work via the ABI version tags, but the native implementation always operates on 64-bit values internally to avoid the rollover.

---

## Linux Syscall Quirks

Some kernel-ABI quirks the native syscall layer encodes:

- **`-errno` return convention**: Linux syscalls return `-errno` for failures; FrankenLibC's syscall wrappers translate to `errno` set + return `-1` (libc convention) at the seam.
- **Restartable syscalls**: certain syscalls (`read`, `write`, `recv`, `send`, etc.) can return `EINTR` when interrupted. The stdio and pthread layers wrap with explicit retry loops where POSIX requires.
- **`futex` with `FUTEX_PRIVATE_FLAG (0x80)`**: tells the kernel the futex is process-local. Cheaper than a shared-process futex. Used by all our pthread primitives.
- **`SYS_clone` argument order varies by architecture**: x86_64 has `(flags, stack, parent_tid, child_tid, tls)`; aarch64 has `(flags, stack, parent_tid, tls, child_tid)`. The native wrapper has per-arch dispatch.
- **`signalfd_siginfo` layout** is kernel-fixed and 128 bytes; we use the kernel-canonical layout.
- **`SIGRTMIN` may be `32` from the kernel's perspective but `34` from libc's perspective** (the kernel reserves 32 and 33 for NPTL). FrankenLibC reports `SIGRTMIN = 34` to match glibc behavior.
- **`O_TMPFILE`** must be combined with `O_DIRECTORY | O_RDWR`; the kernel rejects `O_TMPFILE` alone. The native `open` family encodes this.
- **`statx` STX_* mask bits**: requesting `STX_BTIME` doesn't guarantee the filesystem can provide birth time. The `stx_mask` return value tells you what was actually filled in.
- **`io_uring_setup` SQE/CQE sizes** changed in Linux 5.19+; the wrapper version-detects.

These quirks aren't documented in the C standard or POSIX; they're documented in `man 2 <syscall>` and confirmed by reading the kernel source. The native syscall wrappers have `// SAFETY:` comments explaining each one.

---

## Real Bugs the Fuzz Campaign Caught

A non-exhaustive list of bugs surfaced by `cargo-fuzz` campaigns and fixed in the corresponding bead-tracker entries:

- **4 GiB XDR DoS** (`fuzz_xdr`): An adversarial XDR payload could request a 4 GB allocation through `xdr_array`. Fix: cap at a configurable maximum.
- **`xdr_array` `elsize=0` OOB read** (`fuzz_xdr`): An array with zero-sized elements would compute `count × 0 = 0` allocation size but then index past it. Fix: reject `elsize=0`.
- **printf `%g` precision panic** (`fuzz_printf`): A precision of 65,536 caused `core::fmt` to panic on a length calculation. Fix: cap precision at 65,535.
- **`format_g` exponent overflow** (`fuzz_printf`): `%g` with very small numbers could overflow the requested precision in scientific notation. Fix: auto-switch `%g`→`%e`.
- **Malloc reentrancy panic** (`fuzz_malloc`): Per-thread reentry from inside an allocator callback. Fix: per-thread reentry guard.
- **`atfork` lock-holding deadlock** (`fuzz_pthread_sync_misc`): `on_exit` and `at_quick_exit` handlers held a lock while executing user callbacks that could re-enter. Fix: swap-extract handlers from the protected vector before calling them.
- **`strftime` integer overflow** (`fuzz_strftime`): A very large year combined with a `%Y` directive could overflow a signed integer. Fix: saturate at INT_MAX.
- **`fnmatch` quadratic blowup** (`fuzz_fnmatch`): Certain patterns with `*` and bracket expressions had worst-case `O(2^n)` behavior. Fix: bound the backtrack depth.
- **`snprintf` truncation off-by-one** (`fuzz_printf`): When the formatted output exactly equals the buffer size, the trailing NUL was sometimes overwritten. Fix: explicit NUL-write after truncation.
- **`getaddrinfo_a` reentrancy** (manual review during `fuzz_resolv`): The async glibc-compat variant had a race in the result-list mutation. Fix: rewrite the linked-list mutation under a mutex.

Each of these has a corresponding bead in `.beads/issues.jsonl` and binding evidence in a `*_completion_contract.v1.json`. The fuzz campaigns are not theater; they catch real bugs that fixture-based testing would miss.

---

## The Galois Map in Code

`gamma(alpha(c)) >= c` is the soundness condition. In code:

```rust
// α: abstraction — concrete C pointer → abstract safety state
fn alpha(ptr: *const c_void, context: &CallContext) -> PointerAbstraction {
    if ptr.is_null() {
        return PointerAbstraction::null();
    }
    // 1. Consult the bloom filter, arena, fingerprint, canary
    // 2. Synthesize the (safety_state, allocation_base, remaining_bytes,
    //    generation) tuple
    let metadata = consult_membrane(ptr, context);
    PointerAbstraction {
        state: metadata.safety_state,
        base: metadata.allocation_base,
        remaining: metadata.user_size - (ptr as usize - metadata.user_base),
        generation: metadata.generation,
    }
}

// γ: concretization — abstract safety state → concrete action
fn gamma(abs: PointerAbstraction, op: Operation) -> ConcreteAction {
    match (abs.state, op) {
        (SafetyState::Valid, _) => ConcreteAction::Proceed,
        (SafetyState::Readable, Operation::Read { .. }) => ConcreteAction::Proceed,
        (SafetyState::Readable, Operation::Write { .. }) => ConcreteAction::Deny,
        (SafetyState::Writable, Operation::Read { .. }) => ConcreteAction::Proceed,
        (SafetyState::Writable, Operation::Write { size }) if size <= abs.remaining
            => ConcreteAction::Proceed,
        (SafetyState::Writable, Operation::Write { size }) if size > abs.remaining
            => ConcreteAction::Heal(HealingAction::ClampSize {
                requested: size,
                clamped: abs.remaining,
            }),
        (SafetyState::Quarantined | SafetyState::Freed, _) => ConcreteAction::Deny,
        (SafetyState::Invalid | SafetyState::Unknown, _) => ConcreteAction::Deny,
    }
}
```

The soundness condition `γ(α(c)) ≥ c` says: for any concrete C operation, the action γ-returns is at least as permissive as what a correct program needs. "Permissive" is defined by the lattice ordering on actions (`Proceed > Heal > Deny`), and "correct program" is one whose actual access stays within the bounds we've recorded.

The proof note in `docs/proofs/galois_monotonic_probability_bounds.md` works through this for each operation type. The stated property isn't decoration; it's the reason the membrane is intended to be *transparent*. A correct program should not see a different observable behavior under the membrane than it would under plain glibc.

---

## Performance Counters and Observability

Every membrane decision can emit:

1. **Atomic metrics counters** (`metrics.rs`): `(family, decision, profile)` counters incremented with `Relaxed` ordering. Aggregated by the harness for end-of-run summaries.
2. **Evidence ledger record** (`runtime_math/evidence.rs`): a JSONL record per decision with `(ts_ns, family, decision, latency_ns, healing_action, ptr, size, generation, controller_snapshot_hash, seqno)`. Lock-free MPSC ring buffer.
3. **`FRANKENLIBC_LOG` JSONL stream**: when set, each decision is written to the configured path with the same record shape, suitable for `tail -f` or `jq` post-processing.

What's instrumented at the membrane level:

- Every validation stage outcome (cache hit/miss, bloom positive/negative, arena lookup result, fingerprint pass/fail, canary pass/fail)
- Every healing action triggered, with old + new values
- Every Deny reason
- Every runtime-math controller snapshot (hashable)
- Every latency observation with elapsed nanoseconds
- Every mode-resolution event at startup (one-time)
- Every quarantine drain event (rare but informative)
- Every TLS cache epoch invalidation
- Every bloom filter rebuild (also rare)
- Every fixture/oracle/replay assertion result during testing

What's *not* instrumented:

- Per-allocator-byte allocation counts (would be too noisy)
- Per-string-byte processing counts (same)
- Internal-controller intermediate values (only the snapshot hash is recorded)

The granularity is "every decision," which gives meaningful aggregation without overwhelming the consumer.

---

## The Runtime Math Research vs Production Feature Flag

The membrane crate has two feature gates:

```toml
[features]
default = ["runtime-math-production"]
runtime-math-production = []
runtime-math-research = ["runtime-math-production"]
```

`runtime-math-production` enables the live runtime-math control plane that's compiled into every shipping artifact. It's mandatory; the membrane crate's `build.rs` emits `compile_error!` if it's not set.

`runtime-math-research` is additive: it enables additional controllers, experimental modules, and richer telemetry that are useful for offline analysis but not yet ready for the production hot path. Research-feature controllers may have higher latency, broader instrumentation, or unsynthesized SOS certificates. The release artifact is built with `runtime-math-production` only.

This split lets the project develop new controllers (e.g., a new e-process variant, a new HJI safety controller, a new conformal scoring scheme) without disturbing the production behavior. Once a research controller proves itself, it gets promoted to production via the math-governance gate (`scripts/check_math_governance.sh`) and a corresponding completion contract.

---

## `parking_lot` vs `std::sync::Mutex`

`std::sync::Mutex` is poison-aware: if a thread panics while holding the lock, subsequent acquisitions return a `PoisonError` and the application must explicitly recover. That is the right default for application code but the wrong default for a libc; a poisoned libc mutex would propagate failures up through the entire process.

`parking_lot::Mutex` is *not* poison-aware. A panic while holding the lock unlocks it, and the next acquirer proceeds normally. For the membrane and core kernels, this is the right behavior: a panic in the middle of `malloc` should not poison every future allocation in the process.

Other reasons we use `parking_lot`:

- **Smaller footprint**: `parking_lot::RawMutex` is 1 byte (so `Mutex<T>` adds only 1 byte plus padding to `T`); `std::sync::Mutex` includes a poison flag and platform-specific fields.
- **Faster uncontended path**: `parking_lot` uses an inline CAS without entering the kernel.
- **Adaptive parking**: contended waiters spin briefly before parking, optimizing for short-critical-section workloads.
- **Fair RwLock semantics** are available via `RawRwLock` if needed.

We use `parking_lot::Mutex` and `RwLock` everywhere except where the membrane's `alien_cs` primitives (`SeqLock`, `RCU`, `EBR`, `FlatCombining`, `BravoRwLock`) are explicitly chosen for their lock-free or wait-free properties.

---

## What's in `tests/runtime_math/golden/`

The runtime-math golden snapshots are reference outputs for each controller's deterministic behavior. Each snapshot is a JSON file under `tests/runtime_math/golden/<controller>_<scenario>.json` containing:

- The controller name and config
- The input sequence (deterministic, seeded)
- The output decision sequence
- The internal state after each input
- The final state hash (BLAKE3 digest)

The snapshot gate (`scripts/snapshot_gate.sh`) re-runs the controller against the same inputs and asserts byte-for-byte output equality. Any drift fails the gate, even a single differing decision.

This is how the runtime-math code stays *deterministic* despite being numerically intricate. Changes to a controller require regenerating the snapshot, which forces a code review of every observable behavior change. Hidden numerical changes that affect runtime decisions cannot land silently.

The current golden corpus covers all ~71 controllers across a representative set of scenarios: nominal operation, alarm conditions, regime transitions, drift detection, and worst-case tail-risk events. Regenerating the corpus is a one-line invocation (`bash scripts/regenerate_runtime_math_goldens.sh`) but each regen is a deliberate act that gets reviewed in the corresponding bead.

---

## Why FrankenLibC Doesn't Need an `unsafe` Audit

Standard projects with a lot of `unsafe` need an `unsafe` audit: a manual review of every block to verify the SAFETY comment matches the actual invariants. FrankenLibC's structure makes this audit *structural* rather than manual:

1. **The membrane crate** sets `#![deny(unsafe_code)]` at the crate root. Only specific modules (`fingerprint.rs`, `arena.rs`, `bloom.rs`, etc.) get `#[allow(unsafe_code)]`, and every unsafe block has a `// SAFETY:` comment. The build fails if a new unsafe block lacks the comment.
2. **The core crate** does the same.
3. **The harness crate** sets `#![forbid(unsafe_code)]` — no unsafe at all, even with `#[allow]` attempts.
4. **The ABI crate** is the only place where `extern "C"` minimal-glue is permitted. Every entrypoint follows the validate-delegate pattern; the body is minimal so the review surface is small.
5. The `build.rs` barrier audit enforces minimum atomic-operation counts so a refactor cannot silently strip an `unsafe` block's safety-relevant synchronization.

The audit *is* the code structure. There is no separate periodic-review event because the rules are enforced at build time.

---

## Comparison: What's in This Repo vs What's in Companion Crates

To keep the runtime artifact lean, several capabilities live in companion crates that are build-time tools, not runtime dependencies:

| Capability | Location | Why outside the main repo |
|---|---|---|
| Deterministic async runtime with conformance orchestration | `/dp/asupersync` (companion) | Generic infrastructure usable by many projects |
| TUI framework for diff/snapshot harness output | `/dp/frankentui` (companion) | Same |
| Beads/`br` tracker | `/dp/beads_rust` (companion) | Generic issue tracker |
| MCP Agent Mail server | `/dp/agent-mail` (companion) | Multi-project coordination layer |
| `cass` cross-agent session search | `/dp/cass` (companion) | Session indexing service |
| RCH (remote compile helper) | `/dp/rch` (companion) | Build-offload tooling |
| DSR (release infrastructure) | `/dp/dsr` (companion) | Release tooling |
| UBS (ultimate bug scanner) | `/dp/ubs` (companion) | Pre-commit scanner |

The repo `/data/projects/frankenlibc` contains only what's needed to *build, test, and run* FrankenLibC. The companion crates are pulled in via their published crates.io versions (`asupersync-conformance = "0.3.1"`, `ftui-harness = "0.3.1"`) as build-tooling dependencies, never as runtime libc dependencies.

This separation also makes the safety claim cleaner: "the runtime libc artifact depends on `parking_lot`, `blake3`, `sha2`, `libc` (types only), `libm`", and nothing else from outside the workspace.

---

## Project Health Snapshot

As of 2026-05-16:

| Dimension | Status |
|---|---|
| Total commits | 4,932 across 97 days of active development |
| Classified ABI surface | 4,119 symbols, 100% native (3,705 `Implemented` + 414 `RawSyscall`) |
| Crates | 6 active main-workspace members (`membrane`, `core`, `abi`, `harness`, `bench`, `fixture-exec`) + 2 legacy (`frankenlibc`, `frankenlibc_conformance`) + 1 separate fuzz sub-workspace (`frankenlibc-fuzz` with 66 targets) |
| Rust files in `crates/` | ~1,305 |
| `crates/frankenlibc-abi/src/` | 50 ABI module files, 121 kLOC total |
| `crates/frankenlibc-membrane/src/` | 109 files, ~75 kLOC total |
| `crates/frankenlibc-core/src/` | 134 files, ~70 kLOC total |
| Runtime math controllers | 71 modules |
| `cargo-fuzz` targets | 66 |
| Conformance fixture families | 40+ |
| C integration fixtures | 17 |
| Completion contracts | 258 |
| CLI contracts | 68 |
| CLI meta-gates per contract | ~50 |
| Formal proofs | 9 |
| Shell scripts (CI / gates / smoke / perf) | 554 |
| GNU ld version script | 4,687 lines, `GLIBC_2.2.5` |
| Membrane `build.rs` | 1,030 lines (SOS synthesis + barrier audit) |
| Curated `LD_PRELOAD` smoke battery | 58 pass / 0 fail / 6 skip, strict + hardened green |

---

## Glossary

| Term | Meaning |
|---|---|
| TSM | Transparent Safety Membrane |
| `Implemented` | Symbol path is natively owned in FrankenLibC |
| `RawSyscall` | Symbol path goes directly to Linux syscalls rather than host glibc |
| `WrapsHostLibc` | Native wrapper that still calls host libc symbols internally (0 today) |
| `GlibcCallThrough` | Symbol still depends on host glibc for behavior (0 today) |
| `Stub` | Deterministic fallback/error contract (0 today in classified surface) |
| `strict` | Compatibility-first runtime mode (default) |
| `hardened` | Repair/deny-capable runtime mode |
| reality report | Generated report summarizing current classified symbol state |
| maintenance report | Canonical artifact used to detect support-matrix drift |
| interpose artifact | `libfrankenlibc_abi.so`, used via `LD_PRELOAD` |
| replace artifact | Planned standalone libc artifact with no host-glibc deployment dependency |
| completion contract | `*_completion_contract.v1.json` binding evidence artifact for a closed bead |
| CLI contract | `*_cli_contract.v1.json` manifest for a harness subcommand |
| meta-gate | Pinned Rust test that validates a CLI contract or other artifact against ~50 invariants |
| bead | An issue tracked by `beads_rust` (`br`) under `.beads/`; ID format `bd-xxxxx` |
| alien_cs | The membrane's lock-free / wait-free concurrency primitive toolkit (SeqLock, RCU, EBR, FlatCombining) |
| evidence ledger | The structured JSONL ring buffer of runtime decisions and outcomes |
| L0 / L1 / L2 / L3 | Replacement-level promotion stages |
| PCPT | Proof-Carrying Policy Table (`policy_table.rs`) |

---

## Appendix: Important Files

| Path | Why it matters |
|---|---|
| `README.md` | Top-level project overview |
| `AGENTS.md` | Repo operating rules and architectural expectations |
| `CHANGELOG.md` | Capability-milestone history (Phases 1–16) |
| `support_matrix.json` | Per-symbol implementation taxonomy |
| `Cargo.toml` | Workspace definition and top-level dependencies |
| `crates/frankenlibc-abi/` | ABI boundary and interpose shared library |
| `crates/frankenlibc-membrane/` | Safety membrane, healing, runtime math, alien_cs |
| `crates/frankenlibc-core/` | Safe semantic kernels |
| `crates/frankenlibc-harness/` | Verification and evidence tooling |
| `crates/frankenlibc-membrane/build.rs` | Build-time SOS certificate synthesis + barrier audit |
| `crates/frankenlibc-abi/version_scripts/libc.map` | GNU ld version script (`GLIBC_2.2.5`, 4,687 lines) |
| `tests/conformance/` | Canonical reports, fixtures, completion contracts, CLI contracts |
| `tests/conformance/fixtures/` | Host-libc fixture corpus |
| `tests/integration/` | C integration fixtures linked against `libfrankenlibc_abi.so` |
| `tests/runtime_math/golden/` | Runtime-math golden snapshots |
| `docs/proofs/` | 9 proof notes / obligation narratives (Galois, lattice, refinement, SOS, HJI, sheaf, CPOMDP, replay, repair mapping); no machine-checked proof artifacts yet |
| `scripts/check_support_matrix_maintenance.sh` | High-signal drift gate |
| `scripts/ld_preload_smoke.sh` | Curated smoke battery |
| `scripts/check_release_gate.sh` | Release-claim coherence |
| `scripts/check_aarch64_crosscompile.sh` | aarch64 architecture gate |

---

## About Contributions

> *About Contributions:* Please don't take this the wrong way, but I do not accept outside contributions for any of my projects. I simply don't have the mental bandwidth to review anything, and it's my name on the thing, so I'm responsible for any problems it causes; thus, the risk-reward is highly asymmetric from my perspective. I'd also have to worry about other "stakeholders," which seems unwise for tools I mostly make for myself for free. Feel free to submit issues, and even PRs if you want to illustrate a proposed fix, but know I won't merge them directly. Instead, I'll have Claude or Codex review submissions via `gh` and independently decide whether and how to address them. Bug reports in particular are welcome. Sorry if this offends, but I want to avoid wasted time and hurt feelings. I understand this isn't in sync with the prevailing open-source ethos that seeks community contributions, but it's the only way I can move at this velocity and keep my sanity.

---

## License

FrankenLibC is available under the terms in [LICENSE](LICENSE), currently `MIT License (with OpenAI/Anthropic Rider)`.
