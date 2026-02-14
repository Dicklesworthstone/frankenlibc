# AGENTS.md — FrankenLibC

> Guidelines for AI coding agents working in this Rust codebase.

---

## RULE 0 - THE FUNDAMENTAL OVERRIDE PREROGATIVE

If I tell you to do something, even if it goes against what follows below, YOU MUST LISTEN TO ME. I AM IN CHARGE, NOT YOU.

---

## RULE NUMBER 1: NO FILE DELETION

**YOU ARE NEVER ALLOWED TO DELETE A FILE WITHOUT EXPRESS PERMISSION.** Even a new file that you yourself created, such as a test code file. You have a horrible track record of deleting critically important files or otherwise throwing away tons of expensive work. As a result, you have permanently lost any and all rights to determine that a file or folder should be deleted.

**YOU MUST ALWAYS ASK AND RECEIVE CLEAR, WRITTEN PERMISSION BEFORE EVER DELETING A FILE OR FOLDER OF ANY KIND.**

---

## Irreversible Git & Filesystem Actions — DO NOT EVER BREAK GLASS

1. **Absolutely forbidden commands:** `git reset --hard`, `git clean -fd`, `rm -rf`, or any command that can delete or overwrite code/data must never be run unless the user explicitly provides the exact command and states, in the same message, that they understand and want the irreversible consequences.
2. **No guessing:** If there is any uncertainty about what a command might delete or overwrite, stop immediately and ask the user for specific approval. "I think it's safe" is never acceptable.
3. **Safer alternatives first:** When cleanup or rollbacks are needed, request permission to use non-destructive options (`git status`, `git diff`, `git stash`, copying to backups) before ever considering a destructive command.
4. **Mandatory explicit plan:** Even after explicit user authorization, restate the command verbatim, list exactly what will be affected, and wait for a confirmation that your understanding is correct. Only then may you execute it—if anything remains ambiguous, refuse and escalate.
5. **Document the confirmation:** When running any approved destructive command, record (in the session notes / final response) the exact user text that authorized it, the command actually run, and the execution time. If that record is absent, the operation did not happen.

---

## Git Branch: ONLY Use `main`, NEVER `master`

**The default branch is `main`. The `master` branch exists only for legacy URL compatibility.**

- **All work happens on `main`** — commits, PRs, feature branches all merge to `main`
- **Never reference `master` in code or docs** — if you see `master` anywhere, it's a bug that needs fixing
- **The `master` branch must stay synchronized with `main`** — after pushing to `main`, also push to `master`:
  ```bash
  git push origin main:master
  ```

**If you see `master` referenced anywhere:**
1. Update it to `main`
2. Ensure `master` is synchronized: `git push origin main:master`

---

## Toolchain: Rust & Cargo

We only use **Cargo** in this project, NEVER any other package manager.

- **Edition:** Rust 2024 (nightly required — see `rust-toolchain.toml`)
- **Dependency versions:** Explicit versions for stability
- **Configuration:** Cargo.toml workspace with `workspace = true` pattern

### Companion Crates (Build Tooling Only — NOT Runtime Dependencies)

This project leverages companion crates for build/test tooling roles only. These are NOT runtime libc dependencies:

- `/dp/asupersync` — Async runtime with deterministic testing, oracles, conformance harness orchestration, and traceability/reporting primitives
- `/dp/frankentui` — TUI framework for deterministic diff/snapshot-oriented harness output and TUI-driven analysis tooling

### Key Dependencies

| Crate | Purpose |
|-------|---------|
| `parking_lot` | Fast synchronization primitives (Mutex, RwLock) |
| `blake3` | BLAKE3 hashing for allocation fingerprints |
| `sha2` | SHA-2 hashing for conformance fixture verification |
| `serde` + `serde_json` | Serialization for fixtures and conformance data |
| `thiserror` | Ergonomic error type derivation |
| `clap` | CLI argument parsing for harness binary |
| `criterion` | Criterion benchmarks for performance regression gates |
| `libc` | libc type definitions for ABI compatibility layer |
| `libm` | Pure Rust math implementations (no C dependency) |
| `asupersync-conformance` | Deterministic conformance orchestration (build tooling) |
| `ftui-harness` | TUI-driven harness output (build tooling) |

### Release Profile

The release build optimizes for performance (this is a library producing `libc.so`):

```toml
[profile.release]
opt-level = 3       # Maximum performance optimization
lto = true          # Link-time optimization
codegen-units = 1   # Single codegen unit for better optimization
strip = true        # Remove debug symbols
```

---

## Code Editing Discipline

### No Script-Based Changes

**NEVER** run a script that processes/changes code files in this repo. Brittle regex-based transformations create far more problems than they solve.

- **Always make code changes manually**, even when there are many instances
- For many simple changes: use parallel subagents
- For subtle/complex changes: do them methodically yourself

### No File Proliferation

If you want to change something or add a feature, **revise existing code files in place**.

**NEVER** create variations like:
- `mainV2.rs`
- `main_improved.rs`
- `main_enhanced.rs`

New files are reserved for **genuinely new functionality** that makes zero sense to include in any existing file. The bar for creating new files is **incredibly high**.

---

## Backwards Compatibility

We do not care about backwards compatibility—we're in early development with no users. We want to do things the **RIGHT** way with **NO TECH DEBT**.

- Never create "compatibility shims"
- Never create wrapper functions for deprecated APIs
- Just fix the code directly

---

## Compiler Checks (CRITICAL)

**After any substantive code changes, you MUST verify no errors were introduced:**

```bash
# Check for compiler errors and warnings (workspace-wide)
cargo check --workspace --all-targets

# Check for clippy lints
cargo clippy --workspace --all-targets -- -D warnings

# Verify formatting
cargo fmt --check
```

If you see errors, **carefully understand and resolve each issue**. Read sufficient context to fix them the RIGHT way.

---

## Testing

### Testing Policy

Every component crate includes inline `#[cfg(test)]` unit tests alongside the implementation. Tests must cover:
- Happy path
- Edge cases (empty input, max values, boundary conditions)
- Error conditions

Cross-component integration tests live in the workspace `tests/` directory.

### Unit Tests

```bash
# Run all tests across the workspace
cargo test --workspace

# Run with output
cargo test --workspace -- --nocapture

# Run tests for a specific crate
cargo test -p frankenlibc-membrane
cargo test -p frankenlibc-core
cargo test -p frankenlibc-abi
cargo test -p frankenlibc-harness
cargo test -p frankenlibc-bench

# Run tests with all features enabled
cargo test --workspace --all-features
```

### Test Categories

| Crate | Focus Areas |
|-------|-------------|
| `frankenlibc-membrane` | Safety lattice operations, Galois connection, fingerprint/canary integrity, arena generational correctness, bloom filter false-positive rate, TLS cache hit/miss, page oracle bitmap, healing policy completeness, runtime math kernel correctness, validation pipeline ordering |
| `frankenlibc-core` | POSIX function correctness (string, stdlib, stdio, math, ctype, pthread, etc.), edge cases per spec section, membrane integration |
| `frankenlibc-abi` | ABI symbol export correctness, version script compliance, extern "C" calling convention, minimal body (validate-delegate pattern) |
| `frankenlibc-harness` | Fixture capture/verify round-trip, traceability mapping, healing oracle trigger/verify, report generation |
| `frankenlibc-bench` | String ops throughput, malloc throughput, membrane overhead budget, runtime math kernel latency, stdio throughput, mutex/condvar contention |
| `tests/conformance/` | Fixture-based conformance against host glibc |
| `tests/integration/` | C program link tests against produced `libc.so` |

### Test Fixtures

Conformance fixtures are captured from host glibc (JSON-serialized input/output pairs) and stored in `tests/conformance/fixtures/`. The harness compares FrankenLibC outputs against these fixtures.

---

## Third-Party Library Usage

If you aren't 100% sure how to use a third-party library, **SEARCH ONLINE** to find the latest documentation and current best practices.

---

## FrankenLibC — This Project

**This is the project you're working on.** FrankenLibC is a clean-room, memory-safe Rust reimplementation of glibc targeting full POSIX coverage plus GNU extensions. It produces an ABI-compatible `libc.so` that can be used as a drop-in replacement for glibc.

### The Core Innovation: Transparent Safety Membrane (TSM)

C code thinks it has full control over raw pointers, but behind the ABI boundary, FrankenLibC dynamically validates, sanitizes, and mechanically fixes invalid operations so memory unsafety cannot happen through libc calls.

**TSM Pipeline:**
1. **Validate:** Classify incoming pointers/regions/fd/context via fingerprints, bloom filters, arena lookups, and canary checks.
2. **Sanitize:** Transform invalid/ambiguous inputs into safe, explicit forms.
3. **Repair:** Apply deterministic fallback behavior (clamp/truncate/quarantine/safe-default) instead of allowing corruption.
4. **Audit:** Emit evidence via atomic metrics counters for every repaired/denied unsafe path.

### Non-Negotiable Goals

1. Full POSIX coverage target (with GNU/glibc compatibility where required).
2. ABI compatibility, including symbol/version behavior for supported targets.
3. Transparent safety: caller believes it has raw C control; implementation dynamically sanitizes and mechanically fixes invalid operations to prevent memory unsafety.
4. Conformance harness + feature parity tracking + benchmark regression gates.
5. Mandatory build-tooling leverage of `/dp/asupersync` and `/dp/frankentui`.

### Architecture

```
C caller → extern "C" ABI boundary → TSM Validation Pipeline → Safe Rust Core → Result
                                          │
                     ┌────────────────────┤
                     ▼                    ▼
              Validation Pipeline    Self-Healing Engine
              ┌──────────────┐      ┌───────────────────┐
              │ null check   │      │ ClampSize          │
              │ TLS cache    │      │ TruncateWithNull   │
              │ bloom filter │      │ IgnoreDoubleFree   │
              │ arena lookup │      │ IgnoreForeignFree  │
              │ fingerprint  │      │ ReallocAsMalloc    │
              │ canary check │      │ ReturnSafeDefault  │
              │ bounds check │      │ UpgradeToSafeVariant│
              └──────────────┘      └───────────────────┘
```

### Workspace Structure

```
FrankenLibC/
├── Cargo.toml                    # Workspace root
├── rust-toolchain.toml           # nightly
├── build.rs                      # Version metadata
├── AGENTS.md                     # This file
├── README.md
├── PLAN_TO_PORT_GLIBC_TO_RUST.md
├── EXISTING_GLIBC_STRUCTURE.md
├── PROPOSED_ARCHITECTURE.md
├── FEATURE_PARITY.md
├── legacy_glibc_code/            # Reference only — never translate line-by-line
│   └── glibc/
├── crates/
│   ├── frankenlibc-membrane/     # THE INNOVATION — TSM validation pipeline
│   ├── frankenlibc-core/         # Safe Rust implementations (#![deny(unsafe_code)])
│   ├── frankenlibc-abi/          # extern "C" cdylib boundary (produces libc.so)
│   ├── frankenlibc-fixture-exec/ # Fixture execution helper
│   ├── frankenlibc-harness/      # Conformance testing framework
│   ├── frankenlibc-bench/        # Criterion benchmarks
│   ├── frankenlibc-fuzz/         # cargo-fuzz targets
│   ├── frankenlibc/              # Legacy crate (kept for migration compatibility)
│   └── frankenlibc_conformance/  # Legacy conformance (kept for migration compatibility)
├── tests/
│   ├── conformance/fixtures/     # Reference fixture JSONs
│   └── integration/              # C program link tests
└── scripts/                      # CI, symbol extraction, ABI comparison
```

### Key Files by Crate

| Crate | Key Files | Purpose |
|-------|-----------|---------|
| `frankenlibc-membrane` | `src/lattice.rs` | `SafetyState` enum with join/meet lattice operations |
| `frankenlibc-membrane` | `src/galois.rs` | Galois connection: C flat model <-> rich safety model |
| `frankenlibc-membrane` | `src/fingerprint.rs` | SipHash allocation fingerprints (16-byte header + 8-byte canary) |
| `frankenlibc-membrane` | `src/arena.rs` | Generational arena with quarantine queue |
| `frankenlibc-membrane` | `src/bloom.rs` | Bloom filter for O(1) pointer ownership pre-check |
| `frankenlibc-membrane` | `src/tls_cache.rs` | Thread-local validation cache (1024-entry direct-mapped) |
| `frankenlibc-membrane` | `src/page_oracle.rs` | Two-level page bitmap |
| `frankenlibc-membrane` | `src/heal.rs` | Self-healing policy engine + `HealingAction` enum |
| `frankenlibc-membrane` | `src/config.rs` | Runtime mode config (`strict`/`hardened`) from env var |
| `frankenlibc-membrane` | `src/metrics.rs` | Atomic counters for heals/validations/cache stats |
| `frankenlibc-membrane` | `src/ptr_validator.rs` | Full validation pipeline |
| `frankenlibc-membrane` | `src/runtime_math/` | Online control-plane orchestration (risk, bandit, control, barrier, etc.) |
| `frankenlibc-core` | `src/string/` | mem*, str*, wide string functions |
| `frankenlibc-core` | `src/stdlib/` | Conversion, sort, env, random, exit |
| `frankenlibc-core` | `src/stdio/` | printf engine, scanf, file I/O, buffering |
| `frankenlibc-core` | `src/math/` | Trig, exp, special functions, float utils |
| `frankenlibc-core` | `src/malloc/` | Size-class allocator, thread cache, large alloc |
| `frankenlibc-core` | `src/pthread/` | Mutex, condvar, rwlock, thread, TLS |
| `frankenlibc-abi` | `src/macros.rs` | Helper macros for ABI declarations |
| `frankenlibc-abi` | `src/runtime_policy.rs` | Shared runtime-kernel gate for ABI entrypoints |
| `frankenlibc-abi` | `src/*_abi.rs` | One file per function family |
| `frankenlibc-abi` | `version_scripts/libc.map` | GNU ld version script |
| `frankenlibc-harness` | `src/runner.rs` | Test execution engine |
| `frankenlibc-harness` | `src/capture.rs` | Host libc fixture capture |
| `frankenlibc-harness` | `src/verify.rs` | Output comparison |
| `frankenlibc-harness` | `src/healing_oracle.rs` | Intentional unsafe trigger + healing verification |

### Feature Flags

```toml
# frankenlibc-membrane
[features]
default = ["runtime-math-production"]
runtime-math-production = []             # Production runtime math kernels
runtime-math-research = ["runtime-math-production"]  # Research-only extensions

# frankenlibc-harness
[features]
default = ["asupersync-tooling"]
asupersync-tooling = ["dep:asupersync-conformance"]  # Deterministic conformance orchestration
frankentui-ui = [...]                                 # TUI-driven analysis output
```

### Unsafe Code Policy

| Crate | Policy | Notes |
|-------|--------|-------|
| `frankenlibc-core` | `#![deny(unsafe_code)]` | Safe Rust only. SIMD modules get `#[allow(unsafe_code)]` with per-block `// SAFETY:` comments. |
| `frankenlibc-membrane` | `#![deny(unsafe_code)]` | Arena/fingerprint modules get `#[allow(unsafe_code)]` for raw pointer ops. Every unsafe block must have `// SAFETY:` comment. |
| `frankenlibc-abi` | `#![allow(unsafe_code)]` | ABI boundary is inherently unsafe. Every function body is minimal: validate via membrane, delegate to core. |
| `frankenlibc-harness` | `#![forbid(unsafe_code)]` | Test harness never needs unsafe. |
| `frankenlibc-bench` | `#![allow(unsafe_code)]` | Benchmarks call extern "C" functions. |
| `frankenlibc-fuzz` | `#![allow(unsafe_code)]` | Fuzz harnesses call extern "C" functions. |

Rules:
1. Unsafe is permitted only in explicitly documented boundary modules.
2. All unsafe blocks require written invariants and safety preconditions (`// SAFETY:` comment).
3. Core algorithmic behavior must stay in safe Rust.
4. Memory safety is achieved via the TSM, not by pretending FFI unsafe does not exist.

### TSM Architecture Details

#### Runtime Modes (Hard Requirement)

- `strict` (default): strict ABI-compatible behavior, no repair rewrites.
- `hardened`: TSM repair behavior for invalid/unsafe patterns.
- Runtime selection is process-level and immutable after init (`FRANKENLIBC_MODE=strict|hardened`).

#### Safety State Lattice

```
Valid > Readable > Writable > Quarantined > Freed > Invalid > Unknown
```

States flow monotonically toward more restrictive on new information. Join is commutative, associative, idempotent.

#### Galois Connection

For any C operation `c`: `gamma(alpha(c)) >= c`. The safe interpretation is always at least as permissive as what a correct program needs.

#### Validation Pipeline

```
null check (1ns) -> TLS cache (5ns) -> bloom filter (10ns) -> arena lookup (30ns)
-> fingerprint check (20ns) -> canary check (10ns) -> bounds check (5ns)
```

Fast exits at each stage. Budget target: strict overhead <20ns/call, hardened overhead <200ns/call for membrane-gated hot paths.

#### Allocation Integrity

- 16-byte SipHash fingerprint header + 8-byte canary per allocation
- Generational arena with quarantine queue for UAF detection
- Two-level page bitmap for O(1) "is this pointer ours?" pre-check
- Thread-local 1024-entry validation cache to avoid global lock

#### Self-Healing Actions

`ClampSize | TruncateWithNull | IgnoreDoubleFree | IgnoreForeignFree | ReallocAsMalloc | ReturnSafeDefault | UpgradeToSafeVariant`

### Runtime Math Kernel (Hard Requirement)

The advanced math stack executes at runtime via compact control kernels, not only offline reports.

Runtime decision law (per call):
`mode + context + risk + budget + pareto + design + barrier + consistency -> Allow | FullValidate | Repair | Deny`

Mandatory live modules in `frankenlibc-membrane/src/runtime_math/`:

| Module | Purpose |
|--------|---------|
| `risk.rs` | Online conformal-style risk upper bounds per API family |
| `bandit.rs` | Constrained routing of `Fast` vs `Full` validation profiles |
| `control.rs` | Primal-dual threshold controller for full-check/repair triggers |
| `barrier.rs` | Constant-time admissibility guard |
| `cohomology.rs` | Overlap-consistency monitor for sharded metadata |
| `pareto.rs` | Mode-aware latency/risk Pareto selector with cumulative regret tracking |
| `design.rs` | Runtime D-optimal probe scheduler under strict/hardened budget constraints |
| `sparse.rs` | Online L1 sparse-recovery controller for latent fault-source concentration |
| `fusion.rs` | Online robust signal-fusion controller over runtime math kernels |
| `equivariant.rs` | Representation-stability/group-action symmetry monitor for cross-family semantic drift |
| `eprocess.rs` | Anytime-valid sequential alarming (e-values) |
| `cvar.rs` | Distributionally-robust CVaR tail-risk guard |
| `hji_reachability.rs` | HJI differential game safety certificates |
| `mean_field_game.rs` | Mean-field Nash equilibrium congestion controller |

Developer transparency remains mandatory:
- Contributors write normal Rust APIs/tests/policies
- Runtime executes compact deterministic kernels
- Heavy theorem machinery stays in synthesis/proof pipelines

### Performance Targets

| Operation | Target |
|-----------|--------|
| Strict mode membrane overhead | <20ns/call |
| Hardened mode membrane overhead | <200ns/call |
| Null check (fast exit) | ~1ns |
| TLS cache lookup | ~5ns |
| Bloom filter check | ~10ns |
| Arena lookup | ~30ns |
| Fingerprint check | ~20ns |
| Canary check | ~10ns |
| Bounds check | ~5ns |

### Key Formal Properties (Alien-Artifact Quality)

1. **Monotonic Safety:** Lattice join is commutative, associative, idempotent. States only decrease on new information.
2. **Galois Connection:** `gamma(alpha(c)) >= c`. Safe interpretation is at least as permissive as what correct programs need.
3. **Allocation Integrity:** P(undetected corruption) <= 2^-64 (SipHash collision probability).
4. **UAF Detection:** Generation counters detect use-after-free with probability 1.
5. **Buffer Overflow Detection:** Trailing canaries detect writes past allocation with P(miss) <= 2^-64.
6. **Healing Completeness:** Every libc function has defined healing for every class of invalid input.

### Key Design Decisions

- **Clean-room implementation** — spec-first, never line-by-line translate legacy glibc source
- **TSM validates at ABI boundary** — core implementations stay in safe Rust
- **Generational arena** with quarantine queue for temporal safety (UAF detection)
- **SipHash fingerprints** (16-byte header + 8-byte canary) for allocation integrity
- **Two-level page bitmap** for O(1) pointer ownership pre-check
- **Thread-local validation cache** (1024-entry direct-mapped) to avoid global lock on hot paths
- **Process-level runtime mode** (`strict`/`hardened`) immutable after init
- **Self-healing in hardened mode** — deterministic fallback instead of UB or crash
- **Atomic metrics counters** — every repair/denial emits evidence for auditability
- **Companion crates for tooling only** — asupersync and frankentui are build/test dependencies, not runtime libc deps

---

## Module Inventory (Full)

### frankenlibc-membrane — Safety Substrate

**Core modules:**
- `lattice.rs` — SafetyState enum with join/meet lattice operations
- `galois.rs` — Galois connection: C flat model <-> rich safety model
- `fingerprint.rs` — SipHash allocation fingerprints (16-byte header + 8-byte canary)
- `arena.rs` — Generational arena with quarantine queue
- `bloom.rs` — Bloom filter for O(1) pointer ownership pre-check
- `tls_cache.rs` — Thread-local validation cache (1024-entry direct-mapped)
- `page_oracle.rs` — Two-level page bitmap
- `heal.rs` — Self-healing policy engine + HealingAction enum
- `config.rs` — Runtime mode config (`strict`/`hardened`) from env var
- `metrics.rs` — Atomic counters for heals/validations/cache stats
- `ptr_validator.rs` — Full validation pipeline

**Runtime math control plane (`runtime_math/`):**
- `mod.rs` — Online control-plane orchestration
- `risk.rs` — Per-family risk envelope
- `bandit.rs` — Validation-depth router
- `control.rs` — Threshold controller
- `barrier.rs` — Admissibility oracle
- `cohomology.rs` — Shard-overlap consistency monitor
- `pareto.rs` — Latency/risk frontier + regret accounting
- `eprocess.rs` — Anytime-valid sequential risk monitor (e-values)
- `cvar.rs` — Distributionally-robust CVaR tail controller
- `design.rs` — D-optimal probe scheduling + identifiability control
- `sobol.rs` — Sobol low-discrepancy sequence generator for deterministic probe scheduling
- `redundancy_tuner.rs` — Adaptive evidence redundancy tuner using anytime-valid e-process updates
- `sparse.rs` — Online sparse latent-cause recovery + concentration state
- `fusion.rs` — Robust weighted fusion + entropy/drift telemetry
- `equivariant.rs` — Representation-stability transport + symmetry-break detection
- `higher_topos.rs` — Higher-topos descent diagnostics for locale/catalog coherence
- `commitment_audit.rs` — Commitment-algebra + martingale-audit tamper-evident session traces
- `changepoint.rs` — Bayesian online change-point detection (Adams & MacKay 2007)
- `conformal.rs` — Split conformal prediction risk controller (Vovk et al. 2005)
- `ktheory.rs` — K-theory transport ABI compatibility controller (Atiyah-Singer families index)
- `covering_array.rs` — Covering-array matroid conformance interaction coverage scheduler
- `derived_tstructure.rs` — Derived-category t-structure bootstrap ordering invariant controller
- `atiyah_bott.rs` — Atiyah-Bott fixed-point localization meta-controller
- `localization_chooser.rs` — Localization fixed-point policy chooser for concentrated anomaly regimes
- `pomdp_repair.rs` — Constrained POMDP repair policy controller with Bayesian belief tracking
- `sos_invariant.rs` — Sum-of-squares polynomial invariant runtime guard
- `sos_barrier.rs` — SOS barrier certificate runtime polynomial evaluator
- `admm_budget.rs` — ADMM operator-splitting budget allocator
- `obstruction_detector.rs` — Spectral-sequence obstruction detector for cross-layer consistency defects
- `operator_norm.rs` — Operator-norm spectral radius stability monitor
- `malliavin_sensitivity.rs` — Discrete Malliavin calculus sensitivity controller
- `info_geometry.rs` — Fisher-Rao geodesic distance monitor for structural regime shifts
- `matrix_concentration.rs` — Matrix Bernstein inequality spectral bounds
- `nerve_complex.rs` — Cech nerve theorem correlation coherence monitor with Betti number tracking
- `wasserstein_drift.rs` — 1-Wasserstein distance on severity histograms
- `kernel_mmd.rs` — Maximum Mean Discrepancy with RBF kernel
- `provenance_info.rs` — Information-theoretic provenance tag monitor (Shannon/Renyi/min-entropy)
- `policy_table.rs` — Proof-carrying policy table loader/verifier (`.pcpt` artifacts)
- `grobner_normalizer.rs` — Grobner-basis constraint normalizer
- `grothendieck_glue.rs` — Grothendieck site cocycle/descent/stackification coherence monitor
- `clifford.rs` — Clifford algebra + Spin/Pin symmetry methods for SIMD/alignment correctness
- `coupling.rs` — Probabilistic coupling + Azuma-Hoeffding concentration bounds
- `hodge_decomposition.rs` — Combinatorial Hodge decomposition for cyclic inconsistency detection
- `loss_minimizer.rs` — Decision-theoretic loss minimization for repair policy selection
- `lyapunov_stability.rs` — Maximal Lyapunov exponent estimation for chaotic dynamics detection
- `microlocal.rs` — Kashiwara-Schapira microlocal sheaf propagation
- `pac_bayes.rs` — PAC-Bayes generalization bound monitor
- `rademacher_complexity.rs` — Data-dependent Rademacher complexity bound
- `serre_spectral.rs` — Serre spectral sequence methods for cross-layer consistency
- `stein_discrepancy.rs` — Kernelized Stein Discrepancy for goodness-of-fit testing
- `transfer_entropy.rs` — Directed information-theoretic causality detection (Schreiber)
- `azuma_hoeffding.rs` — Azuma-Hoeffding martingale concentration monitor
- `bifurcation_detector.rs` — Bifurcation proximity detector for controller regime shifts
- `birkhoff_ergodic.rs` — Birkhoff ergodic convergence monitor
- `borel_cantelli.rs` — Borel-Cantelli recurrence monitor
- `dispersion_index.rs` — Fisher index-of-dispersion monitor
- `dobrushin_contraction.rs` — Dobrushin contraction coefficient monitor
- `doob_decomposition.rs` — Doob decomposition martingale monitor
- `entropy_rate.rs` — Shannon entropy-rate monitor for temporal complexity
- `evidence.rs` — Runtime evidence symbol record format and ring buffer
- `fano_bound.rs` — Fano mutual information bound monitor
- `hurst_exponent.rs` — Hurst exponent (R/S) monitor for long-range dependence
- `ito_quadratic_variation.rs` — Ito quadratic variation monitor for volatility
- `lempel_ziv.rs` — Lempel-Ziv complexity monitor for sequence compressibility
- `ornstein_uhlenbeck.rs` — Ornstein-Uhlenbeck mean-reversion monitor
- `renewal_theory.rs` — Renewal theory monitor for inter-arrival dynamics
- `spectral_gap.rs` — Spectral gap mixing-time monitor
- `submodular_coverage.rs` — Submodular validation stage coverage monitor
- `alpha_investing.rs` — Alpha-Investing FDR controller (Foster & Stine 2008)
- `approachability.rs` — Blackwell approachability controller

**Standalone membrane modules:**
- `risk_engine.rs` — Conformal risk scoring per API family
- `check_oracle.rs` — Thompson sampling contextual bandit for validation stage ordering
- `quarantine_controller.rs` — Primal-dual quarantine depth optimizer
- `tropical_latency.rs` — Min-plus algebra worst-case latency bounds
- `spectral_monitor.rs` — Marchenko-Pastur/Tracy-Widom phase transition detection
- `rough_path.rs` — Truncated depth-3 path signatures for noncommutative feature extraction
- `persistence.rs` — 0-dimensional Vietoris-Rips persistent homology
- `schrodinger_bridge.rs` — Entropy-regularized optimal transport regime-transition detector
- `large_deviations.rs` — Cramer rate-function rare-event monitor
- `hji_reachability.rs` — Hamilton-Jacobi-Isaacs differential game reachability controller
- `mean_field_game.rs` — Mean-field game Nash equilibrium contention controller
- `padic_valuation.rs` — Non-Archimedean p-adic valuation error calculus
- `symplectic_reduction.rs` — GIT/symplectic reduction IPC admissibility and deadlock detection

### frankenlibc-core — Safe Implementations

- `string/` — mem*, str*, wide string functions
- `stdlib/` — conversion, sort, env, random, exit
- `stdio/` — printf engine, scanf, file I/O, buffering
- `math/` — trig, exp, special functions, float utils
- `ctype/` — character classification
- `errno/` — thread-local errno
- `signal/` — signal handling
- `unistd/` — POSIX syscall wrappers
- `time/` — time/date functions
- `locale/` — locale support
- `pthread/` — mutex, condvar, rwlock, thread, TLS
- `malloc/` — size-class allocator, thread cache, large alloc
- `dirent/` — directory operations
- `socket/` — socket operations
- `inet/` — network address functions
- `resolv/` — DNS resolution
- `resource/` — resource limits
- `termios/` — terminal control
- `setjmp/` — non-local jumps
- `dlfcn/` — dynamic linking
- `iconv/` — character encoding conversion
- `io/` — low-level I/O

### frankenlibc-abi — ABI Boundary

- `macros.rs` — Helper macros for ABI declarations
- `runtime_policy.rs` — Shared runtime-kernel gate for ABI entrypoints
- `*_abi.rs` — One file per function family
- `version_scripts/libc.map` — GNU ld version script

### frankenlibc-harness — Conformance Testing

- `runner.rs` — Test execution engine
- `capture.rs` — Host libc fixture capture
- `verify.rs` — Output comparison
- `report.rs` — Report generation
- `traceability.rs` — Spec section mapping
- `fixtures.rs` — Fixture loading/management
- `diff.rs` — Diff rendering
- `membrane_tests.rs` — TSM-specific tests
- `healing_oracle.rs` — Intentional unsafe trigger + healing verification

---

## Required Methodology

### Clean-Room Porting

1. Spec-first: extract behavior into spec docs before implementation.
2. Never line-by-line translate legacy glibc source.
3. During implementation, work from extracted spec and standards contracts.

### Innovation Constraint

For memory safety architecture, do **not** search for existing off-the-shelf solutions as the primary design source. Invent from first principles for this project.

### Mandatory Skills

When designing safety mechanisms and performance architecture, explicitly apply:
- `alien-artifact-coding` — mathematical rigor, formal guarantees, lattice-theoretic safety
- `extreme-software-optimization` — profile-driven perf, behavior proofs, mandatory baseline/verify loop

### Reverse-Round Legacy Anchors (Keep Expanding)

All high-math design work must stay grounded in real legacy subsystem pressure points:
- `elf`, `sysdeps/*/dl-*` (loader/symbol/relocation)
- `malloc`, `nptl` (allocator/threading/temporal safety)
- `stdio-common`, `libio`, `io`, `posix` (streams/syscalls/parser surfaces)
- `locale`, `localedata`, `iconv`, `iconvdata`, `wcsmbs` (encoding/collation/transliteration)
- `nss`, `resolv`, `nscd`, `sunrpc` (identity/network lookup/cache/RPC)
- `math`, `soft-fp`, `sysdeps/ieee754` (numeric/fenv correctness)
- `time`, `timezone` (temporal discontinuity semantics)
- `signal`, `setjmp`, `nptl` cancellation (async/nonlocal control transfer)
- `termios`, `login`, `io`, `posix` (terminal/session/ioctl/process-tty edges)
- `elf` `dl-*`, hwcaps, tunables, audit (loader security and policy channels)
- `spawn/exec`, `glob/fnmatch/regex`, env/path (launch and pattern complexity surfaces)

If a proposed mathematical mechanism cannot be tied to one of these (or similarly concrete) legacy anchors, it is out of scope.

### Reverse Core Map (Do Not Drift)

For strategy discussions and architecture edits, use this direction:
surface -> failure class to eliminate -> alien math -> compiled runtime artifact.

1. Loader/symbol/IFUNC: eliminate global compatibility drift; ship resolver automata + compatibility witness ledgers.
2. Allocator: eliminate temporal/provenance corruption; ship allocator policy tables + admissibility guards.
3. Hot string/memory kernels: eliminate overlap/alignment/dispatch edge faults; ship regime classifiers + certified routing tables.
4. Futex/pthread/cancellation: eliminate race/starvation/timeout inconsistency; ship transition kernels + fairness budgets.
5. stdio/parser/locale formatting: eliminate parser-state explosions and locale drift; ship generated parser/transducer tables.
6. signal/setjmp control transfer: eliminate invalid non-local transitions; ship admissible jump/signal/cancel transition matrices.
7. time/timezone/rt timers: eliminate discontinuity/overrun semantic drift; ship temporal transition DAGs + timing envelopes.
8. nss/resolv/nscd/sunrpc: eliminate poisoning/retry/cache instability; ship deterministic lookup DAGs + calibrated thresholds.
9. locale/iconv/transliteration: eliminate conversion-state inconsistency; ship minimized codec automata + consistency certs.
10. ABI/time64/layout bridges: eliminate release-time compatibility fractures; ship invariant ledgers + drift alarms.
11. VM transitions: eliminate unsafe map/protection trajectories; ship VM transition guard complexes.
12. strict/hardened decision calibration: eliminate threshold drift; ship coverage-certified decision sets + abstain/escalate gates.
13. process bootstrap (`csu`, TLS init, auxv, secure mode): eliminate init-order races and secure-mode misclassification; ship startup dependency DAG + secure-mode policy automaton + init witness hashes.
14. cross-ISA syscall glue (`sysdeps/*`): eliminate architecture-specific semantic drift; ship per-ISA obligation matrices + dispatch witness caches.
15. System V IPC (`sysvipc`): eliminate capability drift and deadlock trajectories; ship semaphore admissibility guard polytopes + deadlock-cut certificates.
16. i18n catalog stack (`intl`, `catgets`, `localedata`): eliminate fallback/version incoherence; ship catalog-resolution automata + locale-consistency witness hashes.
17. diagnostics/unwinding (`debug`, backtrace): eliminate unsafe/non-deterministic frame-walk behavior; ship unwind stratification tables + safe-cut fallback matrices.
18. session accounting (`login`, utmp/wtmp): eliminate replay/tamper ambiguity and racey state transitions; ship deterministic session-ledger transitions + anomaly thresholds.
19. profiling hooks (`gmon`, sampling/probe): eliminate probe-induced benchmark distortion; ship minimal probe schedules + deterministic debias weights.
20. floating-point exceptional paths (`soft-fp`, `fenv`): eliminate denormal/NaN/payload drift across regimes; ship regime-indexed numeric guard tables + certified fallback kernels.

All of this must remain developer-transparent: contributors work with normal Rust modules/tests/policy tables, while the alien math remains in offline synthesis/proof artifacts.

### Mandatory Modern Math Stack (No Hand-Wavy Heuristics)

Use and document these explicitly in design/proof artifacts:
1. Abstract interpretation + Galois maps for pointer/lifetime domains.
2. Separation-logic style heap invariants for allocator and concurrency boundaries.
3. SMT-backed refinement checks for strict vs hardened semantics.
4. Decision-theoretic loss minimization for hardened repair policy selection.
5. Anytime-valid sequential testing (e-values/e-processes) for regression monitoring.
6. Bayesian change-point detection for drift in performance and repair-rate behavior.
7. Robust optimization targeting worst-case tail latency, not only mean latency.
8. Constrained POMDP policy design for hardened repair decisions.
9. CHC + CEGAR proof loops with automatic counterexample fixture generation.
10. Equality-saturation superoptimization with SMT equivalence certificates for hot kernels.
11. Information-theoretic provenance tag design with quantified collision/corruption bounds.
12. Wasserstein distributionally robust control + CVaR tail-risk optimization.
13. Barrier-certificate invariance constraints on runtime action admissibility.
14. Iris-style concurrent separation-logic proofs for lock-free/sharded metadata.
15. Hamilton-Jacobi-Isaacs reachability analysis for attacker-controller safety boundaries.
16. Sheaf-cohomology diagnostics for global metadata consistency across overlapping local views.
17. Covering-array + matroid combinatorics for high-order conformance interaction coverage.
18. Probabilistic coupling + concentration bounds for strict/hardened divergence certification.
19. Mean-field game control for thread-population contention dynamics.
20. Schrodinger-bridge entropic optimal transport for stable policy regime transitions.
21. Sum-of-squares certificate synthesis (SDP-backed) for nonlinear invariants.
22. Large-deviations rare-event analysis for catastrophic failure budgeting.
23. Persistent-homology topology-shift diagnostics for anomaly class detection.
24. Rough-path signature embeddings for long-horizon trace dynamics.
25. Tropical/min-plus algebra for compositional worst-case latency bounds.
26. Primal-dual operator-splitting with convergence certificates for online constrained tuning.
27. Conformal prediction/risk-control methods for finite-sample decision guarantees.
28. Spectral-sequence and obstruction-theory diagnostics for cross-layer consistency defects.
29. Semigroup/group-action/representation-theory methods for canonical behavior normalization.
30. Grobner-basis constraint normalization for reproducible proof kernels.
31. Noncommutative probability + random-matrix tail control for burst concurrency risk.
32. Serre spectral-sequence methods for multi-layer invariant lifting.
33. Grothendieck site/topos/descent/stackification methods for local-to-global coherence and compatibility gluing.
34. Atiyah-Singer families index and K-theory transport methods for compatibility integrity.
35. Atiyah-Bott localization methods for fixed-point compression of proof/benchmark obligations.
36. Clifford/geometric algebra + Spin/Pin symmetry methods for SIMD/alignment/overlap kernel correctness.
37. Microlocal sheaf-theoretic propagation methods (Kashiwara-Schapira style) for unwind/signal fault-surface control.
38. Derived-category/t-structure decomposition methods for process-bootstrap ordering invariants.
39. Geometric invariant theory + symplectic reduction for System V IPC admissibility and deadlock elimination.
40. Non-Archimedean (p-adic valuation) error calculus for exceptional floating-point regime control.
41. Optimal experimental design + sparse recovery methods for low-perturbation profiling/probe scheduling.
42. Higher-topos internal logic and descent diagnostics for locale/catalog coherence proofs.
43. Representation-stability and equivariant transport methods for cross-ISA syscall semantic alignment.
44. Commitment-algebra + martingale-audit methods for tamper-evident session/accounting traces.

Branch-diversity rule:
1. Every major subsystem milestone must use at least 3 distinct math families.
2. Each milestone must include at least one obligation from conformal statistics, algebraic topology, abstract algebra, and Grothendieck-Serre methods.
3. No single family should dominate more than 40% of the milestone obligations.
4. SIMD/ABI/compatibility milestones must include Atiyah-Singer/K-theory/localization and Clifford/geometric algebra obligations.

### Developer Transparency Contract

Regular contributors must not need to understand the alien-math internals.
1. Expose only normal Rust APIs and plain policy tables in day-to-day code.
2. Keep advanced math in generated artifacts, proof reports, and CI checks.
3. Any mathematically-derived runtime logic must compile down to simple deterministic guards/dispatch.

---

## Conformance & Benchmark Discipline

### Testing & Conformance Workflow

1. **Fixture capture:** Run test vectors against host glibc, serialize inputs/outputs as JSON.
2. **Fixture verify:** Run same vectors against our implementation, compare outputs.
3. **Traceability:** Map every test to POSIX/C11 spec sections + TSM spec sections.
4. **Healing oracle:** Intentionally trigger unsafe conditions, verify healing behavior.
5. **Benchmark gate:** No regressions; membrane overhead within budget.

### Quality Gates (Run After Every Substantive Change)

```bash
cargo fmt --check
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
```

### Rules

1. No feature is "DONE" without fixture-based conformance proof.
2. No optimization claims without baseline/profile/verify loop.
3. Keep `FEATURE_PARITY.md` synchronized with reality (no aspirational DONE entries).

### Required Docs (Keep Updated)

- `PLAN_TO_PORT_GLIBC_TO_RUST.md`
- `EXISTING_GLIBC_STRUCTURE.md`
- `PROPOSED_ARCHITECTURE.md`
- `FEATURE_PARITY.md`

---

## MCP Agent Mail — Multi-Agent Coordination

A mail-like layer that lets coding agents coordinate asynchronously via MCP tools and resources. Provides identities, inbox/outbox, searchable threads, and advisory file reservations with human-auditable artifacts in Git.

### Why It's Useful

- **Prevents conflicts:** Explicit file reservations (leases) for files/globs
- **Token-efficient:** Messages stored in per-project archive, not in context
- **Quick reads:** `resource://inbox/...`, `resource://thread/...`

### Same Repository Workflow

1. **Register identity:**
   ```
   ensure_project(project_key=<abs-path>)
   register_agent(project_key, program, model)
   ```

2. **Reserve files before editing:**
   ```
   file_reservation_paths(project_key, agent_name, ["src/**"], ttl_seconds=3600, exclusive=true)
   ```

3. **Communicate with threads:**
   ```
   send_message(..., thread_id="FEAT-123")
   fetch_inbox(project_key, agent_name)
   acknowledge_message(project_key, agent_name, message_id)
   ```

4. **Quick reads:**
   ```
   resource://inbox/{Agent}?project=<abs-path>&limit=20
   resource://thread/{id}?project=<abs-path>&include_bodies=true
   ```

### Macros vs Granular Tools

- **Prefer macros for speed:** `macro_start_session`, `macro_prepare_thread`, `macro_file_reservation_cycle`, `macro_contact_handshake`
- **Use granular tools for control:** `register_agent`, `file_reservation_paths`, `send_message`, `fetch_inbox`, `acknowledge_message`

### Common Pitfalls

- `"from_agent not registered"`: Always `register_agent` in the correct `project_key` first
- `"FILE_RESERVATION_CONFLICT"`: Adjust patterns, wait for expiry, or use non-exclusive reservation
- **Auth errors:** If JWT+JWKS enabled, include bearer token with matching `kid`

---

## Beads (br) — Dependency-Aware Issue Tracking

Beads provides a lightweight, dependency-aware issue database and CLI (`br` - beads_rust) for selecting "ready work," setting priorities, and tracking status. It complements MCP Agent Mail's messaging and file reservations.

**Important:** `br` is non-invasive—it NEVER runs git commands automatically. You must manually commit changes after `br sync --flush-only`.

### Conventions

- **Single source of truth:** Beads for task status/priority/dependencies; Agent Mail for conversation and audit
- **Shared identifiers:** Use Beads issue ID (e.g., `br-123`) as Mail `thread_id` and prefix subjects with `[br-123]`
- **Reservations:** When starting a task, call `file_reservation_paths()` with the issue ID in `reason`

### Typical Agent Flow

1. **Pick ready work (Beads):**
   ```bash
   br ready --json  # Choose highest priority, no blockers
   ```

2. **Reserve edit surface (Mail):**
   ```
   file_reservation_paths(project_key, agent_name, ["src/**"], ttl_seconds=3600, exclusive=true, reason="br-123")
   ```

3. **Announce start (Mail):**
   ```
   send_message(..., thread_id="br-123", subject="[br-123] Start: <title>", ack_required=true)
   ```

4. **Work and update:** Reply in-thread with progress

5. **Complete and release:**
   ```bash
   br close 123 --reason "Completed"
   br sync --flush-only  # Export to JSONL (no git operations)
   ```
   ```
   release_file_reservations(project_key, agent_name, paths=["src/**"])
   ```
   Final Mail reply: `[br-123] Completed` with summary

### Mapping Cheat Sheet

| Concept | Value |
|---------|-------|
| Mail `thread_id` | `br-###` |
| Mail subject | `[br-###] ...` |
| File reservation `reason` | `br-###` |
| Commit messages | Include `br-###` for traceability |

---

## bv — Graph-Aware Triage Engine

bv is a graph-aware triage engine for Beads projects (`.beads/beads.jsonl`). It computes PageRank, betweenness, critical path, cycles, HITS, eigenvector, and k-core metrics deterministically.

**Scope boundary:** bv handles *what to work on* (triage, priority, planning). For agent-to-agent coordination (messaging, work claiming, file reservations), use MCP Agent Mail.

**CRITICAL: Use ONLY `--robot-*` flags. Bare `bv` launches an interactive TUI that blocks your session.**

### The Workflow: Start With Triage

**`bv --robot-triage` is your single entry point.** It returns:
- `quick_ref`: at-a-glance counts + top 3 picks
- `recommendations`: ranked actionable items with scores, reasons, unblock info
- `quick_wins`: low-effort high-impact items
- `blockers_to_clear`: items that unblock the most downstream work
- `project_health`: status/type/priority distributions, graph metrics
- `commands`: copy-paste shell commands for next steps

```bash
bv --robot-triage        # THE MEGA-COMMAND: start here
bv --robot-next          # Minimal: just the single top pick + claim command
```

### Command Reference

**Planning:**
| Command | Returns |
|---------|---------|
| `--robot-plan` | Parallel execution tracks with `unblocks` lists |
| `--robot-priority` | Priority misalignment detection with confidence |

**Graph Analysis:**
| Command | Returns |
|---------|---------|
| `--robot-insights` | Full metrics: PageRank, betweenness, HITS, eigenvector, critical path, cycles, k-core, articulation points, slack |
| `--robot-label-health` | Per-label health: `health_level`, `velocity_score`, `staleness`, `blocked_count` |
| `--robot-label-flow` | Cross-label dependency: `flow_matrix`, `dependencies`, `bottleneck_labels` |
| `--robot-label-attention [--attention-limit=N]` | Attention-ranked labels |

**History & Change Tracking:**
| Command | Returns |
|---------|---------|
| `--robot-history` | Bead-to-commit correlations |
| `--robot-diff --diff-since <ref>` | Changes since ref: new/closed/modified issues, cycles |

**Other:**
| Command | Returns |
|---------|---------|
| `--robot-burndown <sprint>` | Sprint burndown, scope changes, at-risk items |
| `--robot-forecast <id\|all>` | ETA predictions with dependency-aware scheduling |
| `--robot-alerts` | Stale issues, blocking cascades, priority mismatches |
| `--robot-suggest` | Hygiene: duplicates, missing deps, label suggestions |
| `--robot-graph [--graph-format=json\|dot\|mermaid]` | Dependency graph export |
| `--export-graph <file.html>` | Interactive HTML visualization |

### Scoping & Filtering

```bash
bv --robot-plan --label backend              # Scope to label's subgraph
bv --robot-insights --as-of HEAD~30          # Historical point-in-time
bv --recipe actionable --robot-plan          # Pre-filter: ready to work
bv --recipe high-impact --robot-triage       # Pre-filter: top PageRank
bv --robot-triage --robot-triage-by-track    # Group by parallel work streams
bv --robot-triage --robot-triage-by-label    # Group by domain
```

### Understanding Robot Output

**All robot JSON includes:**
- `data_hash` — Fingerprint of source beads.jsonl
- `status` — Per-metric state: `computed|approx|timeout|skipped` + elapsed ms
- `as_of` / `as_of_commit` — Present when using `--as-of`

**Two-phase analysis:**
- **Phase 1 (instant):** degree, topo sort, density
- **Phase 2 (async, 500ms timeout):** PageRank, betweenness, HITS, eigenvector, cycles

### jq Quick Reference

```bash
bv --robot-triage | jq '.quick_ref'                        # At-a-glance summary
bv --robot-triage | jq '.recommendations[0]'               # Top recommendation
bv --robot-plan | jq '.plan.summary.highest_impact'        # Best unblock target
bv --robot-insights | jq '.status'                         # Check metric readiness
bv --robot-insights | jq '.Cycles'                         # Circular deps (must fix!)
```

---

## UBS — Ultimate Bug Scanner

**Golden Rule:** `ubs <changed-files>` before every commit. Exit 0 = safe. Exit >0 = fix & re-run.

### Commands

```bash
ubs file.rs file2.rs                    # Specific files (< 1s) — USE THIS
ubs $(git diff --name-only --cached)    # Staged files — before commit
ubs --only=rust,toml src/               # Language filter (3-5x faster)
ubs --ci --fail-on-warning .            # CI mode — before PR
ubs .                                   # Whole project (ignores target/, Cargo.lock)
```

### Output Format

```
Warning  Category (N errors)
    file.rs:42:5 - Issue description
    Suggested fix
Exit code: 1
```

Parse: `file:line:col` -> location | fix suggestion -> how to fix | Exit 0/1 -> pass/fail

### Fix Workflow

1. Read finding -> category + fix suggestion
2. Navigate `file:line:col` -> view context
3. Verify real issue (not false positive)
4. Fix root cause (not symptom)
5. Re-run `ubs <file>` -> exit 0
6. Commit

### Bug Severity

- **Critical (always fix):** Memory safety, use-after-free, data races, SQL injection
- **Important (production):** Unwrap panics, resource leaks, overflow checks
- **Contextual (judgment):** TODO/FIXME, println! debugging

---

## RCH — Remote Compilation Helper

RCH offloads `cargo build`, `cargo test`, `cargo clippy`, and other compilation commands to a fleet of 8 remote Contabo VPS workers instead of building locally. This prevents compilation storms from overwhelming csd when many agents run simultaneously.

**RCH is installed at `~/.local/bin/rch` and is hooked into Claude Code's PreToolUse automatically.** Most of the time you don't need to do anything if you are Claude Code — builds are intercepted and offloaded transparently.

To manually offload a build:
```bash
rch exec -- cargo build --release
rch exec -- cargo test
rch exec -- cargo clippy
```

Quick commands:
```bash
rch doctor                    # Health check
rch workers probe --all       # Test connectivity to all 8 workers
rch status                    # Overview of current state
rch queue                     # See active/waiting builds
```

If rch or its workers are unavailable, it fails open — builds run locally as normal.

**Note for Codex/GPT-5.2:** Codex does not have the automatic PreToolUse hook, but you can (and should) still manually offload compute-intensive compilation commands using `rch exec -- <command>`. This avoids local resource contention when multiple agents are building simultaneously.

---

## ast-grep vs ripgrep

**Use `ast-grep` when structure matters.** It parses code and matches AST nodes, ignoring comments/strings, and can **safely rewrite** code.

- Refactors/codemods: rename APIs, change import forms
- Policy checks: enforce patterns across a repo
- Editor/automation: LSP mode, `--json` output

**Use `ripgrep` when text is enough.** Fastest way to grep literals/regex.

- Recon: find strings, TODOs, log lines, config values
- Pre-filter: narrow candidate files before ast-grep

### Rule of Thumb

- Need correctness or **applying changes** -> `ast-grep`
- Need raw speed or **hunting text** -> `rg`
- Often combine: `rg` to shortlist files, then `ast-grep` to match/modify

### Rust Examples

```bash
# Find structured code (ignores comments)
ast-grep run -l Rust -p 'fn $NAME($$$ARGS) -> $RET { $$$BODY }'

# Find all unwrap() calls
ast-grep run -l Rust -p '$EXPR.unwrap()'

# Quick textual hunt
rg -n 'println!' -t rust

# Combine speed + precision
rg -l -t rust 'unwrap\(' | xargs ast-grep run -l Rust -p '$X.unwrap()' --json
```

---

## Morph Warp Grep — AI-Powered Code Search

**Use `mcp__morph-mcp__warp_grep` for exploratory "how does X work?" questions.** An AI agent expands your query, greps the codebase, reads relevant files, and returns precise line ranges with full context.

**Use `ripgrep` for targeted searches.** When you know exactly what you're looking for.

**Use `ast-grep` for structural patterns.** When you need AST precision for matching/rewriting.

### When to Use What

| Scenario | Tool | Why |
|----------|------|-----|
| "How does the TSM validation pipeline work?" | `warp_grep` | Exploratory; don't know where to start |
| "Where is the healing policy implemented?" | `warp_grep` | Need to understand architecture |
| "Find all uses of `SafetyState::join`" | `ripgrep` | Targeted literal search |
| "Find files with `println!`" | `ripgrep` | Simple pattern |
| "Replace all `unwrap()` with `expect()`" | `ast-grep` | Structural refactor |

### warp_grep Usage

```
mcp__morph-mcp__warp_grep(
  repoPath: "/dp/frankenlibc",
  query: "How does the transparent safety membrane validate pointers?"
)
```

Returns structured results with file paths, line ranges, and extracted code snippets.

### Anti-Patterns

- **Don't** use `warp_grep` to find a specific function name -> use `ripgrep`
- **Don't** use `ripgrep` to understand "how does X work" -> wastes time with manual reads
- **Don't** use `ripgrep` for codemods -> risks collateral edits

<!-- bv-agent-instructions-v1 -->

---

## Beads Workflow Integration

This project uses [beads_rust](https://github.com/Dicklesworthstone/beads_rust) (`br`) for issue tracking. Issues are stored in `.beads/` and tracked in git.

**Important:** `br` is non-invasive—it NEVER executes git commands. After `br sync --flush-only`, you must manually run `git add .beads/ && git commit`.

### Essential Commands

```bash
# View issues (launches TUI - avoid in automated sessions)
bv

# CLI commands for agents (use these instead)
br ready              # Show issues ready to work (no blockers)
br list --status=open # All open issues
br show <id>          # Full issue details with dependencies
br create --title="..." --type=task --priority=2
br update <id> --status=in_progress
br close <id> --reason "Completed"
br close <id1> <id2>  # Close multiple issues at once
br sync --flush-only  # Export to JSONL (NO git operations)
```

### Workflow Pattern

1. **Start**: Run `br ready` to find actionable work
2. **Claim**: Use `br update <id> --status=in_progress`
3. **Work**: Implement the task
4. **Complete**: Use `br close <id>`
5. **Sync**: Run `br sync --flush-only` then manually commit

### Key Concepts

- **Dependencies**: Issues can block other issues. `br ready` shows only unblocked work.
- **Priority**: P0=critical, P1=high, P2=medium, P3=low, P4=backlog (use numbers, not words)
- **Types**: task, bug, feature, epic, question, docs
- **Blocking**: `br dep add <issue> <depends-on>` to add dependencies

### Session Protocol

**Before ending any session, run this checklist:**

```bash
git status              # Check what changed
git add <files>         # Stage code changes
br sync --flush-only    # Export beads to JSONL
git add .beads/         # Stage beads changes
git commit -m "..."     # Commit everything together
git push                # Push to remote
```

### Best Practices

- Check `br ready` at session start to find available work
- Update status as you work (in_progress -> closed)
- Create new issues with `br create` when you discover tasks
- Use descriptive titles and set appropriate priority/type
- Always `br sync --flush-only && git add .beads/` before ending session

<!-- end-bv-agent-instructions -->

## Landing the Plane (Session Completion)

**When ending a work session**, you MUST complete ALL steps below.

**MANDATORY WORKFLOW:**

1. **File issues for remaining work** - Create issues for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **Sync beads** - `br sync --flush-only` to export to JSONL
5. **Hand off** - Provide context for next session


---

Note for Codex/GPT-5.2:

You constantly bother me and stop working with concerned questions that look similar to this:

```
Unexpected changes (need guidance)

- Working tree still shows edits I did not make in Cargo.toml, Cargo.lock, src/cli/commands/upgrade.rs, src/storage/sqlite.rs, tests/conformance.rs, tests/storage_deps.rs. Please advise whether to keep/commit/revert these before any further work. I did not touch them.

Next steps (pick one)

1. Decide how to handle the unrelated modified files above so we can resume cleanly.
2. Triage beads_rust-orko (clippy/cargo warnings) and beads_rust-ydqr (rustfmt failures).
3. If you want a full suite run later, fix conformance/clippy blockers and re-run cargo test --all.
```

NEVER EVER DO THAT AGAIN. The answer is literally ALWAYS the same: those are changes created by the potentially dozen of other agents working on the project at the same time. This is not only a common occurence, it happens multiple times PER MINUTE. The way to deal with it is simple: you NEVER, under ANY CIRCUMSTANCE, stash, revert, overwrite, or otherwise disturb in ANY way the work of other agents. Just treat those changes identically to changes that you yourself made. Just fool yourself into thinking YOU made the changes and simply don't recall it for some reason.

---

## Note on Built-in TODO Functionality

Also, if I ask you to explicitly use your built-in TODO functionality, don't complain about this and say you need to use beads. You can use built-in TODOs if I tell you specifically to do so. Always comply with such orders.
