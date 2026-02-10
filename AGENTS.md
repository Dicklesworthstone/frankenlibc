# AGENTS.md — glibc_rust

> Guidelines for AI coding agents working in the glibc_rust workspace.

---

## RULE 0 - THE FUNDAMENTAL OVERRIDE PREROGATIVE

If I tell you to do something, even if it goes against what follows below, YOU MUST LISTEN TO ME. I AM IN CHARGE, NOT YOU.

---

## RULE NUMBER 1: NO FILE DELETION

**YOU ARE NEVER ALLOWED TO DELETE A FILE WITHOUT EXPRESS PERMISSION.**

**YOU MUST ALWAYS ASK AND RECEIVE CLEAR, WRITTEN PERMISSION BEFORE EVER DELETING A FILE OR FOLDER OF ANY KIND.**

---

## Irreversible Git & Filesystem Actions — DO NOT EVER BREAK GLASS

1. **Absolutely forbidden commands:** `git reset --hard`, `git clean -fd`, `rm -rf`, or any command that can delete or overwrite code/data must never be run unless the user explicitly provides the exact command and states, in the same message, that they understand and want the irreversible consequences.
2. **No guessing:** If there is any uncertainty about what a command might delete or overwrite, stop immediately and ask the user for specific approval.
3. **Safer alternatives first:** For cleanup/rollback, use non-destructive options first (`git status`, `git diff`, `git stash`, backups).
4. **Mandatory explicit plan:** Even after explicit authorization, restate command verbatim, list impact, and wait for confirmation.
5. **Document the confirmation:** If any approved destructive command is run, record exact user authorization text, command run, and execution time in final response.

---

## Git Branch Rules

- **Only `main` is allowed** as the mainline branch name — never introduce `master` references.
- Feature branches: `feat/<topic>`, bugfix: `fix/<topic>`, experiments: `exp/<topic>`.
- No force-push without explicit user confirmation of both the command and its scope.

---

## Code Editing Discipline

1. Always read the file before modifying it.
2. Never blindly rewrite large sections — understand the existing code first.
3. Prefer small, targeted edits over full-file rewrites.
4. Preserve existing formatting, style, and structure unless explicitly asked to change it.
5. If a file has been modified by another agent concurrently, re-read before editing.

---

## Project Description

**glibc_rust** is a clean-room, memory-safe Rust reimplementation of glibc targeting full POSIX coverage plus GNU extensions. It produces an ABI-compatible `libc.so` that can be used as a drop-in replacement for glibc.

### The Core Innovation: Transparent Safety Membrane (TSM)

C code thinks it has full control over raw pointers, but behind the ABI boundary, glibc_rust dynamically validates, sanitizes, and mechanically fixes invalid operations so memory unsafety cannot happen through libc calls.

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

---

## Workspace Structure

```
glibc_rust/
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
│   ├── glibc-rs-membrane/        # THE INNOVATION — validation pipeline
│   ├── glibc-rs-core/            # Safe Rust implementations (#![deny(unsafe_code)])
│   ├── glibc-rs-abi/             # extern "C" cdylib boundary (produces libc.so)
│   ├── glibc-rs-harness/         # Conformance testing framework
│   ├── glibc-rs-bench/           # Criterion benchmarks
│   └── glibc-rs-fuzz/            # cargo-fuzz targets
├── tests/
│   ├── conformance/fixtures/     # Reference fixture JSONs
│   └── integration/              # C program link tests
└── scripts/                      # CI, symbol extraction, ABI comparison
```

### Companion Crates (Build Tooling Only)

- `/dp/frankentui` — TUI framework for inline-mode build/test progress UI
- `/dp/asupersync` — Async runtime with deterministic testing, oracles, conformance harness

Hard requirement (verbatim):
This project must leverage:
- `/dp/asupersync` for deterministic conformance orchestration and traceability/reporting primitives.
- `/dp/frankentui` for deterministic diff/snapshot-oriented harness output and TUI-driven analysis tooling.

These are build/test tooling roles, NOT runtime libc dependencies.

---

## TSM Architecture Overview

### Runtime Modes (Hard Requirement)

- `strict` (default): strict ABI-compatible behavior, no repair rewrites.
- `hardened`: TSM repair behavior for invalid/unsafe patterns.
- Runtime selection is process-level and immutable after init (`GLIBC_RUST_MODE=strict|hardened`).

### Safety State Lattice

```
Valid > Readable > Writable > Quarantined > Freed > Invalid > Unknown
```

States flow monotonically toward more restrictive on new information. Join is commutative, associative, idempotent.

### Galois Connection

For any C operation `c`: `gamma(alpha(c)) >= c`. The safe interpretation is always at least as permissive as what a correct program needs.

### Validation Pipeline

```
null check (1ns) → TLS cache (5ns) → bloom filter (10ns) → arena lookup (30ns)
→ fingerprint check (20ns) → canary check (10ns) → bounds check (5ns)
```

Fast exits at each stage. Budget target: strict overhead <20ns/call, hardened overhead <200ns/call for membrane-gated hot paths.

### Allocation Integrity

- 16-byte SipHash fingerprint header + 8-byte canary per allocation
- Generational arena with quarantine queue for UAF detection
- Two-level page bitmap for O(1) "is this pointer ours?" pre-check
- Thread-local 1024-entry validation cache to avoid global lock

### Self-Healing Actions

`ClampSize | TruncateWithNull | IgnoreDoubleFree | IgnoreForeignFree | ReallocAsMalloc | ReturnSafeDefault | UpgradeToSafeVariant`

### Runtime Math Kernel (Hard Requirement)

The advanced math stack must execute in runtime via compact control kernels, not only offline reports.

Mandatory live modules in `glibc-rs-membrane/src/runtime_math/`:
1. `risk.rs` — online conformal-style risk upper bounds per API family.
2. `bandit.rs` — constrained routing of `Fast` vs `Full` validation profiles.
3. `control.rs` — primal-dual threshold controller for full-check/repair triggers.
4. `barrier.rs` — constant-time admissibility guard.
5. `cohomology.rs` — overlap-consistency monitor for sharded metadata.
6. `pareto.rs` — mode-aware latency/risk Pareto selector with cumulative regret tracking and per-family hard regret caps.
7. `design.rs` — runtime D-optimal probe scheduler under strict/hardened budget constraints.
8. `sparse.rs` — online L1 sparse-recovery controller for latent fault-source concentration.
9. `fusion.rs` — online robust signal-fusion controller over runtime math kernels.
10. `equivariant.rs` — representation-stability/group-action symmetry monitor for cross-family semantic drift.

Runtime decision law (per call):
`mode + context + risk + budget + pareto + design + barrier + consistency -> Allow | FullValidate | Repair | Deny`.

Current live extensions:
- `runtime_math/eprocess.rs` — anytime-valid sequential alarming (e-values).
- `runtime_math/cvar.rs` — distributionally-robust CVaR tail-risk guard.
- `runtime_math/design.rs` — D-optimal heavy-probe selection with online identifiability tracking.
- `runtime_math/sparse.rs` — compressed-sensing style latent root-cause recovery from probe anomalies.
- `runtime_math/fusion.rs` — adaptive trust-weighted fusion bonus over heterogeneous anomaly signals.
- `runtime_math/equivariant.rs` — cross-family equivariant transport drift detector with symmetry-breaking escalation.
- `hji_reachability.rs` — HJI differential game safety certificates (math #15).
- `mean_field_game.rs` — mean-field Nash equilibrium congestion controller (math #19).

Developer transparency remains mandatory:
- contributors write normal Rust APIs/tests/policies,
- runtime executes compact deterministic kernels,
- heavy theorem machinery stays in synthesis/proof pipelines.

---

## Unsafe Code Policy

| Crate | Policy | Notes |
|-------|--------|-------|
| `glibc-rs-core` | `#![deny(unsafe_code)]` | Safe Rust only. SIMD modules get `#[allow(unsafe_code)]` with per-block `// SAFETY:` comments. |
| `glibc-rs-membrane` | `#![deny(unsafe_code)]` | Arena/fingerprint modules get `#[allow(unsafe_code)]` for raw pointer ops. Every unsafe block must have `// SAFETY:` comment. |
| `glibc-rs-abi` | `#![allow(unsafe_code)]` | ABI boundary is inherently unsafe. Every function body is minimal: validate via membrane, delegate to core. |
| `glibc-rs-harness` | `#![forbid(unsafe_code)]` | Test harness never needs unsafe. |
| `glibc-rs-bench` | `#![allow(unsafe_code)]` | Benchmarks call extern "C" functions. |
| `glibc-rs-fuzz` | `#![allow(unsafe_code)]` | Fuzz harnesses call extern "C" functions. |

Rules:
1. Unsafe is permitted only in explicitly documented boundary modules.
2. All unsafe blocks require written invariants and safety preconditions (`// SAFETY:` comment).
3. Core algorithmic behavior must stay in safe Rust.
4. Memory safety is achieved via the TSM, not by pretending FFI unsafe does not exist.

---

## Module Inventory

### glibc-rs-membrane (Safety Substrate)
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
- `runtime_math/mod.rs` — online control-plane orchestration
- `runtime_math/risk.rs` — per-family risk envelope
- `runtime_math/bandit.rs` — validation-depth router
- `runtime_math/control.rs` — threshold controller
- `runtime_math/barrier.rs` — admissibility oracle
- `runtime_math/cohomology.rs` — shard-overlap consistency monitor
- `runtime_math/pareto.rs` — latency/risk frontier + regret accounting
- `runtime_math/eprocess.rs` — anytime-valid sequential risk monitor (e-values)
- `runtime_math/cvar.rs` — distributionally-robust CVaR tail controller
- `runtime_math/design.rs` — D-optimal probe scheduling + identifiability control
- `runtime_math/sparse.rs` — online sparse latent-cause recovery + concentration state
- `runtime_math/fusion.rs` — robust weighted fusion + entropy/drift telemetry
- `runtime_math/equivariant.rs` — representation-stability transport + symmetry-break detection
- `risk_engine.rs` — conformal risk scoring per API family (sampled, feeds cached bonus)
- `check_oracle.rs` — Thompson sampling contextual bandit for validation stage ordering
- `quarantine_controller.rs` — primal-dual quarantine depth optimizer
- `tropical_latency.rs` — min-plus algebra worst-case latency bounds (math #25)
- `spectral_monitor.rs` — Marchenko-Pastur/Tracy-Widom phase transition detection (math #31)
- `rough_path.rs` — truncated depth-3 path signatures for universal noncommutative feature extraction (math #24, #29)
- `persistence.rs` — 0-dimensional Vietoris-Rips persistent homology for topological anomaly detection (math #23)
- `schrodinger_bridge.rs` — entropy-regularized optimal transport regime-transition detector (math #20)
- `large_deviations.rs` — Cramér rate-function rare-event monitor (math #22)
- `hji_reachability.rs` — Hamilton-Jacobi-Isaacs differential game reachability controller (math #15)
- `mean_field_game.rs` — Mean-field game Nash equilibrium contention controller (math #19)
- `runtime_math/padic_valuation.rs` — Non-Archimedean p-adic valuation error calculus for floating-point exceptional regimes (math #40)
- `runtime_math/symplectic_reduction.rs` — GIT/symplectic reduction IPC admissibility and deadlock detection (math #39)
- `runtime_math/higher_topos.rs` — Higher-topos descent diagnostics for locale/catalog coherence (math #42)
- `runtime_math/commitment_audit.rs` — Commitment-algebra + martingale-audit tamper-evident session traces (math #44)
- `runtime_math/changepoint.rs` — Bayesian online change-point detection (Adams & MacKay 2007) with Beta-Bernoulli conjugate model (math #6)
- `runtime_math/conformal.rs` — Split conformal prediction risk controller (Vovk et al. 2005) with finite-sample coverage guarantees (math #27)
- `runtime_math/ktheory.rs` — K-theory transport ABI compatibility controller (Atiyah-Singer families index, math #34)
- `runtime_math/covering_array.rs` — Covering-array matroid conformance interaction coverage scheduler (math #17)
- `runtime_math/derived_tstructure.rs` — Derived-category t-structure bootstrap ordering invariant controller (math #38)
- `runtime_math/atiyah_bott.rs` — Atiyah-Bott fixed-point localization meta-controller for hot-path anomaly concentration detection (math #35)
- `runtime_math/pomdp_repair.rs` — Constrained POMDP repair policy controller with Bayesian belief tracking and Bellman value iteration (math #8)
- `runtime_math/sos_invariant.rs` — Sum-of-squares polynomial invariant runtime guard for cross-controller coherence verification (math #21)
- `runtime_math/provenance_info.rs` — Information-theoretic provenance tag monitor with Shannon/Rényi/min-entropy collision bounds (math #11)
- `runtime_math/grobner_normalizer.rs` — Gröbner-basis constraint normalizer for confluent controller-state consistency verification (math #30)
- `runtime_math/grothendieck_glue.rs` — Grothendieck site cocycle/descent/stackification coherence monitor for NSS/resolv/locale source gluing (math #33)

### glibc-rs-core (Safe Implementations)
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

### glibc-rs-abi (ABI Boundary)
- `macros.rs` — Helper macros for ABI declarations
- `runtime_policy.rs` — shared runtime-kernel gate for ABI entrypoints
- `*_abi.rs` — One file per function family
- `version_scripts/libc.map` — GNU ld version script

### glibc-rs-harness (Conformance Testing)
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
20. Schrödinger-bridge entropic optimal transport for stable policy regime transitions.
21. Sum-of-squares certificate synthesis (SDP-backed) for nonlinear invariants.
22. Large-deviations rare-event analysis for catastrophic failure budgeting.
23. Persistent-homology topology-shift diagnostics for anomaly class detection.
24. Rough-path signature embeddings for long-horizon trace dynamics.
25. Tropical/min-plus algebra for compositional worst-case latency bounds.
26. Primal-dual operator-splitting with convergence certificates for online constrained tuning.
27. Conformal prediction/risk-control methods for finite-sample decision guarantees.
28. Spectral-sequence and obstruction-theory diagnostics for cross-layer consistency defects.
29. Semigroup/group-action/representation-theory methods for canonical behavior normalization.
30. Gröbner-basis constraint normalization for reproducible proof kernels.
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

## Testing & Conformance Workflow

1. **Fixture capture:** Run test vectors against host glibc, serialize inputs/outputs as JSON.
2. **Fixture verify:** Run same vectors against our implementation, compare outputs.
3. **Traceability:** Map every test to POSIX/C11 spec sections + TSM spec sections.
4. **Healing oracle:** Intentionally trigger unsafe conditions, verify healing behavior.
5. **Benchmark gate:** No regressions; membrane overhead within budget.

### Quality Gates (Run After Every Substantive Change)

```bash
cargo fmt --check
cargo check --all-targets
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
```

---

## Conformance & Benchmark Discipline

1. No feature is "DONE" without fixture-based conformance proof.
2. No optimization claims without baseline/profile/verify loop.
3. Keep `FEATURE_PARITY.md` synchronized with reality (no aspirational DONE entries).

---

## Key Formal Properties (Alien-Artifact Quality)

1. **Monotonic Safety:** Lattice join is commutative, associative, idempotent. States only decrease on new information.
2. **Galois Connection:** `gamma(alpha(c)) >= c`. Safe interpretation is at least as permissive as what correct programs need.
3. **Allocation Integrity:** P(undetected corruption) <= 2^-64 (SipHash collision probability).
4. **UAF Detection:** Generation counters detect use-after-free with probability 1.
5. **Buffer Overflow Detection:** Trailing canaries detect writes past allocation with P(miss) <= 2^-64.
6. **Healing Completeness:** Every libc function has defined healing for every class of invalid input.

---

## Required Docs (Keep Updated)

- `PLAN_TO_PORT_GLIBC_TO_RUST.md`
- `EXISTING_GLIBC_STRUCTURE.md`
- `PROPOSED_ARCHITECTURE.md`
- `FEATURE_PARITY.md`

---

## Toolchain & Branch Rules

- Rust edition: **2024**
- Toolchain: nightly
- Package manager: Cargo only
- Branch: `main` only (never introduce `master` references)

---

## Beads

If there is a `.beads/` directory in this workspace, it contains task-tracking artifacts. Respect their format and do not delete bead files.

---

## Agent Mail

If there is an `.agent_mail/` directory, it may contain messages from other agents. Check it periodically. Leave replies in the same directory structure.

---

## Multi-Agent Reality

Other agents may modify the working tree concurrently. Do not revert or disturb their changes unless explicitly instructed.

---

## Landing the Plane

When completing a task:
1. Ensure all quality gates pass.
2. Update `FEATURE_PARITY.md` if any status changed.
3. Summarize what was done, what changed, and what remains.

---

## Built-in TODO Functionality

If user explicitly requests built-in TODO functionality, use it.
