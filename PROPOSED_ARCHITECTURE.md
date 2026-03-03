# PROPOSED_ARCHITECTURE.md

## 1. Architecture Thesis

C ABI compatibility and memory safety are reconciled via a **Transparent Safety Membrane (TSM)**.

At every `extern "C"` boundary, libc entrypoints are treated as untrusted input channels. The membrane enforces safety invariants before dispatching to safe Rust semantic kernels.

Mode is explicit and first-class:
- `strict` (default): ABI-conformant semantics, no repair rewrites.
- `hardened`: TSM repair semantics for invalid/unsafe patterns.

## 2. Layered Design

### Layer A: ABI Boundary (`extern "C"`)

Responsibilities:
- Symbol-compatible C signatures.
- Minimal pointer extraction and call-context capture.
- Immediate handoff into membrane validators.

### Layer B: Transparent Safety Membrane

Responsibilities:
- Pointer provenance classification.
- Bounds/lifetime generation checks.
- Mode-aware action selection (`strict`: allow/deny, `hardened`: allow/repair/deny).
- Evidence logging for sanitization/repair actions.

### Layer C: Safe Semantic Kernels

Responsibilities:
- Canonical behavior for libc operations in safe Rust.
- No direct raw pointer dereference.
- Deterministic and testable semantics.

### Layer D: Tooling/Conformance Plane

Responsibilities:
- Fixture capture + conformance compare.
- Traceability matrix and parity reports.
- Benchmark regressions and hotspot diagnostics.

### Layer E: Runtime Math Control Plane

Responsibilities:
- Online risk envelope updates per API family.
- Online routing of validation depth (`Fast` vs `Full`) under safety constraints.
- Runtime threshold control for repair/full-validation triggers.
- Constant-time barrier admissibility checks.
- Incremental overlap-consistency checks for sharded metadata.

### Layer F: Artifact Compilation Boundary

Responsibilities:
- Convert heavy advanced-math outputs into runtime-friendly artifacts (tables, generated constants, certified rewrites).
- Keep online control kernels simple, deterministic, and low overhead.
- Ensure ordinary contributors work against plain Rust interfaces, not theorem machinery.

## 3. TSM Formal Model (Alien-Artifact Direction)

### 3.1 State and Semantics

Define operational state:

`S = (heap, meta, errno, mode, telemetry)`

Mode-specific semantics for function `f`:

`[[f]]_strict : (S, I) -> (S', O)`

`[[f]]_hardened : (S, I) -> (S', O, R)`

where:
- `I` is ABI input tuple,
- `O` is ABI-visible output tuple,
- `R` is optional repair evidence record.

Define region state lattice:

- `Invalid`
- `Freed`
- `Quarantined`
- `Valid`

Transitions are monotone toward safer states under uncertainty (`Valid -> Quarantined` allowed; unsafe resurrection disallowed).

Each ABI operation computes a safety judgment:

`J = (provenance, bounds, temporal_state, operation_kind)`

Membrane decision function:

`D(mode, J) -> {Allow, Repair(strategy), Deny(errno)}`

Mode guard:
- `mode = strict` => `Repair` is not admissible.
- `mode = hardened` => `Repair` admissible per policy table.

Repair strategy examples:
- size clamp (`memcpy`, `memmove`, `memset`)
- termination-preserving truncation (`strcpy`, `strcat` families)
- quarantine and no-op on temporal invalid frees
- deterministic safe fallback return for irreparable operations

### 3.2 Advanced Mathematical Components

1. Abstract interpretation domain:
- `A = A_provenance x A_bounds x A_temporal x A_effect`
- Sound abstraction/concretization maps define conservative safety judgments.

2. Constrained decision optimization:
- `a* = argmin_a E[L(a, class) | J, mode]`
- subject to ABI and determinism constraints.

3. Sequential statistical guardrails:
- e-process based online tests for conformance/perf regressions under repeated testing.

4. Drift detection:
- Bayesian change-point monitoring for latency tails and repair-rate anomalies.

5. Online safe autotuning:
- Contextual bandit selects among validator fast paths in hardened mode.
- Hard safety constraints gate all admissible actions.

6. CPOMDP action layer:
- Hardened decision is a constrained POMDP policy over abstract safety states.
- Constraint set enforces ABI compatibility envelopes and deterministic replay.

7. Robust control layer:
- Distributionally robust MPC updates policy parameters under workload uncertainty.
- Uncertainty sets are Wasserstein balls over observed workload traces.
- Controller objective includes CVaR penalties for tail-latency and safety-surrogate risk.

8. Proof automation layer:
- CHC encoding of invariants + CEGAR refinement cycle + interpolation-based refinement.
- Counterexamples emitted as concrete regression fixtures.

9. Superoptimization layer:
- Equality saturation (e-graphs) for hot libc kernels.
- CEGIS synthesizes candidates; rewrite admitted only with SMT equivalence certificate.

10. Information-theoretic tag design:
- Provenance tags treated as error-detecting codewords with explicit collision bounds.
- Verification cadence tuned via constrained optimization.

11. Barrier-certificate safety filter:
- Runtime actions must satisfy barrier certificate conditions preserving safe-set forward invariance.

12. Concurrent proof layer:
- Iris-style concurrent separation logic artifacts for lock-free/sharded metadata components.

13. HJI reachability layer:
- attacker-controller differential game computes viability kernel for admissible runtime states.
- policy actions outside viability set are rejected by construction.

14. Sheaf-cohomology consistency layer:
- local metadata views modeled as sheaf sections over overlap covers.
- first-cohomology anomalies trigger inconsistency remediation or fail-safe deny paths.

15. Combinatorial campaign layer:
- covering-array generation for high-order input interaction testing.
- matroid-constrained selection for maximal diagnostic value per test budget.

16. Probabilistic coupling layer:
- coupled strict/hardened execution traces with concentration-bound divergence accounting.

17. Mean-field control layer:
- large-population thread dynamics approximated via mean-field equations for contention control.
- equilibrium-derived parameters feed allocator/pthread tuning knobs.

18. Schrödinger-bridge transition layer:
- entropic OT bridge computes smooth policy transitions between workload regimes.
- transition controller minimizes oscillation while preserving safety constraints.

19. SOS certificate synthesis layer:
- SDP-backed synthesis of polynomial barrier/Lyapunov certificates for nonlinear runtime dynamics.
- synthesized certificates compiled into runtime admissibility checks.

20. Large-deviation risk layer:
- importance splitting and rare-event estimators for catastrophic safety/performance tails.
- risk budgets tied directly to release gates.

21. TDA telemetry layer:
- persistent homology over runtime-state point clouds for anomaly class discovery.
- topology-shift alarms integrated with fail-safe policy fallback.

22. Rough-path feature layer:
- signature transforms of long syscall/memory traces for stable controller state features.

23. Tropical latency layer:
- min-plus composition of stage-level latency envelopes for hard end-to-end bounds.

24. Conformal reliability layer:
- split/Mondrian conformal calibrators for per-family runtime decision sets.
- conformal risk control for bounded false-repair/false-deny rates.

25. Algebraic-topology defect layer:
- spectral-sequence/obstruction diagnostics over subsystem interaction complexes.
- persistent cohomology signatures for repeatable cross-layer defect classes.

26. Abstract-algebra normalization layer:
- semigroup/group-action canonicalization of policy/parser/dispatch compositions.
- Gröbner-basis normalization for constraint system simplification and proof reuse.

27. Noncommutative concurrency layer:
- free-probability/random-matrix approximations for contention spectra.
- operator-valued risk controls for burst-concurrency stability constraints.

28. Serre spectral lifting layer:
- filtered subsystem towers induce spectral-sequence pipelines for invariant transport.
- extension-problem detectors emit explicit non-liftable-invariant witnesses.

29. Grothendieck topos/descent layer:
- runtime observations organized as a Grothendieck site; sheafification yields global semantic state.
- descent/stackification checks guarantee ABI/ISA compatibility witness gluing.

30. Atiyah-Singer families-index layer:
- parameterized implementation bundles carry index constraints for compatibility transport.
- nonzero index residues trigger fail-fast incompatibility localization.

31. Atiyah-Bott localization layer:
- equivariant symmetry actions over policy/dispatch spaces reduced to fixed-point obligations.
- localization layer provides proof/benchmark compression with bounded error accounting.

32. Clifford-kernel geometry layer:
- SIMD/memory kernels represented as Clifford-module normal forms.
- overlap/alignment directionality constraints enforced via Spin/Pin-compatible guards.

### 3.2.1 Online Runtime Kernelization (Required)

The following are mandatory online components in runtime code, not only offline proof artifacts:

1. `risk` kernel:
- conformal-style upper-bound estimator producing per-family risk envelopes in ppm.

2. `bandit` kernel:
- constrained contextual router choosing `Fast` vs `Full` validation profile per call.

3. `control` kernel:
- primal-dual threshold updates for full-validation and repair triggers under latency/safety pressure.

4. `barrier` kernel:
- constant-time admissibility oracle ensuring no runtime action exits certified safe regions.

5. `cohomology` kernel:
- incremental overlap consistency monitor over sharded metadata; faults trigger escalation.

Runtime decision law:
`Decision = F(mode, context, risk, control_limits, barrier, consistency_state)`.

### 3.3 Proof Targets

1. Strict refinement:
- `[[f]]_strict` observationally refines reference glibc semantics on defined inputs.

2. Hardened safety:
- `[[f]]_hardened` preserves safe-state invariants for all routed calls.

3. Deterministic replay:
- identical `(mode, I, env snapshot)` yields identical membrane decision trace.
4. CPOMDP admissibility:
- policy output is always in admissible action set under all reachable abstract states.
5. Superoptimization equivalence:
- every kernel rewrite is semantically equivalent to baseline under formal model.
6. Barrier invariance:
- safe-state set remains invariant under all admitted runtime actions.
7. Robustness radius:
- safety/latency constraints hold for all workloads in declared ambiguity set.
8. Concurrent linearizability:
- metadata operations linearize under documented memory model assumptions.
9. HJI viability:
- runtime policy keeps state in viability kernel under adversarial disturbance model.
10. Sheaf consistency detectability:
- declared global inconsistency classes are detected via cohomological diagnostics.
11. Interaction coverage optimality:
- conformance campaigns satisfy declared t-wise coverage guarantees.
12. Coupled divergence bound:
- strict/hardened observable divergence is bounded on certified domains.
13. Mean-field stability:
- control parameters converge to stable equilibria under declared traffic classes.
14. Entropic transition bound:
- regime transitions satisfy bounded transport-cost and bounded policy overshoot.
15. SOS synthesis soundness:
- synthesized polynomial certificates imply required invariance/stability claims.
16. Large-deviation bound:
- catastrophic-event probability estimates remain below release thresholds.
17. Topological anomaly detectability:
- declared topology-shift classes are detected with bounded miss rate assumptions.
18. Rough-signature stability:
- trace embedding remains stable under bounded perturbations relevant to production noise.
19. Tropical composition correctness:
- composed latency envelopes remain conservative and compositional.
20. Conformal validity:
- runtime decision-set coverage and risk-control guarantees hold at declared confidence levels.
21. Topological obstruction detectability:
- declared global inconsistency classes induce detectable obstruction signatures.
22. Algebraic normal-form uniqueness:
- equivalent policy/parser/dispatch compositions reduce to identical canonical forms.
23. Noncommutative tail-stability:
- contention-spectrum tails remain within certified risk budgets under declared workloads.
24. Arithmetic compatibility integrity:
- layout/symbol/time-width transitions preserve declared compatibility invariants.
25. Serre convergence integrity:
- declared invariant classes survive filtration lift with certified spectral convergence or explicit obstruction.
26. Topos/descent coherence:
- local runtime/compatibility witnesses glue to global contracts under declared coverage axioms.
27. Families-index nullity:
- release-critical compatibility bundles satisfy required index constraints (or emit localized obstruction reports).
28. Localization conservativity:
- fixed-point-reduced obligations remain equivalent to full obligations within declared bounds.
29. Clifford kernel equivalence:
- architecture-specific kernel realizations are equivalent on certified Clifford regime partitions.

### 3.4 Legacy-Grounded Subsystem Engines

This layer maps high-density legacy surfaces directly to runtime/control artifacts.

1. Loader engine (`elf`, `sysdeps/*/dl-*`)
- symbol/version scope automata + relocation schedule envelopes.
- ifunc/hwcaps switching controller with constrained regret.

2. Allocator-thread engine (`malloc`, `nptl`)
- mean-field contention controller + SOS-guarded safety constraints.
- futex/cancellation/TLS transition guards with certificate-backed admissibility.

3. Format-locale engine (`stdio-common`, `wcsmbs`, `locale`)
- generated weighted VPA parser + semiring transducer pipeline.
- compile-time certified formatting action graph.

4. Name-service engine (`nss`, `resolv`)
- robust lookup policy graph with cache/timeout regime morphing.
- anomaly/poisoning monitors with sequential confidence guarantees.

5. Numeric engine (`math`, `soft-fp`, `sysdeps/ieee754`)
- certified minimax approximants + range-reduction witnesses.
- fenv/exception conformance guardrails and ULP budget enforcement.

6. Cross-ISA glue engine (`sysdeps`)
- semantic witness transport across ISA-local implementations.
- interaction-optimal conformance campaigns across ISA x mode x workload.

7. Stream-syscall engine (`libio`, `io`, `posix`)
- coalgebraic stream-state kernel + parity-game-derived lock/flush protocols.
- max-plus latency envelopes and backpressure stability guards.

8. Locale-encoding engine (`localedata`, `locale`, `iconvdata`, `iconv`, `wcsmbs`)
- factorized codec/transliteration automata via Krohn-Rhodes decomposition.
- sheaf-consistency diagnostics and compositional lens-based conversion wiring.

9. Temporal semantics engine (`time`, `timezone`)
- hybrid transition system for DST/leap-second discontinuities.
- interval-temporal model checks + drift detection artifacts.

10. Cache-RPC coherence engine (`nscd`, `sunrpc`, `nss`, `resolv`)
- Stackelberg security policies for poisoning/retry adversaries.
- large-deviation tail controls and cache consistency witnesses.

11. Bootstrap-observability engine (`csu`, `debug`, `support`)
- compositional init-order proofs and structural controllability checks.
- rate-distortion-optimal diagnostics with explicit overhead budgets.

12. Loader-audit security engine (`elf`: `dl-*`, hwcaps, tunables, audit)
- namespace/audit hypergraph controller with sheaf-consistency guards.
- robust tunable/hwcaps policy maps constrained by ABI-safe admissibility.

13. Async-control engine (`signal`, `setjmp`, `nptl` cancellation)
- higher-order pushdown continuation model + hybrid switching controller.
- deterministic transition admissibility kernels for signal/jump/cancel edges.

14. Terminal-session engine (`termios`, `login`, `io`, `posix`)
- polyhedral ioctl/termios transition guards + PTY/session control kernels.
- tail-risk bounded buffering/flush behavior under bursty TTY workloads.

15. Launch-pattern engine (`spawn/exec`, `glob/fnmatch/regex`, env/path)
- grammar-constrained launch policy DAG + symbolic-automata complexity guards.
- interaction-optimized conformance campaigns for high-order env/path flags.

16. Secure-bootstrap policy engine (`csu`, `elf`, secure mode, diagnostics)
- noninterference-certified tunable/diagnostic gates.
- risk-calibrated admission controls for early-init policy channels.

17. VM-transition engine (`mmap/munmap/mprotect/mremap/brk/sbrk`, mmap-backed I/O)
- directed-topology transition kernel for map/protection states.
- viability-constrained policy guards for remap/resize/permission trajectories.

18. Futex-PI engine (`nptl` futex internals, robust lists, cancellation/time64 waits)
- timed-automata protocol core with CEGAR-refined edge admissibility.
- fairness/starvation controls and robust-recovery invariants.

19. Multiarch-SIMD coherence engine (`sysdeps/*/multiarch`, IFUNC hot paths)
- feature-lattice dispatch manifold with deterministic routing constraints.
- cross-kernel equivalence witnesses and alignment-domain safety guards.

20. Realtime-event engine (`rt` timers/mqueue/clock semantics)
- max-plus envelope synthesis for timer/queue pipelines.
- risk-sensitive fallback policy kernels for burst/error regimes.

21. SysV-IPC lifecycle engine (`sysvipc` shm/sem/msg)
- Petri-invariant lifecycle automata for key/segment state flows.
- permission/admission constraint guards with recovery-policy synthesis.

22. ABI-layout bridge engine (`x32/64`, time64, symbol-version variants)
- lens-based layout translation contracts with relational refinement checks.
- compatibility drift monitors with release-gate thresholds.

23. Conformal-calibration engine (cross-surface strict/hardened decision reliability)
- finite-sample calibrated decision sets for allow/repair/deny.
- online conformal validity monitors feeding deterministic abstain/escalate gates.

24. Topological-obstruction engine (cross-layer consistency)
- interaction-complex obstruction diagnostics with subsystem-localized witnesses.
- persistent defect-signature tracking across workload families.

25. Algebraic-normalization engine (cross-cutting policy/parser/dispatch kernels)
- canonical semigroup/orbit normal forms with certificate-carrying rewrites.
- Gröbner-normalized constraint kernels for reproducible proof composition.

26. Noncommutative-concurrency risk engine (`nptl`, allocator/thread hot paths)
- contention-spectrum estimators with random-matrix/free-probability tail controls.
- operator-stability gates for runtime tuning decisions.

27. Serre-invariant transport engine (cross-layer subsystem towers)
- spectral-page invariant propagation with extension-obstruction diagnostics.
- compositional guard generation from converged page witnesses.

28. Grothendieck-coherence engine (cross-layer runtime + compatibility glue)
- site/topos sheafification kernels for local-to-global state consistency.
- descent/stackification certificates for ABI/ISA/version witness bundles.

29. Families-index engine (cross-variant compatibility transport)
- index-ledger construction for implementation families.
- incompatibility-class localization when index constraints fail.

30. Equivariant-localization engine (proof/benchmark compression)
- fixed-point extraction for dispatch/policy symmetry actions.
- bounded-error compression certificates for reduced obligation sets.

31. Clifford-kernel engine (`string/memory` SIMD and overlap semantics)
- Clifford-regime partitioning and kernel normal-form generation.
- Spin/Pin-constrained guard synthesis for direction-sensitive memory ops.

### 3.5 Reverse Core Surface Map (Execution-Facing)

This map is mandatory for architecture reviews: surface first, defect class second, math third, compiled artifact fourth.

1. Loader/symbol/IFUNC:
- defect: local-valid but globally-incompatible symbol/namespace evolution.
- artifact: resolver automata + compatibility witness ledgers.

2. Allocator:
- defect: temporal/provenance corruption under contention.
- artifact: policy tables + admissibility guards.

3. String/memory hot kernels:
- defect: overlap/alignment/dispatch edge unsafety at high speed.
- artifact: regime classifier + certified kernel routing tables.

4. Futex/pthread/cancellation:
- defect: race/starvation/timeout-cancel inconsistency.
- artifact: lock/wait transition kernels + fairness budgets.

5. stdio/parser/locale formatting:
- defect: parser-state explosion and locale-sensitive divergence.
- artifact: generated parser/transducer tables.

6. signal/setjmp control transfer:
- defect: invalid non-local jump/cancel/signal transitions.
- artifact: admissible transition matrices.

7. time/timezone/rt timers:
- defect: discontinuity and overrun correctness drift.
- artifact: temporal transition DAGs + timing envelope tables.

8. nss/resolv/nscd/sunrpc:
- defect: poisoning/retry/cache instability with tail collapse.
- artifact: lookup policy DAGs + calibrated anomaly thresholds.

9. locale/iconv transliteration:
- defect: hidden local-to-global inconsistency across conversion state spaces.
- artifact: minimized codec automata + consistency certificates.

10. ABI/time64/layout bridges:
- defect: latent release-to-release compatibility fracture.
- artifact: invariant ledgers + release-blocking drift alarms.

11. VM transitions:
- defect: unsafe map/protection trajectory transitions.
- artifact: map/protection guard complexes.

12. strict/hardened decision calibration:
- defect: repair/deny/allow thresholds drifting invalidly.
- artifact: coverage-certified decision sets + abstain/escalate gates.

13. process bootstrap (`csu`, TLS init, auxv, secure mode):
- defect: initialization-order races and secure-mode misclassification.
- artifact: startup dependency DAG + secure-mode policy automaton + init witness hashes.

14. cross-ISA syscall glue (`sysdeps/*`):
- defect: architecture-specific semantic drift hidden behind common ABI.
- artifact: per-ISA obligation matrices + dispatch witness cache.

15. System V IPC (`sysvipc`):
- defect: capability drift and deadlock-prone semaphore choreography.
- artifact: semaphore admissibility guard polytopes + deadlock-cut certificates.

16. i18n catalog stack (`intl`, `catgets`, `localedata`):
- defect: fallback-chain incoherence and catalog/version skew.
- artifact: catalog resolution automata + locale-consistency witness hashes.

17. diagnostics/unwinding (`debug`, backtrace paths):
- defect: unsafe or non-deterministic frame walking during async faults.
- artifact: unwind stratification tables + safe-cut fallback matrix.

18. session accounting (`login`, utmp/wtmp interfaces):
- defect: racey session state and replay/tamper ambiguity.
- artifact: deterministic session-ledger transition rules + anomaly thresholds.

19. profiling hook paths (`gmon`, sampling/probe):
- defect: probe-induced perturbation corrupting benchmark conclusions.
- artifact: minimal probe schedules + deterministic debias weights.

20. floating-point edge behavior (`soft-fp`, `fenv` exceptional paths):
- defect: denormal/NaN/payload drift across ISA/optimization regimes.
- artifact: regime-indexed numeric guard tables + certified fallback kernels.

Developer-facing rule:
- every artifact above must compile to simple deterministic runtime logic (tables/guards/kernels), with alien math hidden in offline synthesis/proof pipelines.

### 3.6 Partial Overlay Progression Contract (L1 -> L3)

Lessons from LLVM libc overlay mode are codified as constraints for FrankenLibC progression:

1. Packaging modes are explicit:
- `L1` interpose path and `L2/L3` replacement path are distinct contract surfaces, with per-symbol applicability captured in machine-readable support matrix metadata.

2. ABI-sensitive symbols are classified before promotion:
- symbols dependent on implementation-private layouts (`FILE`, thread/runtime internals, loader-private state) require explicit replacement-closure evidence before L2/L3 promotion.

3. Global-state semantics are mode-gated and audited:
- errno, TLS finalization, and process-exit semantics must be declared and tested per mode (`strict`/`hardened`) and per packaging level (`L1` vs `L2/L3`).

4. Header/layout discipline is enforced:
- replacement-only type/layout assumptions are isolated behind explicit compile-time policy gates so interpose compatibility does not accidentally inherit replacement-specific ABI assumptions.

5. Validation scope matches mode:
- interpose validation runs are allowed to be subset-oriented but must publish coverage boundaries.
- replacement validation requires full-family closure proofs for promoted surfaces.

## 4. Unsafe Policy

Unsafe is allowed only for:

1. ABI boundary adapters
2. tightly-scoped low-level memory introspection in membrane internals
3. documented intrinsics required for performance-sensitive primitives

Every unsafe block must include:
- preconditions
- postconditions
- proof sketch of invariant preservation

## 5. asupersync/frankentui Integration

### asupersync (build/test tooling only)

- Conformance traceability structures (`asupersync-conformance`)
- Deterministic orchestration metadata for test campaigns
- Structured summaries for CI and local analysis

### frankentui (build/test tooling only)

- Snapshot/diff mismatch rendering for fixtures
- Interactive parity/benchmark dashboard
- Visual triage for membrane repair-path frequency and cost

## 6. Performance Strategy (Extreme Optimization)

Mandatory loop:

1. baseline
2. profile
3. prove behavior unchanged
4. single optimization lever
5. golden verification
6. re-profile

Planned fast-path techniques:
- thread-local metadata cache for recent allocations
- probabilistic prefilter for pointer validity (exact check fallback)
- page-level guard metadata to reduce repeated full lookups
- specialized hot-path kernels once correctness is locked
- tail-latency robust optimization (p99/p999 objectives, not just mean)
- regime-aware optimization with change-point-driven re-baselining
- policy-controller guardrails that cap worst-case validator overhead via CVaR constraints

## 7. Validation Artifacts

Every subsystem rollout must provide:

1. spec extraction section references
2. fixture-based conformance report
3. parity matrix update
4. benchmark delta and optimization proof notes
