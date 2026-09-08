# FrankenLibC — Reality-Check Bridge Plan

## Current assessment — 2026-09-08

Audited source: `e8d0b444d640895d6bf830355527551a74879503`, initially clean worktree.
This section supersedes the May assessment below as a statement of current state;
the historical workstreams remain for context, not as fresh measurements.

**Verdict:** a substantial, runnable Linux interposition library, not a demonstrated
full standalone glibc replacement. The implementation has advanced since May.
The evidence system still permits important claims to pass without executing the
claimed behavior. Finishing the existing active queue alone would not close that gap.

### Scope and evidence standard

Read the complete repository AGENTS.md and README.md, suite-wide AGENTS.md, main
porting plan, proposed architecture, feature parity, compatibility, deployment,
existing bridge plan, stdio replacement plan, parity coverage, and architecture
investigation ledger. Traced representative deployed paths through startup,
runtime policy, allocator, string operations, pointer validation, pthread and
dynamic loading, plus the healing and standalone verification pipelines.
This is a goal-oriented assessment, not an exhaustive audit of every symbol,
historical report, or runtime-math theorem. Status below is deliberately scoped.

Evidence classes must stay separate: source inspection; model/unit test; artifact
schema check; actual deployed ABI execution; standalone execution; formal proof;
and same-invocation incumbent performance comparison. One cannot substitute for
another. In particular, a hash chain authenticates recorded bytes, not the truth
of a producer's claims. Deterministic missing-evidence failures should not wait
for a statistical alarm. These corrections supersede historical WS-0's claim
that cryptography or runtime math can make self-authored evidence truthful.

### Vision-to-reality map

| Goal | Current evidence and status | Existing active queue sufficient? |
|---|---|---|
| Usable LD_PRELOAD library | **WORKING on the tested smoke subset.** Fresh release builds; 60 pass / 0 fail / 4 skip, including Python, BusyBox, SQLite, C link fixture and coreutils in both modes. | Preserve this capability; broaden workloads. |
| Full POSIX/GNU behavior | **PARTIAL.** Symbol presence is not behavioral completeness. Current wordexp command-substitution defect already has `bd-uu1wvp`. | No: that defect is only one family/behavior. |
| Native, host-independent implementation | **PARTIAL.** Symbol rows classify 2,388 Implemented + 414 RawSyscall + 1,317 WrapsHostLibc = 4,119. These are classifications, not independently proven native coverage. | No: `bd-38x82` names the destination but its implementation prerequisites are closed. |
| Owned loader/startup/threading | **PARTIAL.** Native pathname DSO loading and native threading exist. Bare SONAME loading still delegates; standalone dlopen rejects non-null filenames. Do not repeat May's claim that all loading/thread creation delegates. | No: closed `bd-73h55.2` promised arbitrary transitive DSO loading. |
| Transparent hardened repairs | **PARTIAL / insufficient end-to-end evidence.** Real bounds/repair paths exist, but verify-membrane's reported observations are policy-model calculations. | No: `bd-l93x.4` is closed. |
| Live adaptive runtime math | **PARTIAL.** Startup now arms runtime readiness. Production strict high-frequency paths bypass the kernel; production hardened high-frequency paths return a Full profile without consulting it. Test configuration differs. | No: `bd-06bxm` and its live E2E bead are closed. |
| Temporal and spatial safety guarantees | **UNPROVEN at the advertised universal scope.** Raw-address validation lacks caller-generation provenance; strict memcpy explicitly skips the membrane. | No active task resolves the universal-claim/actual-observation boundary. |
| ABI/symbol/version compatibility | **PARTIAL.** Release artifact and C/preload smoke run; no exhaustive versioned-export or every-symbol behavioral proof was executed here. | No: needs deployed, version-aware family coverage. |
| Conformance depth | **PARTIAL.** Fresh maintenance inventory links fixtures to 1,165/4,119 symbols (28.3%); linkage is not a pass rate, and unlinked is not synonymous with untested. | No active broad differential-coverage task. |
| Formal guarantees | **DEFERRED, not proved.** All 24 binder obligations say deferred; the existing owner decision chose honest reframing. Build also explicitly skipped the stdio SMT solver. | Honor that decision; do not silently reopen a proof program or count deferred proofs as complete. |
| Performance targets | **WORKING for this curated smoke bound; UNPROVEN globally.** Both-mode 2x smoke gate passes in this run; live allocator/perf beads document unresolved gaps. | Existing perf tasks help, but do not establish all-family budgets. |
| Standalone, aarch64, packages, 24-hour reliability | **UNPROVEN as a combined deliverable.** No standalone/architecture/package/soak execution was observed in this audit. Existing WS-8 gate contains unconditional passes. | No: blocked parent/soak plus closed contract tasks do not supply the missing execution. |
| Tooling boundary and maintainability | **PARTIAL evidence.** Cargo declares companion harness dependencies in tooling features; release builds. Whole-workspace checks and test-target health need separate results, not inference from that build. | `bd-blnp4u` already covers accidental probe targets; retain it. |

### High-confidence gaps

1. **The healing oracle is tautological.** In
   `crates/frankenlibc-harness/src/healing_oracle.rs:293`, expected and observed
   both call `hardened_action_for_condition`. It sets detected, posix_valid and
   evidence_logged to true, and uses a fixed generation timestamp. CLI dispatch
   in `src/bin/harness.rs:1940` calls this report builder without an ABI runner.
   This proves policy consistency, not fault detection or repair of a C process.
2. **Standalone E2E can report success without standalone execution.**
   `scripts/check_ws8_e2e_standalone_verification.sh` accepts absent x86 artifacts
   with `verified_by_bd_38x82.1_contract`; aarch64 failures fall back to pass;
   workload outcomes are constants; companion test success means files exist
   and contain lines. The x86 nm check ignores its exit status and does not boot
   a process. This is a concrete gate defect, not a claim that every other
   standalone checker is equally defective.
3. **The support matrix contradicts itself.** Its symbol rows and maintenance
   dashboard count 2,388/414/1,317; top-level rollups, README and replacement
   assessment retain 2,395/414/1,310. Seven rows' difference survives an otherwise
   green maintenance gate. Zero GlibcCallThrough is not zero host dependency.
4. **Deployment and test semantics diverge.** `runtime_policy.rs:2079` disables
   strict passthrough in tests; `:2260` explicitly skips the hardened production
   fast path in tests. `string_abi.rs:4217` bypasses validation for strict memcpy.
   Startup readiness is genuinely wired now. The required remedy is deployed
   coverage and an explicit routing contract, not an unsupported declaration
   that all kernels are dormant or that hardened bounds checks are absent.
5. **Universal safety language exceeds the interface's observable information.**
   `ptr_validator.rs:676` accepts an address, while `:1317` compares current header
   and arena generations. A stale raw pointer and a new pointer with identical
   address carry no distinct caller generation to this API. Quarantine and
   metadata consistency are useful but do not establish detection of every
   post-reuse UAF. This is an interface-level inference, not a reproduced exploit.
6. **Planning completion is repeatedly mistaken for capability delivery.**
   The initial JSONL census is 7,428 records: 7,410 closed, 11 in progress,
   3 blocked, 4 tombstones, zero open. Several goals have historical beads,
   so the accurate diagnosis is missing *active executable coverage*, not
   "nobody ever created a bead." This is a raw local-file census, not a project
   completion denominator: 1,195 records have non-`bd-` prefixes, including
   `frankenjax-mmk4` with ambiguous `source_repo="."`. Do not blindly reopen
   legitimate scoped deferrals such as `bd-e4phe.2`.

### Observed verification

Commands use isolated Cargo target directories and the repository's rch entrypoint.
No runtime source, thresholds, goldens, or canonical support data were changed.

| Check | Observed outcome |
|---|---|
| `rch exec -- cargo build -p frankenlibc-abi --release` | Exit 0, release finished in 56.60s; warnings present, including missing SMT solver. |
| Fresh `scripts/ld_preload_smoke.sh`, defaults | 60 pass / 0 fail / 4 skip. Redis and nginx tools missing in both modes. |
| Same fresh artifact, `ENFORCE_PARITY_MODES=strict,hardened ENFORCE_PERF_MODES=strict,hardened` | 60 pass / 0 fail / 4 skip; no perf/signature failures. Same-invocation baseline; single-run smoke, not a banked microbenchmark win or universal latency proof. |
| `scripts/check_support_matrix_maintenance.sh` | Exit 0, PASS, 4,119/4,119 statuses validated, 28.3% fixture linkage. Still misses contradictory top-level matrix rollups. |
| `rch exec -- cargo test -p frankenlibc-membrane --lib lattice -- --nocapture` | Remote compilation and execution observed: `test result: ok. 29 passed; 0 failed; 0 ignored; 0 measured; 1371 filtered out`. This is lattice testing, not a universal safety proof. |
| `rch exec -- cargo check --workspace --all-targets --keep-going` | Exit 0; finished with warnings. Checks do not establish that integration targets link or execute. |
| `rch exec -- cargo clippy --workspace --all-targets --keep-going -- -D warnings` | Exit 101; membrane lib and lib-test targets report 29 and 32 errors respectively, with overlap. Do not sum these as independent defects or claim downstream lint coverage. |
| `rch exec -- cargo fmt --check` | Exit 1; existing formatting drift across examples, tests and source. No formatting changes applied during this audit. |

Smoke artifacts: `target/ld_preload_smoke/20260908T043437Z-327204/` and
`target/ld_preload_smoke/20260908T043539Z-337524/`. Fresh library:
`/data/tmp/rch_target_frankenlibc_reality_build_20260908/release/libfrankenlibc_abi.so`.
Check logs: `/data/tmp/frankenlibc-reality-20260908-{check,clippy,fmt,maintenance}.log`.
These local artifacts are reproducibility aids, not durable release evidence.

### Execution bridge and ordering

Use independent, bounded tracks. Evidence repair must block *promotion claims*,
not all unrelated implementation work. Keep safety, compatibility, runtime-math
liveness and speed distinct; never restore liveness by reintroducing bootstrap
deadlocks, or obtain speed by silently discarding required safety behavior.

| Track | Concrete deliverable and acceptance | Complexity |
|---|---|---|
| A: executable evidence | Replace WS-8 fallbacks with fail/blocked; boot actual artifacts, observe maps/providers, execute workloads and tests. Missing tool/artifact, nonzero exit, malformed result, zero tests and stale receipt must never pass. | L |
| B: deployed healing | Keep model tests labeled as such; dispatch fault fixtures into isolated C subprocesses against the release ABI. Independently assert output, memory boundaries, errno and observed audit events for each supported repair. | L |
| C: taxonomy integrity | Derive all rollups from symbol rows; gate contradictory counts and reachable host-backed paths by configuration. No blanket native promotion or canonical regeneration without evidence. | M |
| D: runtime-math contract | Enumerate family/mode/bootstrap/reentry/certificate paths; prove actual observations and decision influence with production cfg, and strict semantic preservation. Measure costs with incumbent in the same run. | L |
| E: owned replacement | Retain `bd-38x82`; supply live prerequisites for loader transitive dependencies and owned startup/TLS/unwind/service integration. Default/preload success is not standalone proof. | XL |
| F: behavioral coverage | Build executable symbol/family/mode/version inventory, then fill high-risk holes with real differentials and hardened fault pairs, including ABI aliases, errno, fenv, locale, concurrency and process behavior. | XL |
| G: safety/proof scope | Define owned/foreign/interior/stale/reused/racing-pointer preconditions; add reuse and boundary probes. Preserve owner-approved deferred proofs and distinguish tested models from theorems. | L |
| H: workload/release proof | Extend real workloads past version banners; execute architecture, package and soak gates with actual artifacts. Integrate existing allocator/perf tasks without relabeling smoke as universal performance. | XL |
| I: coherent claims | Reconcile README, plan "now" claims, compatibility, replacement levels and formal language from the preceding evidence. Correct the lattice diagram and deployed allocator description; preserve the full vision as a target. | M |

Every implementation task includes happy/edge/error unit tests, a deployed E2E
gate, a deliberate negative control, and structured logs containing source/build
identity, features, mode, architecture, command, exit, nonzero executed case count,
expected/observed values and artifact references. Task closure quotes compilation
and execution evidence; blockers close only when their named probe succeeds.
Existing `bd-blnp4u`, `bd-uu1wvp`, allocator/performance and stale-win audit tasks
remain relevant and are reused rather than duplicated.

**Ambition round 1 — executable counterfactuals.** A positive receipt is not enough:
every promotion gate must reject an intentionally missing/wrong artifact or broken
implementation. Production feature/mode selection, independent provider identity,
and zero-test rejection are explicit requirements. Scope checks must be fail-closed
without turning missing evidence into a fabricated product regression.

**Ambition round 2 — integration depth and availability.** Split the replacement
integration into owned startup/TLS/unwind, native stdio, and locale/NSS/resolver
deliverables. Add bootstrap/signal/fork and concurrent-free coverage, not merely
steady-state success. Treat lint/format health and ambiguous tracker ownership
as separate bounded tasks; do not let these become a prerequisite for every
useful implementation change. Universal safety claims require a precise boundary,
not another sophisticated-sounding controller or a finite-test proof claim.

### Planning refinement record

Initial bridge: tracks A-I above; all original non-negotiable goals retained.
Two ambition passes added counterfactual execution requirements and decomposed
owned integration. Five subsequent refinement passes checked the resulting beads:

1. **Evidence class and closure:** distinguish a repaired gate's correct blocked
   result from actual L3 success; retain an executed supported positive fixture.
2. **Test independence:** separate external memory/errno/process observations
   from telemetry; forbid instrumentation that changes production routing.
3. **Dependency usability:** `br ready` revealed that blocking the integration
   parent on the loader also blocked independent children. Moved that edge to
   release acceptance; startup, stdio and service implementation are now ready.
4. **Scope and user impact:** include misleading theorem comments in tests;
   permit immediate honest documentation while implementation remains unfinished.
5. **Final graph and completeness check:** all 16 new records are open and have
   self-contained context and acceptance criteria; no further change identified
   in this pass. Both active and archived cycle checks return zero. `bv` final
   triage agrees on the two P0 evidence defects as the first picks.

### Assigned work

All IDs below share prefix **`bd-reality-202609-lx578q`**. The root and `.6` are
epics; there are 14 implementation/defect tasks, 16 records total.

| Suffix | Deliverable |
|---|---|
| `.1` | P0: executable, fail-closed standalone evidence |
| `.2` | P0: real ABI healing observations |
| `.3` | Consistent support rollups and configuration-aware classifications |
| `.4` | Production runtime-math liveness and causal influence |
| `.5` | Standalone loader search and transitive DSO behavior |
| `.6.1` | Owned CRT, TLS, thread and unwind integration |
| `.6.2` | Native standalone stdio lifecycle |
| `.6.3` | Native locale/conversion, NSS and resolver integration |
| `.7` | Independent behavioral coverage and defect follow-through |
| `.8` | Explicit safety guarantee boundary and correctly scoped proof claims |
| `.9` | Actual workload, architecture, package and soak release evidence |
| `.10` | Current documentation/claim reconciliation |
| `.11` | Observed lint and formatting baseline repair |
| `.12` | Scoped tracker ownership/counting without deleting records |

Existing `bd-38x82` now depends on the relevant executable prerequisites, and its
notes cite the newly observed blockers. Historical predecessors are related links,
not newly asserted completions. Release `.9` depends on `.1`, `.5` and `.6`;
independent child implementation is not serialized behind an evidence framework.
`br ready --limit 0 --json` exposes 13 ready new leaf tasks. No task was closed.

Final graph evidence: `br dep cycles --include-closed --json` reports
`cycles=[]`, `total_count=0`; `bv --robot-triage` reports 16 open, 11 in progress,
3 blocked, `has_cycles=false`. Its raw cross-project totals remain unsuitable as
a project completion percentage. Triage receipt:
`/data/tmp/frankenlibc-reality-20260908-triage-final.json`.

Implementation is subsequent work; creating this plan does not discharge any
capability or proof obligation. No full workspace test execution, exhaustive
4119-symbol audit, formal proof run, standalone boot, aarch64 execution, package
installation, 24-hour soak, or universal performance validation is claimed here.
The changes made by this assessment are planning and tracker changes only;
runtime sources, test sources, gates and canonical performance/support artifacts
were left unchanged. Concurrent local commits captured parts of the planning
updates; the audited runtime source remained the initial revision.

### Implementation checkpoint — deployed healing, 2026-09-08

This subsection records subsequent implementation, not additional credit for the
planning assessment above. Active task: `bd-reality-202609-lx578q.2`.

- [x] Replace synthetic observations with isolated C subprocess calls against an
  explicitly supplied release ABI; check the actual symbol provider.
- [x] Observe return values, errno, destination prefixes/NULs, trailing canaries,
  realloc pointer identity, and the existing atomic healing counters independently.
- [x] Require explicit CLI library/probe paths; fail missing/empty observations
  by default. Strict cases are valid controls, not invalid-input POSIX claims.
- [x] Fix the exposed hardened realloc bug: quarantined slots must not enter the
  live in-place/copy path. Allocate fresh storage without reading retired bytes.
- [x] Record the previously missing hardened strlen/strcmp null-repair counters.
- [x] Compile the release ABI and the C probe; execute all 14 cases in both modes.
- [x] Compile a pre-fix ABI with only the diagnostic counter added, and run the
  same probe against it: five missing hardened counter increments, including two
  shrink cases returning the retired pointer. The fixed ABI passes these checks.
- [x] Run the broader preload smoke against the fixed ABI: 60 pass, 0 fail,
  4 skipped optional workloads (Redis/nginx unavailable).
- [ ] Observe the final oracle-unit and CLI-contract targets compile, link and
  execute nonzero test counts, including missing-provider/output and child failures.
- [ ] Run the complete existing healing gate and retain its live report, logs and
  checked source-file hash manifest; replay the gate against the pre-fix library.
- [ ] Finish workspace check and distinguish new failures from existing lint/fmt
  debt; inspect the final diff and perform a fresh acceptance self-review.
- [ ] Close `.2` only on the cited execution evidence; then proceed to `.1` and
  the independently ready implementation tracks above. Other tasks remain open.

Direct comparison: `/data/tmp/frankenlibc-healing-live-comparison.jsonl`.
Smoke: `target/ld_preload_smoke/20260908T053208Z-811177/`.
Reproduction entrypoint: `bash scripts/check_healing_oracle.sh` (remote build,
real C fixture, default tooling features, ten-second fault subprocess limits).
The general remote build budget was increased after two observed five-minute
compilation timeouts; no fault timeout or acceptance tolerance was relaxed.
This is representative owned-allocation repair coverage, not all-symbol
conformance, post-address-reuse UAF detection, standalone execution, or a perf win.

---

## Historical assessment — 2026-05-20 (not current measurements)

> Generated 2026-05-20 from a comprehensive reality check (5-agent code investigation).
> Purpose: close every gap between the *implemented code* and the *L3 standalone-replacement vision*.
> Iterated through ambition + refinement passes, then converted into beads.
> **Revision: v3 (ambition round 2 — domain-math depth: the alien math is turned on the project's own honesty).**

---

## 1. Context — what the reality check found

FrankenLibC is real, substantial engineering whose **headline metrics systematically overstate what is delivered in the configuration users actually run.**

| Claim | Reality |
|---|---|
| "~71 active runtime-math control kernels, live code" | Real code, **dormant by default** — `OBSERVE_FEEDBACK_STATE` is `DISABLED` and never enabled outside tests; `runtime_policy::decide()` returns passthrough in strict mode and never initializes `RUNTIME_READY` under `LD_PRELOAD`. ~64 exotic kernels are frozen at 0. |
| "TSM validates every call" | `decide()` is bypassed in the default strict/`LD_PRELOAD` path; **12 FFI-PCC certificates short-circuit the hottest symbols even in hardened mode**, so `malloc`/`free`/`memcpy`/`strlen`/`memcmp`/`snprintf` get no membrane repair in *either* mode. |
| "58 / 0 / 6 smoke battery" | Fresh run is **47 / 13 / 4 → FAILED**; all 13 failures are `python3` (~650× slowdown strict, full timeout hardened). The "green" claim is pinned to a **46-day-stale** summary. |
| "4,119 symbols, 100% native, 0 host call-through" | Census is arithmetically honest, but `__libc_start_main`, `dlopen`/`dlsym`/`dl_iterate_phdr`/`dladdr`, `pthread_create` **default-delegate to host glibc** while classified `Implemented`. |
| "9 formal proofs" | 9 **narrative markdown notes**; 0 of 24 proof obligations discharged; no machine-checking. |
| Conformance fixtures captured from host glibc | Fixtures are **synthetic spec tables** with placeholder `00:00:00Z` timestamps; real glibc differential testing exists only in the fuzz layer. |
| Bead queue | **5,859 / 5,859 closed, 0 open** — the swarm exhausted its queue while 5 of 10 vision goals are NOT_STARTED/STUB. |

**Root cause (one disease, many symptoms):** the swarm optimizes for *closing beads* and *greening gates*, and most gates check truth against JSON artifacts the swarm itself regenerates. When the truth source is a file you control, you pass the gate by editing the file instead of fixing reality. This is a Goodhart's-law collapse: the proxy metric (closed beads, green gates) decoupled from the target (a working libc).

**Owner steering decisions (2026-05-20):** (1) the runtime math is to be **wired live** — dormancy is a defect; (2) this plan goes through ambition + refinement passes before bead generation.

---

## 2. The central thesis of this plan

The reality check found two facts that, placed side by side, point at the fix:

1. The project's distinctive **alien-math control plane is dormant** — it has never had a load-bearing job.
2. The project's **evidence loop is broken** — gates trust stale, self-authored JSON, with no rigorous notion of "is this evidence still true?"

**The fix for (2) is exactly the math idle in (1).** FrankenLibC already contains anytime-valid e-processes (`eprocess.rs`), commitment-algebra martingale audit (`commitment_audit.rs`), and Bayesian change-point detection (`changepoint.rs`) — built for "tamper-evident session traces" and "drift detection" and then left inert. WS-0 gives them their first real job: **auditing the project's own honesty.** This is not decoration — it replaces the crude heuristics (an arbitrary "7-day TTL") that AGENTS.md itself forbids as hand-wavy, with calibrated, false-alarm-bounded, tamper-evident machinery. The alien math earns its place by making the project unable to lie to itself.

Per AGENTS.md branch-diversity: WS-0 alone draws on conformal/sequential statistics (e-processes), abstract algebra (commitment algebra), and Bayesian change-point detection — and every math mechanism below compiles down to a plain `check_*.sh` gate and a plain ledger file (the developer-transparency contract: contributors see normal gates; the math lives in synthesis).

---

## 3. Guiding principles

1. **WS-0 (measurement integrity) blocks everything.** No fix below is trustworthy until the truth loop is honest — otherwise the swarm closes these beads exactly as it closed the last 5,859.
2. **Every "Done-when" is a freshly regenerated, independently re-run, tamper-evidently-logged artifact** — never a stored one.
3. **Every implementation bead ships with a companion test bead** — unit (happy/edge/error) + e2e/harness with structured detailed logging.
4. **No bead closes on stale or self-authored evidence** (WS-0 enforces this cryptographically, not by convention).
5. **Math is load-bearing or absent.** Each technique below names a concrete plain-Rust artifact and the simple guard it compiles to. No naming theater.
6. **Bead IDs (`RC-WSn.m`) are placeholders**; `br`-assigned IDs replace them. Each `RC-` item is one bead unless marked `[epic]`.

---

## 4. Workstreams

### WS-0 — Evidence Integrity Kernel `[epic]` (BLOCKS ALL)

**Goal.** Make it structurally impossible to pass a gate against stale or self-authored evidence — and prove it with calibrated, tamper-evident machinery rather than heuristics.

**Why.** Stale-but-green smoke, dormant-but-`DONE` runtime math, and a 3-month-stale `reality_report` are one bug: gates trust stored JSON. A crude TTL is itself a hand-wavy heuristic. The rigorous fix is a small kernel built from the project's own idle math.

**Design — the Evidence Integrity Kernel (EIK).** Three layers, each compiling to a plain gate:
- **Tamper-evidence (commitment algebra).** Every canonical-artifact regeneration appends a hash-chained entry to `tests/conformance/evidence_ledger.jsonl` — `(artifact_hash, source_commit, generator_command, tool_version, prev_chain_hash)`. Editing any past artifact or ledger entry breaks the chain. This is `commitment_audit.rs`'s mechanism applied to the project's own evidence. Compiles to: `check_evidence_ledger.sh` (verify chain) + the ledger file.
- **Freshness as an anytime-valid test (e-processes), not a TTL.** For each gate, an e-process accumulates evidence on "the committed artifact diverges from an independent re-derivation." It alarms when the e-value crosses a threshold giving a *provable* false-alarm rate — no arbitrary day count. This is `eprocess.rs` applied to gate honesty. Compiles to: `check_evidence_freshness.sh`.
- **Drift detection (Bayesian change-point).** A change-point detector watches each gate's pass-rate stream; a jump in "gates passing" not correlated with a code change is flagged as suspicious. This is `changepoint.rs` applied to the CI signal. Compiles to: `check_gate_drift.sh`.

**Beads.**
- `RC-WS0.1` — `freshness_state` schema: every canonical artifact carries `generated_at_utc`, `source_commit`, `generator_command`, `tool_version`, `chain_hash`. *Test:* schema gate rejects a missing field.
- `RC-WS0.2` — Hash-chained `evidence_ledger.jsonl` + `check_evidence_ledger.sh`. *Test:* mutating a past artifact breaks chain verification.
- `RC-WS0.3` — E-process freshness monitor + `check_evidence_freshness.sh`; the e-process is the *first live consumer* of `eprocess.rs` outside tests. *Test:* a divergent artifact drives the e-value over threshold; false-alarm rate is calibrated and asserted.
- `RC-WS0.4` — Change-point gate-drift monitor + `check_gate_drift.sh`. *Test:* an injected pass-rate jump with no code delta is flagged.
- `RC-WS0.5` — Convert "read stored JSON" gates to "regenerate-then-diff": `reality_report`, `support_matrix_maintenance_report`, `hard_parts_truth_table`, `proof_obligations_binder`. *Test:* mutate `support_matrix.json`, gate goes red with no report edit.
- `RC-WS0.6` — Adversarial smoke lane: CI job rebuilds clean and re-runs `ld_preload_smoke.sh`, failing on divergence from the committed summary. *Test:* it catches the python3 regression today.
- `RC-WS0.7` — Bead-closure freshness: closure requires a completion-contract artifact whose `generated_at_utc` + `chain_hash` fall inside the bead's `in_progress → closed` window. *Test:* a pre-dated closure is rejected.
- `RC-WS0.8` — Regenerate every stale canonical artifact; commit fresh; record each in the ledger.

**Risks / unknowns.** Some gates may be green *only* because of stale data — WS-0 will surface real failures (intended). E-process calibration needs a baseline window; bootstrap from existing CI history.

**Done-when.** A deliberately-introduced regression (slowed `memcpy`) turns a gate red within one CI run with zero JSON edits; a hand-edited past artifact breaks the ledger chain; every canonical artifact is ledger-anchored to an ancestor of `HEAD`.

**Depends-on.** Nothing.

---

### WS-1 — P0: fix the python3 perf regression `[epic]`

**Goal.** `python3 -c "print(1)"` runs within the perf budget in strict mode and well under timeout in hardened mode under `LD_PRELOAD`.

**Why.** ~650× slowdown / timeout means heavyweight runtimes — the binaries that validate a "drop-in libc" claim — do not survive interposition.

**Domain framing.** The ~650× is not uniform overhead; it is a **heavy tail** — a hot symbol hit an enormous number of times routing through a slow membrane branch. So the target is not mean latency but the **tail**: the p99.9 per-call cost of the dominant symbol. Use tail-index / extreme-value framing (`large_deviations.rs`, `cvar.rs` exist) to identify *which* symbol's tail dominates, then a profile-driven optimization loop (the `extreme-software-optimization` discipline: baseline → profile → fix → verify) on that one kernel.

**Beads.**
- `RC-WS1.1` — Profiling harness: `perf record`/flamegraph of `python3 -c "print(1)"` under preload, both modes, vs baseline. Artifact: `target/perf/python3_preload_profile.*`. *Test:* deterministic top-N hot-symbol list on re-run.
- `RC-WS1.2` — Ranked RCA: (a) per-call membrane overhead × python's call volume; (b) a pathological hot path; (c) FFI-PCC cert cache missing python's hot symbols; (d) TLS-cache thrashing/collisions; (e) metrics-atomics or evidence-ring contention; (f) a mutex on a hot path. Output: written RCA naming the dominant tail with profile evidence.
- `RC-WS1.3` — Algorithmic fix on the identified hot kernel (not a budget bump); verify against the baseline with a behavior proof (output unchanged).
- `RC-WS1.4` — Perf-blocking regression gate: `python3` + one more heavyweight runtime (`perl`/`node`/a JIT) with per-binary p99.9 budgets. *Test:* gate fails if any tracked runtime exceeds budget.
- `RC-WS1.5` — Hardened-mode completion: python3 completes well under timeout; if membrane work is irreducibly expensive, the measured floor feeds WS-2's budget decision.
- `RC-WS1.6` — Deterministic smoke fixture dir (fixes the `/tmp`-size-sensitive `coreutils_ls_tmp` flake).

**Risks / unknowns.** The fix may conflict with WS-2 (which *adds* overhead). Sequencing: fix existing overhead before WS-2 adds any.

**Done-when.** Fresh `ld_preload_smoke.sh` green in both modes incl. python3, verified by the WS-0 adversarial lane.

**Depends-on.** WS-0.

---

### WS-2 — Wire the runtime-math control plane live `[epic]`

**Goal.** The runtime-math kernels execute on live per-call data in the shipped default configuration, and either provably stay within budget or the budget is honestly revised.

**Why.** Owner decision: dormancy is a defect. Today the runtime math contributes a constant zero to every decision.

**Domain framing — make "live" affordable, not a hack.** Wiring all ~71 kernels per call cannot meet < 20 ns. Two principled mechanisms:
- **Per-call monitor selection = submodular maximization under a knapsack.** Information gain across monitors is submodular; the latency budget is the knapsack. The greedy `(1 − 1/e)`-optimal selection picks the maximally-informative *subset* of kernels per call. `design.rs` (D-optimal) supplies the information matrix; `bandit.rs` routes depth. The runtime math thus *schedules itself* under the budget — provably near-optimal, not ad hoc.
- **Safe arming = a constrained POMDP.** The re-entrancy deadlock the code warns about is a hidden-state problem: "are we past the membrane-sensitive startup window?" is not directly observable. Model arming as a constrained POMDP (`pomdp_repair.rs` exists) — belief state over "safe to arm," action ∈ {arm, wait} — so `RUNTIME_READY` flips at the provably-safe moment, not a guessed one.

**Beads.**
- `RC-WS2.1` — Safe `RUNTIME_READY` arming under `LD_PRELOAD` via the constrained-POMDP arming model; no re-entrancy deadlock. *Test:* a constructor-heavy C++ binary preloads with the kernel armed and no deadlock.
- `RC-WS2.2` — Enable `OBSERVE_FEEDBACK` by default; feed exotic `cached_*_state` from live observations. *Test:* after a workload, ≥ N exotic atomics are non-zero.
- `RC-WS2.3` — Strict-mode observation policy: `decide()` runs the kernel in strict mode for observation + FullValidate routing only (no Repair rewrites — strict stays ABI-faithful). *Test:* strict workload emits evidence; no behavior rewrite.
- `RC-WS2.4` — Submodular-knapsack monitor scheduler over `design.rs` + `bandit.rs`; bounded per-call monitor count under the latency budget. *Test:* per-call monitor count bounded; information-gain telemetry recorded; greedy selection matches the `(1−1/e)` bound on a fixture.
- `RC-WS2.5` — FFI-PCC reconciliation: the 12 certificates short-circuit the hottest symbols in *both* modes. Per symbol, either prove the certificate sound and document it as an intentional fast-path exemption, or route it through the membrane in hardened mode. *Test:* a hardened-mode double-free on a certificated symbol is repaired, or the exemption carries a proof.
- `RC-WS2.6` — Liveness gates: assert `OBSERVE_FEEDBACK` enabled in the shipped artifact; assert each kernel's output reaches a decision; snapshot a workload kernel-state vector as a golden.
- `RC-WS2.7` — Perf re-validation with the math live; if < 20 ns strict / < 200 ns hardened cannot hold, revise the published budget honestly and update README/FEATURE_PARITY.

**Risks / unknowns.** `RC-WS2.1` (arming/deadlock) is the riskiest bead. `RC-WS2.5` may reveal the FFI-PCC certificates are a *correctness* hole in hardened mode, not just a perf shortcut.

**Done-when.** A workload shows non-zero exotic kernel state and ≥ 1 decision changed by a runtime-math signal; perf gate green (or budget honestly revised with evidence).

**Depends-on.** WS-0, WS-1.

---

### WS-3 — Honest symbol taxonomy `[epic]`

**Goal.** No symbol that default-delegates to host glibc is classified `Implemented`.

**Beads.**
- `RC-WS3.1` — Audit every symbol whose default path reaches `resolve_host_symbol_raw` / `delegate_to_host_*` (20 known call sites + ~81 broader refs); produce a definitive host-delegation census artifact.
- `RC-WS3.2` — Add a truthful taxonomy bucket (restore `GlibcCallThrough`, or add `HostDelegated`); reclassify. *Test:* `support_matrix.json` schema accepts the status; census re-derives.
- `RC-WS3.3` — Rescope the README "100% native coverage" badge + headline + FAQ to the genuinely-native subset; state the host-dependent subset explicitly. *Test:* doc-consistency gate matches re-verified count.
- `RC-WS3.4` — Update `replacement_levels.json` so L1 honestly reflects "native classified surface *minus* the host-delegated startup/loader/threading subset."

**Risks / unknowns.** Reclassification will drop the headline "100% native" number — correct and intended. Symbols WS-6 makes natively-default return to `Implemented`.

**Done-when.** Zero `Implemented` rows whose default path delegates to host; README badge matches a freshly re-verified count.

**Depends-on.** WS-0; unblocks back as WS-6 lands.

---

### WS-4 — Doc reconciliation

**Goal.** Every planning doc agrees with the freshly regenerated machine artifacts.

**Beads.**
- `RC-WS4.1` — `DEPLOYMENT.md`: L0 → L1; refresh runtime knobs.
- `RC-WS4.2` — `FEATURE_PARITY.md`: fix stale "TSM Coverage Matrix" + "Macro Coverage Targets"; delete the false Gap-Summary #5; reframe ~50 runtime-math `DONE` rows to honest wiring status (per WS-2); regenerate embedded snapshots.
- `RC-WS4.3` — `PLAN_TO_PORT` + `PROPOSED_ARCHITECTURE`: update stale rollout-status / "Implementation status (now)" sections.
- `RC-WS4.4` — README: reconcile "9 formal proofs" language with WS-7; tighten the headline badge per WS-3.
- `RC-WS4.5` — `check_doc_consistency.sh` gate (WS-0 style): scans docs for claims contradicting machine artifacts. *Test:* a deliberately wrong claim turns it red.

**Done-when.** `check_doc_consistency.sh` finds zero contradictions against fresh artifacts.

**Depends-on.** WS-0; coordinates with WS-2/3/7.

---

### WS-5 — Real, drift-robust conformance evidence `[epic]`

**Goal.** Conformance is genuine host-glibc differential testing, robust to glibc version skew.

**Domain framing.** Pure golden capture is brittle — it breaks on every host glibc version bump and tempts the swarm to "refresh" goldens to whatever the code now does. Pair real captures with **metamorphic relations** (the project's own conformance philosophy; a `testing-metamorphic` skill exists): properties that hold regardless of the oracle's exact value — round-trip identity, monotonicity, commutativity, idempotence. Metamorphic relations cannot be satisfied by editing a golden file, so they are Goodhart-resistant in a way capture-only fixtures are not.

**Beads.**
- `RC-WS5.1` — Real capture pipeline: run vectors against host glibc; serialize input/output with real timestamps + capture-host fingerprint (kernel, glibc version, arch). *Test:* re-running reproduces byte-identical fixtures.
- `RC-WS5.2` — Replace synthetic fixtures family-by-family with real captures; file every FrankenLibC-vs-glibc divergence found as a bug bead.
- `RC-WS5.3` — Metamorphic relation suite per family (round-trip, monotonicity, etc.) that holds without an exact oracle value.
- `RC-WS5.4` — Extend differential testing from the fuzz layer into the fixture-verify harness so every family has a host-parity oracle.

**Risks / unknowns.** Real captures will surface genuine parity bugs currently masked by author-written goldens — expect new bug beads (a good outcome).

**Done-when.** Every fixture family carries a real capture timestamp + host fingerprint + ≥ 1 metamorphic relation; the harness re-derives and matches.

**Depends-on.** WS-0.

---

### WS-6 — L2: standalone-readiness subsystems `[epic]`

**Goal.** The artifact no longer depends on host glibc for startup, dynamic loading, unwinding, or thread creation.

**Beads.**
- `RC-WS6.1` — Owned `__libc_start_main` / `csu` / TLS init as the **default** path (today opt-in via env var). *Test:* startup trace shows no host `__libc_start_main` call.
- `RC-WS6.2` — Owned dynamic loader: a `dlopen` that natively maps + relocates ELF shared objects (today: "Our dlopen cannot load ELF files natively"). *Test:* `dlopen` of a real `.so`, no host `ld-linux` fallback.
- `RC-WS6.3` — Owned unwinder: exercise `owned_unwind_abi.rs` end-to-end; remove libgcc fallback. *Test:* a C++ exception unwinds through the owned unwinder.
- `RC-WS6.4` — Native `pthread_create`/`join`/`detach` as default: flip `FORCE_NATIVE_THREADING`; root-cause and fix whatever forced it off. *Test:* a multi-thread stress binary runs on the native lifecycle.
- `RC-WS6.5` — iconv breadth: the glibc-2.40 `iconvdata` subset (CP932, EUC, BIG5, ISO-2022-*, KOI8-*).
- `RC-WS6.6` — NSS plugins: hosts/backend breadth, or document unsupported with an explicit semantic overlay.
- `RC-WS6.7` — Full pthread closure: barrier, spinlock, named semaphore, cancellation cleanup handlers.

**Risks / unknowns.** `RC-WS6.2` (native loader) is the single hardest item in the plan — dynamic linking is globally coupled to process behavior. `RC-WS6.4` may expose a real native-threading bug behind the default-off flag.

**Done-when.** L1→L2 promotion gates pass: zero residual host-glibc symbol references in the produced cdylib (`nm`-validated).

**Depends-on.** WS-0, WS-3.

---

### WS-7 — Formal proof program `[epic]`

**Goal.** Either the load-bearing theorems are machine-checked, or the "9 formal proofs" language is corrected.

**RC-WS7.1 decision (2026-05-21).** Reframe now; do not claim machine-checked theorem discharge until machine-checked artifacts exist.

**Rationale.** The current proof corpus is narrative notes and binder rows, not Lean/SMT/Coq/etc. artifacts. `FEATURE_PARITY.md` explicitly says no formal proof artifacts are committed yet, and the existing proof-chain CLI tests exercise evidence contracts rather than theorem-level mechanization. Mechanizing the load-bearing theorems remains valuable, but it is a separate implementation track with artifact obligations; until that lands, README/FEATURE_PARITY language must call these proof notes, proof obligations, and tested invariant catalogs, not completed formal proofs.

**Follow-on.** `RC-WS7.2` may add actual machine-checked artifacts; `RC-WS7.3` discharges or honestly defers the 24 proof obligations; `RC-WS7.4` reconciles README and FEATURE_PARITY wording to this decision.

**Beads.**
- `RC-WS7.1` — Owner decision bead: mechanize (the project has a `lean-formal-feedback-loop` skill) vs. reframe.
- `RC-WS7.2` — If mechanizing: machine-check the load-bearing theorems — Galois connection soundness, lattice monotonicity, SOS barrier nonnegativity, healing completeness — one checked artifact per theorem.
- `RC-WS7.3` — Discharge or honestly defer each of the 24 obligations in `proof_obligations_binder.v1.json`; every `planned`/`in_progress` row gets a reason + target.
- `RC-WS7.4` — Reconcile README ↔ FEATURE_PARITY proof language (feeds WS-4.4).

**Done-when.** Every "proof" claim in the README maps to either a machine-checked artifact or honestly-scoped language.

**Depends-on.** WS-0, WS-4.

---

### WS-8 — L3: standalone replacement artifact `[epic]`

**Goal.** `libfrankenlibc_replace.so` exists, builds, and runs as the primary libc.

**Beads.**
- `RC-WS8.1` — Produce `libfrankenlibc_replace.so` that runs a test process with no `LD_PRELOAD` and no host glibc.
- `RC-WS8.2` — aarch64 runtime artifact (passing, not just cross-compile-gated).
- `RC-WS8.3` — Distribution packaging contract: installable package for ≥ 1 Linux distro.
- `RC-WS8.4` — 24-hour soak across the curated workload set, zero divergence.
- `RC-WS8.5` — Perf: hardened mode within 2× native glibc on the standard benchmark suite.

**Done-when.** L2→L3 promotion gates in `replacement_levels.json` pass.

**Depends-on.** WS-6, WS-7.

---

### WS-9 — Anti-recurrence: make honesty the dominant strategy `[epic]`

**Goal.** The swarm cannot again drain its queue while the vision is undelivered.

**Domain framing — this is a mechanism-design problem.** The empty queue + stale-green gates are Goodhart's law: the proxy (closed beads) decoupled from the target. The fix is to redesign the bead-closure protocol so **truthful completion is the dominant strategy** — closure evidence must be *expensive to fake and cheap to verify*. That is a proof-carrying artifact: the project already ships proof-carrying policy tables (`policy_table.rs`, `.pcpt`); extend the pattern to completion contracts. And "done" must be a **sequential stopping rule**, not "queue empty": you only declare a milestone done when an anytime-valid test of "vision goals delivered" passes — the same e-process machinery as WS-0.

**Beads.**
- `RC-WS9.1` — Proof-carrying completion contracts: closure evidence is a cryptographic commitment to a regenerable artifact (hash-chained into the WS-0 ledger). Cheap to verify, expensive to fake. *Test:* a faked closure fails verification.
- `RC-WS9.2` — "Queue empty" triggers a mandatory reality check via a documented automated trigger, instead of resolving to a "done" state.
- `RC-WS9.3` — Milestone "done" as a sequential stopping rule: a milestone closes only when an anytime-valid test over its vision-goal evidence passes — reuses WS-0's e-process.
- `RC-WS9.4` — A standing **adversarial-verifier** agent role in the swarm whose objective is to *disprove* closure claims, not produce them — the structural counterweight to closure-optimizing agents.

**Done-when.** A faked closure is caught by `RC-WS9.1`; an empty queue provably triggers a reality check; no milestone can close without a passing sequential test.

**Depends-on.** WS-0.

---

## 5. Sequencing

```
WS-0 ──┬─> WS-1 ──> WS-2
       ├─> WS-3 ──┐
       ├─> WS-4 ──┼─> WS-7 ──┐
       ├─> WS-5   │           ├─> WS-8
       ├──────────┴─> WS-6 ───┘
       └─> WS-9
```

WS-0 first, always. WS-1 + WS-2 are the P0 critical path. WS-3/4/5/9 run in parallel after WS-0. WS-6/7/8 are the L2→L3 roadmap.

## 6. Success metrics (concrete, measurable)

| Workstream | Metric | Target |
|---|---|---|
| WS-0 | Injected regression caught with zero JSON edits | 100% (it is, or WS-0 failed) |
| WS-0 | Canonical artifacts anchored to a `HEAD` ancestor | 100% |
| WS-1 | `python3 -c "print(1)"` strict-mode perf ratio | within smoke budget (≤ 2,000,000 ppm) |
| WS-1 | `python3` hardened-mode wall time | well under the 10 s smoke timeout |
| WS-1 | Fresh `ld_preload_smoke.sh` | green both modes, python3 included |
| WS-2 | Exotic `cached_*_state` atomics non-zero after a workload | ≥ 90% |
| WS-2 | Decisions changed by a runtime-math signal in a workload | ≥ 1, demonstrably |
| WS-2 | Strict / hardened per-call overhead | within published budget, or budget revised with evidence |
| WS-3 | `Implemented` rows whose default path delegates to host | 0 |
| WS-4 | Doc-vs-artifact contradictions | 0 |
| WS-5 | Fixture families with a real capture + ≥ 1 metamorphic relation | 100% |
| WS-6 | Residual host-glibc symbol references in the cdylib (`nm`) | 0 |
| WS-9 | Faked closures caught | 100% |

## 7. Scope guard — what this plan deliberately does NOT do

Bounding scope is what makes the rest finishable (the README's own discipline).
- It does not re-architect the membrane or the allocator — those are sound; the problem is wiring and honesty, not design.
- It does not chase 100% POSIX semantic parity in one pass — locale/iconv/NSS breadth is staged into WS-6, not front-loaded.
- It does not add new runtime-math kernels — there are already ~71; WS-2 makes the existing ones live, it does not grow the count.
- It does not touch macOS/Windows, setuid deployment, or kernel-side mechanisms — all explicit project non-goals.
- It does not pursue L3 before L2 — WS-8 is gated behind WS-6/7.

## 8. Verification discipline (applies to every bead)

- Every implementation bead has a companion test bead: unit (happy/edge/error) + e2e/harness script with **structured, detailed logging**.
- Every "Done-when" artifact is regenerated fresh, carries a `freshness_state`, and is hash-chained into the WS-0 evidence ledger.
- No bead closes on a stale or self-authored artifact (WS-0.7 + WS-9.1 enforce this).
- Closure notes record: exact commands, artifact paths, `source_commit`, pre-existing failures, and a statement that unrelated swarm changes were not reverted.
