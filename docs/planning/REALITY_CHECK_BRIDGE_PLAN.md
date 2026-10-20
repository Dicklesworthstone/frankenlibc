# FrankenLibC — Reality-Check Bridge Plan

> **Canonical single plan document.** Always revise in place; never create `REALITY_CHECK_BRIDGE_PLAN_v2.md` or parallel plan files.
> **Original assessment:** 2026-09-08 at commit `3bf05e3a` (`bd-reality-202609-lx578q`).
> **Second pass:** 2026-09-23 (`bd-rc0923-epic-eeuy4f`).
> **Current reality check & revision:** 2026-10-20 at commit `9e97da908489a5f8e9b85cfd1f877ab4b40fef52`.
> **Scope:** Close the remaining gap between FrankenLibC's vision (`README.md`, `AGENTS.md`, `PROPOSED_ARCHITECTURE.md`, `PLAN_TO_PORT_GLIBC_TO_RUST.md`, `FEATURE_PARITY.md`) and executed reality at HEAD across all replacement levels (`L0` → `L1` → `L2` → `L3`).

---

## Current assessment — 2026-10-20

**Verdict:** FrankenLibC is substantial Linux interposition engineering with real
native kernels, selected hardened repairs, and improving executable evidence.
It is still **L0**, with major compatibility, performance, provider-independence
and qualification work remaining. It is not a demonstrated standalone glibc
replacement or a universal memory-safety layer. Finishing the intake backlog
alone would not close the vision gap.

This assessment supersedes the October 13 and earlier assessments below as a
statement of current state. Their observations and workstreams are retained as
dated evidence. In particular, their 44-stub counts, stale-healing diagnosis,
ungated aarch64 assembly diagnosis, and mapping of `.30` to printf/RPC work must
not be carried forward as current facts.

### Scope, source identity and verification limits

The checkout began clean on `main` at
`9e97da908489a5f8e9b85cfd1f877ab4b40fef52`. The full repository `AGENTS.md`
(1,567 lines) and `README.md` (3,963 lines), applicable machine/project guidance,
main porting plan, proposed architecture, parity/deployment/compatibility guides,
existing bridge and stdio plans, investigation ledger, and relevant runtime-math
designs were reviewed. `/data/projects/AGENTS.md` is absent on this machine;
`/dp/AGENTS.md` resolves to the applicable `/Users/jemanuel/projects/AGENTS.md`.
Do not invent missing suite rules beyond the operative inline repo instructions.

Source review traced deployed allocator/string routing, runtime-policy bypasses,
pointer validation and quarantine limits, pthread host/native selection, loader
TLS/setjmp changes, healing subprocess execution, artifact admission, and the
claim/closure/architecture/performance gates. Keyword and structural inspection
found no ABI `todo!` macro, but actual unsupported behavior remains in explicit
stub macros and ordinary constant-return functions. A keyword count is not a
semantic completeness measure.

**Fresh Rust compilation, Linux preload execution and performance measurement
were not performed in this pass.** `sbh check --need 20G` returned exit 1 with
`status=critical` (about 254.7 GB free but below the configured APFS percentage
threshold). The machine's nonzero-preflight rule prohibits heavy build lanes.
The host is Darwin/arm64; existing Linux receipts cannot become fresh runtime
evidence by being read here. RCH was running with degraded fleet capacity.
No disk cleanup, local-build fallback, threshold override or service restart was
performed. This is a verification limitation, not a new product test failure.

### What is real, and what the evidence actually establishes

1. **The implementation is substantial.** The matrix contains 4,119 symbol rows:
   2,419 `Implemented`, 410 `RawSyscall`, 1,272 `WrapsHostLibc`, zero
   `GlibcCallThrough`, and 18 `Stub`. Thus 2,829 rows, or 68.7%, are classified
   native/direct-syscall. These are ownership classifications, not a completion
   percentage, full semantic-parity count, or independently verified provider
   census for every deployed configuration.
2. **Selected repairs have materially better evidence than the prior plan.**
   `healing_oracle.rs` launches explicit subprocess probes and checks observations;
   the committed October 19 report records 28/28 cases, library SHA-256
   `55e2f785e79b0cb6e951d13b65d6cd2e18c9659a2abce62a2137441625ea07e5`
   and probe SHA-256
   `41788673570ba38a2c103432bfd9fa90d0cf8363111163791cf3ca9e44ef0197`.
   That report has no `source_commit` field. It proves its recorded cases for its
   identified binaries, not fresh HEAD, every repair path, or invalid strict-mode
   behavior: the strict counterparts are valid controls.
3. **Real-program interposition has historical evidence.** The committed smoke
   summary remains September 24 at `a8a4110b…`: 189 pass, zero fail, four optional
   skips and one xfail. Its structured and free-text xfail assignments disagree.
   Later source and closure records show real fixes and broader cases, but no
   fresh full corpus result was observed here.
4. **Several old defects have source fixes.** `memcmp_validating` now resolves
   extents before installing the PCC scope. x86 TLSDESC assembly is cfg-gated,
   and aarch64 setjmp entries are naked Rust exports. Loader search/TLS and
   resolver/NSS module work has advanced. Do not reopen those historical defects
   merely because an old plan still describes them. Integrated release acceptance
   remains a separate obligation.
5. **The safety boundary is real and limited.** Strict hot copies bypass bounds
   validation. Hardened arena metadata/quarantine can support wired checks and
   repairs, but address reuse removes caller-generation information; direct C
   writes, signal-handler bypasses and a later access racing with free are not
   made safe by a completed validation lookup.

### Vision checklist and active coverage

`PARTIAL` below means implementation exists without complete goal delivery.
`UNPROVEN` means the required current execution was not observed. No row is
promoted to universally `WORKING` on source presence or receipt counts.

| Goal | Reality and status at the audited source | Existing work and bridge coverage |
|---|---|---|
| V1: existing Linux binaries run correctly in both modes | **PARTIAL / current execution UNPROVEN.** Historical smoke is useful; broad HEAD corpus remains outstanding. | Existing `bd-rc0923-epic-eeuy4f.4`; final acceptance `.47`. |
| V2: full POSIX/GNU behavior, including advertised exports | **PARTIAL / explicit STUBS.** Four printf-registration and fourteen SunRPC stubs remain; `printf_size`/`printf_size_info` also have constant fallback bodies. | Existing `bd-reality-202609-lx578q.7`, libm/cancellation work; new `.33`–`.36`, `.45`–`.46`. |
| V3: accurate ownership and host-dependency census | **PARTIAL / live gate FAIL.** Stale census; committed maintenance rejects 1,079 classifications. | Previous `.17` is closed; new `.37`–`.38` resolve the current gap. |
| V4: transparent spatial/temporal hardening | **PARTIAL.** Defined owned/quarantined paths work in recorded probes; universal safety does not follow. | Existing `bd-reality-202609-lx578q.8`, `.7`; retain deployed boundary/negative tests. |
| V5: live runtime math causally controls deployed policy | **PARTIAL.** ABI `decide` still hard-returns for seven hardened hot families; pointer validation can consult a separate kernel. Counters/profiles alone do not prove influence. | Existing `bd-reality-202609-lx578q.4`; keep route-specific causal tests. |
| V6: strict <20 ns and hardened <200 ns overhead, usable workload performance | **UNPROVEN globally / known active gaps.** Historical baseline and active allocator/sort/math work do not establish current all-path budgets. | `.9` sort, `.26` allocator, `bd-dcrhgl`, `bd-65p87u`, `bd-ny3hsa`, `bd-f874go`, `bd-rv2gv6`, current libm beads. |
| V7: complete startup/thread/cancellation/stdio/service integration | **PARTIAL.** Native components coexist with default host NPTL and host-backed fallbacks; integration remains open. | Existing `bd-reality-202609-lx578q.6`, `.6.1`, `.6.2`, `.6.3`, cancellation `.24`. |
| V8: actual host-independent replacement process | **UNPROVEN / preflight BLOCKED.** No supplied source-bound artifacts/package; zero workload processes executed in this pass. | Existing `bd-reality-202609-lx578q.1`, `.6`, `bd-38x82`. |
| V9: x86 baseline and aarch64 release qualification | **PARTIAL / ARM runtime UNPROVEN.** aarch64 type-checking is not release linking; the existing ARM smoke executes a static system-libc program. | Existing `.13` and release `.9`; new `.41`–`.42`. |
| V10: packages and 24-hour reliability | **UNPROVEN as a combined deliverable.** Package/schema receipts do not supply installed no-host execution or a 24-hour run. | Existing `bd-reality-202609-lx578q.9`, `bd-38x82.4`; architecture acceptance feeds release qualification. |
| V11: conformance evidence covers the declared surface | **PARTIAL.** 1,190/4,119 rows (28.9%) have fixture linkage; this is not a pass rate. Semantic overlay has nine representative entries and the join has seventeen blockers. | Existing `.7`; new `.45`–`.46` inventory unknowns and drive actual behavior work. |
| V12: claims and closure reflect executed reality | **PARTIAL / source-confirmed acceptance holes.** Operator guides disagree; closure admission accepts prose plus file existence. | New `.39`–`.40`, `.43`–`.44`; existing workspace hygiene `.11` and `bd-blnp4u`. |
| V13: load-bearing formal guarantees | **DEFERRED.** All 24 binder obligations remain deferred; supplied-matrix arithmetic and finite tests are not system theorems. | Preserve owner decision `bd-e4phe.1` and safety `.8`. No automatic mechanization program or false theorem promotion. |
| V14: asupersync/frankentui remain tooling dependencies | **Source/static-gate supported / execution not refreshed.** Harness features declare companion dependencies; the boundary validator passes. | Existing tooling-boundary gate plus release `.9`; verify feature-specific execution when qualified. |

### Fresh lightweight gate results

Logs for this pass are under `target/conformance/reality-20261020/`; generated
gate reports remain in their existing `target/conformance/` locations. These
are local reproduction aids, not a published release dossier.

| Command | Observed outcome | Meaning |
|---|---|---|
| `bash scripts/check_docs_semantic_claims.sh` | **Exit 1.** Seven stale numeric claims; semantic-field/shape subchecks pass. | Actual documentation drift; no runtime failure implied. |
| `bash scripts/check_support_matrix_maintenance.sh` | **Exit 1.** Host-delegation census is stale; later maintenance stages do not run. | Full maintenance is not green. The committed 1,079-invalid report is separate evidence. |
| `bash scripts/check_semantic_contract_drift.sh` | **Exit 1.** `support taxonomy Stub=0 claim blocker is missing or stale`. | Semantic claim bookkeeping disagrees with current eighteen-stub state. |
| `bash scripts/check_support_semantic_overlay_schema.sh` | **Exit 0.** Nine audited entries; no stale source refs under its predicate. | Bounded schema/source-anchor result, not exhaustive semantic coverage. |
| `bash scripts/check_replacement_levels.sh` | **Exit 0**, but structured L1 objective has **three blocked** obligations. | L0 declaration is coherent; L1 readiness is not established. |
| `bash scripts/check_closure_gate.sh` | **Exit 0.** Nineteen selected critique rows and thirteen post-cutoff rows accepted. | Admission predicates pass; they do not verify stored nonzero runtime results. |
| `bash scripts/check_ws8_e2e_standalone_verification.sh --preflight` | **Exit 2 / blocked.** Six blocked scenarios, zero workload processes and zero companion tests. | Correct missing-evidence refusal in this invocation; no standalone result. |
| `bash scripts/check_tooling_dependency_boundary.sh --validate-only` | **Exit 0.** Tooling boundary validated. | Static dependency validation, not feature-specific runtime execution. |
| `br --no-db dep cycles --json` at intake | **Zero cycles.** | Graph sanity only. |
| `bv --robot-triage` at intake | **Exit 0**, graph analysis completed. | Its 37-open snapshot differs from the raw status census; do not use it as a completion percentage. |

The committed maintenance report's 1,079 invalid rows break down into **1,075
conservative host-label/source mismatches** and **four detected true host calls
labelled `Implemented`**: the cancellation register/unregister wrapper family.
The first category requires reviewed promotion evidence, not blanket native
reclassification. Neither category means 1,079 observed runtime bugs.

### Newly confirmed gaps and the bridge

All IDs `.33`–`.47` below share prefix `bd-rc0923-epic-eeuy4f`.
Each implementation task contains context, existing file surfaces, constraints,
acceptance, positive/error cases and independent counterexamples; each has a
separate acceptance-test task. The complete specification is embedded in Beads.

| Gap and why existing work was insufficient | Implementation / acceptance | Required result and order |
|---|---|---|
| Missing printf registration and size formatter behavior. Historical plan `.30` actually resolves locale caching. | `.33` / `.34` | Callback-visible actual formatting, types/modifiers, truncation/counting, reentry/errors and both-mode provider-verified differentials. |
| Fourteen actual SunRPC stubs block zero-stub L1. No dedicated active implementation covered this set. | `.35` / `.36` | Real bounded local client/server/auth/transport/registration behavior; no permanently failing dlsym fallback promoted to implementation. |
| Closed derivation work leaves stale census and rejected classifications. | `.37` / `.38` | Exact-source conservative configuration-aware census, reviewed promotion proofs and row-level deltas; thresholds unchanged. |
| Active operator guides still claim L1/100% parity/met budgets; source/build descriptions conflict. | `.39` / `.40` | Reconcile existing docs and extend claim checks to their semantic fields. Immediate honest wording can land independently of implementation completion. |
| aarch64 gate does not link, and smoke never loads the library. | `.41` / `.42` | Linked AArch64 release, actual dynamic providers and both-mode C fixtures under native/QEMU execution. Preserve artifacts; missing compiler cannot pass. |
| Post-cutoff closure accepts `PASS` plus an existing filename/test/commit without reading an execution result. | `.43` / `.44` | Stored source/configuration-bound nonzero results; reject fabricated prose, unrelated output and zero-test success. Preserve explicit docs-only evidence and historical exemptions. |
| Representative semantic entries leave unreviewed fallback behavior outside the completion measure. | `.45` / `.46` | Complete inventory with explicit unknowns, case linkage and concrete behavior follow-through under existing `.7`; a complete inventory cannot claim complete semantics. |
| Independent task completion may still miss combined L1 behavior. | Acceptance `.47` | Fresh actual release corpus, repair/stub/claim tests and budgets; read structured blocked obligations before any promotion. |

The source findings are precise: `register_printf_*` bodies in
`glibc_internal_abi.rs` return `ENOSYS`; `printf_size` returns -1 and
`printf_size_info` returns zero. `rpc_stub!` generates unsupported constructors
and other RPC contracts. `runtime_policy::decide` retains its
`cfg!(not(test))` high-frequency hardened bypass before `kernel.decide`.
`run_aarch64_smoke.sh` uses `-static`, never passes its artifact to a process,
and exits zero for absent compiler/compile failure. It also deletes generated
files on its run path and was therefore not run unchanged. The closure-gate
Check 5 source requires a verification regex and any valid reference, not an
execution receipt. These are source-confirmed defects; their independent
executed negative controls are acceptance work, not results invented here.

### Bridge ordering and preserved goals

Implementation tracks remain independent. Evidence defects block promotion
claims, not every unrelated implementation. Tests can be authored early; the
companion acceptance task depends on implementation before it closes.

```text
printf .33 --------> acceptance .34 ----+
RPC .35 -----------> acceptance .36 ----+
census .37 --------> acceptance .38 ----+
docs .39 ----------> acceptance .40 ----+--> integrated L1 acceptance .47
closure .43 -------> acceptance .44 ----+    + fresh corpus .4
semantics .45 -----> acceptance .46 ----+    + hardened sort/budget .9

aarch64 .41 -------> acceptance .42 --> existing release qualification lx578q.9
owned CRT/stdio/services lx578q.6.* --> existing integration lx578q.6
owned integration + standalone lx578q.1 --> L2/L3/package/soak acceptance
```

Continue the existing allocator architecture/performance tasks, libm accuracy
tasks, cancellation `.24`, runtime influence `lx578q.4`, safety-boundary
`lx578q.8`, workspace hygiene `lx578q.11`, behavioral campaigns `lx578q.7`,
standalone `.1`/`.6.*` and release/soak work. New tasks do not discharge them.
Do not blindly implement the old stdio plan's foreign-`FILE` adoption or signal
policy as if its draft were already a demonstrated safe, ABI-faithful design.

All original POSIX/GNU, ABI, safety, performance, developer-transparency,
architecture and replacement goals remain. Mathematical proof obligations
remain explicitly deferred under the recorded owner policy. This pass does not
turn a proof-name/module inventory into a mechanized theorem or start a new
proof program implicitly.

### Ambition and refinement

**Ambition pass 1 — require an observable effect.** A printf registration must
change actual output; an RPC constructor must participate in an exchange; an
ARM test must load this library; a runtime-math signal must change a permitted
decision against a matched control. Non-null tokens, counters and `PASS` prose
cannot substitute. These requirements are embedded in the corresponding beads.

**Ambition pass 2 — compose evidence without inflating it.** Treat source and
configuration as an explicit provider abstraction. Bind source inputs, target,
features, profile, mode, library/probe hashes and actual symbol providers into
the observed result. Preserve unknowns rather than automatically promoting
them. Separate data integrity from behavioral truth. For performance, use the
deployed path and live incumbent in the same invocation; changing a budget is
not an optimization. For adaptive control, identify the signal-to-action path,
assumptions, deterministic fallback and cross-controller interference tests.

The mathematical techniques here serve concrete artifacts: conservative
provider manifests, transition/policy tables and causal counterexample tests.
No new controller is justified by novelty. Existing conformal/topological/
algebraic/descent obligations remain explicit; their required assumptions and
deferred proof state must accompany any future guarantee.

**Five plan-space passes** check the newly added tasks and their interfaces to
existing work: completeness; provider/test independence; dependency usability;
safety/performance/proof scope; then final consistency. Findings and exact
graph results are recorded in the completion checkpoint for this revision.
This is a bounded review of these tasks, not a claim to re-audit 7,490 historical
closures or every one of 4,119 function contracts.

The generation instruction applied verbatim is retained here for reproducibility:

```text
OK so please take ALL of that and elaborate on it and use it to create a comprehensive and granular
set of beads for all this with tasks, subtasks, and dependency structure overlaid, with detailed
comments so that the whole thing is totally self-contained and self-documenting (including relevant
background, reasoning/justification, considerations, etc.-- anything we'd want our "future self" to
know about the goals and intentions and thought process and how it serves the over-arching goals of
the project.) The beads should be so detailed that we never need to consult back to the original
markdown plan document. Remember to ONLY use the `br` tool to create and modify the beads and add
the dependencies.
```

Each refinement pass applies this frozen instruction:

```text
Check over each bead super carefully-- are you sure it makes sense? Is it optimal? Could we change
anything to make the system work better for users? If so, revise the beads. It's a lot easier and
faster to operate in "plan space" before we start implementing these things! DO NOT OVERSIMPLIFY
THINGS! DO NOT LOSE ANY FEATURES OR FUNCTIONALITY! Also make sure that as part of the beads we
include comprehensive unit tests and e2e test scripts with great, detailed logging so we can be
sure that everything is working perfectly after implementation. Make sure to ONLY use the `br` cli
tool for all changes, and you can and should also use the `bv` tool to help diagnose potential
problems with the beads.
```

### Backlog sufficiency and next execution

The intake JSONL contains 7,527 records: 7,490 closed, 23 in progress, five open,
five blocked and four tombstones. The `bd-` slice contains 6,299 closed and 33
active records. Prefix alone is not a proof of project ownership: at least one
active `bd-` title discusses BLAS/LAPACK/XLA performance. It was left intact.
No global completion percentage is meaningful for the vision.

**Would completing the intake backlog finish the project? No.** It omits the
concrete stub work, the actual ARM runtime/gate defect, closure receipt defect,
current census/docs regressions and exhaustive semantic unknowns described
above. The expanded graph now covers these observed gaps, but cannot guarantee
all future implementation discoveries or discharge deferred formal theorems.
The remaining standalone integration is large engineering work, not a small
cleanup implied by the low open count.

The ordinary write path, including `br --no-db create --dry-run`, refused the
old local DB with `SCHEMA_MISMATCH` (expected 19, found 0). The existing DB,
WAL/recovery files and metadata were preserved. The authoritative JSONL was
copied to `target/conformance/reality-20261020/issues.before.jsonl` (SHA-256
`bd38fe2d000cb6136a1371d4c48e646c4be937f5be3d1bd9c27f3a8315df8fd3`),
then imported through `br` into isolated `.beads/reality-20261020.db` with
`--no-auto-import --no-auto-flush`. All planning mutations use `br` against
that isolated DB. Canonical export requires preservation review and a fresh
JSONL comparison; do not export the stale original DB over this work.

Implementation begins with independently ready printf/RPC, census, docs,
closure and architecture tasks while existing owners continue their tracks.
Fresh build/runtime acceptance resumes only after the required disk preflight
passes. No implementation task is closed by this assessment.

### Completion checkpoint for this revision

The two ambition rounds and five plan-space refinement passes are complete:

1. **Completeness:** added independent positive/negative verification to every
   implementation pair, preserved the full inherited behavior contract, and
   made integrated acceptance read the structured L1 obligations.
2. **Independent evidence:** separated provider identity from correct output,
   widened claim checking beyond README counts, and clarified the separate ABI
   and pointer-validator runtime kernels. Existing stdio work must preserve
   ownership and cancellation/signal semantics rather than adopt a draft design
   on faith.
3. **Usable execution order:** allowed independently ready tasks and honest
   documentation fixes to proceed, kept ARM release qualification separate from
   x86 L0 work, and bound freshness to relevant source inputs without inventing
   new runtime measurements for unrelated documentation-only changes.
4. **Scope and ambition:** retained all fourteen RPC contracts, distinguished a
   working host-backed L1 path from native standalone support, bounded semantic
   inventory work through explicit unknowns, and retained the incumbent/live
   performance comparison and owner-deferred theorem policy.
5. **Final consistency:** reread all fifteen new task specifications,
   acceptance criteria and dependencies; cross-checked the vision matrix,
   provider/error controls, level boundaries and retained goals. No further
   plan-space defect was found in this bounded pass. This is convergence of the
   reviewed plan, not a claim of complete product implementation or an exhaustive
   audit of historical closures.

All fifteen new tasks remain **open**. There are seven implementation/test
pairs (`.33`–`.46`) and integrated acceptance `.47`. The implementation tasks
have no new blocking predecessor. Their companion acceptance tasks depend on
the corresponding implementation; `.47` depends on the six relevant companion
acceptances and the existing corpus/sort work. ARM acceptance `.42` additionally
blocks the existing architecture/package qualification task.

`br dep cycles --json` and `br dep cycles --include-closed --json` both report
zero cycles, including zero archived cycles. Final `bv --robot-triage` and
`bv --robot-insights` both completed with data hash `9b45f4175e012977`.
**`bv` skipped its cycle computation because the graph exceeds 2,000 nodes**;
the zero-cycle result comes from `br`, not that skipped analysis. `bv` reports
52 open in its own projection versus 48 active raw records; neither is a
product-completion measure. Its top recommendation includes the existing
BLAS/XLA task, reinforcing the need to choose by project scope rather than
blindly follow graph rank.

The canonical export now contains **7,542 records**, including all 7,527 intake
IDs: 7,490 closed, 23 in progress, 20 open, five blocked and four tombstones.
No existing status, description, acceptance criterion or closure was changed.
Only the three appended notes and one added release dependency were intentional
changes to existing issues. The current exporter also omits 1,475 obsolete
machine-local `source_repo_path` fields while retaining portable `source_repo`,
and renumbers one historical comment ID whose contents are unchanged. All old
comment contents and relations remain present.

The preview export changed `br`'s last-export anchor. A normal canonical flush
then refused stale data, and an unforced merge refused four ambiguous-base
rows. Before resolution, the canonical JSONL was confirmed byte-identical to
the intake snapshot. `br sync --merge --force-db` retained precisely the four
reviewed local note/dependency edits, recorded four `br-sync` audit comments,
and reported **7,542 merged, zero deleted, zero ID collisions**. This was a
reviewed resolution of those owned changes, not an override of peer edits.
`issues.jsonl` and `beads.base.jsonl` are byte-identical, and isolated-DB sync
status is healthy with zero dirty rows and no coverage drift. The original
schema-0 DB remains preserved; do not use it to overwrite the canonical graph.
The field-level comparison is retained locally in
`target/conformance/reality-20261020/preservation-report.json`.

This revision changes planning and tracker data only. It does not alter runtime
code, gate policy, fixture expectations, performance tolerances or deferred
proof decisions. The fresh execution limitation above remains unresolved.
`git diff --check` passes, and field-level JSONL preservation/dependency checks
pass. The required `ubs --staged` invocation exits **3: nothing scanned** because
the three staged files are Markdown/JSONL, outside its supported languages.
This is **not a UBS pass**; no allow-no-scan override was used. It supplies no
code-validation evidence for this documentation/tracker revision.

---

## Retained assessment — 2026-10-13

The following October 13 assessment is historical. Its original detail is
preserved; the current section above governs current status and task mappings.

## 0. Executive Summary (2026-10-13 Reality Check at `9cef7fbd2`)

Between the 2026-09-08 (`3bf05e3a`) and 2026-09-23 reality-check passes and today (`2026-10-13`, `9cef7fbd2`), FrankenLibC crossed a major threshold on its **L0/L1 `LD_PRELOAD` interposition surface**:

1. **Major Real-Program Preload Blockers Resolved (`bd-rc0923-epic-eeuy4f`):**
   - **GNU `FILE*` struct ABI (`bd-rc0923-epic-eeuy4f.1`, closed):** `fopen`/`fdopen`/`tmpfile`/`popen`/`fmemopen`/`open_memstream` now return 216-byte glibc-layout `_IO_FILE_plus` handles backed by host `fopencookie` instead of synthetic indices that caused `git`, `sed`, and `gawk` to `SIGSEGV`.
   - **C++ runtime locale initialization (`bd-rc0923-epic-eeuy4f.2`, closed):** `newlocale(1 << LC_ALL, ...)` and `LC_ALL_MASK` are accepted, unblocking `libstdc++` startup.
   - **Multi-threaded `fork` / `_Fork` / `clone` safety (`bd-rc0923-epic-eeuy4f.5`, `.27`, closed):** Lock ordering (`atfork -> stdio -> ENVIRON_LOCK -> pipeline -> malloc`), `ENVIRON_LOCK` owner-TID tracking, async-signal-safe `_Fork`, and PID-keyed runtime-log windows allow `tar -czf`, `make -j2`, and MT `fork+exec` stress suites to complete without livelock.
   - **C++ exception & forced-unwind propagation (`bd-rc0923-epic-eeuy4f.6`, closed):** Exported callback-taking entrypoints (`qsort`, `bsearch`, `pthread_once`, `dl_iterate_phdr`, `twalk`, `scandir`, `ftw`/`nftw`, `glob`) use `extern "C-unwind"` with `-C force-unwind-tables=yes`.
   - **GNU `argp`, `iconv`, `TZif`, named locales, RFC 6724, `setjmp` guard mangling, and `FRANKENLIBC_LOG` (`bd-rc0923-epic-eeuy4f.7`, `.8`, `.10`, `.11`, `.12`, `.16`, `.20`, `.21`, `.22`, `.23`, closed):** Native engines and differential gates are live in both `strict` and `hardened` modes.
   - **Support taxonomy honesty (`bd-reality-202609-lx578q.3`, `.10`, `.12`, `bd-rc0923-epic-eeuy4f.14`, closed):** `support_matrix.json` was audited and reclassified from the inflated `3,550 Implemented / 155 WrapsHostLibc / 0 Stub` snapshot to `2,399 Implemented (58.2%) / 410 RawSyscall (10.0%) / 1,266 WrapsHostLibc (30.7%) / 44 Stub (1.1%)` across 4,119 exported symbols; foreign `frankentorch-*`/`frankenjax-*` beads (1,195 rows) were separated from FrankenLibC's own `bd-*` backlog.

2. **What Still Does Not Work or Remains Unproven at `9cef7fbd2`:**
   - **L1 Promotion Is Still Blocked (`tests/conformance/replacement_levels.json`):** `current_level` remains `L0`. L1 (`Hardened Interpose`) is blocked on:
     1. **44 `Stub` symbols** (`40 SunRPC` in `rpc_abi.rs` + `4 printf registration` APIs in `glibc_internal_abi.rs`), plus unlabelled stubs (`printf_size`, `printf_size_info`) and mislabelled `ENOSYS` wrappers (`revoke`, `rexec`, `rexec_af`).
     2. **Stale checked-in `tests/conformance/ld_preload_smoke_summary.v1.json`** (still from `2026-09-24`, `a8a4110b`, `189 pass / 0 fail / 4 skip / 1 xfail`, while a 2026-10-06 run recorded 15 strict perf-ratio >2.0x failures on short-lived binaries plus `fork_multithreaded_parent`).
     3. **`fork()` 4x–7x slowdown & 328 MB strict writable `VmData` (`bd-rc0923-epic-eeuy4f.25`, `bd-4n397c`):** `ALLOCATOR_REENTRY_SLOTS` sits in `.data` (~7.4 MiB non-zero init) and `SEGMENT_RESERVE_SIZE` (~292 MiB) is mapped `PROT_READ | PROT_WRITE` upfront, breaking `setrlimit(RLIMIT_DATA, 10MB)` in gnulib and inflating `fork()` page-table copying.
   - **Newly Uncovered Hardened String/Memory Safety & Performance Defect (`NO_BEAD` at start of pass):**
     - `memcmp_validating` (`crates/frankenlibc-abi/src/string_abi.rs:5016-5037`) installs `entrypoint_scope_memcmp()` (`skip_pointer_validation: true`) *before* calling `known_remaining_for_certified_read(s1/s2)`. Because `known_remaining_for_certified_read` only consults `bump_mmap`, `segment`, and `fallback` — and steady-state **hardened** `malloc`/`calloc` allocations live in `AllocationArena` (`pipeline.allocate()`) — **hardened `memcmp` completely skips `AllocationArena` spatial bounds and quarantine UAF checks on hardened heap allocations**, while probing 64 slots of `FALLBACK_ALLOC_PTRS` twice per call on interior pointers!
     - Meanwhile, 12 of the 24 symbols in `FFI_PCC_CERTIFICATES` (`strcmp`, `strncmp`, `strchr`, `strrchr`, `strstr`, `memchr`, `memrchr`, `strnlen`, `memmove`, `memset`, `strcpy`, `strncpy` added in `bd-14baix`) **never call `runtime_policy::entrypoint_scope(...)`** in `string_abi.rs`! Their FFI-PCC certificates are 100% dead code in production (`ACTIVE_TRACE_CONTEXT` is `None`), and each entrypoint calls `check_ownership` + `known_remaining` **2 to 6 times per call** on the same pointer.
   - **Runtime Math Kernel Production Bypass & Baseline Self-Interposition:**
     - `runtime_policy::decide()` (`crates/frankenlibc-abi/src/runtime_policy.rs:2489-2596`) bypasses `RuntimeMathKernel::decide()` under `cfg(not(test))` for 11 families in `strict` mode AND 7 core families (`Allocator`, `StringMemory`, `Ctype`, `Loader`, `Stdlib`, `MathFenv`, `Stdio`) in `hardened` mode, contradicting `README.md:275` (`bd-reality-202609-lx578q.4`).
     - Removing global `+avx2,+fma` (`bd-rc0923-epic-eeuy4f.13`) left **144 call sites** in `libfrankenlibc_abi.so` (including `RuntimeMathKernel::decide`, `KTheoryController::observe`, `DroCvarController`, `microlocal`, `bloom::with_capacity`, `printf` float formatting) calling Rust `f64::mul_add`/`floor`/`ceil`/`trunc`/`round`/`rint`, which resolve to FrankenLibC's own exported `math_abi` entrypoints!
   - **Multi-Threaded Allocator Scaling & Hardened `sort` Gap:**
     - Multi-threaded `malloc` remains 36x–490x slower than glibc (`bd-rc0923-epic-eeuy4f.26`, `bd-65p87u`, `bd-dcrhgl`, `bd-ny3hsa`).
     - Hardened `LC_ALL=C sort` 120k is down from 240x to ~5.2x glibc (`0.199s` vs `0.038s`), still above the `<=3x` milestone and `<=2x` L3 contract, and UTF-8 `strcoll` calls `CStr::from_ptr` -> `strlen_validating` twice per comparison (`bd-rc0923-epic-eeuy4f.9`).
   - **L2/L3 Standalone Replacement & Verification Debt:**
     - 1,266 symbols (30.7%) remain `WrapsHostLibc`; `pthread_create`/`join`/`cancel` default to host NPTL; native thread cancellation (`FRANKENLIBC_THREAD_NATIVE=1`) and unwinding out of `main` under owned startup fail (`bd-rc0923-epic-eeuy4f.24`, `bd-reality-202609-lx578q.6`).
     - `tests/conformance/healing_oracle_report.v1.json` is still the `2026-02-25` policy-simulated artifact; `tests/conformance/support_semantic_overlay.v1.json` is still the `2026-05-25` 9-row snapshot; `scripts/check_docs_semantic_claims.sh` fails on numeric freshness; CVE triggers do not execute under `LD_PRELOAD` (`bd-rc0923-epic-eeuy4f.18`, `bd-reality-202609-lx578q.2`).

---

## 1. Phase 1 Reality Check Assessment: Vision Checklist & Gap Analysis

### 1.1 Vision Checklist & Current Status Matrix (`2026-10-13`, `9cef7fbd2`)

| ID | Vision Pillar & Concrete Requirement | Status | Code / Gate / Artifact Reality at `9cef7fbd2` | Covering Open / In-Progress Beads |
|---|---|---|---|---|
| **V1.1** | **L0/L1 Preload Compatibility:** Real C/C++/Python/Perl/CLI binaries run byte-identically under `LD_PRELOAD=libfrankenlibc_abi.so` in `strict` and `hardened` modes | `PARTIAL` | `git`, `sed`, `grep`, `awk`, `tar -czf`, `make`, `perl`, `iconv`, C++ locale/exceptions, and Python C extensions run. Stale checked-in `ld_preload_smoke_summary.v1.json` (`2026-09-24`); 2026-10-06 run had 15 strict short-lived perf-ratio (>2x) failures + `fork_multithreaded_parent`. | `bd-rc0923-epic-eeuy4f.4`, `bd-rc0923-epic-eeuy4f.3`, `bd-rc0923-epic-eeuy4f.25` |
| **V1.2** | **L1 Zero-Stub Gate (`stub_free_taxonomy`):** Zero `Stub` symbols in `support_matrix.json` and `replacement_levels.json` | `NO_BEAD` / `STUB` | `replacement_levels.json:98-109` blocks L1 on 44 `Stub` rows (`40 SunRPC` in `rpc_abi.rs` + `4 register_printf_*` in `glibc_internal_abi.rs`), plus unlabelled stubs `printf_size`/`printf_size_info`. | **`NO_BEAD`** (only `.17` classifies labels; no bead resolves the 44 L1-blocking stubs) |
| **V2.1** | **TSM Spatial & Temporal Safety in Hardened Mode:** Validating pointer pipeline + deterministic repair (`ClampSize`, `TruncateWithNull`, `IgnoreDoubleFree`, `IgnoreForeignFree`, `ReallocAsMalloc`, `ReturnSafeDefault`) | `REGRESSED` / `PARTIAL` | `AllocationArena` + `ValidationPipeline` work for `malloc`/`free`/`realloc`/`memcpy`/`strlen`. **Defect found:** `memcmp_validating` (`string_abi.rs:5017-5037`) sets `entrypoint_scope_memcmp()` (`skip_pointer_validation: true`) before `known_remaining_for_certified_read`, skipping `AllocationArena` bounds and quarantine UAF checks on hardened heap blocks! UAF guarantee is bounded by 64MB quarantine (`bd-reality-202609-lx578q.8`). | `bd-reality-202609-lx578q.8`, **`NO_BEAD`** for `memcmp` arena-validation bypass & dead FFI-PCC scopes |
| **V2.2** | **Executable Healing & CVE Fault Evidence:** Subprocess ABI fault injection + live CVE arena reproduction under `LD_PRELOAD` | `PARTIAL` | `healing_oracle.rs` (`4d7e35eed`) now spawns subprocesses and checks counter deltas, but committed `tests/conformance/healing_oracle_report.v1.json` is still from `2026-02-25` (`library: null`). CVE scripts (`generate_cve_uaf_validation.py`) only run `cc -fsyntax-only`. | `bd-reality-202609-lx578q.2`, `bd-rc0923-epic-eeuy4f.18` |
| **V3.1** | **Runtime Math Decision Kernel (~71 Modules):** Live routing/validation profile control in production with bounded overhead | `PARTIAL` / `BYPASSED` | `runtime_policy::decide()` (`runtime_policy.rs:2489-2596`) bypasses `RuntimeMathKernel::decide()` under `cfg(not(test))` for 11 families in `strict` AND 7 core families (`Allocator`, `StringMemory`, `Ctype`, `Loader`, `Stdlib`, `MathFenv`, `Stdio`) in `hardened` mode. | `bd-reality-202609-lx578q.4` |
| **V3.2** | **Zero Self-Interposition Inside Membrane & Core:** Internal math/membrane code must never re-enter exported ABI symbols | `NO_BEAD` / `REGRESSED` | Dropping global `+avx2,+fma` (`bd-rc0923-epic-eeuy4f.13`) caused 144 `f64::mul_add`/`floor`/`ceil`/`trunc`/`round`/`rint` sites in `frankenlibc-membrane` and `frankenlibc-core`/`abi` to call FrankenLibC's own exported `math_abi` entrypoints. | `bd-rc0923-epic-eeuy4f.13` (noted in review comment, **needs dedicated child bead + gate**) |
| **V4.1** | **Hardened Mode Throughput (`<= 200ns`, `<= 2x` strict):** Real workloads (`sort`, `python3`, `git`) usable in hardened mode | `PARTIAL` | Hardened `LC_ALL=C sort` 120k improved from 240x to ~5.2x (`0.199s` vs `0.038s` glibc), still above `<=3x`/`<=2x`. 12 string entrypoints in `FFI_PCC_CERTIFICATES` never call `entrypoint_scope` and call `known_remaining` 2–6x per call; UTF-8 `strcoll` calls `strlen_validating` twice. | `bd-rc0923-epic-eeuy4f.9` + **new child bead for string FFI-PCC & single-pass extent lookup** |
| **V4.2** | **Allocator & Process-Lifecycle Performance:** Multi-threaded `malloc` `<= 2x` glibc; `fork()` `<= 1.5x` glibc; `VmData < 10 MB` (`RLIMIT_DATA`) | `BLOCKED` / `PARTIAL` | MT `malloc` is 36x–490x slower (`bd-rc0923-epic-eeuy4f.26`). `fork()` is 4x/7x slower (`bd-rc0923-epic-eeuy4f.25`) and strict `VmData` is 328 MB (`bd-4n397c`) due to 7.4 MiB `.data` `ALLOCATOR_REENTRY_SLOTS` and eager writable 292 MiB `SEGMENT_RESERVE_SIZE`. | `bd-rc0923-epic-eeuy4f.25`, `bd-rc0923-epic-eeuy4f.26`, `bd-4n397c`, `bd-dcrhgl`, `bd-65p87u`, `bd-ny3hsa`, `bd-f874go` |
| **V5.1** | **POSIX / GNU / C23 Conformance & `libm` Accuracy:** Correctly rounded `libm` (`f32`/`f64`), `pthread` cancel/mutexes, `stdio` orientation/`fmemopen`, `wordexp`, `qsort`, `nsswitch` | `PARTIAL` | `f32`/`f64` `libm` sweeps (`bd-li7fb3`, `bd-otip6a`) in progress; host-thread `pthread_cancel` fixed for 67 syscall windows but native-thread cancel, `main` unwind, `thrd_sleep`, and stdio cancel remain (`bd-rc0923-epic-eeuy4f.24`); `PRIO_PROTECT` boost (`bd-rc0923-epic-eeuy4f.15`); `wordexp` (`bd-uu1wvp`), `stdio` (`bd-gtaukk`, `bd-lamxlj`), `qsort` (`bd-8p8q15`), `hosts_policy` (`bd-rc0923-epic-eeuy4f.19`). | `bd-li7fb3`, `bd-otip6a`, `bd-rc0923-epic-eeuy4f.24`, `.15`, `.19`, `bd-uu1wvp`, `bd-gtaukk`, `bd-lamxlj`, `bd-8p8q15`, `bd-o55x4n`, `bd-rv2gv6`, `bd-etgt2x` |
| **V5.2** | **Code-Derived Taxonomy & Semantic Overlay Truth:** `support_matrix.json`, `support_semantic_overlay.v1.json`, and `README.md` claims derived from code and passing CI gates | `PARTIAL` / `NO_BEAD` | `bd-rc0923-epic-eeuy4f.17` tracks deriving `support_matrix.json` from AST/call-graph. However, `support_semantic_overlay.v1.json` is still from `2026-05-25` (`3550 Implemented`, 9 rows) and `check_docs_semantic_claims.sh` fails at HEAD (`numeric_claim_freshness: fail`). | `bd-rc0923-epic-eeuy4f.17`, **`NO_BEAD`** for exhaustive `support_semantic_overlay.v1.json` & docs gate repair |
| **V6.1** | **L2/L3 Standalone Replacement (`libfrankenlibc_replace.so`):** Zero `WrapsHostLibc`, owned CRT/TLS/unwind, native `dlfcn` transitive loader, native `pthread`, native `stdio`/`locale`/`NSS`/`resolver` | `PARTIAL` / `BLOCKED` | `check_ws8_e2e_standalone_verification.sh` now fails closed (`bd-reality-202609-lx578q.1`). Owned CRT direct-link proof passes (`bd-reality-202609-lx578q.6.1`), but 1,266 `WrapsHostLibc` symbols (30.7%) remain across 28 ABI modules, blocking standalone link/boot. | `bd-reality-202609-lx578q.1`, `.5`, `.6`, `.6.1`, `.6.2`, `.6.3`, `bd-38x82` |
| **V7.1** | **Multi-Arch (`x86_64` baseline + `aarch64`), Distro Packaging & 24h Soak:** Portable baseline ISA, full `aarch64` parity, `.deb`/`.rpm` prefix validation, 24h soak | `PARTIAL` | Baseline `x86_64` gate (`check_baseline_isa.sh`) and `aarch64` `setjmp`/`longjmp` (`bd-rc0923-epic-eeuy4f.12`) pass. `dlfcn_tls.rs` TLSDESC asm is still `x86_64`-only; real workload/package/24h soak remain open. | `bd-rc0923-epic-eeuy4f.13`, `bd-reality-202609-lx578q.5`, `.9`, `bd-38x82.4` |
| **V8.1** | **Formal Proof Obligations & Workspace Gate Hygiene:** SOS barriers bound to deployed runtime state, mechanized safety proofs, green `clippy`/`fmt`/ABI test sweep | `PARTIAL` / `NO_BEAD` | `frankenlibc-membrane/build.rs` verifies 3 static `.task` Gram matrices, but `evaluate_size_class_barrier` is only called in undeployed `frankenlibc-core/src/malloc/allocator.rs` and `SosBarrierController` is bypassed on hot families; 0 mechanized proofs exist. `clippy` and `fmt` remain red (`bd-reality-202609-lx578q.11`). | `bd-reality-202609-lx578q.11`, `bd-g8zy5p`, `bd-blnp4u`, **`NO_BEAD`** for deployed SOS/proof binding |

---

### 1.2 The Five Core Gap Analysis Questions

1. **What works at HEAD (`9cef7fbd2`)?**
   - **Real-world `LD_PRELOAD` interposition (`L0`)** works across a broad corpus of real C, C++, Perl, and Python binaries (`git`, `sed`, `grep`, `awk`, `find`, `tar -czf/-cJf`, `gzip`, `make -j2`, `perl`, `iconv`, `getent`, `python3` with `sqlite3`/`ssl`/`ctypes`/`_decimal`, C++ `std::locale` and callback unwinding).
   - **Membrane spatial/temporal enforcement** works on `malloc`/`free`/`realloc`/`calloc`/`memcpy`/`strlen` in `hardened` mode: 24B SipHash header + 8B trailing canary + 64MB quarantine queue + signal-safe `FRANKENLIBC_LOG` JSONL sink (`bd-rc0923-epic-eeuy4f.16`) + live subprocess `healing_oracle.rs` (`4d7e35eed`).
   - **Baseline `x86_64` portability (`bd-rc0923-epic-eeuy4f.13`)**: `.cargo/config.toml` builds for baseline `x86-64` with `-Cllvm-args=-enable-tlsdesc`, `avx2_fma_dispatch!` runtime multiversioning, and `scripts/check_baseline_isa.sh` verifying zero unguarded AVX/FMA instructions and execution under `qemu-x86_64 -cpu Nehalem` and `qemu64`.
   - **AArch64 `setjmp`/`longjmp` (`bd-rc0923-epic-eeuy4f.12`)**: Exported with pointer guard mangling and verified under `qemu-aarch64`.

2. **What doesn't work?**
   - **Hardened `memcmp` Arena Bounds & UAF Bypass:** Because `memcmp_validating` installs `entrypoint_scope_memcmp()` (`skip_pointer_validation: true`) before `known_remaining_for_certified_read`, steady-state hardened heap allocations in `AllocationArena` are invisible to `memcmp` (no bounds clamping, no quarantine UAF detection), while `fallback_remaining` still wastes up to 128 hash-slot probes per call.
   - **Dead FFI-PCC Certificates & Multiple Validation Lookups in `string_abi.rs`:** 12 certified string symbols never call `entrypoint_scope` and call `known_remaining`/`check_ownership` 2–6 times per call.
   - **Production Bypass of `RuntimeMathKernel` & Self-Interposition of `libm`:** `runtime_policy::decide()` bypasses `RuntimeMathKernel::decide()` for the 7 highest-traffic families even in `hardened` mode, while 144 baseline float sites in `membrane`/`core`/`abi` call FrankenLibC's own exported `fma`/`floor`/`ceil`/`trunc`/`round`/`rint`.
   - **Multi-Threaded `malloc` (36x–490x) & `fork()` (4x–7x) / `VmData` (328 MB):** Thread-slot lookup/stats contention and eager writable 292 MiB segment reservation + 7.4 MiB `.data` reentry table.
   - **Incomplete `pthread_cancel` & Standalone Services:** Native-thread cancellation (`FRANKENLIBC_THREAD_NATIVE=1`), unwinding out of `main` under owned startup, stdio/`thrd_sleep` cancellation points, and 1,266 `WrapsHostLibc` symbols.
   - **Non-Executing / Stale Evidence Artifacts:** Committed `ld_preload_smoke_summary.v1.json` (`2026-09-24`), `healing_oracle_report.v1.json` (`2026-02-25`), `support_semantic_overlay.v1.json` (`2026-05-25`), syntax-only CVE triggers, and failing `check_docs_semantic_claims.sh`.

3. **What is blocking progression (`L0` → `L1` → `L2` → `L3`)?**
   - **`L0` → `L1` (`Hardened Interpose`) Blockers:**
     1. 44 `Stub` symbols in `support_matrix.json` (`40 SunRPC` + `4 register_printf_*`) + unlabelled stubs (`printf_size`, `printf_size_info`).
     2. Hardened `memcmp` arena-validation bug + hardened `sort` / string latency (`~5.2x` C locale, higher in UTF-8 `strcoll`).
     3. `fork()` 4x–7x slowdown and 328 MB `VmData` (`bd-rc0923-epic-eeuy4f.25`, `bd-4n397c`) + 15 short-lived process strict perf-ratio failures in `ld_preload_smoke.sh` (`bd-rc0923-epic-eeuy4f.4`).
     4. Multi-threaded `malloc` 36x–490x slowdown (`bd-rc0923-epic-eeuy4f.26`).
   - **`L1` → `L2` (`Partial Replacement`) & `L3` (`Full Replacement`) Blockers:**
     1. 1,266 `WrapsHostLibc` symbols across 28 ABI modules (`math_abi` 510, `glibc_internal_abi` 207, `stdio_abi` 113, `unistd_abi` 67, `io_internal_abi` 63, `stdlib_abi` 60, `wchar_abi` 54, `string_abi` 36, `pthread_abi` 28, `rpc_abi` 26, etc.).
     2. Native thread creation/cancellation (`FRANKENLIBC_THREAD_NATIVE=1`) and owned-startup `main` unwind landing pad (`bd-rc0923-epic-eeuy4f.24`, `bd-reality-202609-lx578q.6.1`).
     3. Standalone `dlfcn` transitive loader + `dladdr`/`dl_iterate_phdr` unification + `aarch64` TLSDESC (`bd-rc0923-epic-eeuy4f.3`, `bd-reality-202609-lx578q.5`).
     4. Standalone native `stdio` FILE lifecycle (`bd-reality-202609-lx578q.6.2`) and native `locale`/`iconv`/`NSS`/`resolver` services (`bd-reality-202609-lx578q.6.3`).

4. **Would completing all currently open and in-progress beads close the gap?**
   - **No.** Completing the 48 currently non-closed beads would close ~80% of the gap, **but would leave five critical gaps open** because they either lack bead coverage (`NO_BEAD`) or fall between existing beads' acceptance criteria:
     1. The **hardened `memcmp` `AllocationArena` bypass** (`skip_pointer_validation: true` before `known_remaining`) and the **12 dead FFI-PCC certificates + 2x–6x redundant `known_remaining` calls** across `string_abi.rs`.
     2. The **44 L1-blocking `Stub` symbols** (`4 register_printf_*` + `printf_size`/`printf_size_info` + `40 SunRPC` symbols) in `replacement_levels.json`.
     3. The **144 self-interposed `fma`/`floor`/`ceil`/`trunc`/`round`/`rint` ABI calls** inside `frankenlibc-membrane` and `frankenlibc-core`/`abi` under the baseline `x86-64` build.
     4. The **stale `support_semantic_overlay.v1.json` (`2026-05-25`) and failing `check_docs_semantic_claims.sh` gate**.
     5. The **disconnected SOS barrier / proof obligations** (`evaluate_size_class_barrier` wired only to undeployed `frankenlibc-core/src/malloc/allocator.rs`, and `SosBarrierController` bypassed on `Allocator`/`StringMemory` in production).

5. **What vision goals had `NO_BEAD` coverage prior to this pass?**
   - We created dedicated, self-contained beads under `bd-rc0923-epic-eeuy4f` and `bd-reality-202609-lx578q` in Phase 3a/4 of this pass to cover all five `NO_BEAD` gaps above (`.28`, `.29`, `.30`, `.31`, `.32`).

---

## 2. Updated Workstreams & Bridge Plan (`WS-0` through `WS-9`)

### Dependency & Execution Order

```
WS-0 (Truth Gates, Semantic Overlay & Executable Evidence: .17, .18, .31, lx578q.2, lx578q.11)
  │
  ├──► WS-1 (Hardened String/Memory Safety, FFI-PCC Unification & Sort <2x: .9, .28)
  │
  ├──► WS-2 (Runtime-Math Production Routing, Zero Self-Interposition & SOS Binding: lx578q.4, .13, .29, .32)
  │
  ├──► WS-3 (Deployed Allocator Scaling, Zero-Init .bss & Demand-Paged Segments: .25, .26, .28, 4n397c, dcrhgl, 65p87u, ny3hsa)
  │
  ├──► WS-4 (L1 Promotion Closure — Printf Specifier Registry, SunRPC Disposition & Fresh Corpus: .4, .30)
  │
  ├──► WS-5 (POSIX/GNU Conformance & Correctly-Rounded libm: .15, .19, .24, li7fb3, otip6a, g8zy5p)
  │
  └──► WS-6/7/8 (L2/L3 Standalone Replacement, Native Loader/CRT/Pthread/Stdio/NSS, AArch64 & 24h Soak: .3, lx578q.1, .5, .6.*, .9, 38x82)
```

---

### WS-0 — Truth Gates, Source-Derived Taxonomy & Executable Evidence (`P0`/`P1`)
**Goal:** Ensure every status table, semantic overlay, CVE gate, healing oracle report, and completion contract is source-derived, freshly executed against HEAD, and capable of failing when behaviour regresses.

- **Active Beads:**
  - `bd-rc0923-epic-eeuy4f.17` (`in_progress`, P2): Derive `support_matrix.json` status from AST/call-graph census across all 4,119 exported symbols (`tools/ verify/census`).
  - `bd-reality-202609-lx578q.2` (`in_progress`, P0): Regenerate `tests/conformance/healing_oracle_report.v1.json` from the live subprocess probe (`crates/frankenlibc-harness/src/healing_oracle.rs`, `tests/integration/fixture_malloc.c`) with non-null `library_sha256`, `probe_sha256`, and `source_commit`.
  - `bd-rc0923-epic-eeuy4f.18` (`open`, P2): Execute all 7 CVE trigger C programs under `LD_PRELOAD` in `strict` and `hardened` modes (`scripts/generate_cve_uaf_validation.py`, `scripts/cve_arena_gate.sh`), classify the 282 completion contracts as `receipt` vs `executes` and convert the top 30 to executing gates, and eliminate the 218 fail-open `return Ok(())` skip sites in `crates/frankenlibc-harness/tests/`.
  - `bd-rc0923-epic-eeuy4f.31` (**NEW**, P1): Reconcile `tests/conformance/support_semantic_overlay.v1.json` (currently stuck at `2026-05-25`, 9 rows, `3550 Implemented`) with the 4,119-symbol source-derived taxonomy (`Implemented: 2399`, `RawSyscall: 410`, `WrapsHostLibc: 1266`, `Stub: 44`), audit remaining `No-op`/`Fallback`/`Bootstrap`/`Unsupported` surfaces (`revoke`, `rexec`, `rexec_af`, `mcheck`, `encrypt`, `_nss_files_*`), and update `README.md` + `scripts/check_docs_semantic_claims.sh` so the semantic claims gate exits `0`.
  - `bd-reality-202609-lx578q.11` (`in_progress`, P2) & `bd-blnp4u` (`in_progress`, P2): Clear the remaining `cargo clippy --workspace --all-targets -- -D warnings` and `cargo fmt --check` findings and wire `scripts/check_test_extern_symbols.sh` into pre-test verification.

---

### WS-1 — Hardened String/Memory Safety, FFI-PCC Unification & `sort` Performance (`P0`/`P1`)
**Goal:** Restore full `AllocationArena` spatial/quarantine protection across all read-only string/memory entrypoints while driving hardened `sort` and string microbenchmarks under `<= 2x` strict (`<= 200ns/call`).

- **Legacy Anchor:** `legacy_glibc_code/glibc/string/` (`memcmp.c`, `strlen.c`, `strcmp.c`, `strcoll_l.c`, `sysdeps/x86_64/multiarch/`).
- **Root Causes Identified in Phase 1:**
  1. `memcmp_validating` (`crates/frankenlibc-abi/src/string_abi.rs:5016-5037`) enters `entrypoint_scope_memcmp()` before `known_remaining`, activating `skip_pointer_validation: true` (`FFI_PCC_READ_ONLY_FLAGS`) and calling `known_remaining_for_certified_read(addr)`, which skips `validate_ptr` (`AllocationArena`) and probes 64 slots of `FALLBACK_ALLOC_PTRS` twice per call.
  2. 12 certified symbols in `FFI_PCC_CERTIFICATES` (`strcmp`, `strncmp`, `strchr`, `strrchr`, `strstr`, `memchr`, `memrchr`, `strnlen`, `memmove`, `memset`, `strcpy`, `strncpy`) never call `entrypoint_scope` in `string_abi.rs`, leaving their FFI-PCC certificates dead and calling `check_ownership` + `known_remaining` 2–6 times per call.
  3. Interior pointers inside `sort`'s large line buffer miss exact-base caches in `TlsValidationCache` (`ptr_validator.rs`) and `FALLBACK_ALLOC_PTRS`, causing repeated multi-stage arena/fallback misses on every line comparison.
  4. In UTF-8 locales (`en_US.UTF-8`), `strcoll` (`string_abi.rs:10632`) calls `CStr::from_ptr(s1)` and `CStr::from_ptr(s2)`, which invoke `strlen` -> `strlen_validating` twice per comparison before `tables.compare(a, b)`.
- **Active Beads:**
  - `bd-rc0923-epic-eeuy4f.9` (`open`, P1): Drive hardened `sort` 100k/120k lines from `~5.2x` (`LC_ALL=C`) and UTF-8 `strcoll` down to `<= 3x` glibc (milestone 1) and `<= 2x` strict (L3 contract).
  - `bd-rc0923-epic-eeuy4f.28` (**NEW**, P0): Fix hardened `memcmp` `AllocationArena` bounds/quarantine bypass, wire `entrypoint_scope` + single-pass `known_remaining` across all 14 string/memory entrypoints in `string_abi.rs`, and add base-interval range caching to `TlsValidationCache` (`crates/frankenlibc-membrane/src/tls_cache.rs`) so interior pointers into an already-validated heap buffer resolve in O(1) (`[user_base, user_base + user_size)`) without re-locking arena shards or probing 64 fallback slots.

---

### WS-2 — Runtime-Math Production Routing, Zero Self-Interposition & SOS/Proof Binding (`P1`)
**Goal:** Make `RuntimeMathKernel` genuinely govern production routing via O(1) precomputed/epoch-updated policy tables without hot-path lock overhead, eliminate all 144 baseline self-interposed `libm` calls, and bind SOS barrier certificates to live deployed allocator/thread telemetry.

- **Legacy Anchor:** `legacy_glibc_code/glibc/math/` (`s_fma.c`, `s_floor.c`, `s_ceil.c`, `s_trunc.c`, `s_round.c`, `s_rint.c`) and `crates/frankenlibc-membrane/src/runtime_math/`.
- **Active Beads:**
  - `bd-reality-202609-lx578q.4` (`in_progress`, P1): Replace the unconditional `cfg(not(test))` kernel bypass in `runtime_policy::decide()` (`runtime_policy.rs:2489-2596`) with cadence-gated / epoch-published atomic routing tables so `RuntimeMathKernel` decisions (`ValidationProfile::Fast` vs `Full`, `Repair`, `Deny`) actively govern production hardened calls at `< 5ns` fast-path read cost, and reconcile `README.md` with exact per-family routing truth.
  - `bd-rc0923-epic-eeuy4f.13` (`in_progress`, P1): Complete export-level dispatch / twin coverage for baseline `x86-64` (`strlen 4096`, `strnlen`, `wcsnlen`, `strcmp`) and verify stdout/stderr parity in `scripts/check_baseline_isa.sh`.
  - `bd-rc0923-epic-eeuy4f.29` (**NEW**, P1): Eliminate all 144 baseline `x86-64` self-interposed calls to `fma`, `fmaf`, `floor`, `ceil`, `trunc`, `round`, and `rint` across `frankenlibc-membrane` (`runtime_math/mod.rs`, `k_theory.rs`, `dro_cvar.rs`, `microlocal.rs`, `bloom.rs`), `frankenlibc-core` (`stdio/printf.rs`, `stdlib/ecvt.rs`, `math/`), and `frankenlibc-abi` by replacing float-intrinsic calls with pure IEEE-754 integer bit-manipulation helpers (for `floor`/`ceil`/`trunc`/`round`/`rint`) and internal non-ABI `core_fma` dispatch, enforced by an `objdump -d -r` gate in `scripts/check_baseline_isa.sh` that forbids internal PLT/relocation edges to exported `math_abi` symbols.
  - `bd-rc0923-epic-eeuy4f.32` (**NEW**, P2): Wire the build-time Cholesky-verified SOS barrier evaluators (`evaluate_fragmentation_barrier`, `evaluate_thread_safety_barrier`, `evaluate_size_class_barrier`, `evaluate_quarantine_barrier`, `evaluate_provenance_barrier` in `crates/frankenlibc-membrane/src/runtime_math/sos_barrier.rs`) into the **deployed** `malloc_abi.rs` and `AllocationArena` cadence telemetry path, and add deterministic property-based / Kani proof harnesses for the core Galois soundness, arena generation-monotonicity, and SOS barrier-invariance obligations (`bd-reality-202609-lx578q.8`).

---

### WS-3 — Deployed Allocator Scaling, Zero-Init `.bss` & Demand-Paged Segments (`P0`/`P1`)
**Goal:** Bring `fork()` latency (`<= 1.5x` glibc), private writable `VmData` (`< 10 MB` under `RLIMIT_DATA`), and 1-to-4-thread `malloc`/`free` throughput (`<= 2x` glibc) into compliance without sacrificing temporal/spatial guarantees.

- **Legacy Anchor:** `legacy_glibc_code/glibc/malloc/malloc.c` (`ptmalloc3` per-thread `tcache_perthread_struct`, `arena_get2`, `sysmalloc`) and Linux `mm/mmap.c` (`may_expand_vm` charging `VM_WRITE & !VM_SHARED` against `RLIMIT_DATA`).
- **Active Beads:**
  - `bd-rc0923-epic-eeuy4f.25` (`open`, P1) & `bd-4n397c` (`open`, P3):
    1. Make `ALLOCATOR_REENTRY_SLOTS` (`malloc_abi.rs:215`, 4,096 slots, ~7.4 MiB) 100% zero-initialized so the linker places it in demand-zero `.bss` instead of initialized `.data`: encode `fallback_cache_index` as `index + 1` (`0 = None`), `SegmentLocalClass.active_segment` as `segment + 1` (`0 = None`), and `SegmentMagazineEntry::EMPTY` as `0` (`offset + 1`).
    2. Change `ensure_segment_arena` (`malloc_abi.rs:651`) to reserve `SEGMENT_RESERVE_SIZE` (~292 MiB) with `PROT_NONE` (`MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE`) and `mprotect` individual 4 MiB segments and their 512 KiB sidecar slices `PROT_READ | PROT_WRITE` lazily when `SEGMENT_NEXT_UNUSED` claims a segment (or coalesce active segment permissions). This drops initial strict `VmData` from ~328 MB to `< 5 MB` (passing gnulib `dprintf-posix2`/`fprintf-posix3` under `RLIMIT_DATA = 10 MB`) and slashes `fork()` VMA/PTE copy time.
  - `bd-rc0923-epic-eeuy4f.26` (`blocked`, P0), `bd-dcrhgl` (`in_progress`, P1), `bd-65p87u` (`in_progress`, P2), `bd-ny3hsa` (`in_progress`, P2), `bd-f874go` (`in_progress`, P2):
    - Replace per-call multi-threaded global stats spinlock / atomic RMW triple (`allocator_depth` CAS + magazine/sidecar RMW + stats fold) with TCB-keyed (`%fs:0` / `tpidr_el0`) thread-local magazines and deferred epoch stats folding, achieving `<= 2x` glibc on 1 and 4 worker threads in `mtm.c`.

---

### WS-4 — L1 Promotion Closure: Printf Specifier Registry, SunRPC Disposition & Fresh Corpus Gate (`P0`/`P1`)
**Goal:** Satisfy every objective obligation in `tests/conformance/replacement_levels.json` so FrankenLibC can honestly promote `current_level` and `current_release_level` from `L0` to `L1` (`Hardened Interpose`).

- **Legacy Anchor:** `legacy_glibc_code/glibc/stdio-common/` (`reg-printf.c`, `reg-modifier.c`, `reg-type.c`, `printf-parsemb.c`, `printf_size.c`) and `legacy_glibc_code/glibc/sunrpc/`.
- **Active Beads:**
  - `bd-rc0923-epic-eeuy4f.30` (**NEW**, P1): Eliminate the 44 `Stub` symbols blocking `stub_free_taxonomy` in `tests/conformance/replacement_levels.json`:
    1. Implement native custom printf registration table (`register_printf_specifier`, `register_printf_function`, `register_printf_modifier`, `register_printf_type`) and `printf_size` / `printf_size_info` in `crates/frankenlibc-core/src/stdio/printf.rs` + `crates/frankenlibc-abi/src/glibc_internal_abi.rs`, wired into `vfprintf`/`vsnprintf` when custom specifiers are registered (zero cost on default path via an `AtomicBool` fast-check `CUSTOM_PRINTF_REGISTERED`).
    2. For the 40 deprecated TIRPC/SunRPC symbols in `crates/frankenlibc-abi/src/rpc_abi.rs` (`authnone_create`, `clnt_create`, `svc_register`, `pmap_set`, etc.), implement host-libc `dlsym(RTLD_NEXT)` interpose wrappers (matching the other 26 `WrapsHostLibc` RPC symbols in `rpc_abi.rs`) with deterministic fallback when host glibc omits obsolete SunRPC exports, and reclassify historical removed Linux syscalls (`revoke`, `rexec`, `rexec_af`, `nfsservctl`, `bdflush`, `create_module`, `get_kernel_syms`, `query_module`, `__sysctl`) consistently in `support_matrix.json` and `support_semantic_overlay.v1.json`.
  - `bd-rc0923-epic-eeuy4f.4` (`in_progress`, P0): Fix the remaining short-lived-process strict startup overhead (lazy segment/runtime init from WS-3) so all ~329 cases in `scripts/ld_preload_smoke.sh` pass with `0 fails` and `0 xfails` in both `strict` and `hardened` modes, regenerate `tests/conformance/ld_preload_smoke_summary.v1.json` via `scripts/check_ld_preload_smoke_regeneration.sh`, and run `scripts/check_replacement_levels.sh` to verify L1 gate readiness.

---

### WS-5 — POSIX / GNU / C23 Conformance & Correctly-Rounded `libm` (`P1`/`P2`)
**Goal:** Close behavioral divergences against glibc 2.43 across `libm`, `pthread`, `stdio`, `stdlib`, `posix`, and `resolv`.

- **Legacy Anchor:** `legacy_glibc_code/glibc/sysdeps/ieee754/` (CORE-MATH `f32`/`f64` kernels), `nptl/` (`pthread_cancel.c`, `pthread_mutex_lock.c`, `unwind.c`), `libio/` (`fmemopen.c`, `iofwide.c`), `posix/wordexp.c`, `stdlib/msort.c`.
- **Active Beads:**
  - `bd-li7fb3` (`in_progress`, P1) & `bd-otip6a` (`in_progress`, P1) & `bd-etgt2x` (`open`, P2): Complete correctly-rounded `f32` (via exact `f64` evaluation + round-to-odd/FMA guard) and `f64` (`asin`, `acos`, `exp`, `log2`, `log10`, `sinh`, `tanh`, `j0`/`j1`/`y0`/`y1`) CORE-MATH ports while keeping `cos`/`tan` within glibc latency budgets.
  - `bd-rc0923-epic-eeuy4f.24` (`in_progress`, P1): Complete `pthread_cancel` parity:
    1. Install a `__libc_start_call_main`-equivalent `setjmp` + `__pthread_register_cancel` unwind landing pad in `crates/frankenlibc-abi/src/startup_abi.rs` so `pthread_exit` or cancellation of `main` under owned startup terminates cleanly instead of `SIGSEGV`ing in `unwind_stop`.
    2. Wire cancellation windows for `thrd_sleep`, `sem_wait`/`sem_timedwait` pre-check, stdio blocking paths, and the opt-in native thread backend (`FRANKENLIBC_THREAD_NATIVE=1`).
  - `bd-rc0923-epic-eeuy4f.15` (`open`, P2): Complete `PTHREAD_PRIO_PROTECT` scheduler priority ceiling enforcement (`sched_setscheduler`/`ENOSYS`/`EINVAL` parity with glibc) and document/optimize robust-mutex owner-death detection.
  - `bd-rc0923-epic-eeuy4f.19` (`open`, P2): Add hermetic namespace DNS/NSS differential tests (`curl`, `ssh -G`, `getent`) for `hosts_policy.rs`.
  - `bd-gtaukk` (`open`, P3), `bd-lamxlj` (`open`, P3), `bd-o55x4n` (`open`, P2), `bd-rv2gv6` (`in_progress`, P2): Enforce `FILE` stream byte/wide orientation (`fwide` state machine), match glibc `fmemopen` deferred write-overflow reporting on `fflush`, and optimize locked `putc`/`fputc` and `fmemopen` `fread`.
  - `bd-uu1wvp` (`in_progress`, P3) & `bd-8p8q15` (`open`, P3) & `bd-g8zy5p` (`open`, P2): Implement `wordexp` command substitution (`fork`+`pipe`+`/bin/sh -c` when `WRDE_NOCMD` is not set), stabilize `qsort` tie order for `n >= 31`, and clear remaining test-sweep failures (`conformance_diff_lfs64_aliases`, `conformance_diff_setfsuid`).

---

### WS-6/7/8 — L2 Partial & L3 Full Standalone Replacement (`libfrankenlibc_replace.so`), Multi-Arch (`aarch64`) & 24h Soak (`P1`/`P3`)
**Goal:** Eliminate `WrapsHostLibc` dependencies on the standalone replacement path, unify the native ELF loader and owned CRT/TLS/pthread/stdio/NSS runtime into a self-hosting `libfrankenlibc_replace.so`, complete `aarch64` TLSDESC/loader parity, and pass the fail-closed WS-8 E2E and 24-hour soak gates.

- **Legacy Anchor:** `legacy_glibc_code/glibc/csu/libc-start.c`, `elf/dl-load.c`, `elf/dl-reloc.c`, `sysdeps/aarch64/dl-tlsdesc.S`, `nptl/pthread_create.c`.
- **Active Beads:**
  - `bd-rc0923-epic-eeuy4f.3` (`in_progress`, P0) & `bd-reality-202609-lx578q.5` (`in_progress`, P1): Unify native `dlopen` link-map registry with `dladdr` and `dl_iterate_phdr` so libgcc/libunwind can unwind through natively loaded DSOs; complete `DT_RPATH`/`DT_RUNPATH`/`LD_LIBRARY_PATH` transitive loading, `DF_1_NODELETE`, and `aarch64` TLSDESC resolver trampoline in `crates/frankenlibc-abi/src/dlfcn_tls.rs`.
  - `bd-reality-202609-lx578q.6` (`open`, P1), `.6.1` (`in_progress`, P1), `.6.2` (`in_progress`, P1), `.6.3` (`blocked`, P1):
    - `.6.1`: Complete owned CRT + TLS + native `clone3`/`futex` thread lifecycle and `__libc_start_call_main` unwind integration without host `libpthread`/`libc`.
    - `.6.2`: Replace the 113 `WrapsHostLibc` `stdio_abi` symbols and 63 `io_internal_abi` symbols on the standalone build profile with native `NativeFile` buffered streams (no host `fopencookie` dependency in standalone mode).
    - `.6.3`: Complete standalone native `locale`, `iconv`, `pwd`/`grp`/`spwd` NSS files, and UDP/TCP DNS resolver backends without host fallback.
  - `bd-reality-202609-lx578q.1` (`in_progress`, P0), `bd-reality-202609-lx578q.9` (`open`, P1), `bd-38x82` (`blocked`, P3), `bd-38x82.4` (`blocked`, P3):
    - Execute `scripts/check_ws8_e2e_standalone_verification.sh --build` and `--check` across `x86_64` and `aarch64` (`qemu-aarch64`), verify `/proc/self/maps` contains zero host `libc.so.6` mappings for standalone probes, validate `.deb` package extraction in an isolated rootfs prefix, and run the 24-hour multi-workload soak harness (`bd-38x82.4`).

---

## 3. Ambition Round 1 — Alien-Artifact Mathematical & Algorithmic Elevation (`alien-artifact-coding`)

> **Core Transparency Invariant (`PLAN_TO_PORT_GLIBC_TO_RUST.md` § "Transparency Rule"):** All high-powered mathematical synthesis runs offline or at startup/epoch boundaries; the hot runtime path executes only plain, deterministic, zero-lock data structures (flat lookup tables, interval caches, bitmasks, seqlocks, and compile-time/startup-verified tokens).

### 3.1 Galois Interval-Projection Cache for O(1) Interior-Pointer Validation (`WS-1` / `bd-rc0923-epic-eeuy4f.9`, `.28`)
- **Problem:** In `hardened` mode, `ValidationPipeline::validate(addr)` (`crates/frankenlibc-membrane/src/ptr_validator.rs:769`) caches `addr -> ValidationOutcome` in `TlsValidationCache` (`tls_cache.rs`) keyed by `(addr >> 4)` (16-byte granularity). When a workload like GNU `sort` allocates a single 4 MiB line buffer `[B, B + L)` and calls `memcmp(p_i, p_j, n)` or `strlen(p_i)` on 120,000 distinct interior line pointers `p_i \in [B, B + L)`, **every distinct 16-byte-aligned interior pointer misses the TLS cache** and falls back to the 16-shard `AllocationArena` lock (`BTreeMap::range(..=addr).next_back()`) or 64-probe `FALLBACK_ALLOC_PTRS` scan!
- **Mathematical Formulation (Abstract Interpretation over Interval Domains, Cousot & Cousot 1977):**
  - An allocation is not a point; it is a contiguous spatial-temporal interval $\mathcal{I}_g = ([b, b + s), g, \sigma)$ with base $b$, length $s$, generation $g$, and safety state $\sigma \in \{\text{Valid}, \text{Quarantined}\}$.
  - Define the Galois insertion $(\alpha, \gamma)$ between concrete interior pointers $p \in \text{Addr}$ and the thread-local interval-ring abstract domain $\mathcal{D}_{\text{TLS}} = \mathcal{I}^K$ ($K = 4$ MRU allocation extents per thread, fitting in two 64-byte L1 cache lines):
    $$\gamma([b, e, g, \text{epoch}]) = \{ p \in [b, e) \mid \text{rem}(p) = e - p \}.$$
  - Soundness condition: as long as `arena.release_epoch() == cached_epoch` (a single `Ordering::Acquire` load of a global `AtomicU64` incremented only when a block is freed/quarantined), any query $p \in [b, e)$ is guaranteed in-bounds with exact remaining bytes $\text{rem}(p) = e - p$ in **4 integer instructions (`sub`, `cmp`, `ja`, `sub`) and 0 locks**!
- **Runtime Artifact (`crates/frankenlibc-membrane/src/tls_cache.rs` & `crates/frankenlibc-abi/src/malloc_abi.rs`):**
  - Add a 4-way MRU **Base-Extent Interval Cache** (`[(base: usize, end: usize, generation: u64, state: SafetyState); 4]`) guarded by `ARENA_RELEASE_EPOCH: AtomicU64` (and `FALLBACK_ALLOC_TABLE_SEQ` for fallback allocations).
  - On any arena or fallback lookup that resolves $p \in [b, b + s)$, insert the full extent $[b, b + s)$ into the thread's 4-slot interval ring.
  - Subsequent `known_remaining(p')` calls for *any* interior pointer $p' \in [b, b + s)$ hit slot 0 in `< 2 ns` (0 locks, 0 hash probes, 0 SipHash recomputations), collapsing `sort`'s 120,000 interior-pointer validations into **1 arena lookup + 119,999 L1 register range checks**!

### 3.2 Static FFI-PCC Token Monomorphization & Single-Pass Validation Synthesis (`WS-1` / `bd-rc0923-epic-eeuy4f.28`)
- **Problem:**
  1. `FFI_PCC_READ_ONLY_FLAGS` (`runtime_policy.rs:405`) sets `skip_pointer_validation: true`, which caused `validate_ptr_in_slot` to return `Unknown` and blinded `memcmp_validating` to `AllocationArena` bounds and quarantine UAFs in hardened mode.
  2. Calling `entrypoint_scope(symbol)` dynamically hashes `(first_8_bytes, len)` and touches TLS twice, while 12 string functions omit `entrypoint_scope` and call `known_remaining` 2–6 times per call.
- **Mathematical Formulation (Proof-Carrying Code Witness Specialization, Necula 1997):**
  - Separate **Stage-Ordering / Kernel-Consult Elision** (`skip_stage_ordering: true`, sound for all 24 certified deterministic string/memory/allocator morphisms) from **Arena-Extent Projection** (`validate_ptr_in_slot`, which *must* remain active in hardened mode so `AllocationArena` bounds and `SafetyState::Quarantined` UAFs are enforced).
  - Factor every unary (`strlen`, `strnlen`, `strchr`, `strrchr`, `memchr`, `memrchr`, `strdup`, `strndup`) and binary (`memcmp`, `memcpy`, `memmove`, `strcmp`, `strncmp`, `strcpy`, `strncpy`, `strcat`, `strncat`, `strstr`, `strcasestr`, `strspn`, `strcspn`, `strpbrk`) hardened string entrypoint into a **Single-Lookup Extent Kernel**:
    $$\text{ExtentSnapshot}(p_1, p_2) = (\text{known\_remaining}(p_1), \text{known\_remaining}(p_2))$$
    computed **exactly once** per call before trace-scope installation, feeding `recent_page`, `bloom_negative`, `decide_certified(PccIndex::SYMBOL, ...)`, and `maybe_clamp_copy_len` from the same register pair.

### 3.3 Bijective Zero-Initialized State Encoding & Demand-Paged VM Geometry (`WS-3` / `bd-rc0923-epic-eeuy4f.25`, `bd-4n397c`)
- **Problem:** Linux `copy_page_range` during `fork()` scales with VMA count and populated PTE count, while `may_expand_vm` (`mm/mmap.c`) rejects any `mmap`/`brk` when private writable pages (`VM_WRITE & !VM_SHARED`) exceed `RLIMIT_DATA`. FrankenLibC's `ALLOCATOR_REENTRY_SLOTS` uses sentinel `usize::MAX`/`u16::MAX`/`u64::MAX` (`~7.4 MiB` in `.data`), and `SEGMENT_RESERVE_SIZE` (`~292 MiB`) is mapped `PROT_READ | PROT_WRITE` upfront.
- **Mathematical Formulation (Affine Sentinel Bijection & Lazy Viability Envelopes):**
  - Define the affine bijection $\phi: \{\text{None}\} \cup \{0, \dots, N-1\} \to \{0, \dots, N\}$ by $\phi(\text{None}) = 0$ and $\phi(i) = i + 1$. Under $\phi$, the identity initial state of `AllocatorReentrySlot` is the zero vector $\mathbf{0} \in \{0\}^{1856}$, moving all $4096 \times 1856 = 7.60\text{ MiB}$ from `.data` (file-backed/dirty COW pages) into `.bss` (unpopulated kernel zero pages).
  - Reserve the 292 MiB segment arena with `mmap(..., PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE)`. Because `PROT_NONE` has `vm_flags & VM_WRITE == 0`, Linux charges **0 bytes** against `RLIMIT_DATA`. When size class $c$ claims segment $k$, transition only $[B + k \cdot 4\text{ MiB}, B + (k+1) \cdot 4\text{ MiB})$ and its sidecar slice via `mprotect(..., PROT_READ | PROT_WRITE)`.

### 3.4 Lock-Free TCB-Keyed Magazine & Hierarchical Counter Folding (`WS-3` / `bd-rc0923-epic-eeuy4f.26`, `bd-65p87u`)
- **Problem:** Multi-threaded `malloc`/`free` is 36x–490x slower than glibc because each pair executes multiple contended atomic RMWs and global stats combiner locks.
- **Mathematical Formulation (Mean-Field Contention Decoupling & Bounded-Drift Martingale Counters):**
  - Key thread reentry slots directly by the architectural TCB self-pointer (`%fs:0` on x86_64, `tpidr_el0` on aarch64) with a direct-mapped thread-local index hint so steady-state `current_allocator_reentry_slot()` executes **zero syscalls and zero shared-cache-line writes**.
  - Replace the per-op global `FlatCombiningStats` spinlock in MT mode with per-slot relaxed accumulators (`SlotMtCounters`) that fold into global stats only every $M = 256$ operations via `try_lock` (never spinning when another thread holds the combiner lock).

### 3.5 IEEE-754 Bit-Level Morphisms for Zero-Reentrancy `libm` Primitives (`WS-2` / `bd-rc0923-epic-eeuy4f.29`)
- **Problem:** In baseline `x86-64` builds without global `+avx2,+fma`, Rust `f64::floor`, `ceil`, `trunc`, `round`, `rint`, and `mul_add` emit calls to the C symbols `floor`, `ceil`, `trunc`, `round`, `rint`, `fma` — which resolve to FrankenLibC's own exported ABI functions (`math_abi.rs`), causing membrane controllers to re-enter the ABI layer!
- **Mathematical Formulation (Bit-Lattice Decomposition of IEEE-754 Binary64):**
  - For any finite $x \in \mathbb{F}_{64}$ with biased exponent $e = ((u \gg 52) \mathbin{\&} \text{0x7ff}) - 1023$:
    - If $e < 0$, $\text{trunc}(x) = \pm 0.0$, $\text{floor}(x) \in \{0.0, -1.0\}$, $\text{ceil}(x) \in \{+0.0, +1.0\}$.
    - If $0 \le e < 52$, the fractional mask is $m = (1 \ll (52 - e)) - 1$; clearing bits $u \mathbin{\&} \sim m$ yields $\text{trunc}(x)$ in **6 branch-free ALU instructions** with zero FPU state or symbol calls!
    - If $e \ge 52$ (or NaN/Inf), $x$ is already an integral float ($x + 0.0$).
  - For `mul_add(a, b, c)` inside internal crates, route through an internal `frankenlibc_core::math::internal_fma(a, b, c)` that dispatches via cached CPUID (`fma` instruction when available, pure Dekkers-Veltkamp `dd_mul_add` software FMA otherwise) without touching `extern "C" fn fma`.

---

## 4. Ambition Round 2 — Extreme Systems Optimization & Verification Architecture (`extreme-software-optimization`)

### 4.1 Zero-Cost Default Path for Custom Printf Registry (`WS-4` / `bd-rc0923-epic-eeuy4f.30`)
- **Design:** GNU `register_printf_specifier` / `register_printf_function` / `register_printf_modifier` / `register_printf_type` and `printf_size` / `printf_size_info` are required by `stub_free_taxonomy` for L1 promotion and by gnulib/systemd-style formatters.
- **Optimization:** Maintain a single `CUSTOM_PRINTF_COUNT: AtomicU32 = AtomicU32::new(0)` in `frankenlibc-abi`. When `CUSTOM_PRINTF_COUNT.load(Ordering::Relaxed) == 0` (99.99% of processes), `vfprintf`/`vsnprintf` stays on the exact existing fused/core fast path with **zero extra branches in the format-specifier inner loop**! Only when a process calls `register_printf_*` does `CUSTOM_PRINTF_COUNT` become non-zero, activating the read-mostly `RwLock<PrintfExtensionRegistry>` table lookup on unknown/registered conversion specifiers.

### 4.2 Unified Host/Native Cancellation & `__libc_start_call_main` Unwind Frame (`WS-5` / `bd-rc0923-epic-eeuy4f.24`)
- **Design:** Under owned startup (`__libc_start_main` in `crates/frankenlibc-abi/src/startup_abi.rs`), calling `pthread_exit` from `main` or cancelling the main thread currently `SIGSEGV`s in libgcc's `unwind_stop` because there is no outer `pthread_unwind_buf` registered on the main thread's stack.
- **Architecture:**
  1. Model `startup_abi.rs` directly on `legacy_glibc_code/glibc/sysdeps/nptl/libc_start_call_main.h`: allocate a `pthread_unwind_buf` on the stack frame of `__libc_start_main`, initialize its `cancel_jmp_buf` via `__sigsetjmp(&mut buf, 0)`, register it via `__pthread_register_cancel(&mut buf)` when `setjmp == 0`, invoke `main(argc, argv, envp)`, and on non-zero `setjmp` return (forced unwind / `pthread_exit` from `main`), call `__pthread_cleanup_routine` and `exit(0)` (or wait for remaining threads via `_exit` when last thread exits).
  2. For native threads (`FRANKENLIBC_THREAD_NATIVE=1`), send `SIGRTMIN` (`SIGCANCEL`) via `tgkill(pid, tid, SIGCANCEL)` on `pthread_cancel`, and in the signal handler, when the interrupted `ucontext_t` PC lies within `[__frankenlibc_cancel_region_start, __frankenlibc_cancel_region_end)` (or async cancel is enabled), invoke `_Unwind_ForcedUnwind` directly from the signal frame.

### 4.3 Live Deployed SOS Barrier Telemetry & Mechanized Invariant Harnesses (`WS-2` / `bd-rc0923-epic-eeuy4f.32`)
- **Design:** Connect the 5 SOS polynomial certificates in `crates/frankenlibc-membrane/src/runtime_math/sos_barrier.rs` (`fragmentation`, `thread_safety`, `size_class`, `quarantine`, `provenance`) to the **actual deployed allocator and validator state** in `crates/frankenlibc-abi/src/malloc_abi.rs` and `crates/frankenlibc-membrane/src/arena.rs` on every 256th allocation/free fold epoch:
  - Feed real `(requested_bytes, class_size, waste_ppm)`, `(active_threads, contention_events, lock_hold_ns)`, and `(quarantine_bytes, arena_live_bytes, adverse_rate_ppm)` into `evaluate_*_barrier(...)`.
  - When any SOS barrier certificate headroom drops below `0` (`SosBarrierState::Violated`), atomically escalate `AllocationArena` quarantine drain cadence and force `ValidationProfile::Full` across all threads, logging a structured `sos_barrier_violation` event to `FRANKENLIBC_LOG`.

---

## 5. Complete Bead Mapping & Backlog Matrix (`2026-10-13`)

### 5.1 Newly Created Beads in This Pass (Closing All `NO_BEAD` Gaps)

| Bead ID | Priority | Parent Epic | Workstream | Title & Scope |
|---|---|---|---|---|
| `bd-rc0923-epic-eeuy4f.28` | `P0` | `bd-rc0923-epic-eeuy4f` | `WS-1` | **[RC-1013] Fix hardened `memcmp` Arena bypass, wire dead FFI-PCC scopes across 12 `string_abi` entrypoints, and add 4-way TLS Base-Extent Interval Cache for O(1) interior-pointer validation** |
| `bd-rc0923-epic-eeuy4f.29` | `P1` | `bd-rc0923-epic-eeuy4f` | `WS-2` | **[RC-1013] Eliminate 144 baseline x86-64 self-interposed `fma`/`floor`/`ceil`/`trunc`/`round`/`rint` ABI calls in membrane/core/abi with bit-level IEEE-754 kernels + relocation gate** |
| `bd-rc0923-epic-eeuy4f.30` | `P1` | `bd-rc0923-epic-eeuy4f` | `WS-4` | **[RC-1013] Unblock L1 `stub_free_taxonomy` gate: implement native `register_printf_*` + `printf_size` registry and host-fallback/reclassify the 40 SunRPC stubs** |
| `bd-rc0923-epic-eeuy4f.31` | `P1` | `bd-rc0923-epic-eeuy4f` | `WS-0` | **[RC-1013] Reconcile `support_semantic_overlay.v1.json` with 4,119-symbol taxonomy and restore `check_docs_semantic_claims.sh` to green** |
| `bd-rc0923-epic-eeuy4f.32` | `P2` | `bd-rc0923-epic-eeuy4f` | `WS-2` | **[RC-1013] Bind Cholesky SOS barrier evaluators to deployed `malloc_abi`/`AllocationArena` telemetry and add mechanized Galois/arena/SOS property proof harnesses** |

### 5.2 Existing Open / In-Progress / Blocked Beads Across Workstreams

| Workstream | Bead IDs | Current Status | Key Deliverable |
|---|---|---|---|
| **WS-0 (Truth & Evidence)** | `bd-rc0923-epic-eeuy4f.17`, `.18`, `.31`, `bd-reality-202609-lx578q.2`, `.11`, `bd-blnp4u` | `in_progress` / `open` | Source-derived `support_matrix.json`, refreshed `support_semantic_overlay.v1.json`, live `healing_oracle_report.v1.json`, executing CVE & completion gates, green `clippy`/`fmt`/`check_docs_semantic_claims.sh`. |
| **WS-1 (Hardened String & `sort`)** | `bd-rc0923-epic-eeuy4f.9`, `.28` | `open` | Hardened `memcmp` bounds/UAF fix, all 24 FFI-PCC scopes active, 4-way TLS Base-Extent Interval Cache, single-pass `known_remaining`, hardened `sort` `<= 2x` strict. |
| **WS-2 (Runtime Math, ISA & SOS)** | `bd-reality-202609-lx578q.4`, `bd-rc0923-epic-eeuy4f.13`, `.29`, `.32` | `in_progress` / `open` | Epoch-published production `RuntimeMathKernel` routing, 0 self-interposed `libm` calls in baseline `.so`, deployed SOS barrier telemetry + mechanized proof tests. |
| **WS-3 (Allocator & `fork` Perf)** | `bd-rc0923-epic-eeuy4f.25`, `.26`, `bd-4n397c`, `bd-dcrhgl`, `bd-65p87u`, `bd-ny3hsa`, `bd-f874go` | `open` / `in_progress` / `blocked` | Zero-init `.bss` `ALLOCATOR_REENTRY_SLOTS`, lazy `PROT_NONE` → `PROT_READ\|PROT_WRITE` segment activation (`VmData < 10 MB`, `fork <= 1.5x`), TCB-keyed MT magazines (`mtm.c <= 2x`). |
| **WS-4 (L1 Promotion Gate)** | `bd-rc0923-epic-eeuy4f.4`, `.30` | `in_progress` / `open` | `stub = 0` in `replacement_levels.json`, fresh `ld_preload_smoke_summary.v1.json` (`0 fails`, `0 xfails` across ~329 cases in strict + hardened), L0 → L1 promotion. |
| **WS-5 (POSIX / `libm` / `pthread`)** | `bd-li7fb3`, `bd-otip6a`, `bd-etgt2x`, `bd-rc0923-epic-eeuy4f.15`, `.19`, `.24`, `bd-gtaukk`, `bd-lamxlj`, `bd-o55x4n`, `bd-rv2gv6`, `bd-uu1wvp`, `bd-8p8q15`, `bd-g8zy5p` | `in_progress` / `open` | Correctly-rounded `f32`/`f64` `libm`, `__libc_start_call_main` cancel landing pad + native-thread cancel, `PRIO_PROTECT` boost, `fwide` orientation, `fmemopen` flush, `wordexp` `$(cmd)`, hermetic DNS tests. |
| **WS-6/7/8 (Standalone L2/L3 & Soak)** | `bd-rc0923-epic-eeuy4f.3`, `bd-reality-202609-lx578q.1`, `.5`, `.6`, `.6.1`, `.6.2`, `.6.3`, `.7`, `.8`, `.9`, `bd-38x82`, `bd-38x82.4` | `in_progress` / `open` / `blocked` | Native `dlfcn` + `dl_iterate_phdr` + `aarch64` TLSDESC, standalone CRT/TLS/pthread/stdio/NSS without `WrapsHostLibc`, fail-closed WS-8 E2E and 24h soak pass. |

---

## 6. Success Metrics & Exit Gates

| Workstream | Metric | Target | Verification Gate |
|---|---|---|---|
| **WS-0** | Stale/contradictory JSON artifacts or non-executing CVE/healing gates | `0` | `bash scripts/check_docs_semantic_claims.sh && bash scripts/cve_arena_gate.sh` |
| **WS-1** | Hardened `memcmp` arena bounds/UAF bypasses; redundant `known_remaining` calls per string op; hardened `sort` 120k ratio vs glibc | `0` bypasses; `1` lookup/ptr; `<= 2.0x` strict (`<= 3.0x` glibc) | `rch exec -- cargo test -p frankenlibc-abi --test string_abi_test --test hardened_mode_safety_test` + pinned `sort` 120k A/B |
| **WS-2** | Self-interposed `fma`/`floor`/`ceil`/`trunc`/`round`/`rint` relocations in `libfrankenlibc_abi.so`; production families with audited `RuntimeMathKernel` routing | `0` self-calls; `100%` families documented & gated | `bash scripts/check_baseline_isa.sh` + `rch exec -- cargo test -p frankenlibc-abi --test runtime_policy_test` |
| **WS-3** | Strict/hardened initial `VmData`; `fork+exit+wait` ratio vs glibc; 1T/4T `mtm.c` ratio vs glibc | `VmData < 10 MB`; `fork <= 1.5x`; `mtm <= 2.0x` | `fixture_fork_mt`, gnulib `dprintf-posix2` (`RLIMIT_DATA=10MB`), `mtm.c` 1T/4T benchmark |
| **WS-4** | `Stub` symbol count in `support_matrix.json`; `ld_preload_smoke.sh` fails/xfails in strict & hardened | `0` stubs; `0` fails / `0` xfails | `bash scripts/check_replacement_levels.sh && bash scripts/check_ld_preload_smoke_regeneration.sh` |
| **WS-5** | `f32`/`f64` non-CR outliers on CORE-MATH domain; `pthread_cancel` hang/SIGSEGV rows across 186-case probe | `0` unaccepted diffs; `0` hangs / `0` SIGSEGVs | `fixture_pthread_cancel`, `conformance_diff_math*`, `wordexp`/`stdio`/`qsort` differential tests |
| **WS-6/7/8** | Host `libc.so.6` mappings in `/proc/self/maps` for L3 standalone binary; WS-8 E2E status | `0` host mappings; `PASS` on `x86_64` + `aarch64` | `bash scripts/check_ws8_e2e_standalone_verification.sh --check` |

---

## 7. Verification Discipline (Applies to Every Bead)

- **No silent or uncompiled gates:** Always compile and execute named test targets via `rch exec -- cargo test ...` with `--keep-going` where appropriate, and quote the `test result: ok. N passed` line (`N > 0`).
- **Incumbent live in the same invocation:** Every performance claim requires live glibc and the incumbent FrankenLibC `.so` measured in the same order-rotated invocation under `scripts/check_perf_ledger_integrity.py`.
- **Companion tests + negative controls:** Every implementation bead carries unit tests (happy/edge/error), an E2E/preload probe emitting structured JSONL logs (`trace_id`, `mode`, `api_family`, `symbol`, `decision_path`, `healing_action`, `errno`, `latency_ns`), and a planted negative control proving the gate fails when the invariant is broken.
- **No file deletion (Rule 1) & worktree hygiene:** Never delete files without explicit user permission; never revert or touch uncommitted work from other agents.


---

## Retained historical assessments and workstreams

The current assessment above remains the active execution plan. The complete earlier
assessment and workstreams below are retained as dated historical evidence, including
their original caveats, source references, acceptance criteria, and unresolved gaps.
They are preserved verbatim from commit
`183f3d0b3d7a99f6a87e5bccaa2ecbe769867737`, before the October rewrite in
`b364c0e24f8da5a869400f317e1a6b1d1517ecfe`; historical observations do not become
current verification results by being retained here. This appendix keeps one canonical
plan document and preserves the incremental work from both assessments.

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

