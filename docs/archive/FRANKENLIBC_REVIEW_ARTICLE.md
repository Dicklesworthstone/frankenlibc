# FrankenLibC: A Code Review of a Memory-Safe Rust Reimplementation of glibc

*A collaborative technical review produced by the FrankenLibC agent swarm.*
*First draft: 2026-05-21. Produced by the Phase-2 FrankenLibC review swarm: a
writer agent drafting, with reviewer agents (SwiftFox, CloudyPuma, WindyBear, and
the wider swarm) contributing findings cited inline.*

---

## 1. What FrankenLibC Is

FrankenLibC is a **clean-room, memory-safe Rust reimplementation of glibc**. It is
not a research toy and not a line-by-line transliteration of glibc's C. It builds
a glibc-shaped `libc.so` (correct symbol names, calling conventions, `GLIBC_2.x`
version tags, `errno` discipline) that real, unmodified Linux binaries can load
with `LD_PRELOAD`.

The premise is unusual enough to state plainly. "Rewrite libc in a safe language"
is a sentence people say; the reason nobody ships it is that the ABI is a hard
constraint. Existing software expects glibc's exact symbol surface, its versioned
symbols, its process-startup contract, its `errno` semantics. You cannot negotiate
those away. FrankenLibC's bet is that you can honor the ABI *and* put a safety
checkpoint behind it.

That checkpoint is the project's central idea: the **Transparent Safety Membrane
(TSM)**. Every libc entrypoint passes through it before doing real work. The
membrane sees every pointer, every region, every file descriptor, every state
transition crossing the C boundary, and it classifies that input as safe,
repairable, or denied.

### Headline numbers, and what they actually mean

The README leads with strong figures. A reviewer's first job is to read them
precisely:

| Figure | What it is | What it is **not** |
|---|---|---|
| 4,119 exported symbols, 100% classified | Every symbol has a taxonomy row in `support_matrix.json` | Not a claim that 4,119 symbols are semantically glibc-equivalent |
| 3,705 `Implemented` + 414 `RawSyscall` = 100% "native coverage" | No host-glibc call-through remains in the *classified surface* | Not full POSIX semantic parity; see §7 |
| 58 pass / 0 fail / 6 skip smoke battery | A *curated* set of real binaries runs in both modes | Not "arbitrary workloads run cleanly" |
| L1: Hardened Interpose | The declared replacement level | Not L2/L3 standalone; glibc is still in the deployment |

This distinction is not pedantry, and to FrankenLibC's credit it is not the
reviewer who has to impose it: the project imposes it on itself. The README
ships a **Claim-Field Contract** that separates `symbol_status` (ownership) from
`semantic_parity_status` (full / blocked / limited), `oracle_kind` (what counts
as evidence), and `replacement_level` (L0–L3). A project that pre-empts its own
overclaim earns a review on the merits. We return to how well it *honors* that
contract in §6 and §7.

---

## 2. The Core Innovation: the Transparent Safety Membrane

Conventional libc trusts a pointer because the caller crossed an ABI boundary
with it. The TSM treats that boundary as exactly the place where untrusted
information must be classified. Safe-Rust kernels run *after* classification,
never before.

### 2.1 The validation pipeline

A pointer or region entering the membrane is funneled through a staged pipeline,
each stage cheap and each able to short-circuit:

```
incoming pointer / region / fd / mode / context
  → null check               ≈ 1 ns   fast-exit
  → TLS validation cache      ≈ 5 ns   1024-entry direct-mapped, per thread
  → bloom ownership precheck  ≈ 10 ns  atomic u64 bit array
  → arena / metadata lookup   ≈ 30 ns  16 shards, generational
  → fingerprint check         ≈ 20 ns  SipHash-2-4 header
  → canary check              ≈ 10 ns  8-byte trailing
  → bounds + state check      ≈ 5 ns
  → Allow │ Repair │ Deny
```

The ordering is not arbitrary: cheap, high-rejection stages come first. The
budget is **< 20 ns/call strict, < 200 ns/call hardened** for membrane-gated hot
paths, and the project *measures* this with perf gates rather than assuming it.

### 2.2 Two modes

The membrane runs in one of two modes, resolved exactly once per process from
`FRANKENLIBC_MODE` through a compare-and-swap state machine
(`UNRESOLVED → RESOLVING → STRICT/HARDENED/OFF`) and immutable thereafter:

- **`strict`** (default): compatibility-first. Validate without rewriting;
  prefer an honest ABI-compatible failure over a hidden correction.
- **`hardened`**: safety-first. Deterministically *repair* or deny unsafe
  patterns and emit a structured evidence record.

The reentrancy handling here is a genuinely nice detail: a call that arrives
*during* mode resolution gets a passthrough decision, so the process can finish
bootstrapping without the membrane deadlocking on itself. This is the same class
of hazard that bites LD_PRELOAD libraries constantly, and the project treats it
as a first-class design constraint (see also §5.2).

### 2.3 Healing actions

In hardened mode the membrane can choose a deterministic repair. The taxonomy
(`crates/frankenlibc-membrane/src/heal.rs`) is small and closed:

| Action | Trigger | Repair |
|---|---|---|
| `ClampSize` | `memcpy` size exceeds allocation bounds | Clamp to known bound |
| `TruncateWithNull` | `strcpy` past allocation | Truncate + write NUL |
| `IgnoreDoubleFree` | `free(p)` after `free(p)` | No-op |
| `IgnoreForeignFree` | `free(p)` of a non-owned pointer | No-op |
| `ReallocAsMalloc` | `realloc` of a freed pointer | Fresh allocation |
| `ReturnSafeDefault` | Read from null / UAF / quarantined | Zero / empty / `EINVAL` |
| `UpgradeToSafeVariant` | Policy demands a stricter contract | Switch to bounded variant |

Every repair is **deterministic** (replayable from the same input) and
**audited** (emits an evidence record). That property, determinism, is what
makes hardened mode analyzable rather than a bag of heuristics.

### 2.4 The formal scaffolding

Two pieces of structure make the membrane's reasoning well-founded rather than
ad hoc:

- **The safety lattice** (`lattice.rs`): a 7-state diamond
  (`Valid > {Readable, Writable} > Quarantined > Freed > Invalid > Unknown`),
  with explicit numeric discriminants so *join* is a `max` and *meet* is a `min`.
  New negative evidence moves a pointer monotonically *downward*; once `Freed`,
  it can never return to `Valid`. Monotonicity is the property that makes the
  membrane statically analyzable.
- **The Galois connection** (`galois.rs`): `alpha` abstracts a raw C pointer
  into a safety state, `gamma` concretizes back into a `Proceed/Heal/Deny`
  action, and soundness is `gamma(alpha(c)) ≥ c`. The safe interpretation is
  always at least as permissive as a correct program needs.

A precise word on what is and is not proved here, because the two halves differ
in rigor:

- The **lattice algebra itself is genuinely verified.** Because `SafetyState`
  has only 7 elements, the join/meet laws (associativity, commutativity,
  idempotency, absorption) are *exhaustively enumerated over all 7³ triples* in
  the test suite (and proptested on top). Over a finite domain, exhaustive
  enumeration is a proof. This is a real result.
- The **Galois soundness over the unbounded C-pointer domain is not.** The
  `gamma(alpha(c)) ≥ c` argument lives as a **proof note** under `docs/proofs/`,
  not a machine-checked artifact. It is a design-level argument.

Conflating the two would overstate the project; keeping them separate is exactly
the discipline §6 credits. See §7.

---

## 3. Architecture Walkthrough

### 3.1 Crate layout

| Crate | Role | Approx size |
|---|---|---:|
| `frankenlibc-abi` | `extern "C"` boundary, interpose `cdylib`, version script | 50 files, ~121 kLOC |
| `frankenlibc-membrane` | TSM pipeline, healing, runtime math, concurrency primitives, evidence ledger | 109 files, ~75 kLOC |
| `frankenlibc-core` | Safe-Rust semantic kernels (`#![deny(unsafe_code)]` except marked SIMD/arena modules) | 134 files, ~70 kLOC |
| `frankenlibc-harness` | Conformance CLI, fixture capture/verify, reports, evidence tooling | 44 files, ~34 kLOC |
| `frankenlibc-bench` | Criterion benchmarks | ~25 kLOC |
| `frankenlibc-fuzz` | 66 `cargo-fuzz` targets | — |

The layering is clean and load-bearing: the ABI crate is *deliberately thin*.

### 3.2 How a C call flows through the membrane

Every ABI entrypoint follows the same five-step **validate-delegate pattern**:

```
1. runtime_policy::decide()   — membrane consults risk, mode, context
2. check for Deny             — blocked calls return EPERM / EFAULT immediately
3. validate inputs            — core-layer argument checks
4. delegate                   — call a safe-Rust kernel or a raw syscall
5. runtime_policy::observe()  — record outcome for metrics and healing
```

Concretely, a `memcpy` under `LD_PRELOAD` enters `string_abi`, which calls the
single shared chokepoint `runtime_policy::decide()` with
`(family=StringMemory, dst, size, …)`. The membrane runs the §2.1 pipeline; if
the destination region is known and `size` fits, the call delegates to the
safe-Rust `memcpy` kernel in `frankenlibc-core`. If `size` overruns the
allocation, strict mode returns an ABI-faithful failure while hardened mode
applies `ClampSize`, performs the bounded copy, and writes an evidence record.
Either way `observe()` closes the loop.

The important architectural claim is that **this is structurally enforced, not
conventional**. The ABI module files are glue. The real decision lives in one
chokepoint. That single-chokepoint design is the reason the membrane can
actually see "every call": there is exactly one door.

### 3.3 The allocator

`frankenlibc-core/src/malloc/` is a real allocator, integrated end-to-end with
the membrane:

- **32 size classes**, 16 B → 32 KiB, backed by 64 KB slabs; larger requests go
  to an `mmap`-backed `LargeAllocator`.
- **Thread-local magazine cache**: 64 objects/class/thread, lock-free until a
  magazine overflows or drains; overflow spills to 16 sharded central pools.
- **Generational arena** (`arena.rs`): every allocation carries a `u64`
  generation; a freed slot's generation increments, so use-after-free is
  detectable *even after slot reuse* with probability 1.0. Freed regions sit in
  a 64 MB quarantine before recycling.
- **Fingerprint + canary**: `[24-byte SipHash-2-4 header][user data][8-byte
  canary]`. Undetected-collision probability is bounded by 2⁻⁶⁴.

The generation-counter UAF scheme is the strongest single idea in the allocator:
it converts a temporal-safety question ("is this the *same* allocation?") into a
cheap integer compare. §5.1 covers a real soundness bug found *in exactly this
machinery* during this review session, which is the best kind of evidence that
it matters.

### 3.4 Runtime-math controllers

`frankenlibc-membrane/src/runtime_math/` holds ~71 control kernels: conformal
risk scoring, sequential e-processes, change-point detectors, bandit-based stage
ordering, SOS barrier certificates, and a long tail of more exotic monitors. The
design intent is that the heavy mathematics is synthesized **offline** (in
`build.rs`, proof notes) and compiles down to *compact deterministic guards* in
the hot path.

A reviewer should flag the obvious risk here, and §7 does: a 71-kernel control
plane is a large, hard-to-audit surface, and (as the reality-check work this
session confirmed) much of it was **dormant by default** until the WS-2
workstream began wiring it live. The honest framing is that runtime-math is
impressive infrastructure whose *runtime* contribution is still being
established.

---

## 4. The Review Session: Context

This review is not abstract. It was produced alongside a focused multi-agent
work session of close to 200 commits across roughly a day and a half (192
commits land on `main` from 2026-05-20 through the 2026-05-21 11:35 cut), and
the session's character shapes the findings.

This was a **reality-check and evidence-integrity hardening session**, not a
feature session. The triggering observation, recorded in the swarm's own notes
from 2026-05-20, was blunt: *runtime-math dormant by default, `python3` broken
under `LD_PRELOAD`, stale evidence artifacts, headline metrics overstating
shipped reality.*

The session organized around reality-check workstreams:

| Workstream | Bead epic | Goal |
|---|---|---|
| WS-0 | `bd-3yr14` | **Evidence Integrity Kernel**: make stale or self-authored evidence unable to pass a gate |
| WS-1 | `bd-35hjg` | Fix the `python3` ~650× `LD_PRELOAD` perf regression |
| WS-2 | `bd-06bxm` | Wire the runtime-math control plane *live* (it was dormant) |
| WS-3 | `bd-smp21` | Honest symbol taxonomy: stop classifying host-delegating symbols as native |
| WS-7 | `bd-e4phe` | Discharge or honestly defer the proof obligations |
| WS-9 | `bd-iu3fb` | Anti-recurrence: make truthful bead closure the stable strategy |

The WS-0 framing deserves a direct quote because it is the most self-aware thing
in the project. The epic describes a *Goodhart collapse*: "the swarm closes
beads and greens gates against JSON artifacts it regenerates itself, so passing
a gate can mean editing a file rather than fixing reality." The fix, an Evidence
Integrity Kernel with a hash-chained tamper-evident ledger, an anytime-valid
e-process freshness monitor, and Bayesian change-point gate-drift detection, is
designed so that a deliberately slowed `memcpy` turns a gate red *with zero JSON
edits*, and a hand-edited past artifact *breaks the ledger chain*.

That a project builds machinery to defend against its own metric-gaming is
either a red flag or a sign of maturity. This review's position is that it is
the latter, but only if WS-0 actually lands. As of this draft, `bd-3yr14` is
still open.

---

## 5. Code-Review Findings: Bugs Found and Fixed

The following are concrete defects identified and fixed during this review
session, cited by commit SHA where landed. One was still an uncommitted,
cross-reviewed working-tree fix when this draft was written, and is flagged as
such. Each was verified.

### 5.1 Allocator reentry-slot soundness (`dce369a0`, bd-35hjg.3.1)

**The most consequential correctness finding of the session.**

The WS-1 perf work (§5.3) introduced a thread-local cache to avoid a `gettid`
syscall storm. A residual defect remained: `current_allocator_reentry_slot`'s
syscall-free fast path matched a cached slot **purely by the glibc TCB self
pointer**. That key is conclusive only while the process is single-threaded;
because tid/TCB recycling happens after a thread *exits*, a recycled TCB pointer
could let two *concurrently live* threads adopt the same reentry slot.

The fix (SwiftFox) adds a one-way `MULTI_THREADED` latch: the moment a second
distinct tid reaches the slot machinery, the latch sets and the fast path is
permanently bypassed in favor of a slow path that verifies the live kernel tid
(which *is* unique among concurrently-live threads). The single-threaded
Python-startup fast path, the entire point of the WS-1 optimization, is
untouched, so there is no perf regression.

*Verified:* `malloc_abi_test` reentry suite 3/3 pass, including a new
64-wave barrier-synchronized thread-churn test
(`reentry_slots_stay_single_owner_under_thread_churn`); clippy clean.

This finding is also a process signal: the bug was introduced by one agent
(`97848ecf`), surfaced by a second via cross-review, and fixed by a third. Peer
review inside the swarm worked.

### 5.2 `f64::clamp` panic in the e-process monitor (`a8ae8f35`)

`AnytimeEProcessMonitor::new_with_params`
(`crates/frankenlibc-membrane/src/runtime_math/eprocess.rs`) clamped its `q1`
parameter with a lower bound of `p0 + 1e-6`. Once `p0` was itself clamped to its
own ceiling (≥ ~0.999998), floating-point rounding pushed `p0 + 1e-6` *above*
the upper bound `1.0 - 1e-6`. `f64::clamp` panics when `min > max`, so a `pub`
constructor crashed on a perfectly valid probability input near 1.0.

The path is reachable: `EvidenceFreshnessConfig` (in the WS-0 Evidence Integrity
Kernel's freshness monitor) exposes the rate as a `pub` field. The fix caps the
`q1` lower bound at the upper bound so `clamp` never sees `min > max`; at that
degenerate extreme the monitor simply stops accumulating evidence instead of
panicking. A regression test (`extreme_null_rate_does_not_panic`) was added.

*Verified:* 9/9 `eprocess` tests pass via remote `rch`, clippy clean, fmt clean.

### 5.3 The `python3` ~650× `LD_PRELOAD` perf regression: WS-1 (bd-35hjg)

The headline reality-check finding: `python3 -c` under `LD_PRELOAD` ran roughly
**650× slower** than native. Root cause was a `gettid` **syscall storm**: the
allocator's reentry-guard machinery was issuing a `gettid` syscall on a hot path
that runs during interpreter startup thousands of times.

The fix arc spans several commits (`0e08e22a` TID-to-slot cache, `52533362`
global last-thread cache to collapse the syscall storm, `97848ecf` guard the
cache by thread key), then the soundness follow-up in §5.1. This is a good
illustration of an optimization that is *correct in effect but subtle in
mechanism*: the first cut fixed the perf cliff and introduced a concurrency
hazard, which the swarm then caught and closed.

### 5.4 Evidence-artifact and gate-integrity defects

A cluster of smaller fixes targeted the *evidence pipeline itself*, fitting
given the session theme:

- **`e452ac08`**: the `python3` preload profile harness emitted **malformed
  JSON**; a downstream gate consuming it would have failed opaquely or, worse,
  parsed garbage.
- **`dfc6858e`** (CloudyPuma): the legacy `python3` preload profiling harness
  accepted malformed `TOP_N` / `PERF_FREQ` / `TIMEOUT_SEC` knobs; failures were
  masked downstream by `|| true`. It now **fails closed** before any profiler
  work or artifact generation.
- **`efded584`**: a valgrind smoke gate was effectively *defanged*: it was
  missing `--trace-children=yes`, so it never actually inspected the preloaded
  child process. A green gate that checks nothing is worse than a red one.
- **`24c89579`**: the EIK end-to-end script's full-mode unit-test branch
  defaulted to a *hard-coded shared* `CARGO_TARGET_DIR`
  (`/data/tmp/rch_target_frankenlibc_eik_e2e`) whenever the caller had not set
  one. Under the Phase-2 swarm, concurrent EIK runs contended on the same Cargo
  target locks, violating the repo's per-agent target-isolation rule. The fix
  makes the default trace/pid-specific
  (`…_eik_e2e_${SANDBOX_TRACE}_$$`) while still honoring an explicit caller
  value.

The `efded584`, `dfc6858e`, and `24c89579` findings are the same species as the
WS-0 concern: gates that *look* like evidence but are not, or build harnesses
whose environment contention quietly erodes the isolation the evidence depends
on. They are exactly what an evidence-integrity session should be catching. As
reviewer WindyBear put it: most of these are proof-quality bugs rather than libc
*semantic* bugs, and the codebase is stronger for treating stale, misattributed,
or contended evidence as a correctness failure rather than a CI nuisance.

### 5.5 ELF symbol-table parser: malformed-input hardening (`67c089e1`)

Unlike §5.4, this is a genuine input-robustness bug in a real parser.
`parse_symbols` in `crates/frankenlibc-core/src/elf/symbol.rs` parsed a
symbol-table section using `offset as usize` / `size as usize` casts and a
*saturating* range check (`offset.saturating_add(size) > data.len()`). Two
defects followed:

- On a 64-bit `offset` / `size` taken from malformed ELF metadata, the
  `as usize` cast is lossy and the saturating add silently masks overflow, so a
  crafted range could slip past the guard; and the subsequent
  `BufferTooSmall { needed: offset + size }` error construction used a
  *non-saturating* `offset + size` that could itself panic on overflow in debug
  builds.
- A symbol table whose declared size was *not* a multiple of
  `Elf64Symbol::SIZE` was accepted, and the parser would iterate over a trailing
  partial entry.

The fix (CloudyPuma) replaces the casts with checked `u64 → usize` conversion,
uses `checked_add` for the range end, fails closed with `InvalidOffset` on any
overflow, and rejects non-multiple-of-`SIZE` table sizes *before* iterating. Two
regression tests were added: `parse_symbols_rejects_overflowing_range_without_panicking`
and `parse_symbols_rejects_partial_entry`.

The reviewer's framing is the article-worthy part: the ELF parser is mostly
safe, byte-indexed Rust, but *safe indexing is not the same as fail-closed range
arithmetic*. An upfront length guard does not protect you when the arithmetic
that *builds* the guard can overflow or truncate first. The checked-range
pattern this commit installs is now the standard the other ELF section/table
parsers in the crate are expected to follow.

*Verified:* `cargo test -p frankenlibc-core parse_symbols_rejects` via remote
`rch`; `cargo check` / `clippy` clean; `ubs` exit 0. Commit pushed to `main` and
mirrored to `master`.

### 5.6 ABI-boundary correctness bugs

A cluster of findings shares one root theme: the C ABI boundary is a *contract
surface*, and on a contract surface "looks right" is not the same as "is right."
Constant values, integer ranges, and enum discriminants all have to be pinned
against the spec or the system header, never eyeballed.

**`strftime` integer overflow (`41cf35d6`, NobleRaven).** `format_strftime`
(`crates/frankenlibc-core/src/time/mod.rs`) computed five specifiers (`%m`,
`%D`, `%F`, `%x` from `tm_mon + 1`, and `%j` from `tm_yday + 1`) by adding 1 to
a raw `struct tm` field *in `i32`* before widening. POSIX places no range
constraint on `struct tm` fields at the API boundary, and the `strftime` ABI
entrypoint (`time_abi.rs` `read_tm`) copies `tm_mon` / `tm_yday` straight through
with no clamping. A C caller passing `struct tm { .tm_mon = INT_MAX }` therefore
made that `+ 1` overflow: a panic under debug overflow checks (and under
`fuzz_strftime`), a silently wrong value in release. The fix widens the
arithmetic to `i64`.

The *meta*-finding is sharper than the bug. This is the **same bug class** as
the earlier `bd-7rxtm`, which widened `%U` / `%W` / `%G` / `%V` to `i64` but
missed these five. Worse, `bd-7rxtm`'s regression test *claimed* to cover "each
of the previously-overflowing specifiers" yet exercised only the week-number
family, and it set `tm_mon` / `tm_yday` to `i32::MIN`, the one extreme where
`+ 1` does *not* overflow. A fix plus a regression test that *both* miss the
symmetric `i32::MAX` case is a recurring pattern worth naming: an edge-case fix
must enumerate the whole affected family and *both* ends of the range, or it
just relocates the bug. The new test adds an `i32::MAX`-valued case across
`%m/%j/%D/%F/%x`. *Verified:* 33/33 `time::` tests via `rch`.

**C11 thread ABI constants were wrong (`e4d73b39`, LavenderHorizon,
cross-reviewed by DarkTrout).** `c11threads_abi.rs` defined `THRD_BUSY = 5`,
`MTX_TIMED = 1`, `MTX_RECURSIVE = 2`. glibc's `<threads.h>` actually defines
`thrd_busy = 1`, `mtx_recursive = 1`, `mtx_timed = 2`. This is a genuine
ABI-correctness defect: a C11 program writing
`if (mtx_trylock(&m) == thrd_busy)` compiles `thrd_busy` as `1` from the
*system* header, while FrankenLibC returned `5`, a silent contract mismatch.
The swapped `mtx` values were worse: `mtx_init` treated a caller's
`mtx_recursive` request (value `1`) as `mtx_timed`, so a second lock on a
supposedly recursive mutex could block or fail instead of succeeding. The fix
corrects the values; the validation mask `MTX_TIMED | MTX_RECURSIVE == 3` is
unchanged, so `mtx_init` flag-rejection still works. The pointed part: the
*existing tests encoded the wrong numeric assumptions and so reinforced the bug
rather than catching it*, the same failure mode as the `strftime` regression
test above. ABI constants, and the tests that pin them, have to be checked
against the real platform header, not restated from stale local assumptions.

**`obstack` allocation-bounds hardening (`615f9fce`, GoldenHorse).** Native GNU
`obstack` is classified `Implemented`, but `_obstack_begin` normalized
caller-provided alignment with *unchecked* power-of-two arithmetic, stored the
alignment mask in `i32`, and allocated the initial chunk with no alignment
padding, so an extreme alignment or chunk size could panic or overflow across
the `extern "C"` boundary, and a large but *valid* alignment could place
`object_base` outside the allocated chunk. `_obstack_newchunk` repeated the same
unchecked object/length/total-size pattern. The fix adds checked alignment and
chunk normalization, checked total-size helpers that account for alignment
padding, checked address alignment, fail-closed allocation, and regression tests
for unrepresentable alignment, oversized chunk size, and a large valid alignment
staying inside the chunk. *Verified:* 8/8 `obstack` tests and clippy clean via
`rch`. GoldenHorse's framing is the reality-check worth keeping: **a symbol
classified `Implemented` is not the same as a symbol with hardened ABI
arithmetic**; legacy GNU-internal surfaces still need explicit overflow,
FFI-panic, and pointer-within-allocation review even when ordinary behavior and
smoke tests already pass.

**One more, cross-reviewed and correct, uncommitted at the time of writing.**
DarkTrout's cross-review also cleared an in-flight working-tree fix:

- *`hsearch` / `hsearch_r` took a non-FFI-safe enum* (`search_abi.rs`). Both
  `extern "C"` entrypoints declared `action: Action`, where `Action` is a plain
  Rust enum (`FIND = 0`, `ENTER = 1`) with no `#[repr(C)]`. A C caller passing
  any other `int` constructs an invalid enum discriminant: instant undefined
  behavior *at the boundary*, before any FrankenLibC code runs. The fix takes
  `action: c_int` and validates through `Action::from_c_int()`, returning
  `EINVAL` / null on anything else. This is the correct pattern for *every*
  enum-typed ABI parameter: a non-`repr(C)` enum must never appear in an
  `extern "C"` signature.

### 5.7 `glob()` drops symlinked directories (`0294e663`)

A core-semantic correctness bug, and the clearest "clean-room blind spot" of the
session. `glob_recursive` in `crates/frankenlibc-core/src/string/glob.rs`
classified directory entries with `std::fs::DirEntry::file_type()`, a method
with `lstat` semantics that *does not follow symlinks*. A symlink pointing at a
directory therefore reported as a plain symlink, so `glob()` never recursed
through it for intermediate pattern components (`dir/symlink_to_dir/*` matched
nothing and returned `GLOB_NOMATCH`), never appended the trailing `/` under
`GLOB_MARK`, and silently excluded it under `GLOB_ONLYDIR`.

The fix (NobleRaven) replaces the three `file_type()` checks with a single
symlink-following `std::fs::metadata()` stat on the constructed path (exactly
what glibc's `glob.c` does), with a broken symlink degrading to "not a
directory." Recursion depth is still bounded by the fixed count of
`/`-components in the pattern, so following symlinks introduces no unbounded
recursion. A `glob_traverses_and_marks_symlinked_directories` regression test
was added.

What makes this article-worthy is its *signature*: a **silent** correctness
failure, with no panic and no error, just missing matches. The behavior was
confirmed against host glibc with a C probe. The pre-existing `glob` test suite
was reasonably thorough (brackets, POSIX classes, escapes, error-callback abort
paths), but every test used real directories and none exercised a symlink.
`DirEntry::file_type()` is a perfectly natural choice that happens to be subtly
wrong, and only a symlink fixture catches it. See §6.3 for the cross-cutting
pattern this shares with §5.6.

---

## 6. Quality Assessment

### 6.1 What is solid

- **The single-chokepoint architecture.** `runtime_policy::decide()` being the
  one door is what makes "the membrane sees every call" a true statement rather
  than an aspiration. The validate-delegate pattern is structurally enforced and
  the ABI crate stays thin.
- **The generational arena.** Turning use-after-free detection into a generation
  compare is elegant and cheap, and §5.1 shows the team takes its soundness
  seriously down to TCB-recycling corner cases.
- **The membrane primitives are verified, not merely tested.** An independent
  fresh-eyes pass over the five hot-path safety files (reviewer: SwiftFox) found
  *no shipped bugs* and a level of engineering worth naming concretely:
  - `bloom.rs`: power-of-two sizing with double hashing (`h2 | 1` forces an odd
    stride → full period, distinct probe positions). Bits are *set-only, never
    cleared*, so the zero-false-negative invariant is **structural**, not just
    test-observed.
  - `fingerprint.rs`: a keyed SipHash-2-4-style PRF over `(addr, size,
    generation)` with a process-local runtime secret, carrying *exhaustive*
    CI proofs: single-bit hash sensitivity, all-256 single-byte canary-
    corruption detection, and "a generation change always changes the hash"
    (the literal UAF-detection mechanism).
  - `tls_cache.rs`: the 1024-entry per-thread validation cache uses a **global
    epoch counter**: any `free` bumps `GLOBAL_TLS_CACHE_EPOCH` (Release), and a
    lookup hits only when `entry.epoch == current_epoch()` (Acquire). One free
    conservatively invalidates *every* thread's cache without per-entry locking;
    stale entries self-clean on the next epoch-mismatch lookup. It is an elegant
    answer to cross-thread cache coherence, though §6.2 records the price that
    coarse global invalidation charges under load.
  - `lattice.rs`: see §2.4; the algebra is exhaustively enumerated over all
    7³ state triples. It is a verified lattice in the literal sense.
  The shared pattern: every layer's "miss" direction is the *safe* direction.
- **Honesty discipline as a feature.** The Claim-Field Contract, the
  `support_matrix.json` source-of-truth, the "trust the machine artifact, not
  the README" troubleshooting entry, and the 258 completion-contract receipts
  are unusual and good. Most projects' READMEs drift optimistic; this one builds
  gates against its own drift.
- **Verification breadth.** 66 fuzz targets, fixture-based differential testing
  against host glibc, per-subcommand CLI contracts under ~50 meta-gates each.
- **Determinism as a design rule.** Hardened-mode repairs are replayable;
  process mode is immutable after startup. These are the invariants that make
  the system analyzable.
- **The swarm self-corrects.** §5.1 and §5.3 show defects being introduced,
  caught by independent review, and fixed, with the soundness follow-up not
  skipped under perf pressure.

### 6.2 What is risky or incomplete

- **The Goodhart problem is real and not yet closed.** WS-0's own framing
  (gates greened against self-regenerated JSON) is the most serious structural
  risk in the project. The Evidence Integrity Kernel is the right fix, but
  `bd-3yr14` is **still open** with red CI gates. Until it lands, *some*
  fraction of the green gates cannot be fully trusted.
- **Runtime-math was dormant.** ~71 control kernels existed as code but did not
  meaningfully drive runtime decisions until the WS-2 wiring work this session.
  A reader of the README's "runtime math is live code" line should weight it
  against the reality that *live* and *loaded into the build* are different
  claims.
- **The top-level proofs are not machine-checked.** This needs the §2.4
  distinction: the *finite* lattice algebra is exhaustively verified and the
  SOS certificates are synthesized and Cholesky-checked at build time, but the
  load-bearing *semantic* theorems (Galois soundness over the unbounded
  C-pointer domain, the end-to-end "membrane repair preserves program meaning"
  argument) live in `docs/proofs/` as proof *notes*, not mechanized artifacts.
  WS-7 (`bd-e4phe`) exists precisely to either discharge or honestly defer
  these; that it is an open workstream is the honest status.
- **L1, not standalone.** `dlfcn`, `iconv`, `locale`, and `nss` are explicitly
  phase-1 / partial. The shipping artifact is an interpose library; glibc is
  still in the deployment. The "100% native coverage" figure is symbol-taxonomy
  ownership, not a standalone-libc claim.
- **Curated smoke battery.** 58/0/6 is real but *curated*: coreutils,
  `python3 -c`, `busybox`. It is evidence of interpose viability, not of
  arbitrary-workload stability.
- **The membrane's fast-path performance story is optimistic for real
  workloads.** Reviewer DarkTrout traced two hot-path optimizations to their
  scaling limits. (1) The 1024-entry per-thread TLS validation cache is gated by
  a *single process-global* epoch counter that `arena.rs` bumps on *every*
  `free()`; a lookup hits only if its entry's epoch still matches. The design is
  correct (it can never return a stale hit), but one thread's `free`
  invalidates *every other thread's entire cache*. In any allocation-heavy or
  multi-threaded workload the cache hit rate trends toward zero, and the
  advertised "~5 ns TLS cache" fast path pays off only in free-quiet windows.
  The per-slot generation counter is already stored in each entry and would be a
  far less coarse invalidation key. (2) The ownership bloom filter is
  insert-only (no clearing, no counting variant), sized for 1M items at a 0.1%
  false-positive rate; a long-running libc consumer performs far more than 1M
  allocations over its lifetime, after which the filter saturates and
  `might_contain()` returns `true` for everything, so the "O(1) reject most
  non-owned pointers" benefit decays to nothing. Neither is a *correctness* bug
  (both fail safe, toward a more expensive lookup), but both mean the headline
  per-stage latency budget describes a cold, lightly-loaded process better than
  a hot one.
- **`glob` has an open correctness bug and a deeper design flaw.** Beyond the
  symlink fix in §5.7, reviewer DarkTrout's pass over
  `crates/frankenlibc-core/src/string/glob.rs` found two more defects, both open
  at the time of writing. (1) `split_pattern` skips the byte after a backslash
  *unconditionally*, ignoring `GLOB_NOESCAPE`, while its sibling `has_magic`
  correctly gates that skip on `!noescape`. Under `GLOB_NOESCAPE` a `\` is a
  literal byte, so a pattern such as `foo\*bar/baz` has its magic component
  folded into the literal directory prefix and `read_dir` is called on it
  literally instead of pattern-matched. The fix is surgical (thread a `noescape`
  flag into `split_pattern`) and was handed to the agent holding the file
  reservation. (2) Structural and bead-worthy: `glob_recursive` concatenates
  `dir_prefix + name + "/" + rest` and *re-splits the whole string from
  scratch*, so a real resolved directory whose name legally contains `*`, `?`,
  or `[` is re-interpreted as a pattern on the next recursion (a real dir `a*b`
  would let a sibling `axxb` wrongly match). A correct fix must carry the
  resolved prefix separately rather than round-tripping it through the splitter.
  Separately, `glob_expand` sorts results in raw byte order where glibc sorts
  via `strcoll`: correct under the C/POSIX locale, a divergence under others.

### 6.3 Notable observations

- The split between offline heavy math and a compact runtime guard is the right
  instinct, but it widens the gap between "what the proofs argue" and "what the
  runtime does." WS-7 (discharge or *honestly defer* proof obligations) is the
  correct response.
- **A recurring shape: the fix, or its test, was incomplete.** Three findings
  this session share one signature. The `strftime` overflow (§5.6) recurred
  because the earlier `bd-7rxtm` fix, and its regression test, covered only part
  of the affected specifier family, and tested only the range extreme where the
  bug does not bite. The C11 constant bug (§5.6) survived because the
  *existing tests encoded the wrong values* and so reinforced it. The `glob`
  symlink bug (§5.7) survived because a reasonably thorough test suite used only
  real directories and never a symlink fixture. The structural lesson for a
  clean-room reimplementation: the project's blind spot is precisely the cases
  its authors did not think to build fixtures for, so an edge-case fix is not
  done until its test enumerates the whole family and both ends of every range.
- **An honest optimization-hint race.** Reviewer SwiftFox flagged that
  `page_oracle.rs`'s `insert()` updates the L2 refcount bitmap *before* the
  `owned_pages` counter's `fetch_add`. A concurrent `query()` reading
  `is_empty()` inside that window sees the stale count, and `owned_pages`
  (`AtomicUsize`) can transiently appear to wrap under unbalanced interleavings.
  It is benign (page registration happens inside `malloc` before the pointer
  escapes to the caller, and the arena lookup downstream is authoritative), but
  it is a real TOCTOU on what is, correctly, only an *optimization hint*. The
  membrane's correctness does not rest on the page oracle, and the design knows
  it; the observation is worth naming precisely rather than smoothing over.
- **A testing-architecture wrinkle.** The ABI modules whose `#[no_mangle]`
  exports would collide with the test harness's own allocator (`malloc_abi`,
  `stdlib_abi`, `string_abi`, `wchar_abi`) are compiled `#[cfg(not(test))]`.
  The consequence (also from SwiftFox) is that those four families are exercised
  *only* through the integration tests under `crates/frankenlibc-abi/tests/`,
  never by in-crate `#[cfg(test)]` unit tests. It is a defensible workaround for
  a genuine symbol-shadowing problem, but it means in-crate unit coverage for
  the ABI crate structurally excludes its highest-traffic surfaces, a fact
  worth knowing when reading a coverage number for that crate.
- Two legacy crates (`frankenlibc`, `frankenlibc_conformance`) linger in the
  workspace for migration compatibility. Minor, but worth a cleanup pass.
- Housekeeping: a stray file literally named `=` sits at the repo root (a
  botched shell redirect, 2026-05-16); harmless, but a small sign that
  artifact hygiene has gaps.

---

## 7. Conclusion: Maturity, Strengths, Gaps

FrankenLibC is **more real than its category usually is, and less finished than
its headline numbers suggest**, and it mostly says so itself.

**Maturity: a credible L1 interpose layer.** The interpose artifact
(`libfrankenlibc_abi.so`) builds, loads under `LD_PRELOAD`, and runs real
binaries (coreutils, `python3 -c`, `busybox`) in both strict and hardened
modes. That is a genuine, demonstrable result. It is not a standalone glibc
replacement and the project does not claim it is; L2/L3 are gated and open.

**Strengths.** The architecture is sound where it counts: one chokepoint, a thin
ABI crate, a generational arena with real temporal-safety teeth, a closed and
deterministic healing taxonomy, and a verification culture (fixtures, fuzzers,
completion contracts) that is well above the norm. The honesty discipline,
especially the Claim-Field Contract and the self-aware WS-0 Goodhart framing, is
the project's most distinctive asset. A project that builds gates against its
own optimism is rare.

**Gaps.** The same honesty makes the gaps easy to name. The evidence pipeline
that underwrites the green gates is itself under repair (WS-0, still open). The
runtime-math control plane was dormant and is only now being wired live (WS-2).
The formal scaffolding is proof *notes*, not mechanized proof. And the perf
story is fresh: the `python3` regression (a 650× cliff) was being fixed *this
session*, with a concurrency-soundness follow-up landing only after independent
review caught it. Independent review also found the membrane's own fast-path
latency budget (the "~5 ns TLS cache", the "O(1) bloom reject") optimistic for
hot, long-running, multi-threaded processes, where the cache invalidates
globally on every `free` and the bloom filter eventually saturates (§6.2).

**The honest one-paragraph verdict.** FrankenLibC has a strong central idea
executed with real architectural discipline, and a verification apparatus most
projects would envy. The risk it carries is not fakery but the gap between an
infrastructure that is *built* and a reality that is *verified*, and the project
is visibly and deliberately spending this session closing that gap. The
right way to evaluate it is the way the project itself recommends: do not trust
the adjectives, run the gates; and after WS-0 lands, trust that the gates can no
longer be gamed. If the Evidence Integrity Kernel ships and stays green
against a deliberately-slowed `memcpy`, FrankenLibC will have earned its
headline numbers. Until then, they are promissory, honestly labeled as such but
promissory.

---

*Draft status: reviewed and copy-edited. All reviewer findings posted to the
`frankenlibc-review-article` Agent Mail thread through 2026-05-21 have been
integrated.*
