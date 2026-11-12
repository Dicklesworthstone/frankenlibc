# Hardened Mode Safety Proof Note & Guarantee Boundary (`bd-34s.1` / `bd-reality-202609-lx578q.8`)

## Evidence Class & Proof-Binder Scope (`PO-02`)
- **Formal status (`tests/conformance/proof_obligations_binder.v1.json`):** `PO-02` (`Hardened Safety Theorem`) and all 24 proof-binder obligations remain **`deferred`** under owner decision `bd-e4phe.1` (`reframe_as_tested_invariant_catalogs`, target mechanization bead `bd-e4phe.2`). No Lean, Coq, Kani, or SMT theorem artifact is committed; missing SMT solvers remain skipped/unproved rather than verified, and no finite unit/fixture/probe corpus constitutes a universal theorem across all symbols, inputs, or thread interleavings.
- **Executable invariant scope in this artifact:** deterministic repair/deny behavior for the declared invalid-input classes in `tests/conformance/hardened_repair_deny_matrix.v1.json`, unit-model temporal/spatial/concurrency invariants in `crates/frankenlibc-membrane/src/ptr_validator.rs`, and contained `strict` vs `hardened` ABI boundary probes in `crates/frankenlibc-abi/tests/hardened_mode_safety_test.rs`.
- **Matrix family coverage today:** `StringMemory`, `WideChar`, `Iconv`, `Poll`, `Locale`, `VirtualMemory`, `Startup`, `Socket`, `Signal`, `Resource`, and `Termios`.

## Invariant Catalog Statement (Declared Domain)
For each covered symbol `s` reaching its membrane-gated hardened route, declared invalid-input class `c`, and input `x` classified as `c` under the preconditions in the boundary matrix below:

`FrankenHardened(s, x) = Decision(c, s)`, where `Decision(c, s)` is fixed to exactly one of:
- `Repair(healing_action)` with deterministic transformed output, or
- `Deny` with deterministic POSIX error result.

For covered valid inputs on those routes, hardened mode remains behavior-compatible with the strict/reference expectation set for the same fixture corpus.

## Membrane Temporal & Spatial Guarantee Boundary Matrix (`bd-reality-202609-lx578q.8`)

`ValidationPipeline::validate(addr: usize)` accepts a flat C virtual address (`usize`), not a fat pointer or caller-carried allocation generation tag (`ptr_validator.rs`, `arena.rs`). Guarantees therefore depend on pointer class, quarantine residence, execution mode (`strict` vs `hardened`), and whether an ABI entrypoint reaches the membrane rather than taking a bypass or direct caller dereference:

| Pointer / Execution Class | Unit-Model Verdict (`ValidationPipeline`) | Deployed `strict` Mode (`FRANKENLIBC_MODE=strict`) | Deployed `hardened` Mode (`FRANKENLIBC_MODE=hardened`) | Guarantee Strength & Explicit Preconditions / Limits |
|---|---|---|---|---|
| **1. Live owned base (`p = malloc(n)`)** | `Validated` / `CachedValid` (`remaining = Some(n)`) | Hot `memcpy`/`memmove`/`strcpy` bypass arena validation; `strlen` bounds segment/fallback scans (`known_remaining`) | `known_remaining(p) == Some(n)`; copy/string writes past `n` clamp (`ClampSize` / `TruncateWithNull`) | **Guaranteed on membrane-gated routes** while allocation remains live and route is not in signal/reentry bypass. |
| **2. Live owned interior (`p + k`, `0 < k < n`)** | `page_oracle` overrides Bloom base-miss -> `arena.lookup` -> `Validated` (`remaining = Some(n - k)`) | Same mode routing as base pointer | `known_remaining(p + k) == Some(n - k)`; writes past `n - k` clamp deterministically | **Guaranteed on membrane-gated routes** for arena/segment/bump/fallback-tracked allocations. |
| **3. Live owned past-end / redzone (`p + n .. p + n + 32`) & metadata corruption** | Stage 7 `BoundsExceeded` (`remaining = Some(0)`); corrupted 24B header (`K_hdr`) or 8B trailing canary (`K_tail`) -> `TemporalViolation` -> `access_abstraction()` `remaining = Some(0)` | Not checked on hot unvalidated copy routes | `known_remaining == Some(0)` (`ClampSize { clamped: 0 }`); warm `TLS_CACHE` checks canary/header on `1-in-16` hits and immediately on near-tail writes (`remaining <= 64` or `write_len >= remaining`); `free(p)` emits `FreedWithCanaryCorruption` JSONL audit | **Guaranteed for deterministic bounds (`p + n` within 32B trailing redzone); conditional ($2^{-64}$ per-tag) for canary/header forgery** assuming 256-bit `getrandom` CSPRNG keys remain unexposed (an arbitrary process-memory read primitive defeats secret-key unpredictability). |
| **4. Allocation size arithmetic overflow (`malloc(SIZE_MAX)`, `SIZE_MAX - k`)** | `AllocationArena::allocate_aligned` uses `checked_add` + `Layout::from_size_align` -> `None` | Returns `NULL` with `errno = ENOMEM` | Returns `NULL` with `errno = ENOMEM` | **Guaranteed** (no integer wrap into undersized allocation). |
| **5. Freed — resident in quarantine (`free(p)` before drain)** | `TemporalViolation(Quarantined)` -> `access_abstraction()` sets `remaining = Some(0)`; `free(p)` -> `DoubleFree` | `free(p)` returns without glibc's tcache abort (tracked divergence `bd-rc0923-epic-eeuy4f.8`); unvalidated copies are not clamped | `free(p)` heals via `IgnoreDoubleFree`; `known_remaining(p) == Some(0)`, clamping gated `memcpy`/`strncpy`/`strcpy` on quarantined block to `0` bytes | **Bounded / Residence-Dependent:** holds while slot stays in shard quarantine (`<= quarantine_controller::current_depth()` per shard and `<= 64 MiB` arena-wide). |
| **6. Freed — drained from quarantine, pre-reuse** | Removed from `addr_to_slot` & `page_oracle` after EBR retirement; `validate(p)` -> `Foreign` (`remaining = None`); `free(p)` -> `ForeignPointer` | Unvalidated / host allocator behavior | `free(p)` heals via `IgnoreForeignFree`; `known_remaining(p) == None` (spatial/temporal history no longer retained) | **Best-Effort / Probabilistic:** once quarantine capacity evicts the entry and EBR reclaims the chunk, only invalid-`free` suppression remains until address reuse. |
| **7. Freed — forced same-address reuse (`p_new = malloc(m)` at `p_new == p_old`)** | Internal stale `CacheEntry` / header generation `G1 != G2` is rejected; raw `validate(p_old as usize)` resolves `p_new` (`generation = G2`, `remaining = Some(m)`) | Sees current allocation `p_new` | Enforces `p_new`'s spatial bound `m` (`memcpy(p_old, src, >m)` clamps to `m`), **but** `p_old` accesses within `[0, m)` and `free(p_old)` alias `p_new` | **Impossible to distinguish stale `p_old` from live `p_new` under unadorned C ABI** (`uintptr_t` carries no caller generation capability); spatial overflow past `m` is still prevented. |
| **8. Foreign pointers (stack, `.data`/`.rodata`, `mmap`, host-owned)** | `Foreign` (`remaining = None`); `free(foreign)` -> `ForeignPointer` | `free(stack)` aborts / delegates; copies run at native speed | `free(foreign)` heals via `IgnoreForeignFree`; copy/string bounds unknown (`None`) | **Guaranteed for `free()` non-ownership check** (for non-reused addresses); **Out-of-Model for stack/`mmap` spatial bounds** without compiler/hardware metadata. |
| **9. `NULL` and unmapped / `PROT_NONE` addresses** | `addr == 0` -> Stage 1 `Null`; non-null unmapped outside owned pages -> `Foreign` without validator dereference | `NULL` / `PROT_NONE` dereference faults (`SIGSEGV`) on non-zero length | `NULL` on gated calls repairs via `ReturnSafeDefault` / `0`-clamp; non-null `PROT_NONE` faults at MMU on non-zero access | **Guaranteed for `NULL` on gated entrypoints; OS MMU-enforced (`SIGSEGV`) for non-null unmapped pages.** |
| **10. Concurrent `free` vs `validate` / ABI access race** | Shard mutexes + EBR `PinnedEpochGuard` + pre-lookup `validation_shard_epochs` prevent validator metadata UAF and invalidate `TLS_CACHE` after `free` | Caller data race is UB per C/POSIX | Validator itself is memory-safe and cache-coherent after `free`, **but** `ValidationOutcome` is a lookup-time snapshot whose EBR guard drops on return | **Lookup-Linearizable Only (Post-Return TOCTOU):** a concurrent `free()` racing between validation return and caller/ABI byte copy is not blocked without external synchronization. |
| **11. Signal-handler / allocator / policy / bootstrap reentry** | `enter_validation_execution_context()` tracks per-thread reentry depth | Bypasses membrane | `in_signal_handler(slot)` (stack-frame watermark set by `signal_abi` trampoline) and reentry guards return `None` bounds on arena blocks | **Intentional Deadlock-Avoidance Bypass (`bd-na6ede`):** async-signal handlers skip arena/page-oracle locks so interrupting `malloc`/`free`/`validate` cannot self-deadlock. |
| **12. Direct caller loads/stores outside `libc` & runtime-math telemetry** | Never enters `ValidationPipeline` | Never enters `libc.so` | Never enters `libc.so`; runtime-math controllers (`SOS`, e-process, `CPOMDP`) tune profiles/cadence | **Out-of-Model:** raw pointer dereferences (`*p = 1`) in application code bypass `LD_PRELOAD` entirely; runtime-math controllers are bounded heuristics/monitors, not formal safety proofs (`bd-reality-202609-lx578q.4`). |

## Determinism Obligations
- Decision identity is stable and auditable via deterministic `policy_id` strings (`tsm.(repair|deny).<family>.<class>.v1`) in `tests/conformance/hardened_repair_deny_matrix.v1.json`.
- Gate enforcement: `scripts/check_hardened_repair_deny_matrix.sh` rejects non-deterministic/duplicate policy IDs, missing class coverage, and drift between matrix `known_healing_actions` and live `HealingAction` variants in `crates/frankenlibc-membrane/src/heal.rs`.
- Integration enforcement: `crates/frankenlibc-harness/tests/hardened_repair_deny_matrix_test.rs` runs the gate in CI/test flow.

## Totality and Safety Mapping
- Every declared invalid-input class in the matrix has at least one entry (totality over the declared set).
- Every matrix entry resolves to a hardened fixture case and a deterministic expected outcome.
- Gate output includes a deterministic canonical policy mapping hash (`summary.policy_mapping_sha256`) so matrix drift is immediately detectable.
- Repair/deny to POSIX-facing outcomes is enumerated in `docs/proofs/repair_posix_mapping.md`.

## Traceability Anchors
- `crates/frankenlibc-membrane/src/heal.rs`
  deterministic healing action vocabulary and global policy counters.
- `crates/frankenlibc-membrane/src/ptr_validator.rs`
  stage-ordered pointer validation, EBR-pinned arena/canary checks, and unit-model temporal/spatial boundary tests.
- `crates/frankenlibc-membrane/src/runtime_math/mod.rs`
  runtime decision + policy ID composition used for action explainability.
- `crates/frankenlibc-abi/src/runtime_policy.rs`
  ABI boundary decision projection and explainability/event recording.
- `crates/frankenlibc-abi/src/malloc_abi.rs`
  `known_remaining` projection (`access_abstraction()`, signal/reentry bypasses, segment/bump/fallback bounds).
- `crates/frankenlibc-abi/tests/hardened_mode_safety_test.rs`
  unit policy-catalog invariants + contained `strict`/`hardened` subprocess boundary probes.
- `tests/conformance/hardened_repair_deny_matrix.v1.json`
  machine-readable invariant catalog for declared `class -> action -> fixture` evidence.
- `scripts/check_hardened_repair_deny_matrix.sh`
  machine gate for matrix validity and deterministic policy identity.

## Evidence Path
- Deterministic matrix: `tests/conformance/hardened_repair_deny_matrix.v1.json`
- Gate script: `scripts/check_hardened_repair_deny_matrix.sh`
- Binder gate: `scripts/check_proof_binder.sh`
- Harness integration test: `crates/frankenlibc-harness/tests/hardened_repair_deny_matrix_test.rs`
- ABI & unit boundary tests: `crates/frankenlibc-abi/tests/hardened_mode_safety_test.rs`, `crates/frankenlibc-membrane/src/ptr_validator.rs`
- Deterministic coverage report: `target/conformance/hardened_repair_deny_matrix.report.json`
- Structured gate log: `target/conformance/hardened_repair_deny_matrix.log.jsonl`
- Fixture corpus: `tests/conformance/fixtures/*.json` (referenced per entry in matrix)
- POSIX mapping companion: `docs/proofs/repair_posix_mapping.md`

## Status
This artifact documents the `bd-34s.1` deterministic repair/deny invariant catalog together with the `bd-reality-202609-lx578q.8` temporal, spatial, concurrency, and C-ABI provenance boundary matrix.
It maintains binder traceability for `PO-02` while preserving `PO-02` (and all 24 binder obligations) as `deferred` under `bd-e4phe.1` / `bd-e4phe.2` until machine-checked formal proofs exist.
