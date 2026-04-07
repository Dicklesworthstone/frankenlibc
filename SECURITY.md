# FrankenLibC Security Model

FrankenLibC is an interpose-first Rust libc that tries to turn memory-unsafe libc boundary interactions into deterministic, auditable outcomes instead of silent corruption. This document describes the security properties the repository is trying to provide today, the mechanisms used to provide them, and the limits of those claims.

## Current Scope

The current shipping artifact is the preload library `target/release/libfrankenlibc_abi.so`. Security claims in this document apply to supported FrankenLibC-managed libc entrypoints running in that interpose model. They do not imply that FrankenLibC is already a full standalone libc replacement.

## Threat Model

### In Scope

| Threat | Why it is in scope |
| --- | --- |
| Invalid pointers passed into libc APIs | The membrane exists specifically to classify and gate unsafe pointer traffic at the ABI boundary. |
| Allocation misuse visible through libc | Double-free, stale frees, foreign frees, and size abuse often surface through allocator-facing libc calls. |
| Boundary-visible buffer misuse | Fingerprints, canaries, bounds metadata, and ownership checks can detect corruption before it compounds. |
| Ambiguous or malformed runtime state at the libc edge | Strict and hardened modes must make deterministic decisions instead of letting undefined behavior propagate. |
| Drift between claimed behavior and actual behavior | The repo treats stale docs, stale gates, and stale evidence as correctness and security problems. |

### Out of Scope

| Threat | Why it is out of scope |
| --- | --- |
| Arbitrary application logic bugs | FrankenLibC is not a whole-program verifier. |
| Kernel vulnerabilities or syscall ABI bugs | Raw-syscall paths still trust kernel behavior. |
| Memory corruption that never crosses a libc path | The membrane only sees calls that pass through FrankenLibC-managed entrypoints. |
| Microarchitectural side channels | Timing, cache, and speculative-execution hardening are not a core guarantee today. |
| Full standalone replacement security claims | The replace artifact remains a future milestone. |

### Attacker Model

FrankenLibC assumes buggy or adversarial callers may:

- pass null, dangling, foreign, or out-of-bounds pointers
- repeat frees, misuse realloc-family APIs, or hand libc inconsistent sizes
- trigger malformed mode or state transitions across string, malloc, stdio, locale, resolver, and related families

FrankenLibC does not assume the kernel, CPU, or the entire application is maliciously contained by the library.

## Runtime Modes

| Mode | Goal | Security posture |
| --- | --- | --- |
| `strict` | Compatibility-first behavior | Preserve ABI-compatible behavior for supported paths and avoid repair rewrites. |
| `hardened` | Safety-first behavior | Validate, repair, or deny invalid patterns instead of allowing undefined behavior to proceed. |

Mode selection is process-wide and immutable after initialization via `FRANKENLIBC_MODE=strict|hardened`.

## Safety Guarantees

These guarantees are strongest for membrane-managed allocations and supported ABI families.

| Guarantee | Mechanism | Bound / property |
| --- | --- | --- |
| Temporal safety on managed allocations | Generational arena plus quarantine queue | Same-slot use-after-free detection is intended to be exact via generation mismatch. |
| Spatial integrity on managed allocations | SipHash-derived fingerprint header plus trailing canary | Undetected corruption probability is bounded by the stated collision bound, `<= 2^-64`. |
| Safety-state monotonicity | Safety lattice in `crates/frankenlibc-membrane/src/lattice.rs` | Join is commutative, associative, and idempotent; new negative evidence only moves toward more restrictive states. |
| Sound C-to-safe projection | Galois connection in `crates/frankenlibc-membrane/src/galois.rs` | `gamma(alpha(c)) >= c` for correct C behavior. |
| Deterministic invalid-input handling in hardened mode | Policy-driven repair or deny decisions | Covered families map invalid classes to fixed repair actions or deterministic error returns. |
| Auditability | Metrics, structured logs, and evidence artifacts | Every repair or denial path is expected to emit machine-readable evidence. |

### Pointer Validation Pipeline

The membrane validation path is ordered to reject or classify obviously unsafe inputs quickly:

1. null check
2. TLS cache probe
3. bloom-filter ownership precheck
4. arena lookup
5. fingerprint verification
6. canary verification
7. bounds validation

Fast exits are part of both the performance model and the security model: the library should reject or classify invalid inputs before unsafe state is used downstream.

## Healing Actions

The current explicit healing vocabulary lives in `crates/frankenlibc-membrane/src/heal.rs`.

| Healing action | Typical trigger | Hardened-mode result | Tradeoff |
| --- | --- | --- | --- |
| `ClampSize` | Oversized or inconsistent length/size inputs | Reduces the requested size to a safe bound | Prevents overflow at the cost of truncating the caller's request |
| `TruncateWithNull` | String operations that need bounded safe output | Produces a shortened, explicitly terminated result | Preserves memory safety but may lose trailing data |
| `IgnoreDoubleFree` | Repeated free of the same managed allocation | Converts repeat free into a counted no-op | Avoids heap corruption but hides a caller bug behind evidence |
| `IgnoreForeignFree` | Free against memory not owned by FrankenLibC | Rejects ownership transfer and returns safely | Prevents allocator corruption but does not fix the caller |
| `ReallocAsMalloc` | Realloc-family misuse that cannot safely preserve the old object | Treats the operation as a fresh allocation | Preserves progress with different allocation semantics |
| `ReturnSafeDefault` | Invalid input where safe continuation is still possible | Returns a deterministic safe fallback value | Favors containment over caller intent |
| `UpgradeToSafeVariant` | API family has a safer bounded variant available | Routes to the safer implementation contract | May change the internal execution path to preserve safety |

### Quarantine Behavior

Quarantine is a core temporal-safety mechanism even though it is not a standalone `HealingAction` variant. Freed managed allocations move through quarantine before reuse so that stale references are more likely to fail validation before memory is recycled.

## Audit Trail and Evidence

Security decisions are supposed to be observable, not implicit.

### Evidence Surfaces

- `crates/frankenlibc-membrane/src/metrics.rs`
  Atomic counters for validations, cache behavior, and healing activity.
- `crates/frankenlibc-membrane/src/evidence_ledger.rs`
  Structured evidence retention surface for security-relevant records.
- `crates/frankenlibc-membrane/src/runtime_math/evidence.rs`
  Deterministic decision/evidence record encoding for runtime decision paths.
- `tests/conformance/hardened_repair_deny_matrix.v1.json`
  Machine-readable mapping from invalid-input classes to deterministic hardened outcomes.
- `tests/cve_arena/results/paired_mode_evidence.v1.json`
  Paired strict vs hardened evidence for adversarial security scenarios.

### Expected Structured Fields

Security-relevant runs are expected to log:

- `trace_id`
- `mode`
- `api_family`
- `symbol`
- `decision_path`
- `healing_action`
- `errno`
- `latency_ns`
- `artifact_refs`

### Operator Verification Path

Useful commands for checking the current security posture:

```bash
bash scripts/check_structured_logs.sh
bash scripts/check_cve_paired_mode_runner.sh
cargo run -p frankenlibc-harness --bin harness -- verify-membrane --mode both --output /tmp/healing.json
```

## Formal Properties

The project explicitly claims the following mathematical or construction-level properties for the membrane design:

- Safety-state joins are commutative, associative, and idempotent.
- Safety classification only becomes more restrictive when new negative evidence appears.
- `gamma(alpha(c)) >= c` is the intended soundness relation between flat C behavior and the richer membrane model.
- Managed-allocation integrity relies on fingerprint and canary verification with the documented `2^-64` collision-style bound.
- Generation counters are intended to make same-slot stale-reference detection exact for managed allocations.
- Healing policy coverage is intended to be machine-checkable rather than left to ad hoc fallback code.

These are design and implementation claims tied to specific modules and gates. They are not a claim that every theorem has already been independently machine-proven across the entire libc surface.

## Limitations

FrankenLibC improves security at the libc boundary, but it does not remove the need for precise scoping.

- It cannot repair corruption that occurs entirely outside FrankenLibC-managed entrypoints.
- It does not make arbitrary application code memory-safe.
- It still depends on kernel behavior for raw-syscall-backed operations.
- It does not currently claim side-channel resistance.
- Performance budgets such as `<20ns` strict and `<200ns` hardened are engineering targets, not a universal guarantee on every host and workload.
- The current production surface is still interpose-first; full standalone replacement remains unfinished.
- Some proof and evidence surfaces are stronger than others. The documented guarantees should be read together with the active gates and artifacts, not as a promise that every possible libc path already has complete closure evidence.

## Security Posture Summary

FrankenLibC's security model is: classify unsafe boundary traffic early, refuse to trust raw pointers blindly, preserve compatibility in `strict`, contain damage in `hardened`, and emit enough evidence that repairs and denials can be audited after the fact. The strongest current guarantees are at the membrane boundary for managed allocations and supported hardened invalid-input classes. Everything outside that envelope is explicitly out of scope until the implementation and gates say otherwise.
