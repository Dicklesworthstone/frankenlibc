# SOS Barrier Certificates (Design)

Goal: replace ad-hoc predicate checks in `barrier.rs` with formally certified polynomial
barriers derived from Sum-of-Squares (SOS) decomposition. Heavy SOS/SDP work runs offline;
runtime evaluates cheap polynomial forms with pre-computed coefficients.

This is a *design-only* document for bead `bd-2pw`. Implementation is `bd-19r` (runtime
polynomial evaluator) + integration `bd-19h` (integrate into barrier/admissibility).

## Background: What Barrier Certificates Prove

A **barrier certificate** B(x) for a dynamical system certifies that trajectories starting
in an initial set X₀ never reach an unsafe set X_u. Formally (Prajna & Jadbabaie 2004):

1. B(x) ≥ 0 for all x ∈ X₀         (initially non-negative)
2. B(x) < 0 for all x ∈ X_u         (negative in unsafe states)
3. dB/dt ≥ 0 along system dynamics   (non-decreasing along trajectories)

If we can find such a B, safety is proven without enumerating trajectories.

The SOS program: find B(x) = Σᵢ qᵢ(x)² (sum of squares) satisfying (1-3). This reduces
to a semidefinite program (SDP) solvable by MOSEK/SCS/DSOS offline. Once solved, the
certificate is a set of polynomial coefficients that runtime evaluates in O(d²) time.

## Why This Matters for the Membrane

The current `barrier.rs` uses hand-written predicate logic:
- `requested_bytes > max_request_bytes → inadmissible`
- `is_write && risk > repair_trigger && profile == Fast → inadmissible`

These predicates are correct but fragile: they miss nonlinear interactions between state
variables, and they cannot be formally verified against the full system dynamics. SOS
barrier certificates provide:

1. **Formal safety proofs**: offline SDP proves the certificate is valid.
2. **Nonlinear coverage**: polynomial barriers capture quadratic/cubic interactions.
3. **Cheap runtime**: evaluation is a single quadratic/cubic form (O(d²) multiply-adds).
4. **Versioned artifacts**: certificates are immutable data; new certificates require
   new offline proof, preventing silent drift.

## Concrete Invariants

We start with two invariants tied to the most critical legacy failure surfaces.

### Invariant A: Quarantine Depth Safety Envelope

**Legacy anchor**: `malloc`/`nptl` — UAF detection depends on quarantine depth holding
freed blocks long enough for stale accesses to be caught. Too shallow → missed UAF.
Too deep → memory waste and latency blowup under contention.

**State vector** (4 variables, all observable at runtime):

```
x_A = (d, c, a, λ)

d = normalized quarantine depth        ∈ [0, 1]   (= (depth - MIN) / (MAX - MIN))
c = normalized contention level        ∈ [0, 1]   (= peak_concurrent / max_threads)
a = adverse event rate (ppm / 1e6)     ∈ [0, 1]   (= adverse_events / total_calls)
λ = latency dual variable (normalized) ∈ [-1, 1]  (= lambda_latency / lambda_max)
```

Normalization to [0,1] or [-1,1] ensures polynomial coefficients have bounded magnitude
and the Gram matrix condition number stays reasonable for the SDP solver.

**Safe set S_A**: the region where quarantine depth provides sufficient UAF detection
while staying within the latency budget. Formally:

```
S_A = { x : d ≥ d_min(c, a)  AND  d ≤ d_max(c, λ) }
```

where:
- `d_min(c, a)` increases with adverse rate (more UAF → deeper quarantine needed)
- `d_max(c, λ)` decreases with contention and latency pressure

**Barrier polynomial** (degree 3, 4 variables):

```
B_A(x) = d(1-d)                           # interior: depth within [0,1] bounds
        - α₁ · a · (1-d)²                 # penalty: high adverse rate + shallow depth
        - α₂ · c² · d                     # penalty: high contention + deep depth
        + α₃ · (1-d) · (1-c) · (1-a)      # reward: low contention + low adverse + room
        - α₄ · λ · d · c                  # penalty: latency pressure + deep + contention
```

This is a degree-3 polynomial in 4 variables. The monomial basis z(x) for degree ≤ 3
has `binomial(4+3, 3) = 35` terms. The Gram matrix Q is at most 35×35 = 1225 entries
(630 unique for upper triangle).

In practice, we restrict to the **DSOS/SDSOS relaxation** (Ahmadi & Majumdar 2019):
instead of full SDP (expensive offline), use LP/SOCP relaxation that produces
diagonally-dominant certificates. This is sufficient for our low-degree, low-variable
setting and the resulting certificates are often sparser.

**Offline SDP problem**:

```
find  Q ≽ 0,  α₁, α₂, α₃, α₄ ≥ 0
such that  B_A(x) = z(x)ᵀ Q z(x)    (SOS decomposition)
           B_A(x₀) ≥ 0               for x₀ ∈ X₀ (initial operating region)
           B_A(x_u) < 0              for x_u ∈ X_u (unsafe corners)
           ∂B_A/∂t ≥ 0              along controller dynamics
```

Unsafe corners X_u include:
- `d ≈ 0, a > 0.01` (shallow quarantine under active UAF)
- `d ≈ 1, c > 0.5`  (deep quarantine under heavy contention)
- `a > 0.1, d < 0.3` (high adverse + insufficient depth)

**Runtime evaluation cost**: For the 4-variable degree-3 case with DSOS sparsity, expect
~50-100 multiply-adds. At ~1ns/fma: **50-100ns**, acceptable for cadence-gated evaluation
(every 256 calls via the quarantine controller epoch).

**Runtime rule**:
- If B_A(x) ≥ 0: current quarantine depth is within the certified safe envelope.
- If B_A(x) < 0: escalate — force quarantine depth adjustment + FullValidate.

### Invariant B: Pointer Provenance Admissibility

**Legacy anchor**: `elf`/`dl-*` loader + `malloc` arena — a stale or forged pointer
passing validation is the most dangerous membrane failure. The membrane's validation
pipeline (bloom → arena → fingerprint → canary) has complementary error modes.

**State vector** (4 variables):

```
x_B = (r, v, b, p)

r = risk upper bound (ppm / 1e6)      ∈ [0, 1]   (= risk_upper_bound_ppm / 1e6)
v = validation depth level             ∈ {0, 1}   (0 = Fast, 1 = Full)
b = bloom false-positive rate          ∈ [0, 1]   (= bloom_fp / bloom_queries, EWMA)
p = arena pressure (normalized)        ∈ [0, 1]   (= arena_used / arena_capacity)
```

**Safe set S_B**: the region where the combined probability of a forged/stale pointer
escaping undetected is below the safety budget ε = 2⁻⁶⁴.

The pipeline's detection probability depends on:
- Bloom filter: catches ~(1-b) of non-arena pointers (b = FP rate).
- Arena lookup: catches all arena pointers (infallible).
- Fingerprint + canary: catches corrupted arena pointers (P(miss) ≤ 2⁻⁶⁴).

The dangerous case is: high risk + fast validation + high bloom FP + high arena pressure
(many allocations → more false positive bloom hits → more work skipped on fast path).

**Barrier polynomial** (degree 2, 4 variables):

```
B_B(x) = (R_budget - r)                       # risk headroom
        - β₁ · r · (1-v) · b                  # penalty: risk × fast-path × bloom FP
        - β₂ · r · p · (1-v)                  # penalty: risk × pressure × fast-path
        + β₃ · v · (1-b)                      # reward: full validation + good bloom
```

This is degree 3 due to the triple products, but can be expressed as degree 2 in
lifted variables {r, v, b, p, rv, rb, rp, vb} with 8-variable degree-2 Gram matrix.
Alternatively, keep as degree 3 with 4 variables (35-term monomial basis).

**Offline SDP**: find β₁, β₂, β₃ and Gram matrix Q such that B_B is SOS and:
- B_B ≥ 0 in the safe operating region (low risk, adequate validation)
- B_B < 0 when risk exceeds budget without sufficient validation

**Runtime rule**:
- If B_B(x) ≥ 0: current validation profile is adequate for the risk level.
- If B_B(x) < 0: escalate from Fast → Full validation (override bandit/pareto).

**Runtime cost**: 4-variable degree-2 quadratic form: ~20-30 multiply-adds → **<30ns**.
This is cheap enough for the hot-path decide() function (not cadence-gated).

## Artifact Format

Each barrier certificate is a self-contained, versioned, deterministic data artifact.

```rust
/// A pre-computed SOS barrier certificate for runtime evaluation.
///
/// Produced offline by SDP solver; consumed at runtime by polynomial evaluator.
/// Immutable after creation — any change requires a new certificate with new proof.
pub struct BarrierCertificate {
    /// Schema version (monotonically increasing).
    pub version: u32,

    /// Human-readable identifier (e.g., "quarantine_depth_safety_v1").
    pub name: &'static str,

    /// Legacy anchor: which glibc subsystem this protects.
    pub legacy_anchor: &'static str,

    /// Indices into the runtime state vector for each variable.
    /// Length = num_variables.
    pub state_indices: &'static [StateVariable],

    /// Number of variables in the polynomial (d).
    pub num_variables: u8,

    /// Maximum degree of the polynomial.
    pub degree: u8,

    /// Monomial basis: each entry is a vector of exponents.
    /// Length = |z| = binomial(num_variables + degree, degree).
    /// Entry i corresponds to monomial x₁^e₁ · x₂^e₂ · ... · x_d^e_d.
    pub monomial_exponents: &'static [[u8; MAX_VARS]],

    /// Gram matrix Q (upper-triangular packed, row-major).
    /// Length = |z| * (|z| + 1) / 2.
    /// The barrier value is: B(x) = z(x)ᵀ Q z(x).
    pub gram_upper: &'static [f64],

    /// Normalization: per-variable (offset, scale) to map raw state to [0,1] or [-1,1].
    /// raw_value → (raw_value - offset) / scale
    pub normalization: &'static [(f64, f64)],

    /// Threshold: B(x) < threshold → violation (typically threshold = 0.0).
    pub threshold: f64,

    /// SHA-256 hash of the offline proof artifact (SDP solution + verification log).
    pub proof_hash: [u8; 32],

    /// Whether this certificate is used on the hot path (decide) or cadence path (observe).
    pub evaluation_cadence: EvaluationCadence,
}

/// Where the state variable comes from at runtime.
pub enum StateVariable {
    /// From RuntimeContext fields.
    Context(ContextField),
    /// From cached controller state (AtomicU8/U32 in RuntimeMathKernel).
    CachedState(CachedStateField),
    /// From quarantine controller observables.
    QuarantineController(QuarantineField),
    /// From PrimalDualController.
    ControlLimits(ControlField),
}

/// When to evaluate this certificate.
pub enum EvaluationCadence {
    /// Evaluate on every decide() call — must be < 30ns.
    HotPath,
    /// Evaluate on cadence (every N calls) — up to 200ns acceptable.
    Cadenced { interval: u32 },
}
```

### Key Design Decisions

**1. Static data, not dynamic.**
Certificates are `&'static` const data compiled into the binary, not loaded from files.
This eliminates file I/O on the hot path and makes tampering impossible. New certificates
require a recompile (by design — certificates are formal proofs, not config).

**2. Normalized variables.**
All state variables are normalized to [0,1] or [-1,1] before polynomial evaluation.
This keeps Gram matrix entries bounded (condition number ~O(1)) and makes the fixed-point
conversion straightforward when we move to integer arithmetic (bd-gn9).

**3. Evaluation cadence.**
Invariant B (pointer provenance) is hot-path — it runs on every decide() and must be
< 30ns. Invariant A (quarantine depth) is cadence-gated — it runs every 256 frees and
can take up to 200ns.

**4. Proof hash.**
Each certificate carries the SHA-256 of its offline proof. The runtime verifier checks
this hash at init time against a compiled-in expected hash. If mismatched, the certificate
is disabled and the system falls back to predicate-based checks (existing barrier.rs).
This is defense-in-depth: even if the binary is patched, the proof must be valid.

## Runtime Evaluation (Pseudocode)

```rust
fn evaluate_barrier(cert: &BarrierCertificate, state: &[f64]) -> f64 {
    let n = cert.monomial_exponents.len();
    // Build monomial vector z(x).
    let mut z = vec![0.0f64; n]; // stack-allocated for n ≤ 35
    for (k, exponents) in cert.monomial_exponents.iter().enumerate() {
        let mut term = 1.0;
        for (i, &exp) in exponents.iter().take(cert.num_variables as usize).enumerate() {
            // Normalize state variable.
            let (offset, scale) = cert.normalization[i];
            let xi = (state[i] - offset) / scale;
            for _ in 0..exp {
                term *= xi;
            }
        }
        z[k] = term;
    }

    // Evaluate quadratic form z(x)ᵀ Q z(x).
    let mut result = 0.0;
    let mut idx = 0;
    for i in 0..n {
        for j in i..n {
            let qij = cert.gram_upper[idx];
            if i == j {
                result += qij * z[i] * z[j];
            } else {
                result += 2.0 * qij * z[i] * z[j];
            }
            idx += 1;
        }
    }

    result
}
```

**Hot-path optimization** (for Invariant B):
- Pre-expand the polynomial into explicit coefficient form (skip monomial vector).
- Use fixed-point milli-units (from bd-gn9) to avoid f64 entirely.
- Example for a 4-variable degree-2 form with 10 unique monomials:

```rust
fn evaluate_provenance_barrier_fast(r: u32, v: u32, b: u32, p: u32) -> i64 {
    // All inputs in ppm (0..1_000_000). Output in ppm.
    // Pre-expanded polynomial: sum of coefficient * monomial.
    let r2 = (r as i64 * r as i64) / 1_000_000;
    let rb = (r as i64 * b as i64) / 1_000_000;
    let rp = (r as i64 * p as i64) / 1_000_000;
    let rv = (r as i64 * v as i64) / 1_000_000;
    let vb = (v as i64 * b as i64) / 1_000_000;

    // Coefficients from offline SDP (example, to be tuned):
    let budget_ppm: i64 = 100_000; // R_budget = 0.1
    (budget_ppm - r as i64)
        - (BETA_1 * rb * (1_000_000 - v as i64)) / 1_000_000_000_000
        - (BETA_2 * rp * (1_000_000 - v as i64)) / 1_000_000_000_000
        + (BETA_3 * vb) / 1_000_000
}
```

~10 multiplications + additions = **<15ns** on modern x86_64.

## Integration Plan

### Phase 1: Invariant B on hot path (bd-19r)

1. Define `BarrierCertificate` struct (simplified: explicit coefficients, not Gram matrix).
2. Implement `evaluate_provenance_barrier_fast()` in fixed-point.
3. Wire into `BarrierOracle::admissible()` as an additional check:
   - If B_B(x) < 0: return `false` (inadmissible — force Full validation).
4. Add unit tests for safe/unsafe corners.

### Phase 2: Invariant A on cadence path (bd-19r)

1. Define quarantine safety certificate with Gram matrix evaluation.
2. Wire into `QuarantineController` epoch update:
   - If B_A(x) < 0: force depth adjustment + emit evidence.
3. Add unit tests for depth/contention/adverse corners.

### Phase 3: Artifact pipeline (future)

1. Script that runs offline SDP solver (MOSEK/SCS via Python) on invariant specs.
2. Outputs Rust `const` data (Gram matrix + normalization + proof hash).
3. CI verifies proof hash and runs certificate evaluation on test vectors.

## Complexity / Overhead Notes

- Invariant B (hot path): ~10 multiply-adds → <15ns (well within strict 20ns budget).
- Invariant A (cadence): ~100 multiply-adds → ~100ns (within 200ns hardened budget).
- No heap allocations. All data is `&'static`.
- No floating-point on strict hot path (Invariant B uses fixed-point ppm arithmetic).
- Gram matrix for Invariant A: 630 f64 entries = 5KB (fits in L1 cache).

## Invariants (Must Hold)

1. **Certificate immutability**: once compiled, certificate data never changes at runtime.
2. **Proof hash verification**: init-time check; mismatch → fallback to predicate barrier.
3. **Normalization bounds**: all raw state values must map to the expected normalized range.
   Out-of-range values are clamped before evaluation (defensive, not a safety hole since
   clamping moves toward the interior of the safe set).
4. **Monotone escalation**: barrier violation can only INCREASE the validation level
   (Fast → Full, Allow → FullValidate). It never de-escalates.
5. **Fallback safety**: if certificate evaluation fails (NaN, overflow), treat as violation
   and escalate. This ensures the certificate is strictly additive safety — removing it
   returns to the existing predicate-based barrier behavior.

## Open Questions (Resolve During Implementation)

1. Whether to use DSOS/SDSOS relaxation (LP/SOCP) vs full SOS (SDP) for the offline step.
   DSOS is faster and produces sparser certificates but may miss valid certificates that
   full SOS would find. For our low-degree setting, DSOS is likely sufficient.

2. Whether Invariant A's degree-3 polynomial justifies the 35-term monomial basis, or
   whether a degree-2 approximation (15 terms) provides adequate safety coverage.
   Will resolve with test vectors from quarantine_controller conformance runs.

3. Whether to add a third invariant for bootstrap ordering (csu/TLS init). This requires
   observing init-sequence state variables that may not yet be exposed. Defer to bd-19h
   integration phase.

4. Whether the proof hash should be checked at init only, or periodically (every N
   evaluations). Periodic checking adds ~50ns but provides runtime tamper detection.

## References

- Prajna, S. & Jadbabaie, A. (2004). "Safety Verification of Hybrid Systems Using
  Barrier Certificates." HSCC 2004.
- Ahmadi, A.A. & Majumdar, A. (2019). "DSOS and SDSOS Optimization: More Tractable
  Alternatives to Sum of Squares and Semidefinite Optimization." SIAM J. Applied
  Algebra and Geometry.
- Parrilo, P.A. (2003). "Semidefinite Programming Relaxations for Semialgebraic
  Problems." Mathematical Programming.
- Jarvis-Wloszek, Z. et al. (2003). "Some Controls Applications of Sum of Squares
  Programming." CDC 2003.
