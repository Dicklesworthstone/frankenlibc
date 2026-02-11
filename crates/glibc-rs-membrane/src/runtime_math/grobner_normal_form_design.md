# Groebner Normal Form for Violation Signatures (Design)

Bead: `bd-1hq`

Status: Draft (2026-02-10)

## Context

The runtime emits many overlapping anomaly signals:
- membrane-side anomalies (invalid pointers, canary/fingerprint failures, repair actions),
- runtime_math controller states (risk, cvar, changepoint, cohomology, etc),
- budget/regime probes (tropical latency phase, spectral transitions, rough-path signatures).

These signals are intentionally redundant (multiple detectors for the same failure class),
but that redundancy creates two concrete problems:
1. **Double counting / drift**: the same underlying root-cause can appear under many surface
   combinations (order-dependent, module-dependent).
2. **Sparse recovery pollution**: correlated features make latent-cause inference less stable
   (more diffuse supports, less consistent attribution).

We want a deterministic, versioned way to canonicalize a raw set of anomaly flags into a
stable **root-cause signature ID** suitable for:
- evidence payload tagging,
- offline clustering / attribution,
- regression tracking ("same bug class again").

Hard constraints:
- no heavy algebra at runtime,
- no allocations on the hot path,
- deterministic output (same inputs -> same ID),
- explicit versioning and hash of the normalization policy.

## Goal

Define:
1. A concrete raw signature schema (small integer features derived from cached states).
2. A Groebner-basis-based reduction story that yields a unique normal form (canonical
   representative) for signatures modulo known equivalences/redundancies.
3. A runtime artifact format (basis + reduction table) and an output ID format.

This document is design-only. Implementation is expected in beads `bd-c0o` (reduction table
engine) and `bd-380`/`bd-3ld` (integration + tests/perf).

## Signature Schema (Raw)

We model a single "violation event" (or observation window) as a sparse set of boolean
atoms. Each atom is derived from an existing cached controller state or membrane result by
thresholding into 0/1.

### Source: `RuntimeMathKernel` cached states

The runtime already builds a 25-element `base_severity` vector (see
`crates/glibc-rs-membrane/src/runtime_math/mod.rs`). We define one boolean atom per entry:

Rule: `atom_i := base_severity[i] >= 2` ("warning-or-worse") unless otherwise noted.

Atom inventory (v1):
- `A00_SPECTRAL`: spectral phase is Transitioning/NewRegime (`>= 1` is enough; phase is 0..2).
- `A01_ROUGHPATH`: rough-path signature state is Anomalous (`== 2`).
- `A02_PERSISTENCE`: persistent-homology state is Anomalous (`== 2`).
- `A03_ANYTIME`: e-process state is Warning/Alarm (`>= 2`, per-family).
- `A04_CVAR`: CVaR state is Warning/Alarm (`>= 2`, per-family).
- `A05_BRIDGE`: Schrodinger-bridge state is Transitioning (`== 2`).
- `A06_LD`: large-deviations state is Elevated/Critical (`>= 2`, per-family).
- `A07_HJI`: HJI reachability is Approaching/Breached (`>= 2`).
- `A08_MFG`: mean-field game is Congested/Collapsed (`>= 2`).
- `A09_PADIC`: p-adic monitor is Drift/Exceptional (`>= 2`).
- `A10_SYMPLECTIC`: symplectic reduction is Warning/Alarm (`>= 2`).
- `A11_SPARSE`: sparse recovery is Focused/Diffuse/Critical (`>= 2` in its ordinal encoding).
- `A12_EQUIVARIANT`: equivariant drift is Warning/Alarm (`>= 2`).
- `A13_TOPOS`: higher-topos controller is DescentFailure/StackificationFault (`>= 2`).
- `A14_AUDIT`: commitment audit is Warning/Alarm (`>= 2`).
- `A15_CHANGEPOINT`: changepoint state is Warning/Alarm (`>= 2`).
- `A16_CONFORMAL`: conformal controller is Warning/Alarm (`>= 2`).
- `A17_LOSS`: loss minimizer is Warning/Critical (`>= 2` in its ordinal encoding).
- `A18_COUPLING`: coupling controller is Warning/Critical (`>= 2` in its ordinal encoding).
- `A19_MICROLOCAL`: microlocal controller is Warning/Alarm (`>= 2`).
- `A20_SERRE`: Serre spectral controller is Warning/Alarm (`>= 2`).
- `A21_CLIFFORD`: Clifford controller is Warning/Alarm (`>= 2`).
- `A22_KTHEORY`: K-theory controller is Warning/Alarm (`>= 2`).
- `A23_COVERING`: covering-array controller is Warning/Alarm (`>= 2`).
- `A24_TSTRUCTURE`: t-structure controller is Warning/Alarm (`>= 2`).

Notes:
- This schema is intentionally derived from existing cached states; it is not an invitation
  to add new per-call computation.
- If future controllers add cached states, they must extend this schema in a versioned way.

### Optional: membrane-side atoms (out of scope for v1)

In a later version, include atoms derived from:
- `ValidationOutcome` classes (TemporalViolation / Foreign / Null),
- canary/fingerprint failure counters,
- healing actions taken.

That extension can reuse the same normal-form machinery.

## What the Normal Form Represents

The raw atom set is intentionally redundant. The **normal form** should represent:

1. A *minimal* set of "root-cause class" atoms explaining the observed atoms, and
2. A stable residual set for non-explainable/novel combinations.

The key property we need is **confluence**:
- the order we apply reductions must not matter,
- the same raw atom set always reduces to the same canonical representative.

This is exactly what Groebner-basis normal forms provide: given an ideal of relations, the
remainder (normal form) is unique under a fixed term order.

## Algebraic Model (Boolean Ring)

For runtime simplicity, v1 uses a boolean polynomial ring:

- Base field: GF(2)
- Variables: one per atom (and optionally some root-cause variables; see below)
- Boolean constraints: for each variable x, enforce x^2 - x = 0 (idempotence)

A raw signature is represented as a monomial (product) of all fired atoms:

    m_raw = Π_{i in Fired} x_i

We then reduce `m_raw` modulo the ideal `I` generated by:
- boolean constraints (x_i^2 - x_i),
- equivalence/redundancy relations (below).

The reduced remainder is the **canonical signature**.

Why a monomial (not a sum)?
- We want a *set-like* object: which atoms are present.
- In the boolean ring, monomial reduction corresponds to applying rewrite rules on sets.

## Relations (Ideal Generators)

We encode two kinds of relations:

### 1) Equivalence (same failure class, multiple detectors)

If two atoms represent the same semantic root-cause, we equate them:

    x_a - x_b = 0   (over GF(2), this is x_a + x_b = 0)

With a suitable term order, the normal form will keep only the preferred representative.

### 2) Redundancy (implication / derived signals)

If an atom is strictly derived from another (by construction), the derived atom is redundant
when the parent is present. Encode:

    x_parent * x_derived - x_parent = 0

This reduces `x_parent * x_derived` to `x_parent`, dropping the derived flag.

Important:
- v1 should only include redundancy relations that are true *by design*, not by correlation.
- Correlation-only reductions belong in probabilistic tooling, not in a canonicalizer.

## Root-Cause Class Layer (Recommended)

To make outputs stable and useful, introduce a small set of root-cause variables aligned
with the sparse latent-cause taxonomy in `runtime_math/sparse.rs`:

- `C0_TEMPORAL`        (temporal/provenance / lifetime integrity)
- `C1_TAIL_LATENCY`    (tail latency / congestion / heavy-tail regimes)
- `C2_TOPOLOGY`        (topological/path-complexity / structural drift)
- `C3_REGIME_SHIFT`    (policy/workload regime transitions)
- `C4_NUMERIC`         (floating-point exceptional regimes)
- `C5_ADMISSIBILITY`   (resource/IPC/ABI admissibility failures)

Then add *mapping* relations from observed atoms to classes.
Example (illustrative, not exhaustive):

- Regime shift detectors:
  - `A00_SPECTRAL  -> C3_REGIME_SHIFT`
  - `A05_BRIDGE    -> C3_REGIME_SHIFT`
  - `A15_CHANGEPOINT -> C3_REGIME_SHIFT`
- Topology/structure detectors:
  - `A01_ROUGHPATH -> C2_TOPOLOGY`
  - `A02_PERSISTENCE -> C2_TOPOLOGY`
  - `A19_MICROLOCAL -> C2_TOPOLOGY`
- Tail-latency/congestion detectors:
  - `A04_CVAR -> C1_TAIL_LATENCY`
  - `A06_LD   -> C1_TAIL_LATENCY`
  - `A08_MFG  -> C1_TAIL_LATENCY`
- Numeric:
  - `A09_PADIC -> C4_NUMERIC`
- Admissibility:
  - `A07_HJI -> C5_ADMISSIBILITY`
  - `A10_SYMPLECTIC -> C5_ADMISSIBILITY`
  - `A20_SERRE, A22_KTHEORY, A24_TSTRUCTURE -> C5_ADMISSIBILITY`
- Temporal/provenance:
  - `A14_AUDIT -> C0_TEMPORAL`

In the polynomial system, a mapping `A -> C` is encoded as:

    x_A - x_C = 0

and we choose a monomial ordering that prefers class variables in the remainder. This makes
the normal form a compact cause-set rather than a long detector list.

## Term Order

We need a fixed term order to ensure uniqueness and to choose preferred representatives.

Recommended v1 ordering:
1. Root-cause class variables `C*` are "smaller" (preferred to remain).
2. Observed detector atoms `A*` are "larger" (prefer to eliminate).
3. Within observed atoms, prefer to eliminate the most-derived ones first (optional).

In practice, this means: class variables appear earlier in lex order (or have lower weight)
so reductions rewrite observed atoms into classes.

## Offline Artifact (Basis + Reduction Table)

Runtime must not compute Groebner bases. We ship an offline-built artifact:

`grobner_signature_policy.v1.bin` (exact format TBD in `bd-c0o`), containing:
- `version` (u16)
- `schema_hash` (u64): hash of the variable inventory and thresholds (atom definitions)
- `basis_hash` (u64): hash of the Groebner basis generators (for provenance)
- `term_order_id` (u16): identifies the monomial order used
- `rules[]`: oriented rewrite rules extracted from the reduced Groebner basis:
  - `lhs_mask` (u64 or u128): monomial/bitset to match
  - `rhs_mask` (same width): monomial/bitset replacement (remainder)

Constraints:
- fixed-width, little-endian, deterministic parsing,
- no allocations when applying rules (stack/local arrays only),
- policy loaded/verified once at init (not per call).

## Runtime Reduction Procedure (Deterministic)

Represent a raw signature as a bitset `mask` of fired atoms (and optionally class vars).

Reduction algorithm:
1. Initialize `mask_raw` from current cached states (thresholding).
2. Apply rewrite rules until a fixed point:

Pseudo:

    mask = mask_raw
    loop:
      changed = false
      for rule in rules:
        if (mask & rule.lhs_mask) == rule.lhs_mask:
          new_mask = (mask & ~rule.lhs_mask) | rule.rhs_mask
          if new_mask != mask:
            mask = new_mask
            changed = true
      if !changed: break

Because the rules are derived from a Groebner basis and oriented by the chosen term order,
this terminates and is confluent (unique normal form) for all signatures in the ideal.

Runtime complexity:
- O(num_rules * iterations). With small rule counts (tens) and small masks (<=128 bits),
  this is within cadence-only budgets; it should not run on the strict fast path.

## Output ID Format

We need a stable identifier that is:
- deterministic,
- versioned,
- collision-resistant enough for clustering (not cryptographic-grade).

Proposed v1:
- `policy_hash_u64 = schema_hash ^ basis_hash`
- `id_u64 = H64(policy_hash_u64 || api_family || canonical_mask)`

Where `H64` is a fast fixed hash (xxh3_64 or equivalent) used elsewhere in evidence code.

String rendering (tooling/UI):
- `gn1:<api_family_hex>:<id_u64_hex>`

The canonical mask itself should also be exportable for debugging (optional).

## Worked Example (Illustrative)

Raw fired atoms:
- `A00_SPECTRAL` (regime transition),
- `A15_CHANGEPOINT` (regime transition),
- `A05_BRIDGE` (transition),
- `A04_CVAR` (tail risk warning).

Normalization (with mappings):
- `A00_SPECTRAL -> C3_REGIME_SHIFT`
- `A15_CHANGEPOINT -> C3_REGIME_SHIFT`
- `A05_BRIDGE -> C3_REGIME_SHIFT`
- `A04_CVAR -> C1_TAIL_LATENCY`

Normal form:
- `{C3_REGIME_SHIFT, C1_TAIL_LATENCY}`

Stable ID then depends only on that cause-set and policy hash.

## Acceptance Criteria Checklist (bd-1hq)

- Concrete signature schema:
  - v1 atom inventory defined above (A00..A24 + optional class vars C0..C5).
- Deterministic reduction procedure:
  - bitset + oriented rewrite rules; fixed-point reduction.
- Output ID format:
  - `policy_hash` + `canonical_mask` -> `id_u64` with `gn1:` rendering.
