# CPOMDP Safety Feasibility Proof Note (bd-249m.4)

## Scope
- This artifact proves a finite CPOMDP abstraction for the live `pomdp_repair` decision surface in `crates/frankenlibc-membrane/src/runtime_math/pomdp_repair.rs`.
- The abstraction keeps the real action vocabulary `{Allow, Quarantine, Repair, Escalate}` and a sensor-aligned observation vocabulary `{Clean, Ambiguous, BoundsAlert, TemporalAlert}`.
- The proof target is feasibility plus offline optimality of the finite repair policy, not a continuous-state proof for every possible telemetry stream.

## Model
- Hidden state space: `{Safe, Suspicious, Unsafe}`.
- Initial belief under the normal workload prior: `b0 = [0.99, 0.008, 0.002]`.
- Observation support:
  `Clean`, `Ambiguous`, `BoundsAlert`, and `TemporalAlert`, with observation rows derived from a validation-pipeline interpretation of ownership/bounds/temporal alarms.
- Action space:
  `Allow`, `Quarantine`, `Repair`, `Escalate`.
- Safety constraint:
  `P(Unsafe and Allow) <= epsilon`, with primary target `epsilon = 0.001`.
- Throughput objective:
  maximize the fraction of operations completed without quarantine or escalation.

## Belief-State Reduction
- The CPOMDP is reduced to a finite belief-support MDP by conditioning the normal-workload prior on the four observation buckets.
- This yields four posterior belief points, one per observation bucket, so the offline controller can be represented as a finite table from observation-belief support to action.
- The reduction is constructive and explicit in the generated `cpomdp_feasibility.json` artifact.

## LP Formulation
- Deterministic observation policies are the vertices of the finite policy polytope.
- Let each policy vertex `pi_i` have throughput `T_i` and unsafe-allow mass `S_i`.
- The primal LP over randomized mixtures `w_i` is:

```text
maximize   sum_i w_i T_i
subject to sum_i w_i S_i <= epsilon
           sum_i w_i = 1
           w_i >= 0
```

- The dual is:

```text
minimize   lambda * epsilon + max_i (T_i - lambda S_i)
subject to lambda >= 0
```

- Because the problem has one inequality plus the simplex equality, the exact optimum lies on a vertex or a two-policy edge. The harness therefore solves the primal exactly by enumerating all deterministic policies and all feasible two-policy boundary mixtures, and solves the dual exactly by scanning the piecewise-linear breakpoints.

## Statement
For the shipped finite abstraction:

- The state, observation, and action spaces are finite.
- Every transition and observation row is normalized, so the CPOMDP is well posed.
- A feasible safe policy exists at `epsilon = 0.001` with throughput `1.0 > 0.95`.
- The best deterministic policy matches the primal LP optimum, so no higher-throughput feasible policy exists.
- The dual solution matches the primal objective exactly (zero duality gap after rounding), providing the offline optimality witness.

## Evidence Surface
- Gate script:
  `scripts/check_runtime_math_cpomdp_feasibility_proofs.sh`
- Harness implementation:
  `crates/frankenlibc-harness/src/runtime_math_cpomdp_feasibility_proofs.rs`
- Harness integration test:
  `crates/frankenlibc-harness/tests/runtime_math_cpomdp_feasibility_proofs_test.rs`
- Generated feasibility artifact:
  `target/conformance/cpomdp_feasibility.json`
- Generated sensitivity artifact:
  `target/conformance/cpomdp_sensitivity.json`
- Generated proof report:
  `target/conformance/runtime_math_cpomdp_feasibility_proofs.report.json`

## Current Result
- Primary feasibility target: `epsilon = 0.001`.
- Certified policy:
  `Clean -> Allow`, `Ambiguous -> Allow`, `BoundsAlert -> Allow`, `TemporalAlert -> Repair`.
- Unsafe-allow probability:
  `0.00064`.
- Throughput:
  `1.0`.
- The epsilon sweep from `0.0001` to `0.01` is emitted into `cpomdp_sensitivity.json`.

## Runtime Traceability
- `crates/frankenlibc-membrane/src/runtime_math/pomdp_repair.rs`
  provides the live repair controller and the embedded `proof_cpomdp_safety_feasibility` unit proof.
- `crates/frankenlibc-membrane/src/runtime_math/mod.rs`
  registers the controller, caches `cached_pomdp_state`, and exports snapshot fields `pomdp_optimality_gap` and `pomdp_divergence_count`.

## Explicit Non-Claims
- No claim is made here about continuous-belief optimality beyond the finite observation support used by the gate.
- No claim is made that the proof abstraction covers every future runtime-math telemetry channel.
- No claim is made that the finite abstraction replaces the live controller’s own embedded invariants; it supplements them with an auditable offline feasibility certificate.
