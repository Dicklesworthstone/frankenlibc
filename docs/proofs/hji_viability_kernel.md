# HJI Viability Kernel Proof Note (bd-34s.2)

## Scope
- This artifact covers the HJI controller that is live in the repo today: the discrete 4x4x4 state model over `(risk, latency, adverse_rate)` implemented in `crates/frankenlibc-membrane/src/hji_reachability.rs`.
- It proves the checked-in viability artifact and runtime wiring for that controller.
- It does not claim closure of the future async-signal-safety state model described by R16 (`pc_region`, `lock_state`, `signal_pending`).

## Statement
For the shipped discrete controller:

- The positive-value set `V = { x : value_fn[x] > 0 }` is a viable kernel for the implemented transition system.
- For every state in `V`, there exists a controller action whose successors remain in `V` for every adversary action.
- For every checked boundary witness outside `V`, each controller action has an adversary response that remains outside `V`.
- The finite value-iteration solver reaches a fixed point on this discretization in two sweeps, and the checked-in Bellman residual trace matches the live solver.

## Evidence Surface
- Checked-in computation artifact: `tests/runtime_math/hji_viability_computation.json`
- Checked-in convergence plot: `tests/runtime_math/viability_convergence.svg`
- Enforcing gate: `scripts/check_runtime_math_hji_viability_proofs.sh`
- Harness proof implementation: `crates/frankenlibc-harness/src/runtime_math_hji_viability_proofs.rs`
- Harness integration test: `crates/frankenlibc-harness/tests/runtime_math_hji_viability_proofs_test.rs`

## Runtime Traceability
- `crates/frankenlibc-membrane/src/hji_reachability.rs`
  solver, winning-policy extraction, convergence trace, and boundary witnesses.
- `crates/frankenlibc-membrane/src/runtime_math/mod.rs`
  runtime observe hook, cached HJI state publication, and snapshot export fields `hji_safety_value` / `hji_breached`.

## Current Result
- Live kernel volume: 48 states.
- Non-viable volume: 16 states.
- Winning-policy histogram on the viable set: `relax=16`, `tighten=16`, `emergency=16`, `hold=0`.
- Checked boundary witnesses are the five closest outside-kernel states in the discrete ordering.

## Explicit Non-Claims
- No viscosity-solution proof for a continuous PDE is claimed here.
- No grid-refinement/Hausdorff convergence claim is made here.
- No signal-program-counter safety map or deferred-delivery policy is proved here.

## Follow-On Work
- Replace the current `(risk, latency, adverse_rate)` surrogate with the signal-state model required by R16.
- Add a true refinement story from the discrete controller to the async-signal-safety contract.
- Extend the proof surface from fixed-point convergence on a fixed grid to grid-refinement convergence once the higher-fidelity model exists.
