# Startup Init Capability Lattice

`bd-2gjs.4` formalizes phase-0 startup as a Galois connection between:

- Concrete world: the ordered `StartupCheckpoint` path executed by `__frankenlibc_startup_phase0`.
- Abstract world: the monotone `InitCapability` set accumulated during bootstrap.

## Capability Lattice

The phase-0 path acquires capabilities in one direction only:

1. `MembraneAdmission`
2. `MainValidated`
3. `ArgvValidated`
4. `ArgvScanned`
5. `ArgcBounded`
6. `EnvpScanned`
7. `AuxvScanned`
8. `SecureModeKnown`
9. `InvariantsCaptured`
10. `EnvpResolved`
11. `ProcessGlobalsBound`
12. `HostSymbolsReady`
13. `HostStdioReady`
14. `HostLibioReady`
15. `ThreadSymbolsReady`
16. `AllocatorSymbolsReady`
17. `RuntimeReady`
18. `InitHookObserved`
19. `MainCompleted`
20. `FiniObserved`
21. `RtldFiniObserved`

`alpha(path)`:

- verifies the concrete checkpoint path respects the startup DAG,
- rejects any step whose required capabilities are not present,
- returns the accumulated capability set after the last checkpoint.

`gamma(capabilities)`:

- returns the concrete checkpoints whose preconditions are satisfied by the current capability set.

This keeps the startup proof developer-transparent: ordinary Rust code still executes the bootstrap path, while the capability lattice supplies the proof witness for ordering safety.

## Manual Proof Sketches

### 1. Canonical allow path

Concrete path:

`Entry -> MembraneGate -> ValidateMainPointer -> ValidateArgvPointer -> ScanArgvVector -> ValidateArgcBound -> ScanEnvpVector -> ScanAuxvVector -> ClassifySecureMode -> CaptureInvariants -> ResolveEnvp -> BindProcessGlobals -> BootstrapHostSymbols -> InitHostStdio -> BootstrapHostLibio -> PrewarmThreadSymbols -> PrewarmAllocatorSymbols -> SignalRuntimeReady -> CallInitHook -> CallMain -> CallFiniHook -> CallRtldFiniHook -> Complete`

Proof sketch:

- Every checkpoint only requires capabilities produced by earlier checkpoints.
- `CallMain` is unreachable until `RuntimeReady` is present.
- `Complete` is unreachable until `MainCompleted` is present.

### 2. Deny path after invalid startup state

Concrete path:

`Entry -> MembraneGate -> ValidateMainPointer -> Deny`

Proof sketch:

- `Deny` carries no additional capability requirements.
- The proof system permits early termination without manufacturing later-stage capabilities.
- Invalid startup vectors therefore fail closed rather than silently skipping prerequisites.

### 3. Host fallback path

Concrete path:

`Entry -> FallbackHost`

Proof sketch:

- Host fallback is modeled as a separate edge from `Entry`.
- It does not claim `RuntimeReady` or any later bootstrap capability.
- This prevents the proof artifact from conflating delegated bootstrap with native phase-0 completion.

## Generated Witness

The build script emits `startup_init_order_certificate.json` into `OUT_DIR`, embeds it via `STARTUP_INIT_ORDER_CERTIFICATE_JSON`, and proves:

- the checkpoint graph is acyclic,
- the checkpoint contracts cover the phase-0 route,
- the bootstrap/self-hosting symbol dependency graph is acyclic.

The contract test persists a replayable copy at:

- `target/conformance/bd-2gjs.4_startup_init_order_certificate.json`

This keeps the proof artifact deterministic and CI-visible without adding runtime startup overhead.
