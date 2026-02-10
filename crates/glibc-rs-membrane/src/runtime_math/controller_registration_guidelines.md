# Controller Registration + Snapshot Schema Guidelines

Standard integration pattern for adding a new runtime_math controller to `RuntimeMathKernel`.

This is the reference checklist for bead `bd-2vf`. All future controllers (SOS barrier,
localization chooser, Groebner normal form, approachability, Sobol scheduler, proof-carrying
policy, etc.) MUST follow this pattern.

---

## Checklist (8 Steps)

### Step 1: Create Module File

Create `crates/glibc-rs-membrane/src/runtime_math/<controller_name>.rs`.

**Required exports:**
```rust
/// Controller state enum (maps to severity code 0..3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MyControllerState {
    Calibrating = 0,   // Insufficient data
    Normal = 1,        // Nominal operation
    Elevated = 2,      // Warning / transitioning
    Critical = 3,      // Alarm / violated
}

/// Summary struct for snapshot reporting.
#[derive(Debug, Clone, Copy)]
pub struct MyControllerSummary {
    pub state: MyControllerState,
    // ... controller-specific telemetry fields
}

/// Controller struct.
pub struct MyController { ... }

impl MyController {
    pub fn new() -> Self { ... }

    /// Feed observations and update internal state.
    ///
    /// Signature depends on controller type:
    /// - Base controller: `observe_and_update(&mut self, <domain-specific inputs>)`
    /// - Meta-controller: `observe_and_update(&mut self, severity: &[u8; N])`
    pub fn observe_and_update(&mut self, ...) { ... }

    /// Current state (for cached atomic).
    pub fn state(&self) -> MyControllerState { ... }

    /// Summary for snapshot (called on cadence, not hot path).
    pub fn summary(&self) -> MyControllerSummary { ... }
}

impl Default for MyController {
    fn default() -> Self { Self::new() }
}
```

**Required invariants:**
- `new()` returns a deterministic initial state (no randomness).
- `observe_and_update()` is O(1) per call (no allocations, no unbounded loops).
- State enum values are contiguous 0..3 (maps directly to AtomicU8 severity code).
- All arithmetic is saturating (no panics on overflow).

**Required tests** (at minimum):
- `starts_calibrating()` — new controller begins in Calibrating state.
- `transitions_to_normal()` — after sufficient nominal data, transitions to Normal.
- `detects_anomaly()` — under adversarial input, transitions to Elevated/Critical.
- `recovers_from_anomaly()` — after anomaly clears, returns to Normal.
- `summary_consistent()` — summary fields match controller state.

### Step 2: Declare Module in mod.rs

Add `pub mod <controller_name>;` in alphabetical order in the module declarations
(lines 14-76 of mod.rs).

Add the `use` import:
```rust
use self::<controller_name>::{MyController, MyControllerState};
```

in the import block (lines 98-163 of mod.rs), alphabetically.

### Step 3: Add Controller Field to RuntimeMathKernel

Add a `Mutex<MyController>` field to the `RuntimeMathKernel` struct (lines 609-762):
```rust
pub struct RuntimeMathKernel {
    // ... existing fields ...
    my_controller: Mutex<MyController>,
    // ...
}
```

**Field naming convention:** use snake_case matching the module name. Examples:
`alpha_investing`, `spectral_gap`, `bifurcation`, `entropy_rate`.

### Step 4: Add Cached State Atomic

Add an `AtomicU8` field for the cached severity code:
```rust
    cached_my_controller_state: AtomicU8,
```

**Naming convention:** `cached_<field_name>_state: AtomicU8`.

Some controllers also have additional cached atomics for values used in `decide()`:
- `cached_<name>_ppm: AtomicU64` for risk/alignment scores
- `cached_<name>_count: AtomicU64` for cumulative counts
Only add these if `decide()` needs them on the hot path.

### Step 5: Initialize in `RuntimeMathKernel::new()`

Add initialization in the `Self { ... }` constructor (lines 778-929):
```rust
    my_controller: Mutex::new(MyController::new()),
    cached_my_controller_state: AtomicU8::new(0),
```

**Initial cached value is always 0** (Calibrating).

### Step 6: Wire into observe_validation_result()

This is the most critical step. Controllers are fed observations in
`observe_validation_result()`, which runs after every validation decision.

**Choose the correct integration tier:**

#### Tier A: Cadence-Gated Meta-Controller (Most Common)

Meta-controllers receive the fused base severity vector and run on a cadence
(every N observations). They analyze cross-controller patterns.

Wire into the existing cadence-gated meta-observe block
(after the base severity construction at line ~2545):

```rust
// Feed my-controller meta-controller.
{
    let state_code = {
        let mut ctrl = self.my_controller.lock();
        ctrl.observe_and_update(&base_severity);
        match ctrl.state() {
            MyControllerState::Calibrating => 0u8,
            MyControllerState::Normal => 1u8,
            MyControllerState::Elevated => 2u8,
            MyControllerState::Critical => 3u8,
        }
    };
    self.cached_my_controller_state
        .store(state_code, Ordering::Relaxed);
}
```

#### Tier B: Domain-Specific Base Controller

Some controllers need domain-specific inputs (e.g., risk_engine needs ApiFamily,
quarantine_controller needs contention signal). These are fed separately in the
observe flow, typically under a cadence gate.

```rust
if sequence.is_multiple_of(CADENCE) {
    let mut ctrl = self.my_controller.lock();
    ctrl.observe_and_update(domain_specific_input);
    self.cached_my_controller_state
        .store(ctrl.state() as u8, Ordering::Relaxed);
}
```

**CRITICAL RULE: Never acquire a Mutex in the fusion severity aggregation literal.**

The block that constructs `severity[25..60]` (lines 3126-3164) MUST use only cached
AtomicU8 loads — never `.lock()`. This is enforced by the compile-time test
`fusion_severity_literal_is_lock_free()`. The Mutex lock happens in the
meta-observe block (Tier A/B above); the result is stored in the cached atomic;
the fusion block reads the cached atomic.

### Step 7: Add to Fusion Severity Vector

If the controller contributes a severity signal (almost all do), add it to the
fusion severity vector construction:

1. **Increment `META_SEVERITY_LEN`** (line 171):
   ```rust
   const META_SEVERITY_LEN: usize = 36; // was 35
   ```
   Also update `fusion::SIGNALS` in `fusion.rs` to match.

2. **Add the cached load** at the next available index:
   ```rust
   severity[60] = self.cached_my_controller_state.load(Ordering::Relaxed); // 0..3
   ```

3. **The compile-time assertion** (line 173) will fail if SIGNALS != BASE + META,
   catching any mismatch.

**Index assignment convention:**
- Indices 0-24: base severity (25 controllers)
- Indices 25+: meta-controllers, appended in integration order
- Document the index in a comment: `// 0..3`

### Step 8: Add Snapshot Fields

Add fields to `RuntimeKernelSnapshot` (lines 289-606):

```rust
/// My-controller primary metric (describe units and range).
pub my_controller_primary_metric: f64,
/// My-controller detection/violation count.
pub my_controller_event_count: u64,
```

**Schema rules (from bd-1az):**
- Fields are **additive only** — never remove or rename existing fields.
- Document units and valid range in the doc comment.
- Use consistent naming: `<controller>_<metric>`.
- Typical pattern: 1-2 float metrics + 1 count field.

Wire in the `snapshot()` method (around line 3349+):
```rust
let my_ctrl_summary = self.my_controller.lock().summary();
// ... later in the snapshot struct literal:
my_controller_primary_metric: my_ctrl_summary.primary_metric,
my_controller_event_count: my_ctrl_summary.event_count,
```

---

## decide() Integration (Optional)

Most controllers do NOT modify `decide()`. They contribute indirectly via:
1. Their cached severity code → fusion bonus → risk aggregation.
2. The barrier oracle reading cached state.

If a controller DOES need to influence `decide()` directly (e.g., alpha-investing
gates escalation, POMDP recommends repair policy), add a read of the cached atomic
in the `decide()` bonus aggregation block (lines 942-1130):

```rust
let my_bonus = match self.cached_my_controller_state.load(Ordering::Relaxed) {
    3 => 100_000u32, // Critical
    2 => 50_000u32,  // Elevated
    _ => 0u32,       // Calibrating/Normal
};
```

**Rules for decide() modifications:**
- Read ONLY cached atomics (no Mutex locks on the hot path).
- Bonus values: use ppm (0..1_000_000).
- Conservative merge: a new controller can only INCREASE validation level, never
  decrease it (monotone escalation).
- No floating-point math on the strict fast path (use integer ppm arithmetic).

---

## Snapshot Schema Versioning

When adding snapshot fields, bump `RUNTIME_KERNEL_SNAPSHOT_SCHEMA_VERSION`:
```rust
const RUNTIME_KERNEL_SNAPSHOT_SCHEMA_VERSION: u32 = <N+1>;
```

The schema version is recorded in every snapshot and used by downstream consumers
(harness, frankentui diff UI) to handle format evolution.

---

## Naming Conventions Summary

| Item | Convention | Example |
|------|-----------|---------|
| Module file | `snake_case.rs` | `alpha_investing.rs` |
| Controller struct | `PascalCase + Controller/Monitor` | `AlphaInvestingController` |
| State enum | `PascalCase + State` | `AlphaInvestingState` |
| Summary struct | `PascalCase + Summary` | `AlphaInvestingSummary` |
| Kernel field | `snake_case` | `alpha_investing` |
| Cached atomic | `cached_<name>_state` | `cached_alpha_investing_state` |
| Snapshot fields | `<name>_<metric>` | `alpha_investing_wealth_milli` |
| Severity index | Append to META block | `severity[59]` |

---

## Anti-Patterns (Do NOT Do)

1. **Do NOT acquire Mutex in fusion severity literal.** Use cached atomics only.
2. **Do NOT add float math to decide() strict path.** Use integer ppm.
3. **Do NOT remove or rename snapshot fields.** Additive only.
4. **Do NOT use `state as u8` directly if enum is non-contiguous.** Use explicit match.
5. **Do NOT forget the compile-time SIGNALS assertion.** It will catch you.
6. **Do NOT forget Default impl.** All controllers must impl `Default`.
7. **Do NOT allocate in observe_and_update().** Fixed-size state only.

---

## Example: Alpha-Investing Integration (Reference)

The `alpha_investing` controller is a complete example of this pattern:

- Module: `runtime_math/alpha_investing.rs` (468 lines)
- Import: `use self::alpha_investing::{AlphaInvestingController, AlphaInvestingState};`
- Kernel field: `alpha_investing: Mutex<AlphaInvestingController>`
- Cached atomic: `cached_alpha_investing_state: AtomicU8`
- Init: `alpha_investing: Mutex::new(AlphaInvestingController::new())`
- Meta-observe: cadence-gated, feeds `base_severity[..25]`, caches state code
- Fusion severity: `severity[59] = self.cached_alpha_investing_state.load(...)`
- Snapshot: `alpha_investing_wealth_milli`, `alpha_investing_rejections`, `alpha_investing_empirical_fdr`
- decide() bonus: reads cached state, maps to severity signal (indirect via fusion)

Use this as the template for all future controllers.
