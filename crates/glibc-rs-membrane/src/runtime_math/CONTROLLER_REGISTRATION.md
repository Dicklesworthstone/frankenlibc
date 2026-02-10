# Controller Registration + Snapshot Schema Guidelines

> Standard integration pattern for adding a new `runtime_math` controller to `RuntimeMathKernel`.

This document codifies the exact steps required. Following it mechanically produces a correct, reviewable integration.

---

## Prerequisites

Before implementing a new controller:

1. **Have a clear legacy anchor.** The controller must map to a concrete glibc subsystem failure class (see AGENTS.md "Reverse Core Map").
2. **Define the state machine.** Every controller has a finite state enum with 3-4 states (codes 0..3). State 0 is always `Calibrating`.
3. **Implement `new()`, `observe_*()`, `state()`, and `summary()`.** These are the four interface methods the kernel calls.
4. **Write unit tests** in the controller module itself.

---

## Step-by-Step Checklist

### Step 1: Create the Module File

Create `crates/glibc-rs-membrane/src/runtime_math/<name>.rs`.

**Required exports:**

```rust
/// State enum — exactly 3 or 4 variants, #[repr(u8)] starting at 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MyControllerState {
    Calibrating = 0,   // Always first — insufficient data
    Normal = 1,        // Healthy / nominal
    Warning = 2,       // Elevated concern
    Critical = 3,      // Severe / action required
}

/// Summary struct for snapshot reporting.
#[derive(Debug, Clone, Copy)]
pub struct MyControllerSummary {
    pub state: MyControllerState,
    // 1-3 numeric fields that characterize the controller's state.
    // Use f64 for rates/scores, u64 for counts.
    pub primary_metric: f64,
    pub event_count: u64,
}

/// The controller itself.
pub struct MyController { /* ... */ }

impl MyController {
    pub fn new() -> Self { /* ... */ }

    /// Main observation entry point.
    /// For base-severity consumers: `observe_and_update(&[u8; 25])`.
    /// For specialized input: define domain-specific parameters.
    pub fn observe_and_update(&mut self, /* inputs */) { /* ... */ }

    /// Current state (0..3 code).
    pub fn state(&self) -> MyControllerState { /* ... */ }

    /// Snapshot summary for telemetry export.
    pub fn summary(&self) -> MyControllerSummary { /* ... */ }
}
```

**Naming conventions:**
- State enum: `<Name>State` (e.g., `AlphaInvestingState`, `BifurcationState`)
- Summary: `<Name>Summary` (e.g., `AlphaInvestingSummary`)
- Controller: `<Name>Controller` or `<Name>Monitor` or `<Name>Detector`

**Hard constraints on the implementation:**
- No heap allocations in `observe_and_update()`.
- No `exp()`, `ln()`, `sqrt()`, matrix solves, or division-heavy float ops on the per-call path. Use cadenced updates (see Step 5) or pre-computed tables.
- O(1) per observation. Fixed-size state arrays only.
- Deterministic from initial state — given the same input sequence, produce the same output.
- Use saturating arithmetic for counters and accumulators.

---

### Step 2: Declare the Module in `mod.rs`

Add the `pub mod` declaration in **alphabetical order** (lines 14-76 of mod.rs):

```rust
pub mod my_controller;
```

Add the `use` import below the module declarations (lines 98-163):

```rust
use self::my_controller::{MyController, MyControllerState};
```

If the summary type is used in snapshot building, import it too. If the state enum is only used for match-to-u8 conversion, it must still be imported.

---

### Step 3: Add Fields to `RuntimeMathKernel`

Add two fields to the kernel struct:

```rust
pub struct RuntimeMathKernel {
    // ... existing fields ...

    // Controller instance (Mutex-wrapped for interior mutability).
    my_controller: Mutex<MyController>,

    // Cached state code (0..3) for lock-free reads in decide().
    cached_my_controller_state: AtomicU8,

    // ... rest of fields ...
}
```

**Field placement rules:**
- Mutex-wrapped controller: add after the last controller field (currently `alpha_investing` at line 684).
- Cached atomic: add after the last cached field (currently `cached_alpha_investing_state` at line 760).

**When to add extra cached atomics:**
- If the controller produces per-`ApiFamily` state: use `[AtomicU8; ApiFamily::COUNT]`.
- If the controller produces a numeric metric used in `decide()`: use `AtomicU64`.
- Keep it minimal — one `AtomicU8` state code is the standard.

---

### Step 4: Initialize in `new()`

Add initialization in the `Self { ... }` literal inside `RuntimeMathKernel::new()`:

```rust
my_controller: Mutex::new(MyController::new()),
cached_my_controller_state: AtomicU8::new(0),  // 0 = Calibrating
```

**Always initialize cached state to 0** (Calibrating). This ensures that until the first observation feeds data, the controller contributes 0 bonus to risk.

---

### Step 5: Wire into `observe_validation_result()`

There are **two tiers** of observation integration:

#### Tier A: Cadence-Gated Meta-Observer (Standard Pattern)

Most controllers operate on the cadence-gated path that runs every 8 observations. This is the standard tier for controllers that consume the `base_severity: [u8; 25]` array.

Add a block **inside the cadence gate** (after the existing meta-controllers, before the fusion block):

```rust
// Feed <name> monitor.
// <One-line description of what this detects.>
{
    let code = {
        let mut ctrl = self.my_controller.lock();
        ctrl.observe_and_update(&base_severity);
        match ctrl.state() {
            MyControllerState::Calibrating => 0u8,
            MyControllerState::Normal => 1u8,
            MyControllerState::Warning => 2u8,
            MyControllerState::Critical => 3u8,
        }
    };
    self.cached_my_controller_state.store(code, Ordering::Relaxed);
}
```

**Critical: the lock is held only within the inner block** (`let code = { ... };`) and released before the `store()`. This prevents cascading lock ordering issues.

#### Tier B: Always-On O(1) Observer

For controllers that need per-call input (e.g., family-specific, latency-specific), add an always-on block **outside** the cadence gate. These must be genuinely O(1) with no lock contention:

```rust
{
    let mut ctrl = self.my_controller.lock();
    ctrl.observe(family, estimated_cost_ns);
    let code = match ctrl.state() { /* ... */ };
    self.cached_my_controller_state.store(code, Ordering::Relaxed);
}
```

Only use Tier B when the controller's mathematical model genuinely requires per-call input. Most controllers should use Tier A.

---

### Step 6: Wire into `decide()` — Risk Bonus Mapping

Add a bonus mapping in `decide()` that reads the cached atomic and maps states to ppm risk bonuses:

```rust
// <Name>: <one-line description>.
// <StateN> means <what it means in plain English>.
let my_controller_bonus = match self.cached_my_controller_state.load(Ordering::Relaxed) {
    3 => XXX_000u32,  // Critical — <why this bonus>
    2 => YY_000u32,   // Warning — <why this bonus>
    _ => 0u32,        // Calibrating/Normal
};
```

Then include it in the saturating sum:

```rust
let raw_risk_ppm = base_risk_ppm
    .saturating_add(sampled_bonus)
    // ... existing bonuses ...
    .saturating_add(my_controller_bonus);
```

**Bonus magnitude guidelines:**
- State 3 (Critical): 100k-200k ppm — strong evidence of a real fault.
- State 2 (Warning): 30k-70k ppm — moderate evidence, worth investigating.
- State 1 (Normal): 0 ppm — no contribution (do not add noise).
- State 0 (Calibrating): 0 ppm — insufficient data to contribute.

**Conservative merge rule:** A controller may only **escalate** risk (increase bonus). It must never de-escalate below what other controllers determined. This is the monotonic risk lattice property.

---

### Step 7: Add Snapshot Fields

Add 2-3 fields to `RuntimeKernelSnapshot` (the struct starting at line 289):

```rust
/// <Name> <primary metric description> (<unit>).
pub my_controller_primary_metric: f64,
/// <Name> <event count description>.
pub my_controller_event_count: u64,
```

**Snapshot field conventions:**
- Prefix all fields with the controller's short name (e.g., `alpha_investing_`, `bifurcation_`, `nerve_`).
- Include 1-2 primary numeric outputs and 0-1 count fields.
- Use `f64` for rates, scores, distances, entropies.
- Use `u64` for event counts.
- Use `u32` for ppm-scaled values.
- Use `u8` for small enum-like values.

**Schema version policy:**
- Additive fields do NOT require a version bump. Just append.
- Renames, removals, or semantic changes require bumping `RUNTIME_KERNEL_SNAPSHOT_SCHEMA_VERSION` with a migration plan.

---

### Step 8: Build Snapshot in `snapshot()`

Add summary extraction and field population in the `snapshot()` method:

1. **Extract summary** (add before the `RuntimeKernelSnapshot { ... }` literal):
```rust
let my_controller_summary = self.my_controller.lock().summary();
```

2. **Populate fields** (add inside the literal):
```rust
my_controller_primary_metric: my_controller_summary.primary_metric,
my_controller_event_count: my_controller_summary.event_count,
```

**Lock ordering:** All summary extractions happen **before** the snapshot literal construction. Never lock inside the literal itself.

---

### Step 9: Update Fusion Severity Vector

If the controller is a meta-controller (operates on base_severity, not a base signal source), it needs a slot in the 60-element fusion severity vector.

1. **Increment `META_SEVERITY_LEN`** (line 171):
```rust
const META_SEVERITY_LEN: usize = 36;  // was 35
```

2. **Update `fusion::SIGNALS`** (in `fusion.rs`):
```rust
pub const SIGNALS: usize = 61;  // was 60
```

3. **Assign a severity index** in the fusion block (lines 3126-3164):
```rust
severity[60] = self.cached_my_controller_state.load(Ordering::Relaxed); // 0..3
```

4. **Verify compile-time assertion still holds** — the static assert on line 173 enforces `SIGNALS == BASE_SEVERITY_LEN + META_SEVERITY_LEN`.

**Important:** Adding a fusion signal changes the weight vector dimension in `KernelFusionController`. Ensure `fusion.rs` handles dynamic or static sizing correctly.

---

### Step 10: Add Design Probe (Optional)

If the controller's observation is expensive (Tier A cadence-gated) and should be subject to probe budget optimization:

1. Add a variant to `design::Probe` enum.
2. Record the probe result in the design kernel section of `observe_validation_result()`.
3. Add an anomaly flag (`Option<bool>`) alongside existing anomaly tracking variables.

This step is optional for lightweight controllers.

---

## Example: Alpha-Investing Integration Reference

The most recent complete integration is `alpha_investing` (commit `debf416`). Use it as a reference:

| Step | File Location | Lines |
|------|--------------|-------|
| Module file | `runtime_math/alpha_investing.rs` | 1-468 |
| `pub mod` | `mod.rs:15` | `pub mod alpha_investing;` |
| `use` import | `mod.rs:99` | `use self::alpha_investing::{...};` |
| Kernel field | `mod.rs:684` | `alpha_investing: Mutex<...>` |
| Cached atomic | `mod.rs:760` | `cached_alpha_investing_state: AtomicU8` |
| Init | `mod.rs:853` | `alpha_investing: Mutex::new(...)` |
| Atomic init | `mod.rs:929` | `cached_alpha_investing_state: AtomicU8::new(0)` |
| Observe | `mod.rs:3106-3121` | Cadence-gated, base_severity input |
| Fusion slot | `mod.rs:3164` | `severity[59] = cached_alpha_investing_state` |
| Snapshot extract | `mod.rs:3349` | `alpha_investing_summary = ...lock().summary()` |
| Snapshot fields | `mod.rs:600-605` | 3 fields: wealth, rejections, fdr |
| Snapshot populate | `mod.rs:3508-3510` | Field assignment in literal |

---

## Invariants to Verify After Integration

Run the full quality gate after every integration:

```bash
cargo fmt --check
cargo check --all-targets
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
```

Specific checks:
1. **Compile-time assertion:** `SIGNALS == BASE_SEVERITY_LEN + META_SEVERITY_LEN` (if fusion slot was added).
2. **No unused imports:** clippy will flag unused `use` statements.
3. **Snapshot schema:** All fields populated — missing fields cause compile error (struct literal completeness).
4. **Lock ordering:** No nested locks. Each block acquires at most one Mutex at a time.
5. **Determinism:** Given the same seed/input sequence, `snapshot()` produces identical output.

---

## Anti-Patterns (Do Not)

1. **Do not add `exp()`, `ln()`, `sqrt()`, or matrix operations to the per-call path.** Use cadenced updates (every N calls) and cache results in atomics.
2. **Do not heap-allocate in `observe_and_update()`.** Fixed-size arrays only.
3. **Do not hold two Mutexes simultaneously.** Release one before acquiring another.
4. **Do not read non-cached state in `decide()`.** Only read `AtomicU8`/`AtomicU64` cached values. Never lock in `decide()` except during `resample_high_order_kernels()` (every 128 calls).
5. **Do not change existing snapshot field semantics.** Only add new fields. Removal/rename requires schema version bump.
6. **Do not map state 0 (Calibrating) to a nonzero bonus.** Calibrating means "no data yet" — contributing phantom risk degrades all decisions until warmup.
7. **Do not remove or reorder existing fusion severity indices.** Only append new slots at the end.
