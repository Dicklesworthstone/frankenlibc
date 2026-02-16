//! # Grothendieck Site/Topos Descent and Stackification Gluer
//!
//! Implements Grothendieck site/topos/descent/stackification methods for
//! local-to-global coherence and compatibility gluing across overlapping
//! data sources (math item #33).
//!
//! ## Mathematical Foundation
//!
//! A **Grothendieck topology** on a category C assigns to each object U
//! a collection of **covering sieves** J(U) — families of morphisms
//! {U_i → U} that "cover" U. A **sheaf** on (C, J) is a presheaf F
//! satisfying the **descent condition**: for every covering {U_i → U},
//! the diagram
//!
//! ```text
//! F(U) → Π_i F(U_i) ⇉ Π_{i,j} F(U_i ×_U U_j)
//! ```
//!
//! is an equalizer. This means:
//! 1. **Restriction**: Local data on each U_i that agrees on overlaps
//!    U_i ∩ U_j can be uniquely **glued** to a global section on U.
//! 2. **Separation**: A global section is determined by its restrictions.
//!
//! **Stackification** generalizes sheafification to categories fibered
//! in groupoids — it turns a prestack into a stack by freely adding
//! descent data. The key computational step is checking the **cocycle
//! condition** on triple overlaps:
//!
//! ```text
//! g_{ij} · g_{jk} = g_{ik}   on U_i ∩ U_j ∩ U_k
//! ```
//!
//! ## Runtime Application
//!
//! The NSS/resolv/locale subsystems are precisely a Grothendieck site:
//!
//! - **Objects**: Data sources (files, DNS, LDAP, NIS, locale files,
//!   iconv tables, transliteration maps).
//!
//! - **Covering**: A lookup query covers multiple sources (e.g., NSS
//!   resolves hostnames via files, then DNS, then LDAP). Each source
//!   provides a "local section" of the answer.
//!
//! - **Overlaps**: When multiple sources can answer the same query
//!   (e.g., /etc/hosts AND DNS both resolve "localhost"), their answers
//!   must be **compatible** — the cocycle condition.
//!
//! - **Gluing**: The final answer is the unique global section glued
//!   from compatible local sections. If sources disagree (cocycle
//!   violation), we detect a **descent failure**.
//!
//! - **Stackification**: When sources provide not just values but
//!   *equivalence classes* of values (e.g., locale aliases, encoding
//!   fallback chains), stackification ensures the equivalence relations
//!   are coherent across sources.
//!
//! ## Distinction from `higher_topos.rs`
//!
//! `higher_topos.rs` implements the *internal logic* of a higher topos
//! for locale/catalog consistency via type-theoretic descent checks.
//! This module implements the *Grothendieck site structure* — covering
//! sieve verification, cocycle conditions on overlaps, and stackification
//! coherence for the NSS/resolv/iconv source-multiplexing layer.
//!
//! ## Connection to Math Item #33
//!
//! Grothendieck site/topos/descent/stackification methods for
//! local-to-global coherence and compatibility gluing.
//!
//! ## Legacy Anchor
//!
//! `nss`, `resolv`, `nscd`, `sunrpc` (identity/network lookup/cache/RPC)
//! and `locale`, `localedata`, `iconv`, `iconvdata`, `wcsmbs`
//! (encoding/collation/transliteration).

/// Number of data sources (NSS backends + locale sources).
const NUM_SOURCES: usize = 8;

/// Number of query families (hostname, service, user, group, locale, encoding, etc.).
const NUM_QUERY_FAMILIES: usize = 6;

/// Maximum overlap pairs tracked per query family.
const MAX_OVERLAP_PAIRS: usize = (NUM_SOURCES * (NUM_SOURCES - 1)) / 2;

/// Observation window for cocycle violation tracking.
const COCYCLE_WINDOW: usize = 256;

/// EWMA decay for violation rates.
const EWMA_ALPHA: f64 = 0.015;

/// Cocycle violation rate threshold for descent failure.
const DESCENT_FAILURE_THRESHOLD: f64 = 0.08;

/// Severe threshold: stackification incoherence.
const STACKIFICATION_THRESHOLD: f64 = 0.20;

/// Calibration observations.
const CALIBRATION_OBS: u64 = 64;

/// A data source in the Grothendieck site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum DataSource {
    Files = 0,
    Dns = 1,
    Ldap = 2,
    Nis = 3,
    Cache = 4,
    LocaleFiles = 5,
    IconvTables = 6,
    Fallback = 7,
}

/// A query family in the covering sieve.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum QueryFamily {
    Hostname = 0,
    Service = 1,
    UserGroup = 2,
    LocaleResolution = 3,
    EncodingLookup = 4,
    Transliteration = 5,
}

/// Cocycle observation: whether two sources agreed on an overlap.
#[derive(Debug, Clone, Copy)]
pub struct CocycleObservation {
    /// Query family.
    pub family: QueryFamily,
    /// First source.
    pub source_i: DataSource,
    /// Second source.
    pub source_j: DataSource,
    /// Whether the local sections are compatible (cocycle condition holds).
    pub compatible: bool,
    /// Whether this is a stackification-level check (equivalence class, not equality).
    pub is_stack_check: bool,
}

/// Grothendieck glue state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum GlueState {
    /// Insufficient observations.
    Calibrating = 0,
    /// All covering sieves produce coherent global sections.
    Coherent = 1,
    /// Cocycle violations detected — local sections disagree on overlaps.
    DescentFailure = 2,
    /// Stackification incoherence — equivalence classes don't compose.
    StackificationFault = 3,
}

/// Telemetry snapshot.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct GlueSnapshot {
    /// Per-family cocycle violation rate (EWMA, 0..1).
    pub family_violation_rates: [f64; NUM_QUERY_FAMILIES],
    /// Global violation rate (EWMA, 0..1).
    pub global_violation_rate: f64,
    /// Stackification violation rate (EWMA, 0..1).
    pub stack_violation_rate: f64,
    /// Current state.
    pub state: GlueState,
    /// Total cocycle checks performed.
    pub checks: u64,
    /// Total descent failure detections.
    pub descent_failure_count: u64,
    /// Total stackification fault detections.
    pub stack_fault_count: u64,
    /// Source pair with highest violation rate.
    pub worst_pair: (u8, u8),
}

/// Per-family tracking state.
struct FamilyCocycleTracker {
    /// Violation rate per overlap pair (EWMA).
    pair_rates: [f64; MAX_OVERLAP_PAIRS],
    /// Overall family violation rate (EWMA).
    family_rate: f64,
    /// Observation count.
    observations: u64,
}

impl FamilyCocycleTracker {
    fn new() -> Self {
        Self {
            pair_rates: [0.0; MAX_OVERLAP_PAIRS],
            family_rate: 0.0,
            observations: 0,
        }
    }

    fn observe(&mut self, pair_idx: usize, compatible: bool) {
        self.observations += 1;
        let violation = if compatible { 0.0 } else { 1.0 };
        if pair_idx < MAX_OVERLAP_PAIRS {
            self.pair_rates[pair_idx] =
                (1.0 - EWMA_ALPHA) * self.pair_rates[pair_idx] + EWMA_ALPHA * violation;
        }
        self.family_rate = (1.0 - EWMA_ALPHA) * self.family_rate + EWMA_ALPHA * violation;
    }
}

/// Online Grothendieck site cocycle/descent/stackification coherence monitor.
pub struct GrothendieckGlueController {
    /// Per-family cocycle trackers.
    families: [FamilyCocycleTracker; NUM_QUERY_FAMILIES],
    /// Stackification-specific violation rate (EWMA).
    stack_rate: f64,
    /// Global violation rate (EWMA).
    global_rate: f64,
    /// Current state.
    state: GlueState,
    /// Total checks.
    checks: u64,
    /// Descent failure count.
    descent_failure_count: u64,
    /// Stack fault count.
    stack_fault_count: u64,
}

impl GrothendieckGlueController {
    /// Create a new Grothendieck glue controller.
    #[must_use]
    pub fn new() -> Self {
        Self {
            families: std::array::from_fn(|_| FamilyCocycleTracker::new()),
            stack_rate: 0.0,
            global_rate: 0.0,
            state: GlueState::Calibrating,
            checks: 0,
            descent_failure_count: 0,
            stack_fault_count: 0,
        }
    }

    /// Observe a cocycle check outcome.
    pub fn observe_cocycle(&mut self, obs: &CocycleObservation) {
        let fam = obs.family as usize;
        if fam >= NUM_QUERY_FAMILIES {
            return;
        }

        // Same-source observations are vacuously compatible — skip.
        if obs.source_i as u8 == obs.source_j as u8 {
            return;
        }

        self.checks += 1;

        // Compute pair index from source indices.
        let (si, sj) = if (obs.source_i as u8) < (obs.source_j as u8) {
            (obs.source_i as usize, obs.source_j as usize)
        } else {
            (obs.source_j as usize, obs.source_i as usize)
        };
        let pair_idx = pair_index(si, sj);

        self.families[fam].observe(pair_idx, obs.compatible);

        let violation = if obs.compatible { 0.0 } else { 1.0 };
        self.global_rate = (1.0 - EWMA_ALPHA) * self.global_rate + EWMA_ALPHA * violation;

        if obs.is_stack_check {
            self.stack_rate = (1.0 - EWMA_ALPHA) * self.stack_rate + EWMA_ALPHA * violation;
        }

        // Periodic state update.
        if self.checks.is_multiple_of(COCYCLE_WINDOW as u64) {
            self.update_state();
        }
    }

    /// Update state based on accumulated violation rates.
    fn update_state(&mut self) {
        if self.checks < CALIBRATION_OBS {
            self.state = GlueState::Calibrating;
            return;
        }

        if self.stack_rate >= STACKIFICATION_THRESHOLD {
            if self.state != GlueState::StackificationFault {
                self.stack_fault_count += 1;
            }
            self.state = GlueState::StackificationFault;
        } else if self.global_rate >= DESCENT_FAILURE_THRESHOLD {
            if self.state != GlueState::DescentFailure {
                self.descent_failure_count += 1;
            }
            self.state = GlueState::DescentFailure;
        } else {
            self.state = GlueState::Coherent;
        }
    }

    /// Current state.
    #[must_use]
    pub fn state(&self) -> GlueState {
        self.state
    }

    /// Telemetry snapshot.
    #[must_use]
    pub fn snapshot(&self) -> GlueSnapshot {
        let mut family_rates = [0.0f64; NUM_QUERY_FAMILIES];
        let mut worst_pair = (0u8, 0u8);
        let mut worst_rate = 0.0f64;

        for (i, fam) in self.families.iter().enumerate() {
            family_rates[i] = fam.family_rate;
            for si in 0..NUM_SOURCES {
                for sj in (si + 1)..NUM_SOURCES {
                    let pidx = pair_index(si, sj);
                    if pidx < MAX_OVERLAP_PAIRS && fam.pair_rates[pidx] > worst_rate {
                        worst_rate = fam.pair_rates[pidx];
                        worst_pair = (si as u8, sj as u8);
                    }
                }
            }
        }

        GlueSnapshot {
            family_violation_rates: family_rates,
            global_violation_rate: self.global_rate,
            stack_violation_rate: self.stack_rate,
            state: self.state,
            checks: self.checks,
            descent_failure_count: self.descent_failure_count,
            stack_fault_count: self.stack_fault_count,
            worst_pair,
        }
    }
}

impl Default for GrothendieckGlueController {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute the pair index for sources i < j.
fn pair_index(i: usize, j: usize) -> usize {
    debug_assert!(i < j);
    // Triangular number: idx = j*(j-1)/2 + i
    j * (j - 1) / 2 + i
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_calibrating() {
        let ctrl = GrothendieckGlueController::new();
        assert_eq!(ctrl.state(), GlueState::Calibrating);
    }

    #[test]
    fn all_compatible_becomes_coherent() {
        let mut ctrl = GrothendieckGlueController::new();
        for _ in 0..512u64 {
            ctrl.observe_cocycle(&CocycleObservation {
                family: QueryFamily::Hostname,
                source_i: DataSource::Files,
                source_j: DataSource::Dns,
                compatible: true,
                is_stack_check: false,
            });
        }
        assert_eq!(ctrl.state(), GlueState::Coherent);
    }

    #[test]
    fn incompatible_triggers_descent_failure() {
        let mut ctrl = GrothendieckGlueController::new();
        // 50% incompatible — well above threshold.
        for i in 0..1024u64 {
            ctrl.observe_cocycle(&CocycleObservation {
                family: QueryFamily::Hostname,
                source_i: DataSource::Files,
                source_j: DataSource::Dns,
                compatible: i % 2 == 0,
                is_stack_check: false,
            });
        }
        assert!(
            ctrl.state() == GlueState::DescentFailure
                || ctrl.state() == GlueState::StackificationFault,
            "50% violation should trigger descent failure, got {:?}",
            ctrl.state()
        );
    }

    #[test]
    fn stack_incoherence_detected() {
        let mut ctrl = GrothendieckGlueController::new();
        // All stack checks fail.
        for _ in 0..1024 {
            ctrl.observe_cocycle(&CocycleObservation {
                family: QueryFamily::EncodingLookup,
                source_i: DataSource::IconvTables,
                source_j: DataSource::Fallback,
                compatible: false,
                is_stack_check: true,
            });
        }
        assert_eq!(
            ctrl.state(),
            GlueState::StackificationFault,
            "All-failing stack checks must trigger stackification fault"
        );
        assert!(ctrl.stack_fault_count > 0);
    }

    #[test]
    fn pair_index_computation() {
        assert_eq!(pair_index(0, 1), 0);
        assert_eq!(pair_index(0, 2), 1);
        assert_eq!(pair_index(1, 2), 2);
        assert_eq!(pair_index(0, 3), 3);
        assert_eq!(pair_index(1, 3), 4);
        assert_eq!(pair_index(2, 3), 5);
    }

    #[test]
    fn same_source_skipped() {
        let mut ctrl = GrothendieckGlueController::new();
        // Same-source observations should be silently ignored.
        for _ in 0..512 {
            ctrl.observe_cocycle(&CocycleObservation {
                family: QueryFamily::Hostname,
                source_i: DataSource::Files,
                source_j: DataSource::Files,
                compatible: false, // would be a violation if not skipped
                is_stack_check: false,
            });
        }
        assert_eq!(
            ctrl.snapshot().checks,
            0,
            "Same-source obs should be skipped"
        );
    }

    #[test]
    fn snapshot_fields() {
        let mut ctrl = GrothendieckGlueController::new();
        for _ in 0..512 {
            ctrl.observe_cocycle(&CocycleObservation {
                family: QueryFamily::Service,
                source_i: DataSource::Files,
                source_j: DataSource::Cache,
                compatible: true,
                is_stack_check: false,
            });
        }
        let snap = ctrl.snapshot();
        assert_eq!(snap.checks, 512);
        assert!(snap.global_violation_rate < 0.01);
    }

    #[test]
    fn descent_failure_counter_tracks_entries_not_duration() {
        let mut ctrl = GrothendieckGlueController::new();

        let coherent_obs = CocycleObservation {
            family: QueryFamily::Hostname,
            source_i: DataSource::Files,
            source_j: DataSource::Dns,
            compatible: true,
            is_stack_check: false,
        };
        let failing_obs = CocycleObservation {
            compatible: false,
            ..coherent_obs
        };

        // Establish coherent baseline.
        for _ in 0..COCYCLE_WINDOW {
            ctrl.observe_cocycle(&coherent_obs);
        }
        assert_eq!(ctrl.state(), GlueState::Coherent);

        // Enter descent failure once.
        for _ in 0..COCYCLE_WINDOW {
            ctrl.observe_cocycle(&failing_obs);
        }
        assert_eq!(ctrl.state(), GlueState::DescentFailure);
        let first_count = ctrl.snapshot().descent_failure_count;
        assert_eq!(first_count, 1);

        // Stay failed: counter should not increase while state is unchanged.
        for _ in 0..(2 * COCYCLE_WINDOW) {
            ctrl.observe_cocycle(&failing_obs);
        }
        assert_eq!(ctrl.snapshot().descent_failure_count, first_count);

        // Recover back to coherent.
        for _ in 0..(4 * COCYCLE_WINDOW) {
            ctrl.observe_cocycle(&coherent_obs);
        }
        assert_eq!(ctrl.state(), GlueState::Coherent);

        // Re-enter failure: counter increments once.
        for _ in 0..COCYCLE_WINDOW {
            ctrl.observe_cocycle(&failing_obs);
        }
        assert_eq!(ctrl.state(), GlueState::DescentFailure);
        assert_eq!(ctrl.snapshot().descent_failure_count, first_count + 1);
    }
}
