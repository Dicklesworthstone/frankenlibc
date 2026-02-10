# RuntimeKernelSnapshot Schema

This document defines the stable schema for `RuntimeKernelSnapshot` as emitted by `RuntimeMathKernel::snapshot(...)`.

- Schema version constant: `RUNTIME_KERNEL_SNAPSHOT_SCHEMA_VERSION = 1`

## Stability Policy

- Additive-only changes (adding new fields) are allowed without bumping the schema version.
- Any rename/removal/semantic change requires bumping the schema version and providing a fixture migration plan.
- Field names are treated as stable identifiers for harness diffing and golden snapshot regression gates.

## Fields

| Field | Type | Units | Expected Range | Meaning |
|---|---|---|---|---|
| `schema_version` | `u32` | count | >=0 | Snapshot schema version (see `RUNTIME_KERNEL_SNAPSHOT_SCHEMA_VERSION`). |
| `decisions` | `u64` | count | >=0 | Total number of `decide(...)` decisions produced by this kernel instance. |
| `consistency_faults` | `u64` | count | >=0 | Total overlap-consistency (cocycle) faults observed by the cohomology monitor. |
| `full_validation_trigger_ppm` | `u32` | ppm (1e-6) | 0..=1_000_000 | Controller threshold: risk ppm at/above which full validation is forced.  Units: ppm (0..=1_000_000). |
| `repair_trigger_ppm` | `u32` | ppm (1e-6) | 0..=1_000_000 | Controller threshold: risk ppm at/above which repair actions are allowed/forced.  Units: ppm (0..=1_000_000). |
| `sampled_risk_bonus_ppm` | `u32` | ppm (1e-6) | 0..=1_000_000 | Sampled high-order risk bonus (ppm) currently applied from `risk_engine`. |
| `pareto_cumulative_regret_milli` | `u64` | milli-units (1e-3) | >=0 | Cumulative regret tracked by the Pareto controller.  Units: milli-units (1e-3), monotone non-decreasing. |
| `pareto_cap_enforcements` | `u64` | count | >=0 | Number of times hard regret caps were enforced by Pareto routing. |
| `pareto_exhausted_families` | `u32` | families (count) | >=0 | Number of API families whose Pareto regret budget is exhausted for the current mode. |
| `quarantine_depth` | `usize` | elements (count) | >=0 | Current published allocator quarantine depth (temporal-safety budget). |
| `tropical_full_wcl_ns` | `u64` | ns | >=0 | Tropical worst-case latency for the full pipeline path (ns). |
| `spectral_edge_ratio` | `f64` | dimensionless | finite f64 (no NaN/Inf) | Spectral edge ratio (max_eigenvalue / median_eigenvalue). |
| `spectral_phase_transition` | `bool` | bool | {false,true} | Whether a spectral phase transition is active. |
| `signature_anomaly_score` | `f64` | dimensionless | >2 | Rough-path signature anomaly score (0 = normal, >2 = anomalous). |
| `signature_anomaly_count` | `u64` | events (count) | >=0 | Total rough-path anomaly detections. |
| `persistence_entropy` | `f64` | dimensionless | finite f64 (no NaN/Inf) | Persistence entropy of the validation cost point cloud. |
| `topo_anomaly_count` | `u64` | events (count) | >=0 | Total topological anomaly detections. |
| `anytime_max_e_value` | `f64` | dimensionless | finite f64 (no NaN/Inf) | Maximum anytime e-process value across runtime families. |
| `anytime_alarmed_families` | `u32` | families (count) | >=0 | Number of families currently in e-process alarm mode. |
| `cvar_max_robust_ns` | `u64` | ns | >=0 | Maximum robust CVaR latency estimate across families. |
| `cvar_alarmed_families` | `u32` | families (count) | >=0 | Number of families in CVaR alarm state. |
| `bridge_transport_distance` | `f64` | dimensionless | finite f64 (no NaN/Inf) | Schrödinger bridge transport distance (W_ε between current policy and equilibrium). |
| `bridge_transitioning` | `bool` | bool | {false,true} | Whether a regime transition is detected via optimal transport. |
| `ld_elevated_families` | `u32` | families (count) | >=0 | Number of families with elevated/critical large-deviation rate state. |
| `ld_max_anomaly_count` | `u64` | events (count) | >=0 | Maximum anomaly count across families in the large-deviation monitor. |
| `hji_safety_value` | `f64` | dimensionless | >0 | HJI reachability value at current discrete state (>0 = safe, ≤0 = breached). |
| `hji_breached` | `bool` | bool | {false,true} | Whether the system state is inside the backward reachable tube. |
| `mfg_mean_contention` | `f64` | dimensionless | 0..1 | Mean-field game empirical contention level (normalized 0..1). |
| `mfg_congestion_count` | `u64` | events (count) | >=0 | Mean-field game congestion collapse detections. |
| `padic_ultrametric_distance` | `f64` | dimensionless | finite f64 (no NaN/Inf) | p-adic ultrametric distance between current and baseline valuation profiles. |
| `padic_drift_count` | `u64` | events (count) | >=0 | p-adic regime drift detection count. |
| `symplectic_energy` | `f64` | dimensionless | finite f64 (no NaN/Inf) | Symplectic Hamiltonian energy (deadlock risk indicator, 0..N). |
| `symplectic_violation_count` | `u64` | events (count) | >=0 | Symplectic admissibility violation count. |
| `topos_violation_rate` | `f64` | dimensionless | 0..1 | Higher-topos descent violation rate (EWMA, 0..1). |
| `topos_violation_count` | `u64` | events (count) | >=0 | Higher-topos descent violation count. |
| `audit_martingale_value` | `f64` | dimensionless | finite f64 (no NaN/Inf) | Commitment audit martingale process value. |
| `audit_replay_count` | `u64` | events (count) | >=0 | Commitment audit replay detection count. |
| `changepoint_posterior_short_mass` | `f64` | dimensionless | 0..1 | Bayesian change-point posterior short-run-length mass (0..1). |
| `changepoint_count` | `u64` | events (count) | >=0 | Bayesian change-point detection count. |
| `conformal_empirical_coverage` | `f64` | dimensionless | 0..1 | Conformal prediction empirical coverage (0..1). |
| `conformal_violation_count` | `u64` | events (count) | >=0 | Conformal prediction coverage violation count. |
| `design_identifiability_ppm` | `u32` | ppm (1e-6) | 0..1e6 | Design-kernel identifiability score (0..1e6). |
| `design_selected_probes` | `u8` | count | >=0 | Number of heavy probes selected in the current budgeted plan. |
| `design_budget_ns` | `u64` | ns | >=0 | Probe-budget assigned by mode/controller. |
| `design_expected_cost_ns` | `u64` | ns | >=0 | Expected cost of selected probes. |
| `sparse_support_size` | `u8` | count | >=0 | Sparse-recovery latent support size. |
| `sparse_l1_energy` | `f64` | dimensionless | finite f64 (no NaN/Inf) | Sparse-recovery L1 energy. |
| `sparse_residual_ewma` | `f64` | dimensionless | finite f64 (no NaN/Inf) | Sparse-recovery residual EWMA. |
| `sparse_critical_count` | `u64` | events (count) | >=0 | Sparse-recovery critical detections. |
| `equivariant_alignment_ppm` | `u32` | ppm (1e-6) | 0..=1_000_000 | Equivariant controller alignment score (higher is more symmetric/stable). |
| `equivariant_drift_count` | `u64` | events (count) | >=0 | Equivariant drift detections. |
| `equivariant_fractured_count` | `u64` | events (count) | >=0 | Equivariant fractured-state detections. |
| `equivariant_dominant_orbit` | `u8` | count | >=0 | Most active runtime orbit class. |
| `fusion_bonus_ppm` | `u32` | ppm (1e-6) | 0..=1_000_000 | Robust fusion bonus currently applied to risk. |
| `fusion_entropy_milli` | `u32` | milli-units (1e-3) | 0..1000 | Fusion entropy (0..1000) over signal trust weights. |
| `fusion_drift_ppm` | `u32` | ppm (1e-6) | 0..=1_000_000 | Fusion weight-drift score in ppm. |
| `fusion_dominant_signal` | `u8` | count | >=0 | Dominant fused signal index. |
| `microlocal_active_strata` | `u8` | count | >=0 | Microlocal wavefront active strata count. |
| `microlocal_failure_rate` | `f64` | dimensionless | 0..1 | Microlocal propagation failure rate (EWMA, 0..1). |
| `microlocal_fault_count` | `u64` | events (count) | >=0 | Microlocal fault boundary detection count. |
| `serre_max_differential` | `f64` | dimensionless | finite f64 (no NaN/Inf) | Serre spectral sequence max differential density. |
| `serre_nontrivial_cells` | `u8` | count | >=0 | Serre spectral sequence non-trivial cell count. |
| `serre_lifting_count` | `u64` | events (count) | >=0 | Serre spectral sequence lifting failure count. |
| `clifford_grade2_energy` | `f64` | dimensionless | finite f64 (no NaN/Inf) | Clifford grade-2 (bivector) energy fraction. |
| `clifford_parity_imbalance` | `f64` | dimensionless | finite f64 (no NaN/Inf) | Clifford grade parity imbalance. |
| `clifford_violation_count` | `u64` | events (count) | >=0 | Clifford overlap violation count. |
| `ktheory_max_transport_distance` | `f64` | dimensionless | finite f64 (no NaN/Inf) | K-theory maximum transport distance across ABI families. |
| `ktheory_fracture_count` | `u64` | events (count) | >=0 | K-theory ABI fracture detection count. |
| `covering_coverage_fraction` | `f64` | dimensionless | 0..1 | Covering-array conformance coverage fraction (0..1). |
| `covering_gap_count` | `u64` | events (count) | >=0 | Covering-array coverage gap detection count. |
| `tstructure_max_violation_rate` | `f64` | dimensionless | 0..=1 (normalized) | Derived t-structure maximum ordering violation rate. |
| `tstructure_violation_count` | `u64` | events (count) | >=0 | Derived t-structure orthogonality violation count. |
| `atiyah_bott_euler_weight` | `f64` | dimensionless | finite f64 (no NaN/Inf) | Atiyah-Bott localization Euler weight. |
| `atiyah_bott_concentration_count` | `u64` | events (count) | >=0 | Atiyah-Bott concentrated anomaly detection count. |
| `pomdp_optimality_gap` | `f64` | dimensionless | 0..1 | POMDP repair optimality gap (0..1+). |
| `pomdp_divergence_count` | `u64` | events (count) | >=0 | POMDP policy divergence detection count. |
| `sos_max_stress` | `f64` | dimensionless | finite f64 (no NaN/Inf) | SOS invariant maximum stress fraction. |
| `sos_violation_count` | `u64` | events (count) | >=0 | SOS invariant violation event count. |
| `admm_primal_dual_gap` | `f64` | dimensionless | 0..∞ | ADMM primal-dual gap (0..∞, lower is better). |
| `admm_violation_count` | `u64` | events (count) | >=0 | ADMM constraint violation count. |
| `obstruction_norm` | `f64` | dimensionless | 0..∞ | Spectral-sequence obstruction norm (0..∞). |
| `obstruction_critical_count` | `u64` | events (count) | >=0 | Critical obstruction detection count. |
| `operator_norm_spectral_radius` | `f64` | dimensionless | finite f64 (no NaN/Inf) | Operator-norm spectral radius estimate. |
| `operator_norm_instability_count` | `u64` | events (count) | >=0 | Operator-norm instability detection count. |
| `provenance_shannon_entropy` | `f64` | dimensionless | 0..8 | Provenance Shannon entropy per byte (0..8, ideal = 8.0). |
| `provenance_renyi_h2` | `f64` | dimensionless | 0..8 | Provenance Rényi H₂ collision entropy per byte (0..8). |
| `provenance_collision_count` | `u64` | events (count) | >=0 | Provenance collision risk detection count. |
| `grobner_violation_rate` | `f64` | dimensionless | 0..1 | Grobner constraint violation rate (EWMA, 0..1). |
| `grobner_fault_count` | `u64` | events (count) | >=0 | Grobner structural fault detection count. |
| `grothendieck_violation_rate` | `f64` | dimensionless | 0..1 | Grothendieck glue global cocycle violation rate (EWMA, 0..1). |
| `grothendieck_stack_fault_count` | `u64` | events (count) | >=0 | Grothendieck stackification fault detection count. |
| `malliavin_sensitivity_norm` | `f64` | dimensionless | 0..∞ | Malliavin sensitivity norm (0..∞, higher = more fragile). |
| `malliavin_fragility_index` | `f64` | dimensionless | 0..1 | Malliavin fragility index (innovation-to-total variance ratio, 0..1). |
| `info_geo_geodesic_distance` | `f64` | dimensionless | 0..∞ | Information geometry aggregate geodesic distance from baseline (0..∞). |
| `info_geo_max_controller_distance` | `f64` | dimensionless | finite f64 (no NaN/Inf) | Information geometry max single-controller Fisher-Rao distance. |
| `matrix_conc_spectral_deviation` | `f64` | dimensionless | finite f64 (no NaN/Inf) | Matrix concentration spectral deviation from baseline covariance. |
| `matrix_conc_bernstein_bound` | `f64` | dimensionless | finite f64 (no NaN/Inf) | Matrix concentration Bernstein confidence bound. |
| `nerve_betti_0` | `u32` | count | >=0 | Nerve complex β₀ (connected components, 1 = cohesive). |
| `nerve_betti_1` | `u32` | count | >=0 | Nerve complex β₁ (1-cycles in correlation graph). |
| `wasserstein_aggregate_distance` | `f64` | dimensionless | 0..3 | Wasserstein drift aggregate distance from baseline (0..3). |
| `wasserstein_max_controller_distance` | `f64` | dimensionless | finite f64 (no NaN/Inf) | Wasserstein drift max single-controller distance. |
| `mmd_squared` | `f64` | dimensionless | 0..2 | Kernel MMD² estimate (0..2, higher = more discrepant). |
| `mmd_mean_shift_norm` | `f64` | dimensionless | finite f64 (no NaN/Inf) | Kernel MMD mean shift norm (Euclidean distance of means). |
| `pac_bayes_bound` | `f64` | dimensionless | 0..1 | PAC-Bayes generalization bound (0..1, lower = tighter). |
| `pac_bayes_kl_divergence` | `f64` | dimensionless | finite f64 (no NaN/Inf) | PAC-Bayes KL divergence from posterior to prior. |
| `pac_bayes_empirical_error` | `f64` | dimensionless | finite f64 (no NaN/Inf) | PAC-Bayes weighted empirical error rate. |
| `stein_ksd_squared` | `f64` | dimensionless | 0..∞ | Stein discrepancy KSD² estimate (0..∞). |
| `stein_max_score_deviation` | `f64` | dimensionless | finite f64 (no NaN/Inf) | Stein discrepancy max per-controller score deviation. |
| `lyapunov_exponent` | `f64` | dimensionless | finite f64 (no NaN/Inf) | Lyapunov stability exponent estimate (negative = stable). |
| `lyapunov_expansion_ratio` | `f64` | dimensionless | finite f64 (no NaN/Inf) | Lyapunov smoothed expansion ratio. |
| `rademacher_complexity` | `f64` | dimensionless | 0..∞ | Rademacher complexity estimate (0..∞, lower = better-regularized). |
| `rademacher_gen_gap_bound` | `f64` | dimensionless | finite f64 (no NaN/Inf) | Rademacher generalization gap bound (2R̂ + concentration). |
| `transfer_entropy_max_te` | `f64` | dimensionless | 0..∞ | Transfer entropy max pairwise TE (0..∞, higher = stronger causal coupling). |
| `transfer_entropy_mean_te` | `f64` | dimensionless | finite f64 (no NaN/Inf) | Transfer entropy mean pairwise TE. |
| `hodge_inconsistency_ratio` | `f64` | dimensionless | 0..1 | Hodge decomposition inconsistency ratio (0..1, 0 = coherent). |
| `hodge_curl_energy` | `f64` | dimensionless | finite f64 (no NaN/Inf) | Hodge decomposition curl energy (squared cycle residual). |
| `doob_drift_rate` | `f64` | dimensionless | finite f64 (no NaN/Inf) | Doob decomposition smoothed drift rate (mean |E[Xₙ₊₁|Xₙ] − Xₙ| across controllers). |
| `doob_max_drift` | `f64` | dimensionless | >=0 | Doob decomposition max per-controller cumulative predictable drift magnitude (|Aₙ|). |
| `fano_mean_mi` | `f64` | bits | >=0 | Fano mutual information bound mean MI across controllers (bits). |
| `fano_mean_bound` | `f64` | dimensionless | 0..1 | Fano error lower bound mean across controllers (0..1, higher = less predictable). |
| `dobrushin_max_contraction` | `f64` | dimensionless | 0..1 | Dobrushin contraction coefficient max across controllers (0..1). |
| `dobrushin_mean_contraction` | `f64` | dimensionless | 0..1 | Dobrushin contraction coefficient mean across controllers (0..1). |
| `coupling_divergence_bound` | `f64` | dimensionless | 0..1 | Coupling empirical divergence bound (`p_hat + eps`, clamped). |
| `coupling_certification_margin` | `f64` | dimensionless | finite f64 (no NaN/Inf) | Coupling certification margin (`threshold - bound`); positive indicates certified. |
| `loss_recommended_action` | `u8` | enum | 0..3 | Loss-minimizer recommended action (0=allow, 1=full-validate, 2=repair, 3=deny). |
| `loss_cost_explosion_count` | `u64` | count | >=0 | Loss-minimizer cost explosion detection count. |
