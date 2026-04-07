//! Runtime-math CPOMDP safety-feasibility proof gate.
//!
//! Bead: `bd-249m.4`
//!
//! Goal:
//! - Construct a finite CPOMDP abstraction for the live repair-policy decision
//!   problem and prove the abstraction is well posed.
//! - Solve the induced constrained linear program exactly over the convex hull of
//!   deterministic observation policies.
//! - Emit auditable JSON artifacts for the feasibility witness and epsilon
//!   sensitivity sweep.
//!
//! Scope:
//! - This gate proves a finite abstraction aligned to the live `pomdp_repair`
//!   controller's action set and risk-bucket observability story.
//! - It does not claim a full continuous-state proof for every possible runtime
//!   telemetry stream.

use crate::structured_log::{LogEmitter, LogEntry, LogLevel, Outcome, StreamKind};
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::Path;

const BEAD_ID: &str = "bd-249m.4";
const GATE: &str = "runtime_math_cpomdp_feasibility_proofs";
const RUN_ID: &str = "rtm-cpomdp-feasibility-proofs";
const EPSILON_TARGET: f64 = 0.001;
const THROUGHPUT_TARGET: f64 = 0.95;
const ROUND_SCALE: f64 = 1_000_000_000.0;

const STATES: [&str; 3] = ["Safe", "Suspicious", "Unsafe"];
const OBSERVATIONS: [&str; 4] = ["Clean", "Ambiguous", "BoundsAlert", "TemporalAlert"];
const ACTIONS: [&str; 4] = ["Allow", "Quarantine", "Repair", "Escalate"];

const INITIAL_BELIEF: [f64; 3] = [0.99, 0.008, 0.002];

// observation_likelihood[state][observation]
const OBS_LIKELIHOODS: [[f64; 4]; 3] = [
    [0.980, 0.015, 0.004, 0.001],
    [0.120, 0.480, 0.250, 0.150],
    [0.000_2, 0.019_8, 0.300, 0.680],
];

// transitions[action][from_state][to_state]
const TRANSITIONS: [[[f64; 3]; 3]; 4] = [
    [
        [0.995, 0.005, 0.0],
        [0.050, 0.800, 0.150],
        [0.0, 0.100, 0.900],
    ],
    [
        [0.998, 0.002, 0.0],
        [0.250, 0.650, 0.100],
        [0.050, 0.350, 0.600],
    ],
    [
        [0.997, 0.003, 0.0],
        [0.550, 0.400, 0.050],
        [0.200, 0.550, 0.250],
    ],
    [
        [0.999, 0.001, 0.0],
        [0.100, 0.800, 0.100],
        [0.020, 0.280, 0.700],
    ],
];

// Throughput counts operations completed without quarantine/escalation.
const ACTION_THROUGHPUT: [f64; 4] = [1.0, 0.40, 1.0, 0.0];

// Secondary tie-break: prefer fewer interventions among throughput-optimal policies.
const ACTION_INTERVENTION_COST: [f64; 4] = [0.0, 0.70, 0.08, 1.0];

const SENSITIVITY_EPSILONS: [f64; 7] = [0.0001, 0.0002, 0.0005, 0.001, 0.002, 0.005, 0.01];

#[derive(Debug, Clone, Copy, Serialize, PartialEq)]
pub struct CpomdpProofSummary {
    pub checks: usize,
    pub passed: usize,
    pub failed: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct CpomdpProofSources {
    pub proof_note: String,
    pub pomdp_repair_rs: String,
    pub runtime_math_mod_rs: String,
    pub log_path: String,
    pub report_path: String,
    pub feasibility_artifact: String,
    pub sensitivity_artifact: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct CpomdpBeliefPoint {
    pub observation: String,
    pub probability: f64,
    pub posterior: [f64; 3],
    pub unsafe_probability: f64,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct CpomdpLinearProgram {
    pub policy_vertex_count: usize,
    pub equality_constraints: usize,
    pub inequality_constraints: usize,
    pub nonnegativity_constraints: usize,
    pub dual_status: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct CpomdpPolicyArtifact {
    pub policy_name: String,
    pub actions: BTreeMap<String, String>,
    pub throughput: f64,
    pub unsafe_allow_probability: f64,
    pub intervention_cost: f64,
    pub feasible: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct CpomdpDualSolution {
    pub lambda: f64,
    pub objective: f64,
    pub attained_by_policy: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct CpomdpMixedPolicyWeight {
    pub policy_name: String,
    pub weight: f64,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct CpomdpPrimalSolution {
    pub objective: f64,
    pub achieved_throughput: f64,
    pub achieved_unsafe_allow_probability: f64,
    pub achieved_intervention_cost: f64,
    pub support: Vec<CpomdpMixedPolicyWeight>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct CpomdpExhaustiveSearchSummary {
    pub total_policies: usize,
    pub feasible_policies: usize,
    pub best_deterministic_policy: CpomdpPolicyArtifact,
    pub best_deterministic_matches_primal: bool,
    pub no_higher_throughput_feasible_policy_exists: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct CpomdpIntegrationReport {
    pub module_registered: bool,
    pub controller_cached: bool,
    pub snapshot_optimality_gap_present: bool,
    pub snapshot_divergence_counter_present: bool,
    pub failures: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct CpomdpFeasibilityArtifact {
    pub schema_version: &'static str,
    pub bead: &'static str,
    pub epsilon: f64,
    pub throughput_target: f64,
    pub state_space: Vec<String>,
    pub observation_space: Vec<String>,
    pub action_space: Vec<String>,
    pub initial_belief: [f64; 3],
    pub belief_support: Vec<CpomdpBeliefPoint>,
    pub transition_rows_normalized: bool,
    pub observation_rows_normalized: bool,
    pub linear_program: CpomdpLinearProgram,
    pub feasible_policy: CpomdpPolicyArtifact,
    pub primal_solution: CpomdpPrimalSolution,
    pub dual_solution: CpomdpDualSolution,
    pub exhaustive_search: CpomdpExhaustiveSearchSummary,
    pub integration: CpomdpIntegrationReport,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct CpomdpSensitivityPoint {
    pub epsilon: f64,
    pub best_policy_name: String,
    pub actions: BTreeMap<String, String>,
    pub throughput: f64,
    pub unsafe_allow_probability: f64,
    pub intervention_cost: f64,
    pub feasible_policies: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct CpomdpSensitivityArtifact {
    pub schema_version: &'static str,
    pub bead: &'static str,
    pub points: Vec<CpomdpSensitivityPoint>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct CpomdpProofReport {
    pub schema_version: &'static str,
    pub bead: &'static str,
    pub generated_at: String,
    pub sources: CpomdpProofSources,
    pub summary: CpomdpProofSummary,
    pub feasibility: CpomdpFeasibilityArtifact,
    pub sensitivity: CpomdpSensitivityArtifact,
}

#[derive(Debug, Clone, Copy)]
struct PolicyMetrics {
    encoded_id: usize,
    actions: [usize; 4],
    throughput: f64,
    unsafe_allow_probability: f64,
    intervention_cost: f64,
}

pub fn run_and_write(
    workspace_root: &Path,
    log_path: &Path,
    report_path: &Path,
    feasibility_artifact_path: &Path,
    sensitivity_artifact_path: &Path,
) -> Result<CpomdpProofReport, Box<dyn std::error::Error>> {
    let proof_note_path = workspace_root.join("docs/proofs/cpomdp_feasibility.md");
    let pomdp_repair_path =
        workspace_root.join("crates/frankenlibc-membrane/src/runtime_math/pomdp_repair.rs");
    let runtime_math_mod_path =
        workspace_root.join("crates/frankenlibc-membrane/src/runtime_math/mod.rs");

    for path in [
        log_path,
        report_path,
        feasibility_artifact_path,
        sensitivity_artifact_path,
    ] {
        std::fs::create_dir_all(
            path.parent()
                .ok_or_else(|| std::io::Error::other("output path must have a parent directory"))?,
        )?;
    }

    let mut emitter = LogEmitter::to_file(log_path, BEAD_ID, RUN_ID)?;

    let belief_support = build_belief_support();
    let transition_rows_normalized = rows_normalized_3d(&TRANSITIONS);
    let observation_rows_normalized = rows_normalized_2d(&OBS_LIKELIHOODS);

    let pomdp_src = std::fs::read_to_string(&pomdp_repair_path)?;
    let runtime_math_src = std::fs::read_to_string(&runtime_math_mod_path)?;
    let integration = inspect_runtime_math_integration(&pomdp_src, &runtime_math_src);

    let feasibility = compute_feasibility(EPSILON_TARGET, &belief_support, integration.clone());
    let sensitivity = compute_sensitivity(&belief_support);

    std::fs::write(
        feasibility_artifact_path,
        serde_json::to_string_pretty(&feasibility)?,
    )?;
    std::fs::write(
        sensitivity_artifact_path,
        serde_json::to_string_pretty(&sensitivity)?,
    )?;

    let mut checks = 0usize;
    let mut passed = 0usize;
    let mut failed = 0usize;

    checks += 1;
    if transition_rows_normalized {
        passed += 1;
    } else {
        failed += 1;
    }
    emitter.emit_entry(
        LogEntry::new("", LogLevel::Info, "runtime_math.cpomdp.transition_rows")
            .with_stream(StreamKind::Conformance)
            .with_gate(GATE)
            .with_api("runtime_math", "pomdp_repair")
            .with_outcome(if transition_rows_normalized {
                Outcome::Pass
            } else {
                Outcome::Fail
            })
            .with_latency_ns(1)
            .with_artifacts(vec![
                rel_path(workspace_root, feasibility_artifact_path),
                rel_path(workspace_root, report_path),
            ])
            .with_details(serde_json::json!({
                "decision_path": "proof->cpomdp->transition_rows",
                "state_count": STATES.len(),
                "action_count": ACTIONS.len(),
                "row_normalized": transition_rows_normalized,
            })),
    )?;

    checks += 1;
    if observation_rows_normalized {
        passed += 1;
    } else {
        failed += 1;
    }
    emitter.emit_entry(
        LogEntry::new("", LogLevel::Info, "runtime_math.cpomdp.observation_rows")
            .with_stream(StreamKind::Conformance)
            .with_gate(GATE)
            .with_api("runtime_math", "pomdp_repair")
            .with_outcome(if observation_rows_normalized {
                Outcome::Pass
            } else {
                Outcome::Fail
            })
            .with_latency_ns(1)
            .with_artifacts(vec![
                rel_path(workspace_root, feasibility_artifact_path),
                rel_path(workspace_root, report_path),
            ])
            .with_details(serde_json::json!({
                "decision_path": "proof->cpomdp->observation_rows",
                "belief_state_count": belief_support.len(),
                "row_normalized": observation_rows_normalized,
            })),
    )?;

    let feasible = feasibility.feasible_policy.feasible
        && feasibility.feasible_policy.unsafe_allow_probability <= EPSILON_TARGET + 1e-12
        && feasibility.feasible_policy.throughput >= THROUGHPUT_TARGET;
    checks += 1;
    if feasible {
        passed += 1;
    } else {
        failed += 1;
    }
    emitter.emit_entry(
        LogEntry::new("", LogLevel::Info, "runtime_math.cpomdp.feasible_policy")
            .with_stream(StreamKind::Conformance)
            .with_gate(GATE)
            .with_api("runtime_math", "pomdp_repair")
            .with_outcome(if feasible {
                Outcome::Pass
            } else {
                Outcome::Fail
            })
            .with_latency_ns(1)
            .with_artifacts(vec![
                rel_path(workspace_root, feasibility_artifact_path),
                rel_path(workspace_root, sensitivity_artifact_path),
            ])
            .with_details(serde_json::json!({
                "decision_path": "proof->cpomdp->feasible_policy",
                "epsilon": EPSILON_TARGET,
                "throughput": feasibility.feasible_policy.throughput,
                "unsafe_allow_probability": feasibility.feasible_policy.unsafe_allow_probability,
                "throughput_target": THROUGHPUT_TARGET,
                "actions": feasibility.feasible_policy.actions,
            })),
    )?;

    let duality_gap_ok =
        (feasibility.primal_solution.objective - feasibility.dual_solution.objective).abs() <= 1e-9;
    checks += 1;
    if duality_gap_ok {
        passed += 1;
    } else {
        failed += 1;
    }
    emitter.emit_entry(
        LogEntry::new("", LogLevel::Info, "runtime_math.cpomdp.lp_duality")
            .with_stream(StreamKind::Conformance)
            .with_gate(GATE)
            .with_api("runtime_math", "pomdp_repair")
            .with_outcome(if duality_gap_ok {
                Outcome::Pass
            } else {
                Outcome::Fail
            })
            .with_latency_ns(1)
            .with_artifacts(vec![
                rel_path(workspace_root, feasibility_artifact_path),
                rel_path(workspace_root, report_path),
            ])
            .with_details(serde_json::json!({
                "decision_path": "proof->cpomdp->lp_duality",
                "primal_objective": feasibility.primal_solution.objective,
                "dual_objective": feasibility.dual_solution.objective,
                "duality_gap": round9((feasibility.primal_solution.objective - feasibility.dual_solution.objective).abs()),
                "dual_lambda": feasibility.dual_solution.lambda,
            })),
    )?;

    let exhaustive_ok = feasibility
        .exhaustive_search
        .best_deterministic_matches_primal
        && feasibility
            .exhaustive_search
            .no_higher_throughput_feasible_policy_exists;
    checks += 1;
    if exhaustive_ok {
        passed += 1;
    } else {
        failed += 1;
    }
    emitter.emit_entry(
        LogEntry::new("", LogLevel::Info, "runtime_math.cpomdp.exhaustive_search")
            .with_stream(StreamKind::Conformance)
            .with_gate(GATE)
            .with_api("runtime_math", "pomdp_repair")
            .with_outcome(if exhaustive_ok {
                Outcome::Pass
            } else {
                Outcome::Fail
            })
            .with_latency_ns(1)
            .with_artifacts(vec![
                rel_path(workspace_root, feasibility_artifact_path),
                rel_path(workspace_root, report_path),
            ])
            .with_details(serde_json::json!({
                "decision_path": "proof->cpomdp->exhaustive_search",
                "total_policies": feasibility.exhaustive_search.total_policies,
                "feasible_policies": feasibility.exhaustive_search.feasible_policies,
                "best_policy": feasibility.exhaustive_search.best_deterministic_policy.policy_name,
                "best_policy_throughput": feasibility.exhaustive_search.best_deterministic_policy.throughput,
            })),
    )?;

    let sensitivity_ok = sensitivity
        .points
        .iter()
        .any(|point| point.epsilon == round9(EPSILON_TARGET))
        && sensitivity.points.len() == SENSITIVITY_EPSILONS.len();
    checks += 1;
    if sensitivity_ok {
        passed += 1;
    } else {
        failed += 1;
    }
    emitter.emit_entry(
        LogEntry::new("", LogLevel::Info, "runtime_math.cpomdp.sensitivity")
            .with_stream(StreamKind::Conformance)
            .with_gate(GATE)
            .with_api("runtime_math", "pomdp_repair")
            .with_outcome(if sensitivity_ok {
                Outcome::Pass
            } else {
                Outcome::Fail
            })
            .with_latency_ns(1)
            .with_artifacts(vec![
                rel_path(workspace_root, sensitivity_artifact_path),
                rel_path(workspace_root, report_path),
            ])
            .with_details(serde_json::json!({
                "decision_path": "proof->cpomdp->sensitivity",
                "epsilon_values": SENSITIVITY_EPSILONS,
                "point_count": sensitivity.points.len(),
            })),
    )?;

    let integration_ok = integration.failures.is_empty();
    checks += 1;
    if integration_ok {
        passed += 1;
    } else {
        failed += 1;
    }
    emitter.emit_entry(
        LogEntry::new("", LogLevel::Info, "runtime_math.cpomdp.integration")
            .with_stream(StreamKind::Conformance)
            .with_gate(GATE)
            .with_api("runtime_math", "pomdp_repair")
            .with_outcome(if integration_ok {
                Outcome::Pass
            } else {
                Outcome::Fail
            })
            .with_latency_ns(1)
            .with_artifacts(vec![
                rel_path(workspace_root, feasibility_artifact_path),
                rel_path(workspace_root, report_path),
            ])
            .with_details(serde_json::json!({
                "decision_path": "proof->cpomdp->integration",
                "module_registered": integration.module_registered,
                "controller_cached": integration.controller_cached,
                "snapshot_optimality_gap_present": integration.snapshot_optimality_gap_present,
                "snapshot_divergence_counter_present": integration.snapshot_divergence_counter_present,
                "failures": integration.failures,
            })),
    )?;

    emitter.flush()?;

    let report = CpomdpProofReport {
        schema_version: "v1",
        bead: BEAD_ID,
        generated_at: LogEntry::new("", LogLevel::Info, "generated").timestamp,
        sources: CpomdpProofSources {
            proof_note: rel_path(workspace_root, &proof_note_path),
            pomdp_repair_rs: rel_path(workspace_root, &pomdp_repair_path),
            runtime_math_mod_rs: rel_path(workspace_root, &runtime_math_mod_path),
            log_path: rel_path(workspace_root, log_path),
            report_path: rel_path(workspace_root, report_path),
            feasibility_artifact: rel_path(workspace_root, feasibility_artifact_path),
            sensitivity_artifact: rel_path(workspace_root, sensitivity_artifact_path),
        },
        summary: CpomdpProofSummary {
            checks,
            passed,
            failed,
        },
        feasibility,
        sensitivity,
    };

    std::fs::write(report_path, serde_json::to_string_pretty(&report)?)?;
    Ok(report)
}

fn compute_feasibility(
    epsilon: f64,
    belief_support: &[CpomdpBeliefPoint],
    integration: CpomdpIntegrationReport,
) -> CpomdpFeasibilityArtifact {
    let policies = enumerate_policies();
    let feasible_policies = policies
        .iter()
        .copied()
        .filter(|policy| policy.unsafe_allow_probability <= epsilon + 1e-12)
        .collect::<Vec<_>>();

    let best_deterministic = feasible_policies
        .iter()
        .copied()
        .max_by(policy_ordering)
        .expect("there must always be at least one feasible policy");

    let primal = solve_primal_lp(&policies, epsilon);
    let dual = solve_dual_lp(&policies, epsilon);

    let best_artifact = policy_artifact(best_deterministic, epsilon);
    let exhaustive = CpomdpExhaustiveSearchSummary {
        total_policies: policies.len(),
        feasible_policies: feasible_policies.len(),
        best_deterministic_policy: best_artifact.clone(),
        best_deterministic_matches_primal: (best_deterministic.throughput - primal.objective).abs()
            <= 1e-9,
        no_higher_throughput_feasible_policy_exists: feasible_policies
            .iter()
            .all(|policy| policy.throughput <= best_deterministic.throughput + 1e-12),
    };

    CpomdpFeasibilityArtifact {
        schema_version: "v1",
        bead: BEAD_ID,
        epsilon: round9(epsilon),
        throughput_target: THROUGHPUT_TARGET,
        state_space: STATES.iter().map(ToString::to_string).collect(),
        observation_space: OBSERVATIONS.iter().map(ToString::to_string).collect(),
        action_space: ACTIONS.iter().map(ToString::to_string).collect(),
        initial_belief: round_triplet(INITIAL_BELIEF),
        belief_support: belief_support.to_vec(),
        transition_rows_normalized: rows_normalized_3d(&TRANSITIONS),
        observation_rows_normalized: rows_normalized_2d(&OBS_LIKELIHOODS),
        linear_program: CpomdpLinearProgram {
            policy_vertex_count: policies.len(),
            equality_constraints: 1,
            inequality_constraints: 1,
            nonnegativity_constraints: policies.len(),
            dual_status: "exact_piecewise_linear".to_string(),
        },
        feasible_policy: best_artifact,
        primal_solution: primal,
        dual_solution: dual,
        exhaustive_search: exhaustive,
        integration,
    }
}

fn compute_sensitivity(belief_support: &[CpomdpBeliefPoint]) -> CpomdpSensitivityArtifact {
    let points = SENSITIVITY_EPSILONS
        .iter()
        .map(|&epsilon| {
            let feasibility = compute_feasibility(
                epsilon,
                belief_support,
                CpomdpIntegrationReport {
                    module_registered: true,
                    controller_cached: true,
                    snapshot_optimality_gap_present: true,
                    snapshot_divergence_counter_present: true,
                    failures: Vec::new(),
                },
            );
            CpomdpSensitivityPoint {
                epsilon: round9(epsilon),
                best_policy_name: feasibility.feasible_policy.policy_name.clone(),
                actions: feasibility.feasible_policy.actions.clone(),
                throughput: feasibility.feasible_policy.throughput,
                unsafe_allow_probability: feasibility.feasible_policy.unsafe_allow_probability,
                intervention_cost: feasibility.feasible_policy.intervention_cost,
                feasible_policies: feasibility.exhaustive_search.feasible_policies,
            }
        })
        .collect();

    CpomdpSensitivityArtifact {
        schema_version: "v1",
        bead: BEAD_ID,
        points,
    }
}

fn build_belief_support() -> Vec<CpomdpBeliefPoint> {
    (0..OBSERVATIONS.len())
        .map(|obs_idx| {
            let probability = round9(observation_probability(obs_idx));
            let posterior = posterior_belief(obs_idx);
            CpomdpBeliefPoint {
                observation: OBSERVATIONS[obs_idx].to_string(),
                probability,
                posterior,
                unsafe_probability: posterior[2],
            }
        })
        .collect()
}

fn enumerate_policies() -> Vec<PolicyMetrics> {
    let policy_count = ACTIONS.len().pow(OBSERVATIONS.len() as u32);
    let observation_probabilities = (0..OBSERVATIONS.len())
        .map(observation_probability)
        .collect::<Vec<_>>();
    let unsafe_observation_mass = (0..OBSERVATIONS.len())
        .map(|idx| INITIAL_BELIEF[2] * OBS_LIKELIHOODS[2][idx])
        .collect::<Vec<_>>();

    (0..policy_count)
        .map(|encoded_id| {
            let actions = decode_policy(encoded_id);
            let mut throughput = 0.0;
            let mut unsafe_allow_probability = 0.0;
            let mut intervention_cost = 0.0;

            for (obs_idx, &action_idx) in actions.iter().enumerate() {
                throughput += observation_probabilities[obs_idx] * ACTION_THROUGHPUT[action_idx];
                intervention_cost +=
                    observation_probabilities[obs_idx] * ACTION_INTERVENTION_COST[action_idx];
                if action_idx == 0 {
                    unsafe_allow_probability += unsafe_observation_mass[obs_idx];
                }
            }

            PolicyMetrics {
                encoded_id,
                actions,
                throughput: round9(throughput),
                unsafe_allow_probability: round9(unsafe_allow_probability),
                intervention_cost: round9(intervention_cost),
            }
        })
        .collect()
}

fn solve_primal_lp(policies: &[PolicyMetrics], epsilon: f64) -> CpomdpPrimalSolution {
    let mut best_candidate = LpCandidate::sentinel();

    for policy in policies {
        if policy.unsafe_allow_probability <= epsilon + 1e-12 {
            update_best_lp_candidate(
                &mut best_candidate,
                LpCandidate {
                    throughput: policy.throughput,
                    intervention_cost: policy.intervention_cost,
                    safety: policy.unsafe_allow_probability,
                    support: vec![(policy.encoded_id, 1.0)],
                },
            );
        }
    }

    for (i, lhs) in policies.iter().enumerate() {
        for rhs in policies.iter().skip(i + 1) {
            if (lhs.unsafe_allow_probability - rhs.unsafe_allow_probability).abs() <= 1e-12 {
                continue;
            }

            let weight_lhs = (epsilon - rhs.unsafe_allow_probability)
                / (lhs.unsafe_allow_probability - rhs.unsafe_allow_probability);
            let weight_rhs = 1.0 - weight_lhs;

            if !(-1e-12..=1.0 + 1e-12).contains(&weight_lhs)
                || !(-1e-12..=1.0 + 1e-12).contains(&weight_rhs)
            {
                continue;
            }

            let throughput = round9(weight_lhs * lhs.throughput + weight_rhs * rhs.throughput);
            let intervention_cost =
                round9(weight_lhs * lhs.intervention_cost + weight_rhs * rhs.intervention_cost);
            let safety = round9(
                weight_lhs * lhs.unsafe_allow_probability
                    + weight_rhs * rhs.unsafe_allow_probability,
            );
            update_best_lp_candidate(
                &mut best_candidate,
                LpCandidate {
                    throughput,
                    intervention_cost,
                    safety,
                    support: vec![
                        (lhs.encoded_id, round9(weight_lhs.clamp(0.0, 1.0))),
                        (rhs.encoded_id, round9(weight_rhs.clamp(0.0, 1.0))),
                    ],
                },
            );
        }
    }

    let support = best_candidate
        .support
        .iter()
        .filter(|(_, weight)| *weight > 0.0)
        .map(|(policy_id, weight)| CpomdpMixedPolicyWeight {
            policy_name: policy_name(*policy_id),
            weight: round9(*weight),
        })
        .collect::<Vec<_>>();

    CpomdpPrimalSolution {
        objective: round9(best_candidate.throughput),
        achieved_throughput: round9(best_candidate.throughput),
        achieved_unsafe_allow_probability: round9(best_candidate.safety),
        achieved_intervention_cost: round9(best_candidate.intervention_cost),
        support,
    }
}

fn solve_dual_lp(policies: &[PolicyMetrics], epsilon: f64) -> CpomdpDualSolution {
    let mut candidates = vec![0.0];
    for (i, lhs) in policies.iter().enumerate() {
        for rhs in policies.iter().skip(i + 1) {
            let ds = lhs.unsafe_allow_probability - rhs.unsafe_allow_probability;
            let dt = lhs.throughput - rhs.throughput;
            if ds.abs() <= 1e-12 {
                continue;
            }
            let lambda = dt / ds;
            if lambda.is_finite() && lambda >= 0.0 {
                candidates.push(round9(lambda));
            }
        }
    }

    let mut best_lambda = 0.0;
    let mut best_objective = f64::INFINITY;
    let mut best_policy = 0usize;

    for lambda in candidates {
        let mut max_adjusted = f64::NEG_INFINITY;
        let mut argmax_policy = 0usize;
        for policy in policies {
            let adjusted = policy.throughput - lambda * policy.unsafe_allow_probability;
            if adjusted > max_adjusted + 1e-12
                || ((adjusted - max_adjusted).abs() <= 1e-12 && policy.encoded_id < argmax_policy)
            {
                max_adjusted = adjusted;
                argmax_policy = policy.encoded_id;
            }
        }
        let objective = round9(lambda * epsilon + max_adjusted);
        if objective < best_objective - 1e-12
            || ((objective - best_objective).abs() <= 1e-12 && lambda < best_lambda)
        {
            best_objective = objective;
            best_lambda = round9(lambda);
            best_policy = argmax_policy;
        }
    }

    CpomdpDualSolution {
        lambda: best_lambda,
        objective: round9(best_objective),
        attained_by_policy: policy_name(best_policy),
    }
}

#[derive(Debug, Clone)]
struct LpCandidate {
    throughput: f64,
    intervention_cost: f64,
    safety: f64,
    support: Vec<(usize, f64)>,
}

impl LpCandidate {
    fn sentinel() -> Self {
        Self {
            throughput: f64::NEG_INFINITY,
            intervention_cost: f64::INFINITY,
            safety: f64::INFINITY,
            support: Vec::new(),
        }
    }

    fn outranks(&self, incumbent: &Self) -> bool {
        let better_throughput = self.throughput > incumbent.throughput + 1e-12;
        let same_throughput = (self.throughput - incumbent.throughput).abs() <= 1e-12;
        let lower_intervention = self.intervention_cost < incumbent.intervention_cost - 1e-12;
        let same_intervention =
            (self.intervention_cost - incumbent.intervention_cost).abs() <= 1e-12;
        let lower_safety = self.safety < incumbent.safety - 1e-12;

        better_throughput
            || (same_throughput && (lower_intervention || (same_intervention && lower_safety)))
    }
}

fn update_best_lp_candidate(best_candidate: &mut LpCandidate, candidate: LpCandidate) {
    if candidate.outranks(best_candidate) {
        *best_candidate = candidate;
    }
}

fn policy_artifact(policy: PolicyMetrics, epsilon: f64) -> CpomdpPolicyArtifact {
    CpomdpPolicyArtifact {
        policy_name: policy_name(policy.encoded_id),
        actions: policy_actions(policy.actions),
        throughput: policy.throughput,
        unsafe_allow_probability: policy.unsafe_allow_probability,
        intervention_cost: policy.intervention_cost,
        feasible: policy.unsafe_allow_probability <= epsilon + 1e-12,
    }
}

fn policy_name(encoded_id: usize) -> String {
    format!("pi_{encoded_id:03}")
}

fn policy_actions(actions: [usize; 4]) -> BTreeMap<String, String> {
    OBSERVATIONS
        .iter()
        .enumerate()
        .map(|(obs_idx, obs)| ((*obs).to_string(), ACTIONS[actions[obs_idx]].to_string()))
        .collect()
}

fn policy_ordering(lhs: &PolicyMetrics, rhs: &PolicyMetrics) -> std::cmp::Ordering {
    lhs.throughput
        .partial_cmp(&rhs.throughput)
        .unwrap_or(std::cmp::Ordering::Equal)
        .then_with(|| {
            rhs.intervention_cost
                .partial_cmp(&lhs.intervention_cost)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .then_with(|| {
            rhs.unsafe_allow_probability
                .partial_cmp(&lhs.unsafe_allow_probability)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
}

fn decode_policy(mut encoded_id: usize) -> [usize; 4] {
    let mut actions = [0usize; 4];
    for action in &mut actions {
        *action = encoded_id % ACTIONS.len();
        encoded_id /= ACTIONS.len();
    }
    actions
}

fn observation_probability(obs_idx: usize) -> f64 {
    round9(
        INITIAL_BELIEF[0] * OBS_LIKELIHOODS[0][obs_idx]
            + INITIAL_BELIEF[1] * OBS_LIKELIHOODS[1][obs_idx]
            + INITIAL_BELIEF[2] * OBS_LIKELIHOODS[2][obs_idx],
    )
}

fn posterior_belief(obs_idx: usize) -> [f64; 3] {
    let denom = observation_probability(obs_idx);
    let safe = INITIAL_BELIEF[0] * OBS_LIKELIHOODS[0][obs_idx] / denom;
    let suspicious = INITIAL_BELIEF[1] * OBS_LIKELIHOODS[1][obs_idx] / denom;
    let unsafe_state = INITIAL_BELIEF[2] * OBS_LIKELIHOODS[2][obs_idx] / denom;
    round_triplet([safe, suspicious, unsafe_state])
}

fn round_triplet(values: [f64; 3]) -> [f64; 3] {
    [round9(values[0]), round9(values[1]), round9(values[2])]
}

fn round9(value: f64) -> f64 {
    (value * ROUND_SCALE).round() / ROUND_SCALE
}

fn rows_normalized_2d(matrix: &[[f64; 4]; 3]) -> bool {
    matrix
        .iter()
        .all(|row| (row.iter().sum::<f64>() - 1.0).abs() <= 1e-12)
}

fn rows_normalized_3d(matrix: &[[[f64; 3]; 3]; 4]) -> bool {
    matrix.iter().all(|action| {
        action
            .iter()
            .all(|row| (row.iter().sum::<f64>() - 1.0).abs() <= 1e-12)
    })
}

fn inspect_runtime_math_integration(
    pomdp_src: &str,
    runtime_math_src: &str,
) -> CpomdpIntegrationReport {
    let module_registered = runtime_math_src.contains("pub mod pomdp_repair;");
    let controller_cached = runtime_math_src.contains("pomdp: Mutex<PomdpRepairController>")
        && runtime_math_src.contains("cached_pomdp_state");
    let snapshot_optimality_gap_present = runtime_math_src.contains("pomdp_optimality_gap");
    let snapshot_divergence_counter_present = runtime_math_src.contains("pomdp_divergence_count");

    let mut failures = Vec::new();
    if !module_registered {
        failures.push("runtime_math mod no longer registers pomdp_repair".to_string());
    }
    if !controller_cached {
        failures
            .push("runtime_math kernel no longer caches PomdpRepairController state".to_string());
    }
    if !snapshot_optimality_gap_present {
        failures.push("runtime_math snapshot missing pomdp_optimality_gap".to_string());
    }
    if !snapshot_divergence_counter_present {
        failures.push("runtime_math snapshot missing pomdp_divergence_count".to_string());
    }
    if !pomdp_src.contains("proof_cpomdp_safety_feasibility") {
        failures.push("pomdp_repair.rs missing embedded CPOMDP feasibility proof test".to_string());
    }

    CpomdpIntegrationReport {
        module_registered,
        controller_cached,
        snapshot_optimality_gap_present,
        snapshot_divergence_counter_present,
        failures,
    }
}

fn rel_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}
