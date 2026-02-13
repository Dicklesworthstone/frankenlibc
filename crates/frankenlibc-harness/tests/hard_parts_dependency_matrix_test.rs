//! Integration test: hard-parts dependency matrix + risk register consistency (bd-y45u).

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn load_json(path: &Path) -> serde_json::Value {
    let content = std::fs::read_to_string(path).expect("json file should be readable");
    serde_json::from_str(&content).expect("json should parse")
}

fn has_cycle(graph: &HashMap<String, Vec<String>>) -> bool {
    fn visit(
        node: &str,
        graph: &HashMap<String, Vec<String>>,
        visiting: &mut HashSet<String>,
        visited: &mut HashSet<String>,
    ) -> bool {
        if visited.contains(node) {
            return false;
        }
        if !visiting.insert(node.to_string()) {
            return true;
        }

        if let Some(next) = graph.get(node) {
            for dep in next {
                if visit(dep, graph, visiting, visited) {
                    return true;
                }
            }
        }

        visiting.remove(node);
        visited.insert(node.to_string());
        false
    }

    let mut visiting = HashSet::new();
    let mut visited = HashSet::new();
    for node in graph.keys() {
        if visit(node, graph, &mut visiting, &mut visited) {
            return true;
        }
    }
    false
}

#[test]
fn hard_parts_dependency_matrix_artifact_exists_with_expected_schema() {
    let root = workspace_root();
    let path = root.join("tests/conformance/hard_parts_dependency_matrix.v1.json");
    assert!(path.exists(), "missing {}", path.display());

    let doc = load_json(&path);
    assert_eq!(doc["schema_version"].as_str(), Some("v1"));
    assert_eq!(doc["bead"].as_str(), Some("bd-y45u"));
    assert!(doc["trace_id"].is_string(), "trace_id is required");
    assert!(doc["dependency_matrix"].is_array());
    assert!(doc["risk_register"].is_array());
    assert!(doc["milestones"].is_array());
    assert!(doc["critical_path"].is_array());
    assert!(doc["parallel_tracks"].is_array());
    assert!(doc["validation"].is_object());
}

#[test]
fn required_subsystems_are_present_and_unique() {
    let root = workspace_root();
    let doc = load_json(&root.join("tests/conformance/hard_parts_dependency_matrix.v1.json"));
    let subsystems = doc["subsystems"].as_array().expect("subsystems must be array");

    let mut seen = HashSet::new();
    for s in subsystems {
        let name = s.as_str().expect("subsystem names must be strings");
        assert!(seen.insert(name), "duplicate subsystem {name}");
    }

    let required = ["startup", "threading", "resolver", "nss", "locale", "iconv"];
    for req in required {
        assert!(seen.contains(req), "required subsystem missing: {req}");
    }
}

#[test]
fn dependency_edges_reference_known_subsystems_and_contract_fields() {
    let root = workspace_root();
    let doc = load_json(&root.join("tests/conformance/hard_parts_dependency_matrix.v1.json"));

    let subsystems: HashSet<String> = doc["subsystems"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str().map(ToString::to_string))
        .collect();

    let milestones = doc["milestones"].as_array().expect("milestones must be array");

    for edge in doc["dependency_matrix"].as_array().unwrap() {
        let from = edge["from_subsystem"]
            .as_str()
            .expect("from_subsystem must be string");
        let to = edge["to_subsystem"]
            .as_str()
            .expect("to_subsystem must be string");

        assert!(subsystems.contains(from), "unknown from_subsystem: {from}");
        assert!(subsystems.contains(to), "unknown to_subsystem: {to}");
        assert!(edge["interface"].is_string(), "edge interface is required");
        assert!(edge["reason"].is_string(), "edge reason is required");

        let beads = edge["blocking_beads"]
            .as_array()
            .expect("blocking_beads must be array");
        assert!(!beads.is_empty(), "edge {from}->{to} must declare blocking beads");
        for bead in beads {
            let bead_id = bead.as_str().expect("bead id must be string");
            assert!(bead_id.starts_with("bd-"), "invalid bead id: {bead_id}");
        }

        let refs = edge["contract_refs"]
            .as_array()
            .expect("contract_refs must be array");
        assert!(!refs.is_empty(), "edge {from}->{to} must have contract refs");

        let covered_by_milestone = milestones.iter().any(|m| {
            let s = m["subsystems"].as_array().unwrap();
            let has_from = s.iter().any(|x| x.as_str() == Some(from));
            let has_to = s.iter().any(|x| x.as_str() == Some(to));
            has_from && has_to
        });
        assert!(
            covered_by_milestone,
            "edge {from}->{to} is not covered by any milestone subsystem set"
        );
    }
}

#[test]
fn risk_register_entries_have_actionable_mitigation_fields() {
    let root = workspace_root();
    let doc = load_json(&root.join("tests/conformance/hard_parts_dependency_matrix.v1.json"));

    let valid_levels: HashSet<&str> = ["low", "medium", "high"].into_iter().collect();
    let risks = doc["risk_register"].as_array().expect("risk_register must be array");
    assert!(!risks.is_empty(), "risk register must be non-empty");

    for risk in risks {
        let risk_id = risk["risk_id"].as_str().unwrap_or("<unknown>");
        let severity = risk["severity"].as_str().expect("severity must be string");
        let likelihood = risk["likelihood"].as_str().expect("likelihood must be string");

        assert!(valid_levels.contains(severity), "{risk_id}: invalid severity {severity}");
        assert!(
            valid_levels.contains(likelihood),
            "{risk_id}: invalid likelihood {likelihood}"
        );
        assert!(risk["failure_mode"].is_string(), "{risk_id}: missing failure_mode");
        assert!(risk["mitigation"].is_string(), "{risk_id}: missing mitigation");

        let owner_bead = risk["owner_bead"].as_str().expect("owner_bead must be string");
        assert!(owner_bead.starts_with("bd-"), "{risk_id}: invalid owner_bead {owner_bead}");

        let evidence = risk["evidence_paths"]
            .as_array()
            .expect("evidence_paths must be array");
        assert!(!evidence.is_empty(), "{risk_id}: missing evidence paths");
    }
}

#[test]
fn milestones_form_valid_acyclic_sequence_with_consistent_critical_path() {
    let root = workspace_root();
    let doc = load_json(&root.join("tests/conformance/hard_parts_dependency_matrix.v1.json"));
    let milestones = doc["milestones"].as_array().expect("milestones must be array");

    let mut ids = HashSet::new();
    let mut graph: HashMap<String, Vec<String>> = HashMap::new();
    let mut milestone_by_id: HashMap<String, &serde_json::Value> = HashMap::new();

    for m in milestones {
        let id = m["milestone_id"].as_str().expect("milestone_id must be string");
        assert!(ids.insert(id), "duplicate milestone id: {id}");
        milestone_by_id.insert(id.to_string(), m);

        let deps: Vec<String> = m["depends_on_milestones"]
            .as_array()
            .expect("depends_on_milestones must be array")
            .iter()
            .map(|v| {
                v.as_str()
                    .expect("dependency milestone id must be string")
                    .to_string()
            })
            .collect();
        graph.insert(id.to_string(), deps);

        let bead_refs = m["depends_on_beads"]
            .as_array()
            .expect("depends_on_beads must be array");
        assert!(!bead_refs.is_empty(), "{id}: depends_on_beads must be non-empty");
        for bead in bead_refs {
            let bead_id = bead.as_str().expect("bead id must be string");
            assert!(bead_id.starts_with("bd-"), "{id}: invalid bead id {bead_id}");
        }
    }

    for (id, deps) in &graph {
        for dep in deps {
            assert!(ids.contains(dep.as_str()), "{id}: unknown milestone dependency {dep}");
        }
    }
    assert!(!has_cycle(&graph), "milestone dependency graph must be acyclic");

    let critical = doc["critical_path"]
        .as_array()
        .expect("critical_path must be array");
    assert!(!critical.is_empty(), "critical path must be non-empty");

    for m in critical {
        let id = m.as_str().expect("critical path id must be string");
        assert!(ids.contains(id), "critical path references unknown milestone {id}");
    }

    for window in critical.windows(2) {
        let current = window[0].as_str().unwrap();
        let next = window[1].as_str().unwrap();
        let next_deps = graph.get(next).expect("critical path next must exist in graph");
        assert!(
            next_deps.contains(&current.to_string()),
            "critical path ordering requires {next} to depend on {current}"
        );
    }

    let first = critical.first().unwrap().as_str().unwrap();
    let first_deps = graph.get(first).unwrap();
    assert!(first_deps.is_empty(), "first critical path milestone must have no prerequisites");

    let last = critical.last().unwrap().as_str().unwrap();
    let last_node = milestone_by_id.get(last).unwrap();
    assert_eq!(
        last_node["parallelizable"].as_bool(),
        Some(false),
        "last critical milestone must be non-parallelizable closure gate"
    );
}

#[test]
fn parallel_tracks_reference_parallelizable_milestones() {
    let root = workspace_root();
    let doc = load_json(&root.join("tests/conformance/hard_parts_dependency_matrix.v1.json"));
    let milestones = doc["milestones"].as_array().unwrap();

    let mut parallelizable = HashSet::new();
    for m in milestones {
        if m["parallelizable"].as_bool().unwrap_or(false) {
            parallelizable.insert(
                m["milestone_id"]
                    .as_str()
                    .expect("milestone_id must be string")
                    .to_string(),
            );
        }
    }

    let tracks = doc["parallel_tracks"].as_array().expect("parallel_tracks must be array");
    assert!(tracks.len() >= 2, "must define at least two explicit parallel tracks");

    let mut track_ids = HashSet::new();
    for t in tracks {
        let track_id = t["track_id"].as_str().expect("track_id must be string");
        assert!(track_ids.insert(track_id), "duplicate track id {track_id}");

        let milestones = t["milestones"].as_array().expect("track milestones must be array");
        assert!(!milestones.is_empty(), "{track_id}: track milestones cannot be empty");

        for m in milestones {
            let mid = m.as_str().expect("track milestone id must be string");
            assert!(
                parallelizable.contains(mid),
                "{track_id}: track milestone {mid} must be marked parallelizable"
            );
        }
    }
}
