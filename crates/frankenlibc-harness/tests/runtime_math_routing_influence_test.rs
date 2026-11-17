//! Integration gate test for `bd-reality-202609-lx578q.4`:
//! verifies that `tests/conformance/runtime_math_routing_inventory.v1.json`
//! stays synchronized with the live routing definitions in
//! `crates/frankenlibc-abi/src/runtime_policy.rs` and
//! `crates/frankenlibc-membrane/src/runtime_math/mod.rs`, and that the
//! causal release-ABI routing influence gate script is present and executable.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq)]
enum JsonVal {
    Null,
    Bool(bool),
    Int(i64),
    Str(String),
    Arr(Vec<JsonVal>),
    Obj(BTreeMap<String, JsonVal>),
}

impl JsonVal {
    fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(s) => Some(s.as_str()),
            _ => None,
        }
    }

    fn as_u64(&self) -> Option<u64> {
        match self {
            Self::Int(v) if *v >= 0 => Some(*v as u64),
            _ => None,
        }
    }

    fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(b) => Some(*b),
            _ => None,
        }
    }

    fn as_array(&self) -> Option<&[JsonVal]> {
        match self {
            Self::Arr(v) => Some(v.as_slice()),
            _ => None,
        }
    }

    fn as_object(&self) -> Option<&BTreeMap<String, JsonVal>> {
        match self {
            Self::Obj(m) => Some(m),
            _ => None,
        }
    }

    fn get(&self, key: &str) -> &JsonVal {
        static NULL: JsonVal = JsonVal::Null;
        match self {
            Self::Obj(m) => m.get(key).unwrap_or(&NULL),
            _ => &NULL,
        }
    }
}

struct JsonParser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> JsonParser<'a> {
    fn new(src: &'a str) -> Self {
        Self {
            bytes: src.as_bytes(),
            pos: 0,
        }
    }

    fn skip_ws(&mut self) {
        while self.pos < self.bytes.len() && self.bytes[self.pos].is_ascii_whitespace() {
            self.pos += 1;
        }
    }

    fn parse_value(&mut self) -> JsonVal {
        self.skip_ws();
        match self.bytes[self.pos] {
            b'"' => JsonVal::Str(self.parse_string()),
            b'{' => self.parse_object(),
            b'[' => self.parse_array(),
            b't' => {
                assert_eq!(&self.bytes[self.pos..self.pos + 4], b"true");
                self.pos += 4;
                JsonVal::Bool(true)
            }
            b'f' => {
                assert_eq!(&self.bytes[self.pos..self.pos + 5], b"false");
                self.pos += 5;
                JsonVal::Bool(false)
            }
            b'n' => {
                assert_eq!(&self.bytes[self.pos..self.pos + 4], b"null");
                self.pos += 4;
                JsonVal::Null
            }
            b'-' | b'0'..=b'9' => self.parse_int(),
            other => panic!("unexpected JSON byte {:?} at {}", other as char, self.pos),
        }
    }

    fn parse_string(&mut self) -> String {
        assert_eq!(self.bytes[self.pos], b'"');
        self.pos += 1;
        let mut out = String::new();
        while self.pos < self.bytes.len() {
            let b = self.bytes[self.pos];
            self.pos += 1;
            if b == b'"' {
                return out;
            }
            if b == b'\\' {
                let esc = self.bytes[self.pos];
                self.pos += 1;
                match esc {
                    b'"' => out.push('"'),
                    b'\\' => out.push('\\'),
                    b'/' => out.push('/'),
                    b'n' => out.push('\n'),
                    b'r' => out.push('\r'),
                    b't' => out.push('\t'),
                    other => panic!("unsupported JSON escape \\{}", other as char),
                }
            } else {
                out.push(b as char);
            }
        }
        panic!("unterminated JSON string");
    }

    fn parse_int(&mut self) -> JsonVal {
        let start = self.pos;
        if self.bytes[self.pos] == b'-' {
            self.pos += 1;
        }
        while self.pos < self.bytes.len() && self.bytes[self.pos].is_ascii_digit() {
            self.pos += 1;
        }
        let s = std::str::from_utf8(&self.bytes[start..self.pos]).expect("ascii digits");
        JsonVal::Int(s.parse::<i64>().expect("valid integer"))
    }

    fn parse_array(&mut self) -> JsonVal {
        assert_eq!(self.bytes[self.pos], b'[');
        self.pos += 1;
        let mut items = Vec::new();
        self.skip_ws();
        if self.bytes[self.pos] == b']' {
            self.pos += 1;
            return JsonVal::Arr(items);
        }
        loop {
            items.push(self.parse_value());
            self.skip_ws();
            match self.bytes[self.pos] {
                b',' => self.pos += 1,
                b']' => {
                    self.pos += 1;
                    return JsonVal::Arr(items);
                }
                other => panic!("expected ',' or ']', got {:?}", other as char),
            }
        }
    }

    fn parse_object(&mut self) -> JsonVal {
        assert_eq!(self.bytes[self.pos], b'{');
        self.pos += 1;
        let mut map = BTreeMap::new();
        self.skip_ws();
        if self.bytes[self.pos] == b'}' {
            self.pos += 1;
            return JsonVal::Obj(map);
        }
        loop {
            self.skip_ws();
            let key = self.parse_string();
            self.skip_ws();
            assert_eq!(self.bytes[self.pos], b':');
            self.pos += 1;
            let val = self.parse_value();
            map.insert(key, val);
            self.skip_ws();
            match self.bytes[self.pos] {
                b',' => self.pos += 1,
                b'}' => {
                    self.pos += 1;
                    return JsonVal::Obj(map);
                }
                other => panic!("expected ',' or '}}', got {:?}", other as char),
            }
        }
    }
}

fn parse_json(raw: &str) -> JsonVal {
    let mut p = JsonParser::new(raw);
    let val = p.parse_value();
    p.skip_ws();
    assert_eq!(p.pos, p.bytes.len(), "trailing bytes after JSON document");
    val
}

fn workspace_root() -> PathBuf {
    if let Some(manifest_dir) = option_env!("CARGO_MANIFEST_DIR") {
        Path::new(manifest_dir)
            .parent()
            .and_then(Path::parent)
            .expect("workspace root must exist")
            .to_path_buf()
    } else {
        std::env::current_dir().expect("cwd must exist")
    }
}

#[test]
fn runtime_math_routing_inventory_matches_source_routes() {
    let root = workspace_root();
    let inv_path = root.join("tests/conformance/runtime_math_routing_inventory.v1.json");
    let inv_raw = fs::read_to_string(&inv_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", inv_path.display()));
    let inv = parse_json(&inv_raw);

    assert_eq!(
        inv.get("schema_version").as_str(),
        Some("runtime_math_routing_inventory.v1")
    );
    assert_eq!(
        inv.get("bead_id").as_str(),
        Some("bd-reality-202609-lx578q.4")
    );

    let rp_path = root.join("crates/frankenlibc-abi/src/runtime_policy.rs");
    let rp_src = fs::read_to_string(&rp_path).expect("runtime_policy.rs must be readable");
    let mod_path = root.join("crates/frankenlibc-membrane/src/runtime_math/mod.rs");
    let mod_src = fs::read_to_string(&mod_path).expect("runtime_math/mod.rs must be readable");

    assert!(
        mod_src.contains("pub const COUNT: usize = 20;"),
        "ApiFamily::COUNT must match inventory count 20"
    );

    let gates = inv
        .get("decision_gates")
        .as_array()
        .expect("decision_gates must be an array");
    assert_eq!(gates.len(), 5, "expected 5 distinct decision gate labels");
    for gate in gates {
        let gate_str = gate.as_str().expect("gate label must be string");
        let needle = format!("\"{gate_str}\"");
        assert!(
            rp_src.contains(&needle),
            "runtime_policy.rs missing decision gate constant {needle}"
        );
    }

    let families = inv
        .get("families")
        .as_array()
        .expect("families must be an array");
    assert_eq!(
        families.len(),
        20,
        "inventory must cover all 20 ApiFamily variants"
    );

    let expected_hot_cached: BTreeSet<&str> = [
        "Allocator",
        "StringMemory",
        "Stdio",
        "MathFenv",
        "Loader",
        "Stdlib",
        "Ctype",
    ]
    .into_iter()
    .collect();

    let expected_strict_hot: BTreeSet<&str> = [
        "Allocator",
        "StringMemory",
        "Stdio",
        "Resolver",
        "MathFenv",
        "Loader",
        "Stdlib",
        "Ctype",
        "Time",
        "Locale",
        "Inet",
        "VirtualMemory",
    ]
    .into_iter()
    .collect();

    let mut seen_indices = BTreeSet::new();
    let mut pcc_total_from_families = 0usize;
    let mut observed_hot_cached = BTreeSet::new();
    let mut observed_strict_hot = BTreeSet::new();

    for entry in families {
        let idx = entry.get("index").as_u64().expect("family index") as usize;
        let variant = entry.get("variant").as_str().expect("family variant");
        let enum_decl = format!("{variant} = {idx},");
        assert!(
            mod_src.contains(&enum_decl),
            "runtime_math/mod.rs missing enum variant `{enum_decl}`"
        );
        assert!(seen_indices.insert(idx), "duplicate family index {idx}");

        if entry.get("hardened_hot_cached").as_bool() == Some(true) {
            observed_hot_cached.insert(variant);
        }
        if entry.get("strict_cfg_not_test").as_str() == Some("strict_passthrough_hot") {
            observed_strict_hot.insert(variant);
        }
        pcc_total_from_families += entry.get("ffi_pcc_count").as_u64().unwrap_or(0) as usize;
    }

    assert_eq!(observed_hot_cached, expected_hot_cached);
    assert_eq!(observed_strict_hot, expected_strict_hot);
    assert_eq!(
        inv.get("ffi_pcc_certificate_count").as_u64(),
        Some(24),
        "FFI_PCC_CERTIFICATES has 24 entries"
    );
    assert_eq!(pcc_total_from_families, 24);

    let pcc_by_family = inv
        .get("ffi_pcc_symbols_by_family")
        .as_object()
        .expect("ffi_pcc_symbols_by_family object");
    let mut sym_map: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut sym_count = 0usize;
    for (fam, arr) in pcc_by_family {
        let list = arr.as_array().expect("symbol list");
        for sym in list {
            let s = sym.as_str().expect("symbol string");
            let cert_needle = format!("\"{s}\",\n        ApiFamily::{fam},");
            assert!(
                rp_src.contains(&cert_needle),
                "runtime_policy.rs missing FFI-PCC certificate entry for {fam}::{s}"
            );
            sym_map.entry(fam.clone()).or_default().push(s.to_string());
            sym_count += 1;
        }
    }
    assert_eq!(sym_count, 24);
    assert_eq!(sym_map["Allocator"].len(), 7);
    assert_eq!(sym_map["StringMemory"].len(), 15);
    assert_eq!(sym_map["Stdio"].len(), 2);
}

#[test]
fn causal_consumers_and_gate_script_are_wired_in_source() {
    let root = workspace_root();

    let tls_src = fs::read_to_string(root.join("crates/frankenlibc-membrane/src/tls_cache.rs"))
        .expect("tls_cache.rs must exist");
    assert!(tls_src.contains("pub fn warm_integrity_cadence_mask() -> u32"));
    assert!(tls_src.contains("pub fn set_warm_integrity_cadence_mask(mask: u32)"));

    let malloc_src = fs::read_to_string(root.join("crates/frankenlibc-abi/src/malloc_abi.rs"))
        .expect("malloc_abi.rs must exist");
    assert!(malloc_src.contains("pub(crate) fn known_remaining_for_decision("));

    let socket_src = fs::read_to_string(root.join("crates/frankenlibc-abi/src/socket_abi.rs"))
        .expect("socket_abi.rs must exist");
    assert!(socket_src.contains("tracked_region_fits_for_decision("));

    let io_src = fs::read_to_string(root.join("crates/frankenlibc-abi/src/io_abi.rs"))
        .expect("io_abi.rs must exist");
    assert!(io_src.contains("tracked_region_fits_for_decision("));

    let startup_src = fs::read_to_string(root.join("crates/frankenlibc-abi/src/startup_abi.rs"))
        .expect("startup_abi.rs must exist");
    assert!(startup_src.contains("pub unsafe extern \"C\" fn __frankenlibc_runtime_route_counts("));

    let map_src = fs::read_to_string(root.join("crates/frankenlibc-abi/version_scripts/libc.map"))
        .expect("libc.map must exist");
    assert!(map_src.contains("__frankenlibc_runtime_decision_snapshot;"));
    assert!(map_src.contains("__frankenlibc_runtime_route_counts;"));

    let gate_script = root.join("scripts/check_runtime_math_routing_influence_e2e.sh");
    let gate_src = fs::read_to_string(&gate_script).expect("gate script must exist");
    assert!(gate_src.contains("--hot-adverse"));
    assert!(gate_src.contains("--socket-adverse"));
    assert!(gate_src.contains("--bench-same-invocation"));
    assert!(gate_src.contains("LM_ID_NEWLM"));
}
