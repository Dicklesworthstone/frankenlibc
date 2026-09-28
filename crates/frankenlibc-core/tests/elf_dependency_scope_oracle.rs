//! Real DT_NEEDED graphs, checked against the host loader and the native planner.
//! Requires Python and a C compiler; missing prerequisites are failures, not skips.
//! Run: cargo test -p frankenlibc-core --test elf_dependency_scope_oracle
//! This tests parsing/scoped lookup/lifecycle planning, not native mapped execution.
#![cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use frankenlibc_core::elf::loader::{
    ElfLoader, LinkMapObject, LoadedObject, RtldLookupScope, RtldVisibility, ScopedSymbolResolver,
};

fn fixtures() -> &'static Path {
    static FIXTURES: OnceLock<PathBuf> = OnceLock::new();
    FIXTURES
        .get_or_init(|| {
            let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .expect("crates directory")
                .parent()
                .expect("workspace directory");
            let output = workspace.join("target/conformance").join(format!(
                "elf-dependency-scope-oracle-{}",
                std::process::id(),
            ));
            let probe = Command::new("python3")
                .arg(workspace.join("scripts/probe_loader_dependency_scope.py"))
                .arg("--output-dir")
                .arg(&output)
                .output()
                .expect("Python and a C compiler are required for this explicit oracle gate");
            assert!(
                probe.status.success(),
                "host oracle failed:\n{}\n{}",
                String::from_utf8_lossy(&probe.stdout),
                String::from_utf8_lossy(&probe.stderr)
            );
            output
        })
        .as_path()
}

fn load(name: &str, base: u64) -> LoadedObject {
    let bytes = std::fs::read(fixtures().join(format!("lib{name}.so")))
        .expect("oracle built the shared library");
    ElfLoader::new(base)
        .parse(&bytes)
        .expect("parse compiler-produced ELF")
}

#[test]
fn native_scope_matches_glibc_breadth_first_oracle() {
    let root = load("root", 0x10_0000);
    let left = load("left", 0x20_0000);
    let leaf = load("leaf", 0x30_0000);
    let right = load("right", 0x40_0000);
    assert_eq!(root.needed_libraries, vec!["libleft.so", "libright.so"]);
    assert_eq!(left.needed_libraries, vec!["libleaf.so"]);
    let resolver = ScopedSymbolResolver::new(vec![
        LinkMapObject {
            name: "libroot.so",
            object: &root,
            visibility: RtldVisibility::Local,
        },
        LinkMapObject {
            name: "libleft.so",
            object: &left,
            visibility: RtldVisibility::Local,
        },
        LinkMapObject {
            name: "libleaf.so",
            object: &leaf,
            visibility: RtldVisibility::Local,
        },
        LinkMapObject {
            name: "libright.so",
            object: &right,
            visibility: RtldVisibility::Local,
        },
    ])
    .expect("build native scope");
    assert_eq!(
        resolver.dependency_graph().local_lookup_order(0).unwrap(),
        vec![0, 1, 3, 2]
    );
    let provider = resolver
        .resolve("provider", None, RtldLookupScope::Local { object_index: 0 })
        .expect("valid scope")
        .expect("provider exists");
    assert_eq!(
        provider.object_index, 3,
        "same direct provider that returned 222 on glibc"
    );
    assert_eq!(
        provider.address,
        right.base + right.lookup_symbol("provider").unwrap().st_value
    );
}

#[test]
fn native_scope_accepts_compiler_produced_dependency_cycle() {
    let a = load("a", 0x10_0000);
    let b = load("b", 0x20_0000);
    assert_eq!(a.needed_libraries, vec!["libb.so"]);
    assert_eq!(b.needed_libraries, vec!["liba.so"]);
    let objects = vec![
        LinkMapObject {
            name: "liba.so",
            object: &a,
            visibility: RtldVisibility::Local,
        },
        LinkMapObject {
            name: "libb.so",
            object: &b,
            visibility: RtldVisibility::Local,
        },
    ];
    let graph = frankenlibc_core::elf::loader::DependencyGraph::build(&objects)
        .expect("glibc accepts this DT_NEEDED cycle");
    assert_eq!(graph.topological_order, vec![1, 0]);
    assert_eq!(graph.local_lookup_order(0).unwrap(), vec![0, 1]);
    let plan = graph
        .lifecycle_plan(&objects)
        .expect("cycle lifecycle plan");
    assert_eq!(
        plan.init_order
            .iter()
            .map(|entry| entry.object_index)
            .collect::<Vec<_>>(),
        vec![1, 0]
    );
    assert_eq!(
        plan.fini_order
            .iter()
            .map(|entry| entry.object_index)
            .collect::<Vec<_>>(),
        vec![0, 1]
    );
    let resolver = ScopedSymbolResolver::new(objects).expect("cyclic native scope");
    let provider = resolver
        .resolve(
            "cycle_from_b",
            None,
            RtldLookupScope::Local { object_index: 0 },
        )
        .expect("valid scope")
        .expect("dependency exports cycle_from_b");
    assert_eq!(provider.object_index, 1);
}
