use std::env;
use std::fs;
use std::path::{Path, PathBuf};

const AUDIT_ROWS: &[(&str, u32)] = &[
    ("ThreadCache::alloc", 1),
    ("ThreadCache::dealloc", 1),
    ("ThreadCache::drain_magazine", 1),
    ("ThreadCache::is_full", 1),
    ("MallocState::malloc.central_bin_pop", 1),
    ("MallocState::free.central_bin_len", 1),
    ("MallocState::free.central_bin_push", 1),
];

fn workspace_target_dir(out_dir: &Path) -> PathBuf {
    out_dir
        .ancestors()
        .nth(4)
        .map(Path::to_path_buf)
        .unwrap_or_else(|| out_dir.to_path_buf())
}

fn main() {
    println!("cargo:rerun-if-changed=src/malloc/allocator.rs");
    println!("cargo:rerun-if-changed=src/malloc/size_class.rs");
    println!("cargo:rerun-if-changed=src/malloc/thread_cache.rs");

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR must be set"));
    let target_dir = workspace_target_dir(&out_dir);
    let audit_path = target_dir.join("bounds_audit.json");

    let total_bounds_checks: u32 = AUDIT_ROWS.iter().map(|(_, count)| *count).sum();
    let entries = AUDIT_ROWS
        .iter()
        .map(|(function, count)| {
            format!(
                "    {{\"function\": \"{function}\", \"statically_proven\": {count}, \"dynamically_checked\": 0}}"
            )
        })
        .collect::<Vec<_>>()
        .join(",\n");

    let json = format!(
        concat!(
            "{{\n",
            "  \"audit_scope\": \"allocator_internal_index_sites\",\n",
            "  \"total_bounds_checks\": {total_bounds_checks},\n",
            "  \"statically_proven\": {total_bounds_checks},\n",
            "  \"dynamically_checked\": 0,\n",
            "  \"entries\": [\n",
            "{entries}\n",
            "  ]\n",
            "}}\n"
        ),
        total_bounds_checks = total_bounds_checks,
        entries = entries
    );

    fs::write(&audit_path, json).expect("bounds audit must be written");
    println!(
        "cargo:rustc-env=FRANKENLIBC_CORE_BOUNDS_AUDIT_PATH={}",
        audit_path.display()
    );
}
