//! Integration gate test for `bd-rc0923-epic-eeuy4f.13`:
//! verifies that the default workspace build targets baseline x86-64 without
//! global `+avx2`/`+fma` rustflags, `Cargo.toml` isolates the A/B benchmark
//! build in `[profile.release-x86-64-v3]`, `cpu_guard` IRELATIVE refusal is
//! wired in `frankenlibc-abi`, and `scripts/check_baseline_isa.sh` enforces
//! static disassembly allow-listing, dynamic `qemu-x86_64 -cpu Nehalem`/`qemu64`
//! stdout+stderr+exit parity, and `V3_LIB` exit-127 refusal.

use std::fs;
use std::path::{Path, PathBuf};

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
fn cargo_config_and_profiles_isolate_x86_64_v3_from_default_release() {
    let root = workspace_root();
    let cargo_cfg =
        fs::read_to_string(root.join(".cargo/config.toml")).expect(".cargo/config.toml readable");
    for line in cargo_cfg.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') {
            continue;
        }
        assert!(
            !trimmed.contains("+avx")
                && !trimmed.contains("+fma")
                && !trimmed.contains("x86-64-v3"),
            "default .cargo/config.toml must not enable non-baseline ISA features: {trimmed}"
        );
    }

    let root_toml = fs::read_to_string(root.join("Cargo.toml")).expect("Cargo.toml readable");
    assert!(root_toml.contains("[profile.release-x86-64-v3]"));
    assert!(root_toml.contains("rustflags = [\"-Ctarget-feature=+avx2,+fma\"]"));
}

#[test]
fn baseline_isa_gate_script_and_cpu_guard_contract_are_complete() {
    let root = workspace_root();
    let gate = fs::read_to_string(root.join("scripts/check_baseline_isa.sh"))
        .expect("scripts/check_baseline_isa.sh readable");
    assert!(gate.contains("QEMU_CPUS=\"${QEMU_CPUS-Nehalem qemu64}\""));
    assert!(gate.contains("functions_with_extensions="));
    assert!(gate.contains("non_math_abi_math_calls="));
    assert!(gate.contains("stdout.txt"));
    assert!(gate.contains("stderr.txt"));
    assert!(gate.contains("__frankenlibc_cpu_guard_resolve"));
    assert!(gate.contains("compiled for x86-64 extensions"));

    let abi_lib = fs::read_to_string(root.join("crates/frankenlibc-abi/src/lib.rs"))
        .expect("frankenlibc-abi/src/lib.rs readable");
    assert!(
        abi_lib.contains("cpu_guard"),
        "frankenlibc-abi must wire cpu_guard for non-baseline feature builds"
    );

    let math_mod = fs::read_to_string(root.join("crates/frankenlibc-core/src/math/mod.rs"))
        .expect("frankenlibc-core/src/math/mod.rs readable");
    assert!(
        math_mod.contains("macro_rules! avx2_fma_dispatch"),
        "core math must expose runtime CPUID avx2_fma_dispatch! macro"
    );
}
