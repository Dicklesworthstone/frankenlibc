// Preserve all existing build-time policy checks and generated artifacts.
mod checks {
    include!("build.rs");
    pub fn run() {
        main();
    }
}

fn main() {
    checks::run();
    println!("cargo:rerun-if-changed=build_elf.rs");
    println!("cargo:rerun-if-changed=version_scripts/fromfp.map");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux")
        && std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("x86_64")
        && std::env::var_os("CARGO_FEATURE_STANDALONE").is_none()
    {
        let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("Cargo manifest directory");
        let base_map_path = format!("{manifest}/version_scripts/fromfp.map");
        let version_map_path = if std::env::var_os("CARGO_FEATURE_OWNED_UNWIND_STUB").is_some()
            && std::env::var_os("CARGO_CFG_DEBUG_ASSERTIONS").is_none()
        {
            let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR");
            let base_map =
                std::fs::read_to_string(&base_map_path).expect("read version_scripts/fromfp.map");
            let owned_map = format!(
                "{base_map}\n\
/* Explicit .symver directives in owned_unwind_abi.rs own these assignments. */\n\
GCC_3.0 {{}};\n\
GCC_3.3 {{}} GCC_3.0;\n\
GCC_4.2.0 {{}} GCC_3.3;\n"
            );
            let combined_path = format!("{out_dir}/owned_unwind_fromfp.map");
            std::fs::write(&combined_path, owned_map).expect("write owned_unwind_fromfp.map");
            combined_path
        } else {
            base_map_path
        };
        // Only define version nodes. Unlike libc.map this does not assign
        // guessed glibc versions to unrelated interposition exports, and has
        // no missing _Unwind_* requirements. LLD (the Rust target default)
        // combines these nodes with rustc's anonymous visibility script.
        println!("cargo:rustc-cdylib-link-arg=-Wl,--version-script={version_map_path}");
        // The `.symver name,alias,remove` directives in fromfp_abi drop the
        // `__frankenlibc_c23_*` export names, but rustc's own anonymous
        // version script still lists them and rustc links with
        // --no-undefined-version, so every release link failed ("version
        // script assignment of 'global' to symbol '__frankenlibc_c23_fromfp'
        // failed: symbol not defined"). The later flag wins in LLD.
        println!("cargo:rustc-cdylib-link-arg=-Wl,--undefined-version");
    }
}
