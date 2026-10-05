// Preserve all existing build-time policy checks and generated artifacts.
mod checks {
    include!("build.rs");
    pub fn run() { main(); }
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
        // Only define version nodes. Unlike libc.map this does not assign
        // guessed glibc versions to unrelated interposition exports, and has
        // no missing _Unwind_* requirements. LLD (the Rust target default)
        // combines these nodes with rustc's anonymous visibility script.
        println!("cargo:rustc-cdylib-link-arg=-Wl,--version-script={manifest}/version_scripts/fromfp.map");
        // The `.symver name,alias,remove` directives in fromfp_abi drop the
        // `__frankenlibc_c23_*` export names, but rustc's own anonymous
        // version script still lists them and rustc links with
        // --no-undefined-version, so every release link failed ("version
        // script assignment of 'global' to symbol '__frankenlibc_c23_fromfp'
        // failed: symbol not defined"). The later flag wins in LLD.
        println!("cargo:rustc-cdylib-link-arg=-Wl,--undefined-version");
    }
}
