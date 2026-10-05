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
    }
}
