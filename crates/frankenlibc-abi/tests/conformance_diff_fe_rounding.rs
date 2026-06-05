#![cfg(target_os = "linux")]

//! Differential conformance: do `rint` / `nearbyint` / `lrint` / `llrint`
//! honor the current `fesetround()` rounding mode, byte-for-byte vs host glibc?
//!
//! C99 requires rint/nearbyint/lrint/llrint to round per the *current* mode
//! (FE_TONEAREST / FE_UPWARD / FE_DOWNWARD / FE_TOWARDZERO). `round`/`lround`
//! (half-away) and `trunc` (toward zero) are mode-INDEPENDENT and not tested
//! here. fesetround sets the real hardware MXCSR/x87 control word, so both fl
//! and glibc observe the same mode within the process.
//!
//! Serialized via a global lock because the rounding mode is process-global.

use std::ffi::c_int;
use std::sync::Mutex;

use frankenlibc_abi::fenv_abi as fl_fenv;
use frankenlibc_abi::math_abi as fl;

unsafe extern "C" {
    fn rint(x: f64) -> f64;
    fn nearbyint(x: f64) -> f64;
    fn lrint(x: f64) -> i64;
    fn llrint(x: f64) -> i64;
    fn fesetround(rnd: c_int) -> c_int;
}

const FE_TONEAREST: c_int = 0x000;
const FE_DOWNWARD: c_int = 0x400;
const FE_UPWARD: c_int = 0x800;
const FE_TOWARDZERO: c_int = 0xC00;

static FE_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn diff_rounding_mode_aware_rint_vs_glibc() {
    let _g = FE_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    // Values where the rounding mode changes the integral result.
    let values: &[f64] = &[
        2.3,
        2.5,
        2.7,
        -2.3,
        -2.5,
        -2.7,
        0.5,
        -0.5,
        1.5,
        -1.5,
        0.4999999999999999,
        0.5000000000000001,
        3.5,
        -3.5,
        123.25,
        -123.75,
        8388608.5,
        1e-300,
        -1e-300,
        100.5,
        101.5,
    ];

    let modes = [
        ("FE_TONEAREST", FE_TONEAREST),
        ("FE_DOWNWARD", FE_DOWNWARD),
        ("FE_UPWARD", FE_UPWARD),
        ("FE_TOWARDZERO", FE_TOWARDZERO),
    ];

    let mut div: Vec<String> = Vec::new();

    for (mname, mode) in modes {
        // Set via host glibc fesetround; sanity-check fl's fegetround agrees.
        unsafe { fesetround(mode) };
        let fl_mode = unsafe { fl_fenv::fegetround() };
        if fl_mode != mode {
            div.push(format!(
                "  fl::fegetround()={fl_mode:#x} but set mode={mode:#x} ({mname})"
            ));
        }

        for &x in values {
            let (fr, gr) = unsafe { (fl::rint(x), rint(x)) };
            if fr.to_bits() != gr.to_bits() {
                div.push(format!("  {mname} rint({x}): fl={fr} glibc={gr}"));
            }
            let (fr, gr) = unsafe { (fl::nearbyint(x), nearbyint(x)) };
            if fr.to_bits() != gr.to_bits() {
                div.push(format!("  {mname} nearbyint({x}): fl={fr} glibc={gr}"));
            }
            let (fr, gr) = unsafe { (fl::lrint(x), lrint(x)) };
            if fr != gr {
                div.push(format!("  {mname} lrint({x}): fl={fr} glibc={gr}"));
            }
            let (fr, gr) = unsafe { (fl::llrint(x), llrint(x)) };
            if fr != gr {
                div.push(format!("  {mname} llrint({x}): fl={fr} glibc={gr}"));
            }
        }
    }

    // Always restore the default before leaving.
    unsafe { fesetround(FE_TONEAREST) };

    assert!(
        div.is_empty(),
        "{} rounding-mode divergences vs host glibc (first 30):\n{}",
        div.len(),
        div.iter().take(30).cloned().collect::<Vec<_>>().join("\n")
    );
}
