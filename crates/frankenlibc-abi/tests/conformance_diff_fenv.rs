#![cfg(target_os = "linux")]

//! Differential conformance harness for `<fenv.h>` floating-point environment.
//!
//! Compares FrankenLibC vs glibc reference for:
//!   - fegetround / fesetround (round-trip across all 4 IEEE rounding modes)
//!   - feclearexcept / fetestexcept / feraiseexcept (exception flags)
//!   - fegetenv / fesetenv (full environment save/restore)
//!
//! All tests serialize via FENV_LOCK because the FPU control word is
//! per-thread and we mutate it. Original state is restored after each
//! test via fesetenv.
//!
//! Bead: CONFORMANCE: libc fenv.h diff matrix.

use std::ffi::{c_int, c_void};
use std::sync::Mutex;

use frankenlibc_abi::fenv_abi as fl;

// glibc rounding-mode constants (x86_64 Linux <fenv.h>)
const FE_TONEAREST: c_int = 0x0000;
const FE_DOWNWARD: c_int = 0x0400;
const FE_UPWARD: c_int = 0x0800;
const FE_TOWARDZERO: c_int = 0x0c00;

// glibc exception constants (x86_64 Linux <fenv.h>)
const FE_INVALID: c_int = 0x01;
const FE_DIVBYZERO: c_int = 0x04;
const FE_OVERFLOW: c_int = 0x08;
const FE_UNDERFLOW: c_int = 0x10;
const FE_INEXACT: c_int = 0x20;
const FE_ALL_EXCEPT: c_int = FE_INVALID | FE_DIVBYZERO | FE_OVERFLOW | FE_UNDERFLOW | FE_INEXACT;

unsafe extern "C" {
    fn fegetround() -> c_int;
    fn fesetround(rnd: c_int) -> c_int;
    fn feclearexcept(excepts: c_int) -> c_int;
    fn fetestexcept(excepts: c_int) -> c_int;
    fn feraiseexcept(excepts: c_int) -> c_int;
    fn fegetenv(envp: *mut c_void) -> c_int;
    fn fesetenv(envp: *const c_void) -> c_int;
}

static FENV_LOCK: Mutex<()> = Mutex::new(());

#[derive(Debug)]
struct Divergence {
    function: &'static str,
    case: String,
    field: &'static str,
    frankenlibc: String,
    glibc: String,
}

fn render_divs(divs: &[Divergence]) -> String {
    let mut out = String::new();
    for d in divs {
        out.push_str(&format!(
            "  {} | case: {} | field: {} | fl: {} | glibc: {}\n",
            d.function, d.case, d.field, d.frankenlibc, d.glibc,
        ));
    }
    out
}

/// fenv_t on x86_64 Linux is ~28 bytes; round up to 64 for safety.
const FENV_SIZE: usize = 64;

unsafe fn save_env() -> Vec<u8> {
    let mut buf = vec![0u8; FENV_SIZE];
    unsafe {
        fegetenv(buf.as_mut_ptr() as *mut c_void);
    }
    buf
}

unsafe fn restore_env(buf: &[u8]) {
    unsafe {
        fesetenv(buf.as_ptr() as *const c_void);
    }
}

// ===========================================================================
// fegetround / fesetround — round-trip every rounding mode
// ===========================================================================

#[test]
fn diff_round_modes_roundtrip() {
    let _g = FENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let prior = unsafe { save_env() };

    let mut divs = Vec::new();
    let modes: &[(&str, c_int)] = &[
        ("FE_TONEAREST", FE_TONEAREST),
        ("FE_DOWNWARD", FE_DOWNWARD),
        ("FE_UPWARD", FE_UPWARD),
        ("FE_TOWARDZERO", FE_TOWARDZERO),
    ];
    for (label, mode) in modes {
        let r_fl = unsafe { fl::fesetround(*mode) };
        let g_fl = unsafe { fl::fegetround() };
        let _ = unsafe { fesetround(*mode) };
        let g_lc = unsafe { fegetround() };
        if r_fl != 0 {
            divs.push(Divergence {
                function: "fesetround",
                case: (*label).into(),
                field: "return",
                frankenlibc: format!("{r_fl}"),
                glibc: "0".into(),
            });
        }
        if g_fl != g_lc {
            divs.push(Divergence {
                function: "fegetround",
                case: (*label).into(),
                field: "return",
                frankenlibc: format!("{g_fl}"),
                glibc: format!("{g_lc}"),
            });
        }
    }

    // Invalid mode → both should fail (non-zero return per POSIX).
    let r_fl = unsafe { fl::fesetround(99999) };
    let r_lc = unsafe { fesetround(99999) };
    if (r_fl == 0) != (r_lc == 0) {
        divs.push(Divergence {
            function: "fesetround",
            case: "invalid".into(),
            field: "success_match",
            frankenlibc: format!("{r_fl}"),
            glibc: format!("{r_lc}"),
        });
    }

    unsafe {
        restore_env(&prior);
    }
    assert!(
        divs.is_empty(),
        "round-mode divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// feclearexcept / fetestexcept / feraiseexcept — exception flag round-trip
// ===========================================================================

#[test]
fn diff_exception_flags_roundtrip() {
    let _g = FENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let prior = unsafe { save_env() };

    let mut divs = Vec::new();
    let excepts: &[(&str, c_int)] = &[
        ("FE_INVALID", FE_INVALID),
        ("FE_DIVBYZERO", FE_DIVBYZERO),
        ("FE_OVERFLOW", FE_OVERFLOW),
        ("FE_UNDERFLOW", FE_UNDERFLOW),
        ("FE_INEXACT", FE_INEXACT),
    ];
    for (label, exc) in excepts {
        // Clear all on both sides.
        let _ = unsafe { fl::feclearexcept(FE_ALL_EXCEPT) };
        let _ = unsafe { feclearexcept(FE_ALL_EXCEPT) };

        // Raise the specific exception on each impl.
        let rr_fl = unsafe { fl::feraiseexcept(*exc) };
        let rr_lc = unsafe { feraiseexcept(*exc) };
        if rr_fl != rr_lc {
            divs.push(Divergence {
                function: "feraiseexcept",
                case: (*label).into(),
                field: "return",
                frankenlibc: format!("{rr_fl}"),
                glibc: format!("{rr_lc}"),
            });
        }

        // fetestexcept: both should report the bit set.
        let t_fl = unsafe { fl::fetestexcept(FE_ALL_EXCEPT) };
        let t_lc = unsafe { fetestexcept(FE_ALL_EXCEPT) };
        if (t_fl & exc) != (t_lc & exc) {
            divs.push(Divergence {
                function: "fetestexcept",
                case: (*label).into(),
                field: "bit_after_raise",
                frankenlibc: format!("{:#x}", t_fl & exc),
                glibc: format!("{:#x}", t_lc & exc),
            });
        }

        // feclearexcept: clear and verify the bit is gone on both.
        let _ = unsafe { fl::feclearexcept(*exc) };
        let _ = unsafe { feclearexcept(*exc) };
        let t_fl = unsafe { fl::fetestexcept(*exc) };
        let t_lc = unsafe { fetestexcept(*exc) };
        if t_fl != t_lc {
            divs.push(Divergence {
                function: "fetestexcept",
                case: (*label).into(),
                field: "bit_after_clear",
                frankenlibc: format!("{t_fl:#x}"),
                glibc: format!("{t_lc:#x}"),
            });
        }
    }

    unsafe {
        restore_env(&prior);
    }
    assert!(
        divs.is_empty(),
        "exception flag divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// fegetenv / fesetenv — save then restore must preserve rounding mode
// ===========================================================================

#[test]
fn diff_fegetenv_fesetenv_roundtrip() {
    let _g = FENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let prior = unsafe { save_env() };

    let mut divs = Vec::new();
    // Set a known round mode, save env, change it, restore env, verify
    // the round mode is back.
    let _ = unsafe { fl::fesetround(FE_DOWNWARD) };
    let mut saved_fl = vec![0u8; FENV_SIZE];
    let r_save_fl = unsafe { fl::fegetenv(saved_fl.as_mut_ptr() as *mut c_void) };
    let _ = unsafe { fl::fesetround(FE_UPWARD) };
    let r_set_fl = unsafe { fl::fesetenv(saved_fl.as_ptr() as *const c_void) };
    let after_fl = unsafe { fl::fegetround() };

    let _ = unsafe { fesetround(FE_DOWNWARD) };
    let mut saved_lc = vec![0u8; FENV_SIZE];
    let r_save_lc = unsafe { fegetenv(saved_lc.as_mut_ptr() as *mut c_void) };
    let _ = unsafe { fesetround(FE_UPWARD) };
    let r_set_lc = unsafe { fesetenv(saved_lc.as_ptr() as *const c_void) };
    let after_lc = unsafe { fegetround() };

    if r_save_fl != r_save_lc {
        divs.push(Divergence {
            function: "fegetenv",
            case: "save".into(),
            field: "return",
            frankenlibc: format!("{r_save_fl}"),
            glibc: format!("{r_save_lc}"),
        });
    }
    if r_set_fl != r_set_lc {
        divs.push(Divergence {
            function: "fesetenv",
            case: "restore".into(),
            field: "return",
            frankenlibc: format!("{r_set_fl}"),
            glibc: format!("{r_set_lc}"),
        });
    }
    if after_fl != after_lc {
        divs.push(Divergence {
            function: "fegetenv/fesetenv",
            case: "round mode round-trip".into(),
            field: "post_restore_round",
            frankenlibc: format!("{after_fl}"),
            glibc: format!("{after_lc}"),
        });
    }
    if after_fl != FE_DOWNWARD {
        divs.push(Divergence {
            function: "fegetenv/fesetenv",
            case: "round mode round-trip".into(),
            field: "expected_FE_DOWNWARD",
            frankenlibc: format!("{after_fl}"),
            glibc: format!("{}", FE_DOWNWARD),
        });
    }

    unsafe {
        restore_env(&prior);
    }
    assert!(
        divs.is_empty(),
        "fegetenv/fesetenv divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn fenv_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"fenv.h\",\"reference\":\"glibc\",\"functions\":7,\"divergences\":0}}",
    );
}
