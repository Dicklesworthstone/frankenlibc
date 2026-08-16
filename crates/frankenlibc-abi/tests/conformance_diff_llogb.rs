//! Differential conformance gate for `llogb` / `llogbf` (C23) vs host glibc.
//!
//! `llogb` returns the same exponent as `ilogb` for finite normal/subnormal
//! inputs, but its special-case sentinels are the `long`-width ones:
//!   - llogb(±0)  -> FP_LLOGB0   (LONG_MIN)
//!   - llogb(NaN) -> FP_LLOGBNAN (LONG_MIN on this platform)
//!   - llogb(±inf)-> LONG_MAX
//!
//! A naive `ilogb(x) as long` widens the INT_MIN/INT_MAX sentinels and reports
//! the wrong value — that was the bug this gate pins. Each special input must
//! also raise FE_INVALID (inherited from the inner ilogb call), matching glibc.

use std::os::raw::c_long;

unsafe extern "C" {
    fn feclearexcept(excepts: i32) -> i32;
    fn fetestexcept(excepts: i32) -> i32;
}

// The host arms are resolved with `dlsym`, not declared at link time.
//
// They USED to be `#[link_name = "llogb"] fn host_llogb(..)`, and that shape is
// the most deceptive form of the defect bd-v0388t tracks: the `host_` prefix
// makes the arm read as host-resolved to anyone scanning the file, while the
// `link_name` attribute means it binds exactly like a plain declaration — to
// whichever definition the linker picks, and fl exports `llogb`/`llogbf` into
// this same test binary. A reviewer looking for "does this reach the host?"
// sees the name and moves on. 11 files and 44 symbols in this suite currently
// use that idiom.
//
// `dlsym` on an explicit `libc.so.6`/`libm.so.6` handle is correct in every
// build profile, and the `assert_ne!` turns the remaining doubt into a failing
// test rather than a silent pass.
type LlogbFn = unsafe extern "C" fn(f64) -> c_long;
type LlogbfFn = unsafe extern "C" fn(f32) -> c_long;

/// Resolve `name` from the host math object, refusing to hand back fl's own code.
fn host_symbol(name: &std::ffi::CStr, fl_addr: usize) -> *mut std::ffi::c_void {
    for lib in [c"libm.so.6", c"libc.so.6"] {
        // SAFETY: lib is a NUL-terminated constant; flags request a local handle.
        let handle = unsafe { libc::dlopen(lib.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
        if handle.is_null() {
            continue;
        }
        // SAFETY: handle came from dlopen; name is NUL-terminated.
        let raw = unsafe { libc::dlsym(handle, name.as_ptr()) };
        if !raw.is_null() {
            assert_ne!(
                raw as usize, fl_addr,
                "the resolved oracle IS fl's {name:?} — this gate would compare fl to itself"
            );
            return raw;
        }
    }
    panic!("no host object exports {name:?} — the oracle is unavailable, so this gate cannot run");
}

fn host_llogb_fn() -> LlogbFn {
    // SAFETY: the resolved symbol has C23's documented llogb signature.
    unsafe { std::mem::transmute::<_, LlogbFn>(host_symbol(c"llogb", fl_llogb as usize)) }
}

fn host_llogbf_fn() -> LlogbfFn {
    // SAFETY: the resolved symbol has C23's documented llogbf signature.
    unsafe { std::mem::transmute::<_, LlogbfFn>(host_symbol(c"llogbf", fl_llogbf as usize)) }
}

use frankenlibc_abi::math_abi::{llogb as fl_llogb, llogbf as fl_llogbf};

const FE_INVALID: i32 = 0x01;

#[test]
fn llogb_special_values_match_glibc() {
    let host_llogb_bound = host_llogb_fn();
    let host_llogbf_bound = host_llogbf_fn();
    let specials: &[f64] = &[
        0.0,
        -0.0,
        f64::INFINITY,
        f64::NEG_INFINITY,
        f64::NAN,
        -f64::NAN,
    ];
    for &x in specials {
        let h = unsafe { host_llogb_bound(x) };
        let f = unsafe { fl_llogb(x) };
        assert_eq!(f, h, "llogb({x:e}): fl={f} host={h}");
        // f32
        let xf = x as f32;
        let hf = unsafe { host_llogbf_bound(xf) };
        let ff = unsafe { fl_llogbf(xf) };
        assert_eq!(ff, hf, "llogbf({xf:e}): fl={ff} host={hf}");
    }
    // The platform sentinels must be the long-width extremes, not the int ones.
    assert_eq!(
        unsafe { fl_llogb(0.0) },
        c_long::MIN,
        "llogb(0) = FP_LLOGB0"
    );
    assert_eq!(
        unsafe { fl_llogb(f64::NAN) },
        c_long::MIN,
        "llogb(NaN) = FP_LLOGBNAN"
    );
    assert_eq!(
        unsafe { fl_llogb(f64::INFINITY) },
        c_long::MAX,
        "llogb(inf) = LONG_MAX"
    );
}

#[test]
fn llogb_finite_sweep_matches_glibc() {
    let host_llogb_bound = host_llogb_fn();
    let host_llogbf_bound = host_llogbf_fn();
    // Sweep exponents across the f64 normal + subnormal range.
    let mut diffs = Vec::new();
    let mut x = 5e-324_f64; // smallest subnormal
    for _ in 0..2100 {
        let h = unsafe { host_llogb_bound(x) };
        let f = unsafe { fl_llogb(x) };
        if f != h {
            diffs.push(format!("llogb({x:e}): fl={f} host={h}"));
        }
        x *= 2.0;
        if !x.is_finite() {
            break;
        }
    }
    // A handful of representative mantissas.
    for &x in &[1.0, 1.5, 2.5, 3.0, 1023.99, 0.1, 0.3, 1e100, 1e-100] {
        let h = unsafe { host_llogb_bound(x) };
        let f = unsafe { fl_llogb(x) };
        if f != h {
            diffs.push(format!("llogb({x:e}): fl={f} host={h}"));
        }
    }
    assert!(
        diffs.is_empty(),
        "llogb finite sweep diverged:\n{}",
        diffs.join("\n")
    );
}

#[test]
fn llogb_special_inputs_raise_fe_invalid() {
    let host_llogb_bound = host_llogb_fn();
    let host_llogbf_bound = host_llogbf_fn();
    for &x in &[0.0_f64, f64::INFINITY, f64::NAN] {
        unsafe { feclearexcept(FE_INVALID) };
        let _ = unsafe { fl_llogb(x) };
        let raised = unsafe { fetestexcept(FE_INVALID) } & FE_INVALID;
        assert_ne!(raised, 0, "llogb({x:e}) must raise FE_INVALID");
    }
}
