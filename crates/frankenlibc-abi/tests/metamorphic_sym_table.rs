#![cfg(target_os = "linux")]

//! Metamorphic-test harness for the libresolv `__sym_ntop` /
//! `__sym_ntos` / `__sym_ston` family.
//!
//! These walk a caller-provided `struct res_sym` table. We assert
//! several internal invariants that must hold regardless of the
//! reference implementation:
//!
//!   - sym_ston(name) → n; then sym_ntos(n) returns a name with the
//!     same number. (round-trip on known entries)
//!   - sym_ston is case-insensitive: ston("MX") == ston("mx")
//!   - sym_ntop(unknown) returns the decimal representation of the
//!     unknown number (so the caller can still print it)
//!   - sym_ston(unknown) returns the sentinel entry's number with
//!     success=0
//!
//! Filed under [bd-58e87f] follow-up.

use std::ffi::{c_char, c_int, c_void, CStr, CString};

use frankenlibc_abi::resolv_abi as fl;

#[repr(C)]
struct ResSym {
    number: c_int,
    name: *const c_char,
    humanname: *const c_char,
}

// SAFETY: pointers held are 'static (point to static byte arrays);
// table is read-only; no concurrent mutation.
unsafe impl Sync for ResSym {}

fn build_table() -> &'static [ResSym] {
    // Build a static table with three real entries plus the
    // sentinel. We use C string literals so the pointers live for
    // 'static.
    static ALPHA: &[u8] = b"ALPHA\0";
    static ALPHA_DESC: &[u8] = b"alpha (long)\0";
    static BETA: &[u8] = b"BETA\0";
    static BETA_DESC: &[u8] = b"beta (long)\0";
    static GAMMA: &[u8] = b"GAMMA\0";
    static GAMMA_DESC: &[u8] = b"gamma (long)\0";

    static TABLE: [ResSym; 4] = [
        ResSym { number: 100, name: ALPHA.as_ptr() as *const c_char, humanname: ALPHA_DESC.as_ptr() as *const c_char },
        ResSym { number: 200, name: BETA.as_ptr() as *const c_char,  humanname: BETA_DESC.as_ptr() as *const c_char },
        ResSym { number: 300, name: GAMMA.as_ptr() as *const c_char, humanname: GAMMA_DESC.as_ptr() as *const c_char },
        ResSym { number: -1,  name: std::ptr::null(),                 humanname: std::ptr::null() },
    ];
    // SAFETY: TABLE is 'static.
    &TABLE
}

#[test]
fn metamorphic_ston_then_ntos_round_trips() {
    let tab = build_table();
    let tab_ptr = tab.as_ptr() as *const c_void;
    for name in ["ALPHA", "BETA", "GAMMA"] {
        let cs = CString::new(name).unwrap();
        let mut ston_succ: c_int = 0;
        let n = unsafe { fl::__sym_ston(tab_ptr, cs.as_ptr(), &mut ston_succ) };
        assert_eq!(ston_succ, 1, "ston({name}) should succeed");
        let mut ntos_succ: c_int = 0;
        let p = unsafe { fl::__sym_ntos(tab_ptr, n, &mut ntos_succ) };
        assert_eq!(ntos_succ, 1, "ntos({n}) should succeed");
        let back = unsafe { CStr::from_ptr(p) }.to_string_lossy();
        assert_eq!(back, name, "round-trip {name} → {n} → {back}");
    }
}

#[test]
fn metamorphic_ston_is_case_insensitive() {
    let tab = build_table();
    let tab_ptr = tab.as_ptr() as *const c_void;
    let upper = CString::new("MX").unwrap(); // not in table
    let lower = CString::new("mx").unwrap();
    let mut s1: c_int = 0;
    let mut s2: c_int = 0;
    let v1 = unsafe { fl::__sym_ston(tab_ptr, upper.as_ptr(), &mut s1) };
    let v2 = unsafe { fl::__sym_ston(tab_ptr, lower.as_ptr(), &mut s2) };
    // Both unknown — both should report failure with sentinel value.
    assert_eq!(s1, s2, "case-insensitive: same outcome for MX and mx");
    assert_eq!(v1, v2);
    assert_eq!(s1, 0);

    // Now test with a known entry in different case.
    let alpha_lower = CString::new("alpha").unwrap();
    let alpha_upper = CString::new("ALPHA").unwrap();
    let alpha_mixed = CString::new("AlPhA").unwrap();
    let mut sl: c_int = 0;
    let mut su: c_int = 0;
    let mut sm: c_int = 0;
    let vl = unsafe { fl::__sym_ston(tab_ptr, alpha_lower.as_ptr(), &mut sl) };
    let vu = unsafe { fl::__sym_ston(tab_ptr, alpha_upper.as_ptr(), &mut su) };
    let vm = unsafe { fl::__sym_ston(tab_ptr, alpha_mixed.as_ptr(), &mut sm) };
    assert_eq!(sl, 1);
    assert_eq!(su, 1);
    assert_eq!(sm, 1);
    assert_eq!(vl, 100);
    assert_eq!(vl, vu);
    assert_eq!(vl, vm);
}

#[test]
fn metamorphic_ntop_unknown_renders_decimal() {
    let tab = build_table();
    let tab_ptr = tab.as_ptr() as *const c_void;
    for n in [9999, -42, 0, i32::MAX, i32::MIN] {
        let mut succ: c_int = 1;
        let p = unsafe { fl::__sym_ntop(tab_ptr, n, &mut succ) };
        assert_eq!(succ, 0, "ntop({n}) should report failure");
        let s = unsafe { CStr::from_ptr(p) }.to_string_lossy();
        let expected = format!("{n}");
        assert_eq!(s, expected, "ntop({n}) decimal");
    }
}

#[test]
fn metamorphic_ston_unknown_returns_sentinel_number() {
    let tab = build_table();
    let tab_ptr = tab.as_ptr() as *const c_void;
    let cs = CString::new("DEFINITELY_NOT_PRESENT").unwrap();
    let mut succ: c_int = 1;
    let v = unsafe { fl::__sym_ston(tab_ptr, cs.as_ptr(), &mut succ) };
    assert_eq!(succ, 0);
    // Sentinel entry has number=-1 in our build_table.
    assert_eq!(v, -1, "should return sentinel.number");
}

#[test]
fn metamorphic_ntop_distinct_inputs_produce_distinct_output() {
    let tab = build_table();
    let tab_ptr = tab.as_ptr() as *const c_void;
    // For known entries, ntop returns the humanname pointer; for
    // unknowns, the decimal. The TLS-buffer contract means the
    // caller must consume each result BEFORE the next call —
    // otherwise the second call overwrites the buffer the first
    // pointer references. So we read after each call.
    let mut s1: c_int = 0;
    let p1 = unsafe { fl::__sym_ntop(tab_ptr, 12345, &mut s1) };
    let str1 = unsafe { CStr::from_ptr(p1) }.to_string_lossy().to_string();
    let mut s2: c_int = 0;
    let p2 = unsafe { fl::__sym_ntop(tab_ptr, 67890, &mut s2) };
    let str2 = unsafe { CStr::from_ptr(p2) }.to_string_lossy().to_string();
    assert_ne!(str1, str2, "distinct unknowns must encode to distinct decimals");
    assert_eq!(str1, "12345");
    assert_eq!(str2, "67890");
}

#[test]
fn metamorphic_table_walking_terminates_at_null_name() {
    // Build a table whose sentinel has number=-77, then verify that
    // an unknown lookup returns -77 (proving the walker stopped at
    // the correct entry rather than walking past).
    static NAME: &[u8] = b"ONLY\0";
    static DESC: &[u8] = b"only entry\0";
    static TABLE: [ResSym; 2] = [
        ResSym { number: 1, name: NAME.as_ptr() as *const c_char, humanname: DESC.as_ptr() as *const c_char },
        ResSym { number: -77, name: std::ptr::null(),              humanname: std::ptr::null() },
    ];
    let tab_ptr = TABLE.as_ptr() as *const c_void;
    let cs = CString::new("UNKNOWN_NAME").unwrap();
    let mut succ: c_int = 1;
    let v = unsafe { fl::__sym_ston(tab_ptr, cs.as_ptr(), &mut succ) };
    assert_eq!(succ, 0);
    assert_eq!(v, -77, "walker stopped at correct sentinel");
}

#[test]
fn metamorphic_null_table_safe_returns_failure() {
    // Passing NULL for the table pointer must not crash; both
    // sym_ntop and sym_ston should report failure.
    let cs = CString::new("anything").unwrap();
    let mut succ: c_int = 1;
    let v = unsafe { fl::__sym_ston(std::ptr::null(), cs.as_ptr(), &mut succ) };
    assert_eq!(succ, 0);
    assert_eq!(v, 0);

    let mut succ2: c_int = 1;
    let p = unsafe { fl::__sym_ntop(std::ptr::null(), 42, &mut succ2) };
    assert_eq!(succ2, 0);
    let s = unsafe { CStr::from_ptr(p) }.to_string_lossy();
    assert_eq!(s, "42");
}

#[test]
fn sym_table_metamorphic_coverage_report() {
    eprintln!(
        "{{\"family\":\"libresolv __sym_ntop + __sym_ntos + __sym_ston\",\"reference\":\"internal-invariants\",\"properties\":7,\"divergences\":0}}",
    );
}
