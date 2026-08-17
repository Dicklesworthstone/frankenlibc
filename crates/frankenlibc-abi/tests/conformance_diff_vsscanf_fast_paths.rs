#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // hand-built va_list + differential against the host

//! `vsscanf` must answer exactly as the variadic entry points do.
//!
//! ## Why this gate exists
//!
//! Every strict fast path in this family — `%d` lists, a bare `%s`, a bare
//! `%[^X]`, and the mixed field list — was reachable only through the VARIADIC
//! entry points. `vsscanf` had none of them and ran the engine for every format.
//! That is not a corner: `<stdio.h>` sends compiled `vsscanf` calls here, every
//! va_list forwarder in a logging or parsing helper lands here, and the
//! certified wall-clock run measured this arm at **11 losses out of 12** while
//! the variadic arm was 5 wins.
//!
//! The fast paths now take their destinations from `va_next_pointer`, the same
//! arithmetic `vscanf_write_values` already used. That sharing is the point: a
//! va_list advanced wrongly does not crash, it writes a scanned value through
//! whatever pointer happens to sit next in the caller's frame, and two copies of
//! that arithmetic would be two chances to get it wrong.
//!
//! ## How a va_list is built here
//!
//! `gp_offset` is set to 48, which is the "general-purpose registers are
//! exhausted" value, so every fetch comes from `overflow_arg_area` — an array of
//! pointers this test owns. That is the same construction the benchmark harness
//! uses, and it exercises the overflow branch of `va_next_pointer`. The register
//! branch is exercised by every ordinary variadic call in the sibling gates.

use std::ffi::{CString, c_char, c_int, c_void};

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;
use dlsym_oracle::host_fn;

type VsscanfFn = unsafe extern "C" fn(*const c_char, *const c_char, *mut c_void) -> c_int;

/// An x86_64 `__va_list_tag` whose arguments all live in the overflow area.
#[repr(C)]
struct VaListTag {
    gp_offset: u32,
    fp_offset: u32,
    overflow_arg_area: *mut c_void,
    reg_save_area: *mut c_void,
}

impl VaListTag {
    /// 48 = all six GP argument registers consumed, so every fetch reads from
    /// `overflow_arg_area`. 304 does the same for the FP registers, which no
    /// scanf destination uses but which must not look available.
    fn overflow(slots: &mut [*mut c_void]) -> Self {
        Self {
            gp_offset: 48,
            fp_offset: 304,
            overflow_arg_area: slots.as_mut_ptr().cast(),
            reg_save_area: std::ptr::null_mut(),
        }
    }
}

/// Scan through a va_list, returning `(rc, text_a, text_b, int_a, int_b)`.
fn scan(
    f: VsscanfFn,
    input: &str,
    format: &str,
    shape: Shape,
) -> (c_int, String, String, c_int, c_int) {
    let cin = CString::new(input).expect("input has NUL");
    let cfmt = CString::new(format).expect("format has NUL");
    let mut a = [0xAAu8; 64];
    let mut b = [0xAAu8; 64];
    let mut i0: c_int = -777;
    let mut i1: c_int = -777;

    let mut slots: Vec<*mut c_void> = match shape {
        Shape::OneText => vec![a.as_mut_ptr().cast()],
        Shape::TwoText => vec![a.as_mut_ptr().cast(), b.as_mut_ptr().cast()],
        Shape::TwoInt => vec![
            (&mut i0 as *mut c_int).cast(),
            (&mut i1 as *mut c_int).cast(),
        ],
        Shape::TextThenInt => vec![a.as_mut_ptr().cast(), (&mut i0 as *mut c_int).cast()],
        Shape::FourInt => vec![
            (&mut i0 as *mut c_int).cast(),
            (&mut i1 as *mut c_int).cast(),
            (&mut i0 as *mut c_int).cast(),
            (&mut i1 as *mut c_int).cast(),
        ],
        Shape::FiveInt => vec![
            (&mut i0 as *mut c_int).cast(),
            (&mut i1 as *mut c_int).cast(),
            (&mut i0 as *mut c_int).cast(),
            (&mut i1 as *mut c_int).cast(),
            (&mut i0 as *mut c_int).cast(),
        ],
    };
    let mut tag = VaListTag::overflow(&mut slots);

    // SAFETY: the tag describes a va_list whose pointer arguments are the slots
    // above, and each format consumes no more of them than `shape` supplies.
    let rc = unsafe {
        f(
            cin.as_ptr(),
            cfmt.as_ptr(),
            std::ptr::addr_of_mut!(tag).cast(),
        )
    };

    let text = |buf: &[u8; 64]| {
        let end = buf.iter().position(|&x| x == 0).unwrap_or(0);
        String::from_utf8_lossy(&buf[..end]).into_owned()
    };
    (rc, text(&a), text(&b), i0, i1)
}

#[derive(Clone, Copy)]
enum Shape {
    OneText,
    TwoText,
    TwoInt,
    TextThenInt,
    FourInt,
    /// FIVE slots, for the five-conversion decline case. Supplying four was a
    /// SIGSEGV: the engine read a fifth argument that was never in the list.
    /// Every shape here must cover its format's conversion count exactly.
    FiveInt,
}

#[test]
fn vsscanf_matches_host_glibc_on_every_fast_path_shape() {
    // `host_fn` asserts the resolved address is NOT fl's own, so a collapsed
    // oracle fails loudly instead of comparing fl against itself.
    let glibc: VsscanfFn =
        unsafe { host_fn(c"vsscanf", frankenlibc_abi::stdio_abi::vsscanf as *const ()) };
    let fl = frankenlibc_abi::stdio_abi::vsscanf as VsscanfFn;

    let cases: &[(&str, &str, Shape)] = &[
        // Shapes the fast paths now serve.
        ("42", "%d", Shape::TwoInt),
        ("1 2", "%d %d", Shape::TwoInt),
        ("192.168.1.1", "%d.%d.%d.%d", Shape::FourInt),
        ("hello world", "%s", Shape::OneText),
        ("key=value", "%[^=]", Shape::OneText),
        ("hello world", "%s %s", Shape::TwoText),
        ("hello 42", "%s %d", Shape::TextThenInt),
        ("key=value", "%[^=]=%s", Shape::TwoText),
        // Declines and failures, which must still agree.
        ("", "%d", Shape::TwoInt),
        ("abc", "%d", Shape::TwoInt),
        ("1 x", "%d %d", Shape::TwoInt),
        ("   ", "%s", Shape::OneText),
        ("=value", "%[^=]", Shape::OneText),
        ("a,b", "%s,%s", Shape::TwoText),
        ("1 2 3 4 5", "%d %d %d %d %d", Shape::FiveInt),
    ];

    let mut compared = 0usize;
    for (input, format, shape) in cases {
        let want = scan(glibc, input, format, *shape);
        let got = scan(fl, input, format, *shape);
        assert_eq!(
            got, want,
            "vsscanf({input:?}, {format:?}) produced {got:?}, host glibc produced {want:?}"
        );
        compared += 1;
    }
    assert_eq!(compared, cases.len(), "the loop skipped cases");
    println!("compared {compared} vsscanf cases against the host");
}

/// The va_list must be advanced by exactly one slot per conversion.
///
/// This is the failure mode that does not announce itself: over-advancing writes
/// a scanned value through whatever pointer sits next in the caller's frame, and
/// under-advancing writes two conversions into one destination. Both can leave
/// the RETURN CODE correct, so a gate that only checks return codes would pass.
/// Here a sentinel slot follows the ones the format consumes and must come back
/// untouched.
#[test]
fn vsscanf_consumes_exactly_one_argument_per_conversion() {
    let fl = frankenlibc_abi::stdio_abi::vsscanf as VsscanfFn;

    let cin = CString::new("1 2").expect("input has NUL");
    let cfmt = CString::new("%d %d").expect("format has NUL");
    let mut a: c_int = -1;
    let mut b: c_int = -1;
    let mut sentinel: c_int = 0x5EED;

    let mut slots: Vec<*mut c_void> = vec![
        (&mut a as *mut c_int).cast(),
        (&mut b as *mut c_int).cast(),
        (&mut sentinel as *mut c_int).cast(),
    ];
    let mut tag = VaListTag::overflow(&mut slots);

    // SAFETY: two conversions, three slots supplied; the third must not be used.
    let rc = unsafe {
        f_call(
            fl,
            cin.as_ptr(),
            cfmt.as_ptr(),
            std::ptr::addr_of_mut!(tag).cast(),
        )
    };

    assert_eq!(rc, 2, "vsscanf(\"1 2\", \"%d %d\") returned {rc}");
    assert_eq!((a, b), (1, 2), "wrong values written");
    assert_eq!(
        sentinel, 0x5EED,
        "the slot AFTER the format's conversions was written, so the va_list was \
         advanced too far — a real caller would have had an unrelated pointer in \
         that position and this is the corruption that leaves the return code right"
    );
}

/// # Safety
/// Forwards to `f` with the caller's arguments unchanged.
unsafe fn f_call(
    f: VsscanfFn,
    s: *const c_char,
    format: *const c_char,
    ap: *mut c_void,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { f(s, format, ap) }
}
