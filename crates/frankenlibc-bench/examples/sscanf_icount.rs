//! Instruction-count driver for `sscanf`: one fl object per run, chosen by argv.
//!
//! ## Why this exists
//!
//! Three wall-clock A/Bs of the sscanf family failed to certify anything, and the
//! fourth — a SAME-INVOCATION self-A/B with both fl objects dlopened into one
//! process — showed why: the untouched control cases still read candidate/base
//! 1.1577 and 1.1348 with tight CIs and holding nulls. Same clock, same load,
//! same page cache, 15% apart. What is left is the OBJECT: two builds differ in
//! code layout, and that alone is worth ~15% on a small hot loop.
//!
//! Instruction counts do not have that problem. Layout changes where code sits
//! and how it caches; it does not change HOW MANY instructions execute. So a
//! two-object comparison by instructions is clean where a comparison by cycles
//! is not, and it is exact rather than statistical — no nulls, no CIs, no quiet
//! window required. That matters on this box, which has not been quiet all day.
//!
//! ## How to use it
//!
//!     perf stat -e instructions,cycles -r 3 \
//!         ./target/release-perf/examples/sscanf_icount <fl.so> <case>
//!
//! Run once per object and subtract. The harness binary is IDENTICAL across
//! arms — only the dlopened object differs — so every instruction outside the
//! measured loop is common-mode.
//!
//! ## Read the controls first
//!
//! `single_int` and `two_ints` are served by `strict_scan_decimal_ints`, which
//! never enters the parsing engine and allocates nothing. A change confined to
//! the engine must leave their instruction counts UNCHANGED. If they move, the
//! comparison is measuring something other than the change and the treated cases
//! cannot be read. This is the same control discipline that caught a uniform
//! +13% bias, and later a real `%[...]` regression, in the wall-clock runs.

use std::ffi::{CString, c_char, c_int, c_void};

type SscanfFn = unsafe extern "C" fn(*const c_char, *const c_char, ...) -> c_int;

fn dl<T: Copy>(handle: *mut c_void, name: &[u8]) -> T {
    // SAFETY: handle came from dlopen; name is a NUL-terminated byte string.
    let p = unsafe { libc::dlsym(handle, name.as_ptr().cast()) };
    assert!(!p.is_null(), "dlsym {:?}", std::str::from_utf8(name));
    // SAFETY: the resolved symbol has the C signature named by `T`.
    unsafe { std::mem::transmute_copy::<usize, T>(&(p as usize)) }
}

/// Iterations per run. Deliberately modest: instruction counts are exact, so a
/// large N buys nothing but wall time.
fn iters() -> u64 {
    std::env::var("SSCANF_ICOUNT_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(200_000)
}

fn main() {
    let mut args = std::env::args().skip(1);
    let so = args.next().expect("usage: sscanf_icount <fl.so> <case>");
    let case = args.next().unwrap_or_else(|| "single_int".to_string());

    let so_c = CString::new(so.as_str()).expect("path has NUL");
    // SAFETY: NUL-terminated path; RTLD_LOCAL keeps the object out of the global
    // namespace so it cannot capture this binary's own libc symbols.
    // RTLD_DEEPBIND IS LOAD-BEARING, and its absence silently hollowed this
    // instrument. Without it the dlopened object's calls to its OWN exported
    // symbols resolve in the GLOBAL scope first, which is host glibc. fl's
    // `__isoc23_sscanf` falls through to `vsscanf` for any format its fast paths
    // decline, and that call bound to GLIBC's vsscanf — so every "fl" row for an
    // engine format was fl's alias wrapping GLIBC's parser. Two flat profiles
    // settled it: `string_token`, served entirely inside fl's own body, is 30.95%
    // `__isoc23_sscanf` + 14.29% `strict_scan_single_string` in
    // libfrankenlibc_abi.so, while `float_only`, which falls through, was 31.42%
    // `__vfscanf_internal` + 25.13% `strtof_l` in libc.so.6.
    let handle = unsafe {
        libc::dlopen(
            so_c.as_ptr(),
            libc::RTLD_NOW | libc::RTLD_LOCAL | libc::RTLD_DEEPBIND,
        )
    };
    assert!(!handle.is_null(), "dlopen {so}");
    // WHICH sscanf. glibc exports BOTH `sscanf@@GLIBC_2.2.5` and
    // `__isoc23_sscanf@@GLIBC_2.38`, and a compiler emits calls to the LATTER —
    // <stdio.h> redirects them under gcc 15's default -std=c23, as it did to
    // __isoc99_sscanf before. Resolving the bare name would measure glibc's
    // legacy shim rather than the entry point real programs reach, which is the
    // hollow-arm trap bd-v0388t exists for, one level down. fl exports only the
    // plain name, so preference plus fallback covers both objects, and the symbol
    // actually used is PRINTED so a row can never be read without knowing which
    // implementation answered.
    let (sscanf, symbol): (SscanfFn, &str) = {
        // SAFETY: handle came from dlopen; the name is NUL-terminated.
        let modern = unsafe { libc::dlsym(handle, c"__isoc23_sscanf".as_ptr()) };
        if modern.is_null() {
            (dl(handle, b"sscanf\0"), "sscanf")
        } else {
            // SAFETY: __isoc23_sscanf has C's sscanf signature.
            (
                unsafe { std::mem::transmute_copy::<usize, SscanfFn>(&(modern as usize)) },
                "__isoc23_sscanf",
            )
        }
    };

    // (input, format) per case, mirroring incumbent_coverage_ab's sscanf family
    // so the two instruments can be read against each other.
    let (input, format) = match case.as_str() {
        // CONTROLS: decimal-int fast path, no engine, no allocation.
        "single_int" => ("42", "%d"),
        "two_ints" => ("1 2", "%d %d"),
        // TREATED: these reach the parsing engine.
        "string_token" => ("hello world", "%s"),
        "scanset_only" => ("key=value", "%[^=]"),
        "key_value" => ("key=value", "%[^=]=%s"),
        "float_only" => ("3.5", "%f"),
        // FIVE directives ('i','d','=' literals plus the conversion): sits just
        // above a 4-slot inline capacity, so it prices the spill.
        "long_literal" => ("id=42", "id=%d"),
        // The IPv4 shape, and the worst case in the family on the certified
        // wall-clock run at 2.899x host glibc. Four conversions and three
        // literals parse to SEVEN directives, which spills the inline vector.
        "dotted_quad" => ("192.168.1.1", "%d.%d.%d.%d"),
        // The last two single-separator shapes to leave the engine.
        "two_strings" => ("hello world", "%s %s"),
        "string_then_int" => ("hello 42", "%s %d"),
        other => panic!("unknown case {other:?}"),
    };

    let cin = CString::new(input).expect("input has NUL");
    let cfmt = CString::new(format).expect("format has NUL");

    let mut int_a: c_int = 0;
    let mut int_b: c_int = 0;
    let mut int_c: c_int = 0;
    let mut int_d: c_int = 0;
    let mut flt: f32 = 0.0;
    let mut buf_a = [0u8; 128];
    let mut buf_b = [0u8; 128];

    let n = iters();
    let mut checksum: u64 = 0;

    for _ in 0..n {
        // SAFETY: each format's arguments match the pointers passed. The
        // destinations are 128-byte buffers and the inputs are far shorter.
        let rc = unsafe {
            match case.as_str() {
                "long_literal" => sscanf(
                    std::hint::black_box(cin.as_ptr()),
                    std::hint::black_box(cfmt.as_ptr()),
                    &mut int_a as *mut c_int,
                ),
                "single_int" => sscanf(
                    std::hint::black_box(cin.as_ptr()),
                    std::hint::black_box(cfmt.as_ptr()),
                    &mut int_a as *mut c_int,
                ),
                "two_ints" => sscanf(
                    std::hint::black_box(cin.as_ptr()),
                    std::hint::black_box(cfmt.as_ptr()),
                    &mut int_a as *mut c_int,
                    &mut int_b as *mut c_int,
                ),
                "dotted_quad" => sscanf(
                    std::hint::black_box(cin.as_ptr()),
                    std::hint::black_box(cfmt.as_ptr()),
                    &mut int_a as *mut c_int,
                    &mut int_b as *mut c_int,
                    &mut int_c as *mut c_int,
                    &mut int_d as *mut c_int,
                ),
                "float_only" => sscanf(
                    std::hint::black_box(cin.as_ptr()),
                    std::hint::black_box(cfmt.as_ptr()),
                    &mut flt as *mut f32,
                ),
                "two_strings" => sscanf(
                    std::hint::black_box(cin.as_ptr()),
                    std::hint::black_box(cfmt.as_ptr()),
                    buf_a.as_mut_ptr().cast::<c_char>(),
                    buf_b.as_mut_ptr().cast::<c_char>(),
                ),
                "string_then_int" => sscanf(
                    std::hint::black_box(cin.as_ptr()),
                    std::hint::black_box(cfmt.as_ptr()),
                    buf_a.as_mut_ptr().cast::<c_char>(),
                    &mut int_a as *mut c_int,
                ),
                "key_value" => sscanf(
                    std::hint::black_box(cin.as_ptr()),
                    std::hint::black_box(cfmt.as_ptr()),
                    buf_a.as_mut_ptr().cast::<c_char>(),
                    buf_b.as_mut_ptr().cast::<c_char>(),
                ),
                _ => sscanf(
                    std::hint::black_box(cin.as_ptr()),
                    std::hint::black_box(cfmt.as_ptr()),
                    buf_a.as_mut_ptr().cast::<c_char>(),
                ),
            }
        };
        // Order-sensitive mix over EVERY destination this driver can write: the
        // return code, both text buffers, both ints and the float. A loop that
        // had been optimised away, or a conversion that silently stopped
        // writing, both change it; an XOR of return codes would collapse to a
        // constant and prove neither.
        //
        // Every destination has to be in here, not just the first. When the
        // `two_strings` case arrived it wrote `buf_b` and nothing read it, so a
        // fast path that dropped the SECOND field would have produced an
        // identical checksum and looked like a free speedup. That is the same
        // hollow-observation shape as an oracle arm that resolves back to fl,
        // one layer down, and it is worth the four extra adds.
        checksum = checksum
            .wrapping_mul(0x100_0000_01b3)
            .wrapping_add(rc as u64)
            .wrapping_add(buf_a[0] as u64)
            .wrapping_add(buf_b[0] as u64)
            .wrapping_add(int_a as u64)
            .wrapping_add(int_b as u64)
            .wrapping_add(flt.to_bits() as u64);
    }

    // The loader mode is PRINTED because a row measured without it is not a
    // row about the named object.
    println!(
        "SSCANF_ICOUNT case={case} iters={n} object={so} symbol={symbol} \
loader=RTLD_NOW|RTLD_LOCAL|RTLD_DEEPBIND checksum=0x{checksum:x}"
    );
}
