//! Conformance gate for C23 NaN-payload fns getpayload/setpayload/setpayloadsig
//! (+f32) vs host glibc. setpayload* require a non-negative INTEGER payload in
//! range and set *res to +0 on failure; getpayload extracts the mantissa
//! payload (or -1 for a non-NaN). Golden tuples captured from a gcc
//! -fno-builtin oracle (these may be IFUNCs). fl exercised via Rust paths.
//!
//! ## Live arm added 2026-08-16 (bd-v0388t)
//!
//! Despite the header and a test named `payload_matches_glibc`, this gate never
//! called glibc: the "oracle" is the frozen table below, read off a gcc probe
//! once. The tables are KEPT — they record what each fix intended — and the same
//! inputs now also run through a dlsym-resolved host arm, so a divergence says
//! which side moved rather than only that the two disagree.
//!
//! These six are a sharper case than most frozen goldens because the payload
//! functions are young (C23, glibc 2.25) and their edge cases are where a
//! release retunes: a payload of exactly 2^52-4, a signalling NaN whose payload
//! would be zero, and getpayload on a non-NaN all sit on rules glibc has itself
//! adjusted since introducing them.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]
use frankenlibc_abi::math_abi as fl;

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

type SetPayload64 = unsafe extern "C" fn(*mut f64, f64) -> i32;
type SetPayload32 = unsafe extern "C" fn(*mut f32, f32) -> i32;
type GetPayload64 = unsafe extern "C" fn(*const f64) -> f64;
type GetPayload32 = unsafe extern "C" fn(*const f32) -> f32;

/// The host's own copy of each entry point, each checked against fl's.
struct HostPayload {
    setpayload: SetPayload64,
    setpayloadsig: SetPayload64,
    setpayloadf: SetPayload32,
    setpayloadsigf: SetPayload32,
    getpayload: GetPayload64,
    getpayloadf: GetPayload32,
}

fn host() -> HostPayload {
    // SAFETY: every signature below matches the C declaration in <math.h>.
    unsafe {
        HostPayload {
            setpayload: dlsym_oracle::host_fn(c"setpayload", fl::setpayload as *const ()),
            setpayloadsig: dlsym_oracle::host_fn(c"setpayloadsig", fl::setpayloadsig as *const ()),
            setpayloadf: dlsym_oracle::host_fn(c"setpayloadf", fl::setpayloadf as *const ()),
            setpayloadsigf: dlsym_oracle::host_fn(
                c"setpayloadsigf",
                fl::setpayloadsigf as *const (),
            ),
            getpayload: dlsym_oracle::host_fn(c"getpayload", fl::getpayload as *const ()),
            getpayloadf: dlsym_oracle::host_fn(c"getpayloadf", fl::getpayloadf as *const ()),
        }
    }
}
// setpayload/setpayloadsig f64: (payload_bits, ret, out_bits)
const SP64: &[(u64, i32, u64)] = &[
    (0x0000000000000000, 0, 0x7ff8000000000000),
    (0x3ff0000000000000, 0, 0x7ff8000000000001),
    (0x4014000000000000, 0, 0x7ff8000000000005),
    (0x3ff8000000000000, 1, 0x0000000000000000),
    (0xbff0000000000000, 1, 0x0000000000000000),
    (0x431ffffffffffffc, 0, 0x7fffffffffffffff),
    (0x4320000000000000, 1, 0x0000000000000000),
    (0x4008000000000000, 0, 0x7ff8000000000003),
    (0x7ff8000000000000, 1, 0x0000000000000000),
    (0x7ff0000000000000, 1, 0x0000000000000000),
    (0x404559999999999a, 1, 0x0000000000000000),
    (0x3fe0000000000000, 1, 0x0000000000000000),
];
const SS64: &[(u64, i32, u64)] = &[
    (0x0000000000000000, 1, 0x0000000000000000),
    (0x3ff0000000000000, 0, 0x7ff0000000000001),
    (0x4014000000000000, 0, 0x7ff0000000000005),
    (0x3ff8000000000000, 1, 0x0000000000000000),
    (0xbff0000000000000, 1, 0x0000000000000000),
    (0x431ffffffffffffc, 0, 0x7ff7ffffffffffff),
    (0x4320000000000000, 1, 0x0000000000000000),
    (0x4008000000000000, 0, 0x7ff0000000000003),
    (0x7ff8000000000000, 1, 0x0000000000000000),
    (0x7ff0000000000000, 1, 0x0000000000000000),
    (0x404559999999999a, 1, 0x0000000000000000),
    (0x3fe0000000000000, 1, 0x0000000000000000),
];
const SP32: &[(u32, i32, u32)] = &[
    (0x00000000, 0, 0x7fc00000),
    (0x3f800000, 0, 0x7fc00001),
    (0x40a00000, 0, 0x7fc00005),
    (0x3fc00000, 1, 0x00000000),
    (0xbf800000, 1, 0x00000000),
    (0x4a7ffffc, 0, 0x7fffffff),
    (0x4a800000, 1, 0x00000000),
    (0x40400000, 0, 0x7fc00003),
    (0x7fc00000, 1, 0x00000000),
    (0x7f800000, 1, 0x00000000),
    (0x422acccd, 1, 0x00000000),
    (0x3f000000, 1, 0x00000000),
];
const SS32: &[(u32, i32, u32)] = &[
    (0x00000000, 1, 0x00000000),
    (0x3f800000, 0, 0x7f800001),
    (0x40a00000, 0, 0x7f800005),
    (0x3fc00000, 1, 0x00000000),
    (0xbf800000, 1, 0x00000000),
    (0x4a7ffffc, 0, 0x7fbfffff),
    (0x4a800000, 1, 0x00000000),
    (0x40400000, 0, 0x7f800003),
    (0x7fc00000, 1, 0x00000000),
    (0x7f800000, 1, 0x00000000),
    (0x422acccd, 1, 0x00000000),
    (0x3f000000, 1, 0x00000000),
];
const GP64: &[(u64, u64)] = &[
    (0x7ff8000000000000, 0x0000000000000000),
    (0x7ff8000000000005, 0x4014000000000000),
    (0x7ff0000000000005, 0x4014000000000000),
    (0xfff8000000000005, 0x4014000000000000),
    (0x3ff0000000000000, 0xbff0000000000000),
    (0x7ff0000000000000, 0xbff0000000000000),
    (0x0000000000000000, 0xbff0000000000000),
    (0x7fffffffffffffff, 0x431ffffffffffffc),
];
const GP32: &[(u32, u32)] = &[
    (0x7fc00000, 0x00000000),
    (0x7fc00005, 0x40a00000),
    (0x7f800005, 0x40a00000),
    (0xffc00005, 0x40a00000),
    (0x3f800000, 0xbf800000),
    (0x7f800000, 0xbf800000),
    (0x00000000, 0xbf800000),
    (0x7fffffff, 0x4a7ffffc),
];

#[test]
fn payload_matches_glibc() {
    let mut div: Vec<String> = Vec::new();
    for &(pb, ret, out) in SP64 {
        let mut o = f64::from_bits(0x1234567890abcdef);
        let r = unsafe { fl::setpayload(&mut o, f64::from_bits(pb)) };
        if r != ret || o.to_bits() != out {
            div.push(format!(
                "setpayload(0x{:016x}): fl=ret{}/0x{:016x} glibc=ret{}/0x{:016x}",
                pb,
                r,
                o.to_bits(),
                ret,
                out
            ));
        }
    }
    for &(pb, ret, out) in SS64 {
        let mut o = f64::from_bits(0x1234567890abcdef);
        let r = unsafe { fl::setpayloadsig(&mut o, f64::from_bits(pb)) };
        if r != ret || o.to_bits() != out {
            div.push(format!(
                "setpayloadsig(0x{:016x}): fl=ret{}/0x{:016x} glibc=ret{}/0x{:016x}",
                pb,
                r,
                o.to_bits(),
                ret,
                out
            ));
        }
    }
    for &(pb, ret, out) in SP32 {
        let mut o = f32::from_bits(0xdeadbeef);
        let r = unsafe { fl::setpayloadf(&mut o, f32::from_bits(pb)) };
        if r != ret || o.to_bits() != out {
            div.push(format!(
                "setpayloadf(0x{:08x}): fl=ret{}/0x{:08x} glibc=ret{}/0x{:08x}",
                pb,
                r,
                o.to_bits(),
                ret,
                out
            ));
        }
    }
    for &(pb, ret, out) in SS32 {
        let mut o = f32::from_bits(0xdeadbeef);
        let r = unsafe { fl::setpayloadsigf(&mut o, f32::from_bits(pb)) };
        if r != ret || o.to_bits() != out {
            div.push(format!(
                "setpayloadsigf(0x{:08x}): fl=ret{}/0x{:08x} glibc=ret{}/0x{:08x}",
                pb,
                r,
                o.to_bits(),
                ret,
                out
            ));
        }
    }
    for &(xb, pl) in GP64 {
        let x = f64::from_bits(xb);
        let g = unsafe { fl::getpayload(&x) }.to_bits();
        if g != pl {
            div.push(format!(
                "getpayload(0x{:016x}): fl=0x{:016x} glibc=0x{:016x}",
                xb, g, pl
            ));
        }
    }
    for &(xb, pl) in GP32 {
        let x = f32::from_bits(xb);
        let g = unsafe { fl::getpayloadf(&x) }.to_bits();
        if g != pl {
            div.push(format!(
                "getpayloadf(0x{:08x}): fl=0x{:08x} glibc=0x{:08x}",
                xb, g, pl
            ));
        }
    }
    assert!(
        div.is_empty(),
        "payload divergences vs glibc ({}):\n  {}",
        div.len(),
        div.join("\n  ")
    );
}

/// The same inputs, against the glibc that is actually running.
///
/// Three relations are recorded per case, not one, so a red names its own cause:
/// fl vs live is the parity claim; live vs the frozen golden says the HOST moved
/// (the `payload_matches_glibc` test above stays green in that case, which is
/// what tells the two apart).
#[test]
fn payload_matches_live_glibc_on_the_same_inputs() {
    let h = host();
    let mut fl_vs_live: Vec<String> = Vec::new();
    let mut host_moved: Vec<String> = Vec::new();
    let mut compared = 0usize;

    // The four setpayload variants share one shape: seed the output with a
    // recognisable pattern, call, then compare (return code, output bits). The
    // seed matters — a failing call must overwrite it with +0, and a call that
    // wrote nothing at all would otherwise read as a pass.
    for &(pb, gold_ret, gold_out) in SP64 {
        let mut o = f64::from_bits(0x1234567890abcdef);
        let r = unsafe { fl::setpayload(&mut o, f64::from_bits(pb)) };
        let mut ho = f64::from_bits(0x1234567890abcdef);
        // SAFETY: ho is a live f64 and the payload is passed by value.
        let hr = unsafe { (h.setpayload)(&mut ho, f64::from_bits(pb)) };
        compared += 1;
        if (r, o.to_bits()) != (hr, ho.to_bits()) {
            fl_vs_live.push(format!(
                "setpayload(0x{pb:016x}): fl=ret{r}/0x{:016x} live=ret{hr}/0x{:016x}",
                o.to_bits(),
                ho.to_bits()
            ));
        }
        if (hr, ho.to_bits()) != (gold_ret, gold_out) {
            host_moved.push(format!(
                "setpayload(0x{pb:016x}): live=ret{hr}/0x{:016x} golden=ret{gold_ret}/0x{gold_out:016x}",
                ho.to_bits()
            ));
        }
    }
    for &(pb, gold_ret, gold_out) in SS64 {
        let mut o = f64::from_bits(0x1234567890abcdef);
        let r = unsafe { fl::setpayloadsig(&mut o, f64::from_bits(pb)) };
        let mut ho = f64::from_bits(0x1234567890abcdef);
        // SAFETY: ho is a live f64 and the payload is passed by value.
        let hr = unsafe { (h.setpayloadsig)(&mut ho, f64::from_bits(pb)) };
        compared += 1;
        if (r, o.to_bits()) != (hr, ho.to_bits()) {
            fl_vs_live.push(format!(
                "setpayloadsig(0x{pb:016x}): fl=ret{r}/0x{:016x} live=ret{hr}/0x{:016x}",
                o.to_bits(),
                ho.to_bits()
            ));
        }
        if (hr, ho.to_bits()) != (gold_ret, gold_out) {
            host_moved.push(format!(
                "setpayloadsig(0x{pb:016x}): live=ret{hr}/0x{:016x} golden=ret{gold_ret}/0x{gold_out:016x}",
                ho.to_bits()
            ));
        }
    }
    for &(pb, gold_ret, gold_out) in SP32 {
        let mut o = f32::from_bits(0xdeadbeef);
        let r = unsafe { fl::setpayloadf(&mut o, f32::from_bits(pb)) };
        let mut ho = f32::from_bits(0xdeadbeef);
        // SAFETY: ho is a live f32 and the payload is passed by value.
        let hr = unsafe { (h.setpayloadf)(&mut ho, f32::from_bits(pb)) };
        compared += 1;
        if (r, o.to_bits()) != (hr, ho.to_bits()) {
            fl_vs_live.push(format!(
                "setpayloadf(0x{pb:08x}): fl=ret{r}/0x{:08x} live=ret{hr}/0x{:08x}",
                o.to_bits(),
                ho.to_bits()
            ));
        }
        if (hr, ho.to_bits()) != (gold_ret, gold_out) {
            host_moved.push(format!(
                "setpayloadf(0x{pb:08x}): live=ret{hr}/0x{:08x} golden=ret{gold_ret}/0x{gold_out:08x}",
                ho.to_bits()
            ));
        }
    }
    for &(pb, gold_ret, gold_out) in SS32 {
        let mut o = f32::from_bits(0xdeadbeef);
        let r = unsafe { fl::setpayloadsigf(&mut o, f32::from_bits(pb)) };
        let mut ho = f32::from_bits(0xdeadbeef);
        // SAFETY: ho is a live f32 and the payload is passed by value.
        let hr = unsafe { (h.setpayloadsigf)(&mut ho, f32::from_bits(pb)) };
        compared += 1;
        if (r, o.to_bits()) != (hr, ho.to_bits()) {
            fl_vs_live.push(format!(
                "setpayloadsigf(0x{pb:08x}): fl=ret{r}/0x{:08x} live=ret{hr}/0x{:08x}",
                o.to_bits(),
                ho.to_bits()
            ));
        }
        if (hr, ho.to_bits()) != (gold_ret, gold_out) {
            host_moved.push(format!(
                "setpayloadsigf(0x{pb:08x}): live=ret{hr}/0x{:08x} golden=ret{gold_ret}/0x{gold_out:08x}",
                ho.to_bits()
            ));
        }
    }
    for &(xb, gold) in GP64 {
        let x = f64::from_bits(xb);
        let g = unsafe { fl::getpayload(&x) }.to_bits();
        // SAFETY: x is a live f64; getpayload takes it by const pointer.
        let hg = unsafe { (h.getpayload)(&x) }.to_bits();
        compared += 1;
        if g != hg {
            fl_vs_live.push(format!(
                "getpayload(0x{xb:016x}): fl=0x{g:016x} live=0x{hg:016x}"
            ));
        }
        if hg != gold {
            host_moved.push(format!(
                "getpayload(0x{xb:016x}): live=0x{hg:016x} golden=0x{gold:016x}"
            ));
        }
    }
    for &(xb, gold) in GP32 {
        let x = f32::from_bits(xb);
        let g = unsafe { fl::getpayloadf(&x) }.to_bits();
        // SAFETY: x is a live f32; getpayloadf takes it by const pointer.
        let hg = unsafe { (h.getpayloadf)(&x) }.to_bits();
        compared += 1;
        if g != hg {
            fl_vs_live.push(format!(
                "getpayloadf(0x{xb:08x}): fl=0x{g:08x} live=0x{hg:08x}"
            ));
        }
        if hg != gold {
            host_moved.push(format!(
                "getpayloadf(0x{xb:08x}): live=0x{hg:08x} golden=0x{gold:08x}"
            ));
        }
    }

    // A zero divergence count is only evidence if every case was actually run.
    let expected = SP64.len() + SS64.len() + SP32.len() + SS32.len() + GP64.len() + GP32.len();
    assert_eq!(compared, expected, "not every case reached the live arm");
    assert!(
        fl_vs_live.is_empty() && host_moved.is_empty(),
        "payload: {} fl-vs-live divergence(s), {} case(s) where LIVE GLIBC differs from the \
         frozen golden (that second list means the host moved, not fl):\n  {}\n  {}",
        fl_vs_live.len(),
        host_moved.len(),
        fl_vs_live.join("\n  "),
        host_moved.join("\n  ")
    );
}
