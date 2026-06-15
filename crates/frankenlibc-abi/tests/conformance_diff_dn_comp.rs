//! Differential gate: dn_comp must match glibc byte-for-byte, including RFC
//! 1035 compression-pointer emission via dnptrs suffix matching.
//!
//! Both fl and glibc dn_comp build the same DNS message when fed the same name
//! sequence through a shared dnptrs array, so this drives each independently
//! (glibc via dlsym) and compares the produced message bytes plus every
//! per-call return value. Sequences exercise full-name reuse, shared suffixes,
//! distinct names (no compression), case-insensitive matching, and the root.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::unistd_abi as flu;
use std::ffi::{CString, c_char, c_int, c_void};

const RTLD_NOW: c_int = 2;

unsafe extern "C" {
    fn dlopen(filename: *const c_char, flag: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
}
type DnCompFn = unsafe extern "C" fn(*const c_char, *mut u8, c_int, *mut *mut u8, *mut *mut u8) -> c_int;

/// Build a message by packing `names` in sequence through one dnptrs array.
/// Returns (message bytes written, per-call return values).
fn build(dn_comp: DnCompFn, names: &[&str]) -> (Vec<u8>, Vec<c_int>) {
    // Fixed, non-reallocating buffer so dnptrs entries stay valid.
    let mut msg = vec![0u8; 8192];
    let base = msg.as_mut_ptr();
    const NPTR: usize = 64;
    let mut dnptrs = [std::ptr::null_mut::<u8>(); NPTR];
    dnptrs[0] = base; // message origin
    dnptrs[1] = std::ptr::null_mut(); // end-of-list marker
    let lastdnptr = unsafe { dnptrs.as_mut_ptr().add(NPTR) };

    let mut off = 0usize;
    let mut rets = Vec::new();
    for name in names {
        let cn = CString::new(*name).unwrap();
        let dst = unsafe { base.add(off) };
        let avail = (msg.len() - off) as c_int;
        let r = unsafe { dn_comp(cn.as_ptr(), dst, avail, dnptrs.as_mut_ptr(), lastdnptr) };
        rets.push(r);
        if r > 0 {
            off += r as usize;
        } else {
            break;
        }
    }
    (msg[..off].to_vec(), rets)
}

#[test]
fn dn_comp_matches_glibc() {
    let g: DnCompFn = unsafe {
        let lib = dlopen(c"libc.so.6".as_ptr(), RTLD_NOW);
        assert!(!lib.is_null(), "dlopen libc.so.6 failed");
        let s = dlsym(lib, c"dn_comp".as_ptr());
        assert!(!s.is_null(), "dlsym dn_comp failed");
        std::mem::transmute::<*mut c_void, DnCompFn>(s)
    };

    let sequences: &[&[&str]] = &[
        &["www.example.com", "mail.example.com", "ftp.example.com"],
        &["example.com", "example.com"],
        &["a.b.c", "x.b.c", "b.c", "c"],
        &["a.com", "b.org", "c.net"],
        &["WWW.Example.COM", "mail.example.com"],
        &["one.two.three.four", "two.three.four", "three.four", "four"],
        &["host.sub.domain.example.org", "other.example.org", "example.org"],
        &["."],
        &["a", "a.", "a"],
        &["x.y", "z.x.y", "y"],
        &["alpha.beta", "beta", "gamma.beta", "delta.gamma.beta"],
    ];

    let mut mismatches = Vec::new();
    for (i, seq) in sequences.iter().enumerate() {
        let (gmsg, grets) = build(g, seq);
        let (fmsg, frets) = build(flu::dn_comp, seq);
        if grets != frets {
            mismatches.push(format!("seq#{i} {seq:?}: rets glibc={grets:?} fl={frets:?}"));
        }
        if gmsg != fmsg {
            mismatches.push(format!(
                "seq#{i} {seq:?}: message bytes differ\n  glibc={gmsg:02x?}\n  fl   ={fmsg:02x?}"
            ));
        }
    }

    // Deterministic pseudo-random fuzz: random sequences of names assembled
    // from a tiny label pool so suffixes collide constantly (the regime where
    // compression actually fires). Seeded LCG keeps it reproducible.
    let pool = ["a", "b", "c", "example", "com", "net", "www", "mail", "x", "y"];
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut next = || {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (state >> 33) as usize
    };
    for round in 0..400 {
        let nnames = 1 + next() % 5;
        let mut names: Vec<String> = Vec::new();
        for _ in 0..nnames {
            let nlabels = 1 + next() % 4;
            let mut parts: Vec<&str> = Vec::new();
            for _ in 0..nlabels {
                parts.push(pool[next() % pool.len()]);
            }
            let mut s = parts.join(".");
            if next() % 4 == 0 {
                s.push('.'); // sometimes fully qualified
            }
            names.push(s);
        }
        let refs: Vec<&str> = names.iter().map(|s| s.as_str()).collect();
        let (gmsg, grets) = build(g, &refs);
        let (fmsg, frets) = build(flu::dn_comp, &refs);
        if grets != frets || gmsg != fmsg {
            mismatches.push(format!(
                "fuzz#{round} {refs:?}: rets g={grets:?} f={frets:?}\n  g={gmsg:02x?}\n  f={fmsg:02x?}"
            ));
        }
    }

    assert!(
        mismatches.is_empty(),
        "dn_comp diverged from glibc ({} cases):\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
}
