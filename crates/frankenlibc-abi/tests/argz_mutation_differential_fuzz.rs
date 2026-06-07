#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // host-glibc argz oracle (libc, linked by std)

//! Randomized live differential fuzzer for the GNU `<argz.h>` MUTATION surface
//! vs host glibc. The existing `conformance_diff_argz` is fixed-case and only
//! exercises argz_create_sep/count/next/stringify; the mutating operations had
//! no randomized coverage.
//!
//! Design: each scenario draws a random op LIST, then replays it TWICE — once on
//! an fl argz buffer, once on a host argz buffer — recording a snapshot (entry
//! count, raw bytes, cumulative replace-count) after every op, and asserts the
//! two snapshot sequences are identical. The two replays are NOT interleaved so
//! fl and host argz never alias on the shared (glibc) process heap.
//!
//! Scope: this covers argz_add / argz_insert / argz_replace. argz_append and
//! argz_delete are intentionally NOT exercised here yet — they trigger a
//! `copy_nonoverlapping` precondition violation (UB) in fl's argz on valid
//! inputs, tracked separately as bd-2g7oyh.212; add them back to `gen_ops` to
//! reproduce once that is fixed.

use std::ffi::{CString, c_char, c_int, c_uint};

use frankenlibc_abi::string_abi as fl;

unsafe extern "C" {
    fn argz_add(argz: *mut *mut c_char, argz_len: *mut usize, str_: *const c_char) -> c_int;
    fn argz_insert(
        argz: *mut *mut c_char,
        argz_len: *mut usize,
        before: *mut c_char,
        entry: *const c_char,
    ) -> c_int;
    fn argz_replace(
        argz: *mut *mut c_char,
        argz_len: *mut usize,
        str_: *const c_char,
        with: *const c_char,
        replace_count: *mut c_uint,
    ) -> c_int;
    fn argz_count(argz: *const c_char, argz_len: usize) -> usize;
    fn argz_next(argz: *const c_char, argz_len: usize, entry: *const c_char) -> *mut c_char;
}

struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 { 0 } else { (self.next() >> 11) as usize % n }
    }
}

/// A short random token (sometimes empty) over a tiny alphabet.
fn token(r: &mut Lcg) -> Vec<u8> {
    const A: &[u8] = b"abc";
    let len = r.below(4);
    (0..len).map(|_| A[r.below(A.len())]).collect()
}

/// A non-empty random token — used as the `str` to find in argz_replace, since
/// glibc's behavior for an empty search string is unspecified.
fn token_nonempty(r: &mut Lcg) -> Vec<u8> {
    const A: &[u8] = b"abc";
    let len = 1 + r.below(3);
    (0..len).map(|_| A[r.below(A.len())]).collect()
}

/// A pre-drawn mutation (operands captured so both libraries replay identically).
#[derive(Debug, Clone)]
enum Op {
    Add(Vec<u8>),
    Insert(usize, Vec<u8>),
    Replace(Vec<u8>, Vec<u8>),
}

fn gen_ops(r: &mut Lcg) -> Vec<Op> {
    let n = 3 + r.below(12);
    (0..n)
        .map(|_| match r.below(3) {
            0 => Op::Add(token(r)),
            1 => Op::Insert(r.below(8), token(r)),
            _ => Op::Replace(token_nonempty(r), token(r)),
        })
        .collect()
}

/// One snapshot of an argz buffer after an op: (count, raw bytes, cumulative
/// replace-count returned so far).
type Snap = (usize, Vec<u8>, u32);

/// Replay `ops` against one library (selected by the fn idents) and return the
/// per-op snapshot sequence. Buffers are intentionally leaked (tiny, short test).
macro_rules! replay {
    ($ops:expr, $add:path, $insert:path, $replace:path, $count:path, $next:path) => {{
        let mut p: *mut c_char = std::ptr::null_mut();
        let mut len: usize = 0;
        let mut rc_total: u32 = 0;
        let mut snaps: Vec<Snap> = Vec::with_capacity($ops.len());
        let nth = |p: *mut c_char, len: usize, k: usize| -> *mut c_char {
            let mut e: *mut c_char = std::ptr::null_mut();
            for _ in 0..=k {
                e = unsafe { $next(p, len, e) };
                if e.is_null() {
                    return std::ptr::null_mut();
                }
            }
            e
        };
        for op in $ops.iter() {
            match op {
                Op::Add(t) => {
                    let c = CString::new(t.clone()).unwrap();
                    unsafe { $add(&mut p, &mut len, c.as_ptr()) };
                }
                Op::Insert(k, t) => {
                    let c = CString::new(t.clone()).unwrap();
                    let before = nth(p, len, *k);
                    unsafe { $insert(&mut p, &mut len, before, c.as_ptr()) };
                }
                Op::Replace(s, w) => {
                    let cs = CString::new(s.clone()).unwrap();
                    let cw = CString::new(w.clone()).unwrap();
                    let mut cnt: c_uint = 0;
                    unsafe { $replace(&mut p, &mut len, cs.as_ptr(), cw.as_ptr(), &mut cnt) };
                    rc_total = rc_total.wrapping_add(cnt);
                }
            }
            let count = unsafe { $count(p, len) };
            let bytes = if p.is_null() || len == 0 {
                Vec::new()
            } else {
                unsafe { std::slice::from_raw_parts(p as *const u8, len) }.to_vec()
            };
            snaps.push((count, bytes, rc_total));
        }
        snaps
    }};
}

#[test]
fn argz_mutation_differential_fuzz_vs_glibc() {
    let mut r = Lcg(0xa11c_e0f5_77aa_1234);
    let mut divs: Vec<String> = Vec::new();
    let mut compared: u64 = 0;

    for _ in 0..4000 {
        let ops = gen_ops(&mut r);
        let fl_snaps = replay!(
            ops,
            fl::argz_add,
            fl::argz_insert,
            fl::argz_replace,
            fl::argz_count,
            fl::argz_next
        );
        let host_snaps = replay!(ops, argz_add, argz_insert, argz_replace, argz_count, argz_next);
        for (i, (f, h)) in fl_snaps.iter().zip(host_snaps.iter()).enumerate() {
            compared += 1;
            if f != h && divs.len() < 30 {
                divs.push(format!(
                    "ops={:?}\n  step {i} ({:?})\n    fl   = count={} rc={} bytes={:?}\n    glibc= count={} rc={} bytes={:?}",
                    ops, ops[i],
                    f.0, f.2, String::from_utf8_lossy(&f.1),
                    h.0, h.2, String::from_utf8_lossy(&h.1),
                ));
            }
        }
    }

    assert!(
        divs.is_empty(),
        "argz mutations diverged from host glibc on {} step(s) (showing up to 30):\n{}",
        divs.len(),
        divs.join("\n")
    );
    eprintln!("argz mutation differential fuzz: {compared} ops compared, 0 divergences vs host glibc");
}
