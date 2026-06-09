#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // host-glibc argz oracle (libc, linked by std)

//! Randomized differential fuzzers for the GNU `<argz.h>` MUTATION surface.
//! The live host-glibc oracle covers argz_add / argz_insert / argz_replace.
//! A separate pure-Rust argz model covers argz_append / argz_delete as well, so
//! those paths can be tested without mixing host-glibc argz allocation with
//! FrankenLibC's malloc ABI in one process. The existing `conformance_diff_argz`
//! is fixed-case and only covers create_sep/count/next/stringify.
//!
//! Design: each scenario draws a random op LIST, then replays it TWICE — once on
//! an fl argz buffer, once on a host argz buffer — recording a snapshot (entry
//! count, raw bytes, cumulative replace-count) after every op, and asserts the
//! two snapshot sequences are byte-identical. The two replays are NOT interleaved
//! so fl and host argz never alias on the shared process heap.
//!
//! Two harness details, both forced by fl's argz allocating from fl's own
//! allocator (`malloc_abi`) while the host argz uses glibc's heap in the same
//! process:
//!   * The per-op byte snapshot copies the argz buffer with a MANUAL loop, not
//!     `slice::to_vec` — `to_vec`'s `copy_nonoverlapping` precondition check can
//!     spuriously flag the fl (malloc_abi) source vs the snapshot (global-alloc)
//!     destination as "overlapping".
//!   * argz_append / argz_delete are intentionally NOT exercised against host
//!     glibc: churning the host argz allocator alongside fl's `malloc_abi` on
//!     the larger buffers those ops produce corrupts the shared process heap
//!     (SIGSEGV). bd-2g7oyh.212 covers them with the pure-Rust model below.

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
        if n == 0 {
            0
        } else {
            (self.next() >> 11) as usize % n
        }
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
    Append(Vec<Vec<u8>>),
    Delete(usize),
}

fn gen_host_ops(r: &mut Lcg) -> Vec<Op> {
    let n = 3 + r.below(12);
    (0..n)
        .map(|_| match r.below(3) {
            0 => Op::Add(token(r)),
            1 => Op::Insert(r.below(8), token(r)),
            _ => Op::Replace(token_nonempty(r), token(r)),
        })
        .collect()
}

fn append_payload(r: &mut Lcg) -> Vec<Vec<u8>> {
    let n = r.below(4);
    (0..n).map(|_| token(r)).collect()
}

fn gen_model_ops(r: &mut Lcg) -> Vec<Op> {
    let n = 3 + r.below(12);
    (0..n)
        .map(|_| match r.below(5) {
            0 => Op::Add(token(r)),
            1 => Op::Insert(r.below(8), token(r)),
            2 => Op::Replace(token_nonempty(r), token(r)),
            3 => Op::Append(append_payload(r)),
            _ => Op::Delete(r.below(8)),
        })
        .collect()
}

/// One snapshot of an argz buffer after an op: (count, raw bytes, cumulative
/// replace-count returned so far).
type Snap = (usize, Vec<u8>, u32);

fn argz_bytes(entries: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for entry in entries {
        out.extend_from_slice(entry);
        out.push(0);
    }
    out
}

fn replace_substrings(entry: &[u8], find: &[u8], with: &[u8]) -> (Vec<u8>, bool) {
    let mut out = Vec::with_capacity(entry.len());
    let mut matched = false;
    let mut pos = 0usize;
    while pos < entry.len() {
        if entry[pos..].starts_with(find) {
            out.extend_from_slice(with);
            pos += find.len();
            matched = true;
        } else {
            out.push(entry[pos]);
            pos += 1;
        }
    }
    (out, matched)
}

fn model_replay(ops: &[Op]) -> Vec<Snap> {
    let mut entries: Vec<Vec<u8>> = Vec::new();
    let mut rc_total = 0u32;
    let mut snaps = Vec::with_capacity(ops.len());
    for op in ops {
        match op {
            Op::Add(t) => entries.push(t.clone()),
            Op::Insert(k, t) => {
                if *k < entries.len() {
                    entries.insert(*k, t.clone());
                } else {
                    entries.push(t.clone());
                }
            }
            Op::Replace(s, w) => {
                for entry in &mut entries {
                    let (rebuilt, matched) = replace_substrings(entry, s, w);
                    if matched {
                        rc_total = rc_total.wrapping_add(1);
                    }
                    *entry = rebuilt;
                }
            }
            Op::Append(more) => entries.extend(more.iter().cloned()),
            Op::Delete(k) => {
                if *k < entries.len() {
                    entries.remove(*k);
                }
            }
        }
        snaps.push((entries.len(), argz_bytes(&entries), rc_total));
    }
    snaps
}

fn nth_entry(p: *mut c_char, len: usize, k: usize) -> *mut c_char {
    let mut e: *mut c_char = std::ptr::null_mut();
    for _ in 0..=k {
        e = unsafe { fl::argz_next(p, len, e) };
        if e.is_null() {
            return std::ptr::null_mut();
        }
    }
    e
}

fn snapshot_fl(p: *mut c_char, len: usize, rc_total: u32) -> Snap {
    let count = unsafe { fl::argz_count(p, len) };
    let mut bytes = Vec::with_capacity(len);
    if !p.is_null() {
        for i in 0..len {
            bytes.push(unsafe { *(p as *const u8).add(i) });
        }
    }
    (count, bytes, rc_total)
}

fn fl_model_replay(ops: &[Op]) -> Vec<Snap> {
    let mut p: *mut c_char = std::ptr::null_mut();
    let mut len: usize = 0;
    let mut rc_total = 0u32;
    let mut snaps = Vec::with_capacity(ops.len());
    for op in ops {
        match op {
            Op::Add(t) => {
                let c = CString::new(t.clone()).unwrap();
                unsafe { fl::argz_add(&mut p, &mut len, c.as_ptr()) };
            }
            Op::Insert(k, t) => {
                let c = CString::new(t.clone()).unwrap();
                let before = nth_entry(p, len, *k);
                unsafe { fl::argz_insert(&mut p, &mut len, before, c.as_ptr()) };
            }
            Op::Replace(s, w) => {
                let cs = CString::new(s.clone()).unwrap();
                let cw = CString::new(w.clone()).unwrap();
                let mut cnt: c_uint = 0;
                unsafe { fl::argz_replace(&mut p, &mut len, cs.as_ptr(), cw.as_ptr(), &mut cnt) };
                rc_total = rc_total.wrapping_add(cnt);
            }
            Op::Append(more) => {
                let raw = argz_bytes(more);
                let ptr = if raw.is_empty() {
                    std::ptr::null()
                } else {
                    raw.as_ptr().cast::<c_char>()
                };
                unsafe { fl::argz_append(&mut p, &mut len, ptr, raw.len()) };
            }
            Op::Delete(k) => {
                let entry = nth_entry(p, len, *k);
                unsafe { fl::argz_delete(&mut p, &mut len, entry) };
            }
        }
        snaps.push(snapshot_fl(p, len, rc_total));
    }
    snaps
}

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
                Op::Append(_) | Op::Delete(_) => {
                    unreachable!("host-glibc replay only receives add/insert/replace ops")
                }
            }
            let count = unsafe { $count(p, len) };
            // Manual byte copy (NOT slice::to_vec) — see the module note on the
            // cross-allocator copy_nonoverlapping artifact (bd-2g7oyh.212).
            let mut bytes = Vec::with_capacity(len);
            if !p.is_null() {
                for i in 0..len {
                    bytes.push(unsafe { *(p as *const u8).add(i) });
                }
            }
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
        let ops = gen_host_ops(&mut r);
        let fl_snaps = replay!(
            ops,
            fl::argz_add,
            fl::argz_insert,
            fl::argz_replace,
            fl::argz_count,
            fl::argz_next
        );
        let host_snaps = replay!(
            ops,
            argz_add,
            argz_insert,
            argz_replace,
            argz_count,
            argz_next
        );
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
    eprintln!(
        "argz mutation differential fuzz: {compared} ops compared, 0 divergences vs host glibc"
    );
}

#[test]
fn argz_mutation_model_fuzz_includes_append_delete() {
    let mut r = Lcg(0x212a_117e_5afe_cafe);
    let mut divs: Vec<String> = Vec::new();
    let mut compared: u64 = 0;

    for _ in 0..4000 {
        let ops = gen_model_ops(&mut r);
        let fl_snaps = fl_model_replay(&ops);
        let model_snaps = model_replay(&ops);
        for (i, (f, m)) in fl_snaps.iter().zip(model_snaps.iter()).enumerate() {
            compared += 1;
            if f != m && divs.len() < 30 {
                divs.push(format!(
                    "ops={:?}\n  step {i} ({:?})\n    fl   = count={} rc={} bytes={:?}\n    model= count={} rc={} bytes={:?}",
                    ops, ops[i],
                    f.0, f.2, String::from_utf8_lossy(&f.1),
                    m.0, m.2, String::from_utf8_lossy(&m.1),
                ));
            }
        }
    }

    assert!(
        divs.is_empty(),
        "argz mutations diverged from pure Rust model on {} step(s) (showing up to 30):\n{}",
        divs.len(),
        divs.join("\n")
    );
    eprintln!("argz mutation model fuzz: {compared} ops compared, 0 divergences");
}
