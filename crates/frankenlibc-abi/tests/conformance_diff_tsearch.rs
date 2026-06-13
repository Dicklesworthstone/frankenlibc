#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc tsearch/tfind/tdelete/twalk oracle

//! `tsearch`/`tfind`/`tdelete`/`twalk` parity vs host glibc (bd-tsearch-twalk).
//!
//! POSIX leaves the *shape* of the managed binary tree unspecified, so the
//! `level` argument and the leaf-vs-internal classification that `twalk` reports
//! legitimately differ between implementations: fl backs `tsearch` with a
//! balanced left-leaning red-black tree, while glibc uses a classic
//! parent-pointer red-black tree, and the two produce different (both valid)
//! trees for the same insertion order. See the companion bead for the deliberate
//! shape divergence.
//!
//! What MUST match — and what this gate pins — is the *observable set behaviour*:
//!   * the in-order key sequence `twalk` produces (postorder for internal nodes
//!     + leaf visits) is the sorted set of live keys, identical across engines;
//!   * `tfind` membership agrees on every probe key;
//!   * `tdelete` is set-correct: after an interleaved insert/delete script the
//!     surviving key set (and its in-order sequence) is identical to glibc's.
//!
//! Before this gate, the whole `tsearch` family had no differential coverage.

use std::cell::RefCell;
use std::ffi::{c_int, c_void};

use frankenlibc_abi::search_abi as fl;

unsafe extern "C" {
    fn tsearch(
        key: *const c_void,
        rootp: *mut *mut c_void,
        compar: unsafe extern "C" fn(*const c_void, *const c_void) -> c_int,
    ) -> *mut c_void;
    fn tfind(
        key: *const c_void,
        rootp: *const *mut c_void,
        compar: unsafe extern "C" fn(*const c_void, *const c_void) -> c_int,
    ) -> *mut c_void;
    fn tdelete(
        key: *const c_void,
        rootp: *mut *mut c_void,
        compar: unsafe extern "C" fn(*const c_void, *const c_void) -> c_int,
    ) -> *mut c_void;
    fn twalk(root: *const c_void, action: unsafe extern "C" fn(*const c_void, c_int, c_int));
}

// Stable key arena: never reallocated for the lifetime of a tree, so the raw
// pointers handed to {t,}search stay valid through every walk.
const ARENA: usize = 256;

thread_local! {
    static INORDER: RefCell<Vec<i64>> = const { RefCell::new(Vec::new()) };
}

unsafe extern "C" fn cmp(a: *const c_void, b: *const c_void) -> c_int {
    let av = unsafe { *(a as *const i64) };
    let bv = unsafe { *(b as *const i64) };
    match av.cmp(&bv) {
        std::cmp::Ordering::Less => -1,
        std::cmp::Ordering::Equal => 0,
        std::cmp::Ordering::Greater => 1,
    }
}

// POSIX VISIT enum: preorder=0, postorder=1, endorder=2, leaf=3.
// The sorted in-order position of every node is its `postorder` visit (internal)
// or its `leaf` visit (childless node).
unsafe extern "C" fn collect_glibc(node: *const c_void, visit: c_int, _level: c_int) {
    if visit == 1 || visit == 3 {
        let keyp = unsafe { *(node as *const *const c_void) };
        let key = unsafe { *(keyp as *const i64) };
        INORDER.with(|t| t.borrow_mut().push(key));
    }
}

unsafe extern "C" fn collect_fl(node: *const c_void, visit: fl::Visit, _level: c_int) {
    let v = visit as i32;
    if v == 1 || v == 3 {
        let keyp = unsafe { *(node as *const *const c_void) };
        let key = unsafe { *(keyp as *const i64) };
        INORDER.with(|t| t.borrow_mut().push(key));
    }
}

/// Drive one engine through an insert/delete script and return the in-order key
/// sequence reported by `twalk` after the script completes.
fn run_script(eng: u8, arena: &[i64], ops: &[(bool, usize)]) -> Vec<i64> {
    INORDER.with(|t| t.borrow_mut().clear());
    let mut root: *mut c_void = std::ptr::null_mut();
    for &(insert, idx) in ops {
        let kp = &arena[idx] as *const i64 as *const c_void;
        if insert {
            if eng == 0 {
                unsafe { fl::tsearch(kp, &mut root, cmp) };
            } else {
                unsafe { tsearch(kp, &mut root, cmp) };
            }
        } else if eng == 0 {
            unsafe { fl::tdelete(kp, &mut root, cmp) };
        } else {
            unsafe { tdelete(kp, &mut root, cmp) };
        }
    }
    if !root.is_null() {
        if eng == 0 {
            unsafe { fl::twalk(root, collect_fl) };
        } else {
            unsafe { twalk(root, collect_glibc) };
        }
    }
    INORDER.with(|t| t.borrow().clone())
}

/// Membership of every arena key via `tfind`, as a bitmask vector.
fn membership(eng: u8, arena: &[i64], ops: &[(bool, usize)]) -> Vec<bool> {
    let mut root: *mut c_void = std::ptr::null_mut();
    for &(insert, idx) in ops {
        let kp = &arena[idx] as *const i64 as *const c_void;
        if insert {
            if eng == 0 {
                unsafe { fl::tsearch(kp, &mut root, cmp) };
            } else {
                unsafe { tsearch(kp, &mut root, cmp) };
            }
        } else if eng == 0 {
            unsafe { fl::tdelete(kp, &mut root, cmp) };
        } else {
            unsafe { tdelete(kp, &mut root, cmp) };
        }
    }
    (0..arena.len())
        .map(|i| {
            let kp = &arena[i] as *const i64 as *const c_void;
            let f = if eng == 0 {
                unsafe { fl::tfind(kp, &root, cmp) }
            } else {
                unsafe { tfind(kp, &root, cmp) }
            };
            !f.is_null()
        })
        .collect()
}

fn arena() -> Vec<i64> {
    (0..ARENA as i64).collect()
}

// A small deterministic xorshift so the fuzz script is reproducible and needs no
// forbidden Date/rand sources.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}

#[test]
fn tsearch_inorder_and_membership_match_glibc() {
    let arena = arena();

    // Curated insertion orders that exercise different balance pressures.
    let curated: Vec<Vec<(bool, usize)>> = vec![
        (0..7).map(|i| (true, i)).collect(),
        (0..15).map(|i| (true, i)).collect(),
        (0..31).map(|i| (true, i)).collect(),
        (0..15).rev().map(|i| (true, i)).collect(),
        vec![5, 3, 8, 1, 4, 7, 9, 2, 6, 0]
            .into_iter()
            .map(|i| (true, i))
            .collect(),
        // Insert-then-delete interleavings (exercise tdelete rebalancing).
        {
            let mut v: Vec<(bool, usize)> = (0..20).map(|i| (true, i)).collect();
            for i in (0..20).step_by(2) {
                v.push((false, i));
            }
            v
        },
        {
            let mut v: Vec<(bool, usize)> = (0..16).map(|i| (true, i)).collect();
            for i in [1usize, 14, 7, 0, 15, 8, 3] {
                v.push((false, i));
            }
            v
        },
        // Delete a missing key (no-op on both).
        vec![(true, 10), (true, 20), (false, 200), (true, 5)],
    ];

    for (ci, ops) in curated.iter().enumerate() {
        let fl_seq = run_script(0, &arena, ops);
        let gl_seq = run_script(1, &arena, ops);
        assert_eq!(
            fl_seq, gl_seq,
            "curated case {ci}: in-order key sequence diverged\n fl={fl_seq:?}\n gl={gl_seq:?}"
        );
        let fl_mem = membership(0, &arena, ops);
        let gl_mem = membership(1, &arena, ops);
        assert_eq!(
            fl_mem, gl_mem,
            "curated case {ci}: tfind membership diverged"
        );
    }

    // Randomized insert/delete scripts over the arena.
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    for trial in 0..400 {
        let len = 8 + (rng.next() as usize % 120);
        let ops: Vec<(bool, usize)> = (0..len)
            .map(|_| {
                let insert = rng.next() & 1 == 0;
                let idx = rng.next() as usize % ARENA;
                (insert, idx)
            })
            .collect();
        let fl_seq = run_script(0, &arena, &ops);
        let gl_seq = run_script(1, &arena, &ops);
        assert_eq!(
            fl_seq, gl_seq,
            "random trial {trial}: in-order key sequence diverged"
        );
        let fl_mem = membership(0, &arena, &ops);
        let gl_mem = membership(1, &arena, &ops);
        assert_eq!(
            fl_mem, gl_mem,
            "random trial {trial}: tfind membership diverged"
        );
    }
}
