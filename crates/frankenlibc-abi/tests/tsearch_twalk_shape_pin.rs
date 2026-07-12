#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // exercises the tsearch/twalk C ABI surface

//! Regression pin for FrankenLibC's deterministic `tsearch`/`twalk` tree shape
//! (bd-2g7oyh.311, resolved as a documented conformant divergence).
//!
//! POSIX leaves the *shape* of the `tsearch`-managed tree unspecified, so the
//! `level` (depth) and leaf-vs-internal classification reported by `twalk`
//! legitimately differ between implementations. fl backs `tsearch` with a
//! balanced left-leaning red-black tree; glibc uses a classic parent-pointer
//! red-black tree. For the in-order insertion 1..=7 the two build different
//! (both valid) trees:
//!   * glibc: root = key 2 at depth 0 (right-leaning / skewed)
//!   * fl   : root = key 4 at depth 0 (perfectly balanced)
//!
//! The differential gate `conformance_diff_tsearch` already pins the *observable
//! set contract* (in-order key sequence, membership, delete correctness) as
//! byte-identical to glibc. This test instead pins fl's OWN shape so an
//! accidental change to the core LLRB rebalancing (which would silently alter
//! every `twalk` consumer's indentation) is caught — WITHOUT depending on the
//! host glibc, so it is stable across glibc versions. Mirroring glibc's exact
//! RB shape is deliberately NOT done: it is a multi-hour bit-for-bit port of
//! glibc's misc/tsearch.c rebalancing that would risk the already-perfect
//! set/order parity to chase a POSIX-unspecified detail of ~zero value.

use std::cell::RefCell;
use std::ffi::{c_int, c_void};

use frankenlibc_abi::search_abi as fl;

thread_local! {
    /// (level, visit-as-int, key) tuples in the order `twalk` emits them.
    static TRACE: RefCell<Vec<(i32, i32, i64)>> = const { RefCell::new(Vec::new()) };
}

unsafe extern "C" fn cmp(a: *const c_void, b: *const c_void) -> c_int {
    let av = unsafe { *(a as *const i64) };
    let bv = unsafe { *(b as *const i64) };
    (av - bv).signum() as c_int
}

unsafe extern "C" fn act(node: *const c_void, visit: fl::Visit, level: c_int) {
    // `node`, cast to void**, dereferences to the stored key pointer.
    let keyp = unsafe { *(node as *const *const c_void) };
    let key = unsafe { *(keyp as *const i64) };
    TRACE.with(|t| t.borrow_mut().push((level, visit as i32, key)));
}

fn trace_fl(keys: &[i64]) -> Vec<(i32, i32, i64)> {
    TRACE.with(|t| t.borrow_mut().clear());
    let mut root: *mut c_void = std::ptr::null_mut();
    for k in keys {
        // SAFETY: each &i64 outlives the walk; fl::tsearch stores the pointer.
        unsafe { fl::tsearch(k as *const i64 as *const c_void, &mut root, cmp) };
    }
    // SAFETY: root is the live tree handle produced above.
    unsafe { fl::twalk(root, act) };
    let out = TRACE.with(|t| t.borrow().clone());
    // SAFETY: drop the tree state (root was allocated by fl::tsearch).
    unsafe { fl::tdestroy(root, None) };
    out
}

// Visit discriminants (must match search_abi::Visit).
const PRE: i32 = 0;
const POST: i32 = 1;
const END: i32 = 2;
const LEAF: i32 = 3;

#[test]
fn fl_twalk_shape_for_1_to_7_is_balanced() {
    let keys: Vec<i64> = (1..=7).collect();
    let trace = trace_fl(&keys);

    // Exact deterministic trace of fl's balanced LLRB. Root (the first, depth-0
    // preorder visit) is key 4, NOT glibc's key 2 — the by-design divergence.
    let expected: Vec<(i32, i32, i64)> = vec![
        (0, PRE, 4),
        (1, PRE, 2),
        (2, LEAF, 1),
        (1, POST, 2),
        (2, LEAF, 3),
        (1, END, 2),
        (0, POST, 4),
        (1, PRE, 6),
        (2, LEAF, 5),
        (1, POST, 6),
        (2, LEAF, 7),
        (1, END, 6),
        (0, END, 4),
    ];
    assert_eq!(
        trace, expected,
        "fl twalk shape changed — the core LLRB rebalancing was altered"
    );

    // Root is at depth 0 with key 4 (balanced), not glibc's skewed key 2.
    assert_eq!(
        trace[0],
        (0, PRE, 4),
        "fl root must be the balanced median key 4"
    );
    // Max depth of fl's balanced 7-node tree is 2 (glibc's skewed tree reaches 3).
    let max_depth = trace.iter().map(|&(lvl, _, _)| lvl).max().unwrap();
    assert_eq!(max_depth, 2, "balanced 7-node LLRB must be depth-2");
}

#[test]
fn fl_twalk_inorder_keys_are_sorted() {
    // The OBSERVABLE set contract (independent of shape): the keys emitted at a
    // node's POSTORDER visit (internal nodes) or LEAF visit (leaves), taken in
    // emission order, are the live keys in sorted order. This is what
    // conformance_diff_tsearch proves matches glibc; reasserted here shape-free.
    for keys in [
        vec![1i64, 2, 3, 4, 5, 6, 7],
        vec![5, 3, 8, 1, 4, 7, 9, 2, 6],
        vec![50, 40, 30, 20, 10],
        (1..=31).collect::<Vec<i64>>(),
    ] {
        let trace = trace_fl(&keys);
        let inorder: Vec<i64> = trace
            .iter()
            .filter(|&&(_, v, _)| v == POST || v == LEAF)
            .map(|&(_, _, k)| k)
            .collect();
        let mut sorted = keys.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            inorder, sorted,
            "twalk in-order key sequence must be the sorted live set"
        );
    }
}
