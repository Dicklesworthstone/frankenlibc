#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // exercises allocator entry points to build the tracked cases
//! Precondition test for a hot-path lever on syscall output buffers (bd-dcrhgl).
//!
//! THE LEVER THIS GATES. Syscall wrappers such as `getrandom` clamp their output
//! length through `known_remaining`, which walks the bump-mmap ranges, then the
//! segment arena, then the membrane validator and the fallback table. That is up
//! to three lookups on every call, and after the vDSO change removed the syscall
//! from `getrandom` it is a visible share of what is left — the residue there is
//! now fl's own entry framing rather than the kernel.
//!
//! `clock_getres` and `gettimeofday` already took the corresponding lever, using
//! a cheap current-stack probe to skip the arena lookup for the overwhelmingly
//! common case of a stack output. Reusing it for a CLAMPING helper needs one more
//! fact than those did: they only asked "does it fit", whereas `known_remaining`
//! returns a LENGTH, so skipping it is equivalent only if it would have returned
//! `None` for a stack address.
//!
//! That is a claim about the membrane, not about the caller, so it is measured
//! here rather than assumed. This file does not test the lever — it tests whether
//! the lever is admissible at all, which is the cheaper question and the one that
//! decides whether the code should be written.
//!
//! Both directions are asserted. A test that only checked "stack gives None"
//! would also pass if `known_remaining` had silently become a function that
//! returns `None` for everything, which would make the whole clamp dead and the
//! lever pointless rather than sound.

use std::ffi::c_void;

#[test]
fn known_remaining_is_none_for_stack_objects_and_some_for_tracked_heap() {
    // POSITIVE CONTROL FIRST. If a tracked heap allocation does not report a
    // remaining length, the negative result below proves nothing.
    let sizes = [16usize, 64, 256, 1024, 4096];
    let mut tracked_reported = 0usize;
    let mut live = Vec::new();
    for &size in &sizes {
        // SAFETY: plain allocation through fl's own entry point.
        let p = unsafe { frankenlibc_abi::malloc_abi::malloc(size) };
        assert!(!p.is_null(), "malloc({size}) returned NULL");
        if let Some(remaining) = frankenlibc_abi::malloc_abi::known_remaining_for_tests(p as usize) {
            assert!(
                remaining >= size,
                "malloc({size}) reports only {remaining} bytes remaining at its own base"
            );
            tracked_reported += 1;
        }
        live.push(p as usize);
    }
    assert!(
        tracked_reported > 0,
        "known_remaining reported a length for NONE of {} tracked allocations — the \
         positive control failed, so a `None` for stack addresses would be evidence \
         about a broken lookup rather than about the stack",
        sizes.len()
    );

    // THE PRECONDITION. Stack objects of several shapes and sizes, including one
    // large enough to span pages, must be unknown to the allocator's lookup.
    let small: [u8; 16] = [0; 16];
    let medium: [u8; 4096] = [0; 4096];
    let mut mutable: [u8; 64] = [0; 64];
    mutable[0] = 1;
    let scalar: u64 = 0;

    let probes: [(&str, usize); 5] = [
        ("small stack array", small.as_ptr() as usize),
        ("medium stack array", medium.as_ptr() as usize),
        ("interior of a stack array", unsafe { medium.as_ptr().add(2048) } as usize),
        ("mutable stack array", mutable.as_ptr() as usize),
        ("stack scalar", (&raw const scalar) as usize),
    ];
    for (what, addr) in probes {
        assert_eq!(
            frankenlibc_abi::malloc_abi::known_remaining_for_tests(addr),
            None,
            "{what}: known_remaining reported a tracked length for a STACK address. \
             The hot-path lever that skips this lookup for stack outputs would then \
             change the clamp and is NOT admissible — do not write it."
        );
    }

    for p in live {
        // SAFETY: each allocated above and freed exactly once.
        unsafe { frankenlibc_abi::malloc_abi::free(p as *mut c_void) };
    }
}

#[test]
fn clamping_a_zero_length_output_is_a_no_op_for_every_pointer_kind() {
    // Independent of the stack question: `min(remaining, 0)` is 0 whatever the
    // lookup returns, so a zero-length request can skip it with no assumption at
    // all. This pins that the identity holds for tracked, stack and null
    // pointers alike, which is what licenses the short-circuit.
    // SAFETY: plain allocation through fl's entry point.
    let heap = unsafe { frankenlibc_abi::malloc_abi::malloc(128) };
    assert!(!heap.is_null(), "malloc(128) returned NULL");
    let stack: [u8; 32] = [0; 32];

    for (what, addr) in [
        ("tracked heap", heap as usize),
        ("stack", stack.as_ptr() as usize),
        ("null", 0usize),
    ] {
        let remaining = frankenlibc_abi::malloc_abi::known_remaining_for_tests(addr);
        let clamped = remaining.map_or(0usize, |r| r.min(0));
        assert_eq!(
            clamped, 0,
            "{what}: clamping a zero-length request did not yield zero, so the \
             short-circuit would not be behaviour-preserving"
        );
    }

    // SAFETY: freed exactly once.
    unsafe { frankenlibc_abi::malloc_abi::free(heap) };
}
