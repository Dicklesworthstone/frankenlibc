#![cfg(target_os = "linux")]

//! Correctness gate for the address-derived slab ownership test (bd-e0y02p).
//!
//! The design's stated falsification criterion is about the ownership test, not
//! the allocator: if it is not cheap, the design is abandoned rather than tuned.
//! But cheap is worthless if it is wrong, and the specific way it could be wrong
//! is dangerous — a false positive means masking a foreign pointer and reading a
//! header out of memory FrankenLibC does not own. So correctness is gated here
//! and cost is measured separately.
//!
//! Written as an INTEGRATION test on purpose: this crate gates its inline
//! `#[cfg(test)]` modules behind `cfg(not(test))`, so unit tests inside
//! `src/slab_region.rs` would never compile and would look like passing coverage
//! that does not exist (bd-0z7a1y).
//!
//! No allocation path is exercised — `register` is called with addresses that
//! are never dereferenced, which is exactly the property under test.

use frankenlibc_abi::slab_region::{
    header_of, live_regions, owns, register, unregister, MAX_REGIONS, SLAB_ALIGN,
};

/// A region base that is aligned but deliberately NOT mapped.
///
/// Nothing in this module may dereference it, and that is the point: the
/// ownership test must answer from its own tables. If a future change starts
/// touching the header inside `owns`, this test faults instead of passing
/// quietly.
const FAKE_BASE: usize = 0x0000_7f00_0000_0000;

#[test]
fn rejects_everything_before_any_region_is_registered() {
    // The envelope starts inverted (lo = usize::MAX, hi = 0) so that the
    // pre-registration answer is a two-compare reject rather than a scan.
    assert!(!owns(0), "null must never be owned");
    assert!(!owns(FAKE_BASE), "an unregistered region must not be owned");
    assert_eq!(header_of(FAKE_BASE), None);

    // A stack address: the most common foreign pointer in practice.
    let local = 0u64;
    let stack_addr = &local as *const u64 as usize;
    assert!(!owns(stack_addr), "a stack address must not be slab-owned");
}

#[test]
fn accepts_only_within_a_registered_region() {
    let base = FAKE_BASE + 16 * SLAB_ALIGN;
    assert!(register(base, SLAB_ALIGN), "registration should succeed");

    assert!(owns(base), "the base itself is owned");
    assert!(owns(base + SLAB_ALIGN - 1), "the last byte is owned");
    assert!(!owns(base + SLAB_ALIGN), "one past the end is NOT owned");
    assert!(
        !owns(base - 1),
        "one before the base is NOT owned -- an off-by-one here would mask into \
         a neighbouring region's header"
    );

    // The mask must land on the base for every address in the region.
    assert_eq!(header_of(base), Some(base));
    assert_eq!(header_of(base + 1), Some(base));
    assert_eq!(header_of(base + SLAB_ALIGN - 1), Some(base));

    assert!(unregister(base), "unregistration should succeed");
    assert!(!owns(base), "a released region is no longer owned");
}

#[test]
fn rejects_alignment_and_overflow_abuse() {
    // Misaligned base: accepting it would break the mask invariant, because
    // `addr & !(SLAB_ALIGN-1)` would not be the region base.
    assert!(
        !register(FAKE_BASE + 1, SLAB_ALIGN),
        "a misaligned base must be refused"
    );
    // Length not a multiple of the granule: the tail would be claimed but
    // unmaskable.
    assert!(
        !register(FAKE_BASE + 32 * SLAB_ALIGN, SLAB_ALIGN + 1),
        "a non-granule length must be refused"
    );
    assert!(!register(0, SLAB_ALIGN), "a null base must be refused");
    assert!(!register(FAKE_BASE, 0), "a zero length must be refused");
    // base + len overflowing usize must not wrap into a huge accepted range.
    assert!(
        !register(usize::MAX - SLAB_ALIGN + 1, SLAB_ALIGN * 2),
        "an overflowing region must be refused"
    );
}

#[test]
fn the_table_fills_and_then_declines_without_panicking() {
    // Exhausting the table is a normal condition, not a failure: later
    // reservations simply are not slab-tracked and fall back to the arena path.
    // A panic here would turn a capacity limit into an allocator crash.
    let mut registered = Vec::new();
    for slot in 0..MAX_REGIONS + 4 {
        let base = FAKE_BASE + (1024 + slot) * SLAB_ALIGN;
        if register(base, SLAB_ALIGN) {
            registered.push(base);
        }
    }
    assert!(
        registered.len() <= MAX_REGIONS,
        "registered {} regions, table holds {MAX_REGIONS}",
        registered.len()
    );
    assert!(
        live_regions() <= MAX_REGIONS,
        "live count must respect the table bound"
    );
    for base in registered {
        assert!(owns(base), "every accepted region must answer owned");
        unregister(base);
    }
}

#[test]
fn a_released_region_leaves_the_envelope_wide_but_answers_false() {
    // Documented behaviour, asserted so it cannot be "optimised" into a bug:
    // the envelope is never narrowed on release. A stale-wide envelope costs a
    // region scan that correctly answers false; narrowing it under concurrency
    // could transiently exclude a LIVE region, which in `free` would leak.
    let base = FAKE_BASE + 2048 * SLAB_ALIGN;
    assert!(register(base, SLAB_ALIGN));
    assert!(owns(base));
    assert!(unregister(base));

    // Still inside the (unnarrowed) envelope, so this exercises the scan path
    // rather than the envelope reject -- and must still be false.
    assert!(!owns(base), "a released region must answer false via the scan");
    assert_eq!(header_of(base), None);
}
