#![cfg(target_os = "linux")]

//! Integration tests for `<search.h>` ABI entrypoints.
//!
//! Tests cover: hash tables (hcreate/hsearch/hdestroy + reentrant),
//! binary trees (tsearch/tfind/tdelete/twalk), linear search (lfind/lsearch),
//! and linked lists (insque/remque).

use std::ffi::{CString, c_char, c_int, c_void};

use frankenlibc_abi::search_abi::*;

unsafe fn malloc_tracked_unterminated(bytes: &[u8]) -> *mut c_char {
    let raw = unsafe { frankenlibc_abi::malloc_abi::malloc(bytes.len()) }.cast::<u8>();
    assert!(!raw.is_null());
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), raw, bytes.len()) };
    raw.cast()
}

#[repr(C)]
struct HsearchDataView {
    table: *mut c_void,
    size: usize,
    filled: usize,
}

fn htab_filled(htab: &HsearchData) -> usize {
    unsafe { (*(htab as *const HsearchData).cast::<HsearchDataView>()).filled }
}

// ===========================================================================
// Hash table: hcreate / hsearch / hdestroy
// ===========================================================================

/// All non-reentrant global hash table tests run sequentially in a single
/// test function because they share the process-wide `GLOBAL_HTAB` static
/// and would race if executed in parallel.
#[test]
fn hash_global_api() {
    // --- create and destroy ---
    let rc = unsafe { hcreate(16) };
    assert_eq!(rc, 1, "hcreate should succeed");
    unsafe { hdestroy() };

    // --- insert and find ---
    unsafe { hcreate(16) };

    let key = CString::new("testkey").unwrap();
    let item = Entry {
        key: key.as_ptr() as *mut _,
        data: 42usize as *mut c_void,
    };

    let result = unsafe { hsearch(item, Action::ENTER) };
    assert!(!result.is_null(), "ENTER should succeed");

    let found = unsafe { hsearch(item, Action::FIND) };
    assert!(!found.is_null(), "FIND should locate inserted key");
    assert_eq!(unsafe { (*found).data } as usize, 42);

    unsafe { hdestroy() };

    // --- find nonexistent returns null ---
    unsafe { hcreate(16) };

    let key = CString::new("missing").unwrap();
    let item = Entry {
        key: key.as_ptr() as *mut _,
        data: std::ptr::null_mut(),
    };

    let found = unsafe { hsearch(item, Action::FIND) };
    assert!(found.is_null(), "FIND on missing key should return null");

    unsafe { hdestroy() };

    // --- multiple entries ---
    unsafe { hcreate(64) };

    let keys: Vec<CString> = (0..10)
        .map(|i| CString::new(format!("key{i}")).unwrap())
        .collect();

    for (i, key) in keys.iter().enumerate() {
        let item = Entry {
            key: key.as_ptr() as *mut _,
            data: (i + 100) as *mut c_void,
        };
        let result = unsafe { hsearch(item, Action::ENTER) };
        assert!(!result.is_null(), "ENTER key{i} should succeed");
    }

    for (i, key) in keys.iter().enumerate() {
        let item = Entry {
            key: key.as_ptr() as *mut _,
            data: std::ptr::null_mut(),
        };
        let found = unsafe { hsearch(item, Action::FIND) };
        assert!(!found.is_null(), "FIND key{i} should succeed");
        assert_eq!(unsafe { (*found).data } as usize, i + 100);
    }

    unsafe { hdestroy() };

    // --- tracked unterminated keys must not be hashed past their allocation ---
    unsafe { hcreate(16) };

    let raw_key = unsafe { malloc_tracked_unterminated(b"unterminated-key") };
    let item = Entry {
        key: raw_key,
        data: 123usize as *mut c_void,
    };
    let inserted = unsafe { hsearch(item, Action::ENTER) };
    assert!(
        inserted.is_null(),
        "ENTER with an unterminated tracked key should fail"
    );
    unsafe {
        frankenlibc_abi::malloc_abi::free(raw_key.cast());
        hdestroy();
    }

    // --- duplicate ENTER: inserting an existing key returns the original entry ---
    unsafe { hcreate(16) };

    let key = CString::new("overwrite_key").unwrap();
    let item1 = Entry {
        key: key.as_ptr() as *mut _,
        data: 100usize as *mut c_void,
    };
    let r1 = unsafe { hsearch(item1, Action::ENTER) };
    assert!(!r1.is_null());

    // Insert same key again with different data
    let item2 = Entry {
        key: key.as_ptr() as *mut _,
        data: 200usize as *mut c_void,
    };
    let r2 = unsafe { hsearch(item2, Action::ENTER) };
    assert!(!r2.is_null());
    assert_eq!(
        unsafe { (*r2).data } as usize,
        100,
        "duplicate ENTER should keep the original payload"
    );

    unsafe { hdestroy() };
}

// ===========================================================================
// Reentrant hash table: hcreate_r / hsearch_r / hdestroy_r
// ===========================================================================

#[test]
fn hash_reentrant_lifecycle() {
    // POSIX: callers zero-initialize hsearch_data before hcreate_r
    let mut htab: HsearchData = unsafe { std::mem::zeroed() };

    let rc = unsafe { hcreate_r(16, &mut htab) };
    assert_eq!(rc, 1, "hcreate_r should succeed");

    let key = CString::new("rkey").unwrap();
    let item = Entry {
        key: key.as_ptr() as *mut _,
        data: 99usize as *mut c_void,
    };

    let mut result: *mut Entry = std::ptr::null_mut();
    let rc = unsafe { hsearch_r(item, Action::ENTER, &mut result, &mut htab) };
    assert_eq!(rc, 1);
    assert!(!result.is_null());
    assert_eq!(
        htab_filled(&htab),
        1,
        "filled should track successful inserts"
    );

    let mut found: *mut Entry = std::ptr::null_mut();
    let rc = unsafe { hsearch_r(item, Action::FIND, &mut found, &mut htab) };
    assert_eq!(rc, 1);
    assert!(!found.is_null());
    assert_eq!(unsafe { (*found).data } as usize, 99);

    unsafe { hdestroy_r(&mut htab) };
    assert_eq!(
        htab_filled(&htab),
        0,
        "hdestroy_r should reset filled count"
    );
}

#[test]
fn hash_reentrant_null_safety() {
    let rc = unsafe { hcreate_r(16, std::ptr::null_mut()) };
    assert_eq!(rc, 0, "hcreate_r with null htab should fail");

    unsafe { hdestroy_r(std::ptr::null_mut()) };
    // Should not crash
}

#[test]
fn hsearch_r_rejects_tracked_unterminated_key() {
    let mut htab: HsearchData = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { hcreate_r(16, &mut htab) }, 1);

    let raw_key = unsafe { malloc_tracked_unterminated(b"unterminated-rkey") };
    let item = Entry {
        key: raw_key,
        data: 321usize as *mut c_void,
    };
    let mut result: *mut Entry = std::ptr::null_mut();
    let rc = unsafe { hsearch_r(item, Action::ENTER, &mut result, &mut htab) };

    assert_eq!(rc, 0);
    assert!(result.is_null());

    unsafe {
        hdestroy_r(&mut htab);
        frankenlibc_abi::malloc_abi::free(raw_key.cast());
    }
}

// ===========================================================================
// Binary tree: tsearch / tfind / tdelete / twalk
// ===========================================================================

/// Integer comparison function for tree operations.
unsafe extern "C" fn int_compare(a: *const c_void, b: *const c_void) -> c_int {
    let va = a as usize as i64;
    let vb = b as usize as i64;
    if va < vb {
        -1
    } else if va > vb {
        1
    } else {
        0
    }
}

#[test]
fn tree_insert_and_find() {
    let mut root: *mut c_void = std::ptr::null_mut();

    // Insert values 5, 3, 7
    let r1 = unsafe { tsearch(5usize as *const c_void, &mut root, int_compare) };
    assert!(!r1.is_null(), "tsearch(5) should succeed");
    assert!(!root.is_null(), "root should be set after insert");

    let r2 = unsafe { tsearch(3usize as *const c_void, &mut root, int_compare) };
    assert!(!r2.is_null(), "tsearch(3) should succeed");

    let r3 = unsafe { tsearch(7usize as *const c_void, &mut root, int_compare) };
    assert!(!r3.is_null(), "tsearch(7) should succeed");

    // Find existing
    let found = unsafe { tfind(5usize as *const c_void, &root as *const _, int_compare) };
    assert!(!found.is_null(), "tfind(5) should find it");

    let found3 = unsafe { tfind(3usize as *const c_void, &root as *const _, int_compare) };
    assert!(!found3.is_null(), "tfind(3) should find it");

    // Find non-existing
    let missing = unsafe { tfind(99usize as *const c_void, &root as *const _, int_compare) };
    assert!(missing.is_null(), "tfind(99) should return null");

    // Cleanup: delete all nodes
    unsafe {
        tdelete(5usize as *const c_void, &mut root, int_compare);
        tdelete(3usize as *const c_void, &mut root, int_compare);
        tdelete(7usize as *const c_void, &mut root, int_compare);
    }
}

#[test]
fn tree_delete() {
    let mut root: *mut c_void = std::ptr::null_mut();

    unsafe {
        tsearch(10usize as *const c_void, &mut root, int_compare);
        tsearch(5usize as *const c_void, &mut root, int_compare);
        tsearch(15usize as *const c_void, &mut root, int_compare);
    }

    // Delete leaf node
    let result = unsafe { tdelete(5usize as *const c_void, &mut root, int_compare) };
    assert!(!result.is_null(), "tdelete(5) should succeed");

    let missing = unsafe { tfind(5usize as *const c_void, &root as *const _, int_compare) };
    assert!(missing.is_null(), "5 should be gone after delete");

    // 10 and 15 still there
    let found10 = unsafe { tfind(10usize as *const c_void, &root as *const _, int_compare) };
    assert!(!found10.is_null(), "10 should still exist");

    // Cleanup
    unsafe {
        tdelete(15usize as *const c_void, &mut root, int_compare);
        tdelete(10usize as *const c_void, &mut root, int_compare);
    }
}

#[test]
fn tree_null_safety() {
    let key = std::ptr::dangling::<c_void>();
    let result = unsafe { tsearch(key, std::ptr::null_mut(), int_compare) };
    assert!(
        result.is_null(),
        "tsearch with null rootp should return null"
    );

    let result = unsafe { tfind(key, std::ptr::null(), int_compare) };
    assert!(result.is_null(), "tfind with null rootp should return null");
}

use std::sync::atomic::{AtomicU32, Ordering};

static WALK_COUNT: AtomicU32 = AtomicU32::new(0);

unsafe extern "C" fn walk_counter(_node: *const c_void, _visit: Visit, _level: c_int) {
    WALK_COUNT.fetch_add(1, Ordering::Relaxed);
}

#[test]
fn tree_walk() {
    let mut root: *mut c_void = std::ptr::null_mut();

    unsafe {
        tsearch(10usize as *const c_void, &mut root, int_compare);
        tsearch(5usize as *const c_void, &mut root, int_compare);
        tsearch(15usize as *const c_void, &mut root, int_compare);
    }

    WALK_COUNT.store(0, Ordering::Relaxed);
    unsafe { twalk(root, walk_counter) };

    let count = WALK_COUNT.load(Ordering::Relaxed);
    // Root (10) has two children: preorder + postorder + endorder = 3
    // Left (5) is leaf = 1
    // Right (15) is leaf = 1
    // Total = 5
    assert_eq!(count, 5, "walk should visit root 3 times + 2 leaves");

    // Cleanup
    unsafe {
        tdelete(5usize as *const c_void, &mut root, int_compare);
        tdelete(15usize as *const c_void, &mut root, int_compare);
        tdelete(10usize as *const c_void, &mut root, int_compare);
    }
}

// ===========================================================================
// Linear search: lfind / lsearch
// ===========================================================================

unsafe extern "C" fn int_array_compare(a: *const c_void, b: *const c_void) -> c_int {
    let va = unsafe { *(a as *const i32) };
    let vb = unsafe { *(b as *const i32) };
    if va == vb { 0 } else { 1 }
}

#[test]
fn lfind_existing() {
    let arr: [i32; 5] = [10, 20, 30, 40, 50];
    let mut nel: usize = 5;
    let key: i32 = 30;

    let result = unsafe {
        lfind(
            &key as *const i32 as *const c_void,
            arr.as_ptr() as *const c_void,
            &mut nel,
            std::mem::size_of::<i32>(),
            int_array_compare,
        )
    };

    assert!(!result.is_null(), "lfind should find 30");
    assert_eq!(unsafe { *(result as *const i32) }, 30);
}

#[test]
fn lfind_missing() {
    let arr: [i32; 5] = [10, 20, 30, 40, 50];
    let mut nel: usize = 5;
    let key: i32 = 99;

    let result = unsafe {
        lfind(
            &key as *const i32 as *const c_void,
            arr.as_ptr() as *const c_void,
            &mut nel,
            std::mem::size_of::<i32>(),
            int_array_compare,
        )
    };

    assert!(result.is_null(), "lfind should not find 99");
}

#[test]
fn lsearch_inserts_missing() {
    let mut arr: [i32; 8] = [10, 20, 30, 0, 0, 0, 0, 0];
    let mut nel: usize = 3;
    let key: i32 = 25;

    let result = unsafe {
        lsearch(
            &key as *const i32 as *const c_void,
            arr.as_mut_ptr() as *mut c_void,
            &mut nel,
            std::mem::size_of::<i32>(),
            int_array_compare,
        )
    };

    assert!(!result.is_null(), "lsearch should return new element");
    assert_eq!(nel, 4, "count should increase");
    assert_eq!(arr[3], 25, "new element should be appended");
}

#[test]
fn lsearch_finds_existing() {
    let mut arr: [i32; 8] = [10, 20, 30, 0, 0, 0, 0, 0];
    let mut nel: usize = 3;
    let key: i32 = 20;

    let result = unsafe {
        lsearch(
            &key as *const i32 as *const c_void,
            arr.as_mut_ptr() as *mut c_void,
            &mut nel,
            std::mem::size_of::<i32>(),
            int_array_compare,
        )
    };

    assert!(!result.is_null(), "lsearch should find existing");
    assert_eq!(nel, 3, "count should NOT increase");
    assert_eq!(unsafe { *(result as *const i32) }, 20);
}

#[test]
fn lfind_null_safety() {
    let mut nel: usize = 0;
    let result = unsafe {
        lfind(
            std::ptr::null(),
            std::ptr::null(),
            &mut nel,
            4,
            int_array_compare,
        )
    };
    assert!(result.is_null());
}

// ===========================================================================
// Linked list: insque / remque
// ===========================================================================

#[repr(C)]
struct QueueNode {
    next: *mut QueueNode,
    prev: *mut QueueNode,
    value: i32,
}

impl QueueNode {
    fn new(value: i32) -> Self {
        QueueNode {
            next: std::ptr::null_mut(),
            prev: std::ptr::null_mut(),
            value,
        }
    }
}

#[test]
fn insque_single_element() {
    let mut node = QueueNode::new(1);
    unsafe {
        insque(
            &mut node as *mut QueueNode as *mut c_void,
            std::ptr::null_mut(),
        )
    };
    assert!(node.next.is_null());
    assert!(node.prev.is_null());
}

#[test]
fn insque_chain() {
    let mut a = QueueNode::new(1);
    let mut b = QueueNode::new(2);
    let mut c = QueueNode::new(3);

    // Build chain: a -> b -> c
    unsafe {
        insque(&mut a as *mut _ as *mut c_void, std::ptr::null_mut());
        insque(
            &mut b as *mut _ as *mut c_void,
            &mut a as *mut _ as *mut c_void,
        );
        insque(
            &mut c as *mut _ as *mut c_void,
            &mut b as *mut _ as *mut c_void,
        );
    }

    assert_eq!(a.next, &mut b as *mut _);
    assert_eq!(b.prev, &mut a as *mut _);
    assert_eq!(b.next, &mut c as *mut _);
    assert_eq!(c.prev, &mut b as *mut _);
    assert!(c.next.is_null());
}

#[test]
fn remque_middle() {
    let mut a = QueueNode::new(1);
    let mut b = QueueNode::new(2);
    let mut c = QueueNode::new(3);

    unsafe {
        insque(&mut a as *mut _ as *mut c_void, std::ptr::null_mut());
        insque(
            &mut b as *mut _ as *mut c_void,
            &mut a as *mut _ as *mut c_void,
        );
        insque(
            &mut c as *mut _ as *mut c_void,
            &mut b as *mut _ as *mut c_void,
        );
    }

    // Remove b from the middle
    unsafe { remque(&mut b as *mut _ as *mut c_void) };

    assert_eq!(a.next, &mut c as *mut _);
    assert_eq!(c.prev, &mut a as *mut _);
    assert_eq!(
        b.next, &mut c as *mut _,
        "removed node keeps its original next link"
    );
    assert_eq!(
        b.prev, &mut a as *mut _,
        "removed node keeps its original prev link"
    );
}

#[test]
fn remque_null_safety() {
    unsafe { remque(std::ptr::null_mut()) };
    // Should not crash
}

// ===========================================================================
// Additional hash table tests
// ===========================================================================

#[test]
fn hash_reentrant_multiple_tables() {
    // Two independent reentrant tables
    let mut htab1: HsearchData = unsafe { std::mem::zeroed() };
    let mut htab2: HsearchData = unsafe { std::mem::zeroed() };

    assert_eq!(unsafe { hcreate_r(16, &mut htab1) }, 1);
    assert_eq!(unsafe { hcreate_r(16, &mut htab2) }, 1);

    let key1 = CString::new("t1_key").unwrap();
    let item1 = Entry {
        key: key1.as_ptr() as *mut _,
        data: 11usize as *mut c_void,
    };
    let mut result: *mut Entry = std::ptr::null_mut();
    assert_eq!(
        unsafe { hsearch_r(item1, Action::ENTER, &mut result, &mut htab1) },
        1
    );

    let key2 = CString::new("t2_key").unwrap();
    let item2 = Entry {
        key: key2.as_ptr() as *mut _,
        data: 22usize as *mut c_void,
    };
    let mut result2: *mut Entry = std::ptr::null_mut();
    assert_eq!(
        unsafe { hsearch_r(item2, Action::ENTER, &mut result2, &mut htab2) },
        1
    );

    // Key from table1 should not be found in table2
    let mut found: *mut Entry = std::ptr::null_mut();
    let rc = unsafe { hsearch_r(item1, Action::FIND, &mut found, &mut htab2) };
    assert_eq!(rc, 0, "table1's key should not be in table2");

    unsafe {
        hdestroy_r(&mut htab1);
        hdestroy_r(&mut htab2);
    }
}

#[test]
fn hash_reentrant_find_nonexistent() {
    let mut htab: HsearchData = unsafe { std::mem::zeroed() };
    unsafe { hcreate_r(16, &mut htab) };

    let key = CString::new("nope").unwrap();
    let item = Entry {
        key: key.as_ptr() as *mut _,
        data: std::ptr::null_mut(),
    };
    let mut found: *mut Entry = std::ptr::null_mut();
    let rc = unsafe { hsearch_r(item, Action::FIND, &mut found, &mut htab) };
    assert_eq!(rc, 0, "FIND on empty table should fail");

    unsafe { hdestroy_r(&mut htab) };
}

#[test]
fn hash_reentrant_filled_tracks_unique_entries() {
    let mut htab: HsearchData = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { hcreate_r(16, &mut htab) }, 1);
    assert_eq!(htab_filled(&htab), 0);

    let key = CString::new("filled-key").unwrap();
    let item = Entry {
        key: key.as_ptr() as *mut _,
        data: 123usize as *mut c_void,
    };
    let mut result: *mut Entry = std::ptr::null_mut();

    assert_eq!(
        unsafe { hsearch_r(item, Action::ENTER, &mut result, &mut htab) },
        1
    );
    assert!(!result.is_null());
    assert_eq!(
        htab_filled(&htab),
        1,
        "first insert should increment filled"
    );

    result = std::ptr::null_mut();
    assert_eq!(
        unsafe { hsearch_r(item, Action::ENTER, &mut result, &mut htab) },
        1
    );
    assert!(!result.is_null());
    assert_eq!(
        htab_filled(&htab),
        1,
        "duplicate ENTER should return existing entry without changing filled"
    );
    assert_eq!(
        unsafe { (*result).data } as usize,
        123,
        "filled accounting should not change the stored payload"
    );

    let updated = Entry {
        key: key.as_ptr() as *mut _,
        data: 456usize as *mut c_void,
    };
    result = std::ptr::null_mut();
    assert_eq!(
        unsafe { hsearch_r(updated, Action::ENTER, &mut result, &mut htab) },
        1
    );
    assert!(!result.is_null());
    assert_eq!(
        htab_filled(&htab),
        1,
        "duplicate ENTER for an existing key must not change filled"
    );
    assert_eq!(
        unsafe { (*result).data } as usize,
        123,
        "duplicate ENTER should keep the original stored payload"
    );

    unsafe { hdestroy_r(&mut htab) };
}

// ===========================================================================
// Additional binary tree tests
// ===========================================================================

#[test]
fn tree_duplicate_insert() {
    let mut root: *mut c_void = std::ptr::null_mut();

    let r1 = unsafe { tsearch(42usize as *const c_void, &mut root, int_compare) };
    assert!(!r1.is_null());

    // Inserting same value again should return existing node
    let r2 = unsafe { tsearch(42usize as *const c_void, &mut root, int_compare) };
    assert!(!r2.is_null());
    assert_eq!(r1, r2, "duplicate insert should return same node");

    unsafe { tdelete(42usize as *const c_void, &mut root, int_compare) };
}

#[test]
fn tree_delete_nonexistent() {
    let mut root: *mut c_void = std::ptr::null_mut();
    unsafe { tsearch(10usize as *const c_void, &mut root, int_compare) };

    let result = unsafe { tdelete(99usize as *const c_void, &mut root, int_compare) };
    assert!(
        result.is_null(),
        "tdelete on nonexistent key should return null"
    );

    unsafe { tdelete(10usize as *const c_void, &mut root, int_compare) };
}

#[test]
fn tree_single_element_delete() {
    let mut root: *mut c_void = std::ptr::null_mut();
    unsafe { tsearch(77usize as *const c_void, &mut root, int_compare) };

    let result = unsafe { tdelete(77usize as *const c_void, &mut root, int_compare) };
    assert!(!result.is_null(), "deleting only element should succeed");

    // Tree should now be empty
    let found = unsafe { tfind(77usize as *const c_void, &root as *const _, int_compare) };
    assert!(
        found.is_null(),
        "tree should be empty after deleting only element"
    );
}

#[test]
fn tree_many_elements() {
    let mut root: *mut c_void = std::ptr::null_mut();

    // Insert 20 elements
    for i in 0..20usize {
        let r = unsafe { tsearch(i as *const c_void, &mut root, int_compare) };
        assert!(!r.is_null(), "tsearch({i}) should succeed");
    }

    // Find all of them
    for i in 0..20usize {
        let found = unsafe { tfind(i as *const c_void, &root as *const _, int_compare) };
        assert!(!found.is_null(), "tfind({i}) should succeed");
    }

    // Delete all
    for i in 0..20usize {
        unsafe { tdelete(i as *const c_void, &mut root, int_compare) };
    }
}

#[test]
fn tfind_empty_tree() {
    let root: *mut c_void = std::ptr::null_mut();
    let found = unsafe { tfind(55usize as *const c_void, &root as *const _, int_compare) };
    assert!(found.is_null(), "tfind on empty tree should return null");
}

#[test]
fn tdelete_from_empty_tree() {
    let mut root: *mut c_void = std::ptr::null_mut();
    let result = unsafe { tdelete(55usize as *const c_void, &mut root, int_compare) };
    assert!(
        result.is_null(),
        "tdelete from empty tree should return null"
    );
}

// ===========================================================================
// twalk_r (reentrant walk)
// ===========================================================================

static WALK_R_COUNT: AtomicU32 = AtomicU32::new(0);

unsafe extern "C" fn walk_r_counter(
    _node: *const c_void,
    _visit: c_int,
    _level: c_int,
    _closure: *mut c_void,
) {
    WALK_R_COUNT.fetch_add(1, Ordering::Relaxed);
}

#[test]
fn tree_walk_r() {
    let mut root: *mut c_void = std::ptr::null_mut();

    unsafe {
        tsearch(10usize as *const c_void, &mut root, int_compare);
        tsearch(5usize as *const c_void, &mut root, int_compare);
        tsearch(15usize as *const c_void, &mut root, int_compare);
    }

    WALK_R_COUNT.store(0, Ordering::Relaxed);
    unsafe { twalk_r(root, walk_r_counter, std::ptr::null_mut()) };

    let count = WALK_R_COUNT.load(Ordering::Relaxed);
    assert_eq!(count, 5, "walk_r should visit root 3 times + 2 leaves");

    unsafe {
        tdelete(5usize as *const c_void, &mut root, int_compare);
        tdelete(15usize as *const c_void, &mut root, int_compare);
        tdelete(10usize as *const c_void, &mut root, int_compare);
    }
}

#[test]
fn twalk_null_root() {
    // Walking a null root should not crash
    WALK_COUNT.store(0, Ordering::Relaxed);
    unsafe { twalk(std::ptr::null_mut(), walk_counter) };
    assert_eq!(WALK_COUNT.load(Ordering::Relaxed), 0);
}

// ===========================================================================
// Additional linear search tests
// ===========================================================================

#[test]
fn lsearch_grows_array() {
    let mut arr: [i32; 16] = [0; 16];
    arr[0] = 10;
    arr[1] = 20;
    let mut nel: usize = 2;

    // Insert 30, 40, 50
    for val in [30, 40, 50] {
        let result = unsafe {
            lsearch(
                &val as *const i32 as *const c_void,
                arr.as_mut_ptr() as *mut c_void,
                &mut nel,
                std::mem::size_of::<i32>(),
                int_array_compare,
            )
        };
        assert!(!result.is_null());
    }
    assert_eq!(nel, 5, "should have 5 elements");
    assert_eq!(arr[2], 30);
    assert_eq!(arr[3], 40);
    assert_eq!(arr[4], 50);
}

#[test]
fn lfind_first_element() {
    let arr: [i32; 3] = [100, 200, 300];
    let mut nel: usize = 3;
    let key: i32 = 100;

    let result = unsafe {
        lfind(
            &key as *const i32 as *const c_void,
            arr.as_ptr() as *const c_void,
            &mut nel,
            std::mem::size_of::<i32>(),
            int_array_compare,
        )
    };
    assert!(!result.is_null());
    assert_eq!(unsafe { *(result as *const i32) }, 100);
}

#[test]
fn lfind_last_element() {
    let arr: [i32; 3] = [100, 200, 300];
    let mut nel: usize = 3;
    let key: i32 = 300;

    let result = unsafe {
        lfind(
            &key as *const i32 as *const c_void,
            arr.as_ptr() as *const c_void,
            &mut nel,
            std::mem::size_of::<i32>(),
            int_array_compare,
        )
    };
    assert!(!result.is_null());
    assert_eq!(unsafe { *(result as *const i32) }, 300);
}

// ===========================================================================
// Linked list: additional insque/remque tests
// ===========================================================================

#[test]
fn remque_head() {
    let mut a = QueueNode::new(1);
    let mut b = QueueNode::new(2);

    unsafe {
        insque(&mut a as *mut _ as *mut c_void, std::ptr::null_mut());
        insque(
            &mut b as *mut _ as *mut c_void,
            &mut a as *mut _ as *mut c_void,
        );
    }

    // Remove head
    unsafe { remque(&mut a as *mut _ as *mut c_void) };
    assert!(b.prev.is_null(), "b should be new head with null prev");
}

#[test]
fn remque_tail() {
    let mut a = QueueNode::new(1);
    let mut b = QueueNode::new(2);

    unsafe {
        insque(&mut a as *mut _ as *mut c_void, std::ptr::null_mut());
        insque(
            &mut b as *mut _ as *mut c_void,
            &mut a as *mut _ as *mut c_void,
        );
    }

    // Remove tail
    unsafe { remque(&mut b as *mut _ as *mut c_void) };
    assert!(a.next.is_null(), "a should now have null next");
}

#[test]
fn insque_builds_four_node_chain() {
    let mut a = QueueNode::new(1);
    let mut b = QueueNode::new(2);
    let mut c = QueueNode::new(3);
    let mut d = QueueNode::new(4);

    unsafe {
        insque(&mut a as *mut _ as *mut c_void, std::ptr::null_mut());
        insque(
            &mut b as *mut _ as *mut c_void,
            &mut a as *mut _ as *mut c_void,
        );
        insque(
            &mut c as *mut _ as *mut c_void,
            &mut b as *mut _ as *mut c_void,
        );
        insque(
            &mut d as *mut _ as *mut c_void,
            &mut c as *mut _ as *mut c_void,
        );
    }

    // Verify full chain: a <-> b <-> c <-> d
    assert!(a.prev.is_null());
    assert_eq!(a.next, &mut b as *mut _);
    assert_eq!(b.prev, &mut a as *mut _);
    assert_eq!(b.next, &mut c as *mut _);
    assert_eq!(c.prev, &mut b as *mut _);
    assert_eq!(c.next, &mut d as *mut _);
    assert_eq!(d.prev, &mut c as *mut _);
    assert!(d.next.is_null());
}
