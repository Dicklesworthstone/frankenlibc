//! ABI layer for `<search.h>` — POSIX hash table, binary tree, and linear search.
//!
//! Provides:
//! - Hash table: `hcreate`, `hsearch`, `hdestroy`, `hcreate_r`, `hsearch_r`, `hdestroy_r`
//! - Binary tree: `tsearch`, `tfind`, `tdelete`, `twalk`, `twalk_r`
//! - Linear search: `lfind`, `lsearch`
//! - Linked list: `insque`, `remque`

use std::ffi::{c_char, c_int, c_void};
use std::sync::Mutex;

// ---------------------------------------------------------------------------
// POSIX ENTRY type and ACTION enum
// ---------------------------------------------------------------------------

/// POSIX `ENTRY` — key/data pair for hash table operations.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Entry {
    pub key: *mut c_char,
    pub data: *mut c_void,
}

/// POSIX `ACTION` — hash table search action.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Action {
    FIND = 0,
    ENTER = 1,
}

// ---------------------------------------------------------------------------
// Global hash table (non-reentrant API)
// ---------------------------------------------------------------------------

// Hash table backing comes from frankenlibc-core. Keys are `*mut c_char`
// (the user's NUL-terminated key strings), values are `*mut c_void`.
// Both are wrapped in #[repr(transparent)] newtypes so the generic
// LinearSlot<HashKey, HashData> has the same memory layout as POSIX
// Entry: { key: *mut c_char, data: *mut c_void, ... }.
//
// Layout-compat hack (matches glibc): casting `&LinearSlot<HashKey, HashData>`
// to `*mut Entry` is well-defined because the first two fields of
// LinearSlot (key, value) are the only fields Entry exposes.

use frankenlibc_core::search::LinearProbeTable;

#[repr(transparent)]
#[derive(Clone, Copy)]
struct HashKey(*mut c_char);

impl Default for HashKey {
    fn default() -> Self {
        HashKey(std::ptr::null_mut())
    }
}

#[repr(transparent)]
#[derive(Clone, Copy)]
struct HashData(*mut c_void);

impl Default for HashData {
    fn default() -> Self {
        HashData(std::ptr::null_mut())
    }
}

// SAFETY: hash table is only accessed under Mutex; the wrapped raw
// pointers are C-owned and the abi layer guarantees serialization.
unsafe impl Send for HashKey {}
unsafe impl Send for HashData {}

unsafe fn hash_key_len(ptr: *mut c_char) -> Option<usize> {
    if ptr.is_null() {
        return None;
    }
    let bound = crate::malloc_abi::known_remaining(ptr as usize);
    let (len, terminated) = unsafe { crate::util::scan_c_string(ptr.cast_const(), bound) };
    terminated.then_some(len)
}

fn hash_key_valid(ptr: *mut c_char) -> bool {
    unsafe { hash_key_len(ptr).is_some() }
}

fn hash_key_djb2(k: &HashKey) -> u64 {
    let Some(len) = (unsafe { hash_key_len(k.0) }) else {
        return 0;
    };
    let mut h = frankenlibc_core::search::hash::djb2_seed();
    let bytes = unsafe { std::slice::from_raw_parts(k.0.cast::<u8>(), len) };
    for &c in bytes {
        h = frankenlibc_core::search::hash::djb2_step(h, c);
    }
    h
}

fn hash_keys_equal(a: &HashKey, b: &HashKey) -> bool {
    let Some(a_len) = (unsafe { hash_key_len(a.0) }) else {
        return a.0 == b.0;
    };
    let Some(b_len) = (unsafe { hash_key_len(b.0) }) else {
        return false;
    };
    if a_len != b_len {
        return false;
    }
    let a_bytes = unsafe { std::slice::from_raw_parts(a.0.cast::<u8>(), a_len) };
    let b_bytes = unsafe { std::slice::from_raw_parts(b.0.cast::<u8>(), b_len) };
    a_bytes == b_bytes
}

type HashTable = LinearProbeTable<HashKey, HashData>;

static GLOBAL_HTAB: Mutex<Option<HashTable>> = Mutex::new(None);

/// POSIX `hcreate` — create a global hash table.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn hcreate(nel: usize) -> c_int {
    let mut guard = GLOBAL_HTAB.lock().unwrap_or_else(|e| e.into_inner());
    *guard = Some(HashTable::new(nel));
    1
}

/// POSIX `hsearch` — search or insert into the global hash table.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn hsearch(item: Entry, action: Action) -> *mut Entry {
    if !hash_key_valid(item.key) {
        return std::ptr::null_mut();
    }

    let mut guard = GLOBAL_HTAB.lock().unwrap_or_else(|e| e.into_inner());
    let ht = match guard.as_mut() {
        Some(ht) => ht,
        None => return std::ptr::null_mut(),
    };
    let key = HashKey(item.key);
    let data = HashData(item.data);
    let idx = match action {
        Action::FIND => ht.search(&key, hash_key_djb2, hash_keys_equal),
        Action::ENTER => ht
            .enter(key, data, hash_key_djb2, hash_keys_equal)
            .map(|(i, _new)| i),
    };
    match idx {
        Some(i) => match ht.slot_address(i) {
            Some(p) => p as *mut Entry,
            None => std::ptr::null_mut(),
        },
        None => std::ptr::null_mut(),
    }
}

/// POSIX `hdestroy` — destroy the global hash table.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn hdestroy() {
    let mut guard = GLOBAL_HTAB.lock().unwrap_or_else(|e| e.into_inner());
    *guard = None;
}

// ---------------------------------------------------------------------------
// Reentrant hash table API (hcreate_r, hsearch_r, hdestroy_r)
// ---------------------------------------------------------------------------

/// Opaque hash table data structure for reentrant API.
/// Layout compatible with glibc `struct hsearch_data`.
#[repr(C)]
pub struct HsearchData {
    table: *mut c_void,
    size: usize,
    filled: usize,
}

/// POSIX `hcreate_r` — create a reentrant hash table.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn hcreate_r(nel: usize, htab: *mut HsearchData) -> c_int {
    if htab.is_null() {
        return 0;
    }
    let ht = Box::new(HashTable::new(nel));
    let htab_ref = unsafe { &mut *htab };
    htab_ref.table = Box::into_raw(ht) as *mut c_void;
    htab_ref.size = nel.max(1);
    htab_ref.filled = 0;
    1
}

/// POSIX `hsearch_r` — reentrant hash table search/insert.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn hsearch_r(
    item: Entry,
    action: Action,
    retval: *mut *mut Entry,
    htab: *mut HsearchData,
) -> c_int {
    if htab.is_null() || retval.is_null() {
        return 0;
    }
    if !hash_key_valid(item.key) {
        unsafe { *retval = std::ptr::null_mut() };
        return 0;
    }
    let htab_ref = unsafe { &mut *htab };
    if htab_ref.table.is_null() {
        unsafe { *retval = std::ptr::null_mut() };
        return 0;
    }
    let ht = unsafe { &mut *(htab_ref.table as *mut HashTable) };
    let key = HashKey(item.key);
    let data = HashData(item.data);
    let (idx_opt, was_new) = match action {
        Action::FIND => (ht.search(&key, hash_key_djb2, hash_keys_equal), false),
        Action::ENTER => match ht.enter(key, data, hash_key_djb2, hash_keys_equal) {
            Some((i, new)) => (Some(i), new),
            None => (None, false),
        },
    };
    let result = match idx_opt.and_then(|i| ht.slot_address(i)) {
        Some(p) => p as *mut Entry,
        None => std::ptr::null_mut(),
    };
    unsafe { *retval = result };
    if action == Action::ENTER && was_new {
        htab_ref.filled = htab_ref.filled.saturating_add(1);
    }
    if result.is_null() { 0 } else { 1 }
}

/// POSIX `hdestroy_r` — destroy a reentrant hash table.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn hdestroy_r(htab: *mut HsearchData) {
    if htab.is_null() {
        return;
    }
    let htab_ref = unsafe { &mut *htab };
    if !htab_ref.table.is_null() {
        let _ = unsafe { Box::from_raw(htab_ref.table as *mut HashTable) };
        htab_ref.table = std::ptr::null_mut();
        htab_ref.size = 0;
        htab_ref.filled = 0;
    }
}

// ---------------------------------------------------------------------------
// Binary tree: tsearch, tfind, tdelete, twalk, twalk_r
// ---------------------------------------------------------------------------
//
// Backed by a left-leaning red-black tree in frankenlibc-core (bd-srch-2,
// epic bd-srch-epic). The previous unbalanced BST implementation lived
// here and was O(n) worst case; the LLRB gives glibc-parity O(log n).
//
// `*rootp` (the user-visible opaque tree handle) points to a heap-
// allocated `RbTreeBox` when the tree is non-empty, and is NULL when
// the tree is empty. POSIX user code only compares against NULL and
// dereferences via tsearch/tfind/tdelete/twalk; the layout of the
// pointed-to memory is implementation-defined.

use core::cmp::Ordering;
use frankenlibc_core::search::{PosixVisit, RbTree};

/// `*const c_void` wrapper so the generic `RbTree<K>` can use raw
/// pointers as keys without violating Send/Sync expectations from
/// downstream Send-bound dependencies.
#[repr(transparent)]
#[derive(Clone, Copy)]
struct OpaqueKey(*const c_void);

// SAFETY: tree state is single-threaded per `*rootp`; the user is
// responsible for serialization (POSIX tsearch is not thread-safe
// w.r.t. concurrent operations on the same root).
unsafe impl Send for OpaqueKey {}

/// Heap-allocated tree state pointed to by `*rootp`.
struct RbTreeBox {
    tree: RbTree<OpaqueKey>,
}

/// POSIX `VISIT` — tree walk visit order.
#[repr(C)]
#[derive(Clone, Copy)]
pub enum Visit {
    Preorder = 0,
    Postorder = 1,
    Endorder = 2,
    Leaf = 3,
}

/// Comparison function type for tree operations.
type CompareFn = unsafe extern "C" fn(*const c_void, *const c_void) -> c_int;

#[inline]
fn make_cmp_closure(compar: CompareFn) -> impl Fn(&OpaqueKey, &OpaqueKey) -> Ordering {
    move |a: &OpaqueKey, b: &OpaqueKey| {
        let r = unsafe { compar(a.0, b.0) };
        if r < 0 {
            Ordering::Less
        } else if r > 0 {
            Ordering::Greater
        } else {
            Ordering::Equal
        }
    }
}

/// POSIX `tsearch` — search or insert into a binary tree (LLRB-backed).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tsearch(
    key: *const c_void,
    rootp: *mut *mut c_void,
    compar: CompareFn,
) -> *mut c_void {
    if rootp.is_null() {
        return std::ptr::null_mut();
    }
    let cmp = make_cmp_closure(compar);

    let handle: &mut RbTreeBox = unsafe {
        if (*rootp).is_null() {
            let h = Box::into_raw(Box::new(RbTreeBox {
                tree: RbTree::new(),
            }));
            *rootp = h as *mut c_void;
            &mut *h
        } else {
            &mut *(*rootp as *mut RbTreeBox)
        }
    };

    handle.tree.insert(OpaqueKey(key), &cmp);
    // POSIX: returned pointer, when cast to `void**`, dereferences to
    // the matching key. Our `OpaqueKey` is `#[repr(transparent)]` over
    // `*const c_void`, so &OpaqueKey IS a void**.
    match handle.tree.find(&OpaqueKey(key), &cmp) {
        Some(k) => k as *const OpaqueKey as *mut c_void,
        None => std::ptr::null_mut(),
    }
}

/// POSIX `tfind` — find a key in a binary tree without inserting.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tfind(
    key: *const c_void,
    rootp: *const *mut c_void,
    compar: CompareFn,
) -> *mut c_void {
    if rootp.is_null() || unsafe { (*rootp).is_null() } {
        return std::ptr::null_mut();
    }
    let cmp = make_cmp_closure(compar);
    let handle: &RbTreeBox = unsafe { &*(*rootp as *const RbTreeBox) };
    match handle.tree.find(&OpaqueKey(key), &cmp) {
        Some(k) => k as *const OpaqueKey as *mut c_void,
        None => std::ptr::null_mut(),
    }
}

/// POSIX `tdelete` — delete a key from a binary tree.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tdelete(
    key: *const c_void,
    rootp: *mut *mut c_void,
    compar: CompareFn,
) -> *mut c_void {
    if rootp.is_null() || unsafe { (*rootp).is_null() } {
        return std::ptr::null_mut();
    }
    let cmp = make_cmp_closure(compar);
    let handle_ptr = unsafe { *rootp } as *mut RbTreeBox;
    let handle = unsafe { &mut *handle_ptr };

    let removed = handle.tree.delete(&OpaqueKey(key), &cmp);
    if removed.is_none() {
        return std::ptr::null_mut();
    }

    if handle.tree.is_empty() {
        // Free the tree state and reset *rootp so subsequent tsearch
        // sees an empty tree.
        let _ = unsafe { Box::from_raw(handle_ptr) };
        unsafe { *rootp = std::ptr::null_mut() };
        // POSIX: tdelete returns "an unspecified non-null pointer" on
        // success when the deleted node was the last one. Return the
        // address of rootp (a stable, non-null pointer) per glibc's
        // convention.
        rootp as *mut c_void
    } else {
        // Successfully deleted, tree non-empty — POSIX says return a
        // pointer to the parent; our LLRB doesn't track parents
        // externally and the user only checks non-null, so return
        // rootp.
        rootp as *mut c_void
    }
}

/// POSIX `twalk` — traverse a binary tree.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn twalk(
    root: *const c_void,
    action: unsafe extern "C" fn(*const c_void, Visit, c_int),
) {
    if root.is_null() {
        return;
    }
    let handle: &RbTreeBox = unsafe { &*(root as *const RbTreeBox) };
    handle.tree.walk_posix(|k, visit, depth| {
        let key_ptr = k as *const OpaqueKey as *const c_void;
        let v = match visit {
            PosixVisit::PreOrder => Visit::Preorder,
            PosixVisit::PostOrder => Visit::Postorder,
            PosixVisit::EndOrder => Visit::Endorder,
            PosixVisit::Leaf => Visit::Leaf,
        };
        unsafe { action(key_ptr, v, depth as c_int) };
    });
}

/// GNU `twalk_r` — traverse a binary tree with closure data (reentrant).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn twalk_r(
    root: *const c_void,
    action: unsafe extern "C" fn(*const c_void, c_int, c_int, *mut c_void),
    closure: *mut c_void,
) {
    if root.is_null() {
        return;
    }
    let handle: &RbTreeBox = unsafe { &*(root as *const RbTreeBox) };
    handle.tree.walk_posix(|k, visit, depth| {
        let key_ptr = k as *const OpaqueKey as *const c_void;
        let v = match visit {
            PosixVisit::PreOrder => 0,
            PosixVisit::PostOrder => 1,
            PosixVisit::EndOrder => 2,
            PosixVisit::Leaf => 3,
        };
        unsafe { action(key_ptr, v, depth as c_int, closure) };
    });
}

/// GNU `tdestroy` — free every node in a binary tree, calling
/// `free_node(key)` on each user-supplied key as the corresponding
/// node is freed (post-order). After this call the underlying tree
/// state is dropped and the original `*rootp` storage holds a
/// dangling pointer; callers typically pass the value of `*rootp`
/// directly (not `rootp`) as required by the GNU ABI.
///
/// `free_node` may be NULL if the keys do not need freeing.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tdestroy(
    root: *mut c_void,
    free_node: Option<unsafe extern "C" fn(*mut c_void)>,
) {
    if root.is_null() {
        return;
    }
    let handle: Box<RbTreeBox> = unsafe { Box::from_raw(root as *mut RbTreeBox) };
    let RbTreeBox { tree } = *handle;
    tree.destroy_with(|opaque_key| {
        if let Some(cb) = free_node {
            unsafe { cb(opaque_key.0 as *mut c_void) };
        }
    });
}

// ---------------------------------------------------------------------------
// Linear search: lfind, lsearch
// ---------------------------------------------------------------------------

fn tracked_region_fits(ptr: *const c_void, len: usize) -> bool {
    match crate::malloc_abi::known_remaining(ptr as usize) {
        Some(remaining) => len <= remaining,
        None => true,
    }
}

/// POSIX `lfind` — linear search (find only, no insert).
///
/// Delegates the array scan to frankenlibc-core::search::lfind_index;
/// abi remains responsible only for raw-pointer / C-comparator
/// adaptation.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lfind(
    key: *const c_void,
    base: *const c_void,
    nelp: *mut usize,
    width: usize,
    compar: CompareFn,
) -> *mut c_void {
    if key.is_null() || base.is_null() || nelp.is_null() || width == 0 {
        return std::ptr::null_mut();
    }
    let nel = unsafe { *nelp };
    let total = match nel.checked_mul(width) {
        Some(n) => n,
        None => return std::ptr::null_mut(),
    };
    if !tracked_region_fits(base, total) || !tracked_region_fits(key, width) {
        return std::ptr::null_mut();
    }
    let buf: &[u8] = unsafe { std::slice::from_raw_parts(base as *const u8, total) };
    let matches = |rec: &[u8], _i: usize| -> bool {
        let r = unsafe { compar(key, rec.as_ptr() as *const c_void) };
        r == 0
    };
    match frankenlibc_core::search::lfind_index(buf, width, nel, matches) {
        Some(idx) => unsafe { (base as *mut u8).add(idx * width) as *mut c_void },
        None => std::ptr::null_mut(),
    }
}

/// POSIX `lsearch` — linear search with insert if not found.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lsearch(
    key: *const c_void,
    base: *mut c_void,
    nelp: *mut usize,
    width: usize,
    compar: CompareFn,
) -> *mut c_void {
    if key.is_null() || base.is_null() || nelp.is_null() || width == 0 {
        return std::ptr::null_mut();
    }
    let nel = unsafe { *nelp };
    let total = match nel.checked_mul(width) {
        Some(n) => n,
        None => return std::ptr::null_mut(),
    };
    if !tracked_region_fits(base.cast_const(), total) || !tracked_region_fits(key, width) {
        return std::ptr::null_mut();
    }
    let buf: &[u8] = unsafe { std::slice::from_raw_parts(base as *const u8, total) };
    let matches = |rec: &[u8], _i: usize| -> bool {
        let r = unsafe { compar(key, rec.as_ptr() as *const c_void) };
        r == 0
    };
    match frankenlibc_core::search::lsearch_or_append_index(buf, width, nel, matches) {
        frankenlibc_core::search::SearchOrAppend::Found(idx) => unsafe {
            (base as *mut u8).add(idx * width) as *mut c_void
        },
        frankenlibc_core::search::SearchOrAppend::AppendAt(idx) => {
            let append_total = match idx.checked_add(1).and_then(|n| n.checked_mul(width)) {
                Some(n) => n,
                None => return std::ptr::null_mut(),
            };
            if !tracked_region_fits(base.cast_const(), append_total) {
                return std::ptr::null_mut();
            }
            let dest = unsafe { (base as *mut u8).add(idx * width) };
            unsafe {
                std::ptr::copy_nonoverlapping(key as *const u8, dest, width);
                *nelp = nel + 1;
            }
            dest as *mut c_void
        }
    }
}

// ---------------------------------------------------------------------------
// Linked list: insque, remque
// ---------------------------------------------------------------------------

/// Queue element (doubly-linked list node).
#[repr(C)]
struct QueueElem {
    next: *mut QueueElem,
    prev: *mut QueueElem,
}

/// POSIX `insque` — insert element into a doubly-linked list.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn insque(elem: *mut c_void, pred: *mut c_void) {
    if elem.is_null() {
        return;
    }
    let e = elem as *mut QueueElem;
    let p = pred as *mut QueueElem;

    if p.is_null() {
        // Insert as sole element.
        unsafe {
            (*e).next = std::ptr::null_mut();
            (*e).prev = std::ptr::null_mut();
        }
    } else {
        unsafe {
            (*e).next = (*p).next;
            (*e).prev = p;
            if !(*p).next.is_null() {
                (*(*p).next).prev = e;
            }
            (*p).next = e;
        }
    }
}

/// POSIX `remque` — remove element from a doubly-linked list.
///
/// glibc unlinks neighboring nodes but leaves the removed element's own
/// `next` and `prev` fields untouched.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn remque(elem: *mut c_void) {
    if elem.is_null() {
        return;
    }
    let e = elem as *mut QueueElem;
    unsafe {
        if !(*e).prev.is_null() {
            (*(*e).prev).next = (*e).next;
        }
        if !(*e).next.is_null() {
            (*(*e).next).prev = (*e).prev;
        }
    }
}
