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

/// Internal hash table slot.
/// Must be `#[repr(C)]` because `search()` casts `*mut HashSlot` to `*mut Entry`,
/// relying on the key/data fields being at the same offsets as `Entry`.
#[repr(C)]
struct HashSlot {
    key: *mut c_char,
    data: *mut c_void,
    occupied: bool,
}

// SAFETY: HashSlot raw pointers are C-owned and only accessed under Mutex.
unsafe impl Send for HashSlot {}

struct HashTable {
    slots: Vec<HashSlot>,
    capacity: usize,
}

impl HashTable {
    fn new(nel: usize) -> Self {
        let capacity = nel.max(1);
        let mut slots = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            slots.push(HashSlot {
                key: std::ptr::null_mut(),
                data: std::ptr::null_mut(),
                occupied: false,
            });
        }
        Self { slots, capacity }
    }

    fn hash_key(&self, key: *const c_char) -> usize {
        if key.is_null() {
            return 0;
        }
        // djb2 hash
        let mut hash: u64 = 5381;
        let mut ptr = key as *const u8;
        loop {
            let c = unsafe { *ptr };
            if c == 0 {
                break;
            }
            hash = hash.wrapping_mul(33).wrapping_add(c as u64);
            ptr = unsafe { ptr.add(1) };
        }
        (hash as usize) % self.capacity
    }

    fn keys_equal(a: *const c_char, b: *const c_char) -> bool {
        if a.is_null() || b.is_null() {
            return a == b;
        }
        unsafe { crate::string_abi::strcmp(a, b) == 0 }
    }

    fn search(&mut self, item: Entry, action: Action) -> *mut Entry {
        let idx = self.hash_key(item.key);
        // Linear probing
        for i in 0..self.capacity {
            let slot_idx = (idx + i) % self.capacity;
            let slot = &mut self.slots[slot_idx];
            if !slot.occupied {
                if action == Action::ENTER {
                    slot.key = item.key;
                    slot.data = item.data;
                    slot.occupied = true;
                    return slot as *mut HashSlot as *mut Entry;
                }
                return std::ptr::null_mut();
            }
            if Self::keys_equal(slot.key, item.key) {
                if action == Action::ENTER {
                    slot.data = item.data;
                }
                return slot as *mut HashSlot as *mut Entry;
            }
        }
        std::ptr::null_mut() // Table full
    }
}

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
    let mut guard = GLOBAL_HTAB.lock().unwrap_or_else(|e| e.into_inner());
    match guard.as_mut() {
        Some(ht) => ht.search(item, action),
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
    let htab_ref = unsafe { &mut *htab };
    if htab_ref.table.is_null() {
        unsafe { *retval = std::ptr::null_mut() };
        return 0;
    }
    let ht = unsafe { &mut *(htab_ref.table as *mut HashTable) };
    let had_existing = if action == Action::ENTER {
        !ht.search(item, Action::FIND).is_null()
    } else {
        false
    };
    let result = ht.search(item, action);
    unsafe { *retval = result };
    if action == Action::ENTER && !had_existing && !result.is_null() {
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
// Binary tree: tsearch, tfind, tdelete, twalk
// ---------------------------------------------------------------------------

/// Internal binary tree node.
#[repr(C)]
struct TreeNode {
    key: *const c_void,
    left: *mut TreeNode,
    right: *mut TreeNode,
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

/// POSIX `tsearch` — search or insert into a binary tree.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tsearch(
    key: *const c_void,
    rootp: *mut *mut c_void,
    compar: CompareFn,
) -> *mut c_void {
    if rootp.is_null() {
        return std::ptr::null_mut();
    }

    let root = unsafe { *rootp } as *mut TreeNode;
    if root.is_null() {
        // Tree is empty; create root node.
        let node = Box::into_raw(Box::new(TreeNode {
            key,
            left: std::ptr::null_mut(),
            right: std::ptr::null_mut(),
        }));
        unsafe { *rootp = node as *mut c_void };
        return node as *mut c_void;
    }

    // Walk the tree.
    let mut current = root;
    loop {
        let cmp = unsafe { compar(key, (*current).key) };
        if cmp == 0 {
            return current as *mut c_void;
        }
        let next_ptr = if cmp < 0 {
            unsafe { &mut (*current).left }
        } else {
            unsafe { &mut (*current).right }
        };
        if (*next_ptr).is_null() {
            let node = Box::into_raw(Box::new(TreeNode {
                key,
                left: std::ptr::null_mut(),
                right: std::ptr::null_mut(),
            }));
            *next_ptr = node;
            return node as *mut c_void;
        }
        current = *next_ptr;
    }
}

/// POSIX `tfind` — find a key in a binary tree without inserting.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tfind(
    key: *const c_void,
    rootp: *const *mut c_void,
    compar: CompareFn,
) -> *mut c_void {
    if rootp.is_null() {
        return std::ptr::null_mut();
    }
    let mut current = unsafe { *rootp } as *mut TreeNode;
    while !current.is_null() {
        let cmp = unsafe { compar(key, (*current).key) };
        if cmp == 0 {
            return current as *mut c_void;
        }
        current = if cmp < 0 {
            unsafe { (*current).left }
        } else {
            unsafe { (*current).right }
        };
    }
    std::ptr::null_mut()
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
    tdelete_recursive(key, rootp, std::ptr::null_mut(), compar)
}

fn tdelete_recursive(
    key: *const c_void,
    nodep: *mut *mut c_void,
    parent: *mut TreeNode,
    compar: CompareFn,
) -> *mut c_void {
    let node = unsafe { *nodep } as *mut TreeNode;
    if node.is_null() {
        return std::ptr::null_mut();
    }

    let cmp = unsafe { compar(key, (*node).key) };
    if cmp < 0 {
        let left_ptr = unsafe { &mut (*node).left as *mut *mut TreeNode as *mut *mut c_void };
        return tdelete_recursive(key, left_ptr, node, compar);
    }
    if cmp > 0 {
        let right_ptr = unsafe { &mut (*node).right as *mut *mut TreeNode as *mut *mut c_void };
        return tdelete_recursive(key, right_ptr, node, compar);
    }

    // Found the node to delete.
    unsafe {
        if (*node).left.is_null() {
            *nodep = (*node).right as *mut c_void;
            let _ = Box::from_raw(node);
        } else if (*node).right.is_null() {
            *nodep = (*node).left as *mut c_void;
            let _ = Box::from_raw(node);
        } else {
            // Two children: find in-order successor (leftmost of right subtree).
            let mut succ_parent = node;
            let mut succ = (*node).right;
            while !(*succ).left.is_null() {
                succ_parent = succ;
                succ = (*succ).left;
            }
            (*node).key = (*succ).key;
            if succ_parent == node {
                (*succ_parent).right = (*succ).right;
            } else {
                (*succ_parent).left = (*succ).right;
            }
            let _ = Box::from_raw(succ);
        }
    }

    if parent.is_null() {
        // POSIX: return unspecified non-null pointer if root node is deleted.
        // Returning the address of rootp itself is a common implementation choice.
        nodep as *mut c_void
    } else {
        parent as *mut c_void
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
    twalk_recursive(root as *const TreeNode, action, 0);
}

fn twalk_recursive(
    node: *const TreeNode,
    action: unsafe extern "C" fn(*const c_void, Visit, c_int),
    level: c_int,
) {
    if node.is_null() {
        return;
    }
    let left = unsafe { (*node).left };
    let right = unsafe { (*node).right };
    let node_ptr = node as *const c_void;

    if left.is_null() && right.is_null() {
        unsafe { action(node_ptr, Visit::Leaf, level) };
    } else {
        unsafe { action(node_ptr, Visit::Preorder, level) };
        twalk_recursive(left, action, level + 1);
        unsafe { action(node_ptr, Visit::Postorder, level) };
        twalk_recursive(right, action, level + 1);
        unsafe { action(node_ptr, Visit::Endorder, level) };
    }
}

/// GNU `twalk_r` — traverse a binary tree with closure data (reentrant).
///
/// Like `twalk`, but the action callback receives an additional `closure`
/// pointer, and the `VISIT` enum is passed as a plain `c_int` per the
/// GNU extension ABI (leaf=0, preorder=1, postorder=2, endorder=3 —
/// note: glibc actually uses the same `VISIT` enum values mapped to int).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn twalk_r(
    root: *const c_void,
    action: unsafe extern "C" fn(*const c_void, c_int, c_int, *mut c_void),
    closure: *mut c_void,
) {
    if root.is_null() {
        return;
    }
    twalk_r_recursive(root as *const TreeNode, action, closure, 0);
}

fn twalk_r_recursive(
    node: *const TreeNode,
    action: unsafe extern "C" fn(*const c_void, c_int, c_int, *mut c_void),
    closure: *mut c_void,
    level: c_int,
) {
    if node.is_null() {
        return;
    }
    let left = unsafe { (*node).left };
    let right = unsafe { (*node).right };
    let node_ptr = node as *const c_void;

    if left.is_null() && right.is_null() {
        unsafe { action(node_ptr, Visit::Leaf as c_int, level, closure) };
    } else {
        unsafe { action(node_ptr, Visit::Preorder as c_int, level, closure) };
        twalk_r_recursive(left, action, closure, level + 1);
        unsafe { action(node_ptr, Visit::Postorder as c_int, level, closure) };
        twalk_r_recursive(right, action, closure, level + 1);
        unsafe { action(node_ptr, Visit::Endorder as c_int, level, closure) };
    }
}

// ---------------------------------------------------------------------------
// Linear search: lfind, lsearch
// ---------------------------------------------------------------------------

/// POSIX `lfind` — linear search (find only, no insert).
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
    let base_ptr = base as *const u8;
    for i in 0..nel {
        let element = unsafe { base_ptr.add(i * width) } as *const c_void;
        if unsafe { compar(key, element) } == 0 {
            return element as *mut c_void;
        }
    }
    std::ptr::null_mut()
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

    // First try to find it.
    let result = unsafe { lfind(key, base, nelp, width, compar) };
    if !result.is_null() {
        return result;
    }

    // Not found: append at end.
    let nel = unsafe { *nelp };
    let dest = unsafe { (base as *mut u8).add(nel * width) };
    unsafe {
        std::ptr::copy_nonoverlapping(key as *const u8, dest, width);
        *nelp = nel + 1;
    }
    dest as *mut c_void
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
        (*e).next = std::ptr::null_mut();
        (*e).prev = std::ptr::null_mut();
    }
}
