//! POSIX `<search.h>` data structures and algorithms.
//!
//! This module is a clean-room native Rust port of the binary-tree
//! (`tsearch`/`tfind`/`tdelete`/`twalk`/`tdestroy`), hash-table
//! (`hcreate`/`hsearch`/`hdestroy`), and linear-search (`lsearch`/
//! `lfind`) families. The previous fl-abi implementation used an
//! unbalanced BST with O(n) worst case; this module uses a left-
//! leaning red-black tree (LLRB, Sedgewick 2008) for guaranteed
//! O(log n) insert/find/delete.
//!
//! No `unsafe` code: keys are stored by value and the public API
//! takes a comparator closure on each call so the data structure
//! can be reused with arbitrary opaque key types from the abi
//! layer (typically `*const c_void` adapted via a wrapper).

pub mod rb_tree;

pub use rb_tree::{PosixVisit, RbTree, RbWalkOrder};
