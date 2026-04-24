//! POSIX `<ftw.h>` file tree walker.
//!
//! This module is a clean-room native Rust port of `ftw` and `nftw`
//! that previously lived in frankenlibc-abi/src/unistd_abi.rs (~339
//! lines of recursive walker, path-joining, and POSIX type-flag
//! dispatch). The split:
//!
//!   - `path` (this commit, bd-ftw-1) — pure-safe path-manipulation
//!     helpers (`build_child_path`, `base_offset_of`) plus the
//!     POSIX [`WalkType`] and [`WalkFlags`] types.
//!   - `walker` (bd-ftw-2) — the recursion driver itself, parameterized
//!     over a closure-based fs-ops abstraction so it stays
//!     `#![deny(unsafe_code)]`-clean.
//!
//! The abi layer (bd-ftw-3) wires concrete syscall closures
//! (newfstatat / opendir / readdir) into the core driver and keeps
//! responsibility for raw-pointer / NUL-terminated C string adaptation.

pub mod path;
pub mod walker;

pub use path::{WalkFlags, WalkType, base_offset_of, build_child_path};
pub use walker::{FsOps, StatLike, walk_tree};
