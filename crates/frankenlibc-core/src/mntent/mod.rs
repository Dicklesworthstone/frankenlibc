//! `<mntent.h>` — fstab/mtab line parsing and serialization.
//!
//! Pure-safe Rust port of the byte-level logic that previously lived
//! inline in `frankenlibc-abi/src/unistd_abi.rs::getmntent_r` /
//! `hasmntopt` / `addmntent`. The abi layer keeps responsibility for
//! the `struct mntent` field-pointer marshalling, caller-buffer NUL
//! packing, and `BufReader`/`Write` integration; this module produces
//! and consumes byte slices only.
//!
//! An mtab/fstab line has six whitespace-separated fields:
//! `fsname dir type opts [freq [passno]]`. Lines beginning with `#`
//! (after leading whitespace) and blank lines are comments and yield
//! `None` from [`parse_mntent_line`].

pub mod parse;

pub use parse::{
    MntFields, format_mntent_line, has_mnt_opt, parse_mntent_freq_passno, parse_mntent_line,
};
