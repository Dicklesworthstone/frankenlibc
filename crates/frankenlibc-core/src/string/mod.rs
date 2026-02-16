//! String and memory operations.
//!
//! Implements `<string.h>` functions as safe Rust operating on slices.

pub mod mem;
pub mod str;
pub mod strtok;
pub mod wide;

// Re-export commonly used functions.
pub use mem::{memchr, memcmp, memcpy, memmove, memrchr, memset};
pub use str::{
    strcat, strchr, strcmp, strcpy, stpcpy, stpncpy, strlen, strncat, strncmp, strncpy, strnlen,
    strrchr, strstr,
};
pub use strtok::{strtok, strtok_r};
pub use wide::{wcscmp, wcscpy, wcslen, wmemchr, wmemcmp, wmemcpy, wmemmove, wmemset};
