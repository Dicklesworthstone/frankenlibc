//! String and memory operations.
//!
//! Implements `<string.h>` functions as safe Rust operating on slices.

pub mod mem;
pub mod str;
pub mod strtok;
pub mod wide;

// Re-export commonly used functions.
pub use mem::{memchr, memcmp, memcpy, memmem, memmove, mempcpy, memrchr, memset};
pub use str::{
    stpcpy, stpncpy, strcasecmp, strcasestr, strcat, strchr, strchrnul, strcmp, strcpy, strcspn,
    strdup_bytes, strlen, strncasecmp, strncat, strncmp, strncpy, strndup_bytes, strnlen, strpbrk,
    strrchr, strspn, strstr,
};
pub use strtok::{strtok, strtok_r};
pub use wide::{wcscmp, wcscpy, wcslen, wmemchr, wmemcmp, wmemcpy, wmemmove, wmemset};
