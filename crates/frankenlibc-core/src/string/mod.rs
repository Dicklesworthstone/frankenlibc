//! String and memory operations.
//!
//! Implements `<string.h>` functions as safe Rust operating on slices.

pub mod mem;
pub mod str;
pub mod strtok;
pub mod wide;

// Re-export commonly used functions.
pub use mem::{
    bcmp, bzero, memccpy, memchr, memcmp, memcpy, memmem, memmove, mempcpy, memrchr, memset, swab,
};
pub use str::{
    stpcpy, stpncpy, strcasecmp, strcasestr, strcat, strchr, strchrnul, strcmp, strcoll, strcpy,
    strcspn, strdup_bytes, strlcat, strlcpy, strlen, strncasecmp, strncat, strncmp, strncpy,
    strndup_bytes, strnlen, strpbrk, strrchr, strsep, strspn, strstr, strxfrm,
};
pub use strtok::{strtok, strtok_r};
pub use wide::{wcscmp, wcscpy, wcslen, wmemchr, wmemcmp, wmemcpy, wmemmove, wmemset};
