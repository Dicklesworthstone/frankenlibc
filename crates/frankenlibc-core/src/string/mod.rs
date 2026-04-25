//! String and memory operations.
//!
//! Implements `<string.h>` functions as safe Rust operating on slices.

pub mod fnmatch;
pub mod glob;
pub mod mem;
pub mod regex;
pub mod str;
pub mod strtok;
pub mod timingsafe;
pub mod wchar;
pub mod wide;
pub mod wildcard;

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
pub use wchar::{
    iswalnum, iswalpha, iswdigit, iswlower, iswprint, iswspace, iswupper, mblen as mb_len,
    mbstowcs, mbtowc, towlower as wc_tolower, towupper as wc_toupper, wcstombs, wctomb, wcwidth,
};
pub use wide::{
    wcpcpy, wcpncpy, wcscasecmp, wcscat, wcscmp, wcscpy, wcscspn, wcsdup_len, wcslen, wcsncasecmp,
    wcsncat, wcsncmp, wcsncpy, wcsnlen, wcspbrk, wcsrchr, wcsspn, wcsstr, wcstok, wcswidth,
    wmemchr, wmemcmp, wmemcpy, wmemmove, wmemrchr, wmemset,
};
