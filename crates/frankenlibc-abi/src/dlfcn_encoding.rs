//! Locale-selected text conversion for native ELF objects.
//!
//! Descriptors, restartable conversion states, and thread locale selection must
//! share the ordinary ABI's owned implementations. Resolving any of these
//! functions through the host loader would split that state across runtimes.

use crate::{glibc_internal_abi as internal, iconv_abi as iconv, wchar_abi as wide};

pub(super) fn address(name: &str, version: Option<&str>) -> Option<u64> {
    let baseline = if cfg!(target_arch = "aarch64") {
        "GLIBC_2.17"
    } else {
        "GLIBC_2.2.5"
    };
    let c11 = if cfg!(target_arch = "aarch64") {
        baseline
    } else {
        "GLIBC_2.16"
    };
    let (function, expected_version) = match name {
        // Always bind the complete descriptor lifecycle to one registry.
        "iconv_open" => (iconv::iconv_open as *const (), baseline),
        "iconv" => (iconv::iconv as *const (), baseline),
        "iconv_close" => (iconv::iconv_close as *const (), baseline),
        // MB_CUR_MAX and all consumers use the active native locale snapshot.
        "__ctype_get_mb_cur_max" => (internal::__ctype_get_mb_cur_max as *const (), baseline),
        "mbrlen" => (wide::mbrlen as *const (), baseline),
        "mbrtowc" => (wide::mbrtowc as *const (), baseline),
        "mbsinit" => (wide::mbsinit as *const (), baseline),
        "wcrtomb" => (wide::wcrtomb as *const (), baseline),
        "mbsrtowcs" => (wide::mbsrtowcs as *const (), baseline),
        "wcsrtombs" => (wide::wcsrtombs as *const (), baseline),
        "mbsnrtowcs" => (wide::mbsnrtowcs as *const (), baseline),
        "wcsnrtombs" => (wide::wcsnrtombs as *const (), baseline),
        "btowc" => (wide::btowc as *const (), baseline),
        "wctob" => (wide::wctob as *const (), baseline),
        "mblen" => (wide::mblen as *const (), baseline),
        "mbtowc" => (wide::mbtowc as *const (), baseline),
        "wctomb" => (wide::wctomb as *const (), baseline),
        "mbstowcs" => (wide::mbstowcs as *const (), baseline),
        "wcstombs" => (wide::wcstombs as *const (), baseline),
        // Internal spellings use the same restartable engines and locale.
        "__mbrlen" => (wide::mbrlen as *const (), baseline),
        "__mbrtowc" => (wide::mbrtowc as *const (), baseline),
        // The C11 entry points postdate the x86-64 baseline. Advertising that
        // baseline would incorrectly satisfy a versioned import or dlvsym.
        "c16rtomb" => (wide::c16rtomb as *const (), c11),
        "c32rtomb" => (wide::c32rtomb as *const (), c11),
        "mbrtoc16" => (wide::mbrtoc16 as *const (), c11),
        "mbrtoc32" => (wide::mbrtoc32 as *const (), c11),
        _ => return None,
    };
    version
        .is_none_or(|version| version == expected_version)
        .then_some(function as usize as u64)
}
