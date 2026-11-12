//! Allocation, virtual memory, string and scalar entry points for the native loader.
//!
//! Bind to FrankenLibC's existing ABI bodies, never to host allocator addresses
//! discovered by symbol name. In particular, calloc/realloc/strdup results must
//! remain compatible with the free already supplied to native plugins.
//! This is a bounded addition to the runtime surface, not a new libc engine.

use crate::{
    ctype_abi as ctype, glibc_internal_abi as internal, isoc_abi as c23, locale_abi as locale,
    malloc_abi as allocation, mmap_abi as mapping, stdlib_abi as stdlib, string_abi as strings,
    unistd_abi as unistd, wchar_abi as wide,
};

#[path = "dlfcn_io.rs"]
mod io;

#[path = "dlfcn_stdio.rs"]
mod stdio;

#[path = "dlfcn_pthread.rs"]
mod pthread;

#[path = "dlfcn_fortify.rs"]
mod fortify;
#[path = "dlfcn_semaphore.rs"]
mod semaphore;
#[path = "dlfcn_thread_control.rs"]
mod thread_control;

/// Only the real baseline symbol version for this target is advertised. A
/// private/future version is not interchangeable with an unversioned lookup.
/// Callers perform native DSO scope/preemption checks before this fallback.
pub(super) fn address(name: &str, version: Option<&str>) -> Option<u64> {
    if let Some(address) = semaphore::address(name, version) {
        return Some(address);
    }
    if let Some(address) = thread_control::address(name, version) {
        return Some(address);
    }
    if let Some(address) = fortify::address(name, version) {
        return Some(address);
    }
    if let Some(address) = io::address(name, version) {
        return Some(address);
    }
    if let Some(address) = stdio::address(name, version) {
        return Some(address);
    }
    if let Some(address) = pthread::address(name, version) {
        return Some(address);
    }
    let baseline = if cfg!(target_arch = "aarch64") {
        "GLIBC_2.17"
    } else {
        "GLIBC_2.2.5"
    };
    // These APIs postdate the x86-64 baseline. A known name with an unsupported
    // version must stay rejected by runtime_export, rather than escaping into
    // host lookup and a different errno, environment or callback domain.
    let versioned = match name {
        "mlock2" => Some((mapping::mlock2 as *const (), "GLIBC_2.27")),
        "secure_getenv" => Some((stdlib::secure_getenv as *const (), "GLIBC_2.17")),
        "qsort_r" => Some((
            stdlib::qsort_r as *const (),
            if cfg!(target_arch = "aarch64") {
                baseline
            } else {
                "GLIBC_2.8"
            },
        )),
        _ => None,
    };
    if let Some((function, expected_version)) = versioned {
        return version
            .is_none_or(|version| version == expected_version)
            .then_some(function as usize as u64);
    }
    let locale_version = if cfg!(target_arch = "aarch64") {
        baseline
    } else {
        "GLIBC_2.3"
    };
    // Locale objects and their consumers must use the same native registry.
    // A host newlocale handle is not interchangeable with a native snapshot.
    // The private aliases predate the public POSIX names on x86-64, except
    // __uselocale, whose version is the same as its public counterpart.
    let locale_function = match name {
        "newlocale" => Some((locale::newlocale as *const (), locale_version)),
        "duplocale" => Some((locale::duplocale as *const (), locale_version)),
        "freelocale" => Some((locale::freelocale as *const (), locale_version)),
        "uselocale" => Some((locale::uselocale as *const (), locale_version)),
        "nl_langinfo_l" => Some((locale::nl_langinfo_l as *const (), locale_version)),
        "strtod_l" => Some((stdlib::strtod_l as *const (), locale_version)),
        "strtof_l" => Some((stdlib::strtof_l as *const (), locale_version)),
        "wcstod_l" => Some((wide::wcstod_l as *const (), locale_version)),
        "wcstof_l" => Some((wide::wcstof_l as *const (), locale_version)),
        #[cfg(target_arch = "x86_64")]
        "strtold_l" => Some((stdlib::strtold_l as *const (), locale_version)),
        #[cfg(target_arch = "x86_64")]
        "wcstold_l" => Some((wide::wcstold_l as *const (), locale_version)),
        "__newlocale" => Some((internal::__newlocale as *const (), baseline)),
        "__duplocale" => Some((internal::__duplocale as *const (), baseline)),
        "__freelocale" => Some((internal::__freelocale as *const (), baseline)),
        "__uselocale" => Some((internal::__uselocale as *const (), locale_version)),
        "__nl_langinfo_l" => Some((internal::__nl_langinfo_l as *const (), baseline)),
        "__strtod_l" => Some((strings::__strtod_l as *const (), baseline)),
        "__strtof_l" => Some((strings::__strtof_l as *const (), baseline)),
        "__wcstod_l" => Some((wide::__wcstod_l as *const (), baseline)),
        "__wcstof_l" => Some((wide::__wcstof_l as *const (), baseline)),
        #[cfg(target_arch = "x86_64")]
        "__strtold_l" => Some((strings::__strtold_l as *const (), baseline)),
        #[cfg(target_arch = "x86_64")]
        "__wcstold_l" => Some((wide::__wcstold_l as *const (), baseline)),
        _ => None,
    };
    if let Some((function, expected_version)) = locale_function {
        return version
            .is_none_or(|version| version == expected_version)
            .then_some(function as usize as u64);
    }
    // Narrow long-long locale aliases arrived later on x86-64; their wide
    // counterparts use GLIBC_2.3. All legacy names share the ARM baseline.
    let narrow_ll_locale_version = if cfg!(target_arch = "aarch64") {
        baseline
    } else {
        "GLIBC_2.3.3"
    };
    let integer = match name {
        "strtol_l" => Some((stdlib::strtol_l as *const (), locale_version)),
        "strtoul_l" => Some((stdlib::strtoul_l as *const (), locale_version)),
        "strtoll_l" => Some((stdlib::strtoll_l as *const (), narrow_ll_locale_version)),
        "strtoull_l" => Some((stdlib::strtoull_l as *const (), narrow_ll_locale_version)),
        "wcstol_l" => Some((wide::wcstol_l as *const (), locale_version)),
        "wcstoul_l" => Some((wide::wcstoul_l as *const (), locale_version)),
        "wcstoll_l" => Some((wide::wcstoll_l as *const (), locale_version)),
        "wcstoull_l" => Some((wide::wcstoull_l as *const (), locale_version)),
        "__isoc23_strtol" => Some((c23::__isoc23_strtol as *const (), "GLIBC_2.38")),
        "__isoc23_strtoul" => Some((c23::__isoc23_strtoul as *const (), "GLIBC_2.38")),
        "__isoc23_strtoll" => Some((c23::__isoc23_strtoll as *const (), "GLIBC_2.38")),
        "__isoc23_strtoull" => Some((c23::__isoc23_strtoull as *const (), "GLIBC_2.38")),
        "__isoc23_strtoimax" => Some((c23::__isoc23_strtoimax as *const (), "GLIBC_2.38")),
        "__isoc23_strtoumax" => Some((c23::__isoc23_strtoumax as *const (), "GLIBC_2.38")),
        "__isoc23_strtol_l" => Some((c23::__isoc23_strtol_l as *const (), "GLIBC_2.38")),
        "__isoc23_strtoul_l" => Some((c23::__isoc23_strtoul_l as *const (), "GLIBC_2.38")),
        "__isoc23_strtoll_l" => Some((c23::__isoc23_strtoll_l as *const (), "GLIBC_2.38")),
        "__isoc23_strtoull_l" => Some((c23::__isoc23_strtoull_l as *const (), "GLIBC_2.38")),
        "__isoc23_wcstol" => Some((c23::__isoc23_wcstol as *const (), "GLIBC_2.38")),
        "__isoc23_wcstoul" => Some((c23::__isoc23_wcstoul as *const (), "GLIBC_2.38")),
        "__isoc23_wcstoll" => Some((c23::__isoc23_wcstoll as *const (), "GLIBC_2.38")),
        "__isoc23_wcstoull" => Some((c23::__isoc23_wcstoull as *const (), "GLIBC_2.38")),
        "__isoc23_wcstoimax" => Some((c23::__isoc23_wcstoimax as *const (), "GLIBC_2.38")),
        "__isoc23_wcstoumax" => Some((c23::__isoc23_wcstoumax as *const (), "GLIBC_2.38")),
        "__isoc23_wcstol_l" => Some((c23::__isoc23_wcstol_l as *const (), "GLIBC_2.38")),
        "__isoc23_wcstoul_l" => Some((c23::__isoc23_wcstoul_l as *const (), "GLIBC_2.38")),
        "__isoc23_wcstoll_l" => Some((c23::__isoc23_wcstoll_l as *const (), "GLIBC_2.38")),
        "__isoc23_wcstoull_l" => Some((c23::__isoc23_wcstoull_l as *const (), "GLIBC_2.38")),
        _ => None,
    };
    if let Some((function, expected_version)) = integer {
        return version
            .is_none_or(|version| version == expected_version)
            .then_some(function as usize as u64);
    }
    // The table accessors were introduced after the x86-64 baseline. Keep
    // their real version separate from the ordinary byte-ctype functions.
    let ctype_table = match name {
        "__ctype_b_loc" => Some(ctype::__ctype_b_loc as *const ()),
        "__ctype_tolower_loc" => Some(ctype::__ctype_tolower_loc as *const ()),
        "__ctype_toupper_loc" => Some(ctype::__ctype_toupper_loc as *const ()),
        _ => None,
    };
    if let Some(function) = ctype_table {
        let table_version = if cfg!(target_arch = "aarch64") {
            baseline
        } else {
            "GLIBC_2.3"
        };
        return version
            .is_none_or(|version| version == table_version)
            .then_some(function as usize as u64);
    }
    if version.is_some_and(|version| version != baseline) {
        return None;
    }
    let function = match name {
        // These two were already direct-import builtins. Dynamic lookup must
        // use the same frontends as the newly admitted allocation functions.
        "malloc" => allocation::malloc as *const (),
        "free" => allocation::free as *const (),
        "calloc" => allocation::calloc as *const (),
        "realloc" => allocation::realloc as *const (),
        "malloc_usable_size" => allocation::malloc_usable_size as *const (),
        // Native plugins share the ABI's VM policy, syscall and errno paths.
        // Taking the real function address also retains msync's unwind ABI.
        "getpagesize" => unistd::getpagesize as *const (),
        "sysconf" => unistd::sysconf as *const (),
        "mmap" => mapping::mmap as *const (),
        "mmap64" => unistd::mmap64 as *const (),
        "munmap" => mapping::munmap as *const (),
        "mprotect" => mapping::mprotect as *const (),
        "msync" => mapping::msync as *const (),
        "madvise" => mapping::madvise as *const (),
        "posix_madvise" => unistd::posix_madvise as *const (),
        "mincore" => unistd::mincore as *const (),
        "mremap" => mapping::mremap as *const (),
        "mlock" => mapping::mlock as *const (),
        "munlock" => mapping::munlock as *const (),
        "mlockall" => mapping::mlockall as *const (),
        "munlockall" => mapping::munlockall as *const (),
        "atoi" => stdlib::atoi as *const (),
        "atol" => stdlib::atol as *const (),
        "atoll" => stdlib::atoll as *const (),
        "atof" => stdlib::atof as *const (),
        "strtod" => stdlib::strtod as *const (),
        "strtof" => stdlib::strtof as *const (),
        "wcstod" => wide::wcstod as *const (),
        "wcstof" => wide::wcstof as *const (),
        // Use the actual x87 return shims, not the f64 conversion functions.
        // The current non-x86-64 bodies do not implement binary128 long double.
        #[cfg(target_arch = "x86_64")]
        "strtold" => stdlib::strtold as *const (),
        #[cfg(target_arch = "x86_64")]
        "wcstold" => wide::wcstold as *const (),
        "setlocale" => locale::setlocale as *const (),
        "localeconv" => locale::localeconv as *const (),
        "nl_langinfo" => locale::nl_langinfo as *const (),
        // Share the process environment and putenv's caller-owned storage with
        // ordinary ABI callers; never resolve an independent host-only table.
        "getenv" => stdlib::getenv as *const (),
        "setenv" => stdlib::setenv as *const (),
        "unsetenv" => stdlib::unsetenv as *const (),
        "putenv" => stdlib::putenv as *const (),
        "clearenv" => stdlib::clearenv as *const (),
        // The direct addresses retain extern "C-unwind" for user comparators.
        "qsort" => stdlib::qsort as *const (),
        "bsearch" => stdlib::bsearch as *const (),
        "strtol" => stdlib::strtol as *const (),
        "strtoul" => stdlib::strtoul as *const (),
        "strtoll" => stdlib::strtoll as *const (),
        "strtoull" => stdlib::strtoull as *const (),
        "strtoimax" => stdlib::strtoimax as *const (),
        "strtoumax" => stdlib::strtoumax as *const (),
        "wcstol" => wide::wcstol as *const (),
        "wcstoul" => wide::wcstoul as *const (),
        "wcstoll" => wide::wcstoll as *const (),
        "wcstoull" => wide::wcstoull as *const (),
        "wcstoimax" => wide::wcstoimax as *const (),
        "wcstoumax" => wide::wcstoumax as *const (),
        "isalnum" => ctype::isalnum as *const (),
        "isalpha" => ctype::isalpha as *const (),
        "isblank" => ctype::isblank as *const (),
        "iscntrl" => ctype::iscntrl as *const (),
        "isdigit" => ctype::isdigit as *const (),
        "isgraph" => ctype::isgraph as *const (),
        "islower" => ctype::islower as *const (),
        "isprint" => ctype::isprint as *const (),
        "ispunct" => ctype::ispunct as *const (),
        "isspace" => ctype::isspace as *const (),
        "isupper" => ctype::isupper as *const (),
        "isxdigit" => ctype::isxdigit as *const (),
        "isascii" => ctype::isascii as *const (),
        "toascii" => ctype::toascii as *const (),
        "tolower" => ctype::tolower as *const (),
        "toupper" => ctype::toupper as *const (),
        "memchr" => strings::memchr as *const (),
        "memrchr" => strings::memrchr as *const (),
        "memcmp" => strings::memcmp as *const (),
        "strchr" => strings::strchr as *const (),
        "strrchr" => strings::strrchr as *const (),
        "strncmp" => strings::strncmp as *const (),
        "strnlen" => strings::strnlen as *const (),
        "strstr" => strings::strstr as *const (),
        "strdup" => strings::strdup as *const (),
        "strndup" => strings::strndup as *const (),
        "strcpy" => strings::strcpy as *const (),
        "strncpy" => strings::strncpy as *const (),
        "strcat" => strings::strcat as *const (),
        "strncat" => strings::strncat as *const (),
        "strspn" => strings::strspn as *const (),
        "strcspn" => strings::strcspn as *const (),
        "strpbrk" => strings::strpbrk as *const (),
        _ => return None,
    };
    Some(function as usize as u64)
}
