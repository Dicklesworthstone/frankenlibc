//! ABI layer for `<locale.h>` functions.
//!
//! Bootstrap provides the POSIX "C"/"POSIX" locale only. `setlocale` accepts
//! these names and rejects all others. `localeconv` returns C-locale defaults.

use std::collections::HashMap;
use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::os::unix::ffi::OsStrExt;
use std::sync::{Mutex, OnceLock};

use frankenlibc_core::locale as locale_core;
use frankenlibc_membrane::runtime_math::{ApiFamily, MembraneAction};

use crate::errno_abi::set_abi_errno;
use crate::runtime_policy;

/// Static C-locale name string.
static C_LOCALE_NAME: &[u8] = b"C\0";
/// Character encoding string for the POSIX C locale.
///
/// glibc reports `ANSI_X3.4-1968` for the `C`/`POSIX` locale, and this crate
/// only implements that locale family here.
static C_LOCALE_CODESET: &[u8] = b"ANSI_X3.4-1968\0";
/// POSIX C-locale radix character.
static C_LOCALE_RADIX: &[u8] = b".\0";
/// POSIX C-locale thousands separator (empty string).
static C_LOCALE_THOUSEP: &[u8] = b"\0";
/// Generic empty locale string result.
static EMPTY_LOCALE_STR: &[u8] = b"\0";

/// Static `struct lconv` for the C locale.
///
/// POSIX specifies that localeconv() returns a pointer to a static struct
/// that is overwritten by subsequent calls. We keep a single global instance.
static LCONV: LConv = LConv {
    decimal_point: b".\0" as *const u8 as *const c_char,
    thousands_sep: b"\0" as *const u8 as *const c_char,
    grouping: b"\0" as *const u8 as *const c_char,
    int_curr_symbol: b"\0" as *const u8 as *const c_char,
    currency_symbol: b"\0" as *const u8 as *const c_char,
    mon_decimal_point: b"\0" as *const u8 as *const c_char,
    mon_thousands_sep: b"\0" as *const u8 as *const c_char,
    mon_grouping: b"\0" as *const u8 as *const c_char,
    positive_sign: b"\0" as *const u8 as *const c_char,
    negative_sign: b"\0" as *const u8 as *const c_char,
    int_frac_digits: 127, // CHAR_MAX
    frac_digits: 127,
    p_cs_precedes: 127,
    p_sep_by_space: 127,
    n_cs_precedes: 127,
    n_sep_by_space: 127,
    p_sign_posn: 127,
    n_sign_posn: 127,
    int_p_cs_precedes: 127,
    int_p_sep_by_space: 127,
    int_n_cs_precedes: 127,
    int_n_sep_by_space: 127,
    int_p_sign_posn: 127,
    int_n_sign_posn: 127,
};

/// C-compatible `struct lconv`.
#[repr(C)]
pub struct LConv {
    decimal_point: *const c_char,
    thousands_sep: *const c_char,
    grouping: *const c_char,
    int_curr_symbol: *const c_char,
    currency_symbol: *const c_char,
    mon_decimal_point: *const c_char,
    mon_thousands_sep: *const c_char,
    mon_grouping: *const c_char,
    positive_sign: *const c_char,
    negative_sign: *const c_char,
    int_frac_digits: c_char,
    frac_digits: c_char,
    p_cs_precedes: c_char,
    p_sep_by_space: c_char,
    n_cs_precedes: c_char,
    n_sep_by_space: c_char,
    p_sign_posn: c_char,
    n_sign_posn: c_char,
    int_p_cs_precedes: c_char,
    int_p_sep_by_space: c_char,
    int_n_cs_precedes: c_char,
    int_n_sep_by_space: c_char,
    int_p_sign_posn: c_char,
    int_n_sign_posn: c_char,
}

// SAFETY: LConv contains only static pointers and scalars, all read-only.
unsafe impl Sync for LConv {}

// ---------------------------------------------------------------------------
// setlocale
// ---------------------------------------------------------------------------

/// POSIX `setlocale`.
///
/// Bootstrap: only the "C" and "POSIX" locales are supported. Querying
/// (null `locale` pointer) returns `"C"`. Setting to "C", "POSIX", or ""
/// succeeds. All other locale names fail and return null.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setlocale(category: c_int, locale: *const c_char) -> *const c_char {
    let (mode, decision) =
        runtime_policy::decide(ApiFamily::Locale, category as usize, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Locale, decision.profile, 5, true);
        return std::ptr::null();
    }

    // Validate category.
    if !locale_core::valid_category(category) {
        runtime_policy::observe(ApiFamily::Locale, decision.profile, 5, true);
        return std::ptr::null();
    }

    // Query mode: locale is NULL.
    if locale.is_null() {
        runtime_policy::observe(ApiFamily::Locale, decision.profile, 5, false);
        return C_LOCALE_NAME.as_ptr() as *const c_char;
    }

    // Parse the locale name.
    let name = unsafe { CStr::from_ptr(locale) }.to_bytes();

    if locale_core::is_c_locale(name) {
        runtime_policy::observe(ApiFamily::Locale, decision.profile, 8, false);
        C_LOCALE_NAME.as_ptr() as *const c_char
    } else if mode.heals_enabled() {
        // Hardened: fall back to C locale instead of failing.
        runtime_policy::observe(ApiFamily::Locale, decision.profile, 8, true);
        C_LOCALE_NAME.as_ptr() as *const c_char
    } else {
        runtime_policy::observe(ApiFamily::Locale, decision.profile, 8, true);
        std::ptr::null()
    }
}

// ---------------------------------------------------------------------------
// localeconv
// ---------------------------------------------------------------------------

/// POSIX `localeconv`.
///
/// Returns a pointer to a static `struct lconv` with C-locale defaults.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn localeconv() -> *const LConv {
    let (_, decision) = runtime_policy::decide(ApiFamily::Locale, 0, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Locale, decision.profile, 4, true);
        return std::ptr::null();
    }
    runtime_policy::observe(ApiFamily::Locale, decision.profile, 4, false);
    &LCONV
}

// ---------------------------------------------------------------------------
// nl_langinfo
// ---------------------------------------------------------------------------

/// POSIX `nl_langinfo`.
///
/// Bootstrap supports a minimal C-locale subset:
/// - `CODESET` -> `"ANSI_X3.4-1968"`
/// - `RADIXCHAR` -> `"."`
/// - `THOUSEP` -> `""`
///   Unsupported items return `""`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nl_langinfo(item: libc::nl_item) -> *const c_char {
    let (_, decision) = runtime_policy::decide(ApiFamily::Locale, item as usize, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Locale, decision.profile, 6, true);
        return std::ptr::null();
    }

    let value = match item {
        libc::CODESET => C_LOCALE_CODESET,
        libc::RADIXCHAR => C_LOCALE_RADIX,
        libc::THOUSEP => C_LOCALE_THOUSEP,
        // Day names (POSIX C locale, English)
        libc::DAY_1 => b"Sunday\0",
        libc::DAY_2 => b"Monday\0",
        libc::DAY_3 => b"Tuesday\0",
        libc::DAY_4 => b"Wednesday\0",
        libc::DAY_5 => b"Thursday\0",
        libc::DAY_6 => b"Friday\0",
        libc::DAY_7 => b"Saturday\0",
        // Abbreviated day names
        libc::ABDAY_1 => b"Sun\0",
        libc::ABDAY_2 => b"Mon\0",
        libc::ABDAY_3 => b"Tue\0",
        libc::ABDAY_4 => b"Wed\0",
        libc::ABDAY_5 => b"Thu\0",
        libc::ABDAY_6 => b"Fri\0",
        libc::ABDAY_7 => b"Sat\0",
        // Month names
        libc::MON_1 => b"January\0",
        libc::MON_2 => b"February\0",
        libc::MON_3 => b"March\0",
        libc::MON_4 => b"April\0",
        libc::MON_5 => b"May\0",
        libc::MON_6 => b"June\0",
        libc::MON_7 => b"July\0",
        libc::MON_8 => b"August\0",
        libc::MON_9 => b"September\0",
        libc::MON_10 => b"October\0",
        libc::MON_11 => b"November\0",
        libc::MON_12 => b"December\0",
        // Abbreviated month names
        libc::ABMON_1 => b"Jan\0",
        libc::ABMON_2 => b"Feb\0",
        libc::ABMON_3 => b"Mar\0",
        libc::ABMON_4 => b"Apr\0",
        libc::ABMON_5 => b"May\0",
        libc::ABMON_6 => b"Jun\0",
        libc::ABMON_7 => b"Jul\0",
        libc::ABMON_8 => b"Aug\0",
        libc::ABMON_9 => b"Sep\0",
        libc::ABMON_10 => b"Oct\0",
        libc::ABMON_11 => b"Nov\0",
        libc::ABMON_12 => b"Dec\0",
        // AM/PM
        libc::AM_STR => b"AM\0",
        libc::PM_STR => b"PM\0",
        // Date/time format strings (POSIX C locale)
        libc::D_T_FMT => b"%a %b %e %H:%M:%S %Y\0",
        libc::D_FMT => b"%m/%d/%y\0",
        libc::T_FMT => b"%H:%M:%S\0",
        libc::T_FMT_AMPM => b"%I:%M:%S %p\0",
        libc::ERA => b"\0",
        libc::ERA_D_FMT => b"\0",
        libc::ERA_D_T_FMT => b"\0",
        libc::ERA_T_FMT => b"\0",
        libc::ALT_DIGITS => b"\0",
        libc::YESEXPR => b"^[yY]\0",
        libc::NOEXPR => b"^[nN]\0",
        libc::CRNCYSTR => b"\0",
        _ => EMPTY_LOCALE_STR,
    };
    runtime_policy::observe(ApiFamily::Locale, decision.profile, 6, false);
    value.as_ptr() as *const c_char
}

// ---------------------------------------------------------------------------
// gettext family — native C-locale implementation
// ---------------------------------------------------------------------------
//
// FrankenLibC supports only the C/POSIX locale. In the C locale, the gettext
// family acts as identity functions — no message catalog is loaded, so msgid
// is returned unmodified. This is the correct POSIX behavior when no
// translations are installed.

/// GNU `gettext` — returns msgid unchanged (C locale: no translation).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn gettext(msgid: *const c_char) -> *mut c_char {
    msgid as *mut c_char
}

/// GNU `dgettext` — returns msgid unchanged (C locale: domain ignored).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn dgettext(_domainname: *const c_char, msgid: *const c_char) -> *mut c_char {
    msgid as *mut c_char
}

/// GNU `ngettext` — returns singular or plural form (C locale: no translation).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ngettext(
    msgid: *const c_char,
    msgid_plural: *const c_char,
    n: libc::c_ulong,
) -> *mut c_char {
    if n == 1 {
        msgid as *mut c_char
    } else {
        msgid_plural as *mut c_char
    }
}

/// Default text domain name.
static DEFAULT_TEXT_DOMAIN: &[u8] = b"messages\0";
/// Default locale directory.
static DEFAULT_LOCALE_DIR: &[u8] = b"/usr/share/locale\0";

struct TextDomainState {
    current: *mut c_char,
    pool: Vec<CString>,
}

// SAFETY: access is synchronized via the surrounding Mutex, and the raw
// pointers refer either to static storage or heap allocations owned by `pool`.
unsafe impl Send for TextDomainState {}

struct LocaleDirState {
    current_by_domain: std::collections::HashMap<Vec<u8>, *mut c_char>,
    pool: Vec<CString>,
}

// SAFETY: access is synchronized via the surrounding Mutex, and the raw
// pointers refer either to static storage or heap allocations owned by `pool`.
unsafe impl Send for LocaleDirState {}

fn text_domain_storage() -> &'static Mutex<TextDomainState> {
    static STORAGE: OnceLock<Mutex<TextDomainState>> = OnceLock::new();
    STORAGE.get_or_init(|| {
        Mutex::new(TextDomainState {
            current: DEFAULT_TEXT_DOMAIN.as_ptr() as *mut c_char,
            pool: Vec::new(),
        })
    })
}

fn locale_dir_bindings() -> &'static Mutex<LocaleDirState> {
    static STORAGE: OnceLock<Mutex<LocaleDirState>> = OnceLock::new();
    STORAGE.get_or_init(|| {
        Mutex::new(LocaleDirState {
            current_by_domain: std::collections::HashMap::new(),
            pool: Vec::new(),
        })
    })
}

/// Test hook: reset process-global gettext domain state for deterministic
/// integration tests that exercise `textdomain`/`bindtextdomain`.
#[doc(hidden)]
pub fn locale_reset_gettext_state_for_tests() {
    let mut domains = text_domain_storage()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    domains.current = DEFAULT_TEXT_DOMAIN.as_ptr() as *mut c_char;
    domains.pool.clear();
    drop(domains);

    let mut bindings = locale_dir_bindings()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    bindings.current_by_domain.clear();
    bindings.pool.clear();
}

/// GNU `textdomain` — set/query current text domain.
///
/// In C-locale mode, the domain is irrelevant since no translations are loaded.
/// Returns the domain name for API compatibility.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn textdomain(domainname: *const c_char) -> *mut c_char {
    let storage = text_domain_storage();
    let mut current = storage.lock().unwrap_or_else(|e| e.into_inner());
    if domainname.is_null() {
        current.current
    } else if unsafe { *domainname } == 0 {
        current.current = DEFAULT_TEXT_DOMAIN.as_ptr() as *mut c_char;
        current.current
    } else {
        let name = unsafe { CStr::from_ptr(domainname) }.to_bytes();
        let owned = CString::new(name).expect("textdomain name must be NUL-free");
        let ptr = owned.as_ptr() as *mut c_char;
        current.pool.push(owned);
        current.current = ptr;
        ptr
    }
}

/// GNU `bindtextdomain` — bind a text domain to a locale directory.
///
/// In C-locale mode, no catalog lookup occurs. Returns the dirname for
/// API compatibility.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn bindtextdomain(
    domainname: *const c_char,
    dirname: *const c_char,
) -> *mut c_char {
    if domainname.is_null() {
        return std::ptr::null_mut();
    }

    let domain = unsafe { CStr::from_ptr(domainname) }.to_bytes();
    if domain.is_empty() {
        return std::ptr::null_mut();
    }
    let storage = locale_dir_bindings();
    let mut bindings = storage.lock().unwrap_or_else(|e| e.into_inner());

    if dirname.is_null() {
        if let Some(bound) = bindings.current_by_domain.get(domain) {
            *bound
        } else {
            DEFAULT_LOCALE_DIR.as_ptr() as *mut c_char
        }
    } else {
        let dir = unsafe { CStr::from_ptr(dirname) }.to_bytes();
        let owned = CString::new(dir).expect("locale directory must be NUL-free");
        let ptr = owned.as_ptr() as *mut c_char;
        bindings.pool.push(owned);
        bindings.current_by_domain.insert(domain.to_vec(), ptr);
        ptr
    }
}

// ---------------------------------------------------------------------------
// POSIX 2008 thread-local locale — native C-locale implementation
// ---------------------------------------------------------------------------
//
// FrankenLibC only supports the C/POSIX locale. These functions provide
// the POSIX.1-2008 thread-safe locale API with deterministic C-locale
// semantics. locale_t is an opaque pointer; we use a sentinel value
// for the C locale handle.

/// Opaque locale handle type (matches glibc `locale_t` = `__locale_t`).
pub type LocaleT = *mut std::ffi::c_void;

/// Sentinel value for the C locale handle.
static C_LOCALE_HANDLE: u8 = 0;

/// Return a pointer to use as the C-locale handle.
#[inline]
fn c_locale_handle() -> LocaleT {
    std::ptr::addr_of!(C_LOCALE_HANDLE) as LocaleT
}

/// POSIX `newlocale` — create a new locale object.
///
/// C-locale only: accepts C/POSIX/"" and returns a handle. All other
/// locale names return null (or the C locale handle in hardened mode).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn newlocale(
    category_mask: c_int,
    locale: *const c_char,
    base: LocaleT,
) -> LocaleT {
    let (mode, decision) =
        runtime_policy::decide(ApiFamily::Locale, category_mask as usize, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Locale, decision.profile, 6, true);
        return std::ptr::null_mut();
    }

    let accept = if locale.is_null() {
        true
    } else {
        let name = unsafe { CStr::from_ptr(locale) }.to_bytes();
        locale_core::is_c_locale(name)
    };

    let _ = base;

    if accept {
        runtime_policy::observe(ApiFamily::Locale, decision.profile, 6, false);
        c_locale_handle()
    } else if mode.heals_enabled() {
        runtime_policy::observe(ApiFamily::Locale, decision.profile, 6, true);
        c_locale_handle()
    } else {
        runtime_policy::observe(ApiFamily::Locale, decision.profile, 6, true);
        std::ptr::null_mut()
    }
}

/// POSIX `uselocale` — set thread-local locale.
///
/// C-locale only: always returns the C locale handle. If `newloc` is
/// non-null and non-`LC_GLOBAL_LOCALE`, it is accepted (C locale only).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn uselocale(newloc: LocaleT) -> LocaleT {
    let _ = newloc;
    c_locale_handle()
}

/// POSIX `freelocale` — free a locale object.
///
/// C-locale only: no-op since our locale handles are static.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn freelocale(_locale: LocaleT) {
    // No-op: C locale handle is static.
}

/// POSIX `duplocale` — duplicate a locale object.
///
/// C-locale only: returns the same C locale handle.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn duplocale(_locale: LocaleT) -> LocaleT {
    c_locale_handle()
}

/// POSIX `nl_langinfo_l` — locale-aware nl_langinfo.
///
/// C-locale only: ignores locale parameter and delegates to nl_langinfo.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nl_langinfo_l(item: libc::nl_item, _locale: *mut c_void) -> *const c_char {
    unsafe { nl_langinfo(item) }
}

// ===========================================================================
// XSI message catalogs — catopen / catgets / catclose
// ===========================================================================

/// nl_catd type — opaque message catalog descriptor.
#[allow(non_camel_case_types)]
pub type nl_catd = isize;

const INVALID_NL_CATD: nl_catd = -1;
const CATGETS_MAGIC: u32 = 0x9604_08de;
const CATALOG_HEADER_WORDS: usize = 3;
const CATALOG_SLOT_WORDS: usize = 3;

struct MessageCatalog {
    plane_size: usize,
    plane_depth: usize,
    table: Box<[u32]>,
    strings: Box<[u8]>,
}

impl MessageCatalog {
    fn message_ptr(&self, set_id: c_int, msg_id: c_int) -> Option<*const c_char> {
        let stored_set = set_id.checked_add(1)?;
        if stored_set <= 0 || msg_id < 0 {
            return None;
        }

        let stored_set = stored_set as usize;
        let msg_id = msg_id as usize;
        let mut idx = ((stored_set * msg_id) % self.plane_size) * CATALOG_SLOT_WORDS;

        for _ in 0..self.plane_depth {
            if self.table[idx] == stored_set as u32 && self.table[idx + 1] == msg_id as u32 {
                let offset = self.table[idx + 2] as usize;
                if offset >= self.strings.len() {
                    return None;
                }
                return Some(self.strings[offset..].as_ptr().cast::<c_char>());
            }
            idx += self.plane_size * CATALOG_SLOT_WORDS;
        }

        None
    }
}

struct CatalogRegistry {
    next_id: nl_catd,
    open: HashMap<nl_catd, MessageCatalog>,
}

fn catalog_registry() -> &'static Mutex<CatalogRegistry> {
    static STORAGE: OnceLock<Mutex<CatalogRegistry>> = OnceLock::new();
    STORAGE.get_or_init(|| {
        Mutex::new(CatalogRegistry {
            next_id: 1,
            open: HashMap::new(),
        })
    })
}

fn next_catalog_id(registry: &mut CatalogRegistry) -> nl_catd {
    loop {
        let candidate = registry.next_id;
        registry.next_id = registry.next_id.checked_add(1).unwrap_or(1);
        if registry.next_id == INVALID_NL_CATD {
            registry.next_id = 1;
        }
        if candidate != INVALID_NL_CATD && !registry.open.contains_key(&candidate) {
            return candidate;
        }
    }
}

fn catalog_word(bytes: &[u8], offset: usize, swapped_header: bool) -> Option<u32> {
    let chunk: [u8; 4] = bytes.get(offset..offset + 4)?.try_into().ok()?;
    Some(if swapped_header {
        u32::from_be_bytes(chunk)
    } else {
        u32::from_le_bytes(chunk)
    })
}

fn parse_catalog_bytes(bytes: Vec<u8>) -> Result<MessageCatalog, c_int> {
    let header_len = CATALOG_HEADER_WORDS * std::mem::size_of::<u32>();
    if bytes.len() <= header_len {
        return Err(libc::EINVAL);
    }

    let magic_le = catalog_word(&bytes, 0, false).ok_or(libc::EINVAL)?;
    let swapped_header = if magic_le == CATGETS_MAGIC {
        false
    } else if catalog_word(&bytes, 0, true).ok_or(libc::EINVAL)? == CATGETS_MAGIC {
        true
    } else {
        return Err(libc::EINVAL);
    };

    let plane_size = catalog_word(&bytes, 4, swapped_header).ok_or(libc::EINVAL)? as usize;
    let plane_depth = catalog_word(&bytes, 8, swapped_header).ok_or(libc::EINVAL)? as usize;
    if plane_size == 0 || plane_depth == 0 {
        return Err(libc::EINVAL);
    }

    let table_words = plane_size
        .checked_mul(plane_depth)
        .and_then(|count| count.checked_mul(CATALOG_SLOT_WORDS))
        .ok_or(libc::EINVAL)?;
    let table_bytes = table_words
        .checked_mul(std::mem::size_of::<u32>())
        .ok_or(libc::EINVAL)?;
    let first_table_end = header_len.checked_add(table_bytes).ok_or(libc::EINVAL)?;
    let strings_offset = first_table_end
        .checked_add(table_bytes)
        .ok_or(libc::EINVAL)?;
    if strings_offset >= bytes.len() {
        return Err(libc::EINVAL);
    }

    let first_table = bytes.get(header_len..first_table_end).ok_or(libc::EINVAL)?;
    let mut table = Vec::with_capacity(table_words);
    for chunk in first_table.chunks_exact(4) {
        let word: [u8; 4] = chunk.try_into().map_err(|_| libc::EINVAL)?;
        table.push(u32::from_le_bytes(word));
    }
    if table.len() != table_words {
        return Err(libc::EINVAL);
    }

    let strings = bytes[strings_offset..].to_vec().into_boxed_slice();
    let max_offset = table
        .iter()
        .skip(2)
        .step_by(CATALOG_SLOT_WORDS)
        .copied()
        .max()
        .unwrap_or(0) as usize;
    if max_offset >= strings.len() || !strings[max_offset..].contains(&0) {
        return Err(libc::EINVAL);
    }

    Ok(MessageCatalog {
        plane_size,
        plane_depth,
        table: table.into_boxed_slice(),
        strings,
    })
}

/// Test hook: clear any process-global catalog descriptors for deterministic
/// locale ABI tests.
#[doc(hidden)]
pub fn locale_reset_catalog_state_for_tests() {
    let mut registry = catalog_registry().lock().unwrap_or_else(|e| e.into_inner());
    registry.next_id = 1;
    registry.open.clear();
}

/// `catopen` — open a message catalog.
///
/// Minimal deterministic backend: open a direct catalog path, parse the glibc
/// `.cat` table format, and return an opaque descriptor id.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn catopen(name: *const c_char, _oflag: c_int) -> nl_catd {
    if name.is_null() {
        unsafe { set_abi_errno(libc::EINVAL) };
        return INVALID_NL_CATD;
    }

    let name = unsafe { CStr::from_ptr(name) };
    let path = std::path::Path::new(std::ffi::OsStr::from_bytes(name.to_bytes()));
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(err) => {
            unsafe { set_abi_errno(err.raw_os_error().unwrap_or(libc::EIO)) };
            return INVALID_NL_CATD;
        }
    };

    let catalog = match parse_catalog_bytes(bytes) {
        Ok(catalog) => catalog,
        Err(err) => {
            unsafe { set_abi_errno(err) };
            return INVALID_NL_CATD;
        }
    };

    let mut registry = catalog_registry().lock().unwrap_or_else(|e| e.into_inner());
    let id = next_catalog_id(&mut registry);
    registry.open.insert(id, catalog);
    id
}

/// `catgets` — read a message from a catalog.
///
/// Mirrors glibc's forgiving contract for failed `catopen` descriptors:
/// `catgets((nl_catd)-1, ...)` simply returns the default string.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn catgets(
    catd: nl_catd,
    set_id: c_int,
    msg_id: c_int,
    s: *const c_char,
) -> *const c_char {
    if catd == INVALID_NL_CATD || set_id < 0 || msg_id < 0 {
        return s;
    }

    let registry = catalog_registry().lock().unwrap_or_else(|e| e.into_inner());
    let Some(catalog) = registry.open.get(&catd) else {
        unsafe { set_abi_errno(libc::EBADF) };
        return s;
    };

    if let Some(message_ptr) = catalog.message_ptr(set_id, msg_id) {
        message_ptr
    } else {
        unsafe { set_abi_errno(libc::ENOMSG) };
        s
    }
}

/// `catclose` — close a message catalog.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn catclose(catd: nl_catd) -> c_int {
    if catd == INVALID_NL_CATD {
        unsafe { set_abi_errno(libc::EBADF) };
        return -1;
    }

    let mut registry = catalog_registry().lock().unwrap_or_else(|e| e.into_inner());
    if registry.open.remove(&catd).is_some() {
        0
    } else {
        unsafe { set_abi_errno(libc::EBADF) };
        -1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setlocale_query_returns_c() {
        // SAFETY: Null locale means query mode.
        let result = unsafe { setlocale(locale_core::LC_ALL, std::ptr::null()) };
        assert!(!result.is_null());
        let name = unsafe { CStr::from_ptr(result) }.to_bytes();
        assert_eq!(name, b"C");
    }

    #[test]
    fn localeconv_returns_c_locale() {
        // SAFETY: No arguments.
        let conv = unsafe { localeconv() };
        assert!(!conv.is_null());
        let dp = unsafe { CStr::from_ptr((*conv).decimal_point) };
        assert_eq!(dp.to_bytes(), b".");
    }

    #[test]
    fn nl_langinfo_codeset_returns_c_locale_ascii() {
        // SAFETY: CODESET is a valid item.
        let result = unsafe { nl_langinfo(libc::CODESET) };
        assert!(!result.is_null());
        let val = unsafe { CStr::from_ptr(result) };
        assert_eq!(val.to_bytes(), b"ANSI_X3.4-1968");
    }

    #[test]
    fn newlocale_c_locale_succeeds() {
        let c_name = b"C\0";
        // SAFETY: Valid C-locale name.
        let loc = unsafe {
            newlocale(
                libc::LC_ALL_MASK,
                c_name.as_ptr() as *const c_char,
                std::ptr::null_mut(),
            )
        };
        assert!(!loc.is_null());
    }

    #[test]
    fn uselocale_returns_handle() {
        // SAFETY: Null means query only.
        let loc = unsafe { uselocale(std::ptr::null_mut()) };
        assert!(!loc.is_null());
    }

    #[test]
    fn duplocale_returns_handle() {
        let handle = c_locale_handle();
        // SAFETY: Valid locale handle.
        let dup = unsafe { duplocale(handle) };
        assert!(!dup.is_null());
        assert_eq!(dup, handle);
    }

    #[test]
    fn freelocale_is_noop() {
        let handle = c_locale_handle();
        // SAFETY: Valid locale handle.
        unsafe { freelocale(handle) };
        // No crash, no-op verified.
    }
}
