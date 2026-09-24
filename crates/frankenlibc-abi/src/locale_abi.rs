//! ABI layer for `<locale.h>` functions.
//!
//! Bootstrap provides a UTF-8 C locale. `setlocale` accepts the conventional
//! C aliases and canonicalizes them to `C.UTF-8`; `localeconv` retains the
//! C-locale numeric defaults.

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::os::unix::ffi::OsStrExt;
use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::{Mutex, OnceLock};

use frankenlibc_core::locale as locale_core;
use frankenlibc_membrane::runtime_math::{ApiFamily, MembraneAction};

use crate::errno_abi::set_abi_errno;
use crate::runtime_policy;
use crate::util::{ArtifactHashMap, artifact_hash_map, scan_c_string};

#[inline]
fn known_locale_string_remaining(ptr: usize) -> Option<usize> {
    #[cfg(not(test))]
    {
        crate::malloc_abi::known_remaining(ptr)
    }

    #[cfg(test)]
    {
        let _ = ptr;
        None
    }
}

/// Read a user-supplied C string pointer with a known-region bound so a
/// non-NUL-terminated argument cannot walk arbitrary process memory.
/// Returns `None` for null, empty, or unterminated input. (bd-z4k96)
#[inline]
unsafe fn read_bounded_cstr(ptr: *const c_char) -> Option<Vec<u8>> {
    if ptr.is_null() {
        return None;
    }
    let (len, terminated) =
        unsafe { scan_c_string(ptr, known_locale_string_remaining(ptr as usize)) };
    if !terminated {
        return None;
    }
    let bytes = unsafe { core::slice::from_raw_parts(ptr as *const u8, len) };
    Some(bytes.to_vec())
}

/// Canonical name for the UTF-8 locale.
static UTF8_LOCALE_NAME: &[u8] = b"C.UTF-8\0";
/// Character encoding string for the UTF-8 locale.
static UTF8_LOCALE_CODESET: &[u8] = b"UTF-8\0";
/// Canonical name for the POSIX C locale.
///
/// glibc canonicalises both `"C"` and `"POSIX"` to `"C"`, measured against
/// host glibc 2.42: `setlocale(LC_ALL,"POSIX")` returns `"C"`, not `"POSIX"`.
static C_LOCALE_NAME: &[u8] = b"C\0";
/// Character encoding string for the POSIX C locale.
///
/// Measured, not assumed: host glibc 2.42 reports `ANSI_X3.4-1968` for
/// `nl_langinfo(CODESET)` under `LC_ALL=C`, with `MB_CUR_MAX == 1`.
static C_LOCALE_CODESET: &[u8] = b"ANSI_X3.4-1968\0";

// ---------------------------------------------------------------------------
// Active locale
// ---------------------------------------------------------------------------

/// The character encodings FrankenLibC can select.
///
/// These are not decoration: the whole point of separating them is that the
/// reported locale NAME, the reported CODESET, `MB_CUR_MAX` and the multibyte
/// codec itself must move together. A build where `setlocale(LC_ALL,"C")`
/// reports `"C"` while the codec keeps decoding UTF-8 matches neither glibc nor
/// this library's own contract, and would make `MB_CUR_MAX` disagree with what
/// `wctomb` actually emits. Every accessor below derives from this one value so
/// that state cannot be constructed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Charset {
    /// 7-bit ASCII, the POSIX C locale's encoding (`ANSI_X3.4-1968`).
    ///
    /// Measured against host glibc 2.42 under `LC_ALL=C`: every byte `>= 0x80`
    /// is `EILSEQ` on decode — including a well-formed UTF-8 lead byte, which
    /// is rejected at the lead rather than consumed — and every wide character
    /// `>= U+0080` is `EILSEQ` on encode. `0x00..=0x7F` maps to itself.
    Ascii,
    /// UTF-8, as `C.UTF-8` (`MB_CUR_MAX == 6`, glibc's historical RFC 2279 size).
    Utf8,
}

const CHARSET_ASCII: u8 = 0;
const CHARSET_UTF8: u8 = 1;

/// The process-wide active character set.
///
/// DEFAULT IS `Ascii`, MATCHING glibc: a C program that never calls `setlocale`
/// runs in the `"C"` locale, where `MB_CUR_MAX` is 1 and `mbrtowc` refuses every
/// byte `>= 0x80`. fl previously started in UTF-8, which made
/// `setlocale(LC_ALL,NULL)` at startup report `C.UTF-8` where glibc reports `C`.
///
/// The flip is what makes the never-called-`setlocale` path agree with the
/// incumbent, and it is why the differential helpers that used to put only the
/// HOST into `C.UTF-8` (`libc::setlocale`) now put fl there too — otherwise they
/// would compare an ASCII fl against a UTF-8 glibc and fail for a reason that
/// has nothing to do with what they test.
/// PER-CATEGORY, not one value for the process. `setlocale(LC_NUMERIC, "C")`
/// must leave `LC_CTYPE` alone, and `setlocale(LC_ALL, NULL)` must be able to
/// report that they now differ — neither is expressible with a single slot.
///
/// Twelve slots, indexed by `locale_core::category_slot`, which skips `LC_ALL`.
/// `LC_ALL` sits at 6 in the MIDDLE of the numeric range, so indexing directly
/// by category number would leave a hole at the pseudo-category.
static ACTIVE_CHARSET: [std::sync::atomic::AtomicU8; locale_core::CATEGORY_COUNT] =
    [const { std::sync::atomic::AtomicU8::new(CHARSET_ASCII) }; locale_core::CATEGORY_COUNT];

/// Direct pointer for `nl_langinfo(CODESET)`, published in lockstep with `ACTIVE_CHARSET`.
static ACTIVE_CODESET_PTR: AtomicPtr<c_char> =
    AtomicPtr::new(C_LOCALE_CODESET.as_ptr() as *mut c_char);

#[inline]
fn decode_charset(raw: u8) -> Charset {
    match raw {
        CHARSET_ASCII => Charset::Ascii,
        _ => Charset::Utf8,
    }
}

/// The character set a single category is set to.
#[inline]
fn category_charset(cat: c_int) -> Charset {
    match locale_core::category_slot(cat) {
        Some(slot) => decode_charset(ACTIVE_CHARSET[slot].load(Ordering::Acquire)),
        // `LC_ALL` has no slot of its own; report LC_CTYPE, which is the
        // category every conversion entrypoint actually consults.
        None => {
            decode_charset(ACTIVE_CHARSET[locale_core::LC_CTYPE as usize].load(Ordering::Acquire))
        }
    }
}

/// The character set every conversion entrypoint must honour.
///
/// This is `LC_CTYPE` specifically, not "the locale": POSIX puts character
/// classification and multibyte conversion under `LC_CTYPE`, so a program that
/// sets only `LC_NUMERIC` to `C.UTF-8` must NOT get a UTF-8 codec.
#[inline]
pub(crate) fn active_charset() -> Charset {
    decode_charset(ACTIVE_CHARSET[locale_core::LC_CTYPE as usize].load(Ordering::Acquire))
}

#[inline]
fn encode_charset(charset: Charset) -> u8 {
    match charset {
        Charset::Ascii => CHARSET_ASCII,
        Charset::Utf8 => CHARSET_UTF8,
    }
}

/// Set one category, or every category when `cat` is `LC_ALL`.
fn set_category_charset(cat: c_int, charset: Charset) {
    let encoded = encode_charset(charset);
    let cptr = codeset_ptr(charset) as *mut c_char;
    match locale_core::category_slot(cat) {
        Some(slot) => {
            ACTIVE_CHARSET[slot].store(encoded, Ordering::Release);
            if slot == locale_core::LC_CTYPE as usize {
                ACTIVE_CODESET_PTR.store(cptr, Ordering::Release);
            }
        }
        None => {
            for slot in ACTIVE_CHARSET.iter() {
                slot.store(encoded, Ordering::Release);
            }
            ACTIVE_CODESET_PTR.store(cptr, Ordering::Release);
        }
    }
}

#[inline]
fn set_active_charset(charset: Charset) {
    set_category_charset(locale_core::LC_ALL, charset);
}

/// Storage for the `LC_ALL` composite string.
///
/// glibc returns a pointer to internal storage that the next `setlocale` may
/// overwrite, and callers are expected to copy it. This mirrors that contract
/// rather than leaking a fresh allocation per query.
static COMPOSITE_BUF: Mutex<Vec<u8>> = Mutex::new(Vec::new());

/// Build the `LC_ALL` answer: a single name when every category agrees, and
/// glibc's `LC_CTYPE=..;LC_NUMERIC=..;..` composite when they do not.
///
/// Measured against glibc 2.42. With only `LC_CTYPE` moved to `C.UTF-8` it
/// answers the full twelve-field composite; with every category on the same
/// locale it answers the bare name. The field ORDER is glibc's, not the numeric
/// category order — see `locale_core::COMPOSITE_ORDER`.
fn lc_all_report() -> *const c_char {
    let first = category_name(locale_core::COMPOSITE_ORDER[0].1);
    if locale_core::COMPOSITE_ORDER
        .iter()
        .all(|(_, cat)| category_name(*cat) == first)
    {
        return first.as_ptr() as *const c_char;
    }

    let mut buf = COMPOSITE_BUF.lock().unwrap_or_else(|e| e.into_inner());
    buf.clear();
    for (index, (name, cat)) in locale_core::COMPOSITE_ORDER.iter().enumerate() {
        if index > 0 {
            buf.push(b';');
        }
        buf.extend_from_slice(name.as_bytes());
        buf.push(b'=');
        // Names are NUL-terminated statics; the composite wants the text only.
        let text = category_name(*cat);
        buf.extend_from_slice(&text[..text.len() - 1]);
    }
    buf.push(0);
    buf.as_ptr() as *const c_char
}

/// Test hook: restore the startup locale so a test that selects one cannot
/// leak it into the arms libtest runs alongside it on other threads.
///
/// Restores `Ascii`, which is the startup default — not `Utf8`. A reset that
/// put the process somewhere it never starts would hide exactly the
/// cross-arm leakage it exists to prevent.
#[doc(hidden)]
pub fn locale_reset_active_charset_for_tests() {
    // EVERY category, not just LC_CTYPE. A reset that left one category on
    // C.UTF-8 would make the next arm's `setlocale(LC_ALL, NULL)` return a
    // composite string, which is exactly the cross-arm leak this exists to stop.
    for slot in &NAMED {
        slot.store(std::ptr::null_mut(), Ordering::Release);
    }
    CTYPE_TABLES.store(std::ptr::null_mut(), Ordering::Release);
    set_category_charset(locale_core::LC_ALL, Charset::Ascii);
}

/// The canonical name `setlocale` reports for `charset`.
#[inline]
fn locale_name_for(charset: Charset) -> &'static [u8] {
    match charset {
        Charset::Ascii => C_LOCALE_NAME,
        Charset::Utf8 => UTF8_LOCALE_NAME,
    }
}

/// The `nl_langinfo(CODESET)` string for `charset`.
#[inline]
fn codeset_for(charset: Charset) -> &'static [u8] {
    match charset {
        Charset::Ascii => C_LOCALE_CODESET,
        Charset::Utf8 => UTF8_LOCALE_CODESET,
    }
}

/// Which locale a requested name selects, or `None` if fl does not ship it.
///
/// `""` is deliberately NOT folded in with `"C"`, though `locale_core::
/// is_c_locale` groups them: POSIX gives `""` "derive from the environment"
/// semantics, and on a host whose `LANG` is a UTF-8 locale glibc answers
/// `setlocale(LC_ALL,"")` with that UTF-8 locale, not with `"C"`. Mapping `""`
/// onto the ASCII C locale would therefore be a fresh divergence introduced by
/// the very change meant to remove one.
#[inline]
fn charset_for_request(name: &[u8]) -> Option<Charset> {
    match name {
        b"C" | b"POSIX" => Some(Charset::Ascii),
        b"C.UTF-8" | b"C.utf8" => Some(Charset::Utf8),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Named locales: glibc's compiled locale data
// ---------------------------------------------------------------------------

use frankenlibc_core::locale::data::{CategoryBlob, LocaleArchive, name_candidates};

/// One category of a named locale: the name `setlocale` reports (as the
/// caller spelled it, NUL-terminated) and the compiled blob. Loaded once per
/// (category, name) and kept for the process lifetime, like glibc's data.
struct NamedCategory {
    category: c_int,
    name: Box<[u8]>,
    blob: CategoryBlob<'static>,
    /// For LC_CTYPE: the wide-character class/case/width tables.
    ctype: Option<frankenlibc_core::locale::data::CtypeTables<'static>>,
}

/// The wide-character tables of the active LC_CTYPE (null: see
/// [`wide_ctype`]).
static CTYPE_TABLES: AtomicPtr<frankenlibc_core::locale::data::CtypeTables<'static>> =
    AtomicPtr::new(std::ptr::null_mut());

/// How wide-character classification, case mapping and `wcwidth` behave.
pub(crate) enum WideCtype {
    /// The C/POSIX locale: ASCII only, as glibc's built-in C locale.
    Ascii,
    /// The active locale's compiled tables.
    Tables(&'static frankenlibc_core::locale::data::CtypeTables<'static>),
    /// UTF-8 with no locale data available: fl's built-in Unicode tables.
    Builtin,
}

#[inline]
pub(crate) fn wide_ctype() -> WideCtype {
    // SAFETY: published pointers come from leaked, never-freed tables.
    if let Some(t) = unsafe { CTYPE_TABLES.load(Ordering::Acquire).as_ref() } {
        return WideCtype::Tables(t);
    }
    match active_charset() {
        Charset::Ascii => WideCtype::Ascii,
        Charset::Utf8 => WideCtype::Builtin,
    }
}

/// glibc's C.UTF-8 is compiled locale data too; use it when installed so
/// classification matches the system's Unicode version.
fn c_utf8_ctype_tables() -> *mut frankenlibc_core::locale::data::CtypeTables<'static> {
    static TABLES: OnceLock<usize> = OnceLock::new();
    *TABLES.get_or_init(|| {
        load_category(locale_core::LC_CTYPE, b"C.utf8")
            .and_then(|n| n.ctype.as_ref())
            .map_or(0, |t| (t as *const _) as usize)
    }) as *mut _
}

/// Per-category named locale (by `category_slot`); null = built-in C data.
static NAMED: [AtomicPtr<NamedCategory>; locale_core::CATEGORY_COUNT] =
    [const { AtomicPtr::new(std::ptr::null_mut()) }; locale_core::CATEGORY_COUNT];

/// Whether any category is on a named locale (keeps the C fast paths free
/// of per-category loads until one is).
static NAMED_ANY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Every category ever loaded, reused for later requests.
static LOADED: Mutex<Vec<&'static NamedCategory>> = Mutex::new(Vec::new());

#[inline]
fn named(category: c_int) -> Option<&'static NamedCategory> {
    if !NAMED_ANY.load(Ordering::Acquire) {
        return None;
    }
    let slot = locale_core::category_slot(category)?;
    // SAFETY: published pointers come from leaked `NamedCategory` values.
    unsafe { NAMED[slot].load(Ordering::Acquire).as_ref() }
}

/// Map a whole file read-only for the process lifetime.
fn map_file(path: &[u8]) -> Option<&'static [u8]> {
    let mut cpath = path.to_vec();
    cpath.push(0);
    // SAFETY: NUL-terminated path; the mapping is never unmapped.
    unsafe {
        let fd = frankenlibc_core::syscall::sys_openat(
            libc::AT_FDCWD,
            cpath.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC,
            0,
        )
        .ok()?;
        let mut st: libc::stat = std::mem::zeroed();
        let ok =
            frankenlibc_core::syscall::sys_fstat(fd, (&mut st as *mut libc::stat).cast()).is_ok();
        let len = st.st_size as usize;
        let map = if ok && len > 0 {
            frankenlibc_core::syscall::sys_mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ,
                libc::MAP_PRIVATE,
                fd,
                0,
            )
            .ok()
        } else {
            None
        };
        let _ = frankenlibc_core::syscall::sys_close(fd);
        map.map(|p| std::slice::from_raw_parts(p.cast_const(), len))
    }
}

/// The system locale archive (glibc's default location).
fn locale_archive() -> Option<LocaleArchive<'static>> {
    static ARCHIVE: OnceLock<Option<LocaleArchive<'static>>> = OnceLock::new();
    *ARCHIVE.get_or_init(|| LocaleArchive::parse(map_file(b"/usr/lib/locale/locale-archive")?))
}

/// The file a category lives in inside an unpacked locale directory.
fn category_file(category: c_int) -> Option<&'static [u8]> {
    Some(match category {
        0 => b"LC_CTYPE",
        1 => b"LC_NUMERIC",
        2 => b"LC_TIME",
        3 => b"LC_COLLATE",
        4 => b"LC_MONETARY",
        5 => b"LC_MESSAGES/SYS_LC_MESSAGES",
        7 => b"LC_PAPER",
        8 => b"LC_NAME",
        9 => b"LC_ADDRESS",
        10 => b"LC_TELEPHONE",
        11 => b"LC_MEASUREMENT",
        12 => b"LC_IDENTIFICATION",
        _ => return None,
    })
}

/// Load one category of locale `name`, as glibc does: with `LOCPATH` set,
/// only its directories; otherwise the locale archive, then the unpacked
/// `/usr/lib/locale/<name>/` directory. Each source is tried with the name
/// as given and with its codeset normalized (`en_US.UTF-8` -> `en_US.utf8`).
fn load_category(category: c_int, name: &[u8]) -> Option<&'static NamedCategory> {
    if name.contains(&b'/') || name == b"." || name == b".." {
        return None;
    }
    let mut loaded = LOADED.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(hit) = loaded
        .iter()
        .find(|n| n.category == category && n.name[..n.name.len() - 1] == *name)
    {
        return Some(hit);
    }
    let file = category_file(category)?;
    let locpath = std::env::var_os("LOCPATH").filter(|v| !v.is_empty());
    let mut blob = None;
    'search: for candidate in name_candidates(name) {
        let dirs: Vec<Vec<u8>> = match &locpath {
            Some(paths) => paths
                .as_bytes()
                .split(|&b| b == b':')
                .filter(|d| !d.is_empty())
                .map(<[u8]>::to_vec)
                .collect(),
            None => {
                if let Some(archive) = locale_archive()
                    && let Some(blobs) = archive.find(&candidate)
                    && let Some(b) = blobs[category as usize]
                {
                    blob = Some(b);
                    break 'search;
                }
                vec![b"/usr/lib/locale".to_vec()]
            }
        };
        for dir in dirs {
            let mut path = dir;
            path.push(b'/');
            path.extend_from_slice(&candidate);
            path.push(b'/');
            path.extend_from_slice(file);
            if let Some(bytes) = map_file(&path)
                && let Some(b) = CategoryBlob::parse(category as usize, bytes)
            {
                blob = Some(b);
                break 'search;
            }
        }
    }
    let mut stored = name.to_vec();
    stored.push(0);
    let blob = blob?;
    let ctype = if category == locale_core::LC_CTYPE {
        frankenlibc_core::locale::data::CtypeTables::from_blob(&blob)
    } else {
        None
    };
    let entry: &'static NamedCategory = Box::leak(Box::new(NamedCategory {
        category,
        name: stored.into_boxed_slice(),
        blob,
        ctype,
    }));
    loaded.push(entry);
    Some(entry)
}

/// What a requested locale name selects for one category.
#[derive(Clone, Copy)]
enum Resolved {
    Builtin(Charset),
    Named(&'static NamedCategory),
}

fn resolve_category(category: c_int, name: &[u8]) -> Option<Resolved> {
    if let Some(charset) = charset_for_request(name) {
        return Some(Resolved::Builtin(charset));
    }
    load_category(category, name).map(Resolved::Named)
}

/// The codec a named LC_CTYPE implies.
fn named_charset(n: &NamedCategory) -> Charset {
    // CODESET is LC_CTYPE item 14.
    match n.blob.string(14) {
        Some(cs) if cs.eq_ignore_ascii_case(b"UTF-8") => Charset::Utf8,
        _ => Charset::Ascii,
    }
}

fn apply_category(category: c_int, resolved: Resolved) {
    let Some(slot) = locale_core::category_slot(category) else {
        return;
    };
    match resolved {
        Resolved::Builtin(charset) => {
            NAMED[slot].store(std::ptr::null_mut(), Ordering::Release);
            set_category_charset(category, charset);
            if category == locale_core::LC_CTYPE {
                let tables = match charset {
                    Charset::Ascii => std::ptr::null_mut(),
                    Charset::Utf8 => c_utf8_ctype_tables(),
                };
                CTYPE_TABLES.store(tables, Ordering::Release);
            }
        }
        Resolved::Named(n) => {
            NAMED[slot].store((n as *const NamedCategory).cast_mut(), Ordering::Release);
            NAMED_ANY.store(true, Ordering::Release);
            let charset = if category == locale_core::LC_CTYPE {
                named_charset(n)
            } else {
                Charset::Ascii
            };
            set_category_charset(category, charset);
            if category == locale_core::LC_CTYPE {
                let tables = n.ctype.as_ref().map_or(std::ptr::null_mut(), |t| {
                    (t as *const frankenlibc_core::locale::data::CtypeTables<'static>).cast_mut()
                });
                CTYPE_TABLES.store(tables, Ordering::Release);
            }
            if category == locale_core::LC_CTYPE
                && let Some(off) = n.blob.offset(14)
            {
                ACTIVE_CODESET_PTR.store(
                    n.blob.bytes()[off..].as_ptr().cast::<c_char>().cast_mut(),
                    Ordering::Release,
                );
            }
        }
    }
}

/// The name `setlocale` reports for one category.
fn category_name(category: c_int) -> &'static [u8] {
    match named(category) {
        Some(n) => &n.name,
        None => locale_name_for(category_charset(category)),
    }
}

/// The environment's locale name for one category: `LC_ALL`, then the
/// category's own variable, then `LANG`, then `"C"`; empty values don't count.
fn env_name_for_category(category: c_int) -> Vec<u8> {
    fn var(name: &str) -> Option<Vec<u8>> {
        let value = std::env::var_os(name)?;
        let bytes = value.as_os_str().as_bytes().to_vec();
        if bytes.is_empty() { None } else { Some(bytes) }
    }
    let specific = locale_core::COMPOSITE_ORDER
        .iter()
        .find(|(_, cat)| *cat == category)
        .map(|(name, _)| *name);
    var("LC_ALL")
        .or_else(|| specific.and_then(var))
        .or_else(|| var("LANG"))
        .unwrap_or_else(|| b"C".to_vec())
}

/// Parse glibc's `LC_CTYPE=..;LC_NUMERIC=..;...` composite name into one
/// name per category (in `COMPOSITE_ORDER` slots), or `None` if malformed.
fn parse_composite(name: &[u8]) -> Option<Vec<(c_int, Vec<u8>)>> {
    let mut out = Vec::new();
    for field in name.split(|&b| b == b';') {
        let eq = field.iter().position(|&b| b == b'=')?;
        let (key, value) = (&field[..eq], &field[eq + 1..]);
        let (_, cat) = locale_core::COMPOSITE_ORDER
            .iter()
            .find(|(n, _)| n.as_bytes() == key)?;
        if value.is_empty() {
            return None;
        }
        out.push((*cat, value.to_vec()));
    }
    (!out.is_empty()).then_some(out)
}

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
/// Bootstrap supports one UTF-8 C locale. Querying (null `locale` pointer)
/// returns its canonical `C.UTF-8` name. The conventional "C"/"POSIX" names
/// are accepted as aliases; other names fail with `ENOENT` in strict mode.
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
        unsafe { set_abi_errno(libc::EINVAL) };
        runtime_policy::observe(ApiFamily::Locale, decision.profile, 5, true);
        return std::ptr::null();
    }

    // Query mode: locale is NULL. Reports what THIS CATEGORY is set to, and for
    // `LC_ALL` either the shared name or glibc's composite string when the
    // categories disagree.
    if locale.is_null() {
        runtime_policy::observe(ApiFamily::Locale, decision.profile, 5, false);
        return if category == locale_core::LC_ALL {
            lc_all_report()
        } else {
            category_name(category).as_ptr() as *const c_char
        };
    }

    // Parse the locale name with a known-region bound. A non-NUL-terminated
    // pointer must be rejected instead of walking unbounded memory. (bd-z4k96)
    let Some(name) = (unsafe { read_bounded_cstr(locale) }) else {
        runtime_policy::observe(ApiFamily::Locale, decision.profile, 5, true);
        return std::ptr::null();
    };

    // Resolve every affected category first and apply only if all load:
    // glibc leaves the locale untouched when any part of a request fails.
    let requests: Vec<(c_int, Vec<u8>)> = if category == locale_core::LC_ALL {
        if name.is_empty() {
            locale_core::COMPOSITE_ORDER
                .iter()
                .map(|(_, cat)| (*cat, env_name_for_category(*cat)))
                .collect()
        } else if name.contains(&b'=') {
            match parse_composite(&name) {
                Some(fields) => fields,
                None => {
                    unsafe { set_abi_errno(libc::ENOENT) };
                    runtime_policy::observe(ApiFamily::Locale, decision.profile, 8, true);
                    return std::ptr::null();
                }
            }
        } else {
            locale_core::COMPOSITE_ORDER
                .iter()
                .map(|(_, cat)| (*cat, name.clone()))
                .collect()
        }
    } else if name.is_empty() {
        vec![(category, env_name_for_category(category))]
    } else {
        vec![(category, name.clone())]
    };

    let mut resolved = Vec::with_capacity(requests.len());
    for (cat, req) in &requests {
        match resolve_category(*cat, req) {
            Some(r) => resolved.push((*cat, r)),
            None if mode.heals_enabled() => {
                // Hardened: report the current locale instead of failing;
                // an unknown NAME must not re-encode the caller's data.
                runtime_policy::observe(ApiFamily::Locale, decision.profile, 8, true);
                return if category == locale_core::LC_ALL {
                    lc_all_report()
                } else {
                    category_name(category).as_ptr() as *const c_char
                };
            }
            None => {
                unsafe { set_abi_errno(libc::ENOENT) };
                runtime_policy::observe(ApiFamily::Locale, decision.profile, 8, true);
                return std::ptr::null();
            }
        }
    }
    for (cat, r) in resolved {
        apply_category(cat, r);
    }
    runtime_policy::observe(ApiFamily::Locale, decision.profile, 8, false);
    if category == locale_core::LC_ALL {
        lc_all_report()
    } else {
        category_name(category).as_ptr() as *const c_char
    }
}

/// The maximum multibyte width of the ACTIVE conversion codec.
///
/// Both values are measured against host glibc 2.42 rather than reasoned from
/// the encodings: `LC_ALL=C` reports 1, `LC_ALL=C.UTF-8` reports 6. The six is
/// glibc's historical RFC 2279 size and is deliberately larger than the four
/// bytes RFC 3629 can actually need, which is why callers size buffers by this
/// value and not by what `wctomb` emits.
#[inline]
pub(crate) fn mb_cur_max() -> libc::size_t {
    match active_charset() {
        Charset::Ascii => 1,
        Charset::Utf8 => 6,
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
    if let Some(lconv) = named_localeconv() {
        return lconv;
    }
    // Deployed strict mode can only return Allow for Locale, and this
    // input-free entrypoint always returns the same immutable C-locale table.
    // Skip the observation-only policy round trip; hardened mode and tests keep
    // the full path below.
    if runtime_policy::strict_passthrough_active() {
        return &LCONV;
    }
    let (_, decision) = runtime_policy::decide(ApiFamily::Locale, 0, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Locale, decision.profile, 4, true);
        return std::ptr::null();
    }
    runtime_policy::observe(ApiFamily::Locale, decision.profile, 4, false);
    &LCONV
}

/// Collation tables when LC_COLLATE is on a named locale with rules
/// (`None` for byte-order collation, including C and C.UTF-8).
pub(crate) fn named_collate() -> Option<frankenlibc_core::locale::collate::CollateTables<'static>> {
    let n = named(locale_core::LC_COLLATE)?;
    frankenlibc_core::locale::collate::CollateTables::from_blob(&n.blob)
}

/// LC_TIME strings for `strftime` when LC_TIME is on a named locale.
/// Item indices are the LC_TIME `nl_item` offsets (ABDAY_1 = 0 ... T_FMT_AMPM = 43).
pub(crate) fn named_time_locale() -> Option<frankenlibc_core::time::TimeLocale<'static>> {
    let n = named(locale_core::LC_TIME)?;
    let s = |i: usize| n.blob.string(i).unwrap_or(b"");
    Some(frankenlibc_core::time::TimeLocale {
        abday: std::array::from_fn(s),
        day: std::array::from_fn(|i| s(7 + i)),
        abmon: std::array::from_fn(|i| s(14 + i)),
        mon: std::array::from_fn(|i| s(26 + i)),
        am_pm: [s(38), s(39)],
        d_t_fmt: s(40),
        d_fmt: s(41),
        t_fmt: s(42),
        t_fmt_ampm: s(43),
    })
}

/// `localeconv`'s result when LC_NUMERIC or LC_MONETARY is on a named
/// locale. Like glibc, one process-wide struct refilled on each call.
struct NamedLconvCell(std::cell::UnsafeCell<LConv>);
// SAFETY: POSIX makes localeconv's result non-reentrant; concurrent callers
// racing on it is the documented C contract, as in glibc.
unsafe impl Sync for NamedLconvCell {}
static NAMED_LCONV: NamedLconvCell = NamedLconvCell(std::cell::UnsafeCell::new(LConv {
    decimal_point: std::ptr::null(),
    thousands_sep: std::ptr::null(),
    grouping: std::ptr::null(),
    int_curr_symbol: std::ptr::null(),
    currency_symbol: std::ptr::null(),
    mon_decimal_point: std::ptr::null(),
    mon_thousands_sep: std::ptr::null(),
    mon_grouping: std::ptr::null(),
    positive_sign: std::ptr::null(),
    negative_sign: std::ptr::null(),
    int_frac_digits: 127,
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
}));

fn named_localeconv() -> Option<*const LConv> {
    let numeric = named(locale_core::LC_NUMERIC);
    let monetary = named(locale_core::LC_MONETARY);
    if numeric.is_none() && monetary.is_none() {
        return None;
    }
    let string = |n: Option<&'static NamedCategory>, index: usize, c_value: *const c_char| {
        n.and_then(|n| {
            n.blob
                .offset(index)
                .map(|off| n.blob.bytes()[off..].as_ptr().cast::<c_char>())
        })
        .unwrap_or(c_value)
    };
    // A grouping of CHAR_MAX (either signedness) means "no grouping": "".
    let grouping = |n: Option<&'static NamedCategory>, index: usize| {
        let p = string(n, index, c"".as_ptr());
        // SAFETY: blob strings are NUL-terminated within the mapping.
        match unsafe { *p.cast::<u8>() } {
            0x7f | 0xff => c"".as_ptr(),
            _ => p,
        }
    };
    let byte = |index: usize| {
        monetary
            .and_then(|n| n.blob.byte(index))
            .map_or(127, |b| b as c_char)
    };
    let c = &LCONV;
    let lconv = LConv {
        decimal_point: string(numeric, 0, c.decimal_point),
        thousands_sep: string(numeric, 1, c.thousands_sep),
        grouping: if numeric.is_some() {
            grouping(numeric, 2)
        } else {
            c.grouping
        },
        int_curr_symbol: string(monetary, 0, c.int_curr_symbol),
        currency_symbol: string(monetary, 1, c.currency_symbol),
        mon_decimal_point: string(monetary, 2, c.mon_decimal_point),
        mon_thousands_sep: string(monetary, 3, c.mon_thousands_sep),
        mon_grouping: if monetary.is_some() {
            grouping(monetary, 4)
        } else {
            c.mon_grouping
        },
        positive_sign: string(monetary, 5, c.positive_sign),
        negative_sign: string(monetary, 6, c.negative_sign),
        int_frac_digits: byte(7),
        frac_digits: byte(8),
        p_cs_precedes: byte(9),
        p_sep_by_space: byte(10),
        n_cs_precedes: byte(11),
        n_sep_by_space: byte(12),
        p_sign_posn: byte(13),
        n_sign_posn: byte(14),
        int_p_cs_precedes: byte(16),
        int_p_sep_by_space: byte(17),
        int_n_cs_precedes: byte(18),
        int_n_sep_by_space: byte(19),
        int_p_sign_posn: byte(20),
        int_n_sign_posn: byte(21),
    };
    // SAFETY: see NamedLconvCell.
    unsafe { *NAMED_LCONV.0.get() = lconv };
    Some(NAMED_LCONV.0.get().cast_const())
}

// ---------------------------------------------------------------------------
// nl_langinfo
// ---------------------------------------------------------------------------

/// The `nl_langinfo` table for a given character set.
///
/// Only `CODESET` varies: every other item in the POSIX C locale is identical
/// between `C` and `C.UTF-8` (both are the unlocalised English set), which is
/// why the parameter threads through to exactly one arm.

#[repr(transparent)]
struct PtrTable<const N: usize>([*const c_char; N]);
unsafe impl<const N: usize> Sync for PtrTable<N> {}

/// All 50 contiguous LC_TIME string items (offsets 0..=49 from `libc::ABDAY_1`).
///
/// In glibc, LC_TIME category enumerators start at `_NL_ITEM(__LC_TIME, 0)` (`ABDAY_1`, 131072)
/// and run contiguously through `_NL_ITEM(__LC_TIME, 49)` (`ERA_T_FMT`, 131121).
/// Storing direct `*const c_char` pointers avoids fat slice `&[u8]` overhead and branch misprediction.
static LC_TIME_C_TABLE: PtrTable<50> = PtrTable([
    // ABDAY_1..=ABDAY_7 — offsets 0..=6
    c"Sun".as_ptr(),
    c"Mon".as_ptr(),
    c"Tue".as_ptr(),
    c"Wed".as_ptr(),
    c"Thu".as_ptr(),
    c"Fri".as_ptr(),
    c"Sat".as_ptr(),
    // DAY_1..=DAY_7 — offsets 7..=13
    c"Sunday".as_ptr(),
    c"Monday".as_ptr(),
    c"Tuesday".as_ptr(),
    c"Wednesday".as_ptr(),
    c"Thursday".as_ptr(),
    c"Friday".as_ptr(),
    c"Saturday".as_ptr(),
    // ABMON_1..=ABMON_12 — offsets 14..=25
    c"Jan".as_ptr(),
    c"Feb".as_ptr(),
    c"Mar".as_ptr(),
    c"Apr".as_ptr(),
    c"May".as_ptr(),
    c"Jun".as_ptr(),
    c"Jul".as_ptr(),
    c"Aug".as_ptr(),
    c"Sep".as_ptr(),
    c"Oct".as_ptr(),
    c"Nov".as_ptr(),
    c"Dec".as_ptr(),
    // MON_1..=MON_12 — offsets 26..=37
    c"January".as_ptr(),
    c"February".as_ptr(),
    c"March".as_ptr(),
    c"April".as_ptr(),
    c"May".as_ptr(),
    c"June".as_ptr(),
    c"July".as_ptr(),
    c"August".as_ptr(),
    c"September".as_ptr(),
    c"October".as_ptr(),
    c"November".as_ptr(),
    c"December".as_ptr(),
    // AM_STR, PM_STR — offsets 38..=39
    c"AM".as_ptr(),
    c"PM".as_ptr(),
    // D_T_FMT, D_FMT, T_FMT, T_FMT_AMPM — offsets 40..=43
    c"%a %b %e %H:%M:%S %Y".as_ptr(),
    c"%m/%d/%y".as_ptr(),
    c"%H:%M:%S".as_ptr(),
    c"%I:%M:%S %p".as_ptr(),
    // ERA, __ERA_YEAR, ERA_D_FMT, ALT_DIGITS, ERA_D_T_FMT, ERA_T_FMT — offsets 44..=49
    c"".as_ptr(),
    c"".as_ptr(),
    c"".as_ptr(),
    c"".as_ptr(),
    c"".as_ptr(),
    c"".as_ptr(),
]);

// Compile-time offset assertions for the table above.
const _: () = assert!(libc::DAY_1 - libc::ABDAY_1 == 7);
const _: () = assert!(libc::DAY_7 - libc::ABDAY_1 == 13);
const _: () = assert!(libc::ABMON_1 - libc::ABDAY_1 == 14);
const _: () = assert!(libc::ABMON_12 - libc::ABDAY_1 == 25);
const _: () = assert!(libc::MON_1 - libc::ABDAY_1 == 26);
const _: () = assert!(libc::MON_12 - libc::ABDAY_1 == 37);
const _: () = assert!(libc::AM_STR - libc::ABDAY_1 == 38);
const _: () = assert!(libc::PM_STR - libc::ABDAY_1 == 39);
const _: () = assert!(libc::D_T_FMT - libc::ABDAY_1 == 40);
const _: () = assert!(libc::D_FMT - libc::ABDAY_1 == 41);
const _: () = assert!(libc::T_FMT - libc::ABDAY_1 == 42);
const _: () = assert!(libc::T_FMT_AMPM - libc::ABDAY_1 == 43);
const _: () = assert!(libc::ERA - libc::ABDAY_1 == 44);
const _: () = assert!(libc::ERA_D_FMT - libc::ABDAY_1 == 46);
const _: () = assert!(libc::ALT_DIGITS - libc::ABDAY_1 == 47);
const _: () = assert!(libc::ERA_D_T_FMT - libc::ABDAY_1 == 48);
const _: () = assert!(libc::ERA_T_FMT - libc::ABDAY_1 == 49);

const _: () = assert!(libc::CODESET == 14);
const _: () = assert!(libc::RADIXCHAR == 65536);
const _: () = assert!(libc::THOUSEP == 65537);
const _: () = assert!(libc::YESEXPR == 327680);
const _: () = assert!(libc::NOEXPR == 327681);
const _: () = assert!(libc::CRNCYSTR == 262159);
const _: () = assert!(libc::CRNCYSTR - (4 << 16) == 15);
const _: () = assert!(libc::RADIXCHAR - (1 << 16) == 0);
const _: () = assert!(libc::THOUSEP - (1 << 16) == 1);
const _: () = assert!(libc::YESEXPR - (5 << 16) == 0);
const _: () = assert!(libc::NOEXPR - (5 << 16) == 1);

static LC_NUMERIC_TABLE: PtrTable<2> = PtrTable([c".".as_ptr(), c"".as_ptr()]);

static LC_MONETARY_TABLE: PtrTable<9> = PtrTable([
    c"\xff".as_ptr(),
    c"\xff".as_ptr(),
    c"\xff".as_ptr(),
    c"\xff".as_ptr(),
    c"\xff".as_ptr(),
    c"\xff".as_ptr(),
    c"\xff".as_ptr(),
    c"\xff".as_ptr(),
    c"-".as_ptr(),
]);

static LC_MESSAGES_TABLE: PtrTable<2> = PtrTable([c"^[yY]".as_ptr(), c"^[nN]".as_ptr()]);

#[inline(always)]
fn codeset_ptr(charset: Charset) -> *const c_char {
    match charset {
        Charset::Ascii => C_LOCALE_CODESET.as_ptr() as *const c_char,
        Charset::Utf8 => UTF8_LOCALE_CODESET.as_ptr() as *const c_char,
    }
}

#[inline(always)]
fn langinfo_non_time_non_codeset(item: libc::nl_item) -> *const c_char {
    let category = (item as u32) >> 16;
    let index = ((item as u32) & 0xffff) as usize;
    match category {
        1 => {
            if index < 2 {
                // SAFETY: index is bounds-checked < 2.
                return unsafe { *LC_NUMERIC_TABLE.0.get_unchecked(index) };
            }
        }
        4 => {
            let offset = index.wrapping_sub(7);
            if offset < 9 {
                // SAFETY: offset is bounds-checked < 9.
                return unsafe { *LC_MONETARY_TABLE.0.get_unchecked(offset) };
            }
        }
        5 => {
            if index < 2 {
                // SAFETY: index is bounds-checked < 2.
                return unsafe { *LC_MESSAGES_TABLE.0.get_unchecked(index) };
            }
        }
        _ => {}
    }
    c"".as_ptr()
}

#[inline(always)]
fn langinfo_c_fast(item: libc::nl_item, charset: Charset) -> *const c_char {
    let offset = item.wrapping_sub(libc::ABDAY_1) as usize;
    if offset < 50 {
        // SAFETY: offset is bounds-checked < 50.
        return unsafe { *LC_TIME_C_TABLE.0.get_unchecked(offset) };
    }
    if item == libc::CODESET {
        return codeset_ptr(charset);
    }
    langinfo_non_time_non_codeset(item)
}

#[inline]
fn langinfo_value_for(charset: Charset, item: libc::nl_item) -> &'static [u8] {
    let ptr = langinfo_c_fast(item, charset);
    // SAFETY: every pointer returned by langinfo_c_fast is a static NUL-terminated C string literal.
    unsafe { std::ffi::CStr::from_ptr(ptr).to_bytes_with_nul() }
}

#[cold]
#[inline(never)]
fn nl_langinfo_with_policy(item: libc::nl_item) -> *const c_char {
    let (_, decision) = runtime_policy::decide(ApiFamily::Locale, item as usize, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Locale, decision.profile, 6, true);
        return std::ptr::null();
    }

    let value = langinfo_c_fast(item, active_charset());
    runtime_policy::observe(ApiFamily::Locale, decision.profile, 6, false);
    value
}

/// `nl_langinfo` for a category on a named locale: the item straight from
/// the compiled blob (`""` for an index the blob does not have).
#[inline(always)]
fn named_langinfo(item: libc::nl_item) -> Option<*const c_char> {
    let n = named(((item as u32) >> 16) as c_int)?;
    let index = ((item as u32) & 0xffff) as usize;
    Some(match n.blob.offset(index) {
        Some(off) => n.blob.bytes()[off..].as_ptr().cast::<c_char>(),
        None => c"".as_ptr(),
    })
}

#[inline(always)]
fn active_codeset_ptr() -> *const c_char {
    ACTIVE_CODESET_PTR.load(Ordering::Acquire)
}

/// POSIX `nl_langinfo`.
///
/// `CODESET` follows the active locale (`ANSI_X3.4-1968` under `C`, `UTF-8`
/// under `C.UTF-8`); `RADIXCHAR` is `"."` and `THOUSEP` is `""` in both, as in
/// glibc's C locale. Unsupported items return `""`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nl_langinfo(item: libc::nl_item) -> *const c_char {
    if let Some(value) = named_langinfo(item) {
        return value;
    }
    // Strict mode cannot repair or deny this scalar selector, and every result
    // points into the immutable C-locale table. LC_TIME selectors (offsets 0..=49)
    // and non-CODESET items are charset-independent, avoiding an Acquire load
    // on ACTIVE_CHARSET. Hardened mode and tests retain the full policy path.
    if runtime_policy::strict_passthrough_active() {
        let offset = item.wrapping_sub(libc::ABDAY_1) as usize;
        if offset < 50 {
            // SAFETY: offset is bounds-checked < 50.
            return unsafe { *LC_TIME_C_TABLE.0.get_unchecked(offset) };
        }
        if item == libc::CODESET {
            return active_codeset_ptr();
        }
        return langinfo_non_time_non_codeset(item);
    }
    nl_langinfo_with_policy(item)
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
/// Lock-free publication point for the current text domain.
///
/// Writers allocate an immutable `CString`, retain it permanently in
/// `TextDomainState::pool`, then publish its pointer with `Release`. Readers
/// acquire that pointer without taking the writer mutex. Because published
/// allocations are never reclaimed, a concurrent or later query cannot
/// observe a dangling pointer.
static TEXT_DOMAIN_CURRENT: AtomicPtr<c_char> =
    AtomicPtr::new(DEFAULT_TEXT_DOMAIN.as_ptr() as *mut c_char);
/// Default locale directory.
static DEFAULT_LOCALE_DIR: &[u8] = b"/usr/share/locale\0";

struct TextDomainState {
    pool: Vec<CString>,
}

struct LocaleDirState {
    current_by_domain: ArtifactHashMap<Vec<u8>, *mut c_char>,
    pool: Vec<CString>,
}

// SAFETY: access is synchronized via the surrounding Mutex, and the raw
// pointers refer either to static storage or heap allocations owned by `pool`.
unsafe impl Send for LocaleDirState {}

fn text_domain_storage() -> &'static Mutex<TextDomainState> {
    static STORAGE: OnceLock<Mutex<TextDomainState>> = OnceLock::new();
    STORAGE.get_or_init(|| Mutex::new(TextDomainState { pool: Vec::new() }))
}

fn locale_dir_bindings() -> &'static Mutex<LocaleDirState> {
    static STORAGE: OnceLock<Mutex<LocaleDirState>> = OnceLock::new();
    STORAGE.get_or_init(|| {
        Mutex::new(LocaleDirState {
            current_by_domain: artifact_hash_map(),
            pool: Vec::new(),
        })
    })
}

/// Test hook: reset process-global gettext domain state for deterministic
/// integration tests that exercise `textdomain`/`bindtextdomain`.
#[doc(hidden)]
pub fn locale_reset_gettext_state_for_tests() {
    let _domains = text_domain_storage()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    TEXT_DOMAIN_CURRENT.store(
        DEFAULT_TEXT_DOMAIN.as_ptr() as *mut c_char,
        Ordering::Release,
    );

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
    if domainname.is_null() {
        return TEXT_DOMAIN_CURRENT.load(Ordering::Acquire);
    }
    // Read the domain name through the bounded helper so a non-NUL-terminated
    // pointer cannot walk arbitrary memory, and the empty-string path is
    // discovered from the bounded bytes rather than a raw dereference of the
    // first byte. (bd-z4k96)
    let Some(name) = (unsafe { read_bounded_cstr(domainname) }) else {
        return TEXT_DOMAIN_CURRENT.load(Ordering::Acquire);
    };
    let storage = text_domain_storage();
    let mut state = storage.lock().unwrap_or_else(|e| e.into_inner());
    if name.is_empty() {
        let default = DEFAULT_TEXT_DOMAIN.as_ptr() as *mut c_char;
        TEXT_DOMAIN_CURRENT.store(default, Ordering::Release);
        return default;
    }
    let Ok(owned) = CString::new(name) else {
        return TEXT_DOMAIN_CURRENT.load(Ordering::Acquire);
    };
    let ptr = owned.as_ptr() as *mut c_char;
    state.pool.push(owned);
    TEXT_DOMAIN_CURRENT.store(ptr, Ordering::Release);
    ptr
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
    // Bound both inputs to prevent unbounded memory walks via CStr::from_ptr
    // when a caller passes a non-NUL-terminated pointer. (bd-z4k96)
    let Some(domain) = (unsafe { read_bounded_cstr(domainname) }) else {
        return std::ptr::null_mut();
    };
    if domain.is_empty() {
        return std::ptr::null_mut();
    }
    let storage = locale_dir_bindings();
    let mut bindings = storage.lock().unwrap_or_else(|e| e.into_inner());

    if dirname.is_null() {
        if let Some(bound) = bindings.current_by_domain.get(&domain) {
            *bound
        } else {
            DEFAULT_LOCALE_DIR.as_ptr() as *mut c_char
        }
    } else {
        let Some(dir) = (unsafe { read_bounded_cstr(dirname) }) else {
            return std::ptr::null_mut();
        };
        let Ok(owned) = CString::new(dir) else {
            return std::ptr::null_mut();
        };
        let ptr = owned.as_ptr() as *mut c_char;
        bindings.pool.push(owned);
        bindings.current_by_domain.insert(domain, ptr);
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

/// Sentinel handles, one per shipped locale.
///
/// There are two because `nl_langinfo_l(CODESET, loc)` has to be able to answer
/// differently for `newlocale(LC_ALL_MASK,"C")` and
/// `newlocale(LC_ALL_MASK,"C.UTF-8")`. A single shared sentinel makes that
/// impossible by construction: the query would have nothing to distinguish. The
/// ADDRESS of each static is the handle, so the two must not be merged by the
/// compiler — each carries a distinct value for that reason.
static C_LOCALE_HANDLE: GlibcLocaleStruct = GlibcLocaleStruct::new(c"C");
/// Sentinel handle for the UTF-8 locale. See [`C_LOCALE_HANDLE`].
static UTF8_LOCALE_HANDLE: GlibcLocaleStruct = GlibcLocaleStruct::new(c"C.UTF-8");

/// glibc's `struct __locale_struct` (locale/xlocale.h), which `locale_t`
/// points at. It is not opaque in practice: libstdc++ builds `ctype<char>`
/// from `__cloc->__ctype_b/__ctype_tolower/__ctype_toupper`, and glibc's own
/// `isalpha_l`-style macros index `__ctype_b` directly. Handing out a pointer
/// to a lone byte made every C++ `istream >> x` dereference garbage
/// (bd-rc0923-epic-eeuy4f.2). `__locales` stays null: fl does not export
/// glibc's per-category `__locale_data` and nothing reachable reads it.
#[repr(C)]
struct GlibcLocaleStruct {
    locales: [*const std::ffi::c_void; 13],
    ctype_b: *const u16,
    ctype_tolower: *const i32,
    ctype_toupper: *const i32,
    names: [*const c_char; 13],
}

// SAFETY: every field points at immutable 'static data.
unsafe impl Sync for GlibcLocaleStruct {}

impl GlibcLocaleStruct {
    const fn new(name: &'static CStr) -> Self {
        Self {
            locales: [std::ptr::null(); 13],
            // glibc tables are indexed from -128, so the public pointer is
            // table + 128 (same convention as __ctype_b_loc).
            ctype_b: (&raw const crate::ctype_abi::CTYPE_B_TABLE)
                .cast::<u16>()
                .wrapping_add(128),
            ctype_tolower: (&raw const crate::ctype_abi::TOLOWER_TABLE)
                .cast::<i32>()
                .wrapping_add(128),
            ctype_toupper: (&raw const crate::ctype_abi::TOUPPER_TABLE)
                .cast::<i32>()
                .wrapping_add(128),
            names: [name.as_ptr(); 13],
        }
    }
}

const VALID_NEWLOCALE_CATEGORY_MASK: c_int = libc::LC_ALL_MASK;

/// Return a pointer to use as the C-locale handle.
#[inline]
fn c_locale_handle() -> LocaleT {
    std::ptr::addr_of!(C_LOCALE_HANDLE) as LocaleT
}

/// The handle representing `charset`.
#[inline]
fn locale_handle_for(charset: Charset) -> LocaleT {
    match charset {
        Charset::Ascii => std::ptr::addr_of!(C_LOCALE_HANDLE) as LocaleT,
        Charset::Utf8 => std::ptr::addr_of!(UTF8_LOCALE_HANDLE) as LocaleT,
    }
}

/// The charset a handle stands for.
///
/// An unrecognised handle — including `LC_GLOBAL_LOCALE` and anything a caller
/// invented — reports the active locale rather than guessing, which is what the
/// `_l` entrypoints did implicitly before there was more than one locale.
#[inline]
fn charset_for_handle(handle: LocaleT) -> Charset {
    if std::ptr::eq(
        handle.cast::<GlibcLocaleStruct>(),
        std::ptr::addr_of!(C_LOCALE_HANDLE),
    ) {
        Charset::Ascii
    } else if std::ptr::eq(
        handle.cast::<GlibcLocaleStruct>(),
        std::ptr::addr_of!(UTF8_LOCALE_HANDLE),
    ) {
        Charset::Utf8
    } else {
        active_charset()
    }
}

/// glibc treats a mask of exactly `1 << LC_ALL` as `LC_ALL_MASK` before its
/// sanity check; only the LC_ALL bit *combined with* other bits is invalid.
/// libstdc++ creates its C locale with `__newlocale(1 << LC_ALL, "C", 0)`, so
/// rejecting the exact form aborts every C++ program at load (bd-rc0923-epic-eeuy4f.2).
#[inline]
fn normalize_newlocale_category_mask(category_mask: c_int) -> c_int {
    if category_mask == 1 << libc::LC_ALL {
        libc::LC_ALL_MASK
    } else {
        category_mask
    }
}

#[inline]
fn valid_newlocale_category_mask(category_mask: c_int) -> bool {
    category_mask >= 0 && (category_mask & !VALID_NEWLOCALE_CATEGORY_MASK) == 0
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

    if !valid_newlocale_category_mask(normalize_newlocale_category_mask(category_mask)) {
        unsafe { set_abi_errno(libc::EINVAL) };
        runtime_policy::observe(ApiFamily::Locale, decision.profile, 6, true);
        return std::ptr::null_mut();
    }

    if locale.is_null() {
        unsafe { set_abi_errno(libc::EINVAL) };
        runtime_policy::observe(ApiFamily::Locale, decision.profile, 6, true);
        return std::ptr::null_mut();
    }

    // Bounded read rejects non-NUL-terminated pointers at the boundary
    // instead of walking memory through CStr::from_ptr. (bd-z4k96)
    let Some(name) = (unsafe { read_bounded_cstr(locale) }) else {
        unsafe { set_abi_errno(libc::EINVAL) };
        runtime_policy::observe(ApiFamily::Locale, decision.profile, 6, true);
        return std::ptr::null_mut();
    };
    let _ = base;

    // Every category in the mask must load, as in glibc; "" is the
    // environment's locale per category. An fl handle carries one codec, so
    // LC_CTYPE (when in the mask) decides it.
    let mask = normalize_newlocale_category_mask(category_mask);
    let mut ctype_charset = None;
    for (_, cat) in locale_core::COMPOSITE_ORDER.iter() {
        if mask & (1 << *cat) == 0 {
            continue;
        }
        let req = if name.is_empty() {
            env_name_for_category(*cat)
        } else {
            name.clone()
        };
        match resolve_category(*cat, &req) {
            Some(resolved) => {
                if *cat == locale_core::LC_CTYPE {
                    ctype_charset = Some(match resolved {
                        Resolved::Builtin(cs) => cs,
                        Resolved::Named(n) => named_charset(n),
                    });
                }
            }
            None if mode.heals_enabled() => {
                runtime_policy::observe(ApiFamily::Locale, decision.profile, 6, true);
                return locale_handle_for(active_charset());
            }
            None => {
                unsafe { set_abi_errno(libc::ENOENT) };
                runtime_policy::observe(ApiFamily::Locale, decision.profile, 6, true);
                return std::ptr::null_mut();
            }
        }
    }
    runtime_policy::observe(ApiFamily::Locale, decision.profile, 6, false);
    locale_handle_for(ctype_charset.unwrap_or_else(active_charset))
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
pub unsafe extern "C" fn duplocale(locale: LocaleT) -> LocaleT {
    // Handles are immutable statics, so a duplicate is the same handle; it
    // must keep the source's charset (libstdc++ clones every locale it uses).
    locale_handle_for(charset_for_handle(locale))
}

/// POSIX `nl_langinfo_l` — locale-aware `nl_langinfo`.
///
/// Answers for the locale the HANDLE names, which is the entire difference
/// between this and `nl_langinfo`: `newlocale(LC_ALL_MASK,"C")` reports
/// `ANSI_X3.4-1968` whether or not the process locale is `C.UTF-8`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nl_langinfo_l(item: libc::nl_item, locale: *mut c_void) -> *const c_char {
    langinfo_c_fast(item, charset_for_handle(locale as LocaleT))
}

// ===========================================================================
// XSI message catalogs — catopen / catgets / catclose
// ===========================================================================

/// nl_catd type — opaque message catalog descriptor.
#[allow(non_camel_case_types)]
pub type nl_catd = isize;

const INVALID_NL_CATD: nl_catd = -1;

use frankenlibc_core::locale::catgets::{
    CatalogParseError, MessageCatalog, parse_catalog_bytes as core_parse_catalog_bytes,
};

struct CatalogRegistry {
    next_id: nl_catd,
    open: ArtifactHashMap<nl_catd, MessageCatalog>,
}

fn catalog_registry() -> &'static Mutex<CatalogRegistry> {
    static STORAGE: OnceLock<Mutex<CatalogRegistry>> = OnceLock::new();
    STORAGE.get_or_init(|| {
        Mutex::new(CatalogRegistry {
            next_id: 1,
            open: artifact_hash_map(),
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

// parse_catalog_bytes / MessageCatalog / catalog_word moved to
// frankenlibc_core::locale::catgets. The abi shim wrapper below maps
// the typed CatalogParseError into the libc::EINVAL errno that the
// previous in-place impl returned.
fn parse_catalog_bytes(bytes: Vec<u8>) -> Result<MessageCatalog, c_int> {
    core_parse_catalog_bytes(bytes).map_err(|_: CatalogParseError| libc::EINVAL)
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

    // Bounded read rejects non-NUL-terminated pointers at the boundary. (bd-z4k96)
    let Some(name_bytes) = (unsafe { read_bounded_cstr(name) }) else {
        unsafe { set_abi_errno(libc::EINVAL) };
        return INVALID_NL_CATD;
    };
    // An empty name is rejected with EINVAL, matching live host glibc 2.43.
    // PROVENANCE OF THIS FLIP-FLOP — read before "fixing" it again:
    //   * 56cbe3fc8: fl rejected "" with EINVAL.
    //   * fb7d7cc03 (bd-rp1e32): glibc-then opened "" and got the kernel's
    //     ENOENT, so fl dropped the special case to match (measured live).
    //   * NOW (bd-7ilguh batch, 2026-09-14): glibc 2.43 rejects "" with
    //     EINVAL up front — the host moved back under us, the same release
    //     that re-cut fromfp. Measured live through the gate's dlsym'd host
    //     arm: catopen("") errno fl=2 (ENOENT via the kernel open) vs
    //     glibc=22 (EINVAL). The lesson of both flips is the same: this
    //     errno is a host-version behavior, and the gate must be the arbiter.
    if name_bytes.is_empty() {
        unsafe { set_abi_errno(libc::EINVAL) };
        return INVALID_NL_CATD;
    }
    let path = std::path::Path::new(std::ffi::OsStr::from_bytes(&name_bytes));
    if path.is_dir() {
        unsafe { set_abi_errno(libc::EINVAL) };
        return INVALID_NL_CATD;
    }
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

    if let Some(offset) = catalog.message_offset(set_id, msg_id) {
        // Construct the *const c_char from the catalog's owned strings
        // blob. The pointer is valid until the descriptor is closed —
        // that's the documented catgets contract.
        catalog.strings[offset..].as_ptr().cast::<c_char>()
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
    use std::ffi::CStr;

    /// A process that has not called `setlocale` is in the `"C"` locale.
    ///
    /// This asserted `C.UTF-8`, which is what fl used to report before
    /// b5aef5e3a deliberately flipped the default to POSIX C to match the
    /// incumbent (bd-1kxrmz). The assertion was left pinning the value that
    /// commit set out to change, and has been red ever since -- unnoticed
    /// because the abi suite was aborting during the build.
    ///
    /// Measured on this host, from a C program that calls nothing first:
    ///     setlocale(LC_ALL, NULL) == "C"
    ///     nl_langinfo(CODESET)    == "ANSI_X3.4-1968"
    ///     MB_CUR_MAX              == 1
    #[test]
    fn setlocale_query_at_startup_returns_posix_c() {
        // SAFETY: Null locale means query mode.
        let result = unsafe { setlocale(locale_core::LC_ALL, std::ptr::null()) };
        assert!(!result.is_null());
        let name = unsafe { CStr::from_ptr(result) }.to_bytes();
        assert_eq!(
            name, b"C",
            "a program that never calls setlocale is in the C locale, as glibc reports"
        );
    }

    #[test]
    fn setlocale_invalid_category_sets_einval() {
        let c_name = b"C\0";
        unsafe { set_abi_errno(0) };
        // SAFETY: The locale string is NUL-terminated; the category is invalid.
        let result = unsafe { setlocale(-1, c_name.as_ptr() as *const c_char) };
        assert!(result.is_null());
        assert_eq!(
            unsafe { *crate::errno_abi::__errno_location() },
            libc::EINVAL
        );
    }

    #[test]
    fn setlocale_unavailable_locale_sets_enoent() {
        let missing = b"frankenlibc.definitely_missing.UTF-8\0";
        unsafe { set_abi_errno(0) };
        // SAFETY: The locale string is NUL-terminated and names an unavailable locale.
        let result = unsafe { setlocale(locale_core::LC_ALL, missing.as_ptr() as *const c_char) };
        assert!(result.is_null());
        assert_eq!(
            unsafe { *crate::errno_abi::__errno_location() },
            libc::ENOENT
        );
    }

    #[test]
    fn localeconv_returns_c_locale() {
        // SAFETY: No arguments.
        let conv = unsafe { localeconv() };
        assert!(!conv.is_null());
        let dp = unsafe { CStr::from_ptr((*conv).decimal_point) };
        assert_eq!(dp.to_bytes(), b".");
    }

    /// `CODESET` in the startup locale is glibc's ASCII name, not UTF-8.
    ///
    /// Stale for the same reason as `setlocale_query_at_startup_returns_posix_c`
    /// above: it pins fl's pre-b5aef5e3a default. glibc on this host reports
    /// `ANSI_X3.4-1968` from a fresh process, and the whole point of that commit
    /// was to agree with it.
    #[test]
    fn nl_langinfo_codeset_at_startup_is_ascii() {
        // SAFETY: CODESET is a valid item.
        let result = unsafe { nl_langinfo(libc::CODESET) };
        assert!(!result.is_null());
        let val = unsafe { CStr::from_ptr(result) };
        assert_eq!(
            val.to_bytes(),
            b"ANSI_X3.4-1968",
            "the C locale's codeset is glibc's ASCII name"
        );
    }

    #[test]
    fn nl_langinfo_crncystr_returns_dash() {
        // glibc C locale returns "-" for CRNCYSTR (currency precedes negative amounts).
        let result = unsafe { nl_langinfo(libc::CRNCYSTR) };
        assert!(!result.is_null());
        let val = unsafe { CStr::from_ptr(result) };
        assert_eq!(val.to_bytes(), b"-");
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
    fn newlocale_rejects_lc_all_category_bit() {
        let c_name = b"C\0";
        let invalid_mask = libc::LC_ALL_MASK | (1 << libc::LC_ALL);
        unsafe { set_abi_errno(0) };
        // SAFETY: Valid C-locale name with an invalid category-mask bit.
        let loc = unsafe {
            newlocale(
                invalid_mask,
                c_name.as_ptr() as *const c_char,
                std::ptr::null_mut(),
            )
        };
        assert!(loc.is_null());
        assert_eq!(
            unsafe { *crate::errno_abi::__errno_location() },
            libc::EINVAL
        );
    }

    #[test]
    fn newlocale_accepts_exact_lc_all_bit_as_all_mask() {
        // glibc normalizes a mask of exactly `1 << LC_ALL` to LC_ALL_MASK;
        // libstdc++'s static init depends on it.
        for name in [&b"C\0"[..], b"POSIX\0", b"C.UTF-8\0"] {
            // SAFETY: NUL-terminated locale name, null base.
            let loc = unsafe {
                newlocale(
                    1 << libc::LC_ALL,
                    name.as_ptr() as *const c_char,
                    std::ptr::null_mut(),
                )
            };
            assert!(!loc.is_null(), "exact 1<<LC_ALL rejected for {name:?}");
        }
    }

    #[test]
    fn newlocale_null_locale_sets_einval() {
        unsafe { set_abi_errno(0) };
        // SAFETY: Null locale pointer exercises the ABI error path.
        let loc = unsafe { newlocale(libc::LC_ALL_MASK, std::ptr::null(), std::ptr::null_mut()) };
        assert!(loc.is_null());
        assert_eq!(
            unsafe { *crate::errno_abi::__errno_location() },
            libc::EINVAL
        );
    }

    #[test]
    fn newlocale_unavailable_locale_sets_enoent() {
        let missing = b"frankenlibc.definitely_missing.UTF-8\0";
        unsafe { set_abi_errno(0) };
        // SAFETY: The locale string is NUL-terminated and names an unavailable locale.
        let loc = unsafe {
            newlocale(
                libc::LC_ALL_MASK,
                missing.as_ptr() as *const c_char,
                std::ptr::null_mut(),
            )
        };
        assert!(loc.is_null());
        assert_eq!(
            unsafe { *crate::errno_abi::__errno_location() },
            libc::ENOENT
        );
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

    /// `catopen("")` reports ENOENT, not EINVAL.
    ///
    /// This test asserted EINVAL and was named for it, which was fl's ORIGINAL
    /// behaviour (93749b4bb). fb7d7cc03 then fixed fl to match glibc -- an
    /// empty name is a name that does not resolve, not a malformed argument --
    /// and left this test pinning the value it had just corrected. It has been
    /// red ever since, unnoticed because the whole abi suite was aborting
    /// during the build.
    ///
    /// The lesson is the one bd-fix-shipped-ungated records: assert what the
    /// ORACLE produces, and make sure the assertion actually runs.
    #[test]
    fn catopen_empty_name_sets_einval() {
        // Host glibc 2.43 rejects "" with EINVAL up front (measured live
        // through the differential gate's dlsym'd host arm, bd-7ilguh batch).
        // History: 56cbe3fc8 EINVAL -> fb7d7cc03/bd-rp1e32 ENOENT (matching
        // glibc-then) -> EINVAL again now that the host flipped back. The
        // flip-flop itself is documented at the catopen branch; this test
        // pins the CURRENT host contract and the differential gate arbitrates.
        let empty = b"\0";
        unsafe { set_abi_errno(0) };
        // SAFETY: The catalog name pointer is NUL-terminated.
        let catd = unsafe { catopen(empty.as_ptr() as *const c_char, 0) };
        assert_eq!(catd, INVALID_NL_CATD);
        assert_eq!(
            unsafe { *crate::errno_abi::__errno_location() },
            libc::EINVAL,
            "catopen(\"\") must report EINVAL like live glibc 2.43"
        );
    }

    #[test]
    fn catopen_directory_name_sets_einval() {
        let current_dir = b".\0";
        unsafe { set_abi_errno(0) };
        // SAFETY: The catalog name pointer is NUL-terminated.
        let catd = unsafe { catopen(current_dir.as_ptr() as *const c_char, 0) };
        assert_eq!(catd, INVALID_NL_CATD);
        assert_eq!(
            unsafe { *crate::errno_abi::__errno_location() },
            libc::EINVAL
        );
    }
}
