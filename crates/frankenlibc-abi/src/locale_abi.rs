//! ABI layer for `<locale.h>` functions.
//!
//! Bootstrap provides a UTF-8 C locale. `setlocale` accepts the conventional
//! C aliases and canonicalizes them to `C.UTF-8`; `localeconv` retains the
//! C-locale numeric defaults.

use std::ffi::{CString, c_char, c_int, c_void};
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
    match locale_core::category_slot(cat) {
        Some(slot) => ACTIVE_CHARSET[slot].store(encoded, Ordering::Release),
        None => {
            for slot in ACTIVE_CHARSET.iter() {
                slot.store(encoded, Ordering::Release);
            }
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
    let first = decode_charset(ACTIVE_CHARSET[0].load(Ordering::Acquire));
    let uniform = ACTIVE_CHARSET
        .iter()
        .all(|slot| decode_charset(slot.load(Ordering::Acquire)) == first);
    if uniform {
        return locale_name_for(first).as_ptr() as *const c_char;
    }

    let mut buf = COMPOSITE_BUF.lock().unwrap_or_else(|e| e.into_inner());
    buf.clear();
    for (index, (name, cat)) in locale_core::COMPOSITE_ORDER.iter().enumerate() {
        if index > 0 {
            buf.push(b';');
        }
        buf.extend_from_slice(name.as_bytes());
        buf.push(b'=');
        let charset = category_charset(*cat);
        // `locale_name_for` returns a NUL-terminated static; the composite
        // wants the text only.
        let text = locale_name_for(charset);
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
        b"" => Some(Charset::Utf8),
        _ => None,
    }
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
            locale_name_for(category_charset(category)).as_ptr() as *const c_char
        };
    }

    // Parse the locale name with a known-region bound. A non-NUL-terminated
    // pointer must be rejected instead of walking unbounded memory. (bd-z4k96)
    let Some(name) = (unsafe { read_bounded_cstr(locale) }) else {
        runtime_policy::observe(ApiFamily::Locale, decision.profile, 5, true);
        return std::ptr::null();
    };

    if let Some(charset) = charset_for_request(&name) {
        // The selection and the report are one step: whatever name goes back to
        // the caller, CODESET, MB_CUR_MAX and the codec already agree with it.
        // A non-`LC_ALL` category moves ONLY itself, which is the whole point of
        // per-category state — `setlocale(LC_NUMERIC, "C.UTF-8")` must not hand
        // the caller a UTF-8 codec.
        set_category_charset(category, charset);
        runtime_policy::observe(ApiFamily::Locale, decision.profile, 8, false);
        locale_name_for(charset).as_ptr() as *const c_char
    } else if mode.heals_enabled() {
        // Hardened: fall back instead of failing. The active charset is left
        // alone — healing an unknown NAME must not silently re-encode the
        // caller's data underneath it.
        runtime_policy::observe(ApiFamily::Locale, decision.profile, 8, true);
        locale_name_for(category_charset(category)).as_ptr() as *const c_char
    } else {
        unsafe { set_abi_errno(libc::ENOENT) };
        runtime_policy::observe(ApiFamily::Locale, decision.profile, 8, true);
        std::ptr::null()
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

// ---------------------------------------------------------------------------
// nl_langinfo
// ---------------------------------------------------------------------------

/// The `nl_langinfo` table for a given character set.
///
/// Only `CODESET` varies: every other item in the POSIX C locale is identical
/// between `C` and `C.UTF-8` (both are the unlocalised English set), which is
/// why the parameter threads through to exactly one arm.
/// The LC_TIME name block, indexed by `item - ABDAY_1`.
///
/// WHY A TABLE AND NOT MORE MATCH ARMS. `nl_item` is `(category << 16) | index`,
/// so these 38 selectors are a DENSE contiguous run and are exactly the shape the
/// match below lowers to a jump table — one data-dependent indirect branch. A
/// pre-registered discriminator (bd-nl-langinfo-contiguous-table-8dlrhi) measured
/// what that costs: cycling seven selectors drawn from this run costs 3.121x
/// glibc, while cycling seven selectors of the SAME count and cycle length drawn
/// from three different categories costs 1.317x, and a single selector costs
/// 1.182x. Depth in the match was refuted as the cause (0.33% between arms
/// fourteen positions apart) and so was selector count. What is left is this run,
/// and an index has no data-dependent branch to mispredict — which is what glibc
/// does, and why glibc measures flat at 2.34 ns across every one of those cases.
static LC_TIME_NAMES: [&[u8]; 38] = [
    // ABDAY_1..=ABDAY_7 — offsets 0..=6
    b"Sun\0",
    b"Mon\0",
    b"Tue\0",
    b"Wed\0",
    b"Thu\0",
    b"Fri\0",
    b"Sat\0",
    // DAY_1..=DAY_7 — offsets 7..=13
    b"Sunday\0",
    b"Monday\0",
    b"Tuesday\0",
    b"Wednesday\0",
    b"Thursday\0",
    b"Friday\0",
    b"Saturday\0",
    // ABMON_1..=ABMON_12 — offsets 14..=25
    b"Jan\0",
    b"Feb\0",
    b"Mar\0",
    b"Apr\0",
    b"May\0",
    b"Jun\0",
    b"Jul\0",
    b"Aug\0",
    b"Sep\0",
    b"Oct\0",
    b"Nov\0",
    b"Dec\0",
    // MON_1..=MON_12 — offsets 26..=37
    b"January\0",
    b"February\0",
    b"March\0",
    b"April\0",
    b"May\0",
    b"June\0",
    b"July\0",
    b"August\0",
    b"September\0",
    b"October\0",
    b"November\0",
    b"December\0",
];

// The table above is indexed by arithmetic on `nl_item`, so a platform whose
// enumerators are ordered differently would silently return "Wednesday" where
// "Mar" was asked for. These are compile-time, not tests: the `#[cfg(test)]`
// blocks in most of this crate never compile (bd-0z7a1y), so a unit test would be
// no protection at all.
const _: () = assert!(libc::DAY_1 - libc::ABDAY_1 == 7);
const _: () = assert!(libc::ABMON_1 - libc::ABDAY_1 == 14);
const _: () = assert!(libc::MON_1 - libc::ABDAY_1 == 26);
const _: () = assert!(libc::ABDAY_7 - libc::ABDAY_1 == 6);
const _: () = assert!(libc::DAY_7 - libc::ABDAY_1 == 13);
const _: () = assert!(libc::ABMON_12 - libc::ABDAY_1 == 25);
const _: () = assert!(libc::MON_12 - libc::ABDAY_1 == 37);

/// Branch-free lookup for the dense LC_TIME name block.
///
/// Returns `None` for anything outside it, which falls through to the match.
#[inline]
fn lc_time_name(item: libc::nl_item) -> Option<&'static [u8]> {
    let offset = item.wrapping_sub(libc::ABDAY_1);
    usize::try_from(offset)
        .ok()
        .and_then(|offset| LC_TIME_NAMES.get(offset).copied())
}

#[inline]
fn langinfo_value_for(charset: Charset, item: libc::nl_item) -> &'static [u8] {
    // Dense-run fast path FIRST: it is one bounds check and one indexed load, and
    // it covers 38 of this function's 57 arms. The match below is retained
    // unchanged as the reference for everything else, and the differential gate
    // against live glibc covers all 63 supported selectors either way.
    if let Some(value) = lc_time_name(item) {
        return value;
    }
    match item {
        libc::CODESET => codeset_for(charset),
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
        libc::CRNCYSTR => b"-\0", // glibc C locale: "-" (currency precedes, no sign)
        // Char-valued LC_MONETARY items. In the C locale glibc returns a pointer
        // to a single CHAR_MAX byte (0xFF) meaning "unspecified" — mirroring the
        // matching `char` fields of `struct lconv`. fl previously fell through to
        // EMPTY_LOCALE_STR, so a caller read 0 (e.g. "0 fractional digits")
        // instead of the unspecified sentinel.
        // The `libc` crate does not export these nl_item constants. Their codes
        // are eight consecutive LC_MONETARY items _NL_ITEM(__LC_MONETARY, 7..=14):
        //   INT_FRAC_DIGITS=262151, FRAC_DIGITS=262152, P_CS_PRECEDES=262153,
        //   P_SEP_BY_SPACE=262154, N_CS_PRECEDES=262155, N_SEP_BY_SPACE=262156,
        //   P_SIGN_POSN=262157, N_SIGN_POSN=262158.
        262151..=262158 => b"\xff\0",
        _ => EMPTY_LOCALE_STR,
    }
}

#[inline]
fn nl_langinfo_with_policy(item: libc::nl_item) -> *const c_char {
    let (_, decision) = runtime_policy::decide(ApiFamily::Locale, item as usize, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Locale, decision.profile, 6, true);
        return std::ptr::null();
    }

    let value = langinfo_value_for(active_charset(), item);
    runtime_policy::observe(ApiFamily::Locale, decision.profile, 6, false);
    value.as_ptr() as *const c_char
}

/// POSIX `nl_langinfo`.
///
/// `CODESET` follows the active locale (`ANSI_X3.4-1968` under `C`, `UTF-8`
/// under `C.UTF-8`); `RADIXCHAR` is `"."` and `THOUSEP` is `""` in both, as in
/// glibc's C locale. Unsupported items return `""`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nl_langinfo(item: libc::nl_item) -> *const c_char {
    // Strict mode cannot repair or deny this scalar selector, and every result
    // points into the immutable C-locale table above. Hardened mode and tests
    // retain the full policy path.
    if runtime_policy::strict_passthrough_active() {
        return langinfo_value_for(active_charset(), item).as_ptr() as *const c_char;
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
static C_LOCALE_HANDLE: u8 = 0;
/// Sentinel handle for the UTF-8 locale. See [`C_LOCALE_HANDLE`].
static UTF8_LOCALE_HANDLE: u8 = 1;

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
    if std::ptr::eq(handle.cast::<u8>(), std::ptr::addr_of!(C_LOCALE_HANDLE)) {
        Charset::Ascii
    } else if std::ptr::eq(handle.cast::<u8>(), std::ptr::addr_of!(UTF8_LOCALE_HANDLE)) {
        Charset::Utf8
    } else {
        active_charset()
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

    if !valid_newlocale_category_mask(category_mask) {
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

    if let Some(charset) = charset_for_request(&name) {
        runtime_policy::observe(ApiFamily::Locale, decision.profile, 6, false);
        locale_handle_for(charset)
    } else if mode.heals_enabled() {
        runtime_policy::observe(ApiFamily::Locale, decision.profile, 6, true);
        locale_handle_for(active_charset())
    } else {
        unsafe { set_abi_errno(libc::ENOENT) };
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

/// POSIX `nl_langinfo_l` — locale-aware `nl_langinfo`.
///
/// Answers for the locale the HANDLE names, which is the entire difference
/// between this and `nl_langinfo`: `newlocale(LC_ALL_MASK,"C")` reports
/// `ANSI_X3.4-1968` whether or not the process locale is `C.UTF-8`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nl_langinfo_l(item: libc::nl_item, locale: *mut c_void) -> *const c_char {
    langinfo_value_for(charset_for_handle(locale as LocaleT), item).as_ptr() as *const c_char
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
    // An empty name is NOT special-cased. glibc does not reject it up front; it
    // simply tries to open "", and the kernel answers ENOENT. Returning EINVAL
    // here made `catopen("")` report errno 22 where glibc reports 2, which is
    // what the caller branches on. Letting the open below produce the errno is
    // both simpler and what the host actually does.
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
    fn catopen_empty_name_sets_enoent() {
        let empty = b"\0";
        unsafe { set_abi_errno(0) };
        // SAFETY: The catalog name pointer is NUL-terminated.
        let catd = unsafe { catopen(empty.as_ptr() as *const c_char, 0) };
        assert_eq!(catd, INVALID_NL_CATD);
        assert_eq!(
            unsafe { *crate::errno_abi::__errno_location() },
            libc::ENOENT,
            "catopen(\"\") must report ENOENT like glibc (fb7d7cc03, bd-rp1e32)"
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
