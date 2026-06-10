//! Time and date functions.
//!
//! Implements `<time.h>` pure-logic helpers. Actual syscall invocations
//! (`clock_gettime`, etc.) live in the ABI crate; this module provides
//! validators and the `epoch_to_broken_down` converter.

/// Represents a timespec value (seconds + nanoseconds).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Timespec {
    /// Seconds.
    pub tv_sec: i64,
    /// Nanoseconds (0 to 999_999_999).
    pub tv_nsec: i64,
}

/// Clock identifiers for `clock_gettime`.
pub const CLOCK_REALTIME: i32 = 0;
pub const CLOCK_MONOTONIC: i32 = 1;
pub const CLOCK_PROCESS_CPUTIME_ID: i32 = 2;

/// POSIX `CLOCKS_PER_SEC` — microseconds per clock tick.
pub const CLOCKS_PER_SEC: i64 = 1_000_000;

/// Returns `true` if `clock_id` is a known valid clock.
#[inline]
pub fn valid_clock_id(clock_id: i32) -> bool {
    matches!(
        clock_id,
        CLOCK_REALTIME | CLOCK_MONOTONIC | CLOCK_PROCESS_CPUTIME_ID
    )
}

/// Broken-down time representation (like `struct tm`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BrokenDownTime {
    /// Seconds (0-60, 60 for leap second).
    pub tm_sec: i32,
    /// Minutes (0-59).
    pub tm_min: i32,
    /// Hours (0-23).
    pub tm_hour: i32,
    /// Day of month (1-31).
    pub tm_mday: i32,
    /// Month (0-11).
    pub tm_mon: i32,
    /// Years since 1900.
    pub tm_year: i32,
    /// Day of week (0-6, Sunday = 0).
    pub tm_wday: i32,
    /// Day of year (0-365).
    pub tm_yday: i32,
    /// Daylight saving time flag.
    pub tm_isdst: i32,
    /// Seconds east of UTC (glibc `tm_gmtoff`). Used by `strftime` `%z`; fl's
    /// own gmtime/localtime always produce 0 (UTC), but a caller (or `strptime
    /// %z`) may set it and `%z` must honour it, exactly like glibc.
    pub tm_gmtoff: i64,
    /// Timezone-name bytes (glibc `tm_zone`), NUL-padded; `zone[0] == 0` means
    /// "unset". Used by `strftime` `%Z`, which echoes it when present and falls
    /// back to "UTC" (fl's only timezone) otherwise — matching glibc, whose `%Z`
    /// reads tm_zone or the process zone. Only the ABI `strftime` populates it
    /// (from the caller's `tm_zone`); fl's own gmtime/localtime set it on the
    /// `struct tm` instead. A name longer than 15 bytes is truncated.
    pub zone: [u8; 16],
}

/// Returns `true` if `year` is a leap year (Gregorian).
#[inline]
fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

/// Days in each month for a non-leap year. Retained as a public constant
/// for callers in the abi crate that mirror glibc's per-month tables.
#[allow(dead_code)]
const DAYS_IN_MONTH: [i32; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

/// Days from the proleptic Gregorian Unix epoch (1970-01-01) to (year, month, day),
/// where month is 1..=12 and day is 1-based.
///
/// Closed-form O(1) algorithm by Howard Hinnant
/// (<https://howardhinnant.github.io/date_algorithms.html>), which sidesteps
/// the year-walking loop that would spin for billions of iterations on
/// extreme `tm_year` inputs (DoS vector when an attacker controls the
/// broken-down time fed to `mktime`/`timegm`).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    // era is the index of the 400-year cycle the year falls in. Use
    // Euclidean division so negative years bin to the correct era.
    let era = y.div_euclid(400);
    let yoe = y - era * 400; // in [0, 399]
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // in [0, 146096]
    era * 146097 + doe - 719468
}

/// Inverse of [`days_from_civil`]: given days since 1970-01-01, return
/// `(year, month_1based, day)`. Closed-form O(1).
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097; // in [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // in [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // in [0, 365]
    let mp = (5 * doy + 2) / 153; // in [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // in [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // in [1, 12]
    let year = y + (m <= 2) as i64;
    (year, m, d)
}

/// Convert seconds since Unix epoch to broken-down UTC time.
///
/// Handles negative epochs (pre-1970). UTC only — no timezone/DST.
/// Maximum epoch second whose corresponding year still fits a `tm_year`
/// field (which is a `c_int` = i32). Beyond this, a glibc-faithful
/// implementation must return NULL from gmtime/localtime/etc. — and
/// crucially, `epoch_to_broken_down` itself would otherwise spin in a
/// year-walking loop for billions of iterations.
///
/// Computed as: max safe year = i32::MAX + 1900 ≈ 2.147e9, days from
/// epoch ≈ 2.147e9 * 365.2425, seconds ≈ days * 86400 ≈ 6.78e16.
/// We pick a slightly conservative ±6.78e16 as the cutoff.
pub const EPOCH_RANGE_LIMIT: i64 = 67_768_036_191_676_800;

/// Like [`epoch_to_broken_down`] but returns `None` if `epoch_secs` would
/// overflow `tm_year` (matching glibc's NULL-return contract on
/// `gmtime`/`localtime` for extreme inputs).
pub fn epoch_to_broken_down_checked(epoch_secs: i64) -> Option<BrokenDownTime> {
    // glibc returns NULL exactly when the resulting year does not fit `tm_year`
    // (a `c_int`). `civil_from_days` is O(1), so we compute the year directly and
    // check that boundary PRECISELY rather than using the conservative
    // ±EPOCH_RANGE_LIMIT cutoff, which rejected years (e.g. tm_year ≈ -2147483510)
    // that glibc still represents. (Found by gmtime_r_wide_range_differential_fuzz.)
    let days = epoch_secs.div_euclid(86400);
    let (year, _, _) = civil_from_days(days);
    let tm_year = year - 1900;
    if tm_year < i32::MIN as i64 || tm_year > i32::MAX as i64 {
        return None;
    }
    Some(epoch_to_broken_down(epoch_secs))
}

pub fn epoch_to_broken_down(epoch_secs: i64) -> BrokenDownTime {
    // Seconds within the day. Use Euclidean division so negative epochs
    // (pre-1970) round toward -∞ correctly.
    let days = epoch_secs.div_euclid(86400);
    let rem = epoch_secs.rem_euclid(86400);

    let tm_sec = (rem % 60) as i32;
    let tm_min = ((rem / 60) % 60) as i32;
    let tm_hour = (rem / 3600) as i32;

    // Day of week: Jan 1 1970 was Thursday (4). Euclidean mod 7.
    let tm_wday = ((days + 4).rem_euclid(7)) as i32;

    // O(1) civil-from-days for year / month / day.
    let (year, month_1based, day) = civil_from_days(days);
    let mon = (month_1based - 1) as i32;
    // tm_yday = days from Jan 1 of `year` to today.
    let tm_yday = (days - days_from_civil(year, 1, 1)) as i32;

    BrokenDownTime {
        tm_sec,
        tm_min,
        tm_hour,
        tm_mday: day as i32,
        tm_mon: mon,
        tm_year: (year - 1900) as i32,
        tm_wday,
        tm_yday,
        tm_isdst: 0,
        tm_gmtoff: 0, // gmtime/localtime are UTC in fl
        zone: [0; 16],
    }
}

/// Convert broken-down UTC time back to seconds since Unix epoch.
///
/// This is the inverse of `epoch_to_broken_down`. Fields are normalized
/// (e.g. tm_mon=13 rolls into the next year). Only UTC — no timezone.
pub fn broken_down_to_epoch(bd: &BrokenDownTime) -> i64 {
    // Normalize month into [0,11] range, adjusting year.
    let mut year = bd.tm_year as i64 + 1900;
    let mut mon = bd.tm_mon as i64;
    if !(0..=11).contains(&mon) {
        year += mon.div_euclid(12);
        mon = mon.rem_euclid(12);
    }

    // O(1) civil → days closed-form. days_from_civil takes month in 1..=12
    // and day in 1..=31; mon is 0..=11 so we add 1.
    let days = days_from_civil(year, mon + 1, bd.tm_mday as i64);

    days * 86400 + bd.tm_hour as i64 * 3600 + bd.tm_min as i64 * 60 + bd.tm_sec as i64
}

/// Day-of-week abbreviations.
const WDAY_NAMES: [&[u8; 3]; 7] = [b"Sun", b"Mon", b"Tue", b"Wed", b"Thu", b"Fri", b"Sat"];

/// Month abbreviations.
const MON_NAMES: [&[u8; 3]; 12] = [
    b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov", b"Dec",
];

/// Format broken-down time as asctime string: "Day Mon DD HH:MM:SS YYYY\n\0".
///
/// Writes at most `buf_len` bytes into `buf` (including NUL terminator).
/// Returns the number of bytes written (excluding NUL), or 0 on error.
/// The canonical asctime output is exactly 26 bytes: 24 chars + '\n' + '\0'.
pub fn format_asctime(bd: &BrokenDownTime, buf: &mut [u8]) -> usize {
    // Need at least 26 bytes (24 chars + newline + NUL)
    if buf.len() < 26 {
        return 0;
    }

    let wday = bd.tm_wday.rem_euclid(7) as usize;
    let mon = bd.tm_mon.rem_euclid(12) as usize;
    let year = bd.tm_year as i64 + 1900;

    // POSIX/glibc format: `"%.3s %.3s%3d %.2d:%.2d:%.2d %d\n"`. Note the
    // day field is `%3d` (no preceding literal space), so a 3-digit day
    // packs flush against the month name ("Jan100"). Year has no width
    // specifier — single-digit years print as "1", not "   1".
    let s = format!(
        "{} {}{:>3} {:02}:{:02}:{:02} {}\n",
        std::str::from_utf8(WDAY_NAMES[wday]).unwrap_or("???"),
        std::str::from_utf8(MON_NAMES[mon]).unwrap_or("???"),
        bd.tm_mday,
        bd.tm_hour,
        bd.tm_min,
        bd.tm_sec,
        year,
    );

    let bytes = s.as_bytes();
    // glibc's asctime/asctime_r bound the output to the 26-byte contract buffer
    // and return NULL (EOVERFLOW) rather than TRUNCATE when it would not fit —
    // e.g. a year outside [-999, 9999] (a 5+ char "%d") makes the string 26 bytes
    // (27 with NUL). Found by asctime_r_differential_fuzz.
    if bytes.len() + 1 > 26 {
        return 0;
    }
    let copy_len = bytes.len().min(buf.len() - 1);
    buf[..copy_len].copy_from_slice(&bytes[..copy_len]);
    buf[copy_len] = 0;
    copy_len
}

/// POSIX `difftime` — difference in seconds between two `time_t` values.
///
/// Convert to `f64` before subtracting so that full-range i64 inputs
/// (e.g. `i64::MAX - i64::MIN`) do not overflow the integer type. f64
/// has enough dynamic range to represent the difference (with some
/// loss of precision for epochs outside ±2^53) — glibc's difftime
/// behaves the same way (bd-5koo6).
#[inline]
pub fn difftime(time1: i64, time0: i64) -> f64 {
    (time1 as f64) - (time0 as f64)
}

/// Full day-of-week names.
const WDAY_FULL_NAMES: [&str; 7] = [
    "Sunday",
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday",
];

/// Full month names.
const MON_FULL_NAMES: [&str; 12] = [
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
];

/// ISO 8601 week number and year calculation.
///
/// Returns (iso_year, iso_week) where iso_week is 1-53.
///
/// Uses i64 arithmetic throughout because POSIX leaves the BrokenDownTime
/// field ranges undefined (e.g. tm_yday is signed int) and out-of-range
/// inputs from a callers like fuzz harnesses must not overflow i32
/// (bd-7rxtm).
fn iso_week(bd: &BrokenDownTime) -> (i64, i32) {
    let year = bd.tm_year as i64 + 1900;
    let yday = bd.tm_yday as i64;
    // ISO weekday: Monday=1 .. Sunday=7
    let wday_iso = if bd.tm_wday == 0 {
        7i64
    } else {
        bd.tm_wday as i64
    };
    // Day of year of the Thursday in the same ISO week
    let thu_yday = yday - wday_iso + 4;
    // ISO year that Thursday belongs to
    let mut iso_y = year;
    if thu_yday < 0 {
        // Thursday is in previous year
        iso_y -= 1;
        let prev_days: i64 = if is_leap_year(iso_y) { 366 } else { 365 };
        let week = ((thu_yday + prev_days) / 7 + 1) as i32;
        return (iso_y, week);
    }
    let year_days: i64 = if is_leap_year(year) { 366 } else { 365 };
    if thu_yday >= year_days {
        // Thursday is in next year
        iso_y += 1;
        return (iso_y, 1);
    }
    let week = (thu_yday / 7 + 1) as i32;
    (iso_y, week)
}

/// Format broken-down time according to a format string (like POSIX `strftime`).
///
/// Writes formatted output into `buf`. Returns the number of bytes written
/// (excluding the NUL terminator), or 0 if the buffer is too small.
///
/// Supports these conversion specifiers:
/// `%a` abbreviated weekday, `%A` full weekday, `%b`/`%h` abbreviated month,
/// `%B` full month, `%c` preferred date/time, `%C` century, `%d` zero-padded day,
/// `%D` equivalent to `%m/%d/%y`, `%e` space-padded day, `%F` ISO date `%Y-%m-%d`,
/// `%G` ISO year, `%g` ISO year (2-digit), `%H` hour (24h), `%I` hour (12h),
/// `%j` day of year, `%k` space-padded hour (24h), `%l` space-padded hour (12h),
/// `%m` month (01-12), `%M` minute, `%n` newline, `%p` AM/PM, `%P` am/pm,
/// `%r` 12-hour time, `%R` `%H:%M`, `%s` epoch seconds, `%S` second,
/// `%t` tab, `%T` `%H:%M:%S`, `%u` ISO weekday (1-7), `%V` ISO week (01-53),
/// `%w` weekday (0-6), `%W` Monday-based week, `%x` preferred date,
/// `%X` preferred time, `%y` year (2-digit), `%Y` full year, `%z` timezone offset,
/// `%Z` timezone name, `%%` literal percent.
pub fn format_strftime(fmt: &[u8], bd: &BrokenDownTime, buf: &mut [u8]) -> usize {
    let mut pos = 0usize;
    let mut i = 0usize;

    macro_rules! push {
        ($b:expr) => {
            if pos >= buf.len().saturating_sub(1) {
                return 0;
            }
            buf[pos] = $b;
            pos += 1;
        };
    }

    macro_rules! push_str {
        ($s:expr) => {
            for &b in $s {
                push!(b);
            }
        };
    }

    // Padding style for numeric conversions
    #[derive(Clone, Copy)]
    enum Pad {
        Zero,
        Space,
        None,
    }

    // GNU case-transform flags: `^` upper-cases, `#` toggles to the opposite of
    // the field's conventional case (names -> upper, AM/PM & zone -> lower).
    #[derive(Clone, Copy, PartialEq)]
    enum CaseFlag {
        None,
        Upper,
        Swap,
    }

    // glibc accepts the `E`/`O` locale modifier only on a per-specifier subset
    // (probed from host glibc); elsewhere the whole directive renders literally.
    // The set includes the format-control specifiers `%`, `n`, `t` — glibc
    // renders `%E%`/`%O%` as a literal `%`, like `%En`/`%Et` give newline/tab.
    const E_MODIFIABLE: &[u8] = b"%cCnpPrRstTuxXyYzZ";
    const O_MODIFIABLE: &[u8] = b"%bBCdegGhHIjklmMnpPrRsStTuUVwWyzZ";

    // Helper: write decimal with specified padding style and width
    macro_rules! push_dec_pad {
        ($val:expr, $width:expr, $pad:expr) => {{
            let mut tmp = [0u8; 20];
            let v = $val as i64;
            let negative = v < 0;
            let mut uv = if negative { (-v) as u64 } else { v as u64 };
            let mut len = 0usize;
            if uv == 0 {
                tmp[0] = b'0';
                len = 1;
            } else {
                while uv > 0 {
                    tmp[len] = b'0' + (uv % 10) as u8;
                    uv /= 10;
                    len += 1;
                }
            }
            let w: usize = $width;
            let total_len = if negative { len + 1 } else { len };
            match $pad {
                Pad::Zero => {
                    if negative {
                        push!(b'-');
                    }
                    if len < w {
                        for _ in 0..(w - len) {
                            push!(b'0');
                        }
                    }
                }
                Pad::Space => {
                    if total_len < w {
                        for _ in 0..(w - total_len) {
                            push!(b' ');
                        }
                    }
                    if negative {
                        push!(b'-');
                    }
                }
                Pad::None => {
                    if negative {
                        push!(b'-');
                    }
                }
            }
            for j in (0..len).rev() {
                push!(tmp[j]);
            }
        }};
    }


    while i < fmt.len() {
        if fmt[i] != b'%' {
            push!(fmt[i]);
            i += 1;
            continue;
        }
        i += 1; // skip '%'
        if i >= fmt.len() {
            // Trailing '%' with no conversion specifier - output literal '%'
            // to match glibc behavior.
            push!(b'%');
            break;
        }

        // Parse optional modifier flags: '-' (no padding), '_' (space), '0' (zero)
        // Track start position so we can output the literal if incomplete.
        let spec_start = i - 1; // points to the '%'
        let mut pad_override: Option<Pad> = None;
        let mut case_flag = CaseFlag::None;
        loop {
            if i >= fmt.len() {
                break;
            }
            match fmt[i] {
                b'-' => {
                    pad_override = Some(Pad::None);
                    i += 1;
                }
                b'_' => {
                    pad_override = Some(Pad::Space);
                    i += 1;
                }
                b'0' => {
                    pad_override = Some(Pad::Zero);
                    i += 1;
                }
                b'^' => {
                    case_flag = CaseFlag::Upper;
                    i += 1;
                }
                b'#' => {
                    case_flag = CaseFlag::Swap;
                    i += 1;
                }
                _ => break,
            }
        }
        if i >= fmt.len() {
            // Incomplete specifier after flags - output literal (e.g. "%-" → "%-")
            for &b in &fmt[spec_start..] {
                push!(b);
            }
            break;
        }

        // Parse optional explicit width (e.g., %6Y for 6-character zero-padded year)
        let mut width_override: Option<usize> = None;
        while i < fmt.len() && fmt[i].is_ascii_digit() {
            let digit = (fmt[i] - b'0') as usize;
            width_override = Some(width_override.unwrap_or(0) * 10 + digit);
            i += 1;
        }
        if i >= fmt.len() {
            // Incomplete specifier after width - output literal (e.g. "%-5" → "%-5")
            for &b in &fmt[spec_start..] {
                push!(b);
            }
            break;
        }

        // Optional `E`/`O` locale modifier. In the C locale it is a no-op on the
        // specifiers glibc accepts it on; for the rest glibc renders the entire
        // directive (flags/width/modifier/spec) literally, so mirror that.
        if i < fmt.len() && (fmt[i] == b'E' || fmt[i] == b'O') {
            let modifier = fmt[i];
            i += 1;
            if i >= fmt.len() {
                for &b in &fmt[spec_start..] {
                    push!(b);
                }
                break;
            }
            let table = if modifier == b'E' { E_MODIFIABLE } else { O_MODIFIABLE };
            if !table.contains(&fmt[i]) {
                // Rejected combination: emit the literal `%…<mod><spec>`.
                for &b in &fmt[spec_start..=i] {
                    push!(b);
                }
                i += 1;
                continue;
            }
        }

        // Macro to apply the override or use default padding
        macro_rules! push_dec_mod {
            ($val:expr, $width:expr, $default:expr) => {{
                let nat: usize = $width;
                // glibc width/pad model:
                //  * default / `0`: zero-pad; the explicit width is a MINIMUM on
                //    top of the specifier's natural width (`%01m` -> "09").
                //  * `_`: like default but SPACE-padded; the natural width is
                //    still a floor (`%_S` -> " 3", `%_5H` -> "   20").
                //  * `-`: drop the natural floor entirely — with a width,
                //    space-pad to exactly it; with none, no padding at all
                //    (`%-1I` -> "4", `%-I` -> "4").
                let (w, p) = match pad_override {
                    Some(Pad::None) => match width_override {
                        Some(wo) => (wo, Pad::Space),
                        None => (0, Pad::None),
                    },
                    Some(Pad::Space) => (width_override.map_or(nat, |wo| wo.max(nat)), Pad::Space),
                    Some(Pad::Zero) => (width_override.map_or(nat, |wo| wo.max(nat)), Pad::Zero),
                    None => (width_override.map_or(nat, |wo| wo.max(nat)), $default),
                };
                push_dec_pad!($val, w, p);
            }};
        }

        // Emit a string specifier with the GNU case transform + field width.
        // `caret_upper` is whether `^` upper-cases (false for `%P`, whose
        // lowercase form glibc leaves untouched); `hash_upper` selects `#`'s
        // direction (names & %P -> upper, AM/PM & zone -> lower). Width
        // right-justifies, padding with spaces (or zeros only when the explicit
        // `0` flag is present); no padding once wide enough.
        macro_rules! push_str_field {
            ($bytes:expr, $caret_upper:expr, $hash_upper:expr) => {{
                let src: &[u8] = $bytes;
                let fits = width_override.map_or(true, |w| src.len() >= w);
                if case_flag == CaseFlag::None && fits {
                    push_str!(src);
                } else {
                    let mut tmp: Vec<u8> = src.to_vec();
                    match case_flag {
                        CaseFlag::Upper => {
                            if $caret_upper {
                                tmp.make_ascii_uppercase();
                            }
                        }
                        CaseFlag::Swap => {
                            if $hash_upper {
                                tmp.make_ascii_uppercase();
                            } else {
                                tmp.make_ascii_lowercase();
                            }
                        }
                        CaseFlag::None => {}
                    }
                    if let Some(w) = width_override {
                        if tmp.len() < w {
                            let padc =
                                if matches!(pad_override, Some(Pad::Zero)) { b'0' } else { b' ' };
                            for _ in 0..(w - tmp.len()) {
                                push!(padc);
                            }
                        }
                    }
                    push_str!(&tmp);
                }
            }};
        }

        // Emit a COMPOSITE specifier (%c %r %D %F %R %T %x %X) by recursively
        // rendering its C-locale expansion, then applying the OUTER field width
        // and case flags to the whole result (glibc: width right-justifies and
        // pads with spaces, or zeros with the `0` flag; `^` upper-cases the whole
        // expansion; `#` is a no-op on composites). The sub-format has no flags,
        // so its bytes are identical to the previous inline rendering when no
        // outer flag/width is present.
        macro_rules! push_composite {
            ($sub:expr) => {{
                let mut scratch = [0u8; 256];
                let n = format_strftime($sub, bd, &mut scratch);
                let src: &[u8] = &scratch[..n];
                let needs_case = case_flag == CaseFlag::Upper; // `#` no-ops here
                let fits = width_override.map_or(true, |w| src.len() >= w);
                if !needs_case && fits {
                    push_str!(src);
                } else {
                    let mut tmp: Vec<u8> = src.to_vec();
                    if needs_case {
                        tmp.make_ascii_uppercase();
                    }
                    if let Some(w) = width_override {
                        if tmp.len() < w {
                            let padc =
                                if matches!(pad_override, Some(Pad::Zero)) { b'0' } else { b' ' };
                            for _ in 0..(w - tmp.len()) {
                                push!(padc);
                            }
                        }
                    }
                    push_str!(&tmp);
                }
            }};
        }

        match fmt[i] {
            b'a' => {
                let wday = bd.tm_wday.rem_euclid(7) as usize;
                push_str_field!(WDAY_NAMES[wday], true, true);
            }
            b'A' => {
                let wday = bd.tm_wday.rem_euclid(7) as usize;
                push_str_field!(WDAY_FULL_NAMES[wday].as_bytes(), true, true);
            }
            b'b' | b'h' => {
                let mon = bd.tm_mon.rem_euclid(12) as usize;
                push_str_field!(MON_NAMES[mon], true, true);
            }
            b'B' => {
                let mon = bd.tm_mon.rem_euclid(12) as usize;
                push_str_field!(MON_FULL_NAMES[mon].as_bytes(), true, true);
            }
            b'c' => {
                // Preferred date/time, C locale: "%a %b %e %H:%M:%S %Y".
                push_composite!(b"%a %b %e %H:%M:%S %Y");
            }
            b'C' => {
                // %C is the bare-decimal century (year / 100). glibc uses
                // `%d` with no width: year 0 → "0", year 200 → "2",
                // year 99999 → "999". The division floors toward negative
                // infinity (glibc behavior), so year -50 → -1 and year
                // -101 → -2; this keeps %C consistent with %y (which uses a
                // positive 0–99 modulus) so %C%y reconstructs negative years.
                let century = (bd.tm_year as i64 + 1900).div_euclid(100);
                push_dec_mod!(century, 0, Pad::Zero);
            }
            b'd' => {
                push_dec_mod!(bd.tm_mday, 2, Pad::Zero);
            }
            b'D' => {
                push_composite!(b"%m/%d/%y");
            }
            b'e' => {
                push_dec_mod!(bd.tm_mday, 2, Pad::Space);
            }
            b'F' => {
                push_composite!(b"%Y-%m-%d");
            }
            b'G' => {
                let (iso_y, _) = iso_week(bd);
                push_dec_mod!(iso_y, 0, Pad::Zero);
            }
            b'g' => {
                let (iso_y, _) = iso_week(bd);
                push_dec_mod!(iso_y.rem_euclid(100), 2, Pad::Zero);
            }
            b'H' => {
                push_dec_mod!(bd.tm_hour, 2, Pad::Zero);
            }
            b'I' => {
                let h = bd.tm_hour % 12;
                push_dec_mod!(if h == 0 { 12 } else { h }, 2, Pad::Zero);
            }
            b'j' => {
                push_dec_mod!(bd.tm_yday as i64 + 1, 3, Pad::Zero);
            }
            b'k' => {
                push_dec_mod!(bd.tm_hour, 2, Pad::Space);
            }
            b'l' => {
                let h = bd.tm_hour % 12;
                push_dec_mod!(if h == 0 { 12 } else { h }, 2, Pad::Space);
            }
            b'm' => {
                push_dec_mod!(bd.tm_mon as i64 + 1, 2, Pad::Zero);
            }
            b'M' => {
                push_dec_mod!(bd.tm_min, 2, Pad::Zero);
            }
            b'n' => {
                push_str_field!(b"\n", true, false);
            }
            b'p' => {
                let s: &[u8] = if bd.tm_hour < 12 { b"AM" } else { b"PM" };
                push_str_field!(s, true, false);
            }
            b'P' => {
                let s: &[u8] = if bd.tm_hour < 12 { b"am" } else { b"pm" };
                push_str_field!(s, false, false);
            }
            b'r' => {
                push_composite!(b"%I:%M:%S %p");
            }
            b'R' => {
                push_composite!(b"%H:%M");
            }
            b's' => {
                // Seconds since epoch
                let epoch = broken_down_to_epoch(bd);
                push_dec_mod!(epoch, 1, Pad::Space);
            }
            b'S' => {
                push_dec_mod!(bd.tm_sec, 2, Pad::Zero);
            }
            b't' => {
                push_str_field!(b"\t", true, false);
            }
            b'T' => {
                push_composite!(b"%H:%M:%S");
            }
            b'u' => {
                // ISO weekday: Monday=1 .. Sunday=7
                let u = if bd.tm_wday == 0 { 7 } else { bd.tm_wday };
                push_dec_mod!(u, 1, Pad::Zero);
            }
            b'U' => {
                // Sunday-based week number. Widen to i64 to absorb
                // arbitrary out-of-range tm_yday/tm_wday without
                // overflowing i32 (bd-7rxtm).
                let wnum = (bd.tm_yday as i64 + 7 - bd.tm_wday as i64) / 7;
                push_dec_mod!(wnum, 2, Pad::Zero);
            }
            b'V' => {
                let (_, w) = iso_week(bd);
                push_dec_mod!(w, 2, Pad::Zero);
            }
            b'w' => {
                push_dec_mod!(bd.tm_wday, 1, Pad::Zero);
            }
            b'W' => {
                // Monday-based week number. Widen to i64 to absorb
                // arbitrary out-of-range tm_yday/tm_wday without
                // overflowing i32 (bd-7rxtm).
                let monday_wday = if bd.tm_wday == 0 {
                    6i64
                } else {
                    bd.tm_wday as i64 - 1
                };
                let wnum = (bd.tm_yday as i64 + 7 - monday_wday) / 7;
                push_dec_mod!(wnum, 2, Pad::Zero);
            }
            b'x' => {
                push_composite!(b"%m/%d/%y");
            }
            b'X' => {
                push_composite!(b"%H:%M:%S");
            }
            b'y' => {
                push_dec_mod!((bd.tm_year as i64 + 1900).rem_euclid(100), 2, Pad::Zero);
            }
            b'Y' => {
                // Default: bare decimal (width 0). With explicit width (e.g. %6Y),
                // zero-pads to that width. Year 50 prints as "50", %6Y prints "000050".
                push_dec_mod!(bd.tm_year as i64 + 1900, 0, Pad::Zero);
            }
            b'z' => {
                // UTC offset from tm_gmtoff, formatted ±HHMM like glibc (which
                // reads the field regardless of how it was set — localtime,
                // strptime %z, or by hand). fl's own gmtime/localtime produce 0,
                // so the common case still renders "+0000".
                let off = bd.tm_gmtoff;
                let (sign, abs) = if off < 0 {
                    (b'-', (-off) as u64)
                } else {
                    (b'+', off as u64)
                };
                let hh = abs / 3600;
                let mm = (abs % 3600) / 60;
                push!(sign);
                push!(b'0' + ((hh / 10) % 10) as u8);
                push!(b'0' + (hh % 10) as u8);
                push!(b'0' + ((mm / 10) % 10) as u8);
                push!(b'0' + (mm % 10) as u8);
            }
            b'Z' => {
                // Timezone name. glibc echoes tm_zone when present, else the
                // process zone. fl populates bd.zone from the caller's tm_zone
                // (gmtime sets "GMT", localtime "UTC"); when unset, fl's only
                // timezone is UTC, so fall back to "UTC" (matching glibc under
                // TZ=UTC and fl's own localtime).
                let end = bd.zone.iter().position(|&b| b == 0).unwrap_or(bd.zone.len());
                let zone: &[u8] = if end == 0 { b"UTC" } else { &bd.zone[..end] };
                push_str_field!(zone, true, false);
            }
            b'%' => {
                push!(b'%');
            }
            _ => {
                // Unknown specifier — output literal
                push!(b'%');
                push!(fmt[i]);
            }
        }
        i += 1;
    }

    if pos < buf.len() {
        buf[pos] = 0; // NUL terminate
    }
    pos
}

/// Additional clock IDs accepted by the kernel.
pub const CLOCK_MONOTONIC_RAW: i32 = 4;
pub const CLOCK_REALTIME_COARSE: i32 = 5;
pub const CLOCK_MONOTONIC_COARSE: i32 = 6;
pub const CLOCK_BOOTTIME: i32 = 7;
pub const CLOCK_THREAD_CPUTIME_ID: i32 = 3;

/// Extended clock validity check (accepts all common Linux clock IDs).
#[inline]
pub fn valid_clock_id_extended(clock_id: i32) -> bool {
    matches!(
        clock_id,
        CLOCK_REALTIME
            | CLOCK_MONOTONIC
            | CLOCK_PROCESS_CPUTIME_ID
            | CLOCK_THREAD_CPUTIME_ID
            | CLOCK_MONOTONIC_RAW
            | CLOCK_REALTIME_COARSE
            | CLOCK_MONOTONIC_COARSE
            | CLOCK_BOOTTIME
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_clock_id() {
        assert!(valid_clock_id(CLOCK_REALTIME));
        assert!(valid_clock_id(CLOCK_MONOTONIC));
        assert!(valid_clock_id(CLOCK_PROCESS_CPUTIME_ID));
        assert!(!valid_clock_id(-1));
        assert!(!valid_clock_id(99));
    }

    #[test]
    fn epoch_zero() {
        let t = epoch_to_broken_down(0);
        assert_eq!(t.tm_year, 70); // 1970
        assert_eq!(t.tm_mon, 0); // January
        assert_eq!(t.tm_mday, 1);
        assert_eq!(t.tm_hour, 0);
        assert_eq!(t.tm_min, 0);
        assert_eq!(t.tm_sec, 0);
        assert_eq!(t.tm_wday, 4); // Thursday
        assert_eq!(t.tm_yday, 0);
    }

    #[test]
    fn known_timestamp() {
        // 2024-01-01 00:00:00 UTC = 1704067200
        let t = epoch_to_broken_down(1_704_067_200);
        assert_eq!(t.tm_year, 124); // 2024 - 1900
        assert_eq!(t.tm_mon, 0); // January
        assert_eq!(t.tm_mday, 1);
        assert_eq!(t.tm_hour, 0);
        assert_eq!(t.tm_min, 0);
        assert_eq!(t.tm_sec, 0);
        assert_eq!(t.tm_wday, 1); // Monday
        assert_eq!(t.tm_yday, 0);
    }

    #[test]
    fn leap_year_feb29() {
        // 2024-02-29 12:00:00 UTC = 1709208000
        let t = epoch_to_broken_down(1_709_208_000);
        assert_eq!(t.tm_year, 124);
        assert_eq!(t.tm_mon, 1); // February
        assert_eq!(t.tm_mday, 29);
        assert_eq!(t.tm_hour, 12);
    }

    #[test]
    fn negative_epoch() {
        // 1969-12-31 23:59:59 UTC = -1
        let t = epoch_to_broken_down(-1);
        assert_eq!(t.tm_year, 69); // 1969
        assert_eq!(t.tm_mon, 11); // December
        assert_eq!(t.tm_mday, 31);
        assert_eq!(t.tm_hour, 23);
        assert_eq!(t.tm_min, 59);
        assert_eq!(t.tm_sec, 59);
        assert_eq!(t.tm_wday, 3); // Wednesday
    }

    #[test]
    fn year_2000_boundary() {
        // 2000-01-01 00:00:00 UTC = 946684800
        let t = epoch_to_broken_down(946_684_800);
        assert_eq!(t.tm_year, 100);
        assert_eq!(t.tm_mon, 0);
        assert_eq!(t.tm_mday, 1);
        assert_eq!(t.tm_wday, 6); // Saturday
    }

    #[test]
    fn is_leap_year_check() {
        assert!(is_leap_year(2000));
        assert!(is_leap_year(2024));
        assert!(!is_leap_year(1900));
        assert!(!is_leap_year(2023));
        assert!(is_leap_year(2400));
    }

    #[test]
    fn end_of_year() {
        // 2023-12-31 23:59:59 UTC = 1704067199
        let t = epoch_to_broken_down(1_704_067_199);
        assert_eq!(t.tm_year, 123);
        assert_eq!(t.tm_mon, 11); // December
        assert_eq!(t.tm_mday, 31);
        assert_eq!(t.tm_hour, 23);
        assert_eq!(t.tm_min, 59);
        assert_eq!(t.tm_sec, 59);
        assert_eq!(t.tm_yday, 364);
    }

    // --- broken_down_to_epoch tests ---

    #[test]
    fn roundtrip_epoch_zero() {
        let bd = epoch_to_broken_down(0);
        assert_eq!(broken_down_to_epoch(&bd), 0);
    }

    #[test]
    fn roundtrip_known_timestamp() {
        let ts = 1_704_067_200i64; // 2024-01-01 00:00:00 UTC
        let bd = epoch_to_broken_down(ts);
        assert_eq!(broken_down_to_epoch(&bd), ts);
    }

    #[test]
    fn roundtrip_negative_epoch() {
        let ts = -1i64;
        let bd = epoch_to_broken_down(ts);
        assert_eq!(broken_down_to_epoch(&bd), ts);
    }

    #[test]
    fn roundtrip_leap_year() {
        let ts = 1_709_208_000i64; // 2024-02-29 12:00:00 UTC
        let bd = epoch_to_broken_down(ts);
        assert_eq!(broken_down_to_epoch(&bd), ts);
    }

    #[test]
    fn roundtrip_y2k() {
        let ts = 946_684_800i64; // 2000-01-01 00:00:00 UTC
        let bd = epoch_to_broken_down(ts);
        assert_eq!(broken_down_to_epoch(&bd), ts);
    }

    #[test]
    fn broken_down_to_epoch_normalizes_day_overflow() {
        // January 32 should normalize to February 1
        let bd = BrokenDownTime {
            tm_year: 70, // 1970
            tm_mon: 0,   // January
            tm_mday: 32, // 32nd day = Feb 1
            tm_hour: 0,
            tm_min: 0,
            tm_sec: 0,
            tm_wday: 0,
            tm_yday: 0,
            tm_isdst: 0,
            tm_gmtoff: 0,
            zone: [0; 16],
        };
        let epoch = broken_down_to_epoch(&bd);
        let normalized = epoch_to_broken_down(epoch);
        assert_eq!(normalized.tm_mon, 1); // February
        assert_eq!(normalized.tm_mday, 1);
    }

    #[test]
    fn broken_down_to_epoch_normalizes_month_overflow() {
        // Month 13 should normalize to February of next year
        let bd = BrokenDownTime {
            tm_year: 70, // 1970
            tm_mon: 13,  // 14th month = February 1971
            tm_mday: 15,
            tm_hour: 0,
            tm_min: 0,
            tm_sec: 0,
            tm_wday: 0,
            tm_yday: 0,
            tm_isdst: 0,
            tm_gmtoff: 0,
            zone: [0; 16],
        };
        let epoch = broken_down_to_epoch(&bd);
        let normalized = epoch_to_broken_down(epoch);
        assert_eq!(normalized.tm_year, 71); // 1971
        assert_eq!(normalized.tm_mon, 1); // February
        assert_eq!(normalized.tm_mday, 15);
    }

    // --- format_asctime tests ---

    #[test]
    fn asctime_epoch_zero() {
        let bd = epoch_to_broken_down(0);
        let mut buf = [0u8; 64];
        let n = format_asctime(&bd, &mut buf);
        assert!(n > 0);
        let s = std::str::from_utf8(&buf[..n]).unwrap();
        assert_eq!(s, "Thu Jan  1 00:00:00 1970\n");
    }

    #[test]
    fn asctime_known_date() {
        let bd = epoch_to_broken_down(1_704_067_200); // 2024-01-01 00:00:00 UTC
        let mut buf = [0u8; 64];
        let n = format_asctime(&bd, &mut buf);
        assert!(n > 0);
        let s = std::str::from_utf8(&buf[..n]).unwrap();
        assert_eq!(s, "Mon Jan  1 00:00:00 2024\n");
    }

    #[test]
    fn asctime_buffer_too_small() {
        let bd = epoch_to_broken_down(0);
        let mut buf = [0u8; 10];
        assert_eq!(format_asctime(&bd, &mut buf), 0);
    }

    // --- difftime tests ---

    #[test]
    fn difftime_basic() {
        assert_eq!(difftime(100, 50), 50.0);
        assert_eq!(difftime(0, 100), -100.0);
        assert_eq!(difftime(0, 0), 0.0);
    }

    // --- valid_clock_id_extended tests ---

    // --- format_strftime tests ---

    #[test]
    fn strftime_iso_date() {
        let bd = epoch_to_broken_down(1_704_067_200); // 2024-01-01 00:00:00 UTC
        let mut buf = [0u8; 64];
        let n = format_strftime(b"%Y-%m-%d", &bd, &mut buf);
        assert_eq!(&buf[..n], b"2024-01-01");
    }

    #[test]
    fn strftime_full_datetime() {
        let bd = epoch_to_broken_down(1_704_067_200);
        let mut buf = [0u8; 64];
        let n = format_strftime(b"%F %T", &bd, &mut buf);
        assert_eq!(&buf[..n], b"2024-01-01 00:00:00");
    }

    #[test]
    fn strftime_12h_ampm() {
        // 2024-01-01 15:30:45 UTC = 1704067200 + 15*3600 + 30*60 + 45 = 1704123045
        let bd = epoch_to_broken_down(1_704_123_045);
        let mut buf = [0u8; 64];
        let n = format_strftime(b"%I:%M:%S %p", &bd, &mut buf);
        assert_eq!(&buf[..n], b"03:30:45 PM");
    }

    #[test]
    fn strftime_day_of_year() {
        // Feb 15, 2024 = day 46
        let bd = epoch_to_broken_down(1_708_041_600); // 2024-02-16 00:00:00
        let mut buf = [0u8; 64];
        let n = format_strftime(b"%j", &bd, &mut buf);
        assert_eq!(&buf[..n], b"047"); // Feb 16 = day 47
    }

    #[test]
    fn strftime_percent_literal() {
        let bd = epoch_to_broken_down(0);
        let mut buf = [0u8; 64];
        let n = format_strftime(b"100%%", &bd, &mut buf);
        assert_eq!(&buf[..n], b"100%");
    }

    #[test]
    fn strftime_trailing_percent_is_literal() {
        // glibc outputs a trailing '%' literally (no conversion specifier follows).
        let bd = epoch_to_broken_down(0);
        let mut buf = [0u8; 64];
        let n = format_strftime(b"foo%", &bd, &mut buf);
        assert_eq!(&buf[..n], b"foo%");

        // Same for trailing '%-' (flag but no conversion)
        let n = format_strftime(b"bar%-", &bd, &mut buf);
        assert_eq!(&buf[..n], b"bar%-");
    }

    #[test]
    fn strftime_epoch_seconds() {
        let bd = epoch_to_broken_down(1_704_067_200);
        let mut buf = [0u8; 64];
        let n = format_strftime(b"%s", &bd, &mut buf);
        assert_eq!(&buf[..n], b"1704067200");
    }

    #[test]
    fn strftime_century_floors_for_negative_years() {
        // %C floors year/100 (glibc behavior): year -50 -> -1, -101 -> -2.
        let mut bd = epoch_to_broken_down(0);
        let mut buf = [0u8; 64];

        bd.tm_year = -1950; // year -50
        let n = format_strftime(b"%C", &bd, &mut buf);
        assert_eq!(&buf[..n], b"-1");

        bd.tm_year = -2001; // year -101
        let n = format_strftime(b"%C", &bd, &mut buf);
        assert_eq!(&buf[..n], b"-2");

        bd.tm_year = 100; // year 2000
        let n = format_strftime(b"%C", &bd, &mut buf);
        assert_eq!(&buf[..n], b"20");
    }

    #[test]
    fn strftime_zone_name() {
        // %Z echoes bd.zone when set; falls back to "UTC" (fl's only timezone)
        // when unset. The ABI layer fills bd.zone from the caller's tm_zone.
        let mut bd = epoch_to_broken_down(1_704_067_200);
        let mut buf = [0u8; 64];
        let n = format_strftime(b"%Z", &bd, &mut buf);
        assert_eq!(&buf[..n], b"UTC", "unset zone falls back to UTC");

        bd.zone[..3].copy_from_slice(b"GMT");
        let n = format_strftime(b"%Z", &bd, &mut buf);
        assert_eq!(&buf[..n], b"GMT", "set zone is echoed");

        bd.zone = [0; 16];
        bd.zone[..3].copy_from_slice(b"PST");
        let n = format_strftime(b"%Z", &bd, &mut buf);
        assert_eq!(&buf[..n], b"PST");
    }

    #[test]
    fn strftime_weekday_names() {
        let bd = epoch_to_broken_down(1_704_067_200); // Monday
        let mut buf = [0u8; 64];
        let n = format_strftime(b"%a %A", &bd, &mut buf);
        assert_eq!(&buf[..n], b"Mon Monday");
    }

    #[test]
    fn strftime_month_names() {
        let bd = epoch_to_broken_down(1_704_067_200); // January
        let mut buf = [0u8; 64];
        let n = format_strftime(b"%b %B", &bd, &mut buf);
        assert_eq!(&buf[..n], b"Jan January");
    }

    #[test]
    fn strftime_buffer_too_small_returns_zero() {
        let bd = epoch_to_broken_down(0);
        let mut buf = [0u8; 3];
        let n = format_strftime(b"%Y-%m-%d", &bd, &mut buf);
        assert_eq!(n, 0);
    }

    #[test]
    fn strftime_iso_week() {
        // 2024-01-01 is Monday of ISO week 1
        let bd = epoch_to_broken_down(1_704_067_200);
        let mut buf = [0u8; 64];
        let n = format_strftime(b"%G-W%V-%u", &bd, &mut buf);
        assert_eq!(&buf[..n], b"2024-W01-1");
    }

    #[test]
    fn strftime_iso_week_year_boundary() {
        // Jan 1, 2021 is a Friday - belongs to ISO week 53 of 2020
        // (ISO year differs from calendar year)
        let mut bd = BrokenDownTime {
            tm_year: 121, // 2021
            tm_mon: 0,    // January
            tm_mday: 1,
            tm_wday: 5, // Friday
            tm_yday: 0,
            ..Default::default()
        };
        let mut buf = [0u8; 64];
        let n = format_strftime(b"%G-W%V-%u", &bd, &mut buf);
        assert_eq!(&buf[..n], b"2020-W53-5");

        // Dec 31, 2020 is Thursday - ISO week 53 of 2020
        bd.tm_year = 120; // 2020
        bd.tm_mon = 11; // December
        bd.tm_mday = 31;
        bd.tm_wday = 4; // Thursday
        bd.tm_yday = 365; // leap year
        let n = format_strftime(b"%G-W%V-%u", &bd, &mut buf);
        assert_eq!(&buf[..n], b"2020-W53-4");
    }

    #[test]
    fn strftime_newline_and_tab() {
        let bd = epoch_to_broken_down(0);
        let mut buf = [0u8; 64];
        let n = format_strftime(b"a%nb%tc", &bd, &mut buf);
        assert_eq!(&buf[..n], b"a\nb\tc");
    }

    #[test]
    fn strftime_padding_modifiers() {
        // March 5, 2025 14:30:45 (mday=5 tests padding)
        let mut bd = BrokenDownTime {
            tm_year: 125, // 2025
            tm_mon: 2,    // March
            tm_mday: 5,
            tm_hour: 14,
            tm_min: 30,
            tm_sec: 45,
            tm_wday: 3, // Wednesday
            tm_yday: 63,
            ..Default::default()
        };

        let mut buf = [0u8; 64];

        // %d default is zero-padded
        let n = format_strftime(b"%d", &bd, &mut buf);
        assert_eq!(&buf[..n], b"05");

        // %-d no padding
        let n = format_strftime(b"%-d", &bd, &mut buf);
        assert_eq!(&buf[..n], b"5");

        // %_d space padding
        let n = format_strftime(b"%_d", &bd, &mut buf);
        assert_eq!(&buf[..n], b" 5");

        // %0d explicit zero padding
        let n = format_strftime(b"%0d", &bd, &mut buf);
        assert_eq!(&buf[..n], b"05");

        // %e default is space-padded, %-e removes padding
        let n = format_strftime(b"%e", &bd, &mut buf);
        assert_eq!(&buf[..n], b" 5");
        let n = format_strftime(b"%-e", &bd, &mut buf);
        assert_eq!(&buf[..n], b"5");

        // %H, %M, %S modifiers
        let n = format_strftime(b"%-H:%-M:%-S", &bd, &mut buf);
        assert_eq!(&buf[..n], b"14:30:45"); // all two-digit, no change

        // Test with single-digit hour (9 AM)
        bd.tm_hour = 9;
        let n = format_strftime(b"[%H] [%-H] [%_H]", &bd, &mut buf);
        assert_eq!(&buf[..n], b"[09] [9] [ 9]");

        // Explicit width specifier (glibc extension)
        bd.tm_year = 124; // 2024
        let n = format_strftime(b"%Y", &bd, &mut buf);
        assert_eq!(&buf[..n], b"2024"); // default: no padding
        let n = format_strftime(b"%6Y", &bd, &mut buf);
        assert_eq!(&buf[..n], b"002024"); // width 6, zero-padded
        let n = format_strftime(b"%-6Y", &bd, &mut buf);
        assert_eq!(&buf[..n], b"  2024"); // width 6, space-padded (- suppresses zeros)
        let n = format_strftime(b"%_6Y", &bd, &mut buf);
        assert_eq!(&buf[..n], b"  2024"); // width 6, space-padded
    }

    // --- valid_clock_id_extended tests ---

    #[test]
    fn test_extended_clock_ids() {
        assert!(valid_clock_id_extended(CLOCK_REALTIME));
        assert!(valid_clock_id_extended(CLOCK_MONOTONIC));
        assert!(valid_clock_id_extended(CLOCK_THREAD_CPUTIME_ID));
        assert!(valid_clock_id_extended(CLOCK_MONOTONIC_RAW));
        assert!(valid_clock_id_extended(CLOCK_BOOTTIME));
        assert!(!valid_clock_id_extended(99));
        assert!(!valid_clock_id_extended(-1));
    }

    /// Regression for bd-7rxtm: difftime on full-range i64 inputs
    /// used to overflow the i64 subtraction (e.g. i64::MAX - i64::MIN).
    /// Surfaced via fuzz_time. The fix converts to f64 before
    /// subtracting — matches glibc's behavior.
    #[test]
    fn difftime_does_not_overflow_on_extreme_epochs() {
        let d = difftime(i64::MAX, i64::MIN);
        assert!(
            d.is_finite(),
            "difftime({:x}, {:x}) = {d}",
            i64::MAX,
            i64::MIN
        );
        assert!(d > 0.0);
        let d_inv = difftime(i64::MIN, i64::MAX);
        assert!(d_inv.is_finite());
        assert!(d_inv < 0.0);
        // Antisymmetry at value level.
        assert_eq!(d, -d_inv);
        // Degenerate self-difference.
        assert_eq!(difftime(i64::MAX, i64::MAX), 0.0);
        assert_eq!(difftime(i64::MIN, i64::MIN), 0.0);
    }

    /// Regression for bd-7rxtm: out-of-range BrokenDownTime fields
    /// (which POSIX does not constrain at the API boundary) used to
    /// overflow i32 inside iso_week / %U / %W formatting and panic
    /// with debug_assertions. Surfaced via fuzz_strftime.
    #[test]
    fn format_strftime_does_not_overflow_on_extreme_tm_fields() {
        let bd = BrokenDownTime {
            tm_sec: i32::MIN,
            tm_min: i32::MIN,
            tm_hour: i32::MAX,
            tm_mday: i32::MAX,
            tm_mon: i32::MIN,
            tm_year: 0,
            tm_wday: i32::MAX,
            tm_yday: i32::MIN,
            tm_isdst: 0,
            tm_gmtoff: 0,
            zone: [0; 16],
        };
        let mut buf = [0u8; 256];
        // Each of the previously-overflowing specifiers must complete
        // without panicking.
        let _ = format_strftime(b"%V", &bd, &mut buf);
        let _ = format_strftime(b"%U", &bd, &mut buf);
        let _ = format_strftime(b"%W", &bd, &mut buf);
        let _ = format_strftime(b"%G", &bd, &mut buf);
        let _ = format_strftime(b"%g", &bd, &mut buf);

        // %m/%D/%F/%x add 1 to tm_mon and %j adds 1 to tm_yday. With the
        // field already at i32::MAX, that `+ 1` overflows i32 unless the
        // arithmetic widens to i64 first. Exercise the max-valued fields
        // explicitly — tm_mon/tm_yday at i32::MIN above already covers the
        // lower bound, but only i32::MAX triggers the +1 overflow.
        let bd_max = BrokenDownTime {
            tm_sec: i32::MAX,
            tm_min: i32::MAX,
            tm_hour: i32::MAX,
            tm_mday: i32::MAX,
            tm_mon: i32::MAX,
            tm_year: 0,
            tm_wday: i32::MAX,
            tm_yday: i32::MAX,
            tm_isdst: 0,
            tm_gmtoff: 0,
            zone: [0; 16],
        };
        let _ = format_strftime(b"%m", &bd_max, &mut buf);
        let _ = format_strftime(b"%j", &bd_max, &mut buf);
        let _ = format_strftime(b"%D", &bd_max, &mut buf);
        let _ = format_strftime(b"%F", &bd_max, &mut buf);
        let _ = format_strftime(b"%x", &bd_max, &mut buf);
    }

    #[test]
    fn glibc_gmtime_epoch_zero_parity() {
        // glibc: gmtime(0) = 1970-01-01 00:00:00 UTC
        let bd = epoch_to_broken_down(0);
        assert_eq!(bd.tm_year, 70); // 1970 - 1900
        assert_eq!(bd.tm_mon, 0); // January
        assert_eq!(bd.tm_mday, 1);
        assert_eq!(bd.tm_hour, 0);
        assert_eq!(bd.tm_min, 0);
        assert_eq!(bd.tm_sec, 0);
        assert_eq!(bd.tm_wday, 4); // Thursday
        assert_eq!(bd.tm_yday, 0);
    }

    #[test]
    fn glibc_mktime_normalizes_feb30() {
        // glibc: mktime(2024-02-30) normalizes to 2024-03-01
        let bd = BrokenDownTime {
            tm_year: 124, // 2024
            tm_mon: 1,    // February
            tm_mday: 30,  // Invalid for Feb
            tm_hour: 0,
            tm_min: 0,
            tm_sec: 0,
            tm_wday: 0,
            tm_yday: 0,
            tm_isdst: -1,
            tm_gmtoff: 0,
            zone: [0; 16],
        };
        // broken_down_to_epoch normalizes and epoch_to_broken_down gives us back
        let epoch = broken_down_to_epoch(&bd);
        let normalized = epoch_to_broken_down(epoch);
        // Feb has 29 days in 2024 (leap year), so Feb 30 → Mar 1
        assert_eq!(normalized.tm_mon, 2); // March
        assert_eq!(normalized.tm_mday, 1);
    }

    #[test]
    fn glibc_strftime_buffer_exact_fit() {
        // glibc: strftime returns length written when buffer is exact size
        let bd = BrokenDownTime {
            tm_year: 126, // 2026
            tm_mon: 4,    // May
            tm_mday: 23,
            tm_hour: 14,
            tm_min: 30,
            tm_sec: 45,
            tm_wday: 5,
            tm_yday: 142,
            tm_isdst: 0,
            tm_gmtoff: 0,
            zone: [0; 16],
        };
        // "%Y-%m-%d" = "2026-05-23" = 10 chars + NUL = 11 bytes
        let mut buf = [0u8; 11];
        let ret = format_strftime(b"%Y-%m-%d", &bd, &mut buf);
        assert_eq!(ret, 10);
        assert_eq!(&buf[..10], b"2026-05-23");
    }

    #[test]
    fn glibc_clock_id_constants() {
        // CLOCK_* constants must match glibc/Linux values
        assert_eq!(CLOCK_REALTIME, 0);
        assert_eq!(CLOCK_MONOTONIC, 1);
        assert_eq!(CLOCK_PROCESS_CPUTIME_ID, 2);
        assert_eq!(CLOCK_THREAD_CPUTIME_ID, 3);
        assert_eq!(CLOCK_MONOTONIC_RAW, 4);
        assert_eq!(CLOCK_REALTIME_COARSE, 5);
        assert_eq!(CLOCK_MONOTONIC_COARSE, 6);
        assert_eq!(CLOCK_BOOTTIME, 7);
    }
}
