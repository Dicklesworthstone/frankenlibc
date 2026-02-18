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
}

/// Returns `true` if `year` is a leap year (Gregorian).
#[inline]
fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

/// Days in each month for a non-leap year.
const DAYS_IN_MONTH: [i32; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

/// Convert seconds since Unix epoch to broken-down UTC time.
///
/// Handles negative epochs (pre-1970). UTC only — no timezone/DST.
pub fn epoch_to_broken_down(epoch_secs: i64) -> BrokenDownTime {
    // Seconds within the day
    let mut rem = epoch_secs % 86400;
    let mut days = epoch_secs / 86400;
    if rem < 0 {
        rem += 86400;
        days -= 1;
    }

    let tm_sec = (rem % 60) as i32;
    let tm_min = ((rem / 60) % 60) as i32;
    let tm_hour = (rem / 3600) as i32;

    // Day of week: Jan 1 1970 was Thursday (4)
    let mut wday = (days % 7 + 4) % 7;
    if wday < 0 {
        wday += 7;
    }
    let tm_wday = wday as i32;

    // Walk years from 1970
    let mut year: i64 = 1970;
    let mut remaining_days = days;

    if remaining_days >= 0 {
        loop {
            let days_in_year: i64 = if is_leap_year(year) { 366 } else { 365 };
            if remaining_days < days_in_year {
                break;
            }
            remaining_days -= days_in_year;
            year += 1;
        }
    } else {
        loop {
            year -= 1;
            let days_in_year: i64 = if is_leap_year(year) { 366 } else { 365 };
            remaining_days += days_in_year;
            if remaining_days >= 0 {
                break;
            }
        }
    }

    let tm_yday = remaining_days as i32;
    let leap = is_leap_year(year);

    // Walk months
    let mut mon = 0i32;
    let mut day_rem = remaining_days as i32;
    for m in 0..12 {
        let dim = if m == 1 && leap {
            29
        } else {
            DAYS_IN_MONTH[m as usize]
        };
        if day_rem < dim {
            mon = m;
            break;
        }
        day_rem -= dim;
        mon = m + 1;
    }

    BrokenDownTime {
        tm_sec,
        tm_min,
        tm_hour,
        tm_mday: day_rem + 1,
        tm_mon: mon,
        tm_year: (year - 1900) as i32,
        tm_wday,
        tm_yday,
        tm_isdst: 0,
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
    // Normalize month
    if !(0..=11).contains(&mon) {
        year += mon.div_euclid(12);
        mon = mon.rem_euclid(12);
    }

    // Accumulated days from epoch (1970-01-01) to start of `year`.
    let mut days: i64 = 0;
    if year >= 1970 {
        for y in 1970..year {
            days += if is_leap_year(y) { 366 } else { 365 };
        }
    } else {
        for y in year..1970 {
            days -= if is_leap_year(y) { 366 } else { 365 };
        }
    }

    // Add days for months [0..mon)
    let leap = is_leap_year(year);
    for m in 0..mon {
        days += if m == 1 && leap {
            29
        } else {
            DAYS_IN_MONTH[m as usize] as i64
        };
    }

    // Add day of month (tm_mday is 1-based)
    days += (bd.tm_mday - 1) as i64;

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

    // "Day Mon DD HH:MM:SS YYYY\n"
    let s = format!(
        "{} {} {:2} {:02}:{:02}:{:02} {:4}\n",
        std::str::from_utf8(WDAY_NAMES[wday]).unwrap_or("???"),
        std::str::from_utf8(MON_NAMES[mon]).unwrap_or("???"),
        bd.tm_mday,
        bd.tm_hour,
        bd.tm_min,
        bd.tm_sec,
        year,
    );

    let bytes = s.as_bytes();
    let copy_len = bytes.len().min(buf.len() - 1);
    buf[..copy_len].copy_from_slice(&bytes[..copy_len]);
    buf[copy_len] = 0;
    copy_len
}

/// POSIX `difftime` — difference in seconds between two `time_t` values.
#[inline]
pub fn difftime(time1: i64, time0: i64) -> f64 {
    (time1 - time0) as f64
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
fn iso_week(bd: &BrokenDownTime) -> (i64, i32) {
    let year = bd.tm_year as i64 + 1900;
    let yday = bd.tm_yday;
    // ISO weekday: Monday=1 .. Sunday=7
    let wday_iso = if bd.tm_wday == 0 { 7 } else { bd.tm_wday };
    // Day of year of the Thursday in the same ISO week
    let thu_yday = yday - wday_iso + 4;
    // ISO year that Thursday belongs to
    let mut iso_y = year;
    if thu_yday < 0 {
        // Thursday is in previous year
        iso_y -= 1;
        let prev_days: i32 = if is_leap_year(iso_y) { 366 } else { 365 };
        let week = (thu_yday + prev_days) / 7 + 1;
        return (iso_y, week);
    }
    let year_days: i32 = if is_leap_year(year) { 366 } else { 365 };
    if thu_yday >= year_days {
        // Thursday is in next year
        iso_y += 1;
        return (iso_y, 1);
    }
    let week = thu_yday / 7 + 1;
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

    // Helper: write zero-padded decimal of a given width
    macro_rules! push_dec {
        ($val:expr, $width:expr) => {{
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
            if negative {
                push!(b'-');
            }
            let w: usize = $width;
            if len < w {
                for _ in 0..(w - len) {
                    push!(b'0');
                }
            }
            for j in (0..len).rev() {
                push!(tmp[j]);
            }
        }};
    }

    // Helper: write space-padded decimal
    macro_rules! push_dec_space {
        ($val:expr, $width:expr) => {{
            let mut tmp = [0u8; 20];
            let v = $val as i64;
            let mut uv = v as u64;
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
            if len < w {
                for _ in 0..(w - len) {
                    push!(b' ');
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
            break;
        }
        match fmt[i] {
            b'a' => {
                let wday = bd.tm_wday.rem_euclid(7) as usize;
                push_str!(WDAY_NAMES[wday]);
            }
            b'A' => {
                let wday = bd.tm_wday.rem_euclid(7) as usize;
                push_str!(WDAY_FULL_NAMES[wday].as_bytes());
            }
            b'b' | b'h' => {
                let mon = bd.tm_mon.rem_euclid(12) as usize;
                push_str!(MON_NAMES[mon]);
            }
            b'B' => {
                let mon = bd.tm_mon.rem_euclid(12) as usize;
                push_str!(MON_FULL_NAMES[mon].as_bytes());
            }
            b'c' => {
                // Preferred date/time: "Day Mon DD HH:MM:SS YYYY"
                let wday = bd.tm_wday.rem_euclid(7) as usize;
                let mon = bd.tm_mon.rem_euclid(12) as usize;
                push_str!(WDAY_NAMES[wday]);
                push!(b' ');
                push_str!(MON_NAMES[mon]);
                push!(b' ');
                push_dec_space!(bd.tm_mday, 2);
                push!(b' ');
                push_dec!(bd.tm_hour, 2);
                push!(b':');
                push_dec!(bd.tm_min, 2);
                push!(b':');
                push_dec!(bd.tm_sec, 2);
                push!(b' ');
                push_dec!(bd.tm_year as i64 + 1900, 4);
            }
            b'C' => {
                let century = (bd.tm_year as i64 + 1900) / 100;
                push_dec!(century, 2);
            }
            b'd' => {
                push_dec!(bd.tm_mday, 2);
            }
            b'D' => {
                // %m/%d/%y
                push_dec!(bd.tm_mon + 1, 2);
                push!(b'/');
                push_dec!(bd.tm_mday, 2);
                push!(b'/');
                push_dec!((bd.tm_year as i64 + 1900).rem_euclid(100), 2);
            }
            b'e' => {
                push_dec_space!(bd.tm_mday, 2);
            }
            b'F' => {
                // %Y-%m-%d
                push_dec!(bd.tm_year as i64 + 1900, 4);
                push!(b'-');
                push_dec!(bd.tm_mon + 1, 2);
                push!(b'-');
                push_dec!(bd.tm_mday, 2);
            }
            b'G' => {
                let (iso_y, _) = iso_week(bd);
                push_dec!(iso_y, 4);
            }
            b'g' => {
                let (iso_y, _) = iso_week(bd);
                push_dec!(iso_y.rem_euclid(100), 2);
            }
            b'H' => {
                push_dec!(bd.tm_hour, 2);
            }
            b'I' => {
                let h = bd.tm_hour % 12;
                push_dec!(if h == 0 { 12 } else { h }, 2);
            }
            b'j' => {
                push_dec!(bd.tm_yday + 1, 3);
            }
            b'k' => {
                push_dec_space!(bd.tm_hour, 2);
            }
            b'l' => {
                let h = bd.tm_hour % 12;
                push_dec_space!(if h == 0 { 12 } else { h }, 2);
            }
            b'm' => {
                push_dec!(bd.tm_mon + 1, 2);
            }
            b'M' => {
                push_dec!(bd.tm_min, 2);
            }
            b'n' => {
                push!(b'\n');
            }
            b'p' => {
                if bd.tm_hour < 12 {
                    push_str!(b"AM");
                } else {
                    push_str!(b"PM");
                }
            }
            b'P' => {
                if bd.tm_hour < 12 {
                    push_str!(b"am");
                } else {
                    push_str!(b"pm");
                }
            }
            b'r' => {
                // %I:%M:%S %p
                let h = bd.tm_hour % 12;
                push_dec!(if h == 0 { 12 } else { h }, 2);
                push!(b':');
                push_dec!(bd.tm_min, 2);
                push!(b':');
                push_dec!(bd.tm_sec, 2);
                push!(b' ');
                if bd.tm_hour < 12 {
                    push_str!(b"AM");
                } else {
                    push_str!(b"PM");
                }
            }
            b'R' => {
                // %H:%M
                push_dec!(bd.tm_hour, 2);
                push!(b':');
                push_dec!(bd.tm_min, 2);
            }
            b's' => {
                // Seconds since epoch
                let epoch = broken_down_to_epoch(bd);
                push_dec!(epoch, 1);
            }
            b'S' => {
                push_dec!(bd.tm_sec, 2);
            }
            b't' => {
                push!(b'\t');
            }
            b'T' => {
                // %H:%M:%S
                push_dec!(bd.tm_hour, 2);
                push!(b':');
                push_dec!(bd.tm_min, 2);
                push!(b':');
                push_dec!(bd.tm_sec, 2);
            }
            b'u' => {
                // ISO weekday: Monday=1 .. Sunday=7
                let u = if bd.tm_wday == 0 { 7 } else { bd.tm_wday };
                push_dec!(u, 1);
            }
            b'U' => {
                // Sunday-based week number
                let wnum = (bd.tm_yday + 7 - bd.tm_wday) / 7;
                push_dec!(wnum, 2);
            }
            b'V' => {
                let (_, w) = iso_week(bd);
                push_dec!(w, 2);
            }
            b'w' => {
                push_dec!(bd.tm_wday, 1);
            }
            b'W' => {
                // Monday-based week number
                let monday_wday = if bd.tm_wday == 0 { 6 } else { bd.tm_wday - 1 };
                let wnum = (bd.tm_yday + 7 - monday_wday) / 7;
                push_dec!(wnum, 2);
            }
            b'x' => {
                // Preferred date: %m/%d/%y
                push_dec!(bd.tm_mon + 1, 2);
                push!(b'/');
                push_dec!(bd.tm_mday, 2);
                push!(b'/');
                push_dec!((bd.tm_year as i64 + 1900).rem_euclid(100), 2);
            }
            b'X' => {
                // Preferred time: %H:%M:%S
                push_dec!(bd.tm_hour, 2);
                push!(b':');
                push_dec!(bd.tm_min, 2);
                push!(b':');
                push_dec!(bd.tm_sec, 2);
            }
            b'y' => {
                push_dec!((bd.tm_year as i64 + 1900).rem_euclid(100), 2);
            }
            b'Y' => {
                push_dec!(bd.tm_year as i64 + 1900, 4);
            }
            b'z' => {
                // UTC offset: +0000 (we only support UTC for now)
                push_str!(b"+0000");
            }
            b'Z' => {
                // Timezone name: UTC
                push_str!(b"UTC");
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
    fn strftime_epoch_seconds() {
        let bd = epoch_to_broken_down(1_704_067_200);
        let mut buf = [0u8; 64];
        let n = format_strftime(b"%s", &bd, &mut buf);
        assert_eq!(&buf[..n], b"1704067200");
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
    fn strftime_newline_and_tab() {
        let bd = epoch_to_broken_down(0);
        let mut buf = [0u8; 64];
        let n = format_strftime(b"a%nb%tc", &bd, &mut buf);
        assert_eq!(&buf[..n], b"a\nb\tc");
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
}
