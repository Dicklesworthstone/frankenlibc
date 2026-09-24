//! Time zones: TZif files (RFC 8536) and POSIX `TZ` strings.
//!
//! Clean-room from RFC 8536 ("The Time Zone Information Format") and the POSIX
//! `TZ` grammar (XBD 8.3), with glibc's documented resolution choices:
//! before the first transition the first non-DST type applies; after the last
//! transition the TZif footer rule applies; a DST name without rules uses
//! `M3.2.0,M11.1.0`.
//!
//! Before this module fl was UTC-only: `localtime_r`/`mktime` ignored `TZ`
//! and `/etc/localtime` (bd-rc0923-epic-eeuy4f.11).

/// One local-time type: offset east of UTC, DST flag, abbreviation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalType {
    /// Seconds east of UTC (glibc `tm_gmtoff`).
    pub utoff: i32,
    /// Whether this type is daylight-saving time.
    pub isdst: bool,
    /// Abbreviation such as `EST` or `+0530`.
    pub abbr: String,
}

impl LocalType {
    fn utc() -> Self {
        Self {
            utoff: 0,
            isdst: false,
            abbr: "UTC".to_string(),
        }
    }
}

/// A rule date in a POSIX `TZ` string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuleDate {
    /// `Jn`: Julian day 1..=365, February 29 never counted.
    Julian1(u16),
    /// `n`: zero-based day of year 0..=365, February 29 counted.
    Julian0(u16),
    /// `Mm.w.d`: day `d` (0 = Sunday) of week `w` (5 = last) of month `m`.
    MonthWeekDay { month: u8, week: u8, weekday: u8 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DstRule {
    dst: LocalType,
    start: RuleDate,
    /// Seconds after local-standard midnight at which DST starts.
    start_time: i32,
    end: RuleDate,
    /// Seconds after local-daylight midnight at which DST ends.
    end_time: i32,
}

/// A parsed POSIX `TZ` string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PosixTz {
    std: LocalType,
    dst: Option<DstRule>,
}

/// A time zone: transition table plus optional POSIX rule for later times.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Zone {
    transitions: Vec<i64>,
    transition_types: Vec<u8>,
    types: Vec<LocalType>,
    footer: Option<PosixTz>,
    /// Returned when the zone has no usable type (never for parsed files).
    fallback: LocalType,
    /// `tzname[1]` is empty (see [`Zone::utc_named`]).
    unnamed_dst: bool,
}

/// The values `tzset` publishes (`tzname`, `timezone`, `daylight`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TzGlobals {
    /// `tzname[0]`.
    pub std_abbr: String,
    /// `tzname[1]`.
    pub dst_abbr: String,
    /// `timezone`: seconds WEST of UTC for standard time.
    pub timezone: i64,
    /// `daylight`: whether the zone has a DST rule or DST types.
    pub daylight: bool,
}

const SECS_PER_DAY: i64 = 86_400;

fn is_leap(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

/// Days since 1970-01-01 of the given proleptic Gregorian date.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Proleptic Gregorian year containing day `days` since the epoch.
fn year_of_days(days: i64) -> i64 {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    yoe + era * 400 + i64::from(m <= 2)
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ if is_leap(year) => 29,
        _ => 28,
    }
}

impl RuleDate {
    /// Days since the epoch of this rule date in `year`.
    fn day_in_year(self, year: i64) -> i64 {
        let jan1 = days_from_civil(year, 1, 1);
        match self {
            Self::Julian1(n) => {
                let n = i64::from(n);
                jan1 + n - 1 + i64::from(is_leap(year) && n >= 60)
            }
            Self::Julian0(n) => jan1 + i64::from(n),
            Self::MonthWeekDay {
                month,
                week,
                weekday,
            } => {
                let m = i64::from(month);
                let first = days_from_civil(year, m, 1);
                // 1970-01-01 was a Thursday (4).
                let first_wday = (first + 4).rem_euclid(7);
                let mut day =
                    1 + (i64::from(weekday) - first_wday).rem_euclid(7) + 7 * (i64::from(week) - 1);
                let dim = days_in_month(year, m);
                while day > dim {
                    day -= 7;
                }
                first + day - 1
            }
        }
    }
}

impl PosixTz {
    fn lookup(&self, t: i64) -> &LocalType {
        let Some(rule) = &self.dst else {
            return &self.std;
        };
        let std_off = i64::from(self.std.utoff);
        let dst_off = i64::from(rule.dst.utoff);
        // glibc computes rule instants for years <= 1970 as if in 1970
        // (tzset.c compute_change), so earlier instants compare against the
        // 1970 transitions; mirror that so pre-1970 times agree.
        let year = year_of_days((t + std_off).div_euclid(SECS_PER_DAY)).max(1970);
        let in_dst = |y: i64| {
            let start =
                rule.start.day_in_year(y) * SECS_PER_DAY + i64::from(rule.start_time) - std_off;
            let end = rule.end.day_in_year(y) * SECS_PER_DAY + i64::from(rule.end_time) - dst_off;
            if start < end {
                start <= t && t < end
            } else {
                !(end <= t && t < start)
            }
        };
        // Decide within the local year; the neighbouring year covers instants
        // whose rule boundary crosses New Year.
        if in_dst(year) { &rule.dst } else { &self.std }
    }

    fn globals(&self) -> TzGlobals {
        TzGlobals {
            std_abbr: self.std.abbr.clone(),
            dst_abbr: self
                .dst
                .as_ref()
                .map_or_else(|| self.std.abbr.clone(), |r| r.dst.abbr.clone()),
            timezone: -i64::from(self.std.utoff),
            daylight: self.dst.is_some(),
        }
    }
}

// ---------------------------------------------------------------------------
// POSIX TZ string parsing
// ---------------------------------------------------------------------------

struct Cursor<'a> {
    s: &'a [u8],
    i: usize,
}

impl Cursor<'_> {
    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }
    fn eat(&mut self, c: u8) -> bool {
        if self.peek() == Some(c) {
            self.i += 1;
            true
        } else {
            false
        }
    }
    fn number(&mut self, max_digits: usize) -> Option<i64> {
        let start = self.i;
        let mut v: i64 = 0;
        while let Some(c) = self.peek() {
            if !c.is_ascii_digit() || self.i - start >= max_digits {
                break;
            }
            v = v * 10 + i64::from(c - b'0');
            self.i += 1;
        }
        (self.i > start).then_some(v)
    }
    fn name(&mut self) -> Option<String> {
        if self.eat(b'<') {
            let start = self.i;
            while let Some(c) = self.peek() {
                if c == b'>' {
                    break;
                }
                if !(c.is_ascii_alphanumeric() || c == b'+' || c == b'-') {
                    return None;
                }
                self.i += 1;
            }
            let name = &self.s[start..self.i];
            if !self.eat(b'>') || name.len() < 3 {
                return None;
            }
            return String::from_utf8(name.to_vec()).ok();
        }
        let start = self.i;
        while self.peek().is_some_and(|c| c.is_ascii_alphabetic()) {
            self.i += 1;
        }
        let name = &self.s[start..self.i];
        if name.len() < 3 {
            return None;
        }
        String::from_utf8(name.to_vec()).ok()
    }
    /// `[+-]hh[:mm[:ss]]`, returned in seconds (sign applied). `max_hours`
    /// bounds the hour field (24 for offsets, 167 for rule times).
    fn hms(&mut self, max_hours: i64) -> Option<i64> {
        let neg = if self.eat(b'-') {
            true
        } else {
            self.eat(b'+');
            false
        };
        let h = self.number(3)?;
        if h > max_hours {
            return None;
        }
        let mut secs = h * 3600;
        if self.eat(b':') {
            let m = self.number(2)?;
            if m > 59 {
                return None;
            }
            secs += m * 60;
            if self.eat(b':') {
                let s = self.number(2)?;
                if s > 59 {
                    return None;
                }
                secs += s;
            }
        }
        Some(if neg { -secs } else { secs })
    }
    fn rule_date(&mut self) -> Option<RuleDate> {
        if self.eat(b'J') {
            let n = self.number(3)?;
            return (1..=365)
                .contains(&n)
                .then_some(RuleDate::Julian1(n as u16));
        }
        if self.eat(b'M') {
            let m = self.number(2)?;
            if !self.eat(b'.') {
                return None;
            }
            let w = self.number(1)?;
            if !self.eat(b'.') {
                return None;
            }
            let d = self.number(1)?;
            if !(1..=12).contains(&m) || !(1..=5).contains(&w) || d > 6 {
                return None;
            }
            return Some(RuleDate::MonthWeekDay {
                month: m as u8,
                week: w as u8,
                weekday: d as u8,
            });
        }
        let n = self.number(3)?;
        (n <= 365).then_some(RuleDate::Julian0(n as u16))
    }
    fn rule_time(&mut self) -> Option<i32> {
        if self.eat(b'/') {
            self.hms(167).map(|v| v as i32)
        } else {
            Some(2 * 3600)
        }
    }
}

/// Parse a POSIX `TZ` string such as `EST5EDT,M3.2.0,M11.1.0` or `<+0530>-5:30`.
#[must_use]
pub fn parse_posix_tz(spec: &[u8]) -> Option<PosixTz> {
    let mut c = Cursor { s: spec, i: 0 };
    let std_name = c.name()?;
    // POSIX offsets are the value added to local time to reach UTC.
    let std_off = -c.hms(24)?;
    let std = LocalType {
        utoff: std_off as i32,
        isdst: false,
        abbr: std_name,
    };
    if c.peek().is_none() {
        return Some(PosixTz { std, dst: None });
    }
    let dst_name = c.name()?;
    let dst_off = match c.peek() {
        Some(b',') | None => std_off + 3600,
        _ => -c.hms(24)?,
    };
    let dst = LocalType {
        utoff: dst_off as i32,
        isdst: true,
        abbr: dst_name,
    };
    let (start, start_time, end, end_time) = if c.eat(b',') {
        let start = c.rule_date()?;
        let start_time = c.rule_time()?;
        if !c.eat(b',') {
            return None;
        }
        let end = c.rule_date()?;
        let end_time = c.rule_time()?;
        (start, start_time, end, end_time)
    } else {
        // glibc's default when a DST name has no rule (US rules).
        (
            RuleDate::MonthWeekDay {
                month: 3,
                week: 2,
                weekday: 0,
            },
            7200,
            RuleDate::MonthWeekDay {
                month: 11,
                week: 1,
                weekday: 0,
            },
            7200,
        )
    };
    if c.peek().is_some() {
        return None;
    }
    Some(PosixTz {
        std,
        dst: Some(DstRule {
            dst,
            start,
            start_time,
            end,
            end_time,
        }),
    })
}

// ---------------------------------------------------------------------------
// TZif parsing (RFC 8536)
// ---------------------------------------------------------------------------

fn be_u32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

fn be_i32(b: &[u8], at: usize) -> Option<i32> {
    Some(i32::from_be_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

fn be_i64(b: &[u8], at: usize) -> Option<i64> {
    Some(i64::from_be_bytes(b.get(at..at + 8)?.try_into().ok()?))
}

struct Header {
    version: u8,
    isutcnt: usize,
    isstdcnt: usize,
    leapcnt: usize,
    timecnt: usize,
    typecnt: usize,
    charcnt: usize,
}

fn header(b: &[u8], at: usize) -> Option<Header> {
    if b.get(at..at + 4)? != b"TZif" {
        return None;
    }
    let count = |k: usize| be_u32(b, at + 20 + 4 * k).map(|v| v as usize);
    Some(Header {
        version: *b.get(at + 4)?,
        isutcnt: count(0)?,
        isstdcnt: count(1)?,
        leapcnt: count(2)?,
        timecnt: count(3)?,
        typecnt: count(4)?,
        charcnt: count(5)?,
    })
}

impl Header {
    fn block_len(&self, time_size: usize) -> Option<usize> {
        self.timecnt
            .checked_mul(time_size + 1)?
            .checked_add(self.typecnt.checked_mul(6)?)?
            .checked_add(self.charcnt)?
            .checked_add(self.leapcnt.checked_mul(time_size + 4)?)?
            .checked_add(self.isstdcnt)?
            .checked_add(self.isutcnt)
    }
}

/// Parse a TZif file. Uses the 64-bit (v2+) block when present.
#[must_use]
pub fn parse_tzif(b: &[u8]) -> Option<Zone> {
    let h1 = header(b, 0)?;
    let v1_len = h1.block_len(4)?;
    let (h, data_at, time_size) = if h1.version >= b'2' {
        let at2 = 44usize.checked_add(v1_len)?;
        (header(b, at2)?, at2 + 44, 8usize)
    } else {
        (h1, 44usize, 4usize)
    };
    if h.typecnt == 0 || h.typecnt > 256 || h.charcnt == 0 {
        return None;
    }
    let block_len = h.block_len(time_size)?;
    let block = b.get(data_at..data_at.checked_add(block_len)?)?;

    let mut transitions = Vec::with_capacity(h.timecnt);
    for k in 0..h.timecnt {
        let t = if time_size == 8 {
            be_i64(block, k * 8)?
        } else {
            i64::from(be_i32(block, k * 4)?)
        };
        if transitions.last().is_some_and(|&prev| t <= prev) {
            return None;
        }
        transitions.push(t);
    }
    let idx_at = h.timecnt * time_size;
    let transition_types = block.get(idx_at..idx_at + h.timecnt)?.to_vec();
    if transition_types
        .iter()
        .any(|&i| usize::from(i) >= h.typecnt)
    {
        return None;
    }
    let tt_at = idx_at + h.timecnt;
    let chars_at = tt_at + h.typecnt * 6;
    let chars = block.get(chars_at..chars_at + h.charcnt)?;
    let mut types = Vec::with_capacity(h.typecnt);
    for k in 0..h.typecnt {
        let at = tt_at + k * 6;
        let utoff = be_i32(block, at)?;
        let isdst = *block.get(at + 4)? != 0;
        let desig = usize::from(*block.get(at + 5)?);
        let tail = chars.get(desig..)?;
        let end = tail.iter().position(|&c| c == 0).unwrap_or(tail.len());
        let abbr = String::from_utf8(tail[..end].to_vec()).ok()?;
        types.push(LocalType { utoff, isdst, abbr });
    }

    let footer = if time_size == 8 {
        let rest = b.get(data_at + block_len..)?;
        match rest {
            [b'\n', body @ ..] => {
                let end = body.iter().position(|&c| c == b'\n')?;
                let spec = &body[..end];
                if spec.is_empty() {
                    None
                } else {
                    parse_posix_tz(spec)
                }
            }
            _ => None,
        }
    } else {
        None
    };
    Some(Zone {
        transitions,
        transition_types,
        types,
        footer,
        fallback: LocalType::utc(),
        unnamed_dst: false,
    })
}

impl Zone {
    /// UTC with abbreviation `UTC`.
    #[must_use]
    pub fn utc() -> Self {
        Self::from_posix(PosixTz {
            std: LocalType::utc(),
            dst: None,
        })
    }

    /// UTC reported under `name`, with an empty `tzname[1]` — glibc's result
    /// for a `TZ` value that is neither a zone file nor a valid POSIX string
    /// (e.g. `TZ=""` becomes "Universal" when that file is absent).
    #[must_use]
    pub fn utc_named(name: &str) -> Self {
        let mut zone = Self::utc();
        zone.fallback = LocalType {
            utoff: 0,
            isdst: false,
            abbr: name.to_string(),
        };
        zone.footer = None;
        zone.unnamed_dst = true;
        zone
    }

    /// A zone defined only by a POSIX rule.
    #[must_use]
    pub fn from_posix(tz: PosixTz) -> Self {
        Self {
            transitions: Vec::new(),
            transition_types: Vec::new(),
            types: Vec::new(),
            footer: Some(tz),
            fallback: LocalType::utc(),
            unnamed_dst: false,
        }
    }

    fn first_standard_type(&self) -> Option<&LocalType> {
        self.types
            .iter()
            .find(|t| !t.isdst)
            .or_else(|| self.types.first())
    }

    /// The local-time type in effect at UTC instant `t`.
    #[must_use]
    pub fn lookup(&self, t: i64) -> &LocalType {
        if self.transitions.is_empty() || t < self.transitions[0] {
            if self.transitions.is_empty()
                && let Some(footer) = &self.footer
            {
                return footer.lookup(t);
            }
            return self.first_standard_type().unwrap_or(&self.fallback);
        }
        let last = *self.transitions.last().unwrap_or(&i64::MIN);
        if t >= last
            && let Some(footer) = &self.footer
        {
            return footer.lookup(t);
        }
        let idx = self.transitions.partition_point(|&x| x <= t) - 1;
        &self.types[usize::from(self.transition_types[idx])]
    }

    /// Every local-time type this zone can return from [`Self::lookup`], so
    /// callers can pre-intern abbreviations and map results by address.
    #[must_use]
    pub fn all_types(&self) -> Vec<&LocalType> {
        let mut out: Vec<&LocalType> = self.types.iter().collect();
        if let Some(footer) = &self.footer {
            out.push(&footer.std);
            if let Some(rule) = &footer.dst {
                out.push(&rule.dst);
            }
        }
        out.push(&self.fallback);
        out
    }

    /// Values for `tzname`, `timezone` and `daylight` (glibc semantics: the
    /// footer rule wins; otherwise the last standard/daylight types used).
    #[must_use]
    pub fn globals(&self) -> TzGlobals {
        if self.types.is_empty() {
            let mut g = self.footer.as_ref().map_or_else(
                || {
                    PosixTz {
                        std: self.fallback.clone(),
                        dst: None,
                    }
                    .globals()
                },
                PosixTz::globals,
            );
            if self.unnamed_dst {
                g.dst_abbr = String::new();
            }
            return g;
        }
        // glibc: names and offsets come from the most recent standard and
        // daylight transitions (falling back to the type list when a kind
        // never occurs in the transition table).
        let name_of = |want_dst: bool| {
            self.transition_types
                .iter()
                .rev()
                .map(|&i| &self.types[usize::from(i)])
                .chain(self.types.iter().rev())
                .find(|t| t.isdst == want_dst)
                .map(|t| t.abbr.clone())
        };
        let std_abbr = name_of(false).unwrap_or_default();
        let dst_abbr = name_of(true).unwrap_or_else(|| std_abbr.clone());
        let (mut std_off, mut dst_off) = (None, None);
        for &i in self.transition_types.iter().rev() {
            let ty = &self.types[usize::from(i)];
            if ty.isdst {
                dst_off.get_or_insert(ty.utoff);
            } else {
                std_off.get_or_insert(ty.utoff);
            }
            if std_off.is_some() && dst_off.is_some() {
                break;
            }
        }
        let std_off = std_off.or(dst_off).unwrap_or(self.types[0].utoff);
        let dst_off = dst_off.unwrap_or(std_off);
        TzGlobals {
            std_abbr,
            dst_abbr,
            timezone: -i64::from(std_off),
            daylight: std_off != dst_off,
        }
    }

    /// Resolve a local wall-clock time (`local` = seconds since the epoch as
    /// if the wall clock were UTC) to a UTC instant, glibc-`mktime` style.
    /// `isdst` is the caller's `tm_isdst` (<0 = unknown).
    ///
    /// `hint` is the offset used by the previous resolution: glibc's mktime
    /// starts its search from a process-wide "last offset" (initially 0), so
    /// which side of a repeated hour it lands on depends on call history.
    /// Returns the instant and the offset used, which the caller feeds back
    /// as the next hint.
    #[must_use]
    pub fn local_to_utc_with_hint(&self, local: i64, isdst: i32, hint: i32) -> (i64, i32) {
        let mut off = hint;
        let mut converged = None;
        for _ in 0..8 {
            let ty = self.lookup(local - i64::from(off));
            if ty.utoff == off {
                converged = Some(ty.isdst);
                break;
            }
            off = ty.utoff;
        }
        match converged {
            Some(found_dst) => {
                if isdst >= 0
                    && found_dst != (isdst > 0)
                    && let Some(alt) = self.consistent_offset(local, isdst > 0)
                {
                    return (local - i64::from(alt), alt);
                }
                if isdst >= 0
                    && found_dst != (isdst > 0)
                    && let Some(alt) = self.nearby_offset(local, isdst > 0)
                {
                    // The requested kind does not apply at this wall time:
                    // reinterpret the fields with that kind's offset.
                    return (local - i64::from(alt), alt);
                }
                (local - i64::from(off), off)
            }
            None => {
                // Skipped hour: interpret with the offset in force before the gap.
                let before = self.lookup(local - SECS_PER_DAY).utoff;
                (local - i64::from(before), before)
            }
        }
    }

    /// Stateless form of [`Self::local_to_utc_with_hint`] starting from 0.
    #[must_use]
    pub fn local_to_utc(&self, local: i64, isdst: i32) -> i64 {
        self.local_to_utc_with_hint(local, isdst, 0).0
    }

    /// An offset of the requested kind that is self-consistent at `local`
    /// (the other interpretation of a repeated hour).
    fn consistent_offset(&self, local: i64, want_dst: bool) -> Option<i32> {
        [local - SECS_PER_DAY, local, local + SECS_PER_DAY]
            .into_iter()
            .map(|probe| self.lookup(probe).utoff)
            .find(|&off| {
                let ty = self.lookup(local - i64::from(off));
                ty.utoff == off && ty.isdst == want_dst
            })
    }

    /// The offset of a type with the requested DST flag in force within about
    /// a year of `local`, if any.
    fn nearby_offset(&self, local: i64, want_dst: bool) -> Option<i32> {
        let step = 7 * SECS_PER_DAY;
        (0..=53).find_map(|k| {
            for probe in [local - k * step, local + k * step] {
                let ty = self.lookup(probe);
                if ty.isdst == want_dst {
                    return Some(ty.utoff);
                }
            }
            None
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(y: i64, mo: i64, d: i64, h: i64, mi: i64) -> i64 {
        days_from_civil(y, mo, d) * SECS_PER_DAY + h * 3600 + mi * 60
    }

    #[test]
    fn posix_us_eastern_rules() {
        let z = Zone::from_posix(parse_posix_tz(b"EST5EDT,M3.2.0,M11.1.0").unwrap());
        // 2023-11-14 22:13 UTC is 17:13 EST.
        let w = z.lookup(1_700_000_000);
        assert_eq!((w.utoff, w.isdst, w.abbr.as_str()), (-18_000, false, "EST"));
        let s = z.lookup(at(2023, 7, 1, 12, 0));
        assert_eq!((s.utoff, s.isdst, s.abbr.as_str()), (-14_400, true, "EDT"));
        // DST starts 2023-03-12 02:00 EST = 07:00 UTC.
        assert!(!z.lookup(at(2023, 3, 12, 6, 59)).isdst);
        assert!(z.lookup(at(2023, 3, 12, 7, 0)).isdst);
        // DST ends 2023-11-05 02:00 EDT = 06:00 UTC.
        assert!(z.lookup(at(2023, 11, 5, 5, 59)).isdst);
        assert!(!z.lookup(at(2023, 11, 5, 6, 0)).isdst);
    }

    #[test]
    fn posix_southern_hemisphere_and_quoted_names() {
        let z = Zone::from_posix(parse_posix_tz(b"AEST-10AEDT,M10.1.0,M4.1.0/3").unwrap());
        assert!(z.lookup(at(2023, 1, 15, 0, 0)).isdst);
        assert!(!z.lookup(at(2023, 7, 15, 0, 0)).isdst);
        let q = parse_posix_tz(b"<+0530>-5:30").unwrap();
        assert_eq!((q.std.utoff, q.std.abbr.as_str()), (19_800, "+0530"));
        assert!(q.dst.is_none());
    }

    #[test]
    fn posix_rejects_malformed() {
        for bad in [
            &b""[..],
            b"E",
            b"EST",
            b"EST5EDT,M13.1.0,M1.1.0",
            b"EST5EDT,J0,J1",
            b"EST5x",
        ] {
            assert!(
                parse_posix_tz(bad).is_none(),
                "{:?}",
                std::str::from_utf8(bad)
            );
        }
    }

    #[test]
    fn rule_dates() {
        // Second Sunday of March 2023 is the 12th; last Sunday of Oct 2023 the 29th.
        let m = RuleDate::MonthWeekDay {
            month: 3,
            week: 2,
            weekday: 0,
        };
        assert_eq!(m.day_in_year(2023), days_from_civil(2023, 3, 12));
        let last = RuleDate::MonthWeekDay {
            month: 10,
            week: 5,
            weekday: 0,
        };
        assert_eq!(last.day_in_year(2023), days_from_civil(2023, 10, 29));
        // J60 is March 1 in every year; 59 (zero-based) is Feb 29 in leap years.
        assert_eq!(
            RuleDate::Julian1(60).day_in_year(2024),
            days_from_civil(2024, 3, 1)
        );
        assert_eq!(
            RuleDate::Julian0(59).day_in_year(2024),
            days_from_civil(2024, 2, 29)
        );
    }

    #[test]
    fn mktime_gap_overlap_and_isdst_hint() {
        let z = Zone::from_posix(parse_posix_tz(b"EST5EDT,M3.2.0,M11.1.0").unwrap());
        // Ordinary summer time.
        assert_eq!(
            z.local_to_utc(at(2023, 7, 1, 12, 0), -1),
            at(2023, 7, 1, 16, 0)
        );
        // Skipped 02:30 on 2023-03-12 resolves with the pre-gap (EST) offset.
        assert_eq!(
            z.local_to_utc(at(2023, 3, 12, 2, 30), -1),
            at(2023, 3, 12, 7, 30)
        );
        // Repeated 01:30 on 2023-11-05: isdst picks the interpretation.
        assert_eq!(
            z.local_to_utc(at(2023, 11, 5, 1, 30), 1),
            at(2023, 11, 5, 5, 30)
        );
        assert_eq!(
            z.local_to_utc(at(2023, 11, 5, 1, 30), 0),
            at(2023, 11, 5, 6, 30)
        );
    }

    #[test]
    fn tzif_system_zone_if_present() {
        let Ok(bytes) = std::fs::read("/usr/share/zoneinfo/America/New_York") else {
            return; // tzdata not installed on this runner
        };
        let z = parse_tzif(&bytes).expect("valid TZif");
        let w = z.lookup(1_700_000_000);
        assert_eq!((w.utoff, w.isdst, w.abbr.as_str()), (-18_000, false, "EST"));
        // Far future comes from the footer rule.
        assert!(z.lookup(at(2100, 7, 1, 12, 0)).isdst);
        // Before standard time (1883) New York used local mean time (LMT).
        assert_eq!(z.lookup(-3_000_000_000).abbr, "LMT");
        let g = z.globals();
        assert_eq!(
            (
                g.std_abbr.as_str(),
                g.dst_abbr.as_str(),
                g.timezone,
                g.daylight
            ),
            ("EST", "EDT", 18_000, true)
        );
    }

    #[test]
    fn tzif_rejects_truncated_and_bad_magic() {
        assert!(parse_tzif(b"").is_none());
        assert!(parse_tzif(b"TZjf2").is_none());
        let mut h = b"TZif2".to_vec();
        h.resize(44, 0);
        assert!(parse_tzif(&h).is_none(), "typecnt 0 must be rejected");
    }
}
