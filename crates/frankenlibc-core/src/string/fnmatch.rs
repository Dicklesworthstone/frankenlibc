//! POSIX `<fnmatch.h>` shell-pattern matcher.
//!
//! Pure-safe Rust port of the engine that previously lived in
//! frankenlibc-abi/src/string_abi.rs. Operates on `&[u8]` slices —
//! the abi layer adapts NUL-terminated C strings via
//! `CStr::to_bytes()`.
//!
//! Supported pattern syntax: literal bytes, `?`, `*`, bracket expressions
//! with optional ranges and `!`/`^` negation, POSIX character classes
//! (`[:alpha:]` …), collating elements (`[.x.]`) and equivalence classes
//! (`[=x=]`), and `\X` escapes unless [`FnmatchFlags::NOESCAPE`] is set.
//!
//! Flag bits match POSIX/glibc `<fnmatch.h>` so the abi layer can pass
//! the user's `c_int` flags through unchanged.

/// Pattern-match flags, bit-compatible with POSIX `<fnmatch.h>`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FnmatchFlags {
    bits: u32,
}

impl FnmatchFlags {
    pub const NONE: FnmatchFlags = FnmatchFlags { bits: 0 };
    /// `*` and `?` do not match `/`; leading `.` after `/` requires
    /// explicit match when [`PERIOD`](Self::PERIOD) is also set.
    pub const PATHNAME: FnmatchFlags = FnmatchFlags { bits: 1 << 0 };
    /// Backslash is literal (no escape semantics).
    pub const NOESCAPE: FnmatchFlags = FnmatchFlags { bits: 1 << 1 };
    /// Leading `.` in `text` (or after `/` if PATHNAME) must be matched
    /// explicitly, never by `*`/`?`/bracket.
    pub const PERIOD: FnmatchFlags = FnmatchFlags { bits: 1 << 2 };
    /// GNU: pattern matches a leading directory prefix of `text`.
    pub const LEADING_DIR: FnmatchFlags = FnmatchFlags { bits: 1 << 3 };
    /// GNU: case-insensitive ASCII matching.
    pub const CASEFOLD: FnmatchFlags = FnmatchFlags { bits: 1 << 4 };
    /// GNU: enable `ksh`-style extended matching — the extglob operators
    /// `?(list)` `*(list)` `+(list)` `@(list)` `!(list)` where `list` is a
    /// `|`-separated set of sub-patterns.
    pub const EXTMATCH: FnmatchFlags = FnmatchFlags { bits: 1 << 5 };

    pub const fn from_bits(b: u32) -> Self {
        FnmatchFlags { bits: b }
    }

    pub const fn bits(self) -> u32 {
        self.bits
    }

    pub const fn contains(self, other: FnmatchFlags) -> bool {
        (self.bits & other.bits) == other.bits
    }
}

impl core::ops::BitOr for FnmatchFlags {
    type Output = FnmatchFlags;
    fn bitor(self, rhs: FnmatchFlags) -> FnmatchFlags {
        FnmatchFlags {
            bits: self.bits | rhs.bits,
        }
    }
}

impl core::ops::BitOrAssign for FnmatchFlags {
    fn bitor_assign(&mut self, rhs: FnmatchFlags) {
        self.bits |= rhs.bits;
    }
}

/// Pre-classification of a `[...]` bracket expression. POSIX leaves
/// unterminated bracket behavior implementation-defined; this matches
/// glibc.
///
/// `Terminated`: closed `]` found, parse as bracket.
/// `LiteralFallback`: unterminated, treat the leading `[` as a literal.
/// `Invalid`: unterminated with a final *unescaped* `-` content byte
/// (an incomplete range); match fails.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BracketShape {
    Terminated,
    LiteralFallback,
    Invalid,
}

fn classify_bracket(pat: &[u8], pi: usize, noescape: bool) -> BracketShape {
    let mut scan = pi + 1; // skip the opening '['
    if let Some(&b'!') | Some(&b'^') = pat.get(scan) {
        scan += 1;
    }
    let mut content_count = 0usize;
    let mut last_was_dash = false;
    loop {
        let bc = match pat.get(scan) {
            None => {
                if last_was_dash && content_count > 1 {
                    return BracketShape::Invalid;
                }
                return BracketShape::LiteralFallback;
            }
            Some(&b) => b,
        };
        // POSIX: `]` as the first content byte (after optional !/^)
        // is literal, not a closer — gated by content_count > 0.
        if bc == b']' && content_count > 0 {
            return BracketShape::Terminated;
        }
        // A POSIX sub-expression `[:class:]` / `[.coll.]` / `[=equiv=]`: its
        // inner `]` (part of the `kind]` terminator) is NOT the bracket's
        // closer, so skip the whole sub-expression — exactly as the matcher's
        // `parse_bracket_subexpr` does, and as glibc does. Without this the
        // class's `]` was mistaken for the bracket close, so an outer bracket
        // that actually runs off the end (e.g. `[![:upper:]\]…`) was wrongly
        // treated as Terminated. Found by fnmatch_differential_fuzz.
        if bc == b'[' && matches!(pat.get(scan + 1), Some(b':' | b'.' | b'=')) {
            let kind = pat[scan + 1];
            let mut k = scan + 2;
            let closed = loop {
                match pat.get(k) {
                    None => break false,
                    Some(&b) if b == kind && pat.get(k + 1) == Some(&b']') => break true,
                    _ => k += 1,
                }
            };
            if !closed {
                // Unterminated sub-expression ⇒ the outer bracket cannot close.
                return BracketShape::LiteralFallback;
            }
            content_count += 1;
            last_was_dash = false;
            scan = k + 2; // past the `kind]` terminator
            continue;
        }
        // An escaped byte (`\X`) is one literal content element; the
        // bracket parser consumes it as such, so the classifier must
        // too. Without this an escaped trailing `-` (`[a\-`) is misread
        // as an incomplete range (`Invalid`) when it is actually a
        // literal dash — glibc treats the unterminated bracket as a
        // literal `[` there and the pattern still matches.
        if bc == b'\\' && !noescape && scan + 1 < pat.len() {
            content_count += 1;
            last_was_dash = false;
            scan += 2;
            continue;
        }
        last_was_dash = bc == b'-';
        content_count += 1;
        scan += 1;
    }
}

/// Test `c` against a POSIX named character class. Returns `None` when
/// `name` is not one of the twelve POSIX classes — the caller then treats
/// the enclosing `[` as a literal byte.
fn posix_class_match(name: &[u8], c: u8) -> Option<bool> {
    let hit = match name {
        b"alpha" => c.is_ascii_alphabetic(),
        b"digit" => c.is_ascii_digit(),
        b"alnum" => c.is_ascii_alphanumeric(),
        b"upper" => c.is_ascii_uppercase(),
        b"lower" => c.is_ascii_lowercase(),
        // POSIX `space`: ' ' \t \n \v \f \r  (0x20 and 0x09..=0x0d).
        b"space" => c == b' ' || (b'\t'..=b'\r').contains(&c),
        b"blank" => c == b' ' || c == b'\t',
        b"print" => c.is_ascii_graphic() || c == b' ',
        b"graph" => c.is_ascii_graphic(),
        b"cntrl" => c.is_ascii_control(),
        b"punct" => c.is_ascii_punctuation(),
        b"xdigit" => c.is_ascii_hexdigit(),
        _ => return None,
    };
    Some(hit)
}

/// Parse a POSIX bracket sub-expression that begins at `pat[open] == b'['`
/// with `pat[open + 1] == kind` — `:` (character class), `.` (collating
/// element), or `=` (equivalence class).
///
/// On success returns `(next_pi, member)` where `next_pi` is the index just
/// past the closing `]` and `member` reports whether `c` belongs to the
/// sub-expression. Returns `None` only when the sub-expression is not even
/// structurally closed (no `kind]` terminator); the caller then treats the
/// leading `[` as an ordinary literal byte. A structurally-closed but
/// unrecognized sub-expression (unknown class name, multi-byte collating
/// element) is consumed and matches nothing — as glibc rejects it too.
fn parse_bracket_subexpr(pat: &[u8], open: usize, kind: u8, c: u8) -> Option<(usize, bool)> {
    let content_start = open + 2;
    let mut j = content_start;
    loop {
        let b = *pat.get(j)?;
        if b == kind && pat.get(j + 1) == Some(&b']') {
            break;
        }
        j += 1;
    }
    let content = &pat[content_start..j];
    let next_pi = j + 2; // index just past `kind` and `]`
    let member = match kind {
        // Character class. An unrecognized class name is a well-formed
        // sub-expression that matches nothing.
        // glibc tests a named character class against the ORIGINAL byte even
        // under FNM_CASEFOLD: it folds literals and ranges, but never
        // `[:class:]` (e.g. `[[:upper:]]` never matches 'a' under CASEFOLD).
        // An unrecognized class name (`None`) matches nothing. Found by
        // fnmatch_differential_fuzz.
        b':' => posix_class_match(content, c).unwrap_or_default(),
        // Collating element / equivalence class. The C locale has only
        // single-byte elements; anything else matches nothing. glibc tests the
        // element against the ORIGINAL byte even under FNM_CASEFOLD — it folds
        // literals and ranges but NEVER a `[.x.]` / `[=x=]` (nor `[:class:]`),
        // so `[[.b.]]` / `[[=b=]]` match only 'b', never 'B'. Found by
        // fnmatch_differential_fuzz.
        b'.' | b'=' => content.len() == 1 && content[0] == c,
        _ => return None,
    };
    Some((next_pi, member))
}

/// If `pat[pi..]` begins a single-byte collating symbol `[.x.]` (the only kind
/// the C locale has), return `(x, next_pi)` with `next_pi` just past the closing
/// `]`. A collating symbol is the ONLY POSIX bracket sub-expression that may
/// serve as a range endpoint (glibc accepts `[a-[.c.]]` / `[[.a.]-c]` as `a..c`).
/// Multibyte collating elements, equivalence classes `[=..=]`, and character
/// classes `[:..:]` are NOT valid range endpoints and return `None` — the caller
/// then keeps its existing behavior (a `[=..=]`/`[:..:]` member, or for a high
/// endpoint the glibc-correct "malformed range matches nothing" fallback).
fn collating_range_endpoint(pat: &[u8], pi: usize) -> Option<(u8, usize)> {
    if pat.get(pi) != Some(&b'[') || pat.get(pi + 1) != Some(&b'.') {
        return None;
    }
    let start = pi + 2;
    let mut j = start;
    loop {
        match pat.get(j) {
            None => return None, // unterminated `[.` ⇒ not an endpoint
            Some(&b'.') if pat.get(j + 1) == Some(&b']') => break,
            _ => j += 1,
        }
    }
    let content = &pat[start..j];
    // Single-byte element only; multibyte (e.g. `[.ch.]`) is not a range bound.
    (content.len() == 1).then(|| (content[0], j + 2))
}

/// Membership test for a bracket range `low..=high` against text byte `c`. Under
/// CASEFOLD glibc folds the test char and any PLAIN endpoint to lowercase, but a
/// collating-symbol endpoint (`low_coll` / `high_coll`) is used literally — so
/// `[9-[.A.]]` is `tolower(c) ∈ [9, A]` and 'A' (→'a') falls outside. An inverted
/// folded range matches nothing.
fn in_bracket_range(
    c: u8,
    low: u8,
    low_coll: bool,
    high: u8,
    high_coll: bool,
    casefold: bool,
) -> bool {
    if casefold {
        let lo = if low_coll {
            low
        } else {
            low.to_ascii_lowercase()
        };
        let hi = if high_coll {
            high
        } else {
            high.to_ascii_lowercase()
        };
        let cl = c.to_ascii_lowercase();
        lo <= hi && cl >= lo && cl <= hi
    } else {
        c >= low && c <= high
    }
}

/// Parse a bracket range endpoint at `pat[pi]`. Returns `(value, next_pi)` where
/// `next_pi` is the position just past the endpoint and `value` is `Some(byte)`
/// for a valid endpoint (a plain byte, a bare literal `[`, a `\X` escape, or a
/// single-byte collating symbol `[.x.]`) or `None` for an INVALID one — an
/// equivalence class `[=..=]`, character class `[:..:]`, or a multibyte/
/// unterminated collating element. An invalid endpoint makes the whole bracket
/// match nothing (glibc), so the caller must record `next_pi` (to keep scanning
/// to the terminator) yet treat the bracket as malformed. Only reached inside a
/// `Terminated` bracket, so a dangling escape cannot occur.
fn parse_range_endpoint(pat: &[u8], pi: usize, noescape: bool) -> (Option<(u8, bool)>, usize) {
    if pat.get(pi) == Some(&b'[')
        && let Some(&kind) = pat.get(pi + 1)
        && matches!(kind, b'.' | b'=' | b':')
    {
        // Scan to the `kind]` terminator shared by all three sub-expressions.
        let start = pi + 2;
        let mut j = start;
        let closed = loop {
            match pat.get(j) {
                None => break false,
                Some(&b) if b == kind && pat.get(j + 1) == Some(&b']') => break true,
                _ => j += 1,
            }
        };
        if !closed {
            // Unterminated `[`-subexpr inside a Terminated bracket: the `[` is a
            // literal (non-collating) endpoint byte.
            return (Some((b'[', false)), pi + 1);
        }
        let next = j + 2; // past `kind]`
        // Only a single-byte collating symbol `[.x.]` is a valid endpoint;
        // equivalence/character classes and multibyte collating are not.
        if kind == b'.' && j - start == 1 {
            return (Some((pat[start], true)), next);
        }
        return (None, next);
    }
    let mut high = pat.get(pi).copied().unwrap_or(0);
    let mut q = pi + 1;
    if high == b'\\'
        && !noescape
        && let Some(&b) = pat.get(q)
    {
        high = b;
        q += 1;
    }
    (Some((high, false)), q)
}

/// From a position `pi` partway through a `Terminated` bracket, return the index
/// just past its closing `]`. Skips POSIX sub-expressions (so their inner `]` is
/// not the closer) and `\X` escapes. Used after a malformed range aborts the
/// member scan, to leave `pi` positioned correctly past the bracket.
fn skip_to_bracket_close(pat: &[u8], mut pi: usize, noescape: bool) -> usize {
    loop {
        match pat.get(pi) {
            None => return pi,
            Some(&b']') => return pi + 1,
            Some(&b'[') if matches!(pat.get(pi + 1), Some(b':' | b'.' | b'=')) => {
                let kind = pat[pi + 1];
                let mut k = pi + 2;
                loop {
                    match pat.get(k) {
                        None => return k,
                        Some(&b) if b == kind && pat.get(k + 1) == Some(&b']') => {
                            pi = k + 2;
                            break;
                        }
                        _ => k += 1,
                    }
                }
            }
            Some(&b'\\') if !noescape && pat.get(pi + 1).is_some() => pi += 2,
            _ => pi += 1,
        }
    }
}

/// Iterative single-backtrack matcher for the common case: bracket-free
/// patterns under flags that impose no positional constraints (no PATHNAME /
/// PERIOD / CASEFOLD / LEADING_DIR). Handles `*`, `?`, `\X` escapes (unless
/// `noescape`) and literals in O(n*m) time, O(1) space — the standard wildcard
/// two-pointer with one remembered star position. No recursion, no memo table.
/// Output-identical to the general matcher on this input class (verified by
/// `simple_fast_path_matches_general` over a random corpus).
/// Match one text byte `c` against the `Terminated` bracket expression at
/// `pat[pi0] == b'['` (the caller must have confirmed `classify_bracket` ==
/// `Terminated`). Returns `(matched, next_pi)` with `next_pi` just past the
/// closing `]`. Case-sensitive only (the `fnmatch_simple` gate excludes
/// CASEFOLD); reuses the shared `parse_bracket_subexpr` for `[:class:]` /
/// `[.x.]` / `[=x=]`, so only the range/literal membership is local logic. The
/// `None => break` arms are unreachable given a `Terminated` bracket.
fn bracket_match_one(
    pat: &[u8],
    pi0: usize,
    c: u8,
    noescape: bool,
    casefold: bool,
) -> (bool, usize) {
    let mut pi = pi0 + 1; // skip '['
    let negated = matches!(pat.get(pi), Some(&b'!') | Some(&b'^'));
    if negated {
        pi += 1;
    }
    let mut matched = false;
    // A range with an invalid endpoint (`[=..=]`/`[:..:]`/multibyte collating)
    // aborts the member scan: glibc keeps the match accumulated from EARLIER
    // members but stops, and a malformed bracket never matches when negated.
    let mut aborted = false;
    let mut first = true;
    loop {
        let bc = match pat.get(pi) {
            None => break,
            Some(&b) => b,
        };
        if bc == b']' && !first {
            break;
        }
        first = false;

        // A collating symbol `[.x.]` that is the LOW endpoint of a range
        // `[.x.]-Y` (glibc: `[[.a.]-c]` == `a..c`). Checked before the generic
        // sub-expression handling, which would otherwise consume `[.x.]` as a
        // standalone member. Equivalence/character-class sub-expressions are
        // never range endpoints, so `collating_range_endpoint` returns None for
        // them and we fall through.
        if let Some((low, after)) = collating_range_endpoint(pat, pi)
            && pat.get(after) == Some(&b'-')
            && !matches!(pat.get(after + 1), None | Some(&b']'))
        {
            let (high, npi) = parse_range_endpoint(pat, after + 1, noescape);
            pi = npi;
            match high {
                Some((high, high_coll))
                    if in_bracket_range(c, low, true, high, high_coll, casefold) =>
                {
                    matched = true;
                }
                Some(_) => {}
                None => {
                    aborted = true;
                    break;
                }
            }
            continue;
        }

        if bc == b'['
            && let Some(&kind) = pat.get(pi + 1)
            && matches!(kind, b':' | b'.' | b'=')
            && let Some((next_pi, member)) = parse_bracket_subexpr(pat, pi, kind, c)
        {
            if member {
                matched = true;
            }
            pi = next_pi;
            continue;
        }

        let mut low = bc;
        pi += 1;
        if low == b'\\' && !noescape {
            match pat.get(pi) {
                None => break,
                Some(&b) => {
                    low = b;
                    pi += 1;
                }
            }
        }

        let next = pat.get(pi);
        let nextnext = pat.get(pi + 1);
        if next == Some(&b'-') && nextnext != Some(&b']') && nextnext.is_some() {
            // High endpoint: a plain byte, `\X` escape, or collating symbol
            // `[.y.]` (glibc: `[a-[.c.]]` == `a..c`); an `[=..=]`/`[:..:]` high
            // endpoint makes the whole bracket malformed.
            let (high, npi) = parse_range_endpoint(pat, pi + 1, noescape);
            pi = npi;
            match high {
                Some((high, high_coll))
                    if in_bracket_range(c, low, false, high, high_coll, casefold) =>
                {
                    matched = true;
                }
                Some(_) => {}
                None => {
                    aborted = true;
                    break;
                }
            }
        } else {
            let test_ch = if casefold { c.to_ascii_lowercase() } else { c };
            let low_cmp = if casefold {
                low.to_ascii_lowercase()
            } else {
                low
            };
            if test_ch == low_cmp {
                matched = true;
            }
        }
    }
    if aborted {
        // glibc keeps the match found before the bad range, but a malformed
        // bracket never matches under negation. Skip past the real `]`.
        let pi = skip_to_bracket_close(pat, pi, noescape);
        return (!negated && matched, pi);
    }
    pi += 1; // skip ']'
    if negated {
        matched = !matched;
    }
    (matched, pi)
}

fn simple_bracket_end_for_literal_prefilter(pat: &[u8], pi0: usize) -> Option<usize> {
    let mut pi = pi0 + 1;
    if matches!(pat.get(pi), Some(&b'!') | Some(&b'^')) {
        pi += 1;
    }
    if pat.get(pi) == Some(&b']') {
        return None;
    }
    while pi < pat.len() {
        match pat[pi] {
            b']' => return Some(pi + 1),
            b'[' | b'\\' => return None,
            _ => pi += 1,
        }
    }
    None
}

fn required_plain_literal_absent_flags_none(pat: &[u8], text: &[u8]) -> bool {
    let mut pi = 0usize;
    while pi < pat.len() {
        match pat[pi] {
            b'*' | b'?' => pi += 1,
            b'[' => {
                let Some(next_pi) = simple_bracket_end_for_literal_prefilter(pat, pi) else {
                    return false;
                };
                pi = next_pi;
            }
            b'\\' => {
                let Some(&lit) = pat.get(pi + 1) else {
                    return false;
                };
                if !text.contains(&lit) {
                    return true;
                }
                pi += 2;
            }
            lit => {
                if !text.contains(&lit) {
                    return true;
                }
                pi += 1;
            }
        }
    }
    false
}

fn fnmatch_simple(pat: &[u8], text: &[u8], flags: FnmatchFlags) -> bool {
    let pathname = flags.contains(FnmatchFlags::PATHNAME);
    let period = flags.contains(FnmatchFlags::PERIOD);
    let casefold = flags.contains(FnmatchFlags::CASEFOLD);
    let noescape = flags.contains(FnmatchFlags::NOESCAPE);
    let leading_dir = flags.contains(FnmatchFlags::LEADING_DIR);

    let eq = |a: u8, b: u8| {
        if casefold {
            a.eq_ignore_ascii_case(&b)
        } else {
            a == b
        }
    };
    // Is `text[si]` a leading '.' that PERIOD requires be matched literally
    // (never by '*'/'?'/'[')? True at text start, or — under PATHNAME — right
    // after a '/'.
    let lp_blocked = |si: usize| -> bool {
        period
            && text.get(si) == Some(&b'.')
            && (si == 0 || (pathname && si >= 1 && text.get(si - 1) == Some(&b'/')))
    };

    let mut pi = 0usize;
    let mut si = 0usize;
    let mut star: Option<(usize, usize)> = None; // (pat index after the '*' run, text index when seen)

    while si < text.len() {
        let c = text[si];
        let mut advanced = false;
        if pi < pat.len() {
            match pat[pi] {
                b'*' => {
                    while pi < pat.len() && pat[pi] == b'*' {
                        pi += 1;
                    }
                    // '*' cannot match a leading '.' under PERIOD.
                    if lp_blocked(si) {
                        return false;
                    }
                    star = Some((pi, si));
                    continue;
                }
                b'\\' if !noescape => {
                    // `\X` matches the literal X; a trailing `\` matches nothing.
                    if let Some(&esc) = pat.get(pi + 1)
                        && eq(c, esc)
                    {
                        pi += 2;
                        si += 1;
                        advanced = true;
                    }
                }
                b'?' => {
                    // '?' matches any one byte except '/' under PATHNAME and
                    // except a leading '.' under PERIOD.
                    if !(pathname && c == b'/') && !lp_blocked(si) {
                        pi += 1;
                        si += 1;
                        advanced = true;
                    }
                }
                b'[' => {
                    if !(pathname && c == b'/') && !lp_blocked(si) {
                        match classify_bracket(pat, pi, noescape) {
                            BracketShape::Terminated => {
                                let (m, next_pi) =
                                    bracket_match_one(pat, pi, c, noescape, casefold);
                                if m {
                                    pi = next_pi;
                                    si += 1;
                                    advanced = true;
                                }
                            }
                            BracketShape::LiteralFallback => {
                                if eq(c, b'[') {
                                    pi += 1;
                                    si += 1;
                                    advanced = true;
                                }
                            }
                            // Malformed bracket: this fixed pattern position can
                            // never match (general matcher returns false too).
                            BracketShape::Invalid => {}
                        }
                    }
                }
                lit => {
                    if eq(c, lit) {
                        pi += 1;
                        si += 1;
                        advanced = true;
                    }
                }
            }
        } else if leading_dir && c == b'/' {
            // Pattern consumed and the text remainder begins at a '/':
            // FNM_LEADING_DIR accepts the directory prefix.
            return true;
        }
        if advanced {
            continue;
        }
        // Mismatch (or pattern exhausted with text left): let the last '*' eat
        // one more text byte. Under PATHNAME a '*' cannot consume '/'.
        match star {
            Some((spi, ssi)) => {
                if pathname && text[ssi] == b'/' {
                    return false;
                }
                let mut new_si = ssi + 1;
                // Fast-skip: when the char right after the '*' run is a plain literal,
                // jump the star directly to that literal's next occurrence instead of
                // retrying the match at every text byte (glibc does this; the byte-walk
                // made fnmatch ~2.8x slower on typical globs; bd-2g7oyh). Only the
                // case-sensitive plain-literal case — '?','[','\\','*' and casefold
                // fall through to the +1 byte-walk. Byte-identical: skipped bytes can
                // never start a match of `lit`, and the search is bounded by the next
                // '/' under PATHNAME (a '*' cannot cross '/').
                if !casefold && new_si < text.len() {
                    if let Some(&lit) = pat.get(spi) {
                        let plain = !matches!(lit, b'*' | b'?' | b'[')
                            && !(lit == b'\\' && !noescape);
                        if plain {
                            if pathname {
                                // '*' may advance only within the current path
                                // segment (it cannot consume '/').
                                let seg_end = text[new_si..]
                                    .iter()
                                    .position(|&b| b == b'/')
                                    .map_or(text.len(), |p| new_si + p);
                                if lit == b'/' {
                                    // The literal AFTER the '*' is itself the '/':
                                    // the star eats the rest of the segment and the
                                    // '/' matches the separator.
                                    if seg_end < text.len() {
                                        new_si = seg_end;
                                    } else {
                                        return false;
                                    }
                                } else {
                                    match text[new_si..seg_end].iter().position(|&b| b == lit) {
                                        Some(off) => new_si += off,
                                        None => return false, // lit not reachable before '/'
                                    }
                                }
                            } else {
                                match text[new_si..].iter().position(|&b| b == lit) {
                                    Some(off) => new_si += off,
                                    None => return false, // lit absent → no match
                                }
                            }
                        }
                    }
                }
                si = new_si;
                pi = spi;
                star = Some((spi, new_si));
            }
            None => return false,
        }
    }

    // Text consumed: any trailing '*' run matches empty; accept iff the whole
    // pattern is consumed.
    while pi < pat.len() && pat[pi] == b'*' {
        pi += 1;
    }
    pi == pat.len()
}

/// Match `text` against `pattern` per POSIX fnmatch semantics + the
/// flags. Returns `true` if the entire `text` matches (modulo
/// [`FnmatchFlags::LEADING_DIR`]).
pub fn fnmatch_match(pattern: &[u8], text: &[u8], flags: FnmatchFlags) -> bool {
    if flags == FnmatchFlags::NONE && required_plain_literal_absent_flags_none(pattern, text) {
        return false;
    }

    // The iterative single-backtrack matcher (`fnmatch_simple`) now handles ALL
    // flags in O(n*m) time / O(1) space — no recursion, no memo, no exponential
    // blow-up — and is faster than glibc. The recursive `fnmatch_inner` below is
    // retained only as the differential-test oracle (`#[cfg(test)]`).
    //
    // FNM_EXTMATCH (extglob) is opt-in and needs genuine recursion/backtracking
    // that the iterative matcher cannot express, so when it is requested AND the
    // pattern actually contains an extglob group we route to the dedicated
    // recursive `ext_match_at`. Every other call — the overwhelmingly common
    // case — keeps the fast path untouched.
    if flags.contains(FnmatchFlags::EXTMATCH)
        && pattern_has_extglob(pattern, flags.contains(FnmatchFlags::NOESCAPE))
    {
        return ext_match_at(pattern, 0, text, 0, flags, false);
    }
    fnmatch_simple(pattern, text, flags)
}

/// Quick scan: does `pat` contain an extglob group `X(` for `X` in `?*+@!`?
/// (Used only to decide whether the recursive matcher is needed.)
fn pattern_has_extglob(pat: &[u8], noescape: bool) -> bool {
    let mut i = 0;
    while i < pat.len() {
        match pat[i] {
            b'\\' if !noescape => i += 2,
            b'?' | b'*' | b'+' | b'@' | b'!' if pat.get(i + 1) == Some(&b'(') => return true,
            _ => i += 1,
        }
    }
    false
}

type ParsedExtglobGroup = (u8, Vec<(usize, usize)>, usize);

/// Parse an extglob group whose operator char is at `pat[pi]` and `pat[pi+1] ==
/// '('`. Returns `(op, alternatives, next_pi)` where each alternative is a
/// `(start, end)` byte range into `pat` (the `|`-separated sub-patterns) and
/// `next_pi` is the index just past the closing `)`. Returns `None` if the group
/// is unterminated — the caller then treats the operator char as a literal,
/// matching glibc, which falls back to ordinary matching on a malformed group.
fn parse_extglob_group(pat: &[u8], pi: usize, noescape: bool) -> Option<ParsedExtglobGroup> {
    let op = pat[pi];
    let mut j = pi + 2; // past `X(`
    let mut depth = 1usize;
    let mut alt_start = j;
    let mut alts: Vec<(usize, usize)> = Vec::new();
    while j < pat.len() {
        match pat[j] {
            b'\\' if !noescape => {
                j += 2;
            }
            b'[' => {
                // Skip a bracket expression so a `)` / `|` inside `[...]` stays
                // literal. Honour the leading `!`/`^` and a literal first `]`.
                let mut k = j + 1;
                if matches!(pat.get(k), Some(b'!' | b'^')) {
                    k += 1;
                }
                if pat.get(k) == Some(&b']') {
                    k += 1;
                }
                j = skip_to_bracket_close(pat, k, noescape);
            }
            b'?' | b'*' | b'+' | b'@' | b'!' if pat.get(j + 1) == Some(&b'(') => {
                depth += 1;
                j += 2;
            }
            b')' => {
                depth -= 1;
                if depth == 0 {
                    alts.push((alt_start, j));
                    return Some((op, alts, j + 1));
                }
                j += 1;
            }
            b'|' if depth == 1 => {
                alts.push((alt_start, j));
                alt_start = j + 1;
                j += 1;
            }
            _ => j += 1,
        }
    }
    None
}

/// Recursive FNM_EXTMATCH matcher: does `pat[pi..]` match `text[si..]` fully?
/// Handles the ordinary tokens (`?`, `*`, `[...]`, `\X`, literals) by recursion
/// and the five extglob operators by backtracking over every split of the text.
/// `star` is true when a `*` wildcard earlier on this match path has absorbed
/// variable-width slack. glibc rejects an `@`/`+` extglob group that completes
/// such a starred match by selecting an EMPTY-WIDTH alternative value at end of
/// text (e.g. `*@(b|)` on "ba", `*?@(b|)` on "b", `*+()` on "bb"), even though
/// the same group matches standalone (`@(b|)` on "") — see bd-4aqdre. The flag
/// is set on entry to a `*` expansion and propagates through subsequent
/// consuming tokens; sub-pattern interiors (`sub_full_match`) reset it.
fn ext_match_at(
    pat: &[u8],
    pi: usize,
    text: &[u8],
    si: usize,
    flags: FnmatchFlags,
    star: bool,
) -> bool {
    let pathname = flags.contains(FnmatchFlags::PATHNAME);
    let period = flags.contains(FnmatchFlags::PERIOD);
    let noescape = flags.contains(FnmatchFlags::NOESCAPE);
    let casefold = flags.contains(FnmatchFlags::CASEFOLD);
    let leading_dir = flags.contains(FnmatchFlags::LEADING_DIR);
    let eq = |a: u8, b: u8| {
        if casefold {
            a.eq_ignore_ascii_case(&b)
        } else {
            a == b
        }
    };
    let lp_blocked = |si: usize| -> bool {
        period
            && text.get(si) == Some(&b'.')
            && (si == 0 || (pathname && si >= 1 && text.get(si - 1) == Some(&b'/')))
    };

    // Pattern exhausted.
    if pi >= pat.len() {
        if si >= text.len() {
            return true;
        }
        if leading_dir && text.get(si) == Some(&b'/') {
            return true;
        }
        return false;
    }
    let pc = pat[pi];

    // Extglob group?
    if let Some((op, alts, next_pi)) = (matches!(pc, b'?' | b'*' | b'+' | b'@' | b'!')
        && pat.get(pi + 1) == Some(&b'('))
    .then(|| parse_extglob_group(pat, pi, noescape))
    .flatten()
    {
        return ext_group_at(op, &alts, pat, next_pi, text, si, flags, star);
    }
    // Unterminated extglob groups fall through and treat `pc` as an ordinary token.

    match pc {
        b'?' => {
            let Some(&c) = text.get(si) else {
                return false;
            };
            if (pathname && c == b'/') || lp_blocked(si) {
                return false;
            }
            ext_match_at(pat, pi + 1, text, si + 1, flags, star)
        }
        b'*' => {
            // Collapse a run of plain `*`s, but STOP at a `*` that opens an
            // extglob group (`*(`) — that one is an operator, not a wildcard.
            let mut p = pi;
            while pat.get(p) == Some(&b'*') && pat.get(p + 1) != Some(&b'(') {
                p += 1;
            }
            if lp_blocked(si) {
                return false;
            }
            let mut j = si;
            loop {
                // Mark the slack: everything matched from here is "under a star".
                if ext_match_at(pat, p, text, j, flags, true) {
                    return true;
                }
                let Some(&c) = text.get(j) else {
                    return false;
                };
                if pathname && c == b'/' {
                    return false;
                }
                j += 1;
            }
        }
        b'[' => match classify_bracket(pat, pi, noescape) {
            BracketShape::Invalid => false,
            BracketShape::LiteralFallback => {
                let Some(&c) = text.get(si) else {
                    return false;
                };
                if (pathname && c == b'/') || lp_blocked(si) {
                    return false;
                }
                if eq(c, b'[') {
                    // A fixed-position literal commits a boundary: it clears the
                    // star slack (glibc allows `*a@(b|)` to end on an empty alt).
                    ext_match_at(pat, pi + 1, text, si + 1, flags, false)
                } else {
                    false
                }
            }
            BracketShape::Terminated => {
                let Some(&c) = text.get(si) else {
                    return false;
                };
                if (pathname && c == b'/') || lp_blocked(si) {
                    return false;
                }
                let (m, next_pi) = bracket_match_one(pat, pi, c, noescape, casefold);
                if m {
                    ext_match_at(pat, next_pi, text, si + 1, flags, false)
                } else {
                    false
                }
            }
        },
        b'\\' if !noescape => {
            // `\X` matches literal X; a trailing `\` matches nothing.
            let Some(&esc) = pat.get(pi + 1) else {
                return false;
            };
            let Some(&c) = text.get(si) else {
                return false;
            };
            if eq(c, esc) {
                ext_match_at(pat, pi + 2, text, si + 1, flags, false)
            } else {
                false
            }
        }
        lit => {
            let Some(&c) = text.get(si) else {
                return false;
            };
            if eq(c, lit) {
                // Fixed literal commits a boundary and clears the star slack.
                ext_match_at(pat, pi + 1, text, si + 1, flags, false)
            } else {
                false
            }
        }
    }
}

/// Match an extglob group `op(alts)` followed by `pat[rest_pi..]` against
/// `text[si..]`. Backtracks over every text split consistent with the operator.
#[allow(clippy::too_many_arguments)] // recursive extglob matcher state, not a config bag
fn ext_group_at(
    op: u8,
    alts: &[(usize, usize)],
    pat: &[u8],
    rest_pi: usize,
    text: &[u8],
    si: usize,
    flags: FnmatchFlags,
    star: bool,
) -> bool {
    // The trailing pattern matched against the remaining text from `s`. Having
    // matched a group occurrence here commits a boundary, so the star slack is
    // cleared for the rest — only a `*`/`?` wildcard run reaching an empty-alt
    // group AT END OF TEXT (handled by `star_empty_block` below) stays quirky.
    let rest = |s: usize| ext_match_at(pat, rest_pi, text, s, flags, false);
    // Does some alternative match the slice text[si..e] exactly?
    let alt_hits = |s: usize, e: usize| -> bool {
        alts.iter()
            .any(|&(as_, ae)| sub_full_match(&pat[as_..ae], text, s, e, flags))
    };
    // glibc rejects a `@`/`+` group completing a starred match by an empty-width
    // alternative at end of text: at `si == text.len()` only an empty alternative
    // can match (no text remains), so under `star` we forbid that here. `?`/`*`
    // (zero-occurrence) empties stay allowed; `!` is left to its own semantics.
    let star_empty_block = star && si == text.len();

    match op {
        // Exactly one occurrence (possibly empty, via an empty alternative).
        b'@' => !star_empty_block && (si..=text.len()).any(|e| alt_hits(si, e) && rest(e)),
        // Zero or one occurrence.
        b'?' => {
            if rest(si) {
                return true;
            }
            (si..=text.len()).any(|e| alt_hits(si, e) && rest(e))
        }
        // Zero or more / one or more occurrences (each consumes ≥1 byte to make
        // progress; an empty alternative therefore counts as "zero").
        b'*' => ext_star_at(alts, pat, rest_pi, text, si, flags, false, star),
        b'+' => ext_star_at(alts, pat, rest_pi, text, si, flags, true, star),
        // Anything the list does NOT match, at any split where the rest matches.
        b'!' => (si..=text.len()).any(|e| rest(e) && !alt_hits(si, e)),
        _ => false,
    }
}

/// Greedy backtracking helper for `*(list)` / `+(list)`. Matches a run of list
/// occurrences (each ≥1 byte) starting at `si`, then the rest of the pattern.
/// `require_one` distinguishes `+` (≥1) from `*` (≥0).
#[allow(clippy::too_many_arguments)] // recursive extglob matcher state, not a config bag
fn ext_star_at(
    alts: &[(usize, usize)],
    pat: &[u8],
    rest_pi: usize,
    text: &[u8],
    si: usize,
    flags: FnmatchFlags,
    require_one: bool,
    star: bool,
) -> bool {
    if !require_one && ext_match_at(pat, rest_pi, text, si, flags, star) {
        return true;
    }
    // `+(list)` with an empty-matching alternative counts that as the single
    // required occurrence (consuming nothing), then matches the rest. (`*` needs
    // no special case — an empty occurrence is identical to zero occurrences,
    // already handled above.) glibc forbids this empty-value occurrence from
    // completing a starred match at end of text (e.g. `*+()` on "bb"), so it is
    // gated on `!(star && si == text.len())` — see bd-4aqdre.
    if require_one && !(star && si == text.len()) {
        let empty_alt = alts
            .iter()
            .any(|&(as_, ae)| sub_full_match(&pat[as_..ae], text, si, si, flags));
        // The empty-value occurrence commits a boundary: clear the star slack
        // for the rest (so e.g. `*+()?+()` on "bc" matches like glibc).
        if empty_alt && ext_match_at(pat, rest_pi, text, si, flags, false) {
            return true;
        }
    }
    for e in (si + 1)..=text.len() {
        let hit = alts
            .iter()
            .any(|&(as_, ae)| sub_full_match(&pat[as_..ae], text, si, e, flags));
        // This occurrence consumed `e - si >= 1` bytes, committing a boundary,
        // so the star slack is cleared for the remaining occurrences and rest.
        if hit && ext_star_at(alts, pat, rest_pi, text, e, flags, false, false) {
            return true;
        }
    }
    false
}

/// Does pattern `sub` fully match the text slice `text[s..e]`? Used for an
/// extglob alternative. LEADING_DIR is cleared (an alternative must match
/// exactly, never just a directory prefix).
fn sub_full_match(sub: &[u8], text: &[u8], s: usize, e: usize, flags: FnmatchFlags) -> bool {
    let mut bits = flags.bits() & !FnmatchFlags::LEADING_DIR.bits();
    // FNM_PERIOD's "a wildcard may not match a leading '.'" rule applies only at
    // a genuine component-leading position — the start of the text, or (under
    // PATHNAME) just after a '/'. An extglob-group occurrence that starts
    // mid-component must NOT re-trigger it: matching the alternative against the
    // fixed sub-slice `text[s..e]` would otherwise see slice-position 0 as
    // "leading" and wrongly reject e.g. `+(a|?)` on "bc.." (the '.' at index 2).
    let pathname = flags.contains(FnmatchFlags::PATHNAME);
    let at_leading = s == 0 || (pathname && s >= 1 && text.get(s - 1) == Some(&b'/'));
    if !at_leading {
        bits &= !FnmatchFlags::PERIOD.bits();
    }
    // The interior of an alternative matches a fixed slice independently; an
    // outer `*`'s slack does not reach inside it, so reset the star context.
    ext_match_at(sub, 0, &text[s..e], 0, FnmatchFlags::from_bits(bits), false)
}

#[cfg(test)]
struct FnmatchOracleCtx<'a> {
    flags: FnmatchFlags,
    failed: &'a mut [bool],
    stride: usize,
}

#[cfg(test)]
fn fnmatch_inner(
    pat: &[u8],
    mut pi: usize,
    text: &[u8],
    mut si: usize,
    at_start_in: bool,
    ctx: &mut FnmatchOracleCtx<'_>,
) -> bool {
    let flags = ctx.flags;
    let pathname = flags.contains(FnmatchFlags::PATHNAME);
    let period = flags.contains(FnmatchFlags::PERIOD);
    let noescape = flags.contains(FnmatchFlags::NOESCAPE);
    let casefold = flags.contains(FnmatchFlags::CASEFOLD);
    let leading_dir = flags.contains(FnmatchFlags::LEADING_DIR);
    let mut at_start = at_start_in;

    loop {
        let pc = pat.get(pi).copied();
        let sc = text.get(si).copied();

        // Pattern exhausted.
        if pc.is_none() {
            if sc.is_none() {
                return true;
            }
            // GNU FNM_LEADING_DIR: pattern matched a prefix; if the
            // remainder of `text` starts with '/', accept.
            if leading_dir && sc == Some(b'/') {
                return true;
            }
            return false;
        }
        let pc = pc.unwrap();

        // Helper: is the current text position considered "at-start"
        // for leading-period purposes?
        let leading_period_blocked = |c: u8, si: usize| -> bool {
            period
                && c == b'.'
                && (at_start || (pathname && si > 0 && text.get(si - 1) == Some(&b'/')))
        };

        match pc {
            b'?' => {
                let c = match sc {
                    None => return false,
                    Some(c) => c,
                };
                if pathname && c == b'/' {
                    return false;
                }
                if leading_period_blocked(c, si) {
                    return false;
                }
                pi += 1;
                si += 1;
                at_start = false;
            }
            b'*' => {
                // Skip consecutive '*'s
                while pat.get(pi) == Some(&b'*') {
                    pi += 1;
                }

                if let Some(c) = sc
                    && leading_period_blocked(c, si)
                {
                    return false;
                }

                // If pattern is exhausted after the '*', match the rest.
                if pi >= pat.len() {
                    if pathname {
                        // Disallow matching '/' under PATHNAME
                        let mut j = si;
                        while let Some(&c) = text.get(j) {
                            if c == b'/' {
                                // Under PATHNAME alone, the trailing '*'
                                // cannot consume a '/'. Under PATHNAME +
                                // LEADING_DIR, accept up to the '/'.
                                if leading_dir {
                                    return true;
                                }
                                return false;
                            }
                            j += 1;
                        }
                    }
                    return true;
                }

                // Try matching the rest of the pattern against
                // increasingly long prefixes of the text.
                let mut j = si;
                loop {
                    // Skip states already proven not to match (collapses the
                    // exponential multi-'*' backtracking to polynomial time).
                    // `stride > 0` here: reaching a '*' implies the pattern has
                    // one, so the table was allocated.
                    let idx = pi * ctx.stride + j;
                    if !ctx.failed[idx] {
                        if fnmatch_inner(pat, pi, text, j, false, ctx) {
                            return true;
                        }
                        // Entering the matcher at (pi, j) with at_start=false does
                        // not match; record it so a later '*' cannot re-explore it.
                        ctx.failed[idx] = true;
                    }
                    let c = match text.get(j) {
                        None => break,
                        Some(&c) => c,
                    };
                    if pathname && c == b'/' {
                        break;
                    }
                    j += 1;
                }
                return false;
            }
            b'[' => match classify_bracket(pat, pi, noescape) {
                BracketShape::Invalid => return false,
                BracketShape::LiteralFallback => {
                    let c = match sc {
                        None => return false,
                        Some(c) => c,
                    };
                    if pathname && c == b'/' {
                        return false;
                    }
                    if leading_period_blocked(c, si) {
                        return false;
                    }
                    let eq = if casefold {
                        b'['.eq_ignore_ascii_case(&c)
                    } else {
                        c == b'['
                    };
                    if !eq {
                        return false;
                    }
                    pi += 1;
                    si += 1;
                    at_start = false;
                }
                BracketShape::Terminated => {
                    let c = match sc {
                        None => return false,
                        Some(c) => c,
                    };
                    if pathname && c == b'/' {
                        return false;
                    }
                    if leading_period_blocked(c, si) {
                        return false;
                    }

                    pi += 1; // skip '['
                    let negated = matches!(pat.get(pi), Some(&b'!') | Some(&b'^'));
                    if negated {
                        pi += 1;
                    }

                    let mut matched = false;
                    // A range with an invalid endpoint aborts the scan: keep the
                    // match from earlier members, but never match when negated
                    // — mirrors bracket_match_one.
                    let mut aborted = false;
                    let mut first = true;
                    loop {
                        let bc = match pat.get(pi) {
                            None => return false, // unterminated (shouldn't reach here)
                            Some(&b) => b,
                        };
                        if bc == b']' && !first {
                            break;
                        }
                        first = false;

                        // Collating symbol `[.x.]` as the LOW endpoint of a
                        // range `[.x.]-Y` (glibc: `[[.a.]-c]` == `a..c`). Checked
                        // before the generic sub-expression handling. Mirrors
                        // bracket_match_one.
                        if let Some((low, after)) = collating_range_endpoint(pat, pi)
                            && pat.get(after) == Some(&b'-')
                            && !matches!(pat.get(after + 1), None | Some(&b']'))
                        {
                            let (high, npi) = parse_range_endpoint(pat, after + 1, noescape);
                            pi = npi;
                            match high {
                                Some((high, high_coll))
                                    if in_bracket_range(
                                        c, low, true, high, high_coll, casefold,
                                    ) =>
                                {
                                    matched = true;
                                }
                                Some(_) => {}
                                None => {
                                    aborted = true;
                                    break;
                                }
                            }
                            continue;
                        }

                        // POSIX bracket sub-expressions: `[:class:]`,
                        // `[.collating.]`, `[=equivalence=]`. A `[` followed
                        // by `:`/`.`/`=` introduces one; anything else
                        // (including a literal `[`) falls through below.
                        if bc == b'['
                            && let Some(&kind) = pat.get(pi + 1)
                            && matches!(kind, b':' | b'.' | b'=')
                            && let Some((next_pi, member)) = parse_bracket_subexpr(pat, pi, kind, c)
                        {
                            if member {
                                matched = true;
                            }
                            pi = next_pi;
                            continue;
                        }

                        let mut low = bc;
                        pi += 1;

                        // Escape inside bracket
                        if low == b'\\' && !noescape {
                            low = match pat.get(pi) {
                                None => return false,
                                Some(&b) => b,
                            };
                            pi += 1;
                        }

                        // Range: low '-' high (where high is not ']' / EOF). The
                        // high endpoint may be a plain byte, a `\X` escape, or a
                        // collating symbol `[.y.]` (glibc: `[a-[.c.]]` == `a..c`);
                        // an `[=..=]`/`[:..:]` high endpoint voids the bracket.
                        let next = pat.get(pi);
                        let nextnext = pat.get(pi + 1);
                        if next == Some(&b'-') && nextnext != Some(&b']') && nextnext.is_some() {
                            let (high, npi) = parse_range_endpoint(pat, pi + 1, noescape);
                            pi = npi;
                            match high {
                                Some((high, high_coll))
                                    if in_bracket_range(
                                        c, low, false, high, high_coll, casefold,
                                    ) =>
                                {
                                    matched = true;
                                }
                                Some(_) => {}
                                None => {
                                    aborted = true;
                                    break;
                                }
                            }
                        } else {
                            let test_ch = if casefold { c.to_ascii_lowercase() } else { c };
                            let low_cmp = if casefold {
                                low.to_ascii_lowercase()
                            } else {
                                low
                            };
                            if test_ch == low_cmp {
                                matched = true;
                            }
                        }
                    }

                    if aborted {
                        // glibc keeps the match found before the bad range, but a
                        // malformed bracket never matches under negation.
                        if negated || !matched {
                            return false;
                        }
                        pi = skip_to_bracket_close(pat, pi, noescape);
                        si += 1;
                        at_start = false;
                        continue;
                    }
                    pi += 1; // skip ']'

                    if negated {
                        matched = !matched;
                    }
                    if !matched {
                        return false;
                    }
                    si += 1;
                    at_start = false;
                }
            },
            b'\\' if !noescape => {
                pi += 1;
                let escaped = match pat.get(pi) {
                    None => return false,
                    Some(&b) => b,
                };
                let c = match sc {
                    None => return false,
                    Some(c) => c,
                };
                let eq = if casefold {
                    escaped.eq_ignore_ascii_case(&c)
                } else {
                    escaped == c
                };
                if !eq {
                    return false;
                }
                pi += 1;
                si += 1;
                at_start = false;
            }
            _ => {
                let c = match sc {
                    None => return false,
                    Some(c) => c,
                };
                let eq = if casefold {
                    pc.eq_ignore_ascii_case(&c)
                } else {
                    pc == c
                };
                if !eq {
                    return false;
                }
                pi += 1;
                si += 1;
                at_start = false;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(p: &str, t: &str, f: FnmatchFlags) -> bool {
        fnmatch_match(p.as_bytes(), t.as_bytes(), f)
    }

    // A POSIX collating symbol `[.x.]` may be a range endpoint (glibc parity,
    // bd-8oyxqg); equivalence classes / character classes / multibyte collating
    // may not, and such a malformed range aborts the bracket scan.
    #[test]
    fn collating_symbol_range_endpoints() {
        let none = FnmatchFlags::NONE;
        // Collating symbol as high / low / both endpoints == the plain range.
        assert!(m("[a-[.c.]]", "b", none));
        assert!(!m("[a-[.c.]]", "d", none));
        assert!(m("[[.a.]-c]", "b", none));
        assert!(m("[[.a.]-[.c.]]", "b", none));
        // A member after a VALID collating range still counts.
        assert!(m("[a-[.c.]x]", "x", none));
        // Negation over a collating range.
        assert!(m("[^a-[.c.]]", "e", none));
        assert!(!m("[^a-[.c.]]", "b", none));
        // A bare `[` (not `[.`/`[=`/`[:`) is a literal range endpoint.
        assert!(m("[+-[]", "A", none)); // '+'..'[' includes 'A'
        assert!(!m("[+-[]", "a", none));

        // CASEFOLD: a collating endpoint is NOT folded, but plain ones are; the
        // char is folded. `[9-[.A.]]` is tolower(c) in [9, A] (A unfolded), so
        // 'A' (→'a') is OUTSIDE while ':' / '@' are inside.
        let cf = FnmatchFlags::CASEFOLD;
        assert!(!m("[9-[.A.]]", "A", cf));
        assert!(m("[9-[.A.]]", ":", cf));
        assert!(m("[[.a.]-C]", "B", cf)); // [a, c]; tolower(B)='b' in range
        assert!(!m("[a-[.C.]]", "b", cf)); // [a, C] inverted → matches nothing

        // Malformed range (equivalence/class/multibyte high endpoint) aborts the
        // scan: keeps a match from EARLIER members, never matches when negated.
        assert!(!m("[a-[=c=]x]", "x", none)); // void: nothing before the bad range
        assert!(m("[[:alnum:]b-[=c=]]", "x", none)); // alnum matched before abort
        assert!(!m("[[:alnum:]b-[=c=]]", "/", none));
        assert!(!m("[b-[=c=][:alnum:]]", "x", none)); // member AFTER abort ignored
        assert!(!m("[^[:alnum:]b-[=c=]]", "x", none)); // negated malformed → no match
        assert!(!m("[a-[.ch.]]", "b", none)); // multibyte collating endpoint
    }

    // Memoization correctness + anti-DoS: multi-'*' patterns that would explode
    // exponentially under naive backtracking must return the right answer (and
    // do so quickly). Each of these would hang the pre-memoization matcher.
    #[test]
    fn multi_star_backtracking_is_bounded_and_correct() {
        // 20 stars over 60 'a' with a trailing 'b' absent -> no match.
        let pat = "*a".repeat(20) + "*b";
        let text = "a".repeat(60);
        assert!(!m(&pat, &text, FnmatchFlags::NONE));
        // Same shape but the needle is satisfiable (no trailing literal) -> match.
        let pat_ok = "*a".repeat(20) + "*";
        assert!(m(&pat_ok, &text, FnmatchFlags::NONE));
        // Mixed '*' and '?' with a final mismatch.
        let pat_q = "*a?".repeat(15) + "*z";
        assert!(!m(&pat_q, &text, FnmatchFlags::NONE));
        // Exact-fit alternating stars that DO match.
        assert!(m("*a*b*c*", "xxaxxbxxcxx", FnmatchFlags::NONE));
        assert!(!m("*a*b*c*d", "xxaxxbxxcxx", FnmatchFlags::NONE));
    }

    #[test]
    fn required_plain_literal_prefilter_is_conservative() {
        let bench_pat = b"*[ab]*[ab]*[ab]*[ab]*[ab]*c";
        let bench_text = b"ababababababababab";
        assert!(required_plain_literal_absent_flags_none(
            bench_pat, bench_text
        ));
        assert!(!fnmatch_match(bench_pat, bench_text, FnmatchFlags::NONE));

        assert!(!required_plain_literal_absent_flags_none(b"[ab]", b"b"));
        assert!(fnmatch_match(b"[ab]", b"b", FnmatchFlags::NONE));

        assert!(!required_plain_literal_absent_flags_none(
            b"[[:digit:]]z",
            b"abc"
        ));
        assert!(!required_plain_literal_absent_flags_none(b"[]ab]z", b"z"));

        assert!(required_plain_literal_absent_flags_none(br"\*", b"abc"));
        assert!(!fnmatch_match(br"\*", b"abc", FnmatchFlags::NONE));
        assert!(!required_plain_literal_absent_flags_none(br"\*", b"*"));
        assert!(fnmatch_match(br"\*", b"*", FnmatchFlags::NONE));
    }

    #[test]
    fn required_plain_literal_prefilter_matches_simple_on_short_none_corpus() {
        fn build_bytes(alpha: &[u8], len: usize, mut idx: usize, out: &mut Vec<u8>) {
            out.clear();
            for _ in 0..len {
                out.push(alpha[idx % alpha.len()]);
                idx /= alpha.len();
            }
        }

        let pat_alpha = *b"a*b?[]\\-!c";
        let txt_alpha = *b"abc[]*-";
        let mut pat = Vec::new();
        let mut txt = Vec::new();
        for plen in 0..=3usize {
            for pidx in 0..pat_alpha.len().pow(plen as u32) {
                build_bytes(&pat_alpha, plen, pidx, &mut pat);
                for tlen in 0..=3usize {
                    for tidx in 0..txt_alpha.len().pow(tlen as u32) {
                        build_bytes(&txt_alpha, tlen, tidx, &mut txt);
                        assert_eq!(
                            fnmatch_match(&pat, &txt, FnmatchFlags::NONE),
                            fnmatch_simple(&pat, &txt, FnmatchFlags::NONE),
                            "prefilter changed fnmatch({pat:?}, {txt:?}, flags=NONE)"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn golden_fnmatch_required_literal_corpus_sha256() {
        use core::fmt::Write;
        use sha2::{Digest, Sha256};

        let cases: &[(&[u8], &[u8], FnmatchFlags)] = &[
            (
                b"*[ab]*[ab]*[ab]*[ab]*[ab]*c",
                b"ababababababababab",
                FnmatchFlags::NONE,
            ),
            (
                b"*[ab]*[ab]*[ab]*[ab]*[ab]*c",
                b"ababababababababc",
                FnmatchFlags::NONE,
            ),
            (b"[ab]", b"b", FnmatchFlags::NONE),
            (b"[ab]", b"c", FnmatchFlags::NONE),
            (b"[[:digit:]]z", b"5z", FnmatchFlags::NONE),
            (b"[[:digit:]]z", b"az", FnmatchFlags::NONE),
            (br"\*", b"*", FnmatchFlags::NONE),
            (br"\*", b"abc", FnmatchFlags::NONE),
            (b"*c", b"abab", FnmatchFlags::PATHNAME),
            (b"*c", b"abab", FnmatchFlags::PERIOD),
            (b"*C", b"abab", FnmatchFlags::CASEFOLD),
            (b"*C", b"ababc", FnmatchFlags::CASEFOLD),
            (b"[]ab]z", b"]z", FnmatchFlags::NONE),
            (b"[!ab]z", b"cz", FnmatchFlags::NONE),
        ];
        let mut hasher = Sha256::new();
        for &(pat, text, flags) in cases {
            let matched = fnmatch_match(pat, text, flags);
            hasher.update((pat.len() as u64).to_le_bytes());
            hasher.update(pat);
            hasher.update((text.len() as u64).to_le_bytes());
            hasher.update(text);
            hasher.update(flags.bits().to_le_bytes());
            hasher.update([matched as u8]);
        }
        let bytes = hasher.finalize();
        let mut digest = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            write!(&mut digest, "{byte:02x}").unwrap();
        }
        println!("fnmatch required literal corpus sha256 = {digest}");
        assert_eq!(
            digest,
            "6d4feb0c1506b8790756bd7cead949644dbb5d9f50feda15b1b17347fc0d048a"
        );
    }

    // Exhaustive isomorphism: the iterative `fnmatch_simple` (now the sole
    // production matcher) must equal the recursive oracle `fnmatch_inner` for
    // EVERY short pattern over {a,A,*,?,\,[,],-,!,.,/} x text over {a,A,b,.,/}
    // x ALL 32 flag-bit combinations (PATHNAME/NOESCAPE/PERIOD/LEADING_DIR/
    // CASEFOLD). The alphabet includes '/' and '.' to exercise PATHNAME and
    // PERIOD interactions and 'A'/'a' for CASEFOLD.
    #[test]
    fn simple_fast_path_matches_general() {
        fn general(pat: &[u8], text: &[u8], flags: FnmatchFlags) -> bool {
            let stride = if pat.contains(&b'*') {
                text.len() + 1
            } else {
                0
            };
            let mut failed = vec![false; (pat.len() + 1) * stride];
            let mut ctx = FnmatchOracleCtx {
                flags,
                failed: &mut failed,
                stride,
            };
            fnmatch_inner(pat, 0, text, 0, true, &mut ctx)
        }
        fn build_bytes(alpha: &[u8], len: usize, mut idx: usize, out: &mut Vec<u8>) {
            out.clear();
            for _ in 0..len {
                out.push(alpha[idx % alpha.len()]);
                idx /= alpha.len();
            }
        }
        let pat_alpha = *b"aA*?\\[]-!./";
        let txt_alpha = *b"aAb./";
        let mut pat = Vec::new();
        let mut txt = Vec::new();
        for fbits in 0u32..32 {
            let flags = FnmatchFlags::from_bits(fbits);
            for plen in 0..=3usize {
                for pidx in 0..pat_alpha.len().pow(plen as u32) {
                    build_bytes(&pat_alpha, plen, pidx, &mut pat);
                    for tlen in 0..=3usize {
                        for tidx in 0..txt_alpha.len().pow(tlen as u32) {
                            build_bytes(&txt_alpha, tlen, tidx, &mut txt);
                            assert_eq!(
                                fnmatch_simple(&pat, &txt, flags),
                                general(&pat, &txt, flags),
                                "fnmatch_simple({pat:?}, {txt:?}, flags={fbits:#x}) != general"
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn literal_match() {
        assert!(m("hello", "hello", FnmatchFlags::NONE));
        assert!(!m("hello", "world", FnmatchFlags::NONE));
        assert!(!m("hello", "hell", FnmatchFlags::NONE));
        assert!(!m("hell", "hello", FnmatchFlags::NONE));
    }

    #[test]
    fn empty_pattern_matches_empty_text() {
        assert!(m("", "", FnmatchFlags::NONE));
        assert!(!m("", "x", FnmatchFlags::NONE));
        assert!(!m("x", "", FnmatchFlags::NONE));
    }

    #[test]
    fn question_mark_matches_one_byte() {
        assert!(m("?", "a", FnmatchFlags::NONE));
        assert!(!m("?", "", FnmatchFlags::NONE));
        assert!(!m("?", "ab", FnmatchFlags::NONE));
        assert!(m("h?llo", "hello", FnmatchFlags::NONE));
        assert!(m("h?llo", "hxllo", FnmatchFlags::NONE));
        assert!(!m("h?llo", "hllo", FnmatchFlags::NONE));
    }

    #[test]
    fn star_matches_zero_or_more() {
        assert!(m("*", "anything", FnmatchFlags::NONE));
        assert!(m("*", "", FnmatchFlags::NONE));
        assert!(m("a*b", "ab", FnmatchFlags::NONE));
        assert!(m("a*b", "axxxb", FnmatchFlags::NONE));
        assert!(!m("a*b", "aXc", FnmatchFlags::NONE));
        assert!(m("*.txt", "file.txt", FnmatchFlags::NONE));
        assert!(!m("*.txt", "file.csv", FnmatchFlags::NONE));
    }

    #[test]
    fn bracket_class_matches_one_of() {
        assert!(m("[abc]", "a", FnmatchFlags::NONE));
        assert!(m("[abc]", "b", FnmatchFlags::NONE));
        assert!(m("[abc]", "c", FnmatchFlags::NONE));
        assert!(!m("[abc]", "d", FnmatchFlags::NONE));
    }

    #[test]
    fn bracket_negation() {
        assert!(m("[!abc]", "d", FnmatchFlags::NONE));
        assert!(!m("[!abc]", "a", FnmatchFlags::NONE));
        assert!(m("[^abc]", "d", FnmatchFlags::NONE));
    }

    #[test]
    fn bracket_range() {
        assert!(m("[a-c]", "b", FnmatchFlags::NONE));
        assert!(!m("[a-c]", "d", FnmatchFlags::NONE));
        assert!(m("[0-9]", "5", FnmatchFlags::NONE));
        assert!(!m("[0-9]", "x", FnmatchFlags::NONE));
    }

    #[test]
    fn pathname_blocks_slash_in_star() {
        let f = FnmatchFlags::PATHNAME;
        assert!(m("a/b", "a/b", f));
        assert!(!m("*", "a/b", f));
        assert!(m("*", "a/b", FnmatchFlags::NONE));
        assert!(m("a/*", "a/b", f));
        assert!(!m("a/*", "a/b/c", f));
        assert!(m("a/*/c", "a/b/c", f));
    }

    #[test]
    fn period_blocks_leading_dot_match() {
        let f = FnmatchFlags::PERIOD;
        assert!(!m("*", ".hidden", f));
        assert!(m("*", ".hidden", FnmatchFlags::NONE));
        assert!(!m("?bashrc", ".bashrc", f));
        assert!(m("?bashrc", ".bashrc", FnmatchFlags::NONE));
        assert!(m(".bashrc", ".bashrc", f)); // explicit '.'
    }

    #[test]
    fn period_pathname_combined() {
        let f = FnmatchFlags::PERIOD | FnmatchFlags::PATHNAME;
        // After '/' a leading '.' is also blocked by PERIOD+PATHNAME.
        assert!(!m("a/*", "a/.hidden", f));
        assert!(m("a/.*", "a/.hidden", f));
    }

    #[test]
    fn noescape_makes_backslash_literal() {
        let f = FnmatchFlags::NOESCAPE;
        assert!(m(r"\*", r"\*", f));
        assert!(!m(r"\*", "x", f));
        // Without NOESCAPE, \* matches literal *
        assert!(m(r"\*", "*", FnmatchFlags::NONE));
        assert!(!m(r"\*", "x", FnmatchFlags::NONE));
    }

    #[test]
    fn casefold() {
        let f = FnmatchFlags::CASEFOLD;
        assert!(m("HELLO", "hello", f));
        assert!(m("hello", "HELLO", f));
        assert!(!m("HELLO", "hello", FnmatchFlags::NONE));
        assert!(m("[a-z]", "M", f));
        // CASEFOLD ranges: glibc folds BOTH endpoints AND the char to lowercase
        // and tests a SINGLE folded range — not a per-element fold of the
        // literal span. `[Z-a]` folds to [z,a] which is inverted (empty), so it
        // matches NOTHING under CASEFOLD even though 'z'/'[' lie in the literal
        // span (verified against host glibc fnmatch).
        assert!(!m("[Z-a]", "z", f));
        assert!(!m("[Z-a]", "[", f));
        // Without CASEFOLD the literal range [Z-a] (0x5a..0x61) still matches.
        assert!(m("[Z-a]", "[", FnmatchFlags::NONE));
        assert!(!m("[Z-a]", "z", FnmatchFlags::NONE));
        // `[B-b]` folds to [b,b]: matches only {B,b}, not the literal interior.
        assert!(m("[B-b]", "B", f));
        assert!(!m("[B-b]", "a", f));
        // Collating / equivalence elements are NEVER folded (like [:class:]).
        assert!(!m("[[.b.]]", "B", f));
        assert!(!m("[[=a=]]", "A", f));
        assert!(m("[[.b.]]", "b", f));
    }

    #[test]
    fn leading_dir_allows_path_prefix() {
        let f = FnmatchFlags::LEADING_DIR;
        // pattern matches a directory prefix when text continues with '/'
        assert!(m("a/b", "a/b/c", f));
        assert!(m("a/b", "a/b", f));
        assert!(!m("a/b", "a/b.txt", f));
        assert!(!m("a/b", "a/c", f));
    }

    #[test]
    fn unterminated_bracket_literal_fallback() {
        // glibc treats '[abc' as literal '[' followed by 'abc'
        assert!(m("[abc", "[abc", FnmatchFlags::NONE));
        assert!(!m("[abc", "a", FnmatchFlags::NONE));
    }

    #[test]
    fn unterminated_bracket_with_dash_invalid() {
        // '[a-' — incomplete range, never matches
        assert!(!m("[a-", "a", FnmatchFlags::NONE));
        assert!(!m("[a-", "[a-", FnmatchFlags::NONE));
    }

    #[test]
    fn unterminated_bracket_with_escaped_dash_is_literal() {
        // '[a\-' — the trailing '-' is escaped, so it is a literal dash,
        // NOT an incomplete range. glibc treats the unterminated bracket
        // as a literal '[', so the pattern matches the literal text
        // "[a-" (verified against host glibc fnmatch). The classifier
        // must be escape-aware to avoid the bogus `Invalid` verdict.
        assert!(m(r"[a\-", "[a-", FnmatchFlags::NONE));
        assert!(!m(r"[a\-", "a", FnmatchFlags::NONE));
        // With NOESCAPE the backslash is literal: '[a\-' really does end
        // in an unescaped '-' → incomplete range → never matches.
        assert!(!m(r"[a\-", "[a-", FnmatchFlags::NOESCAPE));
    }

    #[test]
    fn bracket_close_first_is_literal() {
        // POSIX: ']' as first content byte is literal
        assert!(m("[]ab]", "]", FnmatchFlags::NONE));
        assert!(m("[]ab]", "a", FnmatchFlags::NONE));
        assert!(!m("[]ab]", "c", FnmatchFlags::NONE));
    }

    #[test]
    fn posix_character_classes() {
        let none = FnmatchFlags::NONE;
        assert!(m("[[:digit:]]", "5", none));
        assert!(!m("[[:digit:]]", "a", none));
        assert!(m("[[:alpha:]]", "Z", none));
        assert!(!m("[[:alpha:]]", "5", none));
        assert!(m("[[:alnum:]]", "x", none));
        assert!(m("[[:space:]]", " ", none));
        assert!(m("[[:space:]]", "\t", none));
        assert!(m("[[:xdigit:]]", "f", none));
        assert!(!m("[[:xdigit:]]", "g", none));
        assert!(m("[[:upper:]]", "A", none));
        assert!(!m("[[:upper:]]", "a", none));
        assert!(m("[[:lower:]]", "a", none));
        assert!(m("[[:punct:]]", "!", none));
        assert!(m("[[:cntrl:]]", "\x07", none));
        // A class combined with literals / ranges in the same bracket.
        assert!(m("[[:digit:]abc]", "b", none));
        assert!(m("[[:digit:]abc]", "7", none));
        assert!(!m("[[:digit:]abc]", "z", none));
        assert!(m("[[:digit:]A-F]", "D", none));
        assert!(m("x[[:digit:]]y", "x4y", none));
        assert!(!m("x[[:digit:]]y", "xZy", none));
        // Negated class.
        assert!(m("[![:digit:]]", "a", none));
        assert!(!m("[![:digit:]]", "3", none));
        assert!(m("[^[:space:]]", "q", none));
        // An unknown class name is a recognized form that matches nothing.
        assert!(!m("[[:bogus:]]", "[", none));
        assert!(!m("[[:bogus:]]", "x", none));
    }

    #[test]
    fn posix_class_casefold() {
        let f = FnmatchFlags::CASEFOLD;
        // glibc does NOT case-fold named classes under FNM_CASEFOLD — the class
        // is tested against the original byte (folding applies only to literals
        // and ranges). Verified against host glibc by fnmatch_differential_fuzz.
        assert!(!m("[[:upper:]]", "a", f));
        assert!(m("[[:upper:]]", "A", f));
        assert!(!m("[[:lower:]]", "A", f));
        assert!(m("[[:lower:]]", "a", f));
        assert!(m("[[:digit:]]", "5", f));
        assert!(!m("[[:digit:]]", "x", f));
    }

    #[test]
    fn collating_and_equivalence_elements() {
        let none = FnmatchFlags::NONE;
        assert!(m("[[.a.]]", "a", none));
        assert!(!m("[[.a.]]", "b", none));
        assert!(m("[[=e=]]", "e", none));
        assert!(!m("[[=e=]]", "f", none));
        // Mixed with ordinary members.
        assert!(m("[[.a.]xyz]", "y", none));
        assert!(m("[[.a.]xyz]", "a", none));
    }

    #[test]
    fn glibc_caret_negation_parity() {
        // glibc: [^abc] same as [!abc] for negation.
        let none = FnmatchFlags::NONE;
        assert!(m("[^abc]", "d", none));
        assert!(!m("[^abc]", "a", none));
        assert!(!m("[^abc]", "b", none));
    }

    #[test]
    fn glibc_dash_literal_at_boundaries() {
        // glibc: dash at start or end of bracket is literal, not range.
        let none = FnmatchFlags::NONE;
        assert!(m("[-a]", "-", none));
        assert!(m("[-a]", "a", none));
        assert!(!m("[-a]", "b", none));
        assert!(m("[a-]", "-", none));
        assert!(m("[a-]", "a", none));
        assert!(!m("[a-]", "b", none));
    }

    #[test]
    fn glibc_empty_pattern_matches_empty_text() {
        // glibc: fnmatch("", "", 0) = 0 (match)
        assert!(m("", "", FnmatchFlags::NONE));
        assert!(!m("", "a", FnmatchFlags::NONE));
    }

    #[test]
    fn glibc_star_matches_empty_string() {
        // glibc: fnmatch("*", "", 0) = 0
        assert!(m("*", "", FnmatchFlags::NONE));
        assert!(m("**", "", FnmatchFlags::NONE));
    }
}
