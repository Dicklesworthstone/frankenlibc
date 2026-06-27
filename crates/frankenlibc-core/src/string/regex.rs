//! POSIX regex engine — clean-room Thompson NFA implementation.
//!
//! Supports both Basic Regular Expressions (BRE) and Extended Regular
//! Expressions (ERE) per POSIX.1-2017 §9.3 and §9.4.
//!
//! # Implementation strategy
//!
//! 1. Parse regex pattern into an AST
//! 2. Compile AST to an NFA (Thompson construction)
//! 3. Simulate NFA with tagged transitions for submatch extraction
//! 4. Use a bounded backtracking path for BRE backreferences, which are not
//!    regular and cannot be represented by Thompson NFA transitions.
//!
//! Uses POSIX leftmost-longest match semantics.

// Uses std prelude: Box, Vec, String are available without explicit imports.

// ---------------------------------------------------------------------------
// POSIX constants (must match <regex.h> on glibc x86_64)
// ---------------------------------------------------------------------------

// cflags for regcomp
pub const REG_EXTENDED: i32 = 1;
pub const REG_ICASE: i32 = 2;
pub const REG_NEWLINE: i32 = 4;
pub const REG_NOSUB: i32 = 8;

// eflags for regexec
pub const REG_NOTBOL: i32 = 1;
pub const REG_NOTEOL: i32 = 2;
/// BSD/GNU extension: the match region is `string[pmatch[0].rm_so..rm_eo]`
/// (embedded NULs allowed, no NUL terminator required). Handled in the ABI
/// `regexec` wrapper, not the core engine.
pub const REG_STARTEND: i32 = 4;

// Error codes
pub const REG_NOMATCH: i32 = 1;
pub const REG_BADPAT: i32 = 2;
pub const REG_ECOLLATE: i32 = 3;
pub const REG_ECTYPE: i32 = 4;
pub const REG_EESCAPE: i32 = 5;
pub const REG_ESUBREG: i32 = 6;
pub const REG_EBRACK: i32 = 7;
pub const REG_EPAREN: i32 = 8;
pub const REG_EBRACE: i32 = 9;
pub const REG_BADBR: i32 = 10;
pub const REG_ERANGE: i32 = 11;
pub const REG_ESPACE: i32 = 12;
pub const REG_BADRPT: i32 = 13;
// GNU extensions to the POSIX error codes (used only by `regerror` messages).
pub const REG_EEND: i32 = 14;
pub const REG_ESIZE: i32 = 15;
pub const REG_ERPAREN: i32 = 16;

/// POSIX `RE_DUP_MAX`: the largest permitted interval (`{n,m}`) bound.
/// A bound exceeding this is rejected with `REG_BADBR` per POSIX.2.
pub const RE_DUP_MAX: u32 = 32767;

// ---------------------------------------------------------------------------
// regmatch_t equivalent
// ---------------------------------------------------------------------------

/// POSIX regmatch_t — submatch offsets.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct RegMatch {
    pub rm_so: i32,
    pub rm_eo: i32,
}

impl Default for RegMatch {
    fn default() -> Self {
        Self {
            rm_so: -1,
            rm_eo: -1,
        }
    }
}

// ---------------------------------------------------------------------------
// AST
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum Ast {
    Literal(u8),
    AnyChar,
    CharClass {
        ranges: Vec<(u8, u8)>,
        negated: bool,
    },
    Anchor(AnchorKind),
    Group {
        index: usize, // 1-based
        inner: Box<Ast>,
    },
    BackRef(usize),
    Concat(Vec<Ast>),
    Alternate(Box<Ast>, Box<Ast>),
    Repeat {
        inner: Box<Ast>,
        min: u32,
        max: Option<u32>, // None = unbounded
    },
}

#[derive(Debug, Clone, Copy)]
enum AnchorKind {
    /// `^`. `line` is set for a NON-leading `^` in an ERE (one not at the start
    /// of the pattern / a group / an alternative): glibc makes such a `^` match
    /// after a mid-string `\n` even WITHOUT REG_NEWLINE. A leading `^` (and every
    /// BRE `^`) has `line == false` and uses the compiled REG_NEWLINE flag.
    Start { line: bool },
    /// `$`. `line` is set for a NON-terminal `$` in an ERE (one not at the end of
    /// the pattern / a group / an alternative): glibc makes such a `$` match
    /// before a mid-string `\n` even WITHOUT REG_NEWLINE.
    End { line: bool },
    /// GNU `\b` (word boundary) / `\B` (non-boundary) zero-width assertions.
    WordBoundary { negate: bool },
    /// GNU `\<` — match at the start of a word.
    WordStart,
    /// GNU `\>` — match at the end of a word.
    WordEnd,
    /// GNU `` \` `` — match at the start of the buffer (always position 0,
    /// regardless of REG_NOTBOL or REG_NEWLINE; unlike `^`).
    BufferStart,
    /// GNU `\'` — match at the end of the buffer (always the final position,
    /// regardless of REG_NOTEOL or REG_NEWLINE; unlike `$`).
    BufferEnd,
}

/// A byte is a "word" character for `\b`/`\<`/`\>`/`\w`: `[A-Za-z0-9_]`.
#[inline]
fn regex_is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

// ---------------------------------------------------------------------------
// Compile-time complexity certificate
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegexComplexityClass {
    Linear,
    SuperLinear,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegexRiskReason {
    NestedUnboundedRepeat,
    NullableRepeatedTerm,
    AmbiguousRepeatedAlternation,
    BackReference,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegexComplexityCertificate {
    pub pattern_hash: u64,
    pub complexity: RegexComplexityClass,
    pub estimated_nfa_states: usize,
    pub max_repeat_depth: u32,
    pub unbounded_repeat_count: u32,
    pub risk_reason: Option<RegexRiskReason>,
}

#[derive(Debug, Clone, Copy)]
struct FirstByteSet {
    words: [u64; 4],
    any: bool,
}

impl FirstByteSet {
    fn empty() -> Self {
        Self {
            words: [0; 4],
            any: false,
        }
    }

    fn any() -> Self {
        Self {
            words: [u64::MAX; 4],
            any: true,
        }
    }

    /// True iff `byte` is a member of this first-byte set.
    fn contains(&self, byte: u8) -> bool {
        if self.any {
            return true;
        }
        let index = (byte / 64) as usize;
        let bit = byte % 64;
        self.words[index] & (1u64 << bit) != 0
    }

    /// Number of bytes in the set (256 when `any`).
    fn count(&self) -> u32 {
        if self.any {
            return 256;
        }
        self.words.iter().map(|w| w.count_ones()).sum()
    }

    fn singleton(byte: u8) -> Self {
        let mut set = Self::empty();
        set.insert(byte);
        set
    }

    fn range(lo: u8, hi: u8) -> Self {
        let mut set = Self::empty();
        let mut byte = lo;
        loop {
            set.insert(byte);
            if byte == hi {
                break;
            }
            byte = byte.saturating_add(1);
        }
        set
    }

    fn insert(&mut self, byte: u8) {
        let index = (byte / 64) as usize;
        let bit = byte % 64;
        self.words[index] |= 1u64 << bit;
    }

    /// Add the opposite ASCII case of every letter already in the set, so the
    /// set is sound as a first-byte prefilter under case-insensitive matching
    /// (a literal `e` then matches a start byte of `e` *or* `E`).
    fn fold_ascii_case(mut self) -> Self {
        if self.any {
            return self;
        }
        for b in b'A'..=b'Z' {
            if self.contains(b) {
                self.insert(b + 32);
            }
        }
        for b in b'a'..=b'z' {
            if self.contains(b) {
                self.insert(b - 32);
            }
        }
        self
    }

    fn union(self, other: Self) -> Self {
        if self.any || other.any {
            return Self::any();
        }
        let mut out = Self::empty();
        for (dst, (left, right)) in out
            .words
            .iter_mut()
            .zip(self.words.into_iter().zip(other.words))
        {
            *dst = left | right;
        }
        out
    }

    fn overlaps(self, other: Self) -> bool {
        if self.any || other.any {
            return true;
        }
        self.words
            .iter()
            .zip(other.words.iter())
            .any(|(left, right)| (*left & *right) != 0)
    }
}

#[derive(Clone, Copy)]
struct AstAnalysis {
    nullable: bool,
    first_bytes: FirstByteSet,
    contains_unbounded_repeat: bool,
    unbounded_repeat_count: u32,
    max_repeat_depth: u32,
    complexity: RegexComplexityClass,
    risk_reason: Option<RegexRiskReason>,
}

impl AstAnalysis {
    fn linear(nullable: bool, first_bytes: FirstByteSet) -> Self {
        Self {
            nullable,
            first_bytes,
            contains_unbounded_repeat: false,
            unbounded_repeat_count: 0,
            max_repeat_depth: 0,
            complexity: RegexComplexityClass::Linear,
            risk_reason: None,
        }
    }

    fn merge_risk(&mut self, other: Self) {
        if self.risk_reason.is_none() {
            self.risk_reason = other.risk_reason;
        }
        if matches!(other.complexity, RegexComplexityClass::SuperLinear) {
            self.complexity = RegexComplexityClass::SuperLinear;
        }
    }

    fn mark_super_linear(&mut self, reason: RegexRiskReason) {
        self.complexity = RegexComplexityClass::SuperLinear;
        if self.risk_reason.is_none() {
            self.risk_reason = Some(reason);
        }
    }
}

fn stable_pattern_hash(pattern: &[u8]) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

    let mut hash = FNV_OFFSET;
    for byte in pattern {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

fn strip_groups(mut ast: &Ast) -> &Ast {
    while let Ast::Group { inner, .. } = ast {
        ast = inner.as_ref();
    }
    ast
}

/// The maximal run of leading literal bytes a match must consume at its start:
/// for `Concat`, consecutive `Literal` items from the front (each unwrapped of
/// groups); for a bare `Literal`, that one byte; otherwise empty. Because these
/// bytes are the first thing every match consumes, a match can only begin where
/// this exact byte sequence occurs — letting the search jump there with a SIMD
/// substring scan (`memmem`) instead of probing each position.
fn leading_literal_prefix(ast: &Ast) -> Vec<u8> {
    match strip_groups(ast) {
        Ast::Literal(byte) => vec![*byte],
        Ast::Concat(items) => {
            let mut out = Vec::new();
            for item in items {
                match strip_groups(item) {
                    Ast::Literal(byte) => out.push(*byte),
                    _ => break,
                }
            }
            out
        }
        _ => Vec::new(),
    }
}

/// Find the leftmost occurrence of `needle` in `haystack`, case-insensitively
/// (ASCII) when `icase`. Backs the regex literal-prefix jump: SIMD `memmem` for
/// the case-sensitive path, SIMD-folded `strcasestr` for the case-insensitive
/// one (both match the engine's ASCII-only case folding exactly).
fn find_literal(haystack: &[u8], needle: &[u8], icase: bool) -> Option<usize> {
    if icase {
        crate::string::str::strcasestr(haystack, needle)
    } else {
        crate::string::mem::memmem(haystack, haystack.len(), needle, needle.len())
    }
}

fn analyze_ast(ast: &Ast) -> AstAnalysis {
    match ast {
        Ast::Literal(byte) => AstAnalysis::linear(false, FirstByteSet::singleton(*byte)),
        Ast::AnyChar => AstAnalysis::linear(false, FirstByteSet::any()),
        Ast::CharClass { ranges, negated } => {
            if *negated {
                // A negated class matches the complement of its ranges (modulo
                // newline/locale rules). Conservatively report `any` so the
                // first-byte prefilter never wrongly skips a valid start — the
                // exact set would have to mirror the VM's negation+newline
                // handling, which is not worth the parity risk here.
                AstAnalysis::linear(false, FirstByteSet::any())
            } else {
                let mut set = FirstByteSet::empty();
                for &(lo, hi) in ranges {
                    set = set.union(FirstByteSet::range(lo, hi));
                }
                AstAnalysis::linear(false, set)
            }
        }
        Ast::Anchor(_) => AstAnalysis::linear(true, FirstByteSet::empty()),
        Ast::Group { inner, .. } => analyze_ast(inner),
        Ast::BackRef(_) => {
            let mut out = AstAnalysis::linear(true, FirstByteSet::any());
            out.mark_super_linear(RegexRiskReason::BackReference);
            out
        }
        Ast::Concat(items) => {
            let mut out = AstAnalysis::linear(true, FirstByteSet::empty());
            let mut prefix_nullable = true;

            for item in items {
                let analysis = analyze_ast(item);
                out.merge_risk(analysis);
                out.unbounded_repeat_count += analysis.unbounded_repeat_count;
                out.max_repeat_depth = out.max_repeat_depth.max(analysis.max_repeat_depth);
                out.contains_unbounded_repeat |= analysis.contains_unbounded_repeat;

                if prefix_nullable {
                    out.first_bytes = out.first_bytes.union(analysis.first_bytes);
                }
                prefix_nullable &= analysis.nullable;
            }

            out.nullable = prefix_nullable;
            out
        }
        Ast::Alternate(left, right) => {
            let left_analysis = analyze_ast(left);
            let right_analysis = analyze_ast(right);
            let mut out = AstAnalysis::linear(
                left_analysis.nullable || right_analysis.nullable,
                left_analysis.first_bytes.union(right_analysis.first_bytes),
            );
            out.unbounded_repeat_count =
                left_analysis.unbounded_repeat_count + right_analysis.unbounded_repeat_count;
            out.max_repeat_depth = left_analysis
                .max_repeat_depth
                .max(right_analysis.max_repeat_depth);
            out.contains_unbounded_repeat =
                left_analysis.contains_unbounded_repeat || right_analysis.contains_unbounded_repeat;
            out.merge_risk(left_analysis);
            out.merge_risk(right_analysis);
            out
        }
        Ast::Repeat { inner, min, max } => {
            let inner_analysis = analyze_ast(inner);
            let repeated = max.is_none() || max.is_some_and(|count| count > 1);
            let mut out = AstAnalysis::linear(
                *min == 0 || inner_analysis.nullable,
                inner_analysis.first_bytes,
            );
            out.unbounded_repeat_count =
                inner_analysis.unbounded_repeat_count + u32::from(max.is_none());
            out.contains_unbounded_repeat =
                inner_analysis.contains_unbounded_repeat || max.is_none();
            out.max_repeat_depth = inner_analysis.max_repeat_depth + u32::from(repeated);
            out.merge_risk(inner_analysis);

            if repeated && inner_analysis.nullable {
                out.mark_super_linear(RegexRiskReason::NullableRepeatedTerm);
            }
            if max.is_none() && inner_analysis.contains_unbounded_repeat {
                out.mark_super_linear(RegexRiskReason::NestedUnboundedRepeat);
            }
            if repeated && let Ast::Alternate(left, right) = strip_groups(inner.as_ref()) {
                let left_analysis = analyze_ast(left);
                let right_analysis = analyze_ast(right);
                if left_analysis
                    .first_bytes
                    .overlaps(right_analysis.first_bytes)
                    || left_analysis.nullable
                    || right_analysis.nullable
                {
                    out.mark_super_linear(RegexRiskReason::AmbiguousRepeatedAlternation);
                }
            }

            out
        }
    }
}

fn ast_contains_backref(ast: &Ast) -> bool {
    match ast {
        Ast::BackRef(_) => true,
        Ast::Group { inner, .. } => ast_contains_backref(inner),
        Ast::Concat(items) => items.iter().any(ast_contains_backref),
        Ast::Alternate(left, right) => ast_contains_backref(left) || ast_contains_backref(right),
        Ast::Repeat { inner, .. } => ast_contains_backref(inner),
        Ast::Literal(_) | Ast::AnyChar | Ast::CharClass { .. } | Ast::Anchor(_) => false,
    }
}

fn estimate_nfa_states(ast: &Ast) -> usize {
    match ast {
        Ast::Literal(_)
        | Ast::AnyChar
        | Ast::CharClass { .. }
        | Ast::Anchor(_)
        | Ast::BackRef(_) => 1,
        Ast::Group { inner, .. } => estimate_nfa_states(inner).saturating_add(2),
        Ast::Concat(items) => items.iter().fold(0usize, |sum, item| {
            sum.saturating_add(estimate_nfa_states(item))
        }),
        Ast::Alternate(left, right) => estimate_nfa_states(left)
            .saturating_add(estimate_nfa_states(right))
            .saturating_add(2),
        Ast::Repeat { inner, min, max } => {
            let inner_states = estimate_nfa_states(inner);
            let required = inner_states.saturating_mul(*min as usize);
            match max {
                None => required.saturating_add(inner_states).saturating_add(2),
                Some(max_count) => {
                    let optional_count = max_count.saturating_sub(*min) as usize;
                    required.saturating_add(
                        optional_count.saturating_mul(inner_states.saturating_add(1)),
                    )
                }
            }
        }
    }
}

fn build_complexity_certificate(
    pattern: &[u8],
    ast: &Ast,
    estimated_nfa_states: usize,
) -> RegexComplexityCertificate {
    let analysis = analyze_ast(ast);
    RegexComplexityCertificate {
        pattern_hash: stable_pattern_hash(pattern),
        complexity: analysis.complexity,
        estimated_nfa_states,
        max_repeat_depth: analysis.max_repeat_depth,
        unbounded_repeat_count: analysis.unbounded_repeat_count,
        risk_reason: analysis.risk_reason,
    }
}

// ---------------------------------------------------------------------------
// NFA
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum NfaInstr {
    Match(MatchKind),
    Split(usize, usize), // prefer first, then second
    Jump(usize),
    Save(usize), // save position into slot index
    /// Epsilon guard on the post-body EXIT edge of an unbounded repeat. The
    /// just-completed iteration may flow to the loop exit (recording its
    /// submatch) only if it consumed input (`sp > slots[iter_start]`) OR the
    /// whole repeat has consumed nothing so far (`sp == slots[group_start]`).
    /// This reproduces glibc's POSIX rule: a `*`/`+` takes at most one empty
    /// iteration, and only when no non-empty iteration preceded — so a trailing
    /// empty iteration never overwrites a real capture (e.g. `(b*)+` on "bb"
    /// keeps g1=[2,4]), while a genuinely-empty group still records its
    /// participating span (e.g. `.()*a` on "ba" gives g1=[1,1]). bd-1djvkw.
    RepeatExitGuard {
        group_start: usize,
        iter_start: usize,
    },
    Accept,
}

#[derive(Debug, Clone)]
enum MatchKind {
    Literal(u8),
    LiteralCi(u8, u8), // lowercase, uppercase
    AnyChar {
        newline: bool,
    },
    CharClass {
        /// 256-bit membership table with negation, ICASE case-folding and
        /// REG_NEWLINE all baked in at compile time, so `matches_byte` is a single
        /// O(1) bit lookup instead of a per-byte range scan (and, for ICASE, a
        /// nested per-range character loop). `bit[c]` set ⇔ byte `c` matches.
        set: [u64; 4],
    },
    AnchorStart {
        newline: bool,
    },
    AnchorEnd {
        newline: bool,
    },
    /// GNU `\b` / `\B` word-boundary assertion (zero-width).
    WordBoundary {
        negate: bool,
    },
    /// GNU `\<` — start-of-word assertion (zero-width).
    WordStart,
    /// GNU `\>` — end-of-word assertion (zero-width).
    WordEnd,
    /// GNU `` \` `` — start-of-buffer assertion (position 0, zero-width).
    BufferStart,
    /// GNU `\'` — end-of-buffer assertion (final position, zero-width).
    BufferEnd,
}

/// Precompute a `MatchKind::CharClass` 256-bit membership table at compile time so
/// the hot `matches_byte` is a single bit lookup. Negation, ICASE case-folding and
/// REG_NEWLINE are all baked in (semantics are byte-identical to the former
/// per-byte range scan — verified by the regex glibc-differential fuzz suite).
fn build_class_bitset(ranges: &[(u8, u8)], negated: bool, icase: bool, newline: bool) -> [u64; 4] {
    let mut set = [0u64; 4];
    for &(lo, hi) in ranges {
        for b in lo..=hi {
            set[(b >> 6) as usize] |= 1u64 << (b & 63);
            if icase && b.is_ascii_alphabetic() {
                let s = b ^ 0x20; // ASCII case swap
                set[(s >> 6) as usize] |= 1u64 << (s & 63);
            }
        }
    }
    if negated {
        for w in &mut set {
            *w = !*w;
        }
        // POSIX REG_NEWLINE: a nonmatching (negated) list never matches '\n'.
        if newline {
            set[(b'\n' >> 6) as usize] &= !(1u64 << (b'\n' & 63));
        }
    }
    set
}

/// `true` iff byte `b` is a member of the 256-bit class table.
#[inline]
fn class_set_contains(set: &[u64; 4], b: u8) -> bool {
    (set[(b >> 6) as usize] >> (b & 63)) & 1 != 0
}

/// `true` iff the two 256-bit class tables share no byte.
#[inline]
fn sets_disjoint(a: &[u64; 4], b: &[u64; 4]) -> bool {
    a[0] & b[0] == 0 && a[1] & b[1] == 0 && a[2] & b[2] == 0 && a[3] & b[3] == 0
}

// ---------------------------------------------------------------------------
// Compiled regex
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct CompiledRegex {
    nfa: Vec<NfaInstr>,
    backtrack_ast: Option<Ast>,
    num_groups: usize,
    /// Total VM slot count: the `(num_groups+1)*2` capture slots plus any hidden
    /// repeat-progress slots allocated by the compiler. Threads allocate this
    /// many slots so `RepeatExitGuard` indices stay in bounds.
    total_slots: usize,
    nosub: bool,
    icase: bool,
    newline: bool,
    complexity_certificate: RegexComplexityCertificate,
    /// Set of bytes that can begin a match, when a sound first-byte prefilter
    /// applies (non-nullable, non-`.`-leading, case-sensitive). `Some` lets the
    /// unanchored search loop skip start positions whose byte cannot begin a
    /// match — avoiding the per-start thread/Vec setup — turning the worst case
    /// (no match, rare first byte) from O(n^2) toward O(n). `None` = no skip.
    prefilter: Option<FirstByteSet>,
    /// Leading literal byte sequence (>= 2 bytes) every match must consume at
    /// its start, when one applies (non-nullable, case-sensitive). `Some` lets
    /// the search jump straight to occurrences via SIMD `memmem` — far stronger
    /// than the single-byte `prefilter` when the first byte is common but the
    /// full literal is rare (e.g. `error:` in prose). Mutually exclusive with
    /// `prefilter` (set only when this is `None`).
    literal_prefix: Option<Vec<u8>>,
    /// Byte values that MUST appear somewhere in every string this regex matches
    /// (computed soundly + conservatively from the AST; always a SUBSET of the true
    /// required set). If the input lacks any of them, no match is possible, so the
    /// VM can be skipped entirely with a cheap SIMD `memchr` per byte. Empty when
    /// case-insensitive (a literal could match either case) or when a `literal_prefix`
    /// already covers the search via `memmem`. Never gates on NUL.
    required_bytes: Vec<u8>,
    /// A contiguous byte run (>= 2 bytes) that MUST appear in every match — the longest
    /// top-level literal run in the AST. Strictly stronger than `required_bytes` for these
    /// bytes: if the input lacks the SUBSTRING, no match is possible, even when the
    /// individual bytes are all present but scattered (the common case for literal-ish
    /// patterns over natural text). Checked with one SIMD `memmem`. Empty when ICASE, when
    /// a `literal_prefix` already drives the search, or when no >= 2-byte run exists.
    required_substring: Vec<u8>,
}

impl CompiledRegex {
    fn num_slots(&self) -> usize {
        self.total_slots
    }

    pub fn num_regs(&self) -> usize {
        self.num_groups + 1
    }

    pub fn nosub(&self) -> bool {
        self.nosub
    }

    /// Whether the pattern was compiled with REG_NEWLINE (`^`/`$` match at
    /// line boundaries). Used by the REG_STARTEND wrapper to decide whether a
    /// `\n` just before the match region makes its first position a BOL.
    pub fn newline_mode(&self) -> bool {
        self.newline
    }

    pub fn complexity_certificate(&self) -> RegexComplexityCertificate {
        self.complexity_certificate
    }
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

struct Parser<'a> {
    pat: &'a [u8],
    pos: usize,
    extended: bool,
    group_count: usize,
}

impl<'a> Parser<'a> {
    fn new(pat: &'a [u8], cflags: i32) -> Self {
        Self {
            pat,
            pos: 0,
            extended: cflags & REG_EXTENDED != 0,
            group_count: 0,
        }
    }

    fn peek(&self) -> Option<u8> {
        if self.pos < self.pat.len() {
            Some(self.pat[self.pos])
        } else {
            None
        }
    }

    fn advance(&mut self) -> Option<u8> {
        if self.pos < self.pat.len() {
            let ch = self.pat[self.pos];
            self.pos += 1;
            Some(ch)
        } else {
            None
        }
    }

    fn parse(&mut self) -> Result<Ast, i32> {
        let ast = self.parse_alternation()?;
        if self.pos < self.pat.len() {
            // Unparsed characters remain
            if self.extended {
                // In ERE, unmatched ) is an error
                if self.pat[self.pos] == b')' {
                    return Err(REG_EPAREN);
                }
            }
            return Err(REG_BADPAT);
        }
        Ok(ast)
    }

    fn parse_alternation(&mut self) -> Result<Ast, i32> {
        let mut left = self.parse_concat()?;

        if self.extended {
            while self.peek() == Some(b'|') {
                self.advance();
                let right = self.parse_concat()?;
                left = Ast::Alternate(Box::new(left), Box::new(right));
            }
        } else {
            // BRE: alternation via \|
            while self.pos + 1 < self.pat.len()
                && self.pat[self.pos] == b'\\'
                && self.pat[self.pos + 1] == b'|'
            {
                self.pos += 2;
                let right = self.parse_concat()?;
                left = Ast::Alternate(Box::new(left), Box::new(right));
            }
        }

        Ok(left)
    }

    fn parse_concat(&mut self) -> Result<Ast, i32> {
        let mut items = Vec::new();

        loop {
            match self.peek() {
                None => break,
                Some(b'|') if self.extended => break,
                Some(b')') if self.extended => break,
                _ => {
                    // Check for BRE \| or \)
                    if !self.extended
                        && self.pos + 1 < self.pat.len()
                        && self.pat[self.pos] == b'\\'
                    {
                        let next = self.pat[self.pos + 1];
                        if next == b'|' || next == b')' {
                            break;
                        }
                    }

                    let atom = self.parse_quantified()?;
                    items.push(atom);
                }
            }
        }

        match items.len() {
            0 => Ok(Ast::Concat(Vec::new())),
            1 => Ok(items.into_iter().next().unwrap()),
            _ => Ok(Ast::Concat(items)),
        }
    }

    fn parse_quantified(&mut self) -> Result<Ast, i32> {
        let mut node = self.parse_atom()?;
        // Quantifiers STACK (glibc/GNU): a quantifier following another wraps the
        // already-quantified node. ERE lets `* + ? {m,n}` all stack freely (e.g.
        // `a*+` = `(a*)+`, `a{2}{3}` = `(a{2}){3}`). BRE lets the GNU `\+`/`\?`
        // stack onto any prior quantifier (`a*\+`, `a\{2\}\+`), but a `*` or
        // `\{` AFTER a quantifier is REG_BADRPT. Loop to consume the run.
        let mut quantified = false;
        loop {
            if self.extended {
                match self.peek() {
                    Some(b'*') => {
                        self.advance();
                        node = Ast::Repeat {
                            inner: Box::new(node),
                            min: 0,
                            max: None,
                        };
                    }
                    Some(b'+') => {
                        self.advance();
                        node = Ast::Repeat {
                            inner: Box::new(node),
                            min: 1,
                            max: None,
                        };
                    }
                    Some(b'?') => {
                        self.advance();
                        node = Ast::Repeat {
                            inner: Box::new(node),
                            min: 0,
                            max: Some(1),
                        };
                    }
                    Some(b'{') => {
                        node = self.parse_brace_quantifier(node)?;
                    }
                    _ => return Ok(node),
                }
                quantified = true;
            } else {
                // BRE: * is a quantifier only after a quantifiable atom. POSIX: a
                // `*` immediately following a leading anchor (`^` at RE/subexpr/
                // alternative start, or the GNU `\<`/`\>`/`\b`/`\B` assertions) is
                // a LITERAL `*` — those assertions are not quantifiable (glibc:
                // `^*0` is `^` + literal `*` + `0`; `^**0` is `^` + literal `*`
                // repeated). So only treat `*` as a quantifier on a non-anchor.
                match self.peek() {
                    Some(b'*') => {
                        if quantified {
                            // glibc: a `*` after another quantifier is REG_BADRPT.
                            return Err(REG_BADRPT);
                        }
                        if matches!(node, Ast::Anchor(_)) {
                            return Ok(node);
                        }
                        self.advance();
                        node = Ast::Repeat {
                            inner: Box::new(node),
                            min: 0,
                            max: None,
                        };
                        quantified = true;
                    }
                    _ => {
                        // BRE GNU quantifier extensions: `\{m,n\}`, `\+`, `\?`.
                        // Plain `+`/`?` are literals in BRE.
                        if self.pos + 1 < self.pat.len() && self.pat[self.pos] == b'\\' {
                            match self.pat[self.pos + 1] {
                                b'{' => {
                                    if quantified {
                                        // glibc: `\{` after a quantifier is BADRPT.
                                        return Err(REG_BADRPT);
                                    }
                                    self.pos += 2; // skip \{
                                    node = self.parse_bre_brace_quantifier(node)?;
                                    quantified = true;
                                }
                                b'+' => {
                                    self.pos += 2; // skip \+
                                    node = Ast::Repeat {
                                        inner: Box::new(node),
                                        min: 1,
                                        max: None,
                                    };
                                    quantified = true;
                                }
                                b'?' => {
                                    self.pos += 2; // skip \?
                                    node = Ast::Repeat {
                                        inner: Box::new(node),
                                        min: 0,
                                        max: Some(1),
                                    };
                                    quantified = true;
                                }
                                _ => return Ok(node),
                            }
                        } else {
                            return Ok(node);
                        }
                    }
                }
            }
        }
    }

    fn parse_brace_quantifier(&mut self, atom: Ast) -> Result<Ast, i32> {
        self.advance(); // skip {
        // Lower bound. `{,m}` (leading comma) is the GNU extension for
        // `{0,m}`; an empty `{}` is bad content; anything else that is not a
        // digit makes the brace itself malformed.
        let min = match self.peek() {
            Some(b',') => 0,
            Some(c) if c.is_ascii_digit() => self.parse_decimal()?,
            Some(b'}') => return Err(REG_BADBR),
            _ => return Err(REG_EBRACE),
        };
        let max;

        match self.peek() {
            Some(b',') => {
                self.advance();
                if self.peek() == Some(b'}') {
                    max = None; // unbounded
                } else {
                    let m = self.parse_decimal()?;
                    max = Some(m);
                    if m < min {
                        return Err(REG_BADBR);
                    }
                }
            }
            Some(b'}') => {
                max = Some(min); // exact count
            }
            _ => return Err(REG_EBRACE),
        }

        if self.advance() != Some(b'}') {
            return Err(REG_EBRACE);
        }
        // POSIX.2: an interval bound larger than RE_DUP_MAX is REG_BADBR.
        if min > RE_DUP_MAX || max.is_some_and(|m| m > RE_DUP_MAX) {
            return Err(REG_BADBR);
        }

        Ok(Ast::Repeat {
            inner: Box::new(atom),
            min,
            max,
        })
    }

    fn parse_bre_brace_quantifier(&mut self, atom: Ast) -> Result<Ast, i32> {
        // `\{,m\}` (leading comma) is the GNU extension for `\{0,m\}`.
        let min = if self.peek() == Some(b',') {
            0
        } else {
            self.parse_decimal()?
        };
        let max;

        match self.peek() {
            Some(b',') => {
                self.advance();
                // Check for \}
                if self.pos + 1 < self.pat.len()
                    && self.pat[self.pos] == b'\\'
                    && self.pat[self.pos + 1] == b'}'
                {
                    max = None;
                } else {
                    let m = self.parse_decimal()?;
                    max = Some(m);
                    if m < min {
                        return Err(REG_BADBR);
                    }
                }
            }
            _ => {
                max = Some(min);
            }
        }

        // Expect \}
        if self.pos + 1 < self.pat.len()
            && self.pat[self.pos] == b'\\'
            && self.pat[self.pos + 1] == b'}'
        {
            self.pos += 2;
        } else {
            return Err(REG_EBRACE);
        }
        // POSIX.2: an interval bound larger than RE_DUP_MAX is REG_BADBR.
        if min > RE_DUP_MAX || max.is_some_and(|m| m > RE_DUP_MAX) {
            return Err(REG_BADBR);
        }

        Ok(Ast::Repeat {
            inner: Box::new(atom),
            min,
            max,
        })
    }

    fn parse_decimal(&mut self) -> Result<u32, i32> {
        let mut val: u32 = 0;
        let mut found = false;
        while let Some(ch) = self.peek() {
            if ch.is_ascii_digit() {
                self.advance();
                val = val
                    .checked_mul(10)
                    .and_then(|v| v.checked_add((ch - b'0') as u32))
                    .ok_or(REG_BADBR)?;
                found = true;
            } else {
                break;
            }
        }
        if !found {
            return Err(REG_BADBR);
        }
        Ok(val)
    }

    fn parse_atom(&mut self) -> Result<Ast, i32> {
        match self.peek() {
            None => Err(REG_BADPAT),
            Some(b'^') => {
                // ERE: `^` is always an anchor. BRE: only at the start of the
                // RE or right after `\(` / `\|`; elsewhere it is a literal. The
                // newline-aware `line` flag is filled in by `mark_line_anchors`
                // after the whole AST is built (it needs prefix-nullability).
                let anchored = self.extended
                    || self.pos == 0
                    || self.pat[..self.pos].ends_with(b"\\(")
                    || self.pat[..self.pos].ends_with(b"\\|");
                self.advance();
                if anchored {
                    Ok(Ast::Anchor(AnchorKind::Start { line: false }))
                } else {
                    Ok(Ast::Literal(b'^'))
                }
            }
            Some(b'$') => {
                // ERE: `$` is always an anchor. BRE: only at the end of the
                // RE or right before `\)` / `\|`; elsewhere it is a literal.
                let rest = &self.pat[self.pos + 1..];
                let anchored = self.extended
                    || rest.is_empty()
                    || rest.starts_with(b"\\)")
                    || rest.starts_with(b"\\|");
                self.advance();
                if anchored {
                    Ok(Ast::Anchor(AnchorKind::End { line: false }))
                } else {
                    Ok(Ast::Literal(b'$'))
                }
            }
            Some(b'.') => {
                self.advance();
                Ok(Ast::AnyChar)
            }
            Some(b'[') => self.parse_bracket(),
            Some(b'(') if self.extended => {
                self.advance();
                self.group_count += 1;
                let idx = self.group_count;
                let inner = self.parse_alternation()?;
                if self.advance() != Some(b')') {
                    return Err(REG_EPAREN);
                }
                Ok(Ast::Group {
                    index: idx,
                    inner: Box::new(inner),
                })
            }
            Some(b'\\') => {
                self.advance();
                match self.peek() {
                    None => Err(REG_EESCAPE),
                    Some(b'(') if !self.extended => {
                        self.advance();
                        self.group_count += 1;
                        let idx = self.group_count;
                        let inner = self.parse_alternation()?;
                        // Expect \)
                        if self.pos + 1 < self.pat.len()
                            && self.pat[self.pos] == b'\\'
                            && self.pat[self.pos + 1] == b')'
                        {
                            self.pos += 2;
                        } else {
                            return Err(REG_EPAREN);
                        }
                        Ok(Ast::Group {
                            index: idx,
                            inner: Box::new(inner),
                        })
                    }
                    Some(ch @ b'1'..=b'9') if !self.extended => {
                        self.advance();
                        let idx = (ch - b'0') as usize;
                        if idx > self.group_count {
                            return Err(REG_ESUBREG);
                        }
                        Ok(Ast::BackRef(idx))
                    }
                    // GNU word-boundary assertions (zero-width), valid in both
                    // BRE and ERE — matching glibc. Previously these fell through
                    // to the literal case (`\b` matched a literal 'b').
                    Some(b'b') => {
                        self.advance();
                        Ok(Ast::Anchor(AnchorKind::WordBoundary { negate: false }))
                    }
                    Some(b'B') => {
                        self.advance();
                        Ok(Ast::Anchor(AnchorKind::WordBoundary { negate: true }))
                    }
                    Some(b'<') => {
                        self.advance();
                        Ok(Ast::Anchor(AnchorKind::WordStart))
                    }
                    Some(b'>') => {
                        self.advance();
                        Ok(Ast::Anchor(AnchorKind::WordEnd))
                    }
                    // GNU buffer anchors: `` \` `` start-of-buffer, `\'` end.
                    Some(b'`') => {
                        self.advance();
                        Ok(Ast::Anchor(AnchorKind::BufferStart))
                    }
                    Some(b'\'') => {
                        self.advance();
                        Ok(Ast::Anchor(AnchorKind::BufferEnd))
                    }
                    // GNU character-class escapes (C locale): `\w` == [[:alnum:]_],
                    // `\s` == [[:space:]], and their negations `\W`/`\S`.
                    Some(b'w') => {
                        self.advance();
                        Ok(Ast::CharClass {
                            ranges: vec![(b'0', b'9'), (b'A', b'Z'), (b'a', b'z'), (b'_', b'_')],
                            negated: false,
                        })
                    }
                    Some(b'W') => {
                        self.advance();
                        Ok(Ast::CharClass {
                            ranges: vec![(b'0', b'9'), (b'A', b'Z'), (b'a', b'z'), (b'_', b'_')],
                            negated: true,
                        })
                    }
                    Some(b's') => {
                        self.advance();
                        // [ \t\n\v\f\r] — whitespace bytes 0x09..=0x0D plus space.
                        Ok(Ast::CharClass {
                            ranges: vec![(0x09, 0x0D), (b' ', b' ')],
                            negated: false,
                        })
                    }
                    Some(b'S') => {
                        self.advance();
                        Ok(Ast::CharClass {
                            ranges: vec![(0x09, 0x0D), (b' ', b' ')],
                            negated: true,
                        })
                    }
                    Some(ch) => {
                        self.advance();
                        // Escaped metacharacter becomes literal
                        Ok(Ast::Literal(ch))
                    }
                }
            }
            Some(ch) => {
                // In ERE, these are special and shouldn't appear as atoms
                if self.extended && (ch == b'*' || ch == b'+' || ch == b'?' || ch == b'{') {
                    return Err(REG_BADRPT);
                }
                self.advance();
                Ok(Ast::Literal(ch))
            }
        }
    }

    fn parse_bracket(&mut self) -> Result<Ast, i32> {
        self.advance(); // skip [
        let mut negated = false;
        let mut ranges: Vec<(u8, u8)> = Vec::new();

        if self.peek() == Some(b'^') {
            negated = true;
            self.advance();
        }

        // First character can be ] without closing
        if self.peek() == Some(b']') {
            ranges.push((b']', b']'));
            self.advance();
        }

        loop {
            match self.peek() {
                None => return Err(REG_EBRACK),
                Some(b']') => {
                    self.advance();
                    break;
                }
                // POSIX character class `[:alpha:]`. Like an equivalence class it
                // may not be a range endpoint — a following `-` (not closing the
                // bracket) is REG_ERANGE, matching glibc.
                Some(b'[') if self.pat.get(self.pos + 1) == Some(&b':') => {
                    self.advance(); // [
                    self.advance(); // :
                    let class_ranges = self.parse_posix_class()?;
                    ranges.extend_from_slice(&class_ranges);
                    if self.peek() == Some(b'-')
                        && self.pat.get(self.pos + 1).is_some_and(|&b| b != b']')
                    {
                        return Err(REG_ERANGE);
                    }
                }
                // Equivalence class `[=c=]`. In the C locale the class of a
                // character is just that character. It may NOT be a range
                // endpoint — a following `-` (not closing the bracket) is
                // REG_ERANGE, matching glibc.
                Some(b'[') if self.pat.get(self.pos + 1) == Some(&b'=') => {
                    self.advance(); // [
                    self.advance(); // =
                    let ch = self.read_coll_element(b'=')?;
                    if self.peek() == Some(b'-')
                        && self.pat.get(self.pos + 1).is_some_and(|&b| b != b']')
                    {
                        return Err(REG_ERANGE);
                    }
                    ranges.push((ch, ch));
                }
                // A literal byte or a collating symbol `[.c.]`; either may be a
                // range endpoint (`[[.a.]-z]` == `[a-z]`).
                _ => {
                    let start = self.read_bracket_element()?;
                    if self.peek() == Some(b'-')
                        && self.pat.get(self.pos + 1).is_some_and(|&b| b != b']')
                    {
                        self.advance(); // skip -
                        let end = self.read_bracket_element()?;
                        if end < start {
                            return Err(REG_ERANGE);
                        }
                        ranges.push((start, end));
                    } else {
                        ranges.push((start, start));
                    }
                }
            }
        }

        Ok(Ast::CharClass { ranges, negated })
    }

    /// Read one range-eligible bracket element: a collating symbol `[.c.]`
    /// (yielding its single collating character) or a plain literal byte.
    fn read_bracket_element(&mut self) -> Result<u8, i32> {
        if self.peek() == Some(b'[') && self.pat.get(self.pos + 1) == Some(&b'.') {
            self.advance(); // [
            self.advance(); // .
            self.read_coll_element(b'.')
        } else {
            self.advance().ok_or(REG_EBRACK)
        }
    }

    /// Read the body of an equivalence class (`marker == b'='`) or collating
    /// symbol (`marker == b'.'`) up to the closing `marker` + `]`, having
    /// already consumed the opening `[` and `marker`. In the C locale a valid
    /// element is exactly one character; an unterminated body is REG_EBRACK and
    /// an empty or multi-character (named) body is REG_ECOLLATE — matching glibc.
    fn read_coll_element(&mut self, marker: u8) -> Result<u8, i32> {
        let mut buf: Vec<u8> = Vec::new();
        loop {
            match self.peek() {
                None => return Err(REG_EBRACK),
                Some(b) if b == marker && self.pat.get(self.pos + 1) == Some(&b']') => {
                    self.advance(); // marker
                    self.advance(); // ]
                    break;
                }
                Some(b) => {
                    buf.push(b);
                    self.advance();
                }
            }
        }
        if buf.len() == 1 {
            Ok(buf[0])
        } else {
            Err(REG_ECOLLATE)
        }
    }

    fn parse_posix_class(&mut self) -> Result<Vec<(u8, u8)>, i32> {
        let start = self.pos;
        while self.pos < self.pat.len() && self.pat[self.pos] != b':' {
            self.pos += 1;
        }
        if self.pos + 1 >= self.pat.len() || self.pat[self.pos + 1] != b']' {
            return Err(REG_ECTYPE);
        }
        let class_name = &self.pat[start..self.pos];
        self.pos += 2; // skip :]

        let ranges = match class_name {
            b"alpha" => vec![(b'A', b'Z'), (b'a', b'z')],
            b"upper" => vec![(b'A', b'Z')],
            b"lower" => vec![(b'a', b'z')],
            b"digit" => vec![(b'0', b'9')],
            b"alnum" => vec![(b'A', b'Z'), (b'a', b'z'), (b'0', b'9')],
            b"space" => vec![
                (b' ', b' '),
                (b'\t', b'\t'),
                (b'\n', b'\n'),
                (b'\r', b'\r'),
                (b'\x0b', b'\x0b'),
                (b'\x0c', b'\x0c'),
            ],
            b"blank" => vec![(b' ', b' '), (b'\t', b'\t')],
            b"print" => vec![(b' ', b'~')],
            b"graph" => vec![(b'!', b'~')],
            b"cntrl" => vec![(0, 0x1f), (0x7f, 0x7f)],
            b"punct" => vec![(b'!', b'/'), (b':', b'@'), (b'[', b'`'), (b'{', b'~')],
            b"xdigit" => vec![(b'0', b'9'), (b'A', b'F'), (b'a', b'f')],
            _ => return Err(REG_ECTYPE),
        };
        Ok(ranges)
    }
}

// ---------------------------------------------------------------------------
// NFA Compiler
// ---------------------------------------------------------------------------

struct Compiler {
    nfa: Vec<NfaInstr>,
    compile_icase: bool,
    compile_newline: bool,
    /// Next free slot index for hidden (non-capture) repeat-progress slots.
    /// Capture slots are `0..(num_groups+1)*2`; hidden slots are allocated
    /// above them, two per unbounded repeat (group-start and iteration-start).
    next_hidden_slot: usize,
}

impl Compiler {
    fn new(icase: bool, newline: bool, num_groups: usize) -> Self {
        Self {
            nfa: Vec::new(),
            compile_icase: icase,
            compile_newline: newline,
            next_hidden_slot: (num_groups + 1) * 2,
        }
    }

    /// Reserve one hidden progress slot.
    fn alloc_hidden_slot(&mut self) -> usize {
        let s = self.next_hidden_slot;
        self.next_hidden_slot += 1;
        s
    }

    fn emit(&mut self, instr: NfaInstr) -> usize {
        let idx = self.nfa.len();
        self.nfa.push(instr);
        idx
    }

    fn compile(&mut self, ast: &Ast) {
        match ast {
            Ast::Literal(ch) => {
                if self.compile_icase && ch.is_ascii_alphabetic() {
                    let lo = ch.to_ascii_lowercase();
                    let hi = ch.to_ascii_uppercase();
                    self.emit(NfaInstr::Match(MatchKind::LiteralCi(lo, hi)));
                } else {
                    self.emit(NfaInstr::Match(MatchKind::Literal(*ch)));
                }
            }
            Ast::AnyChar => {
                self.emit(NfaInstr::Match(MatchKind::AnyChar {
                    newline: self.compile_newline,
                }));
            }
            Ast::CharClass { ranges, negated } => {
                self.emit(NfaInstr::Match(MatchKind::CharClass {
                    set: build_class_bitset(
                        ranges,
                        *negated,
                        self.compile_icase,
                        self.compile_newline,
                    ),
                }));
            }
            Ast::Anchor(AnchorKind::Start { line }) => {
                self.emit(NfaInstr::Match(MatchKind::AnchorStart {
                    newline: *line || self.compile_newline,
                }));
            }
            Ast::Anchor(AnchorKind::End { line }) => {
                self.emit(NfaInstr::Match(MatchKind::AnchorEnd {
                    newline: *line || self.compile_newline,
                }));
            }
            Ast::Anchor(AnchorKind::WordBoundary { negate }) => {
                self.emit(NfaInstr::Match(MatchKind::WordBoundary { negate: *negate }));
            }
            Ast::Anchor(AnchorKind::WordStart) => {
                self.emit(NfaInstr::Match(MatchKind::WordStart));
            }
            Ast::Anchor(AnchorKind::WordEnd) => {
                self.emit(NfaInstr::Match(MatchKind::WordEnd));
            }
            Ast::Anchor(AnchorKind::BufferStart) => {
                self.emit(NfaInstr::Match(MatchKind::BufferStart));
            }
            Ast::Anchor(AnchorKind::BufferEnd) => {
                self.emit(NfaInstr::Match(MatchKind::BufferEnd));
            }
            Ast::Concat(items) => {
                for item in items {
                    self.compile(item);
                }
            }
            Ast::Group { index, inner } => {
                let open_slot = index * 2;
                let close_slot = index * 2 + 1;
                self.emit(NfaInstr::Save(open_slot));
                self.compile(inner);
                self.emit(NfaInstr::Save(close_slot));
            }
            Ast::BackRef(_) => unreachable!("backreferences use the backtracking regex engine"),
            Ast::Alternate(left, right) => {
                let split_idx = self.emit(NfaInstr::Split(0, 0)); // placeholder
                self.compile(left);
                let jmp_idx = self.emit(NfaInstr::Jump(0)); // placeholder
                let right_start = self.nfa.len();
                self.compile(right);
                let end = self.nfa.len();
                self.nfa[split_idx] = NfaInstr::Split(split_idx + 1, right_start);
                self.nfa[jmp_idx] = NfaInstr::Jump(end);
            }
            Ast::Repeat { inner, min, max } => {
                // Hidden slot recording the input position where the WHOLE repeat
                // began (before the required min copies), so the unbounded loop's
                // empty-iteration guard can tell "the whole group consumed
                // nothing" from "only a trailing iteration is empty". Allocated
                // for unbounded repeats only (the only case the guard applies to).
                let group_start_slot = if max.is_none() {
                    let s = self.alloc_hidden_slot();
                    self.emit(NfaInstr::Save(s));
                    Some(s)
                } else {
                    None
                };

                // Emit min required copies
                for _ in 0..*min {
                    self.compile(inner);
                }

                match max {
                    None => {
                        // Unbounded greedy loop. Structure:
                        //   split: Split(body, exit)        ; prefer another iteration
                        //   body:  Save(iter_start); <inner>
                        //   post:  Split(split, guard)       ; prefer to loop again
                        //   guard: RepeatExitGuard(gs, is); Jump(exit)
                        //   exit:
                        // The guard lets an iteration flow to `exit` (recording
                        // its submatch) only if it consumed input or the whole
                        // repeat is still empty — reproducing glibc's at-most-one
                        // leading empty iteration (bd-1djvkw).
                        let group_start = group_start_slot.expect("unbounded repeat has gs slot");
                        let iter_start = self.alloc_hidden_slot();
                        let split_idx = self.emit(NfaInstr::Split(0, 0)); // patched below
                        self.emit(NfaInstr::Save(iter_start));
                        self.compile(inner);
                        let post_idx = self.emit(NfaInstr::Split(0, 0)); // patched below
                        let guard_idx = self.emit(NfaInstr::RepeatExitGuard {
                            group_start,
                            iter_start,
                        });
                        let jump_idx = self.emit(NfaInstr::Jump(0)); // patched below
                        let end = self.nfa.len();
                        // greedy: split prefers body (split_idx+1), else exit.
                        self.nfa[split_idx] = NfaInstr::Split(split_idx + 1, end);
                        // post: prefer looping (back to split), else the guard.
                        self.nfa[post_idx] = NfaInstr::Split(split_idx, guard_idx);
                        self.nfa[jump_idx] = NfaInstr::Jump(end);
                    }
                    Some(max_val) => {
                        // Bounded: emit optional copies for (max - min)
                        let remaining = max_val - min;
                        for _ in 0..remaining {
                            let split_idx = self.emit(NfaInstr::Split(0, 0));
                            self.compile(inner);
                            let end = self.nfa.len();
                            self.nfa[split_idx] = NfaInstr::Split(split_idx + 1, end);
                        }
                    }
                }
            }
        }
    }

    fn finish(mut self) -> Vec<NfaInstr> {
        self.nfa.push(NfaInstr::Accept);
        self.nfa
    }
}

// ---------------------------------------------------------------------------
// NFA Simulation — Pike VM with POSIX leftmost-longest semantics
// ---------------------------------------------------------------------------

struct PikeVm<'a> {
    nfa: &'a [NfaInstr],
    input: &'a [u8],
    num_slots: usize,
    eflags: i32,
    prefilter: Option<FirstByteSet>,
    literal_prefix: Option<&'a [u8]>,
    /// When true, the literal-prefix jump uses a case-insensitive substring
    /// search (the regex itself matches case-insensitively).
    literal_icase: bool,
}

/// Thread state in Pike VM
#[derive(Clone)]
struct Thread {
    pc: usize,
    slots: Vec<i32>,
}

#[derive(Clone, Copy)]
struct VmAnchors {
    notbol: bool,
    noteol: bool,
}

struct ClosureState<'a> {
    visited: &'a mut [u64],
    generation: u64,
}

impl<'a> PikeVm<'a> {
    fn new(
        nfa: &'a [NfaInstr],
        input: &'a [u8],
        num_slots: usize,
        eflags: i32,
        prefilter: Option<FirstByteSet>,
        literal_prefix: Option<&'a [u8]>,
        literal_icase: bool,
    ) -> Self {
        Self {
            nfa,
            input,
            num_slots,
            eflags,
            prefilter,
            literal_prefix,
            literal_icase,
        }
    }

    /// True iff a match cannot begin at `start` because its byte is not in the
    /// prefilter's first-byte set (or there is no byte left). Sound only because
    /// the prefilter is built for non-nullable, determinate-first-byte patterns.
    #[inline]
    fn prefilter_skips(&self, start: usize) -> bool {
        match self.prefilter {
            Some(fb) => start >= self.input.len() || !fb.contains(self.input[start]),
            None => false,
        }
    }

    /// Run the NFA, returning submatch slots if a match is found.
    /// For POSIX leftmost-longest: try each start position from left;
    /// for each start position, run all threads to find longest match.
    fn execute(&self) -> Option<Vec<i32>> {
        let notbol = self.eflags & REG_NOTBOL != 0;
        let noteol = self.eflags & REG_NOTEOL != 0;
        let input_len = self.input.len();

        // Closure-dedup scratch shared across every run_from in this execute:
        // `visited[pc] == cur_generation` means "already added in the set being built".
        // `generation` is monotonic (never reset) so a fresh per-build value never
        // collides with a stale stamp — letting us reuse one allocation.
        let mut visited = vec![0u64; self.nfa.len()];
        let mut generation = 0u64;

        // For large inputs, a single forward membership pass rules out a match
        // in O(n*m) instead of re-simulating from every start (O(n^2)) when
        // nothing matches — the worst case for `.`/`*`-leading patterns no
        // prefilter can prune. On a match it early-exits and we fall through to
        // the exact leftmost-longest search below. Sound: any_match reuses
        // add_thread, so it has no false negatives (never skips a real match).
        // Skip this O(n*m) forward pass whenever a cheaper path will determine the
        // result: a `literal_prefix` (SIMD memmem/strcasestr jump straight to
        // occurrences), or a first-byte `prefilter` on a SMALL nfa (the per-start
        // `run_from` below fails within a few bytes, so no O(n^2) blow-up). Running
        // the prescan first paid the full per-position thread-seeding cost
        // (~34 ns/byte → ~140 µs/4 KiB) before ever reaching those fast paths — the
        // pathological cost on `needle[0-9]+`-style absent searches. It is still
        // run for no-prefilter patterns and CLOSURE-HEAVY nfas (e.g. `a?…a?b` on
        // all-'a'), where per-start re-simulation would be O(n^2*m).
        const PRESCAN_MIN_LEN: usize = 256;
        const PRESCAN_SMALL_NFA: usize = 64;
        let cheaper_path = self.literal_prefix.is_some()
            || (self.prefilter.is_some() && self.nfa.len() < PRESCAN_SMALL_NFA);
        if !cheaper_path
            && input_len > PRESCAN_MIN_LEN
            && !self.any_match(notbol, noteol, &mut visited, &mut generation)
        {
            return None;
        }

        // Literal-prefix fast path: a match can only begin where the leading
        // literal occurs, so jump straight to each occurrence with SIMD memmem
        // instead of probing every start. Leftmost preserved (memmem scans L->R).
        if let Some(lit) = self.literal_prefix {
            let mut from = 0;
            while from + lit.len() <= input_len {
                let off = find_literal(&self.input[from..], lit, self.literal_icase)?;
                let start = from + off;
                let mut slots = vec![-1i32; self.num_slots];
                slots[0] = start as i32;
                if let Some(matched_slots) =
                    self.run_from(start, &slots, notbol, noteol, &mut visited, &mut generation)
                {
                    return Some(matched_slots);
                }
                from = start + 1;
            }
            return None;
        }

        // Find the leftmost matching START in one merged unanchored sweep
        // (O(n·m)) instead of probing every start with `run_from` (O(n²·m) when
        // no prefilter prunes and the match is late — a regex-DoS vector). The
        // exact captures still come from a single `run_from` at that start, so
        // the result is identical to the per-start loop below; a debug build
        // asserts that isomorphism on every input (so the differential fuzz
        // proves it across 2320 patterns vs glibc).
        let s_star = self.leftmost_start(notbol, noteol);

        #[cfg(debug_assertions)]
        {
            let mut probe = None;
            for start in 0..=input_len {
                if self.prefilter_skips(start) {
                    continue;
                }
                let mut slots = vec![-1i32; self.num_slots];
                slots[0] = start as i32;
                if self
                    .run_from(start, &slots, notbol, noteol, &mut visited, &mut generation)
                    .is_some()
                {
                    probe = Some(start);
                    break;
                }
            }
            debug_assert_eq!(
                s_star, probe,
                "leftmost_start disagrees with the per-start run_from probe"
            );
        }

        let start = s_star?;
        let mut slots = vec![-1i32; self.num_slots];
        slots[0] = start as i32; // group 0 start
        self.run_from(start, &slots, notbol, noteol, &mut visited, &mut generation)
    }

    /// Membership-only single forward pass: does ANY match exist? Seeds a
    /// start-thread at every position (so a match may begin anywhere) and
    /// accepts on the first reachable `Accept`. Reuses `add_thread`, so its
    /// epsilon-closure and anchor handling are byte-identical to the real
    /// search — guaranteeing no false negatives (it never reports "no match"
    /// when one exists). Slots are irrelevant here, so a dummy is carried.
    /// True when the NFA has no position-dependent zero-width assertion (no
    /// anchor or word-boundary). For such patterns the epsilon-closure and the
    /// byte transitions depend only on the input byte, so a deterministic
    /// closure-set automaton (lazy DFA) over the membership simulation is exact.
    fn is_pos_independent(&self) -> bool {
        !self.nfa.iter().any(|i| {
            matches!(
                i,
                NfaInstr::Match(
                    MatchKind::AnchorStart { .. }
                        | MatchKind::AnchorEnd { .. }
                        | MatchKind::WordBoundary { .. }
                        | MatchKind::WordStart
                        | MatchKind::WordEnd
                        | MatchKind::BufferStart
                        | MatchKind::BufferEnd
                )
            )
        })
    }

    /// Epsilon-closure frontier of `entries`: the consuming-`Match` and `Accept`
    /// PCs reachable through Split/Jump/Save, sorted+deduped so the set can key a
    /// DFA state. Reuses `add_thread` in membership mode (empty slots, so every
    /// closure clone is allocation-free and `Save` is a no-op).
    fn dfa_frontier(
        &self,
        entries: &[usize],
        scratch: &mut Vec<Thread>,
        visited: &mut [u64],
        generation: &mut u64,
    ) -> Vec<usize> {
        *generation += 1;
        let mut closure = ClosureState {
            visited,
            generation: *generation,
        };
        let anchors = VmAnchors {
            notbol: false,
            noteol: false,
        };
        scratch.clear();
        for &pc in entries {
            self.add_thread(
                scratch,
                Thread {
                    pc,
                    slots: Vec::new(),
                },
                0,
                anchors,
                &mut closure,
            );
        }
        let mut pcs: Vec<usize> = scratch.iter().map(|t| t.pc).collect();
        pcs.sort_unstable();
        pcs.dedup();
        pcs
    }

    /// Intern a frontier PC-set into a DFA state id, recording whether it
    /// accepts (contains an `Accept` PC).
    fn dfa_intern(
        &self,
        pcs: Vec<usize>,
        interner: &mut std::collections::HashMap<Box<[usize]>, u32>,
        state_pcs: &mut Vec<Box<[usize]>>,
        state_accepts: &mut Vec<bool>,
    ) -> u32 {
        let key: Box<[usize]> = pcs.into_boxed_slice();
        if let Some(&id) = interner.get(&key) {
            return id;
        }
        let id = state_pcs.len() as u32;
        let accepts = key
            .iter()
            .any(|&pc| matches!(self.nfa[pc], NfaInstr::Accept));
        state_pcs.push(key.clone());
        state_accepts.push(accepts);
        interner.insert(key, id);
        id
    }

    /// Lazy-DFA membership scan for position-independent patterns: does the
    /// pattern match starting at ANY position? Interns epsilon-closure frontier
    /// sets as DFA states and memoizes `(state, byte) -> state` transitions,
    /// turning the prescan's per-position O(m) closure re-walk into amortized
    /// O(1) lookups — O(n) overall once the DFA warms up, vs the NFA
    /// simulation's O(n*m) on closure-heavy patterns. Every transition re-seeds
    /// the start PC so the scan stays unanchored (matching `any_match_nfa`'s
    /// per-position start re-seed). Returns `None` on state-cap overflow
    /// (pathological state explosion) so the caller falls back to the NFA.
    fn any_match_dfa(&self, visited: &mut [u64], generation: &mut u64) -> Option<bool> {
        const MAX_STATES: usize = 4096;
        let mut scratch: Vec<Thread> = Vec::new();
        let mut interner: std::collections::HashMap<Box<[usize]>, u32> =
            std::collections::HashMap::new();
        let mut state_pcs: Vec<Box<[usize]>> = Vec::new();
        let mut state_accepts: Vec<bool> = Vec::new();
        let mut trans: std::collections::HashMap<(u32, u8), u32> = std::collections::HashMap::new();

        let start = self.dfa_frontier(&[0], &mut scratch, visited, generation);
        let mut state = self.dfa_intern(start, &mut interner, &mut state_pcs, &mut state_accepts);

        let input_len = self.input.len();
        let mut sp = 0usize;
        loop {
            if state_accepts[state as usize] {
                return Some(true);
            }
            if sp >= input_len {
                return Some(false);
            }
            let b = self.input[sp];
            state = match trans.get(&(state, b)) {
                Some(&n) => n,
                None => {
                    let mut entries: Vec<usize> =
                        Vec::with_capacity(state_pcs[state as usize].len() + 1);
                    entries.push(0); // unanchored: re-seed the start PC every step
                    for &pc in state_pcs[state as usize].iter() {
                        if let NfaInstr::Match(mk) = &self.nfa[pc]
                            && self.matches_byte(mk, b)
                        {
                            entries.push(pc + 1);
                        }
                    }
                    let frontier = self.dfa_frontier(&entries, &mut scratch, visited, generation);
                    let nid = self.dfa_intern(
                        frontier,
                        &mut interner,
                        &mut state_pcs,
                        &mut state_accepts,
                    );
                    if state_pcs.len() > MAX_STATES {
                        return None; // state explosion → fall back to NFA simulation
                    }
                    trans.insert((state, b), nid);
                    nid
                }
            };
            sp += 1;
        }
    }

    /// Membership prescan: does the pattern match at ANY position? Dispatches to
    /// the lazy DFA for position-independent patterns (the closure-heavy case
    /// the prescan exists for), falling back to the bounded NFA simulation for
    /// anchored/word-boundary patterns or on DFA state-cap overflow.
    fn any_match(
        &self,
        notbol: bool,
        noteol: bool,
        visited: &mut [u64],
        generation: &mut u64,
    ) -> bool {
        if self.is_pos_independent()
            && let Some(result) = self.any_match_dfa(visited, generation)
        {
            return result;
        }
        // DFA hit the state cap; fall back to the bounded NFA simulation.
        self.any_match_nfa(notbol, noteol, visited, generation)
    }

    fn any_match_nfa(
        &self,
        notbol: bool,
        noteol: bool,
        visited: &mut [u64],
        generation: &mut u64,
    ) -> bool {
        let input_len = self.input.len();
        // Membership-only: captures are never read here, so carry an EMPTY slots
        // vec. Every `slots.clone()` in the epsilon closure below is then a
        // zero-allocation clone of an empty Vec, and `Save` is bounds-guarded to a
        // no-op — turning the prior O(n*m) per-thread heap-clone storm (the
        // closure-heavy `a?…a?b` worst case) into pure pointer chasing.
        let dummy: Vec<i32> = Vec::new();
        let mut current: Vec<Thread> = Vec::new();
        let mut next: Vec<Thread> = Vec::new();
        let anchors = VmAnchors { notbol, noteol };
        let mut closure = ClosureState {
            visited,
            generation: 0,
        };

        // Seed the start-thread at position 0 (its own closure generation).
        *generation += 1;
        closure.generation = *generation;
        self.add_thread(
            &mut current,
            Thread {
                pc: 0,
                slots: dummy.clone(),
            },
            0,
            anchors,
            &mut closure,
        );

        // When the NFA has NO position-dependent epsilon assertion (no anchor /
        // word-boundary anywhere), the closure from pc=0 reaches the SAME Match
        // set at every start position. Capture it once and replay it below instead
        // of re-walking the whole closure at each of the n positions — the
        // closure-heavy `a?…a?b` prescan worst case becomes a flat PC copy.
        let pos_independent = !self.nfa.iter().any(|i| {
            matches!(
                i,
                NfaInstr::Match(
                    MatchKind::AnchorStart { .. }
                        | MatchKind::AnchorEnd { .. }
                        | MatchKind::WordBoundary { .. }
                        | MatchKind::WordStart
                        | MatchKind::WordEnd
                        | MatchKind::BufferStart
                        | MatchKind::BufferEnd
                )
            )
        });
        let start_pcs: Vec<usize> = if pos_independent {
            current.iter().map(|t| t.pc).collect()
        } else {
            Vec::new()
        };

        let mut sp = 0;
        loop {
            *generation += 1;
            closure.generation = *generation;
            for t in current.drain(..) {
                if t.pc >= self.nfa.len() {
                    continue;
                }
                match &self.nfa[t.pc] {
                    NfaInstr::Accept => return true,
                    NfaInstr::Match(mk) if self.matches(mk, sp, notbol, noteol) => {
                        self.add_thread(
                            &mut next,
                            Thread {
                                pc: t.pc + 1,
                                slots: t.slots,
                            },
                            sp + 1,
                            anchors,
                            &mut closure,
                        );
                    }
                    _ => {}
                }
            }
            if sp >= input_len {
                return false;
            }
            sp += 1;
            // Seed a fresh start-thread at the new position. For position-
            // independent patterns, replay the cached start closure (gen-stamped
            // for dedup against carried threads) instead of re-walking it; the
            // membership pass ignores thread order, so this is exact.
            if pos_independent {
                for &pc in &start_pcs {
                    if closure.visited[pc] != closure.generation {
                        closure.visited[pc] = closure.generation;
                        next.push(Thread {
                            pc,
                            slots: dummy.clone(),
                        });
                    }
                }
            } else {
                self.add_thread(
                    &mut next,
                    Thread {
                        pc: 0,
                        slots: dummy.clone(),
                    },
                    sp,
                    anchors,
                    &mut closure,
                );
            }
            core::mem::swap(&mut current, &mut next);
            next.clear();
        }
    }

    /// Epsilon-closure for the leftmost-start finder: walk Split/Jump/Save and
    /// the zero-width assertions from `pc` (carrying `start`), pushing each
    /// reachable consuming-`Match` / `Accept` PC paired with `start` onto `list`.
    /// Mirrors `add_thread_inner` exactly — same anchor helpers, same `Save`
    /// skip, same depth guard — but tracks only the thread's START position
    /// (captures are irrelevant; they come from `run_from` at the chosen start).
    /// `visited[pc] == cur_gen` dedups within one position; because entries are
    /// closed in start-ascending priority order, the first (smallest) start to
    /// reach a PC wins, so the recorded start is the minimum.
    #[allow(clippy::too_many_arguments)]
    fn lm_closure(
        &self,
        pc: usize,
        start: usize,
        sp: usize,
        notbol: bool,
        noteol: bool,
        list: &mut Vec<(usize, usize)>,
        visited: &mut [u64],
        cur_gen: u64,
        depth: usize,
    ) {
        if depth > Self::ADD_THREAD_MAX_DEPTH || pc >= self.nfa.len() {
            return;
        }
        if visited[pc] == cur_gen {
            return;
        }
        visited[pc] = cur_gen;
        match &self.nfa[pc] {
            NfaInstr::Split(a, b) => {
                self.lm_closure(
                    *a,
                    start,
                    sp,
                    notbol,
                    noteol,
                    list,
                    visited,
                    cur_gen,
                    depth + 1,
                );
                self.lm_closure(
                    *b,
                    start,
                    sp,
                    notbol,
                    noteol,
                    list,
                    visited,
                    cur_gen,
                    depth + 1,
                );
            }
            NfaInstr::Jump(t) => {
                self.lm_closure(
                    *t,
                    start,
                    sp,
                    notbol,
                    noteol,
                    list,
                    visited,
                    cur_gen,
                    depth + 1,
                );
            }
            NfaInstr::Save(_) | NfaInstr::RepeatExitGuard { .. } => {
                // Membership/leftmost-start: no captures, so the empty-iteration
                // guard never prunes (it only affects submatch recording); follow
                // the exit edge unconditionally to keep whole-match semantics.
                self.lm_closure(
                    pc + 1,
                    start,
                    sp,
                    notbol,
                    noteol,
                    list,
                    visited,
                    cur_gen,
                    depth + 1,
                );
            }
            NfaInstr::Match(mk) => match mk {
                MatchKind::AnchorStart { newline } => {
                    if self.check_anchor_start(sp, notbol, *newline) {
                        self.lm_closure(
                            pc + 1,
                            start,
                            sp,
                            notbol,
                            noteol,
                            list,
                            visited,
                            cur_gen,
                            depth + 1,
                        );
                    }
                }
                MatchKind::AnchorEnd { newline } => {
                    if self.check_anchor_end(sp, noteol, *newline) {
                        self.lm_closure(
                            pc + 1,
                            start,
                            sp,
                            notbol,
                            noteol,
                            list,
                            visited,
                            cur_gen,
                            depth + 1,
                        );
                    }
                }
                MatchKind::WordBoundary { .. }
                | MatchKind::WordStart
                | MatchKind::WordEnd
                | MatchKind::BufferStart
                | MatchKind::BufferEnd => {
                    if self.check_word_assertion(mk, sp) {
                        self.lm_closure(
                            pc + 1,
                            start,
                            sp,
                            notbol,
                            noteol,
                            list,
                            visited,
                            cur_gen,
                            depth + 1,
                        );
                    }
                }
                _ => list.push((pc, start)),
            },
            NfaInstr::Accept => list.push((pc, start)),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn lm_push_cached_closure(
        &self,
        pc: usize,
        start: usize,
        sp: usize,
        notbol: bool,
        noteol: bool,
        list: &mut Vec<(usize, usize)>,
        visited: &mut [u64],
        cur_gen: u64,
        use_cache: bool,
        cache: &mut [Option<Box<[usize]>>],
        cache_visited: &mut [u64],
        cache_gen: &mut u64,
        cache_scratch: &mut Vec<(usize, usize)>,
    ) {
        if !use_cache {
            self.lm_closure(pc, start, sp, notbol, noteol, list, visited, cur_gen, 0);
            return;
        }
        if pc >= cache.len() {
            return;
        }
        if cache[pc].is_none() {
            *cache_gen = cache_gen.wrapping_add(1);
            if *cache_gen == 0 {
                cache_visited.fill(0);
                *cache_gen = 1;
            }
            cache_scratch.clear();
            // Position-independent NFAs have no anchors or word assertions, so
            // the closure PCs depend only on the source PC, not on input offset.
            self.lm_closure(
                pc,
                0,
                0,
                false,
                false,
                cache_scratch,
                cache_visited,
                *cache_gen,
                0,
            );
            cache[pc] = Some(
                cache_scratch
                    .iter()
                    .map(|&(closed_pc, _)| closed_pc)
                    .collect::<Vec<_>>()
                    .into_boxed_slice(),
            );
        }
        if let Some(pcs) = &cache[pc] {
            for &closed_pc in pcs.iter() {
                if visited[closed_pc] != cur_gen {
                    visited[closed_pc] = cur_gen;
                    list.push((closed_pc, start));
                }
            }
        }
    }

    /// Find the leftmost START position at which the pattern matches, in a
    /// SINGLE unanchored NFA sweep that merges all start positions (deduped),
    /// instead of the per-start `run_from` probe loop. This is the leftmost
    /// match-start that `execute`'s `for start in 0..=len` loop would return —
    /// proven by an isomorphism `debug_assert` there — but in O(n·m) worst case
    /// rather than O(n²·m): every (pc, position) state is processed once across
    /// all starts. Threads carry their start; on `Accept` the smallest start
    /// wins. Pruning threads whose start exceeds the best, and returning as soon
    /// as no live thread can start earlier, keeps early/short matches O(match).
    fn leftmost_start(&self, notbol: bool, noteol: bool) -> Option<usize> {
        let input_len = self.input.len();
        let mut visited = vec![0u64; self.nfa.len()];
        let mut cur_gen = 0u64;
        let mut current: Vec<(usize, usize)> = Vec::new();
        let mut next: Vec<(usize, usize)> = Vec::new();
        let mut best: Option<usize> = None;
        let use_closure_cache = self.is_pos_independent();
        let mut closure_cache: Vec<Option<Box<[usize]>>> = if use_closure_cache {
            vec![None; self.nfa.len()]
        } else {
            Vec::new()
        };
        let mut cache_visited = if use_closure_cache {
            vec![0u64; self.nfa.len()]
        } else {
            Vec::new()
        };
        let mut cache_gen = 0u64;
        let mut cache_scratch: Vec<(usize, usize)> = Vec::new();

        cur_gen += 1;
        // A start whose first byte is not in the prefilter's first-byte set can
        // never begin a match (the prefilter implies a non-nullable, determinate-
        // first-byte pattern), so skip seeding it — exactly the soundness the
        // `#[cfg(debug_assertions)]` probe in `execute` checks via `prefilter_skips`.
        if !self.prefilter_skips(0) {
            self.lm_push_cached_closure(
                0,
                0,
                0,
                notbol,
                noteol,
                &mut current,
                &mut visited,
                cur_gen,
                use_closure_cache,
                &mut closure_cache,
                &mut cache_visited,
                &mut cache_gen,
                &mut cache_scratch,
            );
        }

        let bulk_table = self.build_bulk_loop_table();
        let mut sp = 0;
        loop {
            cur_gen += 1;
            for &(pc, start) in current.iter() {
                // A thread that starts at or after the best-known start cannot
                // lower it (and `> best` could never win leftmost), so skip it.
                if best.is_some_and(|b| start >= b) {
                    continue;
                }
                match &self.nfa[pc] {
                    NfaInstr::Accept => {
                        best = Some(best.map_or(start, |b| b.min(start)));
                    }
                    NfaInstr::Match(mk)
                        if sp < input_len && self.matches_byte(mk, self.input[sp]) =>
                    {
                        self.lm_push_cached_closure(
                            pc + 1,
                            start,
                            sp + 1,
                            notbol,
                            noteol,
                            &mut next,
                            &mut visited,
                            cur_gen,
                            use_closure_cache,
                            &mut closure_cache,
                            &mut cache_visited,
                            &mut cache_gen,
                            &mut cache_scratch,
                        );
                    }
                    _ => {}
                }
            }
            if sp >= input_len {
                return best;
            }
            sp += 1;
            // Seed a fresh start at the new position only if it could still beat
            // the best-known start (a later start can never be more leftmost) AND
            // its first byte can actually begin a match (prefilter prune — skips
            // the wasted epsilon-closure on every non-first-byte position, the
            // O(n) win on determinate-first-byte patterns over large inputs).
            if best.is_none_or(|b| sp < b) && !self.prefilter_skips(sp) {
                self.lm_push_cached_closure(
                    0,
                    sp,
                    sp,
                    notbol,
                    noteol,
                    &mut next,
                    &mut visited,
                    cur_gen,
                    use_closure_cache,
                    &mut closure_cache,
                    &mut cache_visited,
                    &mut cache_gen,
                    &mut cache_scratch,
                );
            }
            core::mem::swap(&mut current, &mut next);
            next.clear();
            // Fast-forward over dead regions: with no thread live and no match yet,
            // the next match can only BEGIN at the next prefilter byte, so scan
            // straight to it instead of stepping one empty position per iteration
            // (each otherwise pays the sweep's Vec-swap + seed machinery — the O(n)
            // residual that left determinate-first-byte search ~4x off glibc even
            // after the seed-prune). Sound: `current` is empty so nothing needs to
            // consume the skipped bytes, and a non-prefilter byte can never seed a
            // match — exactly the `prefilter_skips` predicate the debug probe checks.
            if best.is_none()
                && current.is_empty()
                && let Some(fb) = self.prefilter
            {
                match self
                    .input
                    .get(sp + 1..)
                    .and_then(|rest| rest.iter().position(|&b| fb.contains(b)))
                {
                    // `off` is measured from sp+1; the next iteration's `sp += 1`
                    // then lands the seed exactly on that prefilter byte.
                    Some(off) => sp += off,
                    // No further prefilter byte (or no byte left): no match can
                    // begin — and `best` is None here, so the result is None.
                    None => return best,
                }
            }
            // Fast-forward over a CLASS RUN: when the live set is exactly a
            // bulk-safe `class+` loop body plus its first-byte-disjoint exit (one
            // start, no match yet), every byte in the class keeps that 2-state set
            // invariant — the loop re-loops, the exit cannot fire — so scan straight
            // to the first non-class byte instead of re-deriving the closure at each
            // position. Sound: the set is a fixed point over the run, and a later
            // start inside the run can only be less-leftmost than the live one, so
            // the seeds skipped here never win. Generalizes the empty-region jump
            // above from "no live thread" to "one looping disjoint class".
            if best.is_none()
                && sp < input_len
                && let Some(class) = self.bulk_loop_class_lm(&bulk_table, &current)
                && class_set_contains(&class, self.input[sp])
            {
                let e = self.input[sp..]
                    .iter()
                    .position(|&b| !class_set_contains(&class, b))
                    .map_or(input_len, |o| sp + o);
                sp = e;
            }
            // `best` is final once no live thread can start earlier AND no later
            // seed could either (reseeding stops once `sp >= best`). Until then
            // the sweep must continue even when `current` is momentarily empty:
            // a fresh start seeded at a later position may still match (e.g.
            // `^world` only becomes viable just after the newline).
            if let Some(b) = best
                && sp >= b
                && !current.iter().any(|&(_, s)| s < b)
            {
                return Some(b);
            }
        }
    }

    /// Core bulk-safe test over a live PikeVm thread set (by PC): the set is a fixed
    /// point under a class run iff EXACTLY ONE thread is a `class+`/`class*` loop body
    /// (per `table`) and EVERY other thread is a `Match` whose accepted bytes are
    /// DISJOINT from that class (so no other thread fires, and none is `Accept`, while
    /// the run continues). Returns the loop class. Covers single- and multi-exit
    /// follows (`[0-9]+END`, `[0-9]+(END|STOP)`, `\w+[ \t;]`, `[^"]*"`).
    fn bulk_class_core(
        &self,
        table: &[Option<[u64; 4]>],
        pcs: impl Iterator<Item = usize> + Clone,
    ) -> Option<[u64; 4]> {
        let mut class: Option<[u64; 4]> = None;
        for pc in pcs.clone() {
            if let Some(c) = table[pc] {
                if class.is_some() {
                    return None; // more than one looping class — bail conservatively
                }
                class = Some(c);
            }
        }
        let class = class?;
        for pc in pcs {
            if table[pc].is_some() {
                continue; // the loop body itself
            }
            // Every non-loop thread must be a determinate Match disjoint from the
            // class (`None` rules out Accept / AnyChar / anchors — can't bulk past).
            match self.match_byte_set(pc) {
                Some(s) if sets_disjoint(&class, &s) => {}
                _ => return None,
            }
        }
        Some(class)
    }

    /// `leftmost_start` wrapper: bulk-safe only when every live thread shares one
    /// start (a single match attempt), else a skipped position could host a
    /// different, more-leftmost start.
    fn bulk_loop_class_lm(
        &self,
        table: &[Option<[u64; 4]>],
        current: &[(usize, usize)],
    ) -> Option<[u64; 4]> {
        if current.len() < 2 {
            return None;
        }
        let s0 = current[0].1;
        if current.iter().any(|&(_, s)| s != s0) {
            return None;
        }
        self.bulk_class_core(table, current.iter().map(|&(pc, _)| pc))
    }

    /// `run_from` wrapper: single start, so no shared-start guard is needed.
    fn bulk_loop_class_rf(
        &self,
        table: &[Option<[u64; 4]>],
        current: &[Thread],
    ) -> Option<[u64; 4]> {
        if current.len() < 2 {
            return None;
        }
        self.bulk_class_core(table, current.iter().map(|t| t.pc))
    }

    /// Precompute, once per search, the loop-body class of every PC that begins a
    /// `class+`/`class*` iteration: `nfa[pc]` is `Match(CharClass)` and its successor
    /// `Split` has a branch that epsilon-reaches back to `pc` (the `+`/`*` emit
    /// routes the loop-back through `Split`/`Save`/`RepeatExitGuard`/`Jump`, so the
    /// back-edge is indirect — a direct `Split(..pc..)` test misses it). `None`
    /// elsewhere. O(nfa²) once; the runtime bulk-scan is then a table lookup.
    fn build_bulk_loop_table(&self) -> Vec<Option<[u64; 4]>> {
        let n = self.nfa.len();
        let mut table = vec![None; n];
        let mut visited = vec![false; n];
        for pc in 0..n {
            let NfaInstr::Match(MatchKind::CharClass { set }) = &self.nfa[pc] else {
                continue;
            };
            // `pc` is a `class+`/`class*` loop body iff, after consuming a class byte
            // and stepping to `pc+1`, an epsilon path leads back to `pc` (to consume
            // again). This is structure-agnostic: `+` routes the back-edge through a
            // post-`Split`, `*` through a `Jump` to a leading `Split`, etc.
            visited.iter_mut().for_each(|v| *v = false);
            if self.epsilon_reaches(pc + 1, pc, &mut visited) {
                table[pc] = Some(*set);
            }
        }
        table
    }

    /// True iff `from` reaches `target` over epsilon (`Split`/`Jump`/`Save`/
    /// `RepeatExitGuard`) edges without consuming input. `visited` is reusable
    /// scratch (cleared by the caller); `Match`/`Accept` indices are leaves.
    fn epsilon_reaches(&self, from: usize, target: usize, visited: &mut [bool]) -> bool {
        let mut stack = vec![from];
        while let Some(p) = stack.pop() {
            if p == target {
                return true;
            }
            if p >= self.nfa.len() || visited[p] {
                continue;
            }
            visited[p] = true;
            match &self.nfa[p] {
                NfaInstr::Split(a, b) => {
                    stack.push(*a);
                    stack.push(*b);
                }
                NfaInstr::Jump(t) => stack.push(*t),
                NfaInstr::Save(_) | NfaInstr::RepeatExitGuard { .. } => stack.push(p + 1),
                NfaInstr::Match(_) | NfaInstr::Accept => {}
            }
        }
        false
    }

    /// The set of bytes `nfa[pc]`'s `Match` accepts, as a 256-bit table, or `None`
    /// when it is not a determinate byte test (`AnyChar`, anchors, non-`Match`).
    fn match_byte_set(&self, pc: usize) -> Option<[u64; 4]> {
        let NfaInstr::Match(mk) = self.nfa.get(pc)? else {
            return None;
        };
        let mut set = [0u64; 4];
        let mut bit = |b: u8| set[(b >> 6) as usize] |= 1u64 << (b & 63);
        match mk {
            MatchKind::Literal(c) => bit(*c),
            MatchKind::LiteralCi(lo, hi) => {
                bit(*lo);
                bit(*hi);
            }
            MatchKind::CharClass { set: s } => return Some(*s),
            _ => return None, // AnyChar / anchors: not disjointable
        }
        Some(set)
    }

    fn run_from(
        &self,
        start: usize,
        initial_slots: &[i32],
        notbol: bool,
        noteol: bool,
        visited: &mut [u64],
        generation: &mut u64,
    ) -> Option<Vec<i32>> {
        let mut current: Vec<Thread> = Vec::new();
        let mut next: Vec<Thread> = Vec::new();
        let mut best: Option<Vec<i32>> = None;
        let anchors = VmAnchors { notbol, noteol };
        let mut closure = ClosureState {
            visited,
            generation: 0,
        };

        // Add initial thread (its own closure generation).
        let init_thread = Thread {
            pc: 0,
            slots: initial_slots.to_vec(),
        };
        *generation += 1;
        closure.generation = *generation;
        self.add_thread(&mut current, init_thread, start, anchors, &mut closure);

        let bulk_table = self.build_bulk_loop_table();
        let input_len = self.input.len();
        let mut sp = start;

        loop {
            // Each step builds the `next` set in a fresh closure generation.
            *generation += 1;
            closure.generation = *generation;
            // Process all current threads
            for t in current.drain(..) {
                if t.pc >= self.nfa.len() {
                    continue;
                }
                match &self.nfa[t.pc] {
                    NfaInstr::Match(mk) if self.matches(mk, sp, notbol, noteol) => {
                        let new_t = Thread {
                            pc: t.pc + 1,
                            slots: t.slots,
                        };
                        self.add_thread(&mut next, new_t, sp + 1, anchors, &mut closure);
                    }
                    NfaInstr::Match(_) => {}
                    NfaInstr::Accept => {
                        let mut final_slots = t.slots;
                        final_slots[1] = sp as i32; // group 0 end
                        // POSIX: prefer longest match
                        if let Some(ref existing) = best {
                            if final_slots[1] > existing[1] {
                                best = Some(final_slots);
                            }
                        } else {
                            best = Some(final_slots);
                        }
                    }
                    // Split/Jump/Save should have been handled in add_thread
                    _ => {}
                }
            }

            if sp >= input_len {
                break;
            }
            if next.is_empty() && best.is_some() {
                break;
            }
            if next.is_empty() {
                break;
            }

            sp += 1;
            core::mem::swap(&mut current, &mut next);
            next.clear();
            // Bulk class-run fast-forward (mirrors `leftmost_start`): when the live
            // set is a `class+` loop body plus its first-byte-disjoint exit (two
            // threads, no match yet), every class byte keeps the set invariant and
            // leaves the capture slots untouched (the loop body has no `Save`), so
            // scan to the first non-class byte instead of re-deriving the closure at
            // each. This is the half of the long-run win `leftmost_start` cannot
            // reach alone (it confirms the start; `run_from` still walks the run to
            // extract the bounds). `run_from` is single-start, so the pair helper's
            // equal-start guard is satisfied with a shared dummy start.
            if best.is_none()
                && sp < input_len
                && let Some(class) = self.bulk_loop_class_rf(&bulk_table, &current)
                && class_set_contains(&class, self.input[sp])
            {
                let e = self.input[sp..]
                    .iter()
                    .position(|&b| !class_set_contains(&class, b))
                    .map_or(input_len, |o| sp + o);
                sp = e;
            }
        }

        best
    }

    /// Recursively add a thread, following epsilon transitions (Split, Jump, Save).
    fn add_thread(
        &self,
        threads: &mut Vec<Thread>,
        t: Thread,
        sp: usize,
        anchors: VmAnchors,
        closure: &mut ClosureState<'_>,
    ) {
        // Depth-limited wrapper to prevent stack overflow on deeply nested
        // alternations or pathological Jump chains.
        self.add_thread_inner(threads, t, sp, anchors, 0, closure);
    }

    /// Maximum epsilon-closure recursion depth. This bounds the stack usage
    /// for patterns with deeply nested alternations or long epsilon chains.
    /// The NFA size already limits the total work (duplicate-PC check at each
    /// level), but this prevents stack overflow for very large NFAs.
    const ADD_THREAD_MAX_DEPTH: usize = 256;

    fn add_thread_inner(
        &self,
        threads: &mut Vec<Thread>,
        t: Thread,
        sp: usize,
        anchors: VmAnchors,
        depth: usize,
        closure: &mut ClosureState<'_>,
    ) {
        if depth > Self::ADD_THREAD_MAX_DEPTH || t.pc >= self.nfa.len() {
            return;
        }

        // Avoid revisiting the same PC during this closure (thread priority:
        // first wins for POSIX). `visited[pc] == cur_generation` marks "already added in
        // the set currently being built"; `generation` is monotonic across the whole
        // execute(), so a stale stamp from an earlier set never collides. This
        // is an O(1) replacement for the prior O(set-size) linear scan and also
        // dedups epsilon PCs, preventing redundant closure re-walks.
        if closure.visited[t.pc] == closure.generation {
            return;
        }
        closure.visited[t.pc] = closure.generation;

        match &self.nfa[t.pc] {
            NfaInstr::Split(a, b) => {
                let t1 = Thread {
                    pc: *a,
                    slots: t.slots.clone(),
                };
                let t2 = Thread {
                    pc: *b,
                    slots: t.slots,
                };
                self.add_thread_inner(threads, t1, sp, anchors, depth + 1, closure);
                self.add_thread_inner(threads, t2, sp, anchors, depth + 1, closure);
            }
            NfaInstr::Jump(target) => {
                let new_t = Thread {
                    pc: *target,
                    slots: t.slots,
                };
                self.add_thread_inner(threads, new_t, sp, anchors, depth + 1, closure);
            }
            NfaInstr::Save(slot) => {
                let mut new_slots = t.slots;
                // `run_from` always carries full slots (*slot < num_slots); the
                // membership-only `any_match` carries an EMPTY slots vec (captures
                // are irrelevant there), so the bounds guard makes Save a no-op and
                // keeps every clone above allocation-free. Without this, any_match
                // paid an O(n*m) heap-clone storm on closure-heavy patterns.
                if *slot < new_slots.len() {
                    new_slots[*slot] = sp as i32;
                }
                let new_t = Thread {
                    pc: t.pc + 1,
                    slots: new_slots,
                };
                self.add_thread_inner(threads, new_t, sp, anchors, depth + 1, closure);
            }
            NfaInstr::RepeatExitGuard {
                group_start,
                iter_start,
            } => {
                // Allow this iteration to reach the loop exit only if it consumed
                // input, or the whole repeat is still empty. Membership-mode
                // threads carry empty `slots` (captures irrelevant): proceed
                // unconditionally there so whole-match semantics are untouched.
                let proceed = if *iter_start < t.slots.len() && *group_start < t.slots.len() {
                    sp as i32 > t.slots[*iter_start] || sp as i32 == t.slots[*group_start]
                } else {
                    true
                };
                if proceed {
                    let new_t = Thread {
                        pc: t.pc + 1,
                        slots: t.slots,
                    };
                    self.add_thread_inner(threads, new_t, sp, anchors, depth + 1, closure);
                }
            }
            NfaInstr::Match(mk) => {
                // For anchors, check inline so we don't waste a simulation step
                match mk {
                    MatchKind::AnchorStart { newline } => {
                        if self.check_anchor_start(sp, anchors.notbol, *newline) {
                            let new_t = Thread {
                                pc: t.pc + 1,
                                slots: t.slots,
                            };
                            self.add_thread_inner(threads, new_t, sp, anchors, depth + 1, closure);
                        }
                    }
                    MatchKind::AnchorEnd { newline } => {
                        if self.check_anchor_end(sp, anchors.noteol, *newline) {
                            let new_t = Thread {
                                pc: t.pc + 1,
                                slots: t.slots,
                            };
                            self.add_thread_inner(threads, new_t, sp, anchors, depth + 1, closure);
                        }
                    }
                    MatchKind::WordBoundary { .. }
                    | MatchKind::WordStart
                    | MatchKind::WordEnd
                    | MatchKind::BufferStart
                    | MatchKind::BufferEnd => {
                        if self.check_word_assertion(mk, sp) {
                            let new_t = Thread {
                                pc: t.pc + 1,
                                slots: t.slots,
                            };
                            self.add_thread_inner(threads, new_t, sp, anchors, depth + 1, closure);
                        }
                    }
                    _ => {
                        threads.push(t);
                    }
                }
            }
            NfaInstr::Accept => {
                threads.push(t);
            }
        }
    }

    fn check_anchor_start(&self, sp: usize, notbol: bool, newline: bool) -> bool {
        if sp == 0 {
            return !notbol;
        }
        if newline && sp > 0 && self.input[sp - 1] == b'\n' {
            return true;
        }
        false
    }

    fn check_anchor_end(&self, sp: usize, noteol: bool, newline: bool) -> bool {
        if sp == self.input.len() {
            return !noteol;
        }
        if newline && sp < self.input.len() && self.input[sp] == b'\n' {
            return true;
        }
        false
    }

    /// Evaluate a GNU word assertion at byte position `sp`. A position straddles
    /// a "left" char (`input[sp-1]`, absent at the text start) and a "right" char
    /// (`input[sp]`, absent at the text end); text edges count as non-word.
    fn check_word_assertion(&self, mk: &MatchKind, sp: usize) -> bool {
        let left = sp > 0 && regex_is_word_byte(self.input[sp - 1]);
        let right = sp < self.input.len() && regex_is_word_byte(self.input[sp]);
        match mk {
            MatchKind::WordBoundary { negate } => (left != right) != *negate,
            MatchKind::WordStart => !left && right,
            MatchKind::WordEnd => left && !right,
            // GNU buffer anchors: always the buffer edges (REG_NOTBOL/NOTEOL and
            // REG_NEWLINE do not affect them, unlike `^`/`$`).
            MatchKind::BufferStart => sp == 0,
            MatchKind::BufferEnd => sp == self.input.len(),
            _ => false,
        }
    }

    fn matches(&self, mk: &MatchKind, sp: usize, _notbol: bool, _noteol: bool) -> bool {
        if sp >= self.input.len() {
            return false;
        }
        self.matches_byte(mk, self.input[sp])
    }

    /// Whether a consuming `MatchKind` accepts the byte `ch`. This is the
    /// position-independent core of [`matches`](Self::matches) (which only adds
    /// the bounds check) — the single source of truth shared with the lazy-DFA
    /// membership scan in [`any_match_dfa`](Self::any_match_dfa). Zero-width
    /// assertions never consume a byte and return `false` here.
    fn matches_byte(&self, mk: &MatchKind, ch: u8) -> bool {
        match mk {
            MatchKind::Literal(lit) => ch == *lit,
            MatchKind::LiteralCi(lo, hi) => ch == *lo || ch == *hi,
            // glibc: `.` never matches NUL (only reachable via the binary-safe
            // byte path; the C-string path has already truncated at NUL).
            MatchKind::AnyChar { newline } => ch != 0 && !(*newline && ch == b'\n'),
            MatchKind::CharClass { set } => {
                // Single O(1) bit lookup; negation / ICASE / REG_NEWLINE are baked
                // into `set` at compile time (see `build_class_bitset`).
                (set[(ch >> 6) as usize] >> (ch & 63)) & 1 != 0
            }
            // Zero-width assertions are handled in add_thread, not here.
            MatchKind::AnchorStart { .. }
            | MatchKind::AnchorEnd { .. }
            | MatchKind::WordBoundary { .. }
            | MatchKind::WordStart
            | MatchKind::WordEnd
            | MatchKind::BufferStart
            | MatchKind::BufferEnd => false,
        }
    }
}

// ---------------------------------------------------------------------------
// Backreference execution — bounded backtracking for non-regular BREs
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct BacktrackState {
    pos: usize,
    slots: Vec<i32>,
}

#[derive(Clone, Copy)]
struct RepeatBounds {
    min: u32,
    max: Option<u32>,
}

struct BacktrackVm<'a> {
    ast: &'a Ast,
    input: &'a [u8],
    num_slots: usize,
    icase: bool,
    newline: bool,
    eflags: i32,
    prefilter: Option<FirstByteSet>,
    literal_prefix: Option<&'a [u8]>,
}

struct BacktrackConfig<'a> {
    ast: &'a Ast,
    input: &'a [u8],
    num_slots: usize,
    icase: bool,
    newline: bool,
    eflags: i32,
    prefilter: Option<FirstByteSet>,
    literal_prefix: Option<&'a [u8]>,
}

impl<'a> BacktrackVm<'a> {
    const MAX_DEPTH: usize = 512;
    const MAX_STATES: usize = 4096;

    fn new(config: BacktrackConfig<'a>) -> Self {
        Self {
            ast: config.ast,
            input: config.input,
            num_slots: config.num_slots,
            icase: config.icase,
            newline: config.newline,
            eflags: config.eflags,
            prefilter: config.prefilter,
            literal_prefix: config.literal_prefix,
        }
    }

    /// Longest match anchored at exactly `start`, or `None`.
    fn try_start(&self, start: usize) -> Option<Vec<i32>> {
        let mut slots = vec![-1i32; self.num_slots];
        slots[0] = start as i32;
        let mut best: Option<BacktrackState> = None;
        for state in self.match_ast(self.ast, start, slots, 0) {
            if best.as_ref().is_none_or(|current| state.pos > current.pos) {
                best = Some(state);
            }
        }
        best.map(|mut state| {
            state.slots[1] = state.pos as i32;
            state.slots
        })
    }

    fn execute(&self) -> Option<Vec<i32>> {
        // Literal-prefix fast path: jump to each occurrence via SIMD memmem.
        if let Some(lit) = self.literal_prefix {
            let input_len = self.input.len();
            let mut from = 0;
            while from + lit.len() <= input_len {
                let off = find_literal(&self.input[from..], lit, self.icase)?;
                let start = from + off;
                if let Some(slots) = self.try_start(start) {
                    return Some(slots);
                }
                from = start + 1;
            }
            return None;
        }

        for start in 0..=self.input.len() {
            // Prefilter: skip starts whose byte cannot begin a match, avoiding
            // the full backtracking attempt below (the O(n*m)-per-start cost).
            if let Some(fb) = self.prefilter
                && (start >= self.input.len() || !fb.contains(self.input[start]))
            {
                continue;
            }
            if let Some(slots) = self.try_start(start) {
                return Some(slots);
            }
        }
        None
    }

    fn match_ast(
        &self,
        ast: &Ast,
        pos: usize,
        slots: Vec<i32>,
        depth: usize,
    ) -> Vec<BacktrackState> {
        if depth > Self::MAX_DEPTH {
            return Vec::new();
        }

        match ast {
            Ast::Literal(byte) => {
                if self.byte_matches(*byte, pos) {
                    vec![BacktrackState {
                        pos: pos + 1,
                        slots,
                    }]
                } else {
                    Vec::new()
                }
            }
            Ast::AnyChar => {
                // glibc: `.` matches any byte EXCEPT '\n' (under REG_NEWLINE) and
                // EXCEPT the NUL byte. NUL only reaches the matcher via the
                // binary-safe byte path (REG_STARTEND / GNU APIs); the C-string
                // path truncates at the first NUL, so this is a no-op there.
                if pos < self.input.len()
                    && self.input[pos] != 0
                    && !(self.newline && self.input[pos] == b'\n')
                {
                    vec![BacktrackState {
                        pos: pos + 1,
                        slots,
                    }]
                } else {
                    Vec::new()
                }
            }
            Ast::CharClass { ranges, negated } => {
                if self.char_class_matches(ranges, *negated, pos) {
                    vec![BacktrackState {
                        pos: pos + 1,
                        slots,
                    }]
                } else {
                    Vec::new()
                }
            }
            Ast::Anchor(AnchorKind::Start { line }) => {
                if self.check_anchor_start(pos, *line) {
                    vec![BacktrackState { pos, slots }]
                } else {
                    Vec::new()
                }
            }
            Ast::Anchor(AnchorKind::End { line }) => {
                if self.check_anchor_end(pos, *line) {
                    vec![BacktrackState { pos, slots }]
                } else {
                    Vec::new()
                }
            }
            Ast::Anchor(
                kind @ (AnchorKind::WordBoundary { .. }
                | AnchorKind::WordStart
                | AnchorKind::WordEnd
                | AnchorKind::BufferStart
                | AnchorKind::BufferEnd),
            ) => {
                if self.check_word_assertion(*kind, pos) {
                    vec![BacktrackState { pos, slots }]
                } else {
                    Vec::new()
                }
            }
            Ast::Group { index, inner } => {
                let mut group_slots = slots;
                let open_slot = index * 2;
                let close_slot = open_slot + 1;
                if close_slot >= group_slots.len() {
                    return Vec::new();
                }
                group_slots[open_slot] = pos as i32;
                let mut out = Vec::new();
                for mut state in self.match_ast(inner, pos, group_slots, depth + 1) {
                    state.slots[close_slot] = state.pos as i32;
                    Self::push_state(&mut out, state);
                }
                out
            }
            Ast::BackRef(index) => self.match_backref(*index, pos, slots),
            Ast::Concat(items) => {
                let mut states = vec![BacktrackState { pos, slots }];
                for item in items {
                    let mut next = Vec::new();
                    for state in states {
                        for matched in self.match_ast(item, state.pos, state.slots, depth + 1) {
                            Self::push_state(&mut next, matched);
                        }
                    }
                    if next.is_empty() {
                        return Vec::new();
                    }
                    states = next;
                }
                states
            }
            Ast::Alternate(left, right) => {
                let mut out = self.match_ast(left, pos, slots.clone(), depth + 1);
                for state in self.match_ast(right, pos, slots, depth + 1) {
                    Self::push_state(&mut out, state);
                }
                out
            }
            Ast::Repeat { inner, min, max } => {
                let mut out = Vec::new();
                self.collect_repeat(
                    inner,
                    BacktrackState { pos, slots },
                    0,
                    RepeatBounds {
                        min: *min,
                        max: *max,
                    },
                    depth + 1,
                    &mut out,
                );
                out
            }
        }
    }

    fn collect_repeat(
        &self,
        inner: &Ast,
        state: BacktrackState,
        count: u32,
        bounds: RepeatBounds,
        depth: usize,
        out: &mut Vec<BacktrackState>,
    ) {
        if depth > Self::MAX_DEPTH || out.len() >= Self::MAX_STATES {
            return;
        }
        if count >= bounds.min {
            Self::push_state(out, state.clone());
        }
        if bounds.max.is_some_and(|limit| count >= limit) {
            return;
        }

        for next in self.match_ast(inner, state.pos, state.slots, depth + 1) {
            if next.pos == state.pos {
                if count + 1 >= bounds.min {
                    Self::push_state(out, next);
                }
                continue;
            }
            self.collect_repeat(inner, next, count + 1, bounds, depth + 1, out);
            if out.len() >= Self::MAX_STATES {
                return;
            }
        }
    }

    fn match_backref(&self, index: usize, pos: usize, slots: Vec<i32>) -> Vec<BacktrackState> {
        let open_slot = index * 2;
        let close_slot = open_slot + 1;
        if close_slot >= slots.len() {
            return Vec::new();
        }

        let start = slots[open_slot];
        let end = slots[close_slot];
        if start < 0 || end < start {
            return Vec::new();
        }

        let start = start as usize;
        let end = end as usize;
        let captured = &self.input[start..end];
        if pos + captured.len() > self.input.len() {
            return Vec::new();
        }

        let candidate = &self.input[pos..pos + captured.len()];
        if self.slices_equal(captured, candidate) {
            vec![BacktrackState {
                pos: pos + captured.len(),
                slots,
            }]
        } else {
            Vec::new()
        }
    }

    fn byte_matches(&self, expected: u8, pos: usize) -> bool {
        if pos >= self.input.len() {
            return false;
        }
        let actual = self.input[pos];
        if self.icase && expected.is_ascii_alphabetic() {
            actual.eq_ignore_ascii_case(&expected)
        } else {
            actual == expected
        }
    }

    fn char_class_matches(&self, ranges: &[(u8, u8)], negated: bool, pos: usize) -> bool {
        if pos >= self.input.len() {
            return false;
        }
        let ch = self.input[pos];
        let mut found = false;
        for &(lo, hi) in ranges {
            if self.icase {
                let ch_lo = ch.to_ascii_lowercase();
                for range_ch in lo..=hi {
                    if ch_lo == range_ch.to_ascii_lowercase() {
                        found = true;
                        break;
                    }
                }
            } else if ch >= lo && ch <= hi {
                found = true;
            }
            if found {
                break;
            }
        }
        if negated {
            // Under REG_NEWLINE a NONMATCHING list ("[^…]") never matches '\n',
            // even when '\n' is not listed (POSIX): "a <newline> shall not be
            // matched by ... any form of a nonmatching list".
            if self.newline && ch == b'\n' {
                return false;
            }
            !found
        } else {
            found
        }
    }

    fn slices_equal(&self, left: &[u8], right: &[u8]) -> bool {
        if left.len() != right.len() {
            return false;
        }
        left.iter().zip(right.iter()).all(|(a, b)| {
            if self.icase && a.is_ascii_alphabetic() {
                a.eq_ignore_ascii_case(b)
            } else {
                a == b
            }
        })
    }

    fn check_anchor_start(&self, pos: usize, line: bool) -> bool {
        let notbol = self.eflags & REG_NOTBOL != 0;
        if pos == 0 {
            return !notbol;
        }
        (line || self.newline) && self.input[pos - 1] == b'\n'
    }

    fn check_anchor_end(&self, pos: usize, line: bool) -> bool {
        let noteol = self.eflags & REG_NOTEOL != 0;
        if pos == self.input.len() {
            return !noteol;
        }
        (line || self.newline) && pos < self.input.len() && self.input[pos] == b'\n'
    }

    /// GNU word assertion (`\b`/`\B`/`\<`/`\>`) at `pos`; text edges count as
    /// non-word. Mirrors the Pike-VM evaluation for the backtracking path.
    fn check_word_assertion(&self, kind: AnchorKind, pos: usize) -> bool {
        let left = pos > 0 && regex_is_word_byte(self.input[pos - 1]);
        let right = pos < self.input.len() && regex_is_word_byte(self.input[pos]);
        match kind {
            AnchorKind::WordBoundary { negate } => (left != right) != negate,
            AnchorKind::WordStart => !left && right,
            AnchorKind::WordEnd => left && !right,
            AnchorKind::BufferStart => pos == 0,
            AnchorKind::BufferEnd => pos == self.input.len(),
            _ => false,
        }
    }

    fn push_state(out: &mut Vec<BacktrackState>, state: BacktrackState) {
        if out.len() < Self::MAX_STATES {
            out.push(state);
        }
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

fn ast_nullable(ast: &Ast) -> bool {
    analyze_ast(ast).nullable
}

/// Set the `line` flag on every `^`/`$` anchor that is NOT at a buffer-boundary
/// position. `bol` is true while a nullable prefix can still place the cursor at
/// match offset 0 (so a `^` here is the buffer-start anchor); `eol` is true while
/// a nullable suffix can still place the cursor at the buffer end (so a `$` here
/// is the buffer-end anchor). A non-leading `^` (and a non-leading, non-terminal
/// `$`) becomes newline-aware — matching glibc, which treats such anchors as
/// line anchors even without REG_NEWLINE. Returns whether `ast` is nullable.
fn mark_line_anchors(ast: &mut Ast, bol: bool, eol: bool) -> bool {
    match ast {
        Ast::Anchor(AnchorKind::Start { line }) => {
            *line = !bol;
            true
        }
        Ast::Anchor(AnchorKind::End { line }) => {
            *line = !eol;
            true
        }
        Ast::Anchor(_) => true,
        Ast::Literal(_) | Ast::AnyChar | Ast::CharClass { .. } | Ast::BackRef(_) => false,
        Ast::Group { inner, .. } => mark_line_anchors(inner, bol, eol),
        Ast::Alternate(l, r) => {
            // Both branches start from the same surrounding context.
            let a = mark_line_anchors(l, bol, eol);
            let b = mark_line_anchors(r, bol, eol);
            a || b
        }
        Ast::Repeat { inner, min, .. } => {
            // The body may sit at offset 0 (zero prior iterations) and at the end
            // (zero following iterations), so it inherits both contexts.
            let inner_nullable = mark_line_anchors(inner, bol, eol);
            *min == 0 || inner_nullable
        }
        Ast::Concat(items) => {
            // SOUND subset: mark a `^`/`$` newline-aware only when the prefix
            // (for `^`) / suffix (for `$`) is NON-nullable — i.e. it DEFINITELY
            // consumes, so the anchor cannot sit at a buffer boundary. When the
            // neighbor is nullable (`c?^`, `$a*`) glibc's behavior is ambiguous
            // (and `nmatch`-dependent once a capture group is involved), so those
            // keep the plain buffer-anchor semantics — never a regression vs the
            // prior uniform handling. bol propagates left-to-right, eol
            // right-to-left, both gated on nullability.
            let n = items.len();
            let mut bol_at = vec![false; n];
            let mut cur = bol;
            for i in 0..n {
                bol_at[i] = cur;
                cur = cur && ast_nullable(&items[i]);
            }
            let mut eol_at = vec![false; n];
            let mut cur = eol;
            for i in (0..n).rev() {
                eol_at[i] = cur;
                cur = cur && ast_nullable(&items[i]);
            }
            for (i, item) in items.iter_mut().enumerate() {
                mark_line_anchors(item, bol_at[i], eol_at[i]);
            }
            // Return value is unused by callers; report concat nullability.
            items.iter().all(ast_nullable)
        }
    }
}

pub fn regex_compile(pattern: &[u8], cflags: i32) -> Result<Box<CompiledRegex>, i32> {
    // Find null-terminated length
    let pat_len = pattern
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(pattern.len());
    regex_compile_bytes(&pattern[..pat_len], cflags)
}

/// Compile a regex pattern from an exact byte slice without truncating at the
/// first embedded NUL. The old GNU regex APIs use explicit pattern lengths and
/// therefore must remain binary-safe.
pub fn regex_compile_bytes(pattern: &[u8], cflags: i32) -> Result<Box<CompiledRegex>, i32> {
    let pat = pattern;
    let mut parser = Parser::new(pat, cflags);
    let mut ast = parser.parse()?;
    let num_groups = parser.group_count;

    // glibc mid-pattern line-anchor quirk: a `^`/`$` that is NOT at a buffer
    // boundary position matches at `\n` line boundaries even WITHOUT REG_NEWLINE.
    // Fill in the per-anchor `line` flag from prefix/suffix nullability (a `^`
    // is "leading" iff a nullable prefix can place it at offset 0; a `$` is
    // "terminal" iff a nullable suffix can place it at the buffer end). BRE only
    // keeps anchors at terminal/leading positions, so they stay `line == false`.
    mark_line_anchors(&mut ast, true, true);

    let icase = cflags & REG_ICASE != 0;
    let newline = cflags & REG_NEWLINE != 0;
    let nosub = cflags & REG_NOSUB != 0;
    let has_backref = ast_contains_backref(&ast);

    let mut total_slots = (num_groups + 1) * 2;
    let (nfa, estimated_states) = if has_backref {
        (Vec::new(), estimate_nfa_states(&ast))
    } else {
        let mut compiler = Compiler::new(icase, newline, num_groups);
        // Wrap entire pattern in group 0
        compiler.emit(NfaInstr::Save(0));
        compiler.compile(&ast);
        compiler.emit(NfaInstr::Save(1));
        total_slots = compiler.next_hidden_slot;
        let nfa = compiler.finish();
        let estimated_states = nfa.len();
        (nfa, estimated_states)
    };
    let complexity_certificate = build_complexity_certificate(pat, &ast, estimated_states);

    // First-byte prefilter: sound only when every match must consume a byte from
    // a determinate, proper subset of [0,256) at its start. `nullable` rules out
    // zero-width matches (which could start anywhere); `any` rules out
    // `.`-leading patterns; `icase` is excluded because the first-byte set is
    // computed case-sensitively from the AST. Anchors are handled for free: a
    // leading `^` is nullable so the concat prefix still yields the next literal
    // byte, and a non-line-start candidate simply fails the anchor in the VM.
    // A >= 2-byte leading literal lets the search jump via SIMD memmem; it
    // supersedes the single-byte set, so the two are mutually exclusive.
    let (literal_prefix, prefilter) = {
        let analysis = analyze_ast(&ast);
        if analysis.nullable {
            (None, None)
        } else if icase {
            // Case-insensitive: a >= 2-byte leading literal can still be jumped
            // to with a case-folding search (strcasestr); otherwise fold the
            // single-byte set so a start byte of either case stays a candidate.
            let lit = leading_literal_prefix(&ast);
            if lit.len() >= 2 {
                (Some(lit), None)
            } else {
                let fb = analysis.first_bytes.fold_ascii_case();
                if !fb.any && fb.count() > 0 {
                    (None, Some(fb))
                } else {
                    (None, None)
                }
            }
        } else {
            let lit = leading_literal_prefix(&ast);
            if lit.len() >= 2 {
                (Some(lit), None)
            } else if !analysis.first_bytes.any && analysis.first_bytes.count() > 0 {
                (None, Some(analysis.first_bytes))
            } else {
                (None, None)
            }
        }
    };

    // Required-literal fast-reject set (a sound subset of the bytes every match must
    // contain). Skip when case-insensitive (a literal could match either case) or when
    // a `literal_prefix` already drives a memmem search — both make it redundant.
    let required_bytes = if icase || literal_prefix.is_some() {
        Vec::new()
    } else {
        required_literal_bytes(&ast)
    };

    // Required contiguous substring (longest top-level literal run, >= 2 bytes). Same
    // skip conditions as `required_bytes`; strictly stronger when it applies.
    let required_substring = if icase || literal_prefix.is_some() {
        Vec::new()
    } else {
        required_literal_run(&ast)
    };

    let backtrack_ast = if has_backref { Some(ast) } else { None };

    Ok(Box::new(CompiledRegex {
        nfa,
        backtrack_ast,
        num_groups,
        total_slots,
        nosub,
        icase,
        newline,
        complexity_certificate,
        prefilter,
        literal_prefix,
        required_bytes,
        required_substring,
    }))
}

/// Execute a compiled regex against input.
/// Returns matched subgroups or REG_NOMATCH.
pub fn regex_exec(
    compiled: &CompiledRegex,
    input: &[u8],
    matches: &mut [RegMatch],
    eflags: i32,
) -> i32 {
    match regex_exec_cstring_slots(compiled, input, eflags) {
        None => REG_NOMATCH,
        Some(slots) => {
            if !compiled.nosub && !matches.is_empty() {
                // Only the capture slots are caller-visible; hidden repeat-progress
                // slots live above them and must never leak into `pmatch`.
                let cap = (compiled.num_groups + 1) * 2;
                for (i, m) in matches.iter_mut().enumerate() {
                    let so_idx = i * 2;
                    let eo_idx = i * 2 + 1;
                    if eo_idx < cap {
                        m.rm_so = slots[so_idx];
                        m.rm_eo = slots[eo_idx];
                    } else {
                        m.rm_so = -1;
                        m.rm_eo = -1;
                    }
                }
            }
            0
        }
    }
}

/// Execute a compiled regex against an exact byte slice without truncating at
/// the first embedded NUL. The old GNU regex APIs use explicit lengths and
/// therefore must remain binary-safe.
pub fn regex_exec_bytes(
    compiled: &CompiledRegex,
    input: &[u8],
    matches: &mut [RegMatch],
    eflags: i32,
) -> i32 {
    match regex_exec_byte_slots(compiled, input, eflags) {
        None => REG_NOMATCH,
        Some(slots) => {
            if !compiled.nosub && !matches.is_empty() {
                // Only the capture slots are caller-visible; hidden repeat-progress
                // slots live above them and must never leak into `pmatch`.
                let cap = (compiled.num_groups + 1) * 2;
                for (i, m) in matches.iter_mut().enumerate() {
                    let so_idx = i * 2;
                    let eo_idx = i * 2 + 1;
                    if eo_idx < cap {
                        m.rm_so = slots[so_idx];
                        m.rm_eo = slots[eo_idx];
                    } else {
                        m.rm_so = -1;
                        m.rm_eo = -1;
                    }
                }
            }
            0
        }
    }
}

/// Execute a compiled regex and return the whole-match offsets even when
/// REG_NOSUB suppresses submatch materialization.
pub fn regex_match_bounds(
    compiled: &CompiledRegex,
    input: &[u8],
    eflags: i32,
) -> Option<(i32, i32)> {
    let slots = regex_exec_cstring_slots(compiled, input, eflags)?;
    Some((*slots.first().unwrap_or(&-1), *slots.get(1).unwrap_or(&-1)))
}

/// Execute a compiled regex and return whole-match offsets for an exact byte
/// slice, preserving embedded NULs.
pub fn regex_match_bounds_bytes(
    compiled: &CompiledRegex,
    input: &[u8],
    eflags: i32,
) -> Option<(i32, i32)> {
    let slots = regex_exec_byte_slots(compiled, input, eflags)?;
    Some((*slots.first().unwrap_or(&-1), *slots.get(1).unwrap_or(&-1)))
}

/// Bytes that MUST appear in every string the regex matches — a sound, conservative
/// necessary condition for a match. Used as a `memchr` fast-reject before the VM.
///
/// SOUNDNESS: the returned set is always a SUBSET of the true required set, so a byte
/// present here is genuinely required in every match (its absence proves no match).
/// Built so that uncertainty only ever DROPS bytes (never adds a non-required one):
/// `Repeat{min=0}` (can match empty), `Alternate` (no byte need be common to both
/// branches), `AnyChar`/`CharClass`/`Anchor`/`BackRef` all contribute nothing.
fn required_literal_bytes(ast: &Ast) -> Vec<u8> {
    fn collect(ast: &Ast, out: &mut Vec<u8>) {
        match ast {
            Ast::Literal(b) => out.push(*b),
            Ast::Group { inner, .. } => collect(inner, out),
            Ast::Concat(items) => {
                for it in items {
                    collect(it, out);
                }
            }
            Ast::Repeat { inner, min, .. } => {
                if *min >= 1 {
                    collect(inner, out);
                }
            }
            // Alternate / AnyChar / CharClass / Anchor / BackRef: no single byte is
            // guaranteed across all matches — contribute nothing (keeps the set sound).
            _ => {}
        }
    }
    let mut set = Vec::new();
    collect(ast, &mut set);
    set.sort_unstable();
    set.dedup();
    set.retain(|&b| b != 0); // never gate on NUL (cstring inputs exclude it)
    set
}

/// Longest contiguous run of literal bytes that every match must contain — a SOUND
/// required substring used as a `memmem` fast-reject. Scans the top-level `Concat` for the
/// longest maximal run of consecutive `Ast::Literal` nodes (which are matched contiguously)
/// and recurses into a sole `Group`. Anything non-literal (`Repeat`, `Alternate`,
/// `AnyChar`, `CharClass`, `Anchor`, `BackRef`) breaks the run. Conservative: the result is
/// always a genuinely-required contiguous substring, so its absence proves no-match.
/// Returns empty if the longest run is < 2 bytes or contains a NUL.
fn required_literal_run(ast: &Ast) -> Vec<u8> {
    fn scan(ast: &Ast) -> Vec<u8> {
        match ast {
            Ast::Group { inner, .. } => scan(inner),
            Ast::Concat(items) => {
                let mut best: Vec<u8> = Vec::new();
                let mut cur: Vec<u8> = Vec::new();
                for it in items {
                    if let Ast::Literal(b) = it {
                        cur.push(*b);
                    } else {
                        if cur.len() > best.len() {
                            best = core::mem::take(&mut cur);
                        } else {
                            cur.clear();
                        }
                    }
                }
                if cur.len() > best.len() {
                    best = cur;
                }
                best
            }
            _ => Vec::new(),
        }
    }
    let run = scan(ast);
    if run.len() >= 2 && !run.contains(&0) {
        run
    } else {
        Vec::new()
    }
}

fn regex_exec_cstring_slots(
    compiled: &CompiledRegex,
    input: &[u8],
    eflags: i32,
) -> Option<Vec<i32>> {
    // Find null-terminated length
    let input_len = input.iter().position(|&b| b == 0).unwrap_or(input.len());
    regex_exec_byte_slots(compiled, &input[..input_len], eflags)
}

fn regex_exec_byte_slots(compiled: &CompiledRegex, input: &[u8], eflags: i32) -> Option<Vec<i32>> {
    let num_slots = compiled.num_slots();

    // Required-substring fast reject (strongest): every match must contain this contiguous
    // run, so if `memmem` can't find it, no match is possible — and unlike the per-byte
    // check below, this still rejects when the run's individual bytes are all present but
    // SCATTERED (the common case for literal-ish patterns over natural text).
    if !compiled.required_substring.is_empty() {
        let sub = &compiled.required_substring;
        if crate::string::mem::memmem(input, input.len(), sub, sub.len()).is_none() {
            return None;
        }
    }

    // Required-literal fast reject: every match must contain each byte in
    // `required_bytes` (a sound subset of the truly-required bytes). If the input
    // lacks any of them, no match is possible — a SIMD `memchr` per byte is far cheaper
    // than seeding the VM at every start position. Sound: the set never holds a
    // non-required byte, so a real match is never wrongly rejected.
    for &rb in &compiled.required_bytes {
        if crate::string::mem::memchr(input, rb, input.len()).is_none() {
            return None;
        }
    }

    if let Some(ast) = compiled.backtrack_ast.as_ref() {
        let vm = BacktrackVm::new(BacktrackConfig {
            ast,
            input,
            num_slots,
            icase: compiled.icase,
            newline: compiled.newline,
            eflags,
            prefilter: compiled.prefilter,
            literal_prefix: compiled.literal_prefix.as_deref(),
        });
        return vm.execute();
    }

    let vm = PikeVm::new(
        &compiled.nfa,
        input,
        num_slots,
        eflags,
        compiled.prefilter,
        compiled.literal_prefix.as_deref(),
        compiled.icase,
    );

    // REG_NOSUB fast path: only the boolean match/no-match decision is
    // observable (pmatch is never filled), so skip the O(n*m) leftmost_start +
    // run_from offset search and answer with the exact membership pass — a lazy
    // DFA for position-independent patterns. `any_match` has neither false
    // negatives nor false positives (reaching an `Accept` proves a real match
    // path exists; it is already trusted as `execute`'s sound prescan), so it
    // agrees with `execute().is_some()` on every input. Skipped when a literal
    // prefix is present: `execute` already jumps straight to occurrences via
    // SIMD memmem there, which beats seeding a thread at every position.
    if compiled.nosub && compiled.literal_prefix.is_none() {
        let notbol = eflags & REG_NOTBOL != 0;
        let noteol = eflags & REG_NOTEOL != 0;
        let mut visited = vec![0u64; compiled.nfa.len()];
        let mut generation = 0u64;
        return if vm.any_match(notbol, noteol, &mut visited, &mut generation) {
            Some(Vec::new())
        } else {
            None
        };
    }

    vm.execute()
}

/// Map an error code to a human-readable message.
pub fn regex_error(errcode: i32) -> &'static str {
    match errcode {
        0 => "Success",
        REG_NOMATCH => "No match",
        REG_BADPAT => "Invalid regular expression",
        // Messages are glibc's exact `__re_error_msgid` strings so `regerror`
        // output is byte-identical (verified by conformance_diff_regerror).
        REG_ECOLLATE => "Invalid collation character",
        REG_ECTYPE => "Invalid character class name",
        REG_EESCAPE => "Trailing backslash",
        REG_ESUBREG => "Invalid back reference",
        REG_EBRACK => "Unmatched [, [^, [:, [., or [=",
        REG_EPAREN => "Unmatched ( or \\(",
        REG_EBRACE => "Unmatched \\{",
        REG_BADBR => "Invalid content of \\{\\}",
        REG_ERANGE => "Invalid range end",
        REG_ESPACE => "Memory exhausted",
        REG_BADRPT => "Invalid preceding regular expression",
        REG_EEND => "Premature end of regular expression",
        REG_ESIZE => "Regular expression too big",
        REG_ERPAREN => "Unmatched ) or \\)",
        _ => "Unknown error",
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    type MatchBounds = Option<(i32, i32)>;
    type BorrowedRegexCase<'a> = (&'a str, &'a str, MatchBounds);
    type OwnedRegexCase<'a> = (&'a str, String, MatchBounds);

    fn compile_and_match(pattern: &str, input: &str, cflags: i32) -> bool {
        let compiled = regex_compile(pattern.as_bytes(), cflags).unwrap();
        let mut matches = [RegMatch::default(); 10];
        regex_exec(&compiled, input.as_bytes(), &mut matches, 0) == 0
    }

    fn compile_and_submatch(pattern: &str, input: &str, cflags: i32) -> (bool, Vec<(i32, i32)>) {
        let compiled = regex_compile(pattern.as_bytes(), cflags).unwrap();
        let mut matches = [RegMatch::default(); 10];
        let result = regex_exec(&compiled, input.as_bytes(), &mut matches, 0);
        let subs: Vec<(i32, i32)> = matches.iter().map(|m| (m.rm_so, m.rm_eo)).collect();
        (result == 0, subs)
    }

    /// Empty/nullable quantified-group submatch offsets must record the
    /// PARTICIPATING empty span [p,p] like glibc, not drop to [-1,-1], while a
    /// trailing empty iteration must NOT overwrite a non-empty capture (the
    /// `..(b*)+` case that regressed a prior naive fix). bd-1djvkw. Expected
    /// offsets captured from host glibc.
    #[test]
    fn empty_iter_submatch_offsets_match_glibc() {
        // (pattern, input, [(group, so, eo) ...]) — REG_EXTENDED.
        type SubmatchCase = (&'static str, &'static str, &'static [(usize, i32, i32)]);
        let cases: &[SubmatchCase] = &[
            (".()*a", "ba", &[(0, 0, 2), (1, 1, 1)]),
            ("(a?)*", ".baaa", &[(0, 0, 0), (1, 0, 0)]),
            ("(a*)*b?", "b", &[(0, 0, 1), (1, 0, 0)]),
            ("((a?b?))*", "", &[(0, 0, 0), (1, 0, 0), (2, 0, 0)]),
            ("a(a*)*", ".ab", &[(0, 1, 2), (1, 2, 2)]),
            ("((a*)*a)", "abaaa", &[(0, 0, 1), (1, 0, 1), (2, 0, 0)]),
            // Trailing empty iteration must keep the non-empty capture [2,4].
            ("..(b*)+", "aabba", &[(0, 0, 4), (1, 2, 4)]),
        ];
        for &(pat, inp, expect) in cases {
            let (matched, subs) = compile_and_submatch(pat, inp, REG_EXTENDED);
            assert!(matched, "pattern {pat:?} on {inp:?} should match");
            for &(g, so, eo) in expect {
                assert_eq!(
                    subs[g],
                    (so, eo),
                    "pattern {pat:?} on {inp:?}: group {g} = {:?}, want ({so},{eo})",
                    subs[g]
                );
            }
        }
    }

    #[test]
    fn cstring_exec_stops_at_embedded_nul() {
        let compiled = regex_compile(b"c", REG_EXTENDED).unwrap();
        let mut matches = [RegMatch::default(); 2];
        assert_eq!(
            regex_exec(&compiled, b"ab\0c", &mut matches, 0),
            REG_NOMATCH
        );
        assert_eq!(regex_match_bounds(&compiled, b"ab\0c", 0), None);
    }

    #[test]
    fn byte_exec_preserves_embedded_nul_bytes() {
        let compiled = regex_compile(b"c", REG_EXTENDED).unwrap();
        let mut matches = [RegMatch::default(); 2];
        assert_eq!(regex_exec_bytes(&compiled, b"ab\0c", &mut matches, 0), 0);
        assert_eq!(matches[0].rm_so, 3);
        assert_eq!(matches[0].rm_eo, 4);
        assert_eq!(
            regex_match_bounds_bytes(&compiled, b"ab\0c", 0),
            Some((3, 4))
        );
    }

    #[test]
    fn cstring_compile_truncates_pattern_at_embedded_nul() {
        let compiled = regex_compile(b"c\0d", REG_EXTENDED).unwrap();
        assert_eq!(
            regex_match_bounds_bytes(&compiled, b"xc\0dy", 0),
            Some((1, 2))
        );
    }

    #[test]
    fn byte_compile_preserves_embedded_nul_bytes() {
        let compiled = regex_compile_bytes(b"c\0d", REG_EXTENDED).unwrap();
        let mut matches = [RegMatch::default(); 2];
        assert_eq!(regex_exec_bytes(&compiled, b"xc\0dy", &mut matches, 0), 0);
        assert_eq!(matches[0].rm_so, 1);
        assert_eq!(matches[0].rm_eo, 4);
        assert_eq!(
            regex_match_bounds_bytes(&compiled, b"xc\0dy", 0),
            Some((1, 4))
        );
    }

    #[test]
    fn literal_match() {
        assert!(compile_and_match("hello", "hello world", REG_EXTENDED));
        assert!(compile_and_match("world", "hello world", REG_EXTENDED));
        assert!(!compile_and_match("xyz", "hello world", REG_EXTENDED));
    }

    #[test]
    fn dot_matches_any() {
        assert!(compile_and_match("h.llo", "hello", REG_EXTENDED));
        assert!(compile_and_match("h..lo", "hello", REG_EXTENDED));
        assert!(!compile_and_match("h...lo", "hello", REG_EXTENDED));
    }

    #[test]
    fn anchors() {
        assert!(compile_and_match("^hello", "hello world", REG_EXTENDED));
        assert!(!compile_and_match("^world", "hello world", REG_EXTENDED));
        assert!(compile_and_match("world$", "hello world", REG_EXTENDED));
        assert!(!compile_and_match("hello$", "hello world", REG_EXTENDED));
        assert!(compile_and_match(
            "^hello world$",
            "hello world",
            REG_EXTENDED
        ));
    }

    #[test]
    fn star_quantifier() {
        assert!(compile_and_match("ab*c", "ac", REG_EXTENDED));
        assert!(compile_and_match("ab*c", "abc", REG_EXTENDED));
        assert!(compile_and_match("ab*c", "abbbbc", REG_EXTENDED));
        assert!(!compile_and_match("ab*c", "abbbbd", REG_EXTENDED));
    }

    #[test]
    fn plus_quantifier() {
        assert!(!compile_and_match("ab+c", "ac", REG_EXTENDED));
        assert!(compile_and_match("ab+c", "abc", REG_EXTENDED));
        assert!(compile_and_match("ab+c", "abbbbc", REG_EXTENDED));
    }

    #[test]
    fn question_quantifier() {
        assert!(compile_and_match("ab?c", "ac", REG_EXTENDED));
        assert!(compile_and_match("ab?c", "abc", REG_EXTENDED));
        assert!(!compile_and_match("ab?c", "abbc", REG_EXTENDED));
    }

    #[test]
    fn alternation() {
        assert!(compile_and_match("cat|dog", "I have a cat", REG_EXTENDED));
        assert!(compile_and_match("cat|dog", "I have a dog", REG_EXTENDED));
        assert!(!compile_and_match("cat|dog", "I have a fish", REG_EXTENDED));
    }

    #[test]
    fn character_class() {
        assert!(compile_and_match("[abc]", "a", REG_EXTENDED));
        assert!(compile_and_match("[abc]", "b", REG_EXTENDED));
        assert!(!compile_and_match("[abc]", "d", REG_EXTENDED));
        assert!(compile_and_match("[a-z]", "m", REG_EXTENDED));
        assert!(!compile_and_match("[a-z]", "M", REG_EXTENDED));
    }

    #[test]
    fn negated_character_class() {
        assert!(!compile_and_match("[^abc]", "a", REG_EXTENDED));
        assert!(compile_and_match("[^abc]", "d", REG_EXTENDED));
    }

    #[test]
    fn first_byte_prefilter_preserves_match_positions() {
        // Each case exercises the unanchored search where the first-byte
        // prefilter skips non-candidate starts. The whole-match offsets must be
        // identical to a full scan: match at start / middle / not-at-all, plus
        // char-class / plus / negated-class / backref leading bytes.
        let cases: &[BorrowedRegexCase<'_>] = &[
            ("abc", "abcxx", Some((0, 3))),      // at start
            ("abc", "xxabcxx", Some((2, 5))),    // skip to candidate in the middle
            ("abc", "xxxxxxxx", None),           // absent -> skip everything
            ("abc", "ababcab", Some((2, 5))),    // false candidate at 0, real at 2
            ("[xy]z", "aazbxz", Some((4, 6))),   // char-class first byte
            ("a+b", "cccaaab", Some((3, 7))),    // plus-leading
            ("[^abc]d", "xxbdyd", Some((4, 6))), // negated class (prefilter=any)
            ("xyz", "", None),                   // empty input
        ];
        for &(pat, input, expected) in cases {
            let (matched, subs) = compile_and_submatch(pat, input, REG_EXTENDED);
            let got = if matched { Some(subs[0]) } else { None };
            assert_eq!(got, expected, "pattern {pat:?} on input {input:?}");
        }
    }

    #[test]
    fn icase_first_byte_prefilter_folds_case() {
        // The case-folded first-byte prefilter must not skip a start whose byte
        // is the opposite case of the pattern's first literal.
        let icase = REG_EXTENDED | REG_ICASE;
        let cases: &[BorrowedRegexCase<'_>] = &[
            ("abc", "xxABCxx", Some((2, 5))), // upper input, lower pattern
            ("ABC", "xxabcxx", Some((2, 5))), // lower input, upper pattern
            ("abc", "xxAbCxx", Some((2, 5))), // mixed
            ("abc", "xxxyzxx", None),         // absent
            ("a+b", "cccAAAB", Some((3, 7))), // folded plus-leading
        ];
        for &(pat, input, expected) in cases {
            let (matched, subs) = compile_and_submatch(pat, input, icase);
            let got = if matched { Some(subs[0]) } else { None };
            assert_eq!(got, expected, "icase pattern {pat:?} on input {input:?}");
        }
    }

    #[test]
    fn membership_prescan_preserves_results_on_large_inputs() {
        // Inputs > the prescan threshold (256) so the single-pass membership
        // guard fires. `.`/`*`-leading patterns have no prefilter, so this is
        // exactly the path the prescan must keep correct: no-match returns None
        // in one pass; a real match (incl. at the very end) still falls through
        // to the exact search and reports identical bounds.
        let big = 600usize;
        let a_run: String = core::iter::repeat_n('a', big).collect();
        let cases: &[OwnedRegexCase<'_>] = &[
            (".*x", a_run.clone(), None), // no-match, prescan rules out
            (".*x", format!("{a_run}x"), Some((0, big as i32 + 1))), // match at end
            ("a*z", a_run.clone(), None), // greedy no-match
            ("[bc]+", a_run.clone(), None), // class, none present
            (
                "a",
                format!("{}a{}", "b".repeat(300), "b".repeat(300)),
                Some((300, 301)),
            ), // match mid
        ];
        for (pat, input, expected) in cases {
            let (matched, subs) = compile_and_submatch(pat, input, REG_EXTENDED);
            let got = if matched { Some(subs[0]) } else { None };
            assert_eq!(
                got,
                *expected,
                "prescan pattern {pat:?} on len-{} input",
                input.len()
            );
        }
    }

    #[test]
    fn case_insensitive() {
        assert!(compile_and_match(
            "hello",
            "HELLO",
            REG_EXTENDED | REG_ICASE
        ));
        assert!(compile_and_match(
            "HELLO",
            "hello",
            REG_EXTENDED | REG_ICASE
        ));
    }

    #[test]
    fn submatch_groups() {
        let (matched, subs) = compile_and_submatch("(foo)(bar)", "foobar", REG_EXTENDED);
        assert!(matched);
        assert_eq!(subs[0], (0, 6)); // whole match
        assert_eq!(subs[1], (0, 3)); // group 1
        assert_eq!(subs[2], (3, 6)); // group 2
    }

    #[test]
    fn brace_quantifier() {
        assert!(compile_and_match("a{3}", "aaa", REG_EXTENDED));
        assert!(!compile_and_match("a{3}", "aa", REG_EXTENDED));
        assert!(compile_and_match("a{2,4}", "aaa", REG_EXTENDED));
        assert!(compile_and_match("a{2,}", "aaaaaaa", REG_EXTENDED));
    }

    #[test]
    fn posix_class() {
        assert!(compile_and_match("[[:digit:]]", "5", REG_EXTENDED));
        assert!(!compile_and_match("[[:digit:]]", "a", REG_EXTENDED));
        assert!(compile_and_match("[[:alpha:]]", "Z", REG_EXTENDED));
        assert!(!compile_and_match("[[:alpha:]]", "5", REG_EXTENDED));
    }

    #[test]
    fn bre_basic() {
        // BRE: no REG_EXTENDED
        assert!(compile_and_match("hello", "hello", 0));
        assert!(compile_and_match("h.llo", "hello", 0));
        assert!(compile_and_match("ab*c", "abbc", 0));
    }

    #[test]
    fn bre_backreferences_match_captured_text() {
        let (matched, subs) = compile_and_submatch("\\(ab*\\)c\\1", "zzabbcabb", 0);
        assert!(matched);
        assert_eq!(subs[0], (2, 9));
        assert_eq!(subs[1], (2, 5));

        assert!(compile_and_match("\\(a\\)\\1", "aa", 0));
        assert!(!compile_and_match("\\(a\\)\\1", "ab", 0));
    }

    #[test]
    fn bre_invalid_backreferences_fail_at_compile_time() {
        assert_eq!(regex_compile(b"\\1", 0).unwrap_err(), REG_ESUBREG);
        assert_eq!(regex_compile(b"\\(a\\)\\2", 0).unwrap_err(), REG_ESUBREG);
    }

    #[test]
    fn bre_caret_dollar_are_literal_when_not_anchoring() {
        // POSIX BRE: `^`/`$` are literals except at anchor positions.
        assert!(compile_and_match("a^b", "a^b", 0));
        assert!(compile_and_match("a$b", "a$b", 0));
        assert!(!compile_and_match("a^b", "axb", 0));
        // Still anchors at the ends of the BRE.
        assert!(compile_and_match("^ab", "abc", 0));
        assert!(compile_and_match("bc$", "abc", 0));
        // Anchor positions inside subexpressions.
        assert!(compile_and_match("\\(^a\\)", "abc", 0));
        // In ERE, `^`/`$` are always anchors, so `a^b` cannot match.
        assert!(!compile_and_match("a^b", "a^b", REG_EXTENDED));
    }

    #[test]
    fn brace_interval_edges() {
        // GNU extension: `{,m}` means `{0,m}` — the longest match is "aaa".
        let (ok, subs) = compile_and_submatch("a{,3}", "aaaaa", REG_EXTENDED);
        assert!(ok);
        assert_eq!(subs[0], (0, 3));
        assert!(compile_and_match("a{,3}", "", REG_EXTENDED));
        // A malformed brace is REG_EBRACE; empty `{}` is REG_BADBR.
        assert_eq!(regex_compile(b"a{", REG_EXTENDED).unwrap_err(), REG_EBRACE);
        assert_eq!(regex_compile(b"a{}", REG_EXTENDED).unwrap_err(), REG_BADBR);
        // An interval bound past RE_DUP_MAX is rejected (REG_BADBR).
        assert_eq!(
            regex_compile(b"a{32768}", REG_EXTENDED).unwrap_err(),
            REG_BADBR
        );
        assert!(regex_compile(b"a{32767}", REG_EXTENDED).is_ok());
    }

    #[test]
    fn error_codes() {
        // Messages mirror glibc's __re_error_msgid byte-for-byte
        // (conformance_diff_regerror gates this vs the live host).
        assert_eq!(regex_error(REG_NOMATCH), "No match");
        assert_eq!(regex_error(REG_BADPAT), "Invalid regular expression");
        assert_eq!(regex_error(REG_EBRACK), "Unmatched [, [^, [:, [., or [=");
        assert_eq!(regex_error(REG_ECOLLATE), "Invalid collation character");
        assert_eq!(regex_error(REG_EEND), "Premature end of regular expression");
        assert_eq!(regex_error(REG_ERPAREN), "Unmatched ) or \\)");
    }

    #[test]
    fn newline_handling() {
        // With REG_NEWLINE, ^ and $ match at newlines
        assert!(compile_and_match(
            "^world",
            "hello\nworld",
            REG_EXTENDED | REG_NEWLINE
        ));
        assert!(compile_and_match(
            "hello$",
            "hello\nworld",
            REG_EXTENDED | REG_NEWLINE
        ));
    }

    #[test]
    fn empty_pattern() {
        assert!(compile_and_match("", "hello", REG_EXTENDED));
        assert!(compile_and_match("", "", REG_EXTENDED));
    }

    #[test]
    fn escaped_metachar() {
        assert!(compile_and_match("a\\.b", "a.b", REG_EXTENDED));
        assert!(!compile_and_match("a\\.b", "axb", REG_EXTENDED));
    }

    #[test]
    fn complexity_certificate_marks_linear_patterns() {
        let compiled = regex_compile(b"(foo|bar)+baz", REG_EXTENDED).unwrap();
        let certificate = compiled.complexity_certificate();
        assert_eq!(certificate.complexity, RegexComplexityClass::Linear);
        assert_eq!(certificate.risk_reason, None);
        assert!(certificate.estimated_nfa_states > 0);
        assert!(certificate.pattern_hash != 0);
    }

    #[test]
    fn complexity_certificate_marks_risky_patterns_without_rejecting_them() {
        let cases = [
            (b"(a+)+$".as_slice(), RegexRiskReason::NestedUnboundedRepeat),
            (
                b"(a|aa)+$".as_slice(),
                RegexRiskReason::AmbiguousRepeatedAlternation,
            ),
            (b"(a?)+$".as_slice(), RegexRiskReason::NullableRepeatedTerm),
        ];

        for (pattern, expected_reason) in cases {
            let compiled = regex_compile(pattern, REG_EXTENDED).unwrap();
            let certificate = compiled.complexity_certificate();
            assert_eq!(certificate.complexity, RegexComplexityClass::SuperLinear);
            assert_eq!(certificate.risk_reason, Some(expected_reason));
        }

        assert!(compile_and_match("(a+)+$", "aaaa", REG_EXTENDED));
        assert!(compile_and_match("([a-z]+)*$", "abcxyz", REG_EXTENDED));
    }

    #[test]
    fn reg_notbol_prevents_caret_match_at_start() {
        // Without REG_NOTBOL, "^abc" matches "abc" at position 0.
        let compiled = regex_compile(b"^abc", REG_EXTENDED).unwrap();
        let m1 = regex_match_bounds(&compiled, b"abc\0", 0);
        assert!(m1.is_some(), "^abc should match 'abc' without REG_NOTBOL");

        // With REG_NOTBOL, "^abc" does not match "abc" because the start
        // is not treated as beginning-of-line.
        let m2 = regex_match_bounds(&compiled, b"abc\0", REG_NOTBOL);
        assert!(m2.is_none(), "^abc should NOT match 'abc' with REG_NOTBOL");

        // "^" still matches after embedded newline if REG_NEWLINE is set.
        let compiled2 = regex_compile(b"^abc", REG_EXTENDED | REG_NEWLINE).unwrap();
        let m3 = regex_match_bounds(&compiled2, b"\nabc\0", REG_NOTBOL);
        assert!(
            m3.is_some(),
            "^abc should match after newline with REG_NEWLINE even with REG_NOTBOL"
        );
    }

    #[test]
    fn glibc_empty_pattern_matches_anywhere() {
        // glibc: regcomp("", REG_EXTENDED) succeeds, regexec matches anywhere
        let compiled = regex_compile(b"", REG_EXTENDED).unwrap();
        let m = regex_match_bounds(&compiled, b"anything\0", 0);
        assert!(m.is_some(), "empty pattern should match");
        // Empty pattern matches at position 0 with length 0.
        let (start, end) = m.unwrap();
        assert_eq!((start, end), (0, 0));
    }

    #[test]
    fn glibc_dot_matches_newline_without_reg_newline() {
        // glibc: without REG_NEWLINE, '.' matches '\n'
        let compiled = regex_compile(b"a.c", REG_EXTENDED).unwrap();
        let m = regex_match_bounds(&compiled, b"a\nc\0", 0);
        assert!(m.is_some(), "'.' should match newline without REG_NEWLINE");
    }

    #[test]
    fn glibc_optional_matches_empty() {
        // glibc: 'a?' matches empty string at position 0
        let compiled = regex_compile(b"a?", REG_EXTENDED).unwrap();
        let m = regex_match_bounds(&compiled, b"\0", 0);
        assert!(m.is_some(), "'a?' should match empty string");
        let (start, end) = m.unwrap();
        assert_eq!((start, end), (0, 0));
    }

    #[test]
    fn glibc_invalid_interval_returns_reg_badbr() {
        // glibc: a{{5,3}} returns REG_BADBR (invalid interval)
        let result = regex_compile(b"a{5,3}", REG_EXTENDED);
        assert!(result.is_err(), "a{{5,3}} should fail to compile");
        let err = result.unwrap_err();
        assert_eq!(err, REG_BADBR, "should return REG_BADBR");
    }

    #[test]
    fn glibc_unmatched_star_returns_reg_badrpt() {
        // glibc: '*' without preceding atom returns REG_BADRPT
        let result = regex_compile(b"*", REG_EXTENDED);
        assert!(result.is_err(), "'*' alone should fail to compile");
        let err = result.unwrap_err();
        assert_eq!(err, REG_BADRPT, "should return REG_BADRPT");
    }
}
