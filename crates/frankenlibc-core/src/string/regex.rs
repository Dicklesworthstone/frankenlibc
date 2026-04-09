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
    Start,
    End,
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

#[derive(Clone, Copy)]
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

fn analyze_ast(ast: &Ast) -> AstAnalysis {
    match ast {
        Ast::Literal(byte) => AstAnalysis::linear(false, FirstByteSet::singleton(*byte)),
        Ast::AnyChar => AstAnalysis::linear(false, FirstByteSet::any()),
        Ast::CharClass { ranges, .. } => {
            let mut set = FirstByteSet::empty();
            for &(lo, hi) in ranges {
                set = set.union(FirstByteSet::range(lo, hi));
            }
            AstAnalysis::linear(false, set)
        }
        Ast::Anchor(_) => AstAnalysis::linear(true, FirstByteSet::empty()),
        Ast::Group { inner, .. } => analyze_ast(inner),
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
        ranges: Vec<(u8, u8)>,
        negated: bool,
        icase: bool,
    },
    AnchorStart {
        newline: bool,
    },
    AnchorEnd {
        newline: bool,
    },
}

// ---------------------------------------------------------------------------
// Compiled regex
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct CompiledRegex {
    nfa: Vec<NfaInstr>,
    num_groups: usize,
    nosub: bool,
    complexity_certificate: RegexComplexityCertificate,
}

impl CompiledRegex {
    fn num_slots(&self) -> usize {
        (self.num_groups + 1) * 2
    }

    pub fn num_regs(&self) -> usize {
        self.num_groups + 1
    }

    pub fn nosub(&self) -> bool {
        self.nosub
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
        let atom = self.parse_atom()?;

        // Check for quantifiers
        if self.extended {
            match self.peek() {
                Some(b'*') => {
                    self.advance();
                    Ok(Ast::Repeat {
                        inner: Box::new(atom),
                        min: 0,
                        max: None,
                    })
                }
                Some(b'+') => {
                    self.advance();
                    Ok(Ast::Repeat {
                        inner: Box::new(atom),
                        min: 1,
                        max: None,
                    })
                }
                Some(b'?') => {
                    self.advance();
                    Ok(Ast::Repeat {
                        inner: Box::new(atom),
                        min: 0,
                        max: Some(1),
                    })
                }
                Some(b'{') => self.parse_brace_quantifier(atom),
                _ => Ok(atom),
            }
        } else {
            // BRE: * is a quantifier (only after an atom), \{m,n\} for braces
            match self.peek() {
                Some(b'*') => {
                    self.advance();
                    Ok(Ast::Repeat {
                        inner: Box::new(atom),
                        min: 0,
                        max: None,
                    })
                }
                _ => {
                    // Check for \{
                    if self.pos + 1 < self.pat.len()
                        && self.pat[self.pos] == b'\\'
                        && self.pat[self.pos + 1] == b'{'
                    {
                        self.pos += 2; // skip \{
                        self.parse_bre_brace_quantifier(atom)
                    } else {
                        Ok(atom)
                    }
                }
            }
        }
    }

    fn parse_brace_quantifier(&mut self, atom: Ast) -> Result<Ast, i32> {
        self.advance(); // skip {
        let min = self.parse_decimal()?;
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

        Ok(Ast::Repeat {
            inner: Box::new(atom),
            min,
            max,
        })
    }

    fn parse_bre_brace_quantifier(&mut self, atom: Ast) -> Result<Ast, i32> {
        let min = self.parse_decimal()?;
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
                self.advance();
                Ok(Ast::Anchor(AnchorKind::Start))
            }
            Some(b'$') => {
                self.advance();
                Ok(Ast::Anchor(AnchorKind::End))
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
                Some(b'[') => {
                    // Check for POSIX character class [:alpha:]
                    if self.pos + 1 < self.pat.len() && self.pat[self.pos + 1] == b':' {
                        self.advance(); // [
                        self.advance(); // :
                        let class_ranges = self.parse_posix_class()?;
                        ranges.extend_from_slice(&class_ranges);
                        continue;
                    }
                    let ch = self.advance().unwrap();
                    // Check for range
                    if self.peek() == Some(b'-')
                        && self.pos + 1 < self.pat.len()
                        && self.pat[self.pos + 1] != b']'
                    {
                        self.advance(); // skip -
                        let end = self.advance().ok_or(REG_EBRACK)?;
                        if end < ch {
                            return Err(REG_ERANGE);
                        }
                        ranges.push((ch, end));
                    } else {
                        ranges.push((ch, ch));
                    }
                }
                Some(_) => {
                    let ch = self.advance().unwrap();
                    // Check for range
                    if self.peek() == Some(b'-')
                        && self.pos + 1 < self.pat.len()
                        && self.pat[self.pos + 1] != b']'
                    {
                        self.advance(); // skip -
                        let end = self.advance().ok_or(REG_EBRACK)?;
                        if end < ch {
                            return Err(REG_ERANGE);
                        }
                        ranges.push((ch, end));
                    } else {
                        ranges.push((ch, ch));
                    }
                }
            }
        }

        Ok(Ast::CharClass { ranges, negated })
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
}

impl Compiler {
    fn new(icase: bool, newline: bool) -> Self {
        Self {
            nfa: Vec::new(),
            compile_icase: icase,
            compile_newline: newline,
        }
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
                    ranges: ranges.clone(),
                    negated: *negated,
                    icase: self.compile_icase,
                }));
            }
            Ast::Anchor(AnchorKind::Start) => {
                self.emit(NfaInstr::Match(MatchKind::AnchorStart {
                    newline: self.compile_newline,
                }));
            }
            Ast::Anchor(AnchorKind::End) => {
                self.emit(NfaInstr::Match(MatchKind::AnchorEnd {
                    newline: self.compile_newline,
                }));
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
                // Emit min required copies
                for _ in 0..*min {
                    self.compile(inner);
                }

                match max {
                    None => {
                        // Unbounded: emit split-body-jump loop
                        let split_idx = self.emit(NfaInstr::Split(0, 0));
                        self.compile(inner);
                        self.emit(NfaInstr::Jump(split_idx));
                        let end = self.nfa.len();
                        // POSIX: greedy = prefer match (first branch)
                        self.nfa[split_idx] = NfaInstr::Split(split_idx + 1, end);
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
}

/// Thread state in Pike VM
#[derive(Clone)]
struct Thread {
    pc: usize,
    slots: Vec<i32>,
}

impl<'a> PikeVm<'a> {
    fn new(nfa: &'a [NfaInstr], input: &'a [u8], num_slots: usize, eflags: i32) -> Self {
        Self {
            nfa,
            input,
            num_slots,
            eflags,
        }
    }

    /// Run the NFA, returning submatch slots if a match is found.
    /// For POSIX leftmost-longest: try each start position from left;
    /// for each start position, run all threads to find longest match.
    fn execute(&self) -> Option<Vec<i32>> {
        let notbol = self.eflags & REG_NOTBOL != 0;
        let noteol = self.eflags & REG_NOTEOL != 0;
        let input_len = self.input.len();

        // Try each start position (leftmost wins)
        for start in 0..=input_len {
            let mut slots = vec![-1i32; self.num_slots];
            slots[0] = start as i32; // group 0 start
            if let Some(matched_slots) = self.run_from(start, &slots, notbol, noteol) {
                return Some(matched_slots);
            }
        }
        None
    }

    fn run_from(
        &self,
        start: usize,
        initial_slots: &[i32],
        notbol: bool,
        noteol: bool,
    ) -> Option<Vec<i32>> {
        let mut current: Vec<Thread> = Vec::new();
        let mut next: Vec<Thread> = Vec::new();
        let mut best: Option<Vec<i32>> = None;

        // Add initial thread
        let init_thread = Thread {
            pc: 0,
            slots: initial_slots.to_vec(),
        };
        self.add_thread(&mut current, init_thread, start, notbol, noteol);

        let input_len = self.input.len();
        let mut sp = start;

        loop {
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
                        self.add_thread(&mut next, new_t, sp + 1, notbol, noteol);
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
        }

        best
    }

    /// Recursively add a thread, following epsilon transitions (Split, Jump, Save).
    fn add_thread(
        &self,
        threads: &mut Vec<Thread>,
        t: Thread,
        sp: usize,
        notbol: bool,
        noteol: bool,
    ) {
        // Depth-limited wrapper to prevent stack overflow on deeply nested
        // alternations or pathological Jump chains.
        self.add_thread_inner(threads, t, sp, notbol, noteol, 0);
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
        notbol: bool,
        noteol: bool,
        depth: usize,
    ) {
        if depth > Self::ADD_THREAD_MAX_DEPTH || t.pc >= self.nfa.len() {
            return;
        }

        // Avoid duplicate threads at same PC (thread priority: first wins for POSIX)
        if threads.iter().any(|existing| existing.pc == t.pc) {
            return;
        }

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
                self.add_thread_inner(threads, t1, sp, notbol, noteol, depth + 1);
                self.add_thread_inner(threads, t2, sp, notbol, noteol, depth + 1);
            }
            NfaInstr::Jump(target) => {
                let new_t = Thread {
                    pc: *target,
                    slots: t.slots,
                };
                self.add_thread_inner(threads, new_t, sp, notbol, noteol, depth + 1);
            }
            NfaInstr::Save(slot) => {
                let mut new_slots = t.slots;
                new_slots[*slot] = sp as i32;
                let new_t = Thread {
                    pc: t.pc + 1,
                    slots: new_slots,
                };
                self.add_thread_inner(threads, new_t, sp, notbol, noteol, depth + 1);
            }
            NfaInstr::Match(mk) => {
                // For anchors, check inline so we don't waste a simulation step
                match mk {
                    MatchKind::AnchorStart { newline } => {
                        if self.check_anchor_start(sp, notbol, *newline) {
                            let new_t = Thread {
                                pc: t.pc + 1,
                                slots: t.slots,
                            };
                            self.add_thread_inner(threads, new_t, sp, notbol, noteol, depth + 1);
                        }
                    }
                    MatchKind::AnchorEnd { newline } => {
                        if self.check_anchor_end(sp, noteol, *newline) {
                            let new_t = Thread {
                                pc: t.pc + 1,
                                slots: t.slots,
                            };
                            self.add_thread_inner(threads, new_t, sp, notbol, noteol, depth + 1);
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

    fn matches(&self, mk: &MatchKind, sp: usize, _notbol: bool, _noteol: bool) -> bool {
        if sp >= self.input.len() {
            return false;
        }
        let ch = self.input[sp];

        match mk {
            MatchKind::Literal(lit) => ch == *lit,
            MatchKind::LiteralCi(lo, hi) => ch == *lo || ch == *hi,
            MatchKind::AnyChar { newline } => !(*newline && ch == b'\n'),
            MatchKind::CharClass {
                ranges,
                negated,
                icase,
            } => {
                let mut found = false;
                for &(lo, hi) in ranges.iter() {
                    if *icase {
                        let ch_lo = ch.to_ascii_lowercase();
                        let lo_lo = lo.to_ascii_lowercase();
                        let hi_lo = hi.to_ascii_lowercase();
                        if ch_lo >= lo_lo && ch_lo <= hi_lo {
                            found = true;
                            break;
                        }
                    } else if ch >= lo && ch <= hi {
                        found = true;
                        break;
                    }
                }
                if *negated { !found } else { found }
            }
            // Anchors are handled in add_thread, not here
            MatchKind::AnchorStart { .. } | MatchKind::AnchorEnd { .. } => false,
        }
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Compile a regex pattern. Returns a boxed CompiledRegex on success.
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
    let ast = parser.parse()?;
    let num_groups = parser.group_count;

    let icase = cflags & REG_ICASE != 0;
    let newline = cflags & REG_NEWLINE != 0;
    let nosub = cflags & REG_NOSUB != 0;

    let mut compiler = Compiler::new(icase, newline);
    // Wrap entire pattern in group 0
    compiler.emit(NfaInstr::Save(0));
    compiler.compile(&ast);
    compiler.emit(NfaInstr::Save(1));
    let nfa = compiler.finish();
    let complexity_certificate = build_complexity_certificate(pat, &ast, nfa.len());

    Ok(Box::new(CompiledRegex {
        nfa,
        num_groups,
        nosub,
        complexity_certificate,
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
                for (i, m) in matches.iter_mut().enumerate() {
                    let so_idx = i * 2;
                    let eo_idx = i * 2 + 1;
                    if so_idx < slots.len() && eo_idx < slots.len() {
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
                for (i, m) in matches.iter_mut().enumerate() {
                    let so_idx = i * 2;
                    let eo_idx = i * 2 + 1;
                    if so_idx < slots.len() && eo_idx < slots.len() {
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
    let vm = PikeVm::new(&compiled.nfa, input, num_slots, eflags);

    vm.execute()
}

/// Map an error code to a human-readable message.
pub fn regex_error(errcode: i32) -> &'static str {
    match errcode {
        0 => "Success",
        REG_NOMATCH => "No match",
        REG_BADPAT => "Invalid regular expression",
        REG_ECOLLATE => "Invalid collating element",
        REG_ECTYPE => "Invalid character class name",
        REG_EESCAPE => "Trailing backslash",
        REG_ESUBREG => "Invalid back reference",
        REG_EBRACK => "Unmatched [",
        REG_EPAREN => "Unmatched (",
        REG_EBRACE => "Unmatched {",
        REG_BADBR => "Invalid content of \\{\\}",
        REG_ERANGE => "Invalid range end",
        REG_ESPACE => "Memory exhausted",
        REG_BADRPT => "Invalid preceding regular expression",
        _ => "Unknown error",
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

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
    fn error_codes() {
        assert_eq!(regex_error(REG_NOMATCH), "No match");
        assert_eq!(regex_error(REG_BADPAT), "Invalid regular expression");
        assert_eq!(regex_error(REG_EBRACK), "Unmatched [");
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
}
