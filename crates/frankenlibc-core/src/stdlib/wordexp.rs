//! POSIX `wordexp` variable-expansion building blocks.
//!
//! Pure-safe Rust port of the byte-level expansion logic that
//! previously lived inline in frankenlibc-abi/src/unistd_abi.rs::expand_vars.
//! The abi layer keeps responsibility for the C-ABI marshalling, the
//! `wordexp_t` struct construction, the optional `WRDE_NOCMD`-gated
//! command substitution path, and the actual environment lookup
//! (passed in here as a closure so core stays pure-safe and free of
//! `std::env` dependencies).
//!
//! Supported expansions:
//!   - backslash escape (`\\X` → literal `X`)
//!   - single-quoted (`'...'`) — verbatim, no expansion
//!   - `$VAR` and `${VAR}` — environment lookup via the supplied closure
//!   - double-quoted (`"..."`) — recursively expanded, drops the
//!     surrounding quotes from the output
//!
//! Any other byte is appended literally.

/// Why expansion failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExpandError {
    /// A `$VAR` reference resolved to no value, and the caller asked
    /// to treat that as an error (the POSIX `WRDE_UNDEF` flag).
    UndefinedVariable(String),
    /// A `${...}` body used an operator POSIX `wordexp` does not support
    /// (a bash extension such as `${var:off:len}`, `${var/p/r}`, `${var^^}`,
    /// `${var@U}`, `${var[i]}`, or a bare/invalid `${var:}`). glibc reports
    /// `WRDE_SYNTAX` for these.
    Syntax,
}

/// Expand a single shell-style word into a `String`.
///
/// `lookup_env` is invoked for each `$VAR` / `${VAR}` reference; it
/// returns `Some(value)` to expand or `None` to indicate the variable
/// is unset. When `undef_is_error` is true, an unset variable causes
/// the whole expansion to fail with [`ExpandError::UndefinedVariable`].
///
/// The function is byte-oriented: the input `&str` is processed as
/// `&[u8]` and result bytes are appended to a `String`. Non-UTF-8
/// bytes inside a `${VAR}` literal name are silently skipped.
pub fn expand_vars<F>(
    word: &str,
    undef_is_error: bool,
    lookup_env: F,
) -> Result<String, ExpandError>
where
    F: Fn(&str) -> Option<String>,
{
    // Funnel through the dyn-trait variant so the recursive call inside
    // the double-quoted branch doesn't infinitely re-instantiate `F`.
    expand_vars_dyn(word, undef_is_error, &lookup_env)
}

fn expand_vars_dyn(
    word: &str,
    undef_is_error: bool,
    lookup_env: &dyn Fn(&str) -> Option<String>,
) -> Result<String, ExpandError> {
    let mut result = String::with_capacity(word.len());
    let bytes = word.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            result.push(bytes[i + 1] as char);
            i += 2;
            continue;
        }
        if bytes[i] == b'\'' {
            i += 1;
            while i < bytes.len() && bytes[i] != b'\'' {
                result.push(bytes[i] as char);
                i += 1;
            }
            if i < bytes.len() {
                i += 1; // skip closing '
            }
            continue;
        }
        if bytes[i] == b'$' {
            i += 1;
            if i >= bytes.len() {
                result.push('$');
                continue;
            }
            if bytes[i] == b'{' {
                // `${...}` — full parameter expansion (default/alt/length forms).
                i += 1;
                let start = i;
                while i < bytes.len() && bytes[i] != b'}' {
                    i += 1;
                }
                let content = core::str::from_utf8(&bytes[start..i]).unwrap_or("");
                if i < bytes.len() {
                    i += 1; // skip }
                }
                if content.is_empty() {
                    result.push('$');
                    continue;
                }
                result.push_str(&expand_braced_param(content, undef_is_error, lookup_env)?);
                continue;
            }
            // Bare `$VAR`.
            let start = i;
            while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                i += 1;
            }
            let var_name = core::str::from_utf8(&bytes[start..i]).unwrap_or("");
            if var_name.is_empty() {
                result.push('$');
                continue;
            }
            match lookup_env(var_name) {
                Some(val) => result.push_str(&val),
                None => {
                    if undef_is_error {
                        return Err(ExpandError::UndefinedVariable(var_name.to_string()));
                    }
                    // Otherwise expand to empty string.
                }
            }
            continue;
        }
        if bytes[i] == b'"' {
            i += 1;
            let mut inner = String::new();
            while i < bytes.len() && bytes[i] != b'"' {
                inner.push(bytes[i] as char);
                i += 1;
            }
            if i < bytes.len() {
                i += 1; // skip closing "
            }
            // Recursively expand the inner content. The dyn-trait
            // funnel above means this doesn't blow up generic
            // monomorphization.
            let expanded = expand_vars_dyn(&inner, undef_is_error, lookup_env)?;
            result.push_str(&expanded);
            continue;
        }
        result.push(bytes[i] as char);
        i += 1;
    }
    Ok(result)
}

/// Remove the smallest (largest, if `largest`) suffix (or prefix, if `!suffix`)
/// of `value` that matches the glob pattern `pat` — shell `${VAR%pat}`/`%%pat`
/// (suffix) and `${VAR#pat}`/`##pat` (prefix). The candidate suffix/prefix is
/// matched against `pat` with `fnmatch` (anchored, whole-slice). Byte-oriented to
/// match glibc; a removed boundary inside a multi-byte UTF-8 sequence (which the
/// shell would not produce) is rendered lossily.
fn remove_affix(value: &str, pat: &str, suffix: bool, largest: bool) -> String {
    use crate::string::fnmatch::{FnmatchFlags, fnmatch_match};
    let vb = value.as_bytes();
    let hit = |slice: &[u8]| fnmatch_match(pat.as_bytes(), slice, FnmatchFlags::NONE);

    if suffix {
        // Suffix is `value[start..]`; the shortest suffix is the largest `start`.
        // `%%` wants the longest match (smallest `start` first); `%` the shortest.
        let order: Box<dyn Iterator<Item = usize>> = if largest {
            Box::new(0..=vb.len())
        } else {
            Box::new((0..=vb.len()).rev())
        };
        for start in order {
            if hit(&vb[start..]) {
                return String::from_utf8_lossy(&vb[..start]).into_owned();
            }
        }
    } else {
        // Prefix is `value[..end]`; the shortest prefix is the smallest `end`.
        let order: Box<dyn Iterator<Item = usize>> = if largest {
            Box::new((0..=vb.len()).rev())
        } else {
            Box::new(0..=vb.len())
        };
        for end in order {
            if hit(&vb[..end]) {
                return String::from_utf8_lossy(&vb[end..]).into_owned();
            }
        }
    }
    value.to_string()
}

/// Evaluate the body of a `${...}` parameter expansion (the text between `${`
/// and `}`), supporting the common POSIX forms beyond a plain name:
///   `${#NAME}`       — character length of NAME's value (0 if unset)
///   `${NAME:-WORD}`  — WORD if NAME is unset or empty, else NAME's value
///   `${NAME-WORD}`   — WORD if NAME is unset, else NAME's value
///   `${NAME:+WORD}`  — WORD if NAME is set and non-empty, else empty
///   `${NAME+WORD}`   — WORD if NAME is set, else empty
/// WORD is itself expanded (it may reference other variables, escapes, quotes).
/// Operators not handled here (`= ? % #` after the name) fall back to a plain
/// lookup of the whole body, preserving the previous behaviour.
pub fn expand_braced_param(
    content: &str,
    undef_is_error: bool,
    lookup_env: &dyn Fn(&str) -> Option<String>,
) -> Result<String, ExpandError> {
    let is_name = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');

    // `${#NAME}` — string length.
    if let Some(name) = content.strip_prefix('#')
        && is_name(name)
    {
        let len = lookup_env(name).map(|v| v.chars().count()).unwrap_or(0);
        return Ok(len.to_string());
    }

    let name_len = content
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or(content.len());
    let name = &content[..name_len];
    let op = &content[name_len..];
    let raw = lookup_env(name);

    let plain = |raw: Option<String>, key: &str| -> Result<String, ExpandError> {
        match raw {
            Some(v) => Ok(v),
            None if undef_is_error => Err(ExpandError::UndefinedVariable(key.to_string())),
            None => Ok(String::new()),
        }
    };

    if op.is_empty() || name.is_empty() {
        // Plain `${NAME}`, or a body we don't special-case: look up verbatim.
        return plain(lookup_env(content), content);
    }

    // Suffix removal `${NAME%pat}`/`${NAME%%pat}` and prefix removal
    // `${NAME#pat}`/`${NAME##pat}` (a leading `#` would be the length form, which
    // is handled above, so any `#` reaching here is the prefix-removal operator).
    // `pat` is a glob pattern and is itself expanded first.
    let op_bytes = op.as_bytes();
    if matches!(op_bytes[0], b'%' | b'#') {
        let kind = op_bytes[0];
        let largest = op_bytes.get(1) == Some(&kind);
        let pat_raw = if largest { &op[2..] } else { &op[1..] };
        let pat = expand_vars_dyn(pat_raw, undef_is_error, lookup_env)?;
        let value = raw.unwrap_or_default();
        return Ok(remove_affix(&value, &pat, kind == b'%', largest));
    }

    let (colon, rest) = match op.strip_prefix(':') {
        Some(r) => (true, r),
        None => (false, op),
    };
    let opc = rest.as_bytes().first().copied();
    let word = if rest.is_empty() { "" } else { &rest[1..] };
    let unset = raw.is_none();
    let test = if colon {
        unset || raw.as_deref() == Some("")
    } else {
        unset
    };

    match opc {
        // Default when unset (or empty, with `:`). `=` also assigns the default,
        // but wordexp runs in a subshell so that assignment is not visible to the
        // caller — the observable result is identical to `-`.
        Some(b'-') | Some(b'=') => {
            if test {
                expand_vars_dyn(word, undef_is_error, lookup_env)
            } else {
                Ok(raw.unwrap_or_default())
            }
        }
        // Use an alternative only when the variable IS set (and non-empty, `:`).
        Some(b'+') => {
            if test {
                Ok(String::new())
            } else {
                expand_vars_dyn(word, undef_is_error, lookup_env)
            }
        }
        // `${var:?word}` / `${var?word}`: when the variable is set (non-empty for
        // the `:` form) the value is used; otherwise glibc's wordexp expands to
        // empty (it does not abort here). The `word` message is ignored.
        Some(b'?') => {
            if test {
                Ok(String::new())
            } else {
                Ok(raw.unwrap_or_default())
            }
        }
        // Any other operator after a real name is a bash extension POSIX/glibc
        // wordexp rejects — substring `${var:off}` / `${var:off:len}`, pattern
        // substitution `${var/p/r}`, case `${var^^}` / `${var,,}`, transform
        // `${var@U}`, subscript `${var[i]}`, or a bare/dangling `${var:}`.
        // glibc returns WRDE_SYNTAX.
        _ => Err(ExpandError::Syntax),
    }
}

// ---------------------------------------------------------------------------
// POSIX arithmetic expansion: the body of `$(( ... ))`
// ---------------------------------------------------------------------------

/// Evaluate a POSIX arithmetic expression (the inner text of `$(( ... ))`).
///
/// Supports integer literals (decimal, `0x`/`0X` hex, leading-`0` octal),
/// variables (bare `name`, `$name`, or `${name}` resolved via `lookup`; unset
/// or empty is `0`, a non-numeric value is recursively evaluated), parentheses,
/// the unary operators `+ - ! ~`, and the binary operators
/// `* / % + - << >> < <= > >= == != & ^ | && ||` plus the ternary `?:`, with C
/// precedence. Arithmetic is performed in wrapping `i64` (POSIX `intmax_t`).
/// `&&`/`||`/`?:` short-circuit. Division/modulo by zero and any malformed
/// expression yield [`ExpandError::Syntax`] (glibc's `WRDE_SYNTAX`).
pub fn eval_arith<F>(expr: &str, lookup: &F) -> Result<i64, ExpandError>
where
    F: Fn(&str) -> Option<String>,
{
    // An empty body — `$(( ))` — evaluates to 0 (matches glibc/POSIX shells).
    if expr.trim().is_empty() {
        return Ok(0);
    }
    let toks = arith_tokenize(expr)?;
    let mut p = ArithParser { toks: &toks, pos: 0 };
    let node = p.parse_expr()?;
    if p.pos != p.toks.len() {
        return Err(ExpandError::Syntax);
    }
    arith_eval(&node, lookup, 0, true)
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ATok {
    Num(i64),
    Var(String),
    Plus, Minus, Star, Slash, Percent,
    Shl, Shr, Lt, Le, Gt, Ge, Eq, Ne,
    Amp, Caret, Pipe, AmpAmp, PipePipe,
    Not, Tilde, Quest, Colon, LParen, RParen,
}

fn arith_parse_num(b: &[u8], start: usize) -> Result<(i64, usize), ExpandError> {
    let mut i = start;
    if b[i] == b'0' && i + 1 < b.len() && (b[i + 1] == b'x' || b[i + 1] == b'X') {
        i += 2;
        let hs = i;
        while i < b.len() && b[i].is_ascii_hexdigit() {
            i += 1;
        }
        if i == hs {
            return Err(ExpandError::Syntax);
        }
        let v = i64::from_str_radix(core::str::from_utf8(&b[hs..i]).unwrap_or(""), 16)
            .map_err(|_| ExpandError::Syntax)?;
        return Ok((v, i));
    }
    if b[i] == b'0' {
        i += 1;
        let os = i;
        while i < b.len() && (b'0'..=b'7').contains(&b[i]) {
            i += 1;
        }
        if os == i {
            return Ok((0, i));
        }
        let v = i64::from_str_radix(core::str::from_utf8(&b[os..i]).unwrap_or(""), 8)
            .map_err(|_| ExpandError::Syntax)?;
        return Ok((v, i));
    }
    while i < b.len() && b[i].is_ascii_digit() {
        i += 1;
    }
    let v = core::str::from_utf8(&b[start..i])
        .unwrap_or("")
        .parse::<i64>()
        .map_err(|_| ExpandError::Syntax)?;
    Ok((v, i))
}

fn arith_tokenize(s: &str) -> Result<Vec<ATok>, ExpandError> {
    let b = s.as_bytes();
    let mut i = 0usize;
    let mut out = Vec::new();
    while i < b.len() {
        let c = b[i];
        if c.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        match c {
            b'+' => { out.push(ATok::Plus); i += 1; }
            b'-' => { out.push(ATok::Minus); i += 1; }
            b'*' => { out.push(ATok::Star); i += 1; }
            b'/' => { out.push(ATok::Slash); i += 1; }
            b'%' => { out.push(ATok::Percent); i += 1; }
            b'~' => { out.push(ATok::Tilde); i += 1; }
            b'(' => { out.push(ATok::LParen); i += 1; }
            b')' => { out.push(ATok::RParen); i += 1; }
            b'^' => { out.push(ATok::Caret); i += 1; }
            b'?' => { out.push(ATok::Quest); i += 1; }
            b':' => { out.push(ATok::Colon); i += 1; }
            b'<' => {
                if i + 1 < b.len() && b[i + 1] == b'<' { out.push(ATok::Shl); i += 2; }
                else if i + 1 < b.len() && b[i + 1] == b'=' { out.push(ATok::Le); i += 2; }
                else { out.push(ATok::Lt); i += 1; }
            }
            b'>' => {
                if i + 1 < b.len() && b[i + 1] == b'>' { out.push(ATok::Shr); i += 2; }
                else if i + 1 < b.len() && b[i + 1] == b'=' { out.push(ATok::Ge); i += 2; }
                else { out.push(ATok::Gt); i += 1; }
            }
            b'=' => {
                if i + 1 < b.len() && b[i + 1] == b'=' { out.push(ATok::Eq); i += 2; }
                else { return Err(ExpandError::Syntax); } // bare `=` (assignment) unsupported
            }
            b'!' => {
                if i + 1 < b.len() && b[i + 1] == b'=' { out.push(ATok::Ne); i += 2; }
                else { out.push(ATok::Not); i += 1; }
            }
            b'&' => {
                if i + 1 < b.len() && b[i + 1] == b'&' { out.push(ATok::AmpAmp); i += 2; }
                else { out.push(ATok::Amp); i += 1; }
            }
            b'|' => {
                if i + 1 < b.len() && b[i + 1] == b'|' { out.push(ATok::PipePipe); i += 2; }
                else { out.push(ATok::Pipe); i += 1; }
            }
            b'0'..=b'9' => {
                let (v, ni) = arith_parse_num(b, i)?;
                out.push(ATok::Num(v));
                i = ni;
            }
            b'$' => {
                i += 1;
                if i < b.len() && b[i] == b'{' {
                    i += 1;
                    let st = i;
                    while i < b.len() && b[i] != b'}' {
                        i += 1;
                    }
                    if i >= b.len() {
                        return Err(ExpandError::Syntax);
                    }
                    let name = String::from_utf8_lossy(&b[st..i]).into_owned();
                    i += 1;
                    out.push(ATok::Var(name));
                } else {
                    let st = i;
                    while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
                        i += 1;
                    }
                    if st == i {
                        return Err(ExpandError::Syntax);
                    }
                    out.push(ATok::Var(String::from_utf8_lossy(&b[st..i]).into_owned()));
                }
            }
            _ if c.is_ascii_alphabetic() || c == b'_' => {
                let st = i;
                while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
                    i += 1;
                }
                out.push(ATok::Var(String::from_utf8_lossy(&b[st..i]).into_owned()));
            }
            _ => return Err(ExpandError::Syntax),
        }
    }
    Ok(out)
}

enum ANode {
    Num(i64),
    Var(String),
    Unary(ATok, Box<ANode>),
    Bin(ATok, Box<ANode>, Box<ANode>),
    Ternary(Box<ANode>, Box<ANode>, Box<ANode>),
}

struct ArithParser<'a> {
    toks: &'a [ATok],
    pos: usize,
}

impl ArithParser<'_> {
    fn peek(&self) -> Option<&ATok> {
        self.toks.get(self.pos)
    }
    fn eat(&mut self, t: &ATok) -> bool {
        if self.toks.get(self.pos) == Some(t) {
            self.pos += 1;
            true
        } else {
            false
        }
    }
    // expr := ternary
    fn parse_expr(&mut self) -> Result<ANode, ExpandError> {
        let cond = self.parse_lor()?;
        if self.eat(&ATok::Quest) {
            let then = self.parse_expr()?;
            if !self.eat(&ATok::Colon) {
                return Err(ExpandError::Syntax);
            }
            let els = self.parse_expr()?;
            Ok(ANode::Ternary(Box::new(cond), Box::new(then), Box::new(els)))
        } else {
            Ok(cond)
        }
    }
    fn parse_binlevel(
        &mut self,
        ops: &[ATok],
        next: fn(&mut Self) -> Result<ANode, ExpandError>,
    ) -> Result<ANode, ExpandError> {
        let mut lhs = next(self)?;
        loop {
            let mut matched = false;
            for op in ops {
                if self.eat(op) {
                    let rhs = next(self)?;
                    lhs = ANode::Bin(op.clone(), Box::new(lhs), Box::new(rhs));
                    matched = true;
                    break;
                }
            }
            if !matched {
                return Ok(lhs);
            }
        }
    }
    fn parse_lor(&mut self) -> Result<ANode, ExpandError> {
        self.parse_binlevel(&[ATok::PipePipe], Self::parse_land)
    }
    fn parse_land(&mut self) -> Result<ANode, ExpandError> {
        self.parse_binlevel(&[ATok::AmpAmp], Self::parse_bor)
    }
    fn parse_bor(&mut self) -> Result<ANode, ExpandError> {
        self.parse_binlevel(&[ATok::Pipe], Self::parse_bxor)
    }
    fn parse_bxor(&mut self) -> Result<ANode, ExpandError> {
        self.parse_binlevel(&[ATok::Caret], Self::parse_band)
    }
    fn parse_band(&mut self) -> Result<ANode, ExpandError> {
        self.parse_binlevel(&[ATok::Amp], Self::parse_eq)
    }
    fn parse_eq(&mut self) -> Result<ANode, ExpandError> {
        self.parse_binlevel(&[ATok::Eq, ATok::Ne], Self::parse_rel)
    }
    fn parse_rel(&mut self) -> Result<ANode, ExpandError> {
        self.parse_binlevel(&[ATok::Lt, ATok::Le, ATok::Gt, ATok::Ge], Self::parse_shift)
    }
    fn parse_shift(&mut self) -> Result<ANode, ExpandError> {
        self.parse_binlevel(&[ATok::Shl, ATok::Shr], Self::parse_add)
    }
    fn parse_add(&mut self) -> Result<ANode, ExpandError> {
        self.parse_binlevel(&[ATok::Plus, ATok::Minus], Self::parse_mul)
    }
    fn parse_mul(&mut self) -> Result<ANode, ExpandError> {
        self.parse_binlevel(&[ATok::Star, ATok::Slash, ATok::Percent], Self::parse_unary)
    }
    fn parse_unary(&mut self) -> Result<ANode, ExpandError> {
        match self.peek() {
            Some(ATok::Plus) => { self.pos += 1; self.parse_unary() }
            Some(ATok::Minus) => { self.pos += 1; Ok(ANode::Unary(ATok::Minus, Box::new(self.parse_unary()?))) }
            Some(ATok::Not) => { self.pos += 1; Ok(ANode::Unary(ATok::Not, Box::new(self.parse_unary()?))) }
            Some(ATok::Tilde) => { self.pos += 1; Ok(ANode::Unary(ATok::Tilde, Box::new(self.parse_unary()?))) }
            _ => self.parse_primary(),
        }
    }
    fn parse_primary(&mut self) -> Result<ANode, ExpandError> {
        match self.peek().cloned() {
            Some(ATok::Num(n)) => { self.pos += 1; Ok(ANode::Num(n)) }
            Some(ATok::Var(name)) => { self.pos += 1; Ok(ANode::Var(name)) }
            Some(ATok::LParen) => {
                self.pos += 1;
                let e = self.parse_expr()?;
                if !self.eat(&ATok::RParen) {
                    return Err(ExpandError::Syntax);
                }
                Ok(e)
            }
            _ => Err(ExpandError::Syntax),
        }
    }
}

fn arith_eval<F>(node: &ANode, lookup: &F, depth: u32, live: bool) -> Result<i64, ExpandError>
where
    F: Fn(&str) -> Option<String>,
{
    if depth > 32 {
        return Err(ExpandError::Syntax);
    }
    match node {
        ANode::Num(n) => Ok(*n),
        ANode::Var(name) => match lookup(name) {
            None => Ok(0),
            Some(v) if v.trim().is_empty() => Ok(0),
            Some(v) => {
                // A variable's value is itself an arithmetic expression
                // (commonly just an integer literal).
                eval_arith_depth(v.trim(), lookup, depth + 1)
            }
        },
        ANode::Unary(op, e) => {
            let v = arith_eval(e, lookup, depth + 1, live)?;
            Ok(match op {
                ATok::Minus => v.wrapping_neg(),
                ATok::Not => (v == 0) as i64,
                ATok::Tilde => !v,
                _ => return Err(ExpandError::Syntax),
            })
        }
        ANode::Ternary(c, t, f) => {
            let cv = arith_eval(c, lookup, depth + 1, live)?;
            if cv != 0 {
                arith_eval(t, lookup, depth + 1, live)
            } else {
                arith_eval(f, lookup, depth + 1, live)
            }
        }
        ANode::Bin(op, l, r) => {
            // Short-circuit logical operators.
            if matches!(op, ATok::AmpAmp) {
                let lv = arith_eval(l, lookup, depth + 1, live)?;
                if lv == 0 {
                    // RHS is dead: parse-checked already, don't evaluate.
                    let _ = arith_eval(r, lookup, depth + 1, false);
                    return Ok(0);
                }
                let rv = arith_eval(r, lookup, depth + 1, live)?;
                return Ok((rv != 0) as i64);
            }
            if matches!(op, ATok::PipePipe) {
                let lv = arith_eval(l, lookup, depth + 1, live)?;
                if lv != 0 {
                    let _ = arith_eval(r, lookup, depth + 1, false);
                    return Ok(1);
                }
                let rv = arith_eval(r, lookup, depth + 1, live)?;
                return Ok((rv != 0) as i64);
            }
            let lv = arith_eval(l, lookup, depth + 1, live)?;
            let rv = arith_eval(r, lookup, depth + 1, live)?;
            Ok(match op {
                ATok::Star => lv.wrapping_mul(rv),
                ATok::Slash => {
                    if rv == 0 {
                        if live { return Err(ExpandError::Syntax); }
                        0
                    } else {
                        lv.wrapping_div(rv)
                    }
                }
                ATok::Percent => {
                    if rv == 0 {
                        if live { return Err(ExpandError::Syntax); }
                        0
                    } else {
                        lv.wrapping_rem(rv)
                    }
                }
                ATok::Plus => lv.wrapping_add(rv),
                ATok::Minus => lv.wrapping_sub(rv),
                ATok::Shl => lv.wrapping_shl(rv as u32),
                ATok::Shr => lv.wrapping_shr(rv as u32),
                ATok::Lt => (lv < rv) as i64,
                ATok::Le => (lv <= rv) as i64,
                ATok::Gt => (lv > rv) as i64,
                ATok::Ge => (lv >= rv) as i64,
                ATok::Eq => (lv == rv) as i64,
                ATok::Ne => (lv != rv) as i64,
                ATok::Amp => lv & rv,
                ATok::Caret => lv ^ rv,
                ATok::Pipe => lv | rv,
                _ => return Err(ExpandError::Syntax),
            })
        }
    }
}

fn eval_arith_depth<F>(expr: &str, lookup: &F, depth: u32) -> Result<i64, ExpandError>
where
    F: Fn(&str) -> Option<String>,
{
    if depth > 32 {
        return Err(ExpandError::Syntax);
    }
    let toks = arith_tokenize(expr)?;
    let mut p = ArithParser { toks: &toks, pos: 0 };
    let node = p.parse_expr()?;
    if p.pos != p.toks.len() {
        return Err(ExpandError::Syntax);
    }
    arith_eval(&node, lookup, depth, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn map_env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        // Build an owned HashMap that the returned closure captures by
        // value (`move`). Lifetimes are independent of `pairs` because
        // the closure no longer borrows from it.
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |name: &str| map.get(name).cloned()
    }

    #[test]
    fn literal_text_passes_through() {
        let r = expand_vars("hello world", false, |_| None).unwrap();
        assert_eq!(r, "hello world");
    }

    #[test]
    fn simple_dollar_var() {
        let env = map_env(&[("HOME", "/root")]);
        assert_eq!(expand_vars("$HOME", false, &env).unwrap(), "/root");
        assert_eq!(
            expand_vars("path:$HOME/bin", false, &env).unwrap(),
            "path:/root/bin"
        );
    }

    #[test]
    fn brace_var() {
        let env = map_env(&[("USER", "alice")]);
        assert_eq!(expand_vars("${USER}", false, &env).unwrap(), "alice");
        assert_eq!(
            expand_vars("hi ${USER}!", false, &env).unwrap(),
            "hi alice!"
        );
    }

    #[test]
    fn brace_var_followed_by_letters() {
        // ${USER}name should expand USER then append "name" — distinguish from $USERname.
        let env = map_env(&[("USER", "alice")]);
        assert_eq!(
            expand_vars("${USER}name", false, &env).unwrap(),
            "alicename"
        );
    }

    #[test]
    fn unbraced_var_stops_at_non_alnum() {
        let env = map_env(&[("U", "alice"), ("USER", "bob")]);
        // $USER stops at the / — full var name "USER" matched.
        assert_eq!(expand_vars("$USER/bin", false, &env).unwrap(), "bob/bin");
        // $U stops at - (non-alphanumeric).
        assert_eq!(expand_vars("$U-tag", false, &env).unwrap(), "alice-tag");
    }

    #[test]
    fn undefined_var_expands_empty_when_not_strict() {
        let env = map_env(&[]);
        assert_eq!(expand_vars("a${MISSING}b", false, &env).unwrap(), "ab");
    }

    #[test]
    fn undefined_var_errors_when_strict() {
        let env = map_env(&[]);
        let err = expand_vars("$MISSING", true, &env).unwrap_err();
        assert_eq!(err, ExpandError::UndefinedVariable("MISSING".into()));
    }

    #[test]
    fn single_quoted_does_not_expand() {
        let env = map_env(&[("HOME", "/root")]);
        assert_eq!(expand_vars("'$HOME'", false, &env).unwrap(), "$HOME");
    }

    #[test]
    fn double_quoted_expands_inside() {
        let env = map_env(&[("USER", "bob")]);
        assert_eq!(
            expand_vars(r#""hello $USER""#, false, &env).unwrap(),
            "hello bob"
        );
    }

    #[test]
    fn backslash_escapes_next_char() {
        let env = map_env(&[]);
        assert_eq!(expand_vars(r"\$HOME", false, &env).unwrap(), "$HOME");
        assert_eq!(expand_vars(r"\\x", false, &env).unwrap(), r"\x");
    }

    #[test]
    fn dollar_at_end_is_literal() {
        let env = map_env(&[]);
        assert_eq!(expand_vars("end$", false, &env).unwrap(), "end$");
    }

    #[test]
    fn empty_brace_is_literal_dollar() {
        let env = map_env(&[]);
        assert_eq!(expand_vars("${}", false, &env).unwrap(), "$");
    }

    #[test]
    fn dollar_followed_by_non_alpha_is_literal() {
        let env = map_env(&[]);
        // $1 → name is "1", which doesn't start with letter/_; the `$` then `1`
        // are emitted as their literal bytes per shell semantics for this path.
        // Our parser actually treats `1` as alnum and reads "1" as the name —
        // so $1 looks up "1". When that's missing AND not strict, expands to empty.
        let r = expand_vars("$1", false, &env).unwrap();
        assert_eq!(r, "");
        // If lookup returns a value:
        let env2 = map_env(&[("1", "first-arg")]);
        assert_eq!(expand_vars("$1", false, &env2).unwrap(), "first-arg");
    }

    #[test]
    fn empty_input_returns_empty() {
        let env = map_env(&[]);
        assert_eq!(expand_vars("", false, &env).unwrap(), "");
    }

    #[test]
    fn consecutive_vars() {
        let env = map_env(&[("A", "alpha"), ("B", "beta")]);
        assert_eq!(expand_vars("$A$B", false, &env).unwrap(), "alphabeta");
        assert_eq!(expand_vars("${A}-${B}", false, &env).unwrap(), "alpha-beta");
    }

    #[test]
    fn nested_double_quotes_recursively_expand() {
        let env = map_env(&[("NESTED", "$INNER"), ("INNER", "deep")]);
        // The "expansion of NESTED" yields "$INNER" — that's not re-expanded by
        // the lookup itself, but if we put it in double-quotes the recursive
        // expand_vars would expand it. expand_vars(NESTED) returns "$INNER"
        // verbatim because lookup_env returns "$INNER" as-is.
        assert_eq!(expand_vars("$NESTED", false, &env).unwrap(), "$INNER");
    }

    #[test]
    fn mixed_quoted_and_unquoted() {
        let env = map_env(&[("X", "value")]);
        assert_eq!(
            expand_vars(r#"prefix-'$X'-"$X"-$X"#, false, &env).unwrap(),
            "prefix-$X-value-value"
        );
    }

    #[test]
    fn unclosed_brace_consumes_remainder_as_var_name() {
        let env = map_env(&[("ABC", "got it")]);
        // ${ABC<no closing brace> reads name as "ABC" until end.
        assert_eq!(expand_vars("${ABC", false, &env).unwrap(), "got it");
    }

    #[test]
    fn unclosed_quote_consumes_to_end() {
        let env = map_env(&[("X", "val")]);
        // Single-quoted unterminated: consumes literally to end.
        assert_eq!(expand_vars("'$X", false, &env).unwrap(), "$X");
        // Double-quoted unterminated: expands inside to end.
        assert_eq!(expand_vars(r#""$X"#, false, &env).unwrap(), "val");
    }

    #[test]
    fn lookup_closure_called_with_exact_name() {
        let mut last_seen: Option<String> = None;
        let lookup = |name: &str| {
            // Capture the name we were asked about (single-call test).
            // Can't mutate here in Fn; use a Cell pattern instead.
            // Simpler: just return Some(reverse-of-name).
            Some(name.chars().rev().collect::<String>())
        };
        assert_eq!(expand_vars("$HELLO", false, lookup).unwrap(), "OLLEH");
        // Avoid unused-mut warning.
        let _ = &mut last_seen;
    }
}
