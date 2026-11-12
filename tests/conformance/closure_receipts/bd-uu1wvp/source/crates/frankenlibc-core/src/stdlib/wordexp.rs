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
    /// A `$((...))` arithmetic expansion was malformed. glibc reports this
    /// as `WRDE_SYNTAX`. See [`eval_arith`] for exactly which inputs qualify.
    ArithSyntax,
    /// `${VAR?word}` / `${VAR:?word}` fired: the parameter was unset (or null,
    /// with `:`). glibc writes `"<name>: <message>"` to stderr and expands to
    /// NOTHING, while still returning success — so this is carried as a typed
    /// outcome rather than a failure, and the caller decides how to render it.
    NullOrUnset { name: String, message: String },
    /// A `${...}` form using an operator POSIX/glibc's `wordexp` does not
    /// implement — e.g. bash's substring `${VAR:1}` or replacement
    /// `${VAR/a/b}`. glibc reports `WRDE_SYNTAX`; fl used to fall through to a
    /// literal lookup of the whole braced text and silently expand to nothing.
    BadSubstitution,
}

/// Evaluate the inside of a `$((...))` arithmetic expansion the way glibc's
/// `wordexp` actually does — which is NOT full POSIX shell arithmetic.
///
/// Measured against live glibc (see `conformance_diff_wordexp_arith`), the
/// implemented grammar is exactly:
///
/// ```text
/// expr    := term  (('+' | '-') term)*
/// term    := factor (('*' | '/') factor)*
/// factor  := ('+' | '-')* primary
/// primary := number | '(' expr ')'
/// number  := 0x<hex> | 0<octal> | <decimal>
/// ```
///
/// Two behaviours are surprising and both are glibc's, reproduced deliberately
/// rather than "fixed":
///
/// 1. **Any operator outside that grammar silently ENDS the expression, and the
///    value parsed so far is the result.** glibc does not error and does not
///    evaluate the rest. Measured: `$((10%3))` -> `10`, `$((1<<4))` -> `1`,
///    `$((6&3))` -> `6`, `$((1?42:7))` -> `1`, and — the case that pins the rule
///    — `$((1+2*3<4))` -> `7`, i.e. `1+2*3` is evaluated and `<4` is dropped.
///    So `%`, shifts, comparisons, bitwise, logical and ternary are all absent,
///    not merely unimplemented-with-an-error.
/// 2. **A missing or non-numeric operand IS an error** (`WRDE_SYNTAX`), as is
///    division by zero and any identifier. Measured: `$((1+))`, `$(( ))`,
///    `$((abc))`, `$((1/0))`, `$((~5))`, `$((!0))` all fail, and notably
///    `$((FLVAR+1))` fails too — glibc's wordexp has no variables in arithmetic
///    even when the variable is set and exported.
/// 3. **The caller expands the body first, and that is the only way a value gets
///    in.** `$(($FLVAR+1))` is `42` while `$((FLVAR+1))` is an error, because
///    the expansion layer substitutes `$FLVAR` before this parser runs. An
///    unset name leaves nothing behind, so `$(($UNSET+1))` is `1` and a
///    zero-length body is `0` — but a blank one is still an error.
///
/// Arithmetic is `i64` and wrapping, so a pathological expression cannot panic.
pub fn eval_arith(expr: &[u8]) -> Result<i64, ExpandError> {
    // `expr` arrives ALREADY EXPANDED — the caller substitutes parameters first,
    // which is the only way a variable's value ever reaches this parser (see the
    // callers). Note the grammar above still has no identifiers: `$((VAR+1))` is
    // an error even when `VAR` is exported, while `$(($VAR+1))` works.
    //
    // An EMPTY expression is zero; a BLANK one is a syntax error. The rule is
    // length, not content, so it is checked before any whitespace is skipped.
    // Measured on live glibc 2.42 (bd-6a9tuc): `$(())` -> "0" and
    // `$(($UNSET))` -> "0", against `$(( ))` -> WRDE_SYNTAX and
    // `$(( $UNSET ))` -> WRDE_SYNTAX.
    if expr.is_empty() {
        return Ok(0);
    }
    let mut p = ArithParser { s: expr, i: 0 };
    p.skip_ws();
    let v = p.expr()?;
    // Trailing junk is NOT an error: glibc stops at the first operator it does
    // not implement and keeps what it has.
    Ok(v)
}

struct ArithParser<'a> {
    s: &'a [u8],
    i: usize,
}

impl ArithParser<'_> {
    fn skip_ws(&mut self) {
        while self.i < self.s.len() && self.s[self.i].is_ascii_whitespace() {
            self.i += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }

    fn expr(&mut self) -> Result<i64, ExpandError> {
        let mut acc = self.term()?;
        loop {
            self.skip_ws();
            match self.peek() {
                // `+=`/`-=` etc. are not in the grammar; a following `=` means
                // this is an operator glibc does not implement, so stop here.
                Some(op @ (b'+' | b'-')) if self.s.get(self.i + 1) != Some(&b'=') => {
                    self.i += 1;
                    let rhs = self.term()?;
                    acc = if op == b'+' {
                        acc.wrapping_add(rhs)
                    } else {
                        acc.wrapping_sub(rhs)
                    };
                }
                _ => return Ok(acc),
            }
        }
    }

    fn term(&mut self) -> Result<i64, ExpandError> {
        let mut acc = self.factor()?;
        loop {
            self.skip_ws();
            match self.peek() {
                Some(op @ (b'*' | b'/')) if self.s.get(self.i + 1) != Some(&b'=') => {
                    self.i += 1;
                    let rhs = self.factor()?;
                    if op == b'*' {
                        acc = acc.wrapping_mul(rhs);
                    } else {
                        if rhs == 0 {
                            return Err(ExpandError::ArithSyntax);
                        }
                        acc = acc.wrapping_div(rhs);
                    }
                }
                _ => return Ok(acc),
            }
        }
    }

    fn factor(&mut self) -> Result<i64, ExpandError> {
        self.skip_ws();
        match self.peek() {
            Some(b'+') => {
                self.i += 1;
                self.factor()
            }
            Some(b'-') => {
                self.i += 1;
                Ok(self.factor()?.wrapping_neg())
            }
            _ => self.primary(),
        }
    }

    fn primary(&mut self) -> Result<i64, ExpandError> {
        self.skip_ws();
        match self.peek() {
            Some(b'(') => {
                self.i += 1;
                let v = self.expr()?;
                self.skip_ws();
                if self.peek() != Some(b')') {
                    return Err(ExpandError::ArithSyntax);
                }
                self.i += 1;
                Ok(v)
            }
            Some(c) if c.is_ascii_digit() => Ok(self.number()),
            // Identifiers, `~`, `!`, an empty expression and a trailing operator
            // all land here and are syntax errors, matching glibc.
            _ => Err(ExpandError::ArithSyntax),
        }
    }

    /// `0x`/`0X` hex, leading `0` octal, otherwise decimal. Digits outside the
    /// active base simply end the number (they become trailing junk, which the
    /// caller drops).
    fn number(&mut self) -> i64 {
        let start = self.i;
        let mut val: i64 = 0;
        if self.s[self.i] == b'0' && matches!(self.s.get(self.i + 1), Some(b'x' | b'X')) {
            self.i += 2;
            while let Some(d) = self.peek().and_then(|c| (c as char).to_digit(16)) {
                val = val.wrapping_mul(16).wrapping_add(d as i64);
                self.i += 1;
            }
            // A bare `0x` with no digits is just the literal 0 followed by junk.
            if self.i == start + 2 {
                self.i = start + 1;
                return 0;
            }
            return val;
        }
        if self.s[self.i] == b'0' {
            self.i += 1;
            while let Some(c) = self.peek() {
                if !(b'0'..=b'7').contains(&c) {
                    break;
                }
                val = val.wrapping_mul(8).wrapping_add((c - b'0') as i64);
                self.i += 1;
            }
            return val;
        }
        while let Some(c) = self.peek() {
            if !c.is_ascii_digit() {
                break;
            }
            val = val.wrapping_mul(10).wrapping_add((c - b'0') as i64);
            self.i += 1;
        }
        val
    }
}

/// Given `bytes` positioned just past the `$((` of an arithmetic expansion,
/// return `(expression, index_after_closing_parens)`. Parenthesis depth starts
/// at 2 for the two already-consumed `(`, so nested groups such as
/// `$(((2+3)*4))` close correctly. Returns `None` if the `))` never arrives.
pub fn scan_arith_end(bytes: &[u8], after_open: usize) -> Option<(&[u8], usize)> {
    let mut depth = 2usize;
    let mut j = after_open;
    while j < bytes.len() {
        match bytes[j] {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some((&bytes[after_open..j - 1], j + 1));
                }
            }
            _ => {}
        }
        j += 1;
    }
    None
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
        // `$((expr))` arithmetic expansion. Checked BEFORE the generic `$`
        // handling so it cannot be mistaken for `$(command)` — which is exactly
        // the confusion bd-yb9f9r was about on the WRDE_NOCMD side.
        if bytes[i] == b'$' && bytes.get(i + 1) == Some(&b'(') && bytes.get(i + 2) == Some(&b'(') {
            let Some((expr, next)) = scan_arith_end(bytes, i + 3) else {
                return Err(ExpandError::ArithSyntax);
            };
            // The body is expanded BEFORE it is parsed as arithmetic — see the
            // matching note in the abi expander. `eval_arith` has no variables;
            // `$(($VAR+1))` works only because the parameter is substituted
            // here first, leaving digits for the parser. bd-6a9tuc.
            let expr_text = core::str::from_utf8(expr).map_err(|_| ExpandError::ArithSyntax)?;
            let expanded = expand_vars_dyn(expr_text, undef_is_error, lookup_env)?;
            let value = eval_arith(expanded.as_bytes())?;
            result.push_str(&value.to_string());
            i = next;
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
    let is_name =
        |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');

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
        // `${VAR?word}` / `${VAR:?word}` — "indicate error if unset [or null]".
        //
        // This used to fall through to `plain(lookup_env(content), content)`,
        // where `content` is the WHOLE braced text including the operator, so it
        // looked up an environment variable literally named `FOO:?`, found
        // nothing, and expanded to nothing. `${FOO:?}` with FOO=bar therefore
        // produced ZERO words where glibc produces "bar" — the value was
        // silently dropped on the SUCCESS path, which is the common one.
        //
        // Measured against live glibc (FOO=bar, EMPTY="", UNSET_ONE unset):
        //   ${FOO:?}  ${FOO?}  ${FOO:?msg}          -> ["bar"]
        //   ${EMPTY:?}                              -> [] + stderr "EMPTY: parameter null or not set"
        //   ${EMPTY?}                               -> []  (set-but-null is not an error without `:`)
        //   ${UNSET_ONE:?} ${UNSET_ONE?}            -> [] + stderr "UNSET_ONE: parameter null or not set"
        //   ${UNSET_ONE:?custom message}            -> [] + stderr "UNSET_ONE: custom message"
        // Note the return code is 0 in every one of those — wordexp reports this
        // condition by diagnostic and an empty expansion, not by an error code.
        Some(b'?') => {
            if test {
                let msg = if word.is_empty() {
                    "parameter null or not set".to_string()
                } else {
                    expand_vars_dyn(word, undef_is_error, lookup_env)?
                };
                Err(ExpandError::NullOrUnset {
                    name: name.to_string(),
                    message: msg,
                })
            } else {
                Ok(raw.unwrap_or_default())
            }
        }
        // Only `-`, `=`, `+` and `?` (each optionally preceded by `:`) exist in
        // POSIX parameter expansion; `#`/`%` were handled above. Anything else
        // is bash-only syntax that glibc rejects — measured: `${FOO:1}` gives
        // WRDE_SYNTAX(5), where fl used to look up a variable literally named
        // "FOO:1", find nothing, and expand to zero words. bd-xyjzl0.
        _ => Err(ExpandError::BadSubstitution),
    }
}

// ---------------------------------------------------------------------------
// Whole-input expansion with per-character provenance (wordexp's engine)
// ---------------------------------------------------------------------------
//
// glibc's wordexp decides field splitting and pathname expansion from where
// each character CAME FROM, not from the final text. Measured on glibc 2.39:
//   - literal blanks in the input separate words; IFS only splits text that
//     an UNQUOTED expansion produced ($VAR, ${...}, $(cmd), `cmd`, $((...)));
//   - a `${...}` result is split as a whole even if its WORD was quoted
//     (`${U:-"a b"}` -> a, b);
//   - only glob characters typed literally and unquoted in the input glob:
//     `*.msg` and `$(echo a)*.msg` glob, `$(echo "*.msg")`, `$G` and
//     `${U:-*.msg}` stay literal;
//   - an unquoted expansion that produces nothing leaves no field (`$(echo)`,
//     `$(echo)$(echo)`), while any quoted part keeps one (`"$(echo)"` -> "");
//   - positional parameters are the PROGRAM's argv ($0, $1, ${10}, $#, $*,
//     "$@"), `$$` is the pid, `$?`/`$!`/`$-` stay literal, `${#}` is a
//     syntax error;
//   - tilde expands at the start of a word and after any unquoted `=`, up to
//     an unquoted `/` or `:`.

/// One character of an expanded word plus the provenance that field splitting
/// and pathname expansion depend on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WordChar {
    pub byte: u8,
    /// Produced by an unquoted expansion: IFS characters here split fields.
    pub splittable: bool,
    /// Typed literally and unquoted in the input: `*`, `?`, `[` here glob.
    pub glob_active: bool,
}

/// Why whole-input expansion failed (each maps to a WRDE_* code).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WordexpFailure {
    /// An unquoted `| & ; < > ( ) { }` or newline.
    BadChar,
    /// An undefined parameter under `WRDE_UNDEF`.
    BadVal,
    /// Command substitution was requested but is not allowed (`WRDE_NOCMD`).
    CmdSub,
    /// Malformed input: unterminated quote/expansion, bad arithmetic, ...
    Syntax,
    /// The command runner could not run the command.
    NoSpace,
}

/// Runs one command-substitution body (`/bin/sh -c BODY`), returning stdout.
pub type CommandRunner<'a> = &'a mut dyn FnMut(&[u8]) -> Result<Vec<u8>, WordexpFailure>;

/// Everything the expander needs from its environment.
pub struct WordexpContext<'a> {
    pub lookup_env: &'a dyn Fn(&str) -> Option<String>,
    /// Home directory for `~` (empty name: the current user) or `~name`.
    pub home_dir: &'a dyn Fn(&[u8]) -> Option<Vec<u8>>,
    /// Run a command substitution body with `/bin/sh -c`, returning stdout.
    pub run_command: CommandRunner<'a>,
    /// The program's argv: `$0`, `$1`, ...
    pub positional: &'a [Vec<u8>],
    pub pid: u32,
    pub undef_is_error: bool,
    /// Sink for `${NAME:?message}` diagnostics (glibc writes them to stderr).
    pub diagnostic: &'a mut dyn FnMut(&str),
}

/// One element of a raw word: a character, a forced field break (between
/// the parameters of `"$@"`), or a mark that quoted text began here (so an
/// otherwise empty field survives).
#[derive(Clone, Copy)]
enum Item {
    Char(WordChar),
    Break,
    QuoteMark,
}

/// A raw word under construction.
#[derive(Default)]
struct RawWord {
    items: Vec<Item>,
}

impl RawWord {
    fn push(&mut self, byte: u8, splittable: bool, glob_active: bool) {
        self.items.push(Item::Char(WordChar {
            byte,
            splittable,
            glob_active,
        }));
    }
    fn push_expansion(&mut self, bytes: &[u8], splittable: bool) {
        for &byte in bytes {
            self.push(byte, splittable, false);
        }
    }
    fn mark_quoted(&mut self) {
        self.items.push(Item::QuoteMark);
    }
    fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

/// Expand a whole wordexp input into fields, before pathname expansion.
pub fn expand_input_fields(
    input: &[u8],
    ifs: &[u8],
    ctx: &mut WordexpContext<'_>,
) -> Result<Vec<Vec<WordChar>>, WordexpFailure> {
    let mut words: Vec<RawWord> = Vec::new();
    let mut word = RawWord::default();
    let mut i = 0;
    while i < input.len() {
        let b = input[i];
        match b {
            b' ' | b'\t' => {
                if !word.is_empty() {
                    words.push(std::mem::take(&mut word));
                }
                i += 1;
            }
            b'\n' | b'|' | b'&' | b';' | b'<' | b'>' | b'(' | b')' | b'{' | b'}' => {
                return Err(WordexpFailure::BadChar);
            }
            b'~' if word.items.is_empty() || ends_with_unquoted_eq(&word) => {
                i = expand_tilde_at(input, i, &mut word, ctx)?;
            }
            _ => {
                i = expand_one(input, i, &mut word, false, ifs, ctx)?;
            }
        }
    }
    if !word.is_empty() {
        words.push(word);
    }
    let mut fields = Vec::new();
    for word in words {
        split_fields(word, ifs, &mut fields);
    }
    Ok(fields)
}

fn ends_with_unquoted_eq(word: &RawWord) -> bool {
    matches!(
        word.items.last(),
        Some(Item::Char(WordChar {
            byte: b'=',
            glob_active: true,
            ..
        }))
    )
}

/// Handle the construct starting at `input[i]` (anything but a word-separating
/// blank), appending to `word`. `quoted` means inside double quotes. Returns
/// the index after the construct.
fn expand_one(
    input: &[u8],
    i: usize,
    word: &mut RawWord,
    quoted: bool,
    ifs: &[u8],
    ctx: &mut WordexpContext<'_>,
) -> Result<usize, WordexpFailure> {
    let b = input[i];
    match b {
        b'\\' if !quoted => {
            let Some(&next) = input.get(i + 1) else {
                return Err(WordexpFailure::Syntax);
            };
            word.mark_quoted();
            word.push(next, false, false);
            Ok(i + 2)
        }
        b'\\' => {
            // Inside double quotes a backslash escapes only $ ` " \ and newline.
            match input.get(i + 1) {
                Some(&next @ (b'$' | b'`' | b'"' | b'\\' | b'\n')) => {
                    word.push(next, false, false);
                    Ok(i + 2)
                }
                Some(_) => {
                    word.push(b'\\', false, false);
                    Ok(i + 1)
                }
                None => Err(WordexpFailure::Syntax),
            }
        }
        b'\'' if !quoted => {
            let Some(len) = input[i + 1..].iter().position(|&c| c == b'\'') else {
                return Err(WordexpFailure::Syntax);
            };
            word.mark_quoted();
            for &c in &input[i + 1..i + 1 + len] {
                word.push(c, false, false);
            }
            Ok(i + len + 2)
        }
        b'"' if !quoted => {
            word.mark_quoted();
            let mut j = i + 1;
            loop {
                match input.get(j) {
                    None => return Err(WordexpFailure::Syntax),
                    Some(b'"') => return Ok(j + 1),
                    Some(_) => j = expand_one(input, j, word, true, ifs, ctx)?,
                }
            }
        }
        b'`' => {
            let (body, next) = backquote_body(input, i, quoted)?;
            let output = (ctx.run_command)(&body)?;
            word.push_expansion(trim_trailing_newlines(&output), !quoted);
            Ok(next)
        }
        b'$' => expand_dollar(input, i, word, quoted, ifs, ctx),
        _ => {
            word.push(b, false, !quoted);
            Ok(i + 1)
        }
    }
}

fn trim_trailing_newlines(output: &[u8]) -> &[u8] {
    let end = output
        .iter()
        .rposition(|&c| c != b'\n')
        .map_or(0, |p| p + 1);
    &output[..end]
}

/// The body of a backquoted command starting at `input[open]` (with `\$`,
/// `` \` ``, `\\` -- and `\"` inside double quotes -- unescaped) and the index
/// after the closing backquote.
fn backquote_body(
    input: &[u8],
    open: usize,
    quoted: bool,
) -> Result<(Vec<u8>, usize), WordexpFailure> {
    let mut body = Vec::new();
    let mut j = open + 1;
    while let Some(&c) = input.get(j) {
        match c {
            b'`' => return Ok((body, j + 1)),
            b'\\' => match input.get(j + 1) {
                Some(&next @ (b'$' | b'`' | b'\\')) => {
                    body.push(next);
                    j += 2;
                }
                Some(&b'"') if quoted => {
                    body.push(b'"');
                    j += 2;
                }
                Some(&next) => {
                    body.push(b'\\');
                    body.push(next);
                    j += 2;
                }
                None => return Err(WordexpFailure::Syntax),
            },
            _ => {
                body.push(c);
                j += 1;
            }
        }
    }
    Err(WordexpFailure::Syntax)
}

/// Index of the `)` closing a `$(` whose body starts at `start`, skipping
/// quotes, escapes, backquotes and nested parentheses.
fn command_body_end(input: &[u8], start: usize) -> Option<usize> {
    let mut depth = 1usize;
    let mut j = start;
    while let Some(&c) = input.get(j) {
        match c {
            b'\\' => j += 2,
            b'\'' => {
                let len = input[j + 1..].iter().position(|&q| q == b'\'')?;
                j += len + 2;
            }
            b'"' => {
                j += 1;
                loop {
                    match input.get(j)? {
                        b'\\' => j += 2,
                        b'"' => break,
                        _ => j += 1,
                    }
                }
                j += 1;
            }
            b'`' => {
                j += 1;
                loop {
                    match input.get(j)? {
                        b'\\' => j += 2,
                        b'`' => break,
                        _ => j += 1,
                    }
                }
                j += 1;
            }
            b'(' => {
                depth += 1;
                j += 1;
            }
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(j);
                }
                j += 1;
            }
            _ => j += 1,
        }
    }
    None
}

/// Index of the `}` closing a `${` whose body starts at `start`, honouring
/// quotes, escapes and nested `${`/`$(`.
fn brace_body_end(input: &[u8], start: usize) -> Option<usize> {
    let mut j = start;
    while let Some(&c) = input.get(j) {
        match c {
            b'\\' => j += 2,
            b'\'' => {
                let len = input[j + 1..].iter().position(|&q| q == b'\'')?;
                j += len + 2;
            }
            b'"' => {
                j += 1;
                loop {
                    match input.get(j)? {
                        b'\\' => j += 2,
                        b'"' => break,
                        _ => j += 1,
                    }
                }
                j += 1;
            }
            b'$' if input.get(j + 1) == Some(&b'{') => j = brace_body_end(input, j + 2)? + 1,
            b'$' if input.get(j + 1) == Some(&b'(') => j = command_body_end(input, j + 2)? + 1,
            b'}' => return Some(j),
            _ => j += 1,
        }
    }
    None
}

fn is_name_start(c: u8) -> bool {
    c.is_ascii_alphabetic() || c == b'_'
}

fn is_name_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

fn expand_dollar(
    input: &[u8],
    i: usize,
    word: &mut RawWord,
    quoted: bool,
    ifs: &[u8],
    ctx: &mut WordexpContext<'_>,
) -> Result<usize, WordexpFailure> {
    let split = !quoted;
    match input.get(i + 1).copied() {
        Some(b'(') if input.get(i + 2) == Some(&b'(') => {
            let Some((expr, next)) = scan_arith_end(input, i + 3) else {
                return Err(WordexpFailure::Syntax);
            };
            // The body is expanded textually first; glibc's arithmetic itself
            // has no variables (see `eval_arith`).
            let body = expand_to_string(expr, ifs, ctx)?;
            let value = eval_arith(&body).map_err(|_| WordexpFailure::Syntax)?;
            word.push_expansion(value.to_string().as_bytes(), split);
            Ok(next)
        }
        Some(b'(') => {
            let Some(end) = command_body_end(input, i + 2) else {
                return Err(WordexpFailure::Syntax);
            };
            let output = (ctx.run_command)(&input[i + 2..end])?;
            word.push_expansion(trim_trailing_newlines(&output), split);
            Ok(end + 1)
        }
        Some(b'{') => {
            let Some(end) = brace_body_end(input, i + 2) else {
                return Err(WordexpFailure::Syntax);
            };
            let value = expand_braced(&input[i + 2..end], ifs, ctx)?;
            if let Some(value) = value {
                word.push_expansion(&value, split);
            }
            Ok(end + 1)
        }
        Some(b'$') => {
            word.push_expansion(ctx.pid.to_string().as_bytes(), split);
            Ok(i + 2)
        }
        Some(d @ b'0'..=b'9') => {
            let index = usize::from(d - b'0');
            push_positional(word, index, split, ctx)?;
            Ok(i + 2)
        }
        Some(b'#') => {
            let count = ctx.positional.len().saturating_sub(1);
            word.push_expansion(count.to_string().as_bytes(), split);
            Ok(i + 2)
        }
        Some(b'*') => {
            // glibc quirk, measured: a quoted `$*` with no positional
            // parameters fails with WRDE_NOSPACE when the word holds no
            // characters yet (`"$*"`, `a "$*"`, `"${1}$*"`), but not after any
            // (`x"$*"y`, `"a$*"`, `"$#$*"`).
            if quoted
                && ctx.positional.len() <= 1
                && !word.items.iter().any(|item| matches!(item, Item::Char(_)))
            {
                return Err(WordexpFailure::NoSpace);
            }
            let joined = join_params(ctx.positional, ifs, quoted);
            word.push_expansion(&joined, split);
            Ok(i + 2)
        }
        Some(b'@') => {
            // Each parameter is its own field: an explicit break when quoted;
            // unquoted, a splittable separator, so empty parameters vanish as
            // field splitting removes empty unquoted fields.
            let params = ctx.positional.get(1..).unwrap_or_default();
            for (n, param) in params.iter().enumerate() {
                if n > 0 {
                    match ifs.first() {
                        Some(&sep) if !quoted => word.push(sep, true, false),
                        _ => word.items.push(Item::Break),
                    }
                } else if quoted {
                    word.mark_quoted();
                }
                word.push_expansion(param, split);
            }
            Ok(i + 2)
        }
        Some(c) if is_name_start(c) => {
            let len = input[i + 1..]
                .iter()
                .take_while(|&&c| is_name_char(c))
                .count();
            let name = core::str::from_utf8(&input[i + 1..i + 1 + len]).unwrap_or("");
            match (ctx.lookup_env)(name) {
                Some(value) => word.push_expansion(value.as_bytes(), split),
                None if ctx.undef_is_error => return Err(WordexpFailure::BadVal),
                None => {}
            }
            Ok(i + 1 + len)
        }
        // `$` alone, `$?`, `$!`, `$-`, ...: a literal dollar sign.
        _ => {
            word.push(b'$', false, !quoted);
            Ok(i + 1)
        }
    }
}

fn push_positional(
    word: &mut RawWord,
    index: usize,
    split: bool,
    ctx: &WordexpContext<'_>,
) -> Result<(), WordexpFailure> {
    match ctx.positional.get(index) {
        Some(value) => word.push_expansion(value, split),
        None if ctx.undef_is_error => return Err(WordexpFailure::BadVal),
        None => {}
    }
    Ok(())
}

/// `$*`: the positional parameters joined by IFS's first character (a space
/// when IFS is unset/default, nothing when IFS is empty and quoted).
fn join_params(positional: &[Vec<u8>], ifs: &[u8], quoted: bool) -> Vec<u8> {
    let separator: &[u8] = match ifs.first() {
        Some(c) => std::slice::from_ref(c),
        None if quoted => b"",
        None => b" ",
    };
    positional.get(1..).unwrap_or_default().join(separator)
}

/// Expand `text` (a parameter word, an arithmetic body) to plain bytes:
/// quotes removed, expansions performed, no splitting.
fn expand_to_string(
    text: &[u8],
    ifs: &[u8],
    ctx: &mut WordexpContext<'_>,
) -> Result<Vec<u8>, WordexpFailure> {
    let mut word = RawWord::default();
    let mut i = 0;
    while i < text.len() {
        i = expand_one(text, i, &mut word, false, ifs, ctx)?;
    }
    Ok(word
        .items
        .into_iter()
        .filter_map(|item| match item {
            Item::Char(c) => Some(c.byte),
            Item::Break => Some(b' '),
            Item::QuoteMark => None,
        })
        .collect())
}

/// Evaluate a `${...}` body. `None` means "expands to nothing".
fn expand_braced(
    body: &[u8],
    ifs: &[u8],
    ctx: &mut WordexpContext<'_>,
) -> Result<Option<Vec<u8>>, WordexpFailure> {
    // `${#NAME}` / `${#N}`: length. `${#}` alone is a syntax error in glibc.
    if let Some(rest) = body.strip_prefix(b"#") {
        if rest.is_empty() {
            return Err(WordexpFailure::Syntax);
        }
        if rest.iter().all(|&c| c.is_ascii_digit()) {
            let index: usize = core::str::from_utf8(rest)
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(usize::MAX);
            let len = ctx.positional.get(index).map_or(0, |v| char_count(v));
            return Ok(Some(len.to_string().into_bytes()));
        }
        if rest.iter().all(|&c| is_name_char(c)) && is_name_start(rest[0]) {
            let name = core::str::from_utf8(rest).unwrap_or("");
            let len = (ctx.lookup_env)(name).map_or(0, |v| v.chars().count());
            return Ok(Some(len.to_string().into_bytes()));
        }
        return Err(WordexpFailure::Syntax);
    }
    let (value, name_len) = if body.first().is_some_and(|c| c.is_ascii_digit()) {
        let len = body.iter().take_while(|c| c.is_ascii_digit()).count();
        let index: usize = core::str::from_utf8(&body[..len])
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(usize::MAX);
        (ctx.positional.get(index).cloned(), len)
    } else if body.first().is_some_and(|&c| is_name_start(c)) {
        let len = body.iter().take_while(|&&c| is_name_char(c)).count();
        let name = core::str::from_utf8(&body[..len]).unwrap_or("");
        ((ctx.lookup_env)(name).map(String::into_bytes), len)
    } else {
        return Err(WordexpFailure::Syntax);
    };
    let name = String::from_utf8_lossy(&body[..name_len]).into_owned();
    let op = &body[name_len..];
    if op.is_empty() {
        return match value {
            Some(v) => Ok(Some(v)),
            None if ctx.undef_is_error => Err(WordexpFailure::BadVal),
            None => Ok(None),
        };
    }
    // `${NAME%pat}` `${NAME%%pat}` `${NAME#pat}` `${NAME##pat}`.
    if matches!(op[0], b'%' | b'#') {
        let kind = op[0];
        let largest = op.get(1) == Some(&kind);
        let pattern = expand_to_string(&op[if largest { 2 } else { 1 }..], ifs, ctx)?;
        let value = String::from_utf8_lossy(&value.unwrap_or_default()).into_owned();
        let pattern = String::from_utf8_lossy(&pattern).into_owned();
        return Ok(Some(
            remove_affix(&value, &pattern, kind == b'%', largest).into_bytes(),
        ));
    }
    let (colon, rest) = match op.strip_prefix(b":") {
        Some(rest) => (true, rest),
        None => (false, op),
    };
    let Some((&operator, word)) = rest.split_first() else {
        return Err(WordexpFailure::Syntax);
    };
    let missing = value.is_none() || (colon && value.as_deref() == Some(b""));
    match operator {
        // `=` would also assign, which a wordexp subshell cannot make visible.
        b'-' | b'=' => {
            if missing {
                Ok(Some(expand_to_string(word, ifs, ctx)?))
            } else {
                Ok(value)
            }
        }
        b'+' => {
            if missing {
                Ok(None)
            } else {
                Ok(Some(expand_to_string(word, ifs, ctx)?))
            }
        }
        b'?' => {
            if missing {
                let message = if word.is_empty() {
                    "parameter null or not set".to_owned()
                } else {
                    String::from_utf8_lossy(&expand_to_string(word, ifs, ctx)?).into_owned()
                };
                (ctx.diagnostic)(&format!("{name}: {message}"));
                Ok(None)
            } else {
                Ok(value)
            }
        }
        _ => Err(WordexpFailure::Syntax),
    }
}

fn char_count(bytes: &[u8]) -> usize {
    String::from_utf8_lossy(bytes).chars().count()
}

/// Tilde expansion at `input[i]` (start of word, or after an unquoted `=`):
/// the prefix runs to an unquoted `/` or `:`; a quoted prefix or unknown user
/// is left literal.
fn expand_tilde_at(
    input: &[u8],
    i: usize,
    word: &mut RawWord,
    ctx: &mut WordexpContext<'_>,
) -> Result<usize, WordexpFailure> {
    let len = input[i + 1..]
        .iter()
        .take_while(|&&c| !matches!(c, b'/' | b':' | b' ' | b'\t'))
        .count();
    let prefix = &input[i + 1..i + 1 + len];
    let end = i + 1 + len;
    // glibc copies a prefix holding quotes or `$` verbatim -- no quote
    // removal, no expansion (`~"x"` stays `~"x"`, `~$HOME` stays `~$HOME`).
    if prefix
        .iter()
        .any(|c| matches!(c, b'"' | b'\'' | b'$' | b'`'))
    {
        word.push(b'~', false, true);
        for &c in prefix {
            word.push(c, false, true);
        }
        return Ok(end);
    }
    // A backslash in the prefix disables the lookup but is itself removed
    // (`~roo\t` gives `~root`, not root's home).
    if prefix.contains(&b'\\') {
        word.push(b'~', false, true);
        let mut j = 0;
        while j < prefix.len() {
            if prefix[j] == b'\\' {
                if let Some(&escaped) = prefix.get(j + 1) {
                    word.push(escaped, false, false);
                }
                j += 2;
            } else {
                word.push(prefix[j], false, true);
                j += 1;
            }
        }
        return Ok(end);
    }
    let home = if prefix.is_empty() {
        (ctx.lookup_env)("HOME")
            .map(String::into_bytes)
            .or_else(|| (ctx.home_dir)(b""))
    } else {
        (ctx.home_dir)(prefix)
    };
    match home {
        Some(home) => word.push_expansion(&home, false),
        None => {
            // Unknown user: the prefix stays as written.
            word.push(b'~', false, true);
            for &c in prefix {
                word.push(c, false, true);
            }
        }
    }
    Ok(end)
}

/// POSIX field splitting of one raw word on its splittable IFS characters
/// (plus explicit `"$@"` breaks): IFS whitespace runs delimit, each non-
/// whitespace IFS character delimits exactly one field (so two in a row make
/// an empty field), leading/trailing delimiters add nothing. A field holding
/// quoted text survives even when empty; one made only of empty unquoted
/// expansions does not.
fn split_fields(word: RawWord, ifs: &[u8], out: &mut Vec<Vec<WordChar>>) {
    #[derive(PartialEq)]
    enum Prev {
        Start,
        Text,
        WsDelim,
        NonWsDelim,
    }
    let mut current: Vec<WordChar> = Vec::new();
    // The current field exists even if empty (quoted text or a "$@" break).
    let mut live = false;
    let mut prev = Prev::Start;
    for item in word.items {
        match item {
            Item::QuoteMark => {
                live = true;
                prev = Prev::Text;
            }
            Item::Break => {
                out.push(std::mem::take(&mut current));
                live = true;
                prev = Prev::Text;
            }
            Item::Char(ch) if ch.splittable && ifs.contains(&ch.byte) => {
                let ws = matches!(ch.byte, b' ' | b'\t' | b'\n');
                let field_open = !current.is_empty() || live;
                match (ws, &prev) {
                    (true, Prev::Text) if field_open => {
                        out.push(std::mem::take(&mut current));
                        live = false;
                        prev = Prev::WsDelim;
                    }
                    (true, _) => {}
                    (false, Prev::Text) if field_open => {
                        out.push(std::mem::take(&mut current));
                        live = false;
                        prev = Prev::NonWsDelim;
                    }
                    (false, Prev::WsDelim) => prev = Prev::NonWsDelim,
                    (false, _) => {
                        // Leading, or a second in a row: an empty field.
                        out.push(Vec::new());
                        prev = Prev::NonWsDelim;
                    }
                }
            }
            Item::Char(ch) => {
                current.push(ch);
                prev = Prev::Text;
            }
        }
    }
    if !current.is_empty() || live {
        out.push(current);
    }
}

/// The pathname pattern for a field, or `None` when it has no glob-active
/// metacharacter (then it is used literally). Inactive metacharacters and
/// backslashes are escaped so they match only themselves.
pub fn field_glob_pattern(field: &[WordChar]) -> Option<Vec<u8>> {
    if !field
        .iter()
        .any(|c| c.glob_active && matches!(c.byte, b'*' | b'?' | b'['))
    {
        return None;
    }
    let mut pattern = Vec::with_capacity(field.len() * 2);
    for c in field {
        if !c.glob_active && matches!(c.byte, b'*' | b'?' | b'[' | b']' | b'\\') {
            pattern.push(b'\\');
        }
        pattern.push(c.byte);
    }
    Some(pattern)
}

/// The field's text (quote removal already happened during expansion).
pub fn field_text(field: &[WordChar]) -> Vec<u8> {
    field.iter().map(|c| c.byte).collect()
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
    // ---- whole-input expander (expand_input_fields) ----------------------
    //
    // Expected values are glibc 2.39 wordexp results for the same input,
    // environment (HOME=/root, SP="a b", G="*.msg", X=y) and argv.

    struct Fixture {
        env: Vec<(&'static str, &'static str)>,
        commands: Vec<(&'static str, &'static str)>,
        argv: Vec<Vec<u8>>,
        nocmd: bool,
        undef: bool,
    }

    impl Fixture {
        fn new() -> Self {
            Self {
                env: vec![("HOME", "/root"), ("SP", "a b"), ("G", "*.msg"), ("X", "y")],
                commands: vec![
                    ("echo hi there", "hi there\n"),
                    ("echo", "\n"),
                    ("echo x", "x\n"),
                    ("echo a", "a\n"),
                    ("echo \"*.msg\"", "*.msg\n"),
                    ("echo 41", "41\n"),
                    ("echo a b", "a b\n"),
                    ("echo dflt v", "dflt v\n"),
                    ("printf 'a\\n\\n'", "a\n\n"),
                    ("echo \"p:q r\"", "p:q r\n"),
                ],
                argv: vec![
                    b"prog".to_vec(),
                    b"one".to_vec(),
                    b"".to_vec(),
                    b"t h".to_vec(),
                ],
                nocmd: false,
                undef: false,
            }
        }

        fn run(&self, input: &str, ifs: &str) -> Result<Vec<String>, WordexpFailure> {
            let env = self.env.clone();
            let lookup = move |name: &str| {
                env.iter()
                    .find(|(k, _)| *k == name)
                    .map(|(_, v)| (*v).to_string())
            };
            let home = |user: &[u8]| match user {
                b"" | b"root" => Some(b"/root".to_vec()),
                _ => None,
            };
            let commands = self.commands.clone();
            let nocmd = self.nocmd;
            let mut run = move |body: &[u8]| {
                if nocmd {
                    return Err(WordexpFailure::CmdSub);
                }
                let body = core::str::from_utf8(body).unwrap();
                commands
                    .iter()
                    .find(|(cmd, _)| *cmd == body)
                    .map(|(_, out)| out.as_bytes().to_vec())
                    .ok_or(WordexpFailure::NoSpace)
            };
            let mut diag = |_: &str| {};
            let mut ctx = WordexpContext {
                lookup_env: &lookup,
                home_dir: &home,
                run_command: &mut run,
                positional: &self.argv,
                pid: 4242,
                undef_is_error: self.undef,
                diagnostic: &mut diag,
            };
            let fields = expand_input_fields(input.as_bytes(), ifs.as_bytes(), &mut ctx)?;
            Ok(fields
                .iter()
                .map(|f| String::from_utf8(field_text(f)).unwrap())
                .collect())
        }
    }

    fn words(list: &[&str]) -> Result<Vec<String>, WordexpFailure> {
        Ok(list.iter().map(|s| s.to_string()).collect())
    }

    #[test]
    fn command_substitution_fields_match_glibc() {
        let f = Fixture::new();
        let d = " \t\n";
        assert_eq!(f.run("$(echo hi there)", d), words(&["hi", "there"]));
        assert_eq!(f.run("\"$(echo hi there)\"", d), words(&["hi there"]));
        assert_eq!(f.run("x$(echo a b)y", d), words(&["xa", "by"]));
        assert_eq!(f.run("$(($(echo 41)+1))", d), words(&["42"]));
        assert_eq!(f.run("`echo a b`", d), words(&["a", "b"]));
        assert_eq!(f.run("$(printf 'a\\n\\n')", d), words(&["a"]));
        assert_eq!(f.run("$(echo)", d), words(&[]));
        assert_eq!(f.run("$(echo)$(echo)", d), words(&[]));
        assert_eq!(f.run("\"$(echo)\"", d), words(&[""]));
        assert_eq!(f.run("p$(echo)q", d), words(&["pq"]));
        assert_eq!(f.run("a $(echo) b", d), words(&["a", "b"]));
        assert_eq!(f.run("${U:-$(echo dflt v)}", d), words(&["dflt", "v"]));
        assert_eq!(f.run("$(echo \"p:q r\")", ":"), words(&["p", "q r"]));
    }

    #[test]
    fn nocmd_and_unterminated_substitution() {
        let mut f = Fixture::new();
        f.nocmd = true;
        let d = " \t\n";
        assert_eq!(f.run("$(echo x)", d), Err(WordexpFailure::CmdSub));
        assert_eq!(f.run("\"`echo x`\"", d), Err(WordexpFailure::CmdSub));
        assert_eq!(f.run("$(($(echo 41)+1))", d), Err(WordexpFailure::CmdSub));
        // The unterminated body is a syntax error before NOCMD is consulted.
        assert_eq!(f.run("$(true", d), Err(WordexpFailure::Syntax));
        assert_eq!(f.run("$((1+2))", d), words(&["3"]));
        assert_eq!(f.run("'$(echo x)'", d), words(&["$(echo x)"]));
    }

    #[test]
    fn parameter_expansion_splitting_matches_glibc() {
        let f = Fixture::new();
        let d = " \t\n";
        assert_eq!(f.run("${U:-a b}", d), words(&["a", "b"]));
        // glibc splits a ${} result as a whole, even a quoted WORD.
        assert_eq!(f.run("${U:-\"a b\"}", d), words(&["a", "b"]));
        assert_eq!(f.run("${U:-'a b'}", d), words(&["a", "b"]));
        assert_eq!(f.run("\"${U:-a b}\"", d), words(&["a b"]));
        assert_eq!(f.run("$SP$SP", d), words(&["a", "ba", "b"]));
        assert_eq!(f.run("\"$SP\"x$SP", d), words(&["a bxa", "b"]));
        assert_eq!(f.run("x${U}y", d), words(&["xy"]));
        assert_eq!(f.run("${#SP}", d), words(&["3"]));
        assert_eq!(f.run("${SP%b}", d), words(&["a"]));
        assert_eq!(f.run("${SP#a }", d), words(&["b"]));
        assert_eq!(f.run("${U:+z}", d), words(&[]));
        assert_eq!(f.run("${X:+z $SP}", d), words(&["z", "a", "b"]));
        assert_eq!(f.run("$SP", ":"), words(&["a b"]));
        assert_eq!(f.run("a b:c", ":"), words(&["a", "b:c"]));
        assert_eq!(f.run("$SP", ""), words(&["a b"]));
        assert_eq!(f.run("${#}", d), Err(WordexpFailure::Syntax));
        assert_eq!(f.run("${U:1}", d), Err(WordexpFailure::Syntax));
    }

    #[test]
    fn ifs_non_whitespace_delimiters() {
        let mut f = Fixture::new();
        f.env.push(("C", "a::b:"));
        f.env.push(("L", ":a"));
        assert_eq!(f.run("$C", ":"), words(&["a", "", "b"]));
        assert_eq!(f.run("$L", ":"), words(&["", "a"]));
        f.env.push(("M", "a : b"));
        assert_eq!(f.run("$M", " :"), words(&["a", "b"]));
    }

    #[test]
    fn special_and_positional_parameters_match_glibc() {
        let mut f = Fixture::new();
        let d = " \t\n";
        assert_eq!(f.run("$0", d), words(&["prog"]));
        assert_eq!(f.run("$1", d), words(&["one"]));
        assert_eq!(f.run("$10", d), words(&["one0"]));
        assert_eq!(f.run("${3}", d), words(&["t", "h"]));
        assert_eq!(f.run("\"${3}\"", d), words(&["t h"]));
        assert_eq!(f.run("${#3}", d), words(&["3"]));
        assert_eq!(f.run("$#", d), words(&["3"]));
        assert_eq!(f.run("$*", d), words(&["one", "t", "h"]));
        assert_eq!(f.run("\"$*\"", d), words(&["one  t h"]));
        assert_eq!(f.run("\"$@\"", d), words(&["one", "", "t h"]));
        assert_eq!(f.run("p\"$@\"q", d), words(&["pone", "", "t hq"]));
        assert_eq!(f.run("$$x", d), words(&["4242x"]));
        assert_eq!(f.run("$? $! $- $", d), words(&["$?", "$!", "$-", "$"]));
        f.undef = true;
        assert_eq!(f.run("$NOPE", d), Err(WordexpFailure::BadVal));
        assert_eq!(f.run("${NOPE}", d), Err(WordexpFailure::BadVal));
    }

    #[test]
    fn tilde_positions_match_glibc() {
        let f = Fixture::new();
        let d = " \t\n";
        assert_eq!(f.run("~", d), words(&["/root"]));
        assert_eq!(f.run("\"~\"", d), words(&["~"]));
        assert_eq!(f.run("~root", d), words(&["/root"]));
        assert_eq!(f.run("~nosuch", d), words(&["~nosuch"]));
        assert_eq!(f.run("a=~", d), words(&["a=/root"]));
        assert_eq!(f.run("a=b=~", d), words(&["a=b=/root"]));
        assert_eq!(f.run("a:~", d), words(&["a:~"]));
        assert_eq!(f.run("x~", d), words(&["x~"]));
        assert_eq!(f.run("~/x~", d), words(&["/root/x~"]));
        assert_eq!(f.run("~:", d), words(&["/root:"]));
        assert_eq!(f.run("\\~", d), words(&["~"]));
        assert_eq!(f.run("a=~root/b", d), words(&["a=/root/b"]));
        // A prefix with quotes or `$` is copied verbatim; a backslash only
        // blocks the lookup.
        assert_eq!(f.run("~\"x\"", d), words(&["~\"x\""]));
        assert_eq!(f.run("~$HOME", d), words(&["~$HOME"]));
        assert_eq!(f.run("~root\"x\"/y", d), words(&["~root\"x\"/y"]));
        assert_eq!(f.run("~roo\\t", d), words(&["~root"]));
        assert_eq!(f.run("~a/b\"c\"", d), words(&["~a/bc"]));
        assert_eq!(f.run("~/\"a b\"", d), words(&["/root/a b"]));
    }

    #[test]
    fn quoted_star_without_parameters_is_nospace_like_glibc() {
        let mut f = Fixture::new();
        f.argv.truncate(1);
        let d = " \t\n";
        for input in ["\"$*\"", "a \"$*\"", "\"${1}$*\"", "\"\"\"$*\"", "\"$*$*\""] {
            assert_eq!(f.run(input, d), Err(WordexpFailure::NoSpace), "{input:?}");
        }
        assert_eq!(f.run("x\"$*\"y", d), words(&["xy"]));
        assert_eq!(f.run("\"a$*\"", d), words(&["a"]));
        assert_eq!(f.run("\"$#$*\"", d), words(&["0"]));
        assert_eq!(f.run("$*", d), words(&[]));
        assert_eq!(f.run("\"$@\"", d), words(&[""]));
    }

    #[test]
    fn glob_activity_follows_input_provenance() {
        let f = Fixture::new();
        let d = " \t\n";
        let pattern = |input: &str| {
            let env = f.env.clone();
            let lookup = move |name: &str| {
                env.iter()
                    .find(|(k, _)| *k == name)
                    .map(|(_, v)| (*v).to_string())
            };
            let home = |_: &[u8]| None;
            let commands = f.commands.clone();
            let mut run = move |body: &[u8]| {
                let body = core::str::from_utf8(body).unwrap();
                Ok(commands
                    .iter()
                    .find(|(cmd, _)| *cmd == body)
                    .map(|(_, out)| out.as_bytes().to_vec())
                    .unwrap_or_default())
            };
            let mut diag = |_: &str| {};
            let mut ctx = WordexpContext {
                lookup_env: &lookup,
                home_dir: &home,
                run_command: &mut run,
                positional: &[],
                pid: 1,
                undef_is_error: false,
                diagnostic: &mut diag,
            };
            expand_input_fields(input.as_bytes(), d.as_bytes(), &mut ctx)
                .unwrap()
                .iter()
                .map(|field| field_glob_pattern(field).map(|p| String::from_utf8(p).unwrap()))
                .collect::<Vec<_>>()
        };
        assert_eq!(pattern("*.msg"), vec![Some("*.msg".to_string())]);
        assert_eq!(pattern("*.\"msg\""), vec![Some("*.msg".to_string())]);
        assert_eq!(pattern("\"*.msg\""), vec![None]);
        assert_eq!(pattern("'*.msg'"), vec![None]);
        assert_eq!(pattern("\\*.msg"), vec![None]);
        assert_eq!(pattern("$G"), vec![None]);
        assert_eq!(pattern("${U:-*.msg}"), vec![None]);
        assert_eq!(pattern("$(echo \"*.msg\")"), vec![None]);
        assert_eq!(pattern("$(echo a)*.msg"), vec![Some("a*.msg".to_string())]);
        // A literal glob next to quoted metacharacters escapes the quoted ones.
        assert_eq!(pattern("x\"*\"*"), vec![Some("x\\**".to_string())]);
        assert_eq!(pattern("[ab].msg"), vec![Some("[ab].msg".to_string())]);
    }

    #[test]
    fn bad_characters_and_syntax_errors() {
        let f = Fixture::new();
        let d = " \t\n";
        for input in ["a|b", "a;b", "a&b", "a<b", "a>b", "(a)", "{a}", "a\nb"] {
            assert_eq!(f.run(input, d), Err(WordexpFailure::BadChar), "{input:?}");
        }
        assert_eq!(f.run("\"a|b\"", d), words(&["a|b"]));
        assert_eq!(f.run("'unterminated", d), Err(WordexpFailure::Syntax));
        assert_eq!(f.run("\"unterminated", d), Err(WordexpFailure::Syntax));
        assert_eq!(f.run("trailing\\", d), Err(WordexpFailure::Syntax));
        assert_eq!(f.run("${unterminated", d), Err(WordexpFailure::Syntax));
        assert_eq!(f.run("`unterminated", d), Err(WordexpFailure::Syntax));
        assert_eq!(f.run("$((1+))", d), Err(WordexpFailure::Syntax));
        assert_eq!(f.run("\"\"", d), words(&[""]));
        assert_eq!(f.run("''x''", d), words(&["x"]));
    }
}
