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
///
/// Arithmetic is `i64` and wrapping, so a pathological expression cannot panic.
pub fn eval_arith(expr: &[u8]) -> Result<i64, ExpandError> {
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
            let value = eval_arith(expr)?;
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
