//! BSD `setmode` / `getmode` — chmod symbolic-mode parser/applier.
//!
//! Pure-safe Rust port of the byte-level logic. The C ABI shim in
//! `frankenlibc-abi::stdlib_abi` allocates the opaque "bitbox" via
//! malloc so the C contract (`void *setmode(...)` →
//! `mode_t getmode(void *, mode_t)`) is preserved.
//!
//! ## Grammar (POSIX 1003.1, restricted subset)
//!
//! ```text
//! mode    = clause ( "," clause )*
//! clause  = [ who ] op perm ( op perm )*
//! who     = ( "u" | "g" | "o" | "a" )*
//! op      = "+" | "-" | "="
//! perm    = ( "r" | "w" | "x" | "s" | "t" )*
//! ```
//!
//! `who` empty is treated as `a` (all). `s` adds setuid when `who`
//! covers `u`, setgid when it covers `g`, and both when it's `a`/empty.
//! `t` adds the sticky bit (S_ISVTX) regardless of `who` (BSD parity).
//!
//! ## Not implemented (yet)
//!
//! * `X` (conditional execute — only when target is a directory or
//!   any execute bit is already set).
//! * `u`/`g`/`o` as a `perm` value (copy current bits from another
//!   triple).
//!
//! Both are documented BSD extensions but rarely appear in real
//! config files. The unsupported syntax causes [`parse`] to return
//! `None`.

const S_ISUID: u32 = 0o4000;
const S_ISGID: u32 = 0o2000;
const S_ISVTX: u32 = 0o1000;

const S_IRUSR: u32 = 0o400;
const S_IWUSR: u32 = 0o200;
const S_IXUSR: u32 = 0o100;
const S_IRGRP: u32 = 0o040;
const S_IWGRP: u32 = 0o020;
const S_IXGRP: u32 = 0o010;
const S_IROTH: u32 = 0o004;
const S_IWOTH: u32 = 0o002;
const S_IXOTH: u32 = 0o001;

/// One parsed `op perm` step within a clause.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChmodOp {
    /// `+` add bits, `-` clear bits, `=` replace bits.
    pub kind: OpKind,
    /// "Who" mask: which mode bits get cleared by `=` and which are
    /// modified by `+`/`-`. Always a subset of `S_IRWXU|S_IRWXG|
    /// S_IRWXO|S_ISUID|S_ISGID|S_ISVTX`.
    pub who_mask: u32,
    /// Bits to set / clear / replace within `who_mask`.
    pub bits: u32,
}

/// Operation kind in a `ChmodOp`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpKind {
    /// `+` — add `bits` to the current mode.
    Add,
    /// `-` — clear `bits` from the current mode.
    Clear,
    /// `=` — clear `who_mask` from the current mode then set `bits`.
    Set,
}

/// Parse `mode_str` into a sequence of operations. Returns `None`
/// for any malformed input (empty string, unknown character, op
/// without a perm, perm character outside the supported subset).
pub fn parse(mode_str: &[u8]) -> Option<Vec<ChmodOp>> {
    if mode_str.is_empty() {
        return None;
    }

    let mut out = Vec::new();
    let mut i = 0usize;

    loop {
        // Each iteration consumes one clause.
        let mut who_letters = 0u8; // bit 0=u, 1=g, 2=o
        while i < mode_str.len() {
            match mode_str[i] {
                b'u' => who_letters |= 0b001,
                b'g' => who_letters |= 0b010,
                b'o' => who_letters |= 0b100,
                b'a' => who_letters |= 0b111,
                _ => break,
            }
            i += 1;
        }

        // Default `who` = `a` (all), per POSIX. The umask filter
        // documented for default-`a` is intentionally NOT applied
        // here — getmode applies the operations to a caller-
        // supplied mode and the umask isn't part of that contract
        // (chmod(1) handles umask separately).
        if who_letters == 0 {
            who_letters = 0b111;
        }

        // Build the who_mask from the letters.
        let who_mask = who_letters_to_mask(who_letters);

        // Must see at least one op-perm pair per clause.
        let clause_start = i;
        loop {
            let kind = match mode_str.get(i) {
                Some(b'+') => OpKind::Add,
                Some(b'-') => OpKind::Clear,
                Some(b'=') => OpKind::Set,
                _ => break,
            };
            i += 1;

            // Collect perm letters (may be empty — e.g. "u-" clears
            // nothing, but is still a valid op syntactically; we
            // emit a no-op step rather than failing).
            let mut perm_letters = 0u8;
            while i < mode_str.len() {
                match mode_str[i] {
                    b'r' => perm_letters |= 0b00001,
                    b'w' => perm_letters |= 0b00010,
                    b'x' => perm_letters |= 0b00100,
                    b's' => perm_letters |= 0b01000,
                    b't' => perm_letters |= 0b10000,
                    _ => break,
                }
                i += 1;
            }

            let bits = perm_letters_to_bits(perm_letters, who_letters);
            out.push(ChmodOp {
                kind,
                who_mask,
                bits,
            });
        }
        if i == clause_start {
            // No op-perm pair found in this clause — malformed.
            return None;
        }

        // Optional comma separator.
        match mode_str.get(i) {
            Some(b',') => {
                i += 1;
                continue;
            }
            None => break,
            _ => return None, // garbage between clauses
        }
    }

    Some(out)
}

/// Apply the parsed operations to `current_mode`, returning the new
/// mode. Mirrors the BSD `getmode(3)` contract.
pub fn apply(ops: &[ChmodOp], current_mode: u32) -> u32 {
    let mut mode = current_mode;
    for op in ops {
        match op.kind {
            OpKind::Add => mode |= op.bits,
            OpKind::Clear => mode &= !op.bits,
            OpKind::Set => {
                // Clear all bits in who_mask, then set `bits` (which
                // is already filtered to be a subset of who_mask).
                mode = (mode & !op.who_mask) | op.bits;
            }
        }
    }
    mode
}

fn who_letters_to_mask(who: u8) -> u32 {
    let mut m = 0u32;
    if who & 0b001 != 0 {
        m |= S_IRWXU | S_ISUID;
    }
    if who & 0b010 != 0 {
        m |= S_IRWXG | S_ISGID;
    }
    if who & 0b100 != 0 {
        m |= S_IRWXO;
    }
    // Sticky lives outside the "u/g/o" rwx triples; if `a` was
    // implied (all three set), include it in the who_mask so `=`
    // can clear it. BSD `chmod a=rwx` does not clear sticky, but
    // `=` of an explicit `o` does. We follow the explicit case:
    // include sticky only when `o` is in the who set.
    if who & 0b100 != 0 {
        m |= S_ISVTX;
    }
    m
}

const fn s_irwxu() -> u32 {
    S_IRUSR | S_IWUSR | S_IXUSR
}
const fn s_irwxg() -> u32 {
    S_IRGRP | S_IWGRP | S_IXGRP
}
const fn s_irwxo() -> u32 {
    S_IROTH | S_IWOTH | S_IXOTH
}
const S_IRWXU: u32 = s_irwxu();
const S_IRWXG: u32 = s_irwxg();
const S_IRWXO: u32 = s_irwxo();

fn perm_letters_to_bits(perm: u8, who: u8) -> u32 {
    let mut bits = 0u32;
    let r = perm & 0b00001 != 0;
    let w = perm & 0b00010 != 0;
    let x = perm & 0b00100 != 0;
    let s_bit = perm & 0b01000 != 0;
    let t_bit = perm & 0b10000 != 0;

    if who & 0b001 != 0 {
        if r {
            bits |= S_IRUSR;
        }
        if w {
            bits |= S_IWUSR;
        }
        if x {
            bits |= S_IXUSR;
        }
        if s_bit {
            bits |= S_ISUID;
        }
    }
    if who & 0b010 != 0 {
        if r {
            bits |= S_IRGRP;
        }
        if w {
            bits |= S_IWGRP;
        }
        if x {
            bits |= S_IXGRP;
        }
        if s_bit {
            bits |= S_ISGID;
        }
    }
    if who & 0b100 != 0 {
        if r {
            bits |= S_IROTH;
        }
        if w {
            bits |= S_IWOTH;
        }
        if x {
            bits |= S_IXOTH;
        }
        // BSD: `t` set on `o` adds sticky. (chmod also accepts `+t`
        // without a who, treated as `a+t` here, which still ends up
        // including `o` and so still sets S_ISVTX.)
        if t_bit {
            bits |= S_ISVTX;
        }
    }
    bits
}

#[cfg(test)]
mod tests {
    use super::*;

    fn am(ops: &[ChmodOp], mode: u32) -> u32 {
        apply(ops, mode)
    }

    // ---- parse-and-apply: simple cases ----

    #[test]
    fn user_add_execute() {
        let ops = parse(b"u+x").unwrap();
        assert_eq!(am(&ops, 0o644), 0o744);
    }

    #[test]
    fn group_clear_write() {
        let ops = parse(b"g-w").unwrap();
        assert_eq!(am(&ops, 0o664), 0o644);
    }

    #[test]
    fn other_set_read_only() {
        let ops = parse(b"o=r").unwrap();
        // 0o755: clear o-rwx (other = 5 → 0), then set o-r → 4.
        assert_eq!(am(&ops, 0o755), 0o754);
    }

    #[test]
    fn all_set_rwx() {
        let ops = parse(b"a=rwx").unwrap();
        // Clears every rwx triple, then sets every triple to rwx.
        assert_eq!(am(&ops, 0o000), 0o777);
        assert_eq!(am(&ops, 0o644), 0o777);
    }

    #[test]
    fn empty_who_defaults_to_all() {
        // "+x" == "a+x" — adds x to u, g, o.
        let ops = parse(b"+x").unwrap();
        assert_eq!(am(&ops, 0o644), 0o755);
    }

    // ---- comma-chained clauses ----

    #[test]
    fn comma_chained_clauses() {
        let ops = parse(b"u=rwx,g=rx,o=r").unwrap();
        assert_eq!(am(&ops, 0o000), 0o754);
    }

    #[test]
    fn add_then_clear() {
        let ops = parse(b"u+x,g-w").unwrap();
        assert_eq!(am(&ops, 0o664), 0o744);
    }

    // ---- multiple ops in one clause ----

    #[test]
    fn multiple_op_perm_pairs() {
        // "u+x-w" → add x for u, then clear w for u.
        let ops = parse(b"u+x-w").unwrap();
        assert_eq!(am(&ops, 0o644), 0o544);
    }

    // ---- setuid / setgid / sticky ----

    #[test]
    fn add_setuid() {
        let ops = parse(b"u+s").unwrap();
        assert_eq!(am(&ops, 0o0755), 0o4755);
    }

    #[test]
    fn add_setgid() {
        let ops = parse(b"g+s").unwrap();
        assert_eq!(am(&ops, 0o0755), 0o2755);
    }

    #[test]
    fn add_sticky() {
        // Sticky lives in S_ISVTX (0o1000); add via "+t" (default
        // who = a, but only the `o` slice carries sticky).
        let ops = parse(b"+t").unwrap();
        assert_eq!(am(&ops, 0o0755), 0o1755);
    }

    #[test]
    fn user_set_with_setuid() {
        // "u=rwxs": clear u-rwx, then set u-rwx + setuid.
        let ops = parse(b"u=rwxs").unwrap();
        assert_eq!(am(&ops, 0o0044), 0o4744);
    }

    #[test]
    fn clear_setuid() {
        let ops = parse(b"u-s").unwrap();
        assert_eq!(am(&ops, 0o4755), 0o0755);
    }

    // ---- file-type bits preserved (not in any who_mask) ----

    #[test]
    fn high_file_type_bits_are_preserved() {
        // S_IFREG = 0o100000 — outside any who_mask.
        let ops = parse(b"a=rwx").unwrap();
        assert_eq!(am(&ops, 0o100644), 0o100777);
    }

    #[test]
    fn equal_does_not_disturb_special_bits_for_other_who() {
        // "u=rwx" must not touch g/o bits AND must not touch sticky
        // (sticky lives in `o`'s who_mask, not `u`'s).
        let ops = parse(b"u=rwx").unwrap();
        assert_eq!(am(&ops, 0o1644), 0o1744);
    }

    // ---- error / malformed input ----

    #[test]
    fn empty_input_returns_none() {
        assert!(parse(b"").is_none());
    }

    #[test]
    fn unknown_perm_char_returns_none() {
        // 'z' is not a valid perm char.
        assert!(parse(b"u+z").is_none());
    }

    #[test]
    fn unknown_who_char_returns_none() {
        // 'q' is not a valid who char.
        assert!(parse(b"q+x").is_none());
    }

    #[test]
    fn missing_op_returns_none() {
        // "u" alone, no op-perm pair.
        assert!(parse(b"u").is_none());
        assert!(parse(b"a").is_none());
    }

    #[test]
    fn lone_op_with_no_perm_is_a_no_op_clause() {
        // "u-" is a clear with empty perm — emits a no-op step.
        // Some implementations reject this; we accept it (and it
        // changes nothing).
        let ops = parse(b"u-").unwrap();
        assert_eq!(am(&ops, 0o755), 0o755);
        // Verify it produced a single Clear step with bits = 0.
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].kind, OpKind::Clear);
        assert_eq!(ops[0].bits, 0);
    }

    #[test]
    fn trailing_comma_returns_none() {
        // Empty clause after a comma is malformed.
        assert!(parse(b"u+x,").is_none());
    }

    #[test]
    fn garbage_between_clauses_returns_none() {
        assert!(parse(b"u+x;g+x").is_none());
    }

    // ---- octal-style mode strings (NOT supported in this module) ----

    #[test]
    fn octal_strings_are_rejected_by_this_parser() {
        // Real BSD setmode(3) also accepts "0755" as a numeric mode.
        // We delegate the numeric path to the abi shim (it can pre-
        // detect a leading digit and return a single Set op). This
        // module focuses on the symbolic grammar.
        assert!(parse(b"0755").is_none());
        assert!(parse(b"755").is_none());
    }
}
