//! GNU gettext message catalogs: the `.mo` file format, `Plural-Forms`
//! expressions and the order in which locale-name variants are searched.
//!
//! Pure functions over bytes. The ABI decides which files to open, caches the
//! catalogs, and hands C callers pointers into the mapped file.

use core::cmp::Ordering;

/// Magic number of a `.mo` file, read in the byte order it was written in.
const MO_MAGIC: u32 = 0x9504_12de;

/// One `.mo` file: two parallel tables of (length, offset) string
/// descriptors, originals sorted bytewise (as GNU `msgfmt` writes them).
#[derive(Clone, Copy)]
pub struct MoCatalog<'a> {
    data: &'a [u8],
    big_endian: bool,
    count: usize,
    originals: usize,
    translations: usize,
}

impl<'a> MoCatalog<'a> {
    /// Validate the header; `None` for anything that is not a `.mo` file of
    /// major revision 0 or 1 whose descriptor tables lie inside `data`.
    pub fn parse(data: &'a [u8]) -> Option<Self> {
        let magic = u32::from_le_bytes(data.get(0..4)?.try_into().ok()?);
        let big_endian = if magic == MO_MAGIC {
            false
        } else if magic.swap_bytes() == MO_MAGIC {
            true
        } else {
            return None;
        };
        let mut catalog = Self {
            data,
            big_endian,
            count: 0,
            originals: 0,
            translations: 0,
        };
        if catalog.word(4)? >> 16 > 1 {
            return None;
        }
        let count = catalog.word(8)? as usize;
        let table_bytes = count.checked_mul(8)?;
        for table in [catalog.word(12)? as usize, catalog.word(16)? as usize] {
            if table.checked_add(table_bytes)? > data.len() {
                return None;
            }
        }
        catalog.count = count;
        catalog.originals = catalog.word(12)? as usize;
        catalog.translations = catalog.word(16)? as usize;
        Some(catalog)
    }

    fn word(&self, at: usize) -> Option<u32> {
        let bytes: [u8; 4] = self.data.get(at..at.checked_add(4)?)?.try_into().ok()?;
        Some(if self.big_endian {
            u32::from_be_bytes(bytes)
        } else {
            u32::from_le_bytes(bytes)
        })
    }

    /// Entry `index` of a descriptor table as `(offset, len)`. The format
    /// stores a NUL after every string; an entry without one is unusable,
    /// since C callers receive a pointer to it.
    fn string(&self, table: usize, index: usize) -> Option<(usize, usize)> {
        let at = table + 8 * index;
        let len = self.word(at)? as usize;
        let offset = self.word(at + 4)? as usize;
        (self.data.get(offset.checked_add(len)?) == Some(&0)).then_some((offset, len))
    }

    /// The translation of `msgid` as `(offset, len)` into the catalog bytes.
    /// A plural entry's original is `singular\0plural`; it is found by its
    /// singular, and its translation holds the NUL-separated plural forms.
    pub fn find(&self, msgid: &[u8]) -> Option<(usize, usize)> {
        let (mut lo, mut hi) = (0, self.count);
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let (offset, len) = self.string(self.originals, mid)?;
            let original = &self.data[offset..offset + len];
            let key = original
                .iter()
                .position(|&b| b == 0)
                .map_or(original, |nul| &original[..nul]);
            match key.cmp(msgid) {
                Ordering::Less => lo = mid + 1,
                Ordering::Greater => hi = mid,
                Ordering::Equal => return self.string(self.translations, mid),
            }
        }
        None
    }

    /// The whole catalog image that `find` offsets index.
    pub fn bytes(&self) -> &'a [u8] {
        self.data
    }

    /// The header: the translation of the empty msgid.
    pub fn header(&self) -> &'a [u8] {
        self.find(b"")
            .map_or(&[][..], |(offset, len)| &self.data[offset..offset + len])
    }
}

/// `field=` value inside the header (`charset=UTF-8`), up to whitespace or `;`.
fn header_value<'h>(header: &'h [u8], field: &[u8]) -> Option<&'h [u8]> {
    let start = header.windows(field.len()).position(|w| w == field)? + field.len();
    let rest = &header[start..];
    let end = rest
        .iter()
        .position(|&b| b == b';' || b.is_ascii_whitespace())
        .unwrap_or(rest.len());
    Some(&rest[..end])
}

/// The charset a catalog's strings are written in (`Content-Type: ...;
/// charset=UTF-8`), if the header names one.
pub fn header_charset(header: &[u8]) -> Option<&[u8]> {
    header_value(header, b"charset=")
}

/// Codeset names compared as glibc normalizes them: letters lowercased,
/// punctuation dropped (`UTF-8` == `utf8`).
pub fn same_codeset(a: &[u8], b: &[u8]) -> bool {
    let norm = |s: &[u8]| {
        s.iter()
            .filter(|b| b.is_ascii_alphanumeric())
            .map(u8::to_ascii_lowercase)
            .collect::<Vec<u8>>()
    };
    norm(a) == norm(b)
}

/// A catalog's plural rule: how many forms it has and which one `n` selects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluralRule {
    nplurals: u64,
    expr: Expr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Expr {
    N,
    Num(u64),
    Not(Box<Expr>),
    Binary(BinOp, Box<Expr>, Box<Expr>),
    Cond(Box<Expr>, Box<Expr>, Box<Expr>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BinOp {
    Or,
    And,
    Eq,
    Ne,
    Lt,
    Gt,
    Le,
    Ge,
    Add,
    Sub,
    Mul,
    Div,
    Rem,
}

impl BinOp {
    /// Binding strength; larger binds tighter. All are left-associative.
    fn precedence(self) -> u8 {
        match self {
            Self::Or => 1,
            Self::And => 2,
            Self::Eq | Self::Ne => 3,
            Self::Lt | Self::Gt | Self::Le | Self::Ge => 4,
            Self::Add | Self::Sub => 5,
            Self::Mul | Self::Div | Self::Rem => 6,
        }
    }
}

/// Nesting deeper than this is rejected, so a hostile catalog cannot exhaust
/// the stack. Real rules (Arabic's six forms) nest about a dozen levels.
const MAX_DEPTH: usize = 100;

struct Parser<'s> {
    src: &'s [u8],
    pos: usize,
    depth: usize,
}

impl Parser<'_> {
    fn skip_space(&mut self) {
        while self
            .src
            .get(self.pos)
            .is_some_and(|b| b.is_ascii_whitespace() && *b != b'\n')
        {
            self.pos += 1;
        }
    }

    fn peek(&mut self) -> Option<u8> {
        self.skip_space();
        self.src.get(self.pos).copied()
    }

    fn eat(&mut self, token: &[u8]) -> bool {
        self.skip_space();
        if self.src[self.pos..].starts_with(token) {
            self.pos += token.len();
            true
        } else {
            false
        }
    }

    /// The binary operator at the cursor and its token length.
    fn binop(&mut self) -> Option<(BinOp, usize)> {
        self.skip_space();
        Some(match &self.src[self.pos..] {
            [b'|', b'|', ..] => (BinOp::Or, 2),
            [b'&', b'&', ..] => (BinOp::And, 2),
            [b'=', b'=', ..] => (BinOp::Eq, 2),
            [b'!', b'=', ..] => (BinOp::Ne, 2),
            [b'<', b'=', ..] => (BinOp::Le, 2),
            [b'>', b'=', ..] => (BinOp::Ge, 2),
            [b'<', ..] => (BinOp::Lt, 1),
            [b'>', ..] => (BinOp::Gt, 1),
            [b'+', ..] => (BinOp::Add, 1),
            [b'-', ..] => (BinOp::Sub, 1),
            [b'*', ..] => (BinOp::Mul, 1),
            [b'/', ..] => (BinOp::Div, 1),
            [b'%', ..] => (BinOp::Rem, 1),
            _ => return None,
        })
    }

    /// `cond ? a : b`, right-associative, below every binary operator.
    fn conditional(&mut self) -> Option<Expr> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return None;
        }
        let cond = self.binary(1)?;
        let expr = if self.eat(b"?") {
            let then = self.conditional()?;
            if !self.eat(b":") {
                return None;
            }
            let other = self.conditional()?;
            Expr::Cond(Box::new(cond), Box::new(then), Box::new(other))
        } else {
            cond
        };
        self.depth -= 1;
        Some(expr)
    }

    fn binary(&mut self, min_precedence: u8) -> Option<Expr> {
        let mut lhs = self.unary()?;
        while let Some((op, len)) = self.binop() {
            let precedence = op.precedence();
            if precedence < min_precedence {
                break;
            }
            self.pos += len;
            let rhs = self.binary(precedence + 1)?;
            lhs = Expr::Binary(op, Box::new(lhs), Box::new(rhs));
        }
        Some(lhs)
    }

    fn unary(&mut self) -> Option<Expr> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return None;
        }
        let expr = match self.peek()? {
            b'!' if self.src.get(self.pos + 1) != Some(&b'=') => {
                self.pos += 1;
                Expr::Not(Box::new(self.unary()?))
            }
            b'(' => {
                self.pos += 1;
                let inner = self.conditional()?;
                if !self.eat(b")") {
                    return None;
                }
                inner
            }
            b'n' => {
                self.pos += 1;
                Expr::N
            }
            b'0'..=b'9' => {
                let mut value: u64 = 0;
                while let Some(d @ b'0'..=b'9') = self.src.get(self.pos).copied() {
                    value = value.wrapping_mul(10).wrapping_add(u64::from(d - b'0'));
                    self.pos += 1;
                }
                Expr::Num(value)
            }
            _ => return None,
        };
        self.depth -= 1;
        Some(expr)
    }
}

impl Expr {
    fn eval(&self, n: u64) -> u64 {
        match self {
            Self::N => n,
            Self::Num(v) => *v,
            Self::Not(e) => u64::from(e.eval(n) == 0),
            Self::Cond(c, a, b) => {
                if c.eval(n) != 0 {
                    a.eval(n)
                } else {
                    b.eval(n)
                }
            }
            Self::Binary(op, a, b) => {
                let x = a.eval(n);
                // Short-circuit like C, so `n != 0 && 10 / n` cannot divide by zero.
                match op {
                    BinOp::Or => return u64::from(x != 0 || b.eval(n) != 0),
                    BinOp::And => return u64::from(x != 0 && b.eval(n) != 0),
                    _ => {}
                }
                let y = b.eval(n);
                match op {
                    BinOp::Eq => u64::from(x == y),
                    BinOp::Ne => u64::from(x != y),
                    BinOp::Lt => u64::from(x < y),
                    BinOp::Gt => u64::from(x > y),
                    BinOp::Le => u64::from(x <= y),
                    BinOp::Ge => u64::from(x >= y),
                    BinOp::Add => x.wrapping_add(y),
                    BinOp::Sub => x.wrapping_sub(y),
                    BinOp::Mul => x.wrapping_mul(y),
                    // A rule that divides by zero selects form 0.
                    BinOp::Div => x.checked_div(y).unwrap_or(0),
                    BinOp::Rem => x.checked_rem(y).unwrap_or(0),
                    BinOp::Or | BinOp::And => unreachable!(),
                }
            }
        }
    }
}

impl Default for PluralRule {
    /// The Germanic rule gettext assumes when a catalog declares none:
    /// two forms, the singular for exactly one.
    fn default() -> Self {
        Self {
            nplurals: 2,
            expr: Expr::Binary(BinOp::Ne, Box::new(Expr::N), Box::new(Expr::Num(1))),
        }
    }
}

impl PluralRule {
    /// The rule a catalog header declares (`Plural-Forms: nplurals=3;
    /// plural=...;`), or the default when it is absent or malformed.
    pub fn from_header(header: &[u8]) -> Self {
        Self::parse_header(header).unwrap_or_default()
    }

    fn parse_header(header: &[u8]) -> Option<Self> {
        let find = |key: &[u8]| {
            header
                .windows(key.len())
                .position(|w| w == key)
                .map(|at| at + key.len())
        };
        let mut nplurals_at = find(b"nplurals=")?;
        while header.get(nplurals_at).is_some_and(u8::is_ascii_whitespace) {
            nplurals_at += 1;
        }
        let digits = header[nplurals_at..]
            .iter()
            .take_while(|b| b.is_ascii_digit())
            .count();
        if digits == 0 {
            return None;
        }
        let nplurals = header[nplurals_at..nplurals_at + digits]
            .iter()
            .fold(0u64, |v, d| {
                v.wrapping_mul(10).wrapping_add(u64::from(d - b'0'))
            });
        // "plural=" cannot match inside "nplurals=": the 's' intervenes.
        let start = find(b"plural=")?;
        let end = header[start..]
            .iter()
            .position(|&b| b == b';' || b == b'\n')
            .map_or(header.len(), |len| start + len);
        let mut parser = Parser {
            src: &header[start..end],
            pos: 0,
            depth: 0,
        };
        let expr = parser.conditional()?;
        parser.skip_space();
        (parser.pos == parser.src.len()).then_some(Self { nplurals, expr })
    }

    /// The plural form `n` selects; an out-of-range result selects form 0.
    pub fn index(&self, n: u64) -> usize {
        let index = self.expr.eval(n);
        if index >= self.nplurals {
            0
        } else {
            index as usize
        }
    }
}

/// Form `index` of a plural translation (`form0\0form1\0...`) as an offset
/// into it, or `None` when the translation has fewer forms.
pub fn plural_form(translation: &[u8], index: usize) -> Option<usize> {
    let mut offset = 0;
    for _ in 0..index {
        offset += translation[offset..].iter().position(|&b| b == 0)? + 1;
        if offset >= translation.len() {
            return None;
        }
    }
    Some(offset)
}

/// Whether a locale name selects untranslated messages: `C`, `POSIX`, or a
/// `C.<codeset>` variant such as `C.UTF-8`.
pub fn is_c_locale(name: &[u8]) -> bool {
    name == b"C" || name == b"POSIX" || name.starts_with(b"C.")
}

/// The directory names searched for locale `name`, most specific first:
/// `en_US.UTF-8` gives `en_US.UTF-8`, `en_US.utf8`, `en_US`, `en.UTF-8`,
/// `en.utf8`, `en` -- the order glibc 2.43 opens them in (strace). The
/// normalized codeset (alphanumerics, lowercased, `iso` before an all-digit
/// name) is tried only when it differs from the codeset as written.
pub fn locale_variants(name: &[u8]) -> Vec<Vec<u8>> {
    let split =
        |s: &[u8], stops: &[u8]| s.iter().position(|b| stops.contains(b)).unwrap_or(s.len());
    let language_end = split(name, b"_.@");
    let language = &name[..language_end];
    let mut rest = &name[language_end..];
    let territory_end = if rest.first() == Some(&b'_') {
        split(rest, b".@")
    } else {
        0
    };
    let territory = &rest[..territory_end];
    rest = &rest[territory_end..];
    let codeset_end = if rest.first() == Some(&b'.') {
        split(rest, b"@")
    } else {
        0
    };
    let codeset = &rest[..codeset_end];
    let modifier = &rest[codeset_end..];

    let mut normalized = Vec::new();
    if codeset.len() > 1 {
        let body = &codeset[1..];
        normalized.push(b'.');
        if body.iter().all(|b| !b.is_ascii_alphabetic()) {
            normalized.extend_from_slice(b"iso");
        }
        normalized.extend(
            body.iter()
                .filter(|b| b.is_ascii_alphanumeric())
                .map(u8::to_ascii_lowercase),
        );
    }

    const NORM: u8 = 1;
    const CODESET: u8 = 2;
    const TERRITORY: u8 = 4;
    const MODIFIER: u8 = 8;
    let mut mask = 0;
    if !territory.is_empty() {
        mask |= TERRITORY;
    }
    if codeset.len() > 1 {
        mask |= CODESET;
        if normalized != codeset {
            mask |= NORM;
        }
    }
    if !modifier.is_empty() {
        mask |= MODIFIER;
    }
    let mut variants = Vec::new();
    for bits in (0..=mask).rev() {
        if bits & !mask != 0 || (bits & CODESET != 0 && bits & NORM != 0) {
            continue;
        }
        let mut variant = language.to_vec();
        if bits & TERRITORY != 0 {
            variant.extend_from_slice(territory);
        }
        if bits & CODESET != 0 {
            variant.extend_from_slice(codeset);
        }
        if bits & NORM != 0 {
            variant.extend_from_slice(&normalized);
        }
        if bits & MODIFIER != 0 {
            variant.extend_from_slice(modifier);
        }
        variants.push(variant);
    }
    variants
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A little-endian `.mo` image with `entries` (sorted here, as msgfmt does).
    fn build_mo(entries: &[(&[u8], &[u8])]) -> Vec<u8> {
        let mut entries = entries.to_vec();
        entries.sort_by(|a, b| a.0.cmp(b.0));
        let n = entries.len();
        let originals = 28;
        let translations = originals + 8 * n;
        let mut strings = translations + 8 * n;
        let mut out = Vec::new();
        for word in [
            MO_MAGIC,
            0,
            n as u32,
            originals as u32,
            translations as u32,
            0,
            0,
        ] {
            out.extend_from_slice(&word.to_le_bytes());
        }
        let mut blob = Vec::new();
        let originals_then_translations = entries
            .iter()
            .map(|e| e.0)
            .chain(entries.iter().map(|e| e.1));
        for s in originals_then_translations {
            out.extend_from_slice(&(s.len() as u32).to_le_bytes());
            out.extend_from_slice(&(strings as u32).to_le_bytes());
            strings += s.len() + 1;
            blob.extend_from_slice(s);
            blob.push(0);
        }
        out.extend_from_slice(&blob);
        out
    }

    fn text(data: &[u8], found: Option<(usize, usize)>) -> Option<&[u8]> {
        found.map(|(offset, len)| &data[offset..offset + len])
    }

    #[test]
    fn finds_entries_by_singular_and_rejects_non_catalogs() {
        let mo = build_mo(&[
            (b"", b"Content-Type: text/plain; charset=UTF-8\nPlural-Forms: nplurals=2; plural=(n != 1);\n"),
            (b"hello", b"bonjour"),
            (b"%d file\0%d files", b"%d fichier\0%d fichiers"),
            (b"zebra", b"z\xc3\xa8bre"),
        ]);
        let cat = MoCatalog::parse(&mo).expect("valid catalog");
        assert_eq!(text(&mo, cat.find(b"hello")), Some(&b"bonjour"[..]));
        assert_eq!(text(&mo, cat.find(b"zebra")), Some(&b"z\xc3\xa8bre"[..]));
        assert_eq!(
            text(&mo, cat.find(b"%d file")),
            Some(&b"%d fichier\0%d fichiers"[..])
        );
        assert_eq!(cat.find(b"%d files"), None);
        assert_eq!(cat.find(b"hell"), None);
        assert_eq!(cat.find(b"absent"), None);
        assert_eq!(header_charset(cat.header()), Some(&b"UTF-8"[..]));

        // The same catalog written big-endian: header and both descriptor tables.
        let mut big = mo.clone();
        for word in big[..28 + 16 * 4].as_chunks_mut::<4>().0 {
            word.reverse();
        }
        let big_cat = MoCatalog::parse(&big).expect("swapped magic selects big-endian");
        assert_eq!(text(&big, big_cat.find(b"hello")), Some(&b"bonjour"[..]));
        assert!(MoCatalog::parse(&mo[..20]).is_none());
        assert!(MoCatalog::parse(b"not a catalog at all, nothing here").is_none());
        // Descriptor table past the end of the file.
        let mut truncated = mo.clone();
        truncated.truncate(40);
        assert!(MoCatalog::parse(&truncated).is_none());
    }

    #[test]
    fn entry_without_trailing_nul_is_not_returned() {
        let mut mo = build_mo(&[(b"a", b"x")]);
        let last = mo.len() - 1;
        mo[last] = b'!';
        let cat = MoCatalog::parse(&mo).unwrap();
        assert_eq!(cat.find(b"a"), None);
    }

    fn rule(header: &str) -> PluralRule {
        PluralRule::parse_header(header.as_bytes()).expect(header)
    }

    #[test]
    fn plural_rules_of_real_languages() {
        let polish = rule(
            "Plural-Forms: nplurals=3; plural=(n==1 ? 0 : n%10>=2 && n%10<=4 && (n%100<10 || n%100>=20) ? 1 : 2);",
        );
        let got: Vec<usize> = [0, 1, 2, 4, 5, 12, 21, 22, 25, 112, 122]
            .iter()
            .map(|&n| polish.index(n))
            .collect();
        assert_eq!(got, [2, 0, 1, 1, 2, 2, 2, 1, 2, 2, 1]);

        let arabic = rule(
            "nplurals=6; plural=n==0 ? 0 : n==1 ? 1 : n==2 ? 2 : n%100>=3 && n%100<=10 ? 3 : n%100>=11 ? 4 : 5;",
        );
        let got: Vec<usize> = [0, 1, 2, 3, 10, 11, 99, 100, 102]
            .iter()
            .map(|&n| arabic.index(n))
            .collect();
        assert_eq!(got, [0, 1, 2, 3, 3, 4, 4, 5, 5]);

        let french = rule("nplurals=2; plural=(n > 1);");
        assert_eq!(
            (french.index(0), french.index(1), french.index(2)),
            (0, 0, 1)
        );
        let japanese = rule("nplurals=1; plural=0;");
        assert_eq!(japanese.index(7), 0);
        let not = rule("nplurals=2; plural=!(n == 1);");
        assert_eq!((not.index(1), not.index(3)), (0, 1));
        let arithmetic = rule("nplurals=9; plural=n*2-1+4/2;");
        assert_eq!(arithmetic.index(3), 7);
    }

    #[test]
    fn malformed_or_absent_rules_fall_back_to_germanic() {
        let default = PluralRule::default();
        for header in [
            "",
            "Plural-Forms: nplurals=; plural=n;",
            "Plural-Forms: nplurals=2; plural=n !== 1;",
            "Plural-Forms: nplurals=2; plural=(n != 1;",
            "Plural-Forms: nplurals=2; plural=x;",
            "Plural-Forms: nplurals=2;",
        ] {
            assert_eq!(
                PluralRule::from_header(header.as_bytes()),
                default,
                "{header:?}"
            );
        }
        assert_eq!(
            (default.index(0), default.index(1), default.index(2)),
            (1, 0, 1)
        );
        // Out-of-range results and division by zero select form 0.
        assert_eq!(rule("nplurals=2; plural=n;").index(5), 0);
        assert_eq!(rule("nplurals=3; plural=10/n;").index(0), 0);
        assert_eq!(rule("nplurals=3; plural=n != 0 && 4 % n;").index(0), 0);
        // Hostile nesting is rejected, not a stack overflow.
        let deep = format!(
            "nplurals=2; plural={}n{};",
            "(".repeat(5000),
            ")".repeat(5000)
        );
        assert_eq!(PluralRule::from_header(deep.as_bytes()), default);
    }

    #[test]
    fn plural_forms_are_selected_by_index() {
        let t = b"one\0few\0many";
        assert_eq!(plural_form(t, 0), Some(0));
        assert_eq!(plural_form(t, 1), Some(4));
        assert_eq!(plural_form(t, 2), Some(8));
        assert_eq!(plural_form(t, 3), None);
        assert_eq!(plural_form(b"only", 1), None);
    }

    fn names(variants: Vec<Vec<u8>>) -> Vec<String> {
        variants
            .into_iter()
            .map(|v| String::from_utf8(v).unwrap())
            .collect()
    }

    #[test]
    fn locale_variants_match_glibc_search_order() {
        assert_eq!(
            names(locale_variants(b"en_US.UTF-8")),
            [
                "en_US.UTF-8",
                "en_US.utf8",
                "en_US",
                "en.UTF-8",
                "en.utf8",
                "en"
            ]
        );
        assert_eq!(names(locale_variants(b"en_GB")), ["en_GB", "en"]);
        assert_eq!(names(locale_variants(b"fr")), ["fr"]);
        // An already-normalized codeset is not tried twice.
        assert_eq!(
            names(locale_variants(b"de_DE.utf8")),
            ["de_DE.utf8", "de_DE", "de.utf8", "de"]
        );
        assert_eq!(
            names(locale_variants(b"sr_RS.UTF-8@latin")),
            [
                "sr_RS.UTF-8@latin",
                "sr_RS.utf8@latin",
                "sr_RS@latin",
                "sr.UTF-8@latin",
                "sr.utf8@latin",
                "sr@latin",
                "sr_RS.UTF-8",
                "sr_RS.utf8",
                "sr_RS",
                "sr.UTF-8",
                "sr.utf8",
                "sr",
            ]
        );
        assert_eq!(
            names(locale_variants(b"pl_PL.8859-2")),
            [
                "pl_PL.8859-2",
                "pl_PL.iso88592",
                "pl_PL",
                "pl.8859-2",
                "pl.iso88592",
                "pl"
            ]
        );
    }

    #[test]
    fn c_locales_and_codesets() {
        assert!(is_c_locale(b"C") && is_c_locale(b"POSIX") && is_c_locale(b"C.UTF-8"));
        assert!(!is_c_locale(b"en_US.UTF-8") && !is_c_locale(b"Ca"));
        assert!(same_codeset(b"UTF-8", b"utf8"));
        assert!(!same_codeset(b"UTF-8", b"ISO-8859-1"));
    }
}
