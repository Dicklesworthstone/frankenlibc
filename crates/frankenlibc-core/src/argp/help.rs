//! GNU argp help and usage formatting.
//!
//! Output must be byte-identical to glibc's, including its line-wrapping
//! stream's behaviour on overlong words, so the text stream here ([`Fmt`])
//! models that stream's observable semantics precisely: text is appended to a
//! buffer and wrapped *lazily*, only when the column is queried, a margin
//! changes, or the buffer must make room; `lmargin` pads the start of a line
//! the stream believes is fresh; `wmargin` indents continuation lines; a word
//! too long for the line stays on an overlong line of its own (and, when it
//! ends the buffered text, leaves the stream believing it is at column 0).
//!
//! The option layout (the "HOL": help option list) is built from the argp
//! tree, sorted, and rendered with glibc's column rules. Everything here is
//! verified against glibc by `tests/integration/fixture_argp.c help`.

/// Option flags (as in `struct argp_option`).
pub const OPTION_ARG_OPTIONAL: i32 = 0x1;
pub const OPTION_HIDDEN: i32 = 0x2;
pub const OPTION_ALIAS: i32 = 0x4;
pub const OPTION_DOC: i32 = 0x8;
pub const OPTION_NO_USAGE: i32 = 0x10;

/// `argp_help` flags.
pub const HELP_USAGE: u32 = 0x01;
pub const HELP_SHORT_USAGE: u32 = 0x02;
pub const HELP_SEE: u32 = 0x04;
pub const HELP_LONG: u32 = 0x08;
pub const HELP_PRE_DOC: u32 = 0x10;
pub const HELP_POST_DOC: u32 = 0x20;
pub const HELP_BUG_ADDR: u32 = 0x40;

/// Help-filter keys.
pub const KEY_HELP_PRE_DOC: i32 = 0x200_0001;
pub const KEY_HELP_POST_DOC: i32 = 0x200_0002;
pub const KEY_HELP_HEADER: i32 = 0x200_0003;
pub const KEY_HELP_EXTRA: i32 = 0x200_0004;
pub const KEY_HELP_DUP_ARGS_NOTE: i32 = 0x200_0005;
pub const KEY_HELP_ARGS_DOC: i32 = 0x200_0006;

/// One `struct argp_option`.
#[derive(Clone, Debug, Default)]
pub struct HelpOption {
    pub name: Option<Vec<u8>>,
    pub key: i32,
    pub arg: Option<Vec<u8>>,
    pub flags: i32,
    pub doc: Option<Vec<u8>>,
    pub group: i32,
}

/// One `struct argp` (with its children). `id` identifies it to the filter.
#[derive(Clone, Debug, Default)]
pub struct HelpArgp {
    pub id: usize,
    pub options: Vec<HelpOption>,
    pub args_doc: Option<Vec<u8>>,
    pub doc: Option<Vec<u8>>,
    pub children: Vec<HelpChild>,
    pub has_filter: bool,
}

/// One `struct argp_child`.
#[derive(Clone, Debug, Default)]
pub struct HelpChild {
    pub argp: HelpArgp,
    pub header: Option<Vec<u8>>,
    pub group: i32,
}

/// The argp `help_filter` callback. `text` is the unfiltered text; the
/// return value replaces it (`None` suppresses it).
pub trait HelpFilter {
    fn filter(&mut self, argp_id: usize, key: i32, text: Option<&[u8]>) -> Option<Vec<u8>>;
}

/// No filtering at all.
pub struct NoFilter;
impl HelpFilter for NoFilter {
    fn filter(&mut self, _: usize, _: i32, text: Option<&[u8]>) -> Option<Vec<u8>> {
        text.map(<[u8]>::to_vec)
    }
}

/// User-tunable layout parameters (`ARGP_HELP_FMT`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Uparams {
    pub short_opt_col: i32,
    pub long_opt_col: i32,
    pub doc_opt_col: i32,
    pub opt_doc_col: i32,
    pub header_col: i32,
    pub usage_indent: i32,
    pub rmargin: i32,
    pub dup_args: bool,
    pub dup_args_note: bool,
}

impl Default for Uparams {
    fn default() -> Self {
        Self {
            short_opt_col: 2,
            long_opt_col: 6,
            doc_opt_col: 2,
            opt_doc_col: 29,
            header_col: 1,
            usage_indent: 12,
            rmargin: 79,
            dup_args: false,
            dup_args_note: true,
        }
    }
}

const UPARAM_NAMES: [(&[u8], bool); 9] = [
    (b"dup-args", true),
    (b"dup-args-note", true),
    (b"short-opt-col", false),
    (b"long-opt-col", false),
    (b"doc-opt-col", false),
    (b"opt-doc-col", false),
    (b"header-col", false),
    (b"usage-indent", false),
    (b"rmargin", false),
];

impl Uparams {
    fn slot(&mut self, name: &[u8]) -> Option<UparamSlot<'_>> {
        Some(match name {
            b"dup-args" => UparamSlot::Bool(&mut self.dup_args),
            b"dup-args-note" => UparamSlot::Bool(&mut self.dup_args_note),
            b"short-opt-col" => UparamSlot::Int(&mut self.short_opt_col),
            b"long-opt-col" => UparamSlot::Int(&mut self.long_opt_col),
            b"doc-opt-col" => UparamSlot::Int(&mut self.doc_opt_col),
            b"opt-doc-col" => UparamSlot::Int(&mut self.opt_doc_col),
            b"header-col" => UparamSlot::Int(&mut self.header_col),
            b"usage-indent" => UparamSlot::Int(&mut self.usage_indent),
            b"rmargin" => UparamSlot::Int(&mut self.rmargin),
            _ => return None,
        })
    }

    /// Apply an `ARGP_HELP_FMT` value on top of `self`. Returns the
    /// diagnostics argp prints (via `argp_failure`, without the program-name
    /// prefix). An out-of-range column leaves `self` unchanged.
    pub fn apply_help_fmt(&mut self, var: &[u8]) -> Vec<Vec<u8>> {
        let mut diags = Vec::new();
        let mut new = *self;
        let mut i = 0;
        let at = |i: usize| var.get(i).copied().unwrap_or(0);
        while i < var.len() {
            while at(i).is_ascii_whitespace() {
                i += 1;
            }
            if i >= var.len() {
                break;
            }
            if at(i).is_ascii_alphabetic() {
                let start = i;
                let mut a = i;
                while at(a).is_ascii_alphanumeric() || at(a) == b'-' || at(a) == b'_' {
                    a += 1;
                }
                let mut name = &var[start..a];
                while at(a).is_ascii_whitespace() {
                    a += 1;
                }
                let mut unspec = false;
                let mut val = 0i32;
                if at(a) == 0 || at(a) == b',' {
                    unspec = true;
                } else if at(a) == b'=' {
                    a += 1;
                    while at(a).is_ascii_whitespace() {
                        a += 1;
                    }
                }
                if unspec {
                    if name.starts_with(b"no-") {
                        name = &name[3..];
                        val = 0;
                    } else {
                        val = 1;
                    }
                } else if at(a).is_ascii_digit() {
                    while at(a).is_ascii_digit() {
                        val = val.wrapping_mul(10).wrapping_add(i32::from(at(a) - b'0'));
                        a += 1;
                    }
                    while at(a).is_ascii_whitespace() {
                        a += 1;
                    }
                }
                match UPARAM_NAMES.iter().find(|(n, _)| *n == name) {
                    Some((_, is_bool)) => {
                        if unspec && !is_bool {
                            let mut m = name.to_vec();
                            m.extend_from_slice(b": ARGP_HELP_FMT parameter requires a value");
                            diags.push(m);
                        } else {
                            match new.slot(name) {
                                Some(UparamSlot::Bool(b)) => *b = val != 0,
                                Some(UparamSlot::Int(v)) => *v = val,
                                None => {}
                            }
                        }
                    }
                    None => {
                        let mut m = name.to_vec();
                        m.extend_from_slice(b": Unknown ARGP_HELP_FMT parameter");
                        diags.push(m);
                    }
                }
                i = a;
                if at(i) == b',' {
                    i += 1;
                }
            } else {
                let mut m = b"Garbage in ARGP_HELP_FMT: ".to_vec();
                m.extend_from_slice(&var[i..]);
                diags.push(m);
                break;
            }
        }
        for (name, is_bool) in UPARAM_NAMES {
            if is_bool || name == b"rmargin" {
                continue;
            }
            let rmargin = new.rmargin;
            if let Some(UparamSlot::Int(v)) = new.slot(name)
                && *v >= rmargin
            {
                let mut m = b"ARGP_HELP_FMT: rmargin value is less than or equal to ".to_vec();
                m.extend_from_slice(name);
                diags.push(m);
                return diags;
            }
        }
        *self = new;
        diags
    }
}

enum UparamSlot<'a> {
    Bool(&'a mut bool),
    Int(&'a mut i32),
}

// ---------------------------------------------------------------------------
// The line-wrapping text stream.
// ---------------------------------------------------------------------------

const FMT_INIT_BUF: usize = 200;
const FMT_PRINTF_GUESS: usize = 150;

fn is_blank(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

/// Lazily wrapping output stream (see the module docs).
pub struct Fmt {
    /// Text already handed to the underlying stream.
    pub out: Vec<u8>,
    buf: Vec<u8>,
    cap: usize,
    point_offs: usize,
    point_col: isize,
    lmargin: usize,
    rmargin: usize,
    wmargin: isize,
}

impl Fmt {
    pub fn new(rmargin: usize) -> Self {
        Self {
            out: Vec::new(),
            buf: Vec::new(),
            cap: FMT_INIT_BUF,
            point_offs: 0,
            point_col: 0,
            lmargin: 0,
            rmargin,
            wmargin: 0,
        }
    }

    /// Make room for `amount` more bytes: when short, wrap and flush the
    /// buffer, growing it if a single write needs more than its capacity.
    fn ensure(&mut self, amount: usize) {
        if self.cap - self.buf.len() >= amount {
            return;
        }
        self.update();
        self.out.extend_from_slice(&self.buf);
        self.buf.clear();
        self.point_offs = 0;
        if self.cap < amount {
            self.cap += amount;
        }
    }

    pub fn putc(&mut self, c: u8) {
        if self.buf.len() >= self.cap {
            self.ensure(1);
        }
        self.buf.push(c);
    }

    pub fn write(&mut self, s: &[u8]) {
        if self.buf.len() + s.len() > self.cap {
            self.ensure(s.len());
        }
        self.buf.extend_from_slice(s);
    }

    /// Formatted output: reserves the printf size guess first (which can
    /// flush), exactly like the C stream's printf.
    pub fn printf(&mut self, s: &[u8]) {
        let mut guess = FMT_PRINTF_GUESS;
        loop {
            self.ensure(guess);
            let avail = self.cap - self.buf.len();
            if s.len() < avail {
                break;
            }
            guess = s.len() + 1;
        }
        self.buf.extend_from_slice(s);
    }

    pub fn point(&mut self) -> usize {
        if self.buf.len() > self.point_offs {
            self.update();
        }
        self.point_col.max(0) as usize
    }

    pub fn lmargin(&self) -> usize {
        self.lmargin
    }

    pub fn set_lmargin(&mut self, lm: usize) -> usize {
        if self.buf.len() > self.point_offs {
            self.update();
        }
        std::mem::replace(&mut self.lmargin, lm)
    }

    pub fn set_wmargin(&mut self, wm: isize) -> isize {
        if self.buf.len() > self.point_offs {
            self.update();
        }
        std::mem::replace(&mut self.wmargin, wm)
    }

    pub fn wmargin(&self) -> isize {
        self.wmargin
    }

    /// Flush everything and return the produced bytes.
    pub fn finish(mut self) -> Vec<u8> {
        self.update();
        self.out.extend_from_slice(&self.buf);
        self.out
    }

    /// Wrap the not-yet-scanned part of the buffer.
    fn update(&mut self) {
        let mut buf = self.point_offs;
        while buf < self.buf.len() {
            if self.point_col == 0 && self.lmargin != 0 {
                let pad = self.lmargin;
                if self.buf.len() + pad < self.cap {
                    self.buf.splice(buf..buf, std::iter::repeat_n(b' ', pad));
                    buf += pad;
                } else {
                    self.out.extend(std::iter::repeat_n(b' ', pad));
                }
                self.point_col = pad as isize;
            }

            let mut len = self.buf.len() - buf;
            let nl_found = self.buf[buf..].iter().position(|&b| b == b'\n').map(|i| buf + i);
            if self.point_col < 0 {
                self.point_col = 0;
            }
            let mut nl = match nl_found {
                None => {
                    if (self.point_col as usize) + len < self.rmargin {
                        self.point_col += len as isize;
                        break;
                    }
                    self.buf.len()
                }
                Some(nl) => {
                    if (self.point_col as usize) + (nl - buf) < self.rmargin {
                        self.point_col = 0;
                        buf = nl + 1;
                        continue;
                    }
                    nl
                }
            };

            // The line is too long.
            let r = self.rmargin as isize - 1;
            if self.wmargin < 0 {
                // Truncate instead of wrapping.
                let cut = buf as isize + (r - self.point_col);
                if nl < self.buf.len() {
                    let cut = cut.max(buf as isize) as usize;
                    self.buf.drain(cut..nl);
                    self.point_col = 0;
                    buf += r as usize + 1;
                } else {
                    self.point_col += len as isize;
                    let excess = (self.point_col - r).max(0) as usize;
                    let keep = self.buf.len().saturating_sub(excess);
                    self.buf.truncate(keep);
                    break;
                }
                continue;
            }

            let wmargin = self.wmargin as usize;
            // Scan back from just past the margin for a word start.
            let start = buf as isize + (r + 1 - self.point_col);
            let mut p = start;
            while p >= buf as isize && !is_blank(self.byte(p)) {
                p -= 1;
            }
            let mut nextline = (p + 1) as usize;
            if nextline > buf {
                // Swallow separating blanks; the newline replaces the first.
                if p >= buf as isize {
                    loop {
                        p -= 1;
                        if !(p >= buf as isize && is_blank(self.byte(p))) {
                            break;
                        }
                    }
                }
                nl = (p + 1) as usize;
            } else {
                // One word wider than the line: an overlong line of its own.
                let mut q = start;
                if (q as usize) < nl {
                    loop {
                        q += 1;
                        if !((q as usize) < nl && !is_blank(self.byte(q))) {
                            break;
                        }
                    }
                }
                if q as usize == nl {
                    self.point_col = 0;
                    buf = nl + 1;
                    continue;
                }
                nl = q as usize;
                loop {
                    q += 1;
                    if !is_blank(self.byte(q)) {
                        break;
                    }
                }
                nextline = q as usize;
            }

            let end_of_buffer = nextline == buf + len + 1;
            let mut nl = nl;
            if (if end_of_buffer {
                self.cap.saturating_sub(nl) < wmargin + 1
            } else {
                nextline.saturating_sub(nl + 1) < wmargin
            }) && self.buf.len() > nextline
            {
                if self.cap - self.buf.len() > wmargin + 1 {
                    // Open a gap for the margin.
                    let gap = nl + 1 + wmargin - nextline;
                    self.buf.splice(nextline..nextline, std::iter::repeat_n(0u8, gap));
                    nextline = nl + 1 + wmargin;
                    len = self.buf.len() - buf;
                    self.buf[nl] = b'\n';
                    nl += 1;
                } else {
                    // Emit the finished part to make room.
                    self.out.extend_from_slice(&self.buf[..nl]);
                    self.out.push(b'\n');
                    len += buf;
                    self.buf.drain(..nextline.min(self.buf.len()));
                    let _ = len;
                    buf = 0;
                    nl = 0;
                    nextline = 0;
                    len = self.buf.len();
                }
            } else {
                self.set_byte(nl, b'\n');
                nl += 1;
            }

            let end_of_buffer = nextline == buf + len + 1;
            if nextline.saturating_sub(nl) >= wmargin
                || (end_of_buffer && self.cap.saturating_sub(nextline) >= wmargin)
            {
                for _ in 0..wmargin {
                    self.set_byte(nl, b' ');
                    nl += 1;
                }
            } else {
                self.out.extend(std::iter::repeat_n(b' ', wmargin));
            }

            // Close the gap between the new line start and the next text.
            let tail_end = (buf + len).min(self.buf.len());
            if nl < nextline && nextline <= tail_end {
                self.buf.drain(nl..nextline);
            } else if nl > self.buf.len() {
                self.buf.resize(nl, b' ');
            }
            buf = nl;
            self.point_col = if wmargin != 0 { wmargin as isize } else { -1 };
        }
        self.point_offs = self.buf.len();
    }

    fn byte(&self, i: isize) -> u8 {
        if i < 0 {
            return 0;
        }
        self.buf.get(i as usize).copied().unwrap_or(0)
    }

    fn set_byte(&mut self, i: usize, b: u8) {
        if i < self.buf.len() {
            self.buf[i] = b;
        } else {
            self.buf.resize(i, b' ');
            self.buf.push(b);
        }
    }
}

// ---------------------------------------------------------------------------
// The help option list.
// ---------------------------------------------------------------------------

/// A group of child options under a header (`argp_child` with a header or
/// group).
struct Cluster {
    header: Option<Vec<u8>>,
    index: usize,
    group: i32,
    parent: Option<usize>,
    argp_id: usize,
    has_filter: bool,
    depth: usize,
}

/// One help entry: an option and its aliases.
struct Entry {
    opts: Vec<HelpOption>,
    /// The short options this entry owns (not shadowed by earlier entries).
    shorts: Vec<u8>,
    group: i32,
    cluster: Option<usize>,
    argp_id: usize,
    has_filter: bool,
    ord: usize,
}

fn oshort(o: &HelpOption) -> bool {
    o.flags & OPTION_DOC == 0 && (0x20..0x7f).contains(&o.key)
}
fn ovisible(o: &HelpOption) -> bool {
    o.flags & OPTION_HIDDEN == 0
}
fn odoc(o: &HelpOption) -> bool {
    o.flags & OPTION_DOC != 0
}
fn oalias(o: &HelpOption) -> bool {
    o.flags & OPTION_ALIAS != 0
}

struct Hol {
    entries: Vec<Entry>,
    clusters: Vec<Cluster>,
    shorts: Vec<u8>,
}

impl Hol {
    fn build(argp: &HelpArgp) -> Self {
        let mut hol = Hol {
            entries: Vec::new(),
            clusters: Vec::new(),
            shorts: Vec::new(),
        };
        hol.add_argp(argp, None);
        for (i, e) in hol.entries.iter_mut().enumerate() {
            e.ord = i;
        }
        hol
    }

    fn add_argp(&mut self, argp: &HelpArgp, cluster: Option<usize>) {
        let mut cur_group = 0;
        let mut i = 0;
        while i < argp.options.len() {
            let first = &argp.options[i];
            cur_group = if first.group != 0 {
                first.group
            } else if first.name.is_none() && first.key == 0 {
                cur_group + 1
            } else {
                cur_group
            };
            let mut opts = Vec::new();
            let mut shorts = Vec::new();
            loop {
                let o = &argp.options[i];
                if oshort(o) && !self.shorts.contains(&(o.key as u8)) {
                    self.shorts.push(o.key as u8);
                    shorts.push(o.key as u8);
                }
                opts.push(o.clone());
                i += 1;
                if i >= argp.options.len() || !oalias(&argp.options[i]) {
                    break;
                }
            }
            self.entries.push(Entry {
                opts,
                shorts,
                group: cur_group,
                cluster,
                argp_id: argp.id,
                has_filter: argp.has_filter,
                ord: 0,
            });
        }
        for (index, child) in argp.children.iter().enumerate() {
            let child_cluster = if child.group != 0 || child.header.is_some() {
                let depth = cluster.map_or(0, |c| self.clusters[c].depth + 1);
                self.clusters.push(Cluster {
                    header: child.header.clone(),
                    index,
                    group: child.group,
                    parent: cluster,
                    argp_id: argp.id,
                    has_filter: argp.has_filter,
                    depth,
                });
                Some(self.clusters.len() - 1)
            } else {
                cluster
            };
            self.add_argp(&child.argp, child_cluster);
        }
    }

    fn set_group(&mut self, name: &[u8], group: i32) {
        if let Some(e) = self
            .entries
            .iter_mut()
            .find(|e| e.opts.iter().any(|o| o.name.as_deref() == Some(name)))
        {
            e.group = group;
        }
    }

    fn cluster_base(&self, mut c: usize) -> usize {
        while let Some(p) = self.clusters[c].parent {
            c = p;
        }
        c
    }

    fn cluster_is_child(&self, mut c: Option<usize>, ancestor: usize) -> bool {
        while let Some(x) = c {
            if x == ancestor {
                return true;
            }
            c = self.clusters[x].parent;
        }
        false
    }

    fn cluster_cmp(&self, mut a: usize, mut b: usize) -> std::cmp::Ordering {
        use std::cmp::Ordering as O;
        // Bring both to the same depth, then walk up to siblings.
        while self.clusters[a].depth > self.clusters[b].depth {
            let p = self.clusters[a].parent.expect("depth");
            if p == b {
                return O::Greater;
            }
            a = p;
        }
        while self.clusters[b].depth > self.clusters[a].depth {
            let p = self.clusters[b].parent.expect("depth");
            if p == a {
                return O::Less;
            }
            b = p;
        }
        while self.clusters[a].parent != self.clusters[b].parent {
            a = self.clusters[a].parent.expect("depth");
            b = self.clusters[b].parent.expect("depth");
        }
        group_cmp(self.clusters[a].group, self.clusters[b].group)
            .then(self.clusters[a].index.cmp(&self.clusters[b].index))
    }

    fn entry_cmp(&self, e1: &Entry, e2: &Entry) -> std::cmp::Ordering {
        use std::cmp::Ordering as O;
        let base_group =
            |e: &Entry| e.cluster.map_or(e.group, |c| self.clusters[self.cluster_base(c)].group);
        let c = group_cmp(base_group(e1), base_group(e2));
        if c != O::Equal {
            return c;
        }
        match (e1.cluster, e2.cluster) {
            (None, Some(_)) => return O::Less,
            (Some(_), None) => return O::Greater,
            (Some(a), Some(b)) => {
                let c = self.cluster_cmp(a, b);
                if c != O::Equal {
                    return c;
                }
                let c = group_cmp(e1.group, e2.group);
                if c != O::Equal {
                    return c;
                }
            }
            (None, None) => {
                let c = group_cmp(e1.group, e2.group);
                if c != O::Equal {
                    return c;
                }
            }
        }

        let short1 = entry_first_short(e1);
        let short2 = entry_first_short(e2);
        let mut long1 = entry_first_long(e1);
        let mut long2 = entry_first_long(e2);
        let doc1 = odoc(&e1.opts[0]) && long1.is_some() && canon_doc_option(&mut long1);
        let doc2 = odoc(&e2.opts[0]) && long2.is_some() && canon_doc_option(&mut long2);
        if doc1 != doc2 {
            return doc1.cmp(&doc2);
        }
        if short1.is_none()
            && short2.is_none()
            && let (Some(l1), Some(l2)) = (long1, long2)
        {
            let c = casecmp(l1, l2);
            if c != O::Equal {
                return c;
            }
            return e1.ord.cmp(&e2.ord);
        }
        let first1 = short1.or_else(|| long1.and_then(|l| l.first().copied())).unwrap_or(0);
        let first2 = short2.or_else(|| long2.and_then(|l| l.first().copied())).unwrap_or(0);
        let lower = first1.to_ascii_lowercase().cmp(&first2.to_ascii_lowercase());
        if lower != O::Equal {
            return lower;
        }
        // Same letter: lower-case first; on the very same letter a long-only
        // entry precedes one with that short option ("--ca" before
        // "-c, --cz", "--child-level" before "-c, --child"); then table order.
        first2
            .cmp(&first1)
            .then(short1.is_some().cmp(&short2.is_some()))
            .then(e1.ord.cmp(&e2.ord))
    }
}

fn group_cmp(g1: i32, g2: i32) -> std::cmp::Ordering {
    use std::cmp::Ordering as O;
    match (g1 >= 0, g2 >= 0) {
        (true, true) | (false, false) => g1.cmp(&g2),
        (true, false) => O::Less,
        (false, true) => O::Greater,
    }
}

fn casecmp(a: &[u8], b: &[u8]) -> std::cmp::Ordering {
    a.iter()
        .map(u8::to_ascii_lowercase)
        .cmp(b.iter().map(u8::to_ascii_lowercase))
}

/// For documentation "options": skip leading blanks and punctuation for
/// sorting; true when the name does not look like an option.
fn canon_doc_option(name: &mut Option<&[u8]>) -> bool {
    let Some(mut n) = *name else {
        return false;
    };
    while n.first().is_some_and(u8::is_ascii_whitespace) {
        n = &n[1..];
    }
    let non_opt = n.first() != Some(&b'-');
    while n.first().is_some_and(|b| !b.is_ascii_alphanumeric()) {
        n = &n[1..];
    }
    *name = Some(n);
    non_opt
}

fn entry_first_short(e: &Entry) -> Option<u8> {
    let mut so = e.shorts.iter().peekable();
    for o in &e.opts {
        if let Some(&&c) = so.peek()
            && oshort(o)
            && o.key as u8 == c
        {
            if ovisible(o) {
                return Some(c);
            }
            so.next();
        }
    }
    None
}

fn entry_first_long(e: &Entry) -> Option<&[u8]> {
    e.opts
        .iter()
        .find(|o| o.name.is_some() && ovisible(o))
        .and_then(|o| o.name.as_deref())
}

/// Visible, non-shadowed short options of an entry with their `real` option.
fn entry_shorts(e: &Entry) -> Vec<(&HelpOption, &HelpOption)> {
    let mut out = Vec::new();
    let mut real = &e.opts[0];
    let mut so = e.shorts.iter().peekable();
    for o in &e.opts {
        if let Some(&&c) = so.peek()
            && oshort(o)
            && o.key as u8 == c
        {
            if !oalias(o) {
                real = o;
            }
            if ovisible(o) {
                out.push((o, real));
            }
            so.next();
        }
    }
    out
}

/// Visible long names of an entry with their `real` option.
fn entry_longs(e: &Entry) -> Vec<(&HelpOption, &HelpOption)> {
    let mut out = Vec::new();
    let mut real = &e.opts[0];
    for o in &e.opts {
        if !oalias(o) {
            real = o;
        }
        if o.name.is_some() && ovisible(o) {
            out.push((o, real));
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Rendering.
// ---------------------------------------------------------------------------

/// Everything `_help` needs besides the argp tree.
pub struct HelpContext<'a> {
    pub params: Uparams,
    pub name: &'a [u8],
    pub bug_address: Option<&'a [u8]>,
}

struct HelpState {
    prev_entry: Option<usize>,
    sep_groups: bool,
    suppressed_dup_arg: bool,
}

/// Render help for `argp` with `flags` (`HELP_*`). `dup_note_filter` is the
/// argp whose filter sees the duplicate-arguments note (the state's root
/// argp; `None` without a state).
pub fn render(
    argp: &HelpArgp,
    flags: u32,
    ctx: &HelpContext<'_>,
    filter: &mut dyn HelpFilter,
    dup_note_filter: Option<(usize, bool)>,
) -> Vec<u8> {
    let up = ctx.params;
    let mut fs = Fmt::new(up.rmargin.max(0) as usize);
    let mut flags = flags;
    let mut anything = false;

    let hol = if flags & (HELP_USAGE | HELP_SHORT_USAGE | HELP_LONG) != 0 {
        let mut hol = Hol::build(argp);
        hol.set_group(b"help", -1);
        hol.set_group(b"version", -1);
        let mut order: Vec<usize> = (0..hol.entries.len()).collect();
        order.sort_by(|&a, &b| hol.entry_cmp(&hol.entries[a], &hol.entries[b]));
        let mut entries: Vec<Option<Entry>> = hol.entries.drain(..).map(Some).collect();
        hol.entries = order.iter().map(|&i| entries[i].take().expect("entry")).collect();
        Some(hol)
    } else {
        None
    };

    if flags & (HELP_USAGE | HELP_SHORT_USAGE) != 0 {
        let hol = hol.as_ref().expect("hol");
        let mut levels = vec![0usize; args_levels(argp)];
        let mut first_pattern = true;
        loop {
            let old_wm = fs.set_wmargin(up.usage_indent as isize);
            let mut line = if first_pattern { b"Usage:".to_vec() } else { b"  or: ".to_vec() };
            line.push(b' ');
            line.extend_from_slice(ctx.name);
            fs.printf(&line);
            let old_lm = fs.set_lmargin(up.usage_indent.max(0) as usize);
            if flags & HELP_SHORT_USAGE != 0 {
                if !hol.entries.is_empty() {
                    fs.write(b" [OPTION...]");
                }
            } else {
                hol_usage(hol, &mut fs);
                flags |= HELP_SHORT_USAGE;
            }
            let mut li = 0;
            let more = args_usage(argp, &mut levels, &mut li, true, &mut fs, filter);
            fs.set_wmargin(old_wm);
            fs.set_lmargin(old_lm);
            fs.putc(b'\n');
            anything = true;
            first_pattern = false;
            if !more {
                break;
            }
        }
    }

    if flags & HELP_PRE_DOC != 0 {
        anything |= argp_doc(argp, false, false, true, &mut fs, filter);
    }

    if flags & HELP_SEE != 0 {
        let mut s = b"Try `".to_vec();
        s.extend_from_slice(ctx.name);
        s.extend_from_slice(b" --help' or `");
        s.extend_from_slice(ctx.name);
        s.extend_from_slice(b" --usage' for more information.\n");
        fs.printf(&s);
        anything = true;
    }

    if flags & HELP_LONG != 0 {
        let hol = hol.as_ref().expect("hol");
        if !hol.entries.is_empty() {
            if anything {
                fs.putc(b'\n');
            }
            hol_help(hol, &up, &mut fs, filter, dup_note_filter);
            anything = true;
        }
    }

    if flags & HELP_POST_DOC != 0 {
        anything |= argp_doc(argp, true, anything, false, &mut fs, filter);
    }

    if flags & HELP_BUG_ADDR != 0
        && let Some(addr) = ctx.bug_address
    {
        if anything {
            fs.putc(b'\n');
        }
        let mut s = b"Report bugs to ".to_vec();
        s.extend_from_slice(addr);
        s.extend_from_slice(b".\n");
        fs.printf(&s);
    }

    fs.finish()
}

fn filter_doc(
    filter: &mut dyn HelpFilter,
    argp_id: usize,
    has_filter: bool,
    key: i32,
    doc: Option<&[u8]>,
) -> Option<Vec<u8>> {
    if has_filter {
        filter.filter(argp_id, key, doc)
    } else {
        doc.map(<[u8]>::to_vec)
    }
}

/// `space`: a separating blank, or a newline if `ensure` more columns would
/// not fit.
fn space(fs: &mut Fmt, ensure: usize) {
    let rmargin = fs.rmargin;
    if fs.point() + ensure >= rmargin {
        fs.putc(b'\n');
    } else {
        fs.putc(b' ');
    }
}

fn hol_usage(hol: &Hol, fs: &mut Fmt) {
    if hol.entries.is_empty() {
        return;
    }
    let mut argless = Vec::new();
    for e in &hol.entries {
        for (o, real) in entry_shorts(e) {
            if o.arg.is_none()
                && real.arg.is_none()
                && (o.flags | real.flags) & OPTION_NO_USAGE == 0
            {
                argless.push(o.key as u8);
            }
        }
    }
    if !argless.is_empty() {
        let mut s = b" [-".to_vec();
        s.extend_from_slice(&argless);
        s.push(b']');
        fs.printf(&s);
    }
    for e in &hol.entries {
        for (o, real) in entry_shorts(e) {
            let flags = o.flags | real.flags;
            let arg = o.arg.as_ref().or(real.arg.as_ref());
            if let Some(arg) = arg
                && flags & OPTION_NO_USAGE == 0
            {
                if flags & OPTION_ARG_OPTIONAL != 0 {
                    let mut s = b" [-".to_vec();
                    s.push(o.key as u8);
                    s.push(b'[');
                    s.extend_from_slice(arg);
                    s.extend_from_slice(b"]]");
                    fs.printf(&s);
                } else {
                    space(fs, 6 + arg.len());
                    let mut s = b"[-".to_vec();
                    s.push(o.key as u8);
                    s.push(b' ');
                    s.extend_from_slice(arg);
                    s.push(b']');
                    fs.printf(&s);
                }
            }
        }
    }
    for e in &hol.entries {
        for (o, real) in entry_longs(e) {
            let flags = o.flags | real.flags;
            if flags & OPTION_NO_USAGE != 0 {
                continue;
            }
            let name = o.name.as_deref().unwrap_or(b"");
            let mut s = b" [--".to_vec();
            s.extend_from_slice(name);
            match o.arg.as_ref().or(real.arg.as_ref()) {
                Some(arg) if flags & OPTION_ARG_OPTIONAL != 0 => {
                    s.extend_from_slice(b"[=");
                    s.extend_from_slice(arg);
                    s.extend_from_slice(b"]]");
                }
                Some(arg) => {
                    s.push(b'=');
                    s.extend_from_slice(arg);
                    s.push(b']');
                }
                None => s.push(b']'),
            }
            fs.printf(&s);
        }
    }
}

/// Number of argps in the tree whose args_doc has several alternatives.
fn args_levels(argp: &HelpArgp) -> usize {
    usize::from(argp.args_doc.as_ref().is_some_and(|d| d.contains(&b'\n')))
        + argp.children.iter().map(|c| args_levels(&c.argp)).sum::<usize>()
}

/// Print this pattern's args_doc alternatives; true if more patterns remain.
fn args_usage(
    argp: &HelpArgp,
    levels: &mut [usize],
    li: &mut usize,
    advance: bool,
    fs: &mut Fmt,
    filter: &mut dyn HelpFilter,
) -> bool {
    let mut advance = advance;
    let fdoc = filter_doc(
        filter,
        argp.id,
        argp.has_filter,
        KEY_HELP_ARGS_DOC,
        argp.args_doc.as_deref(),
    );
    let mut my_level: Option<usize> = None;
    let mut rest_after = false;
    if let Some(doc) = fdoc.as_deref() {
        let mut parts = doc.split(|&b| b == b'\n');
        let mut cur = parts.next().unwrap_or(b"");
        let multiple = doc.contains(&b'\n');
        if multiple {
            let lvl = *li;
            *li += 1;
            my_level = Some(lvl);
            for _ in 0..levels[lvl] {
                cur = parts.next().unwrap_or(b"");
            }
            rest_after = parts.next().is_some();
        }
        space(fs, 1 + cur.len());
        fs.write(cur);
    }
    for child in &argp.children {
        advance = !args_usage(&child.argp, levels, li, advance, fs, filter);
    }
    if advance && let Some(lvl) = my_level {
        if rest_after {
            levels[lvl] += 1;
            advance = false;
        } else if levels[lvl] > 0 {
            levels[lvl] = 0;
        }
    }
    !advance
}

fn argp_doc(
    argp: &HelpArgp,
    post: bool,
    pre_blank: bool,
    first_only: bool,
    fs: &mut Fmt,
    filter: &mut dyn HelpFilter,
) -> bool {
    let mut anything = false;
    let inp: Option<&[u8]> = argp.doc.as_deref().and_then(|doc| {
        match doc.iter().position(|&b| b == b'\x0b') {
            Some(vt) => Some(if post { &doc[vt + 1..] } else { &doc[..vt] }),
            None => (!post).then_some(doc),
        }
    });
    let key = if post { KEY_HELP_POST_DOC } else { KEY_HELP_PRE_DOC };
    let text = filter_doc(filter, argp.id, argp.has_filter, key, inp);
    if let Some(text) = text {
        if pre_blank {
            fs.putc(b'\n');
        }
        fs.write(&text);
        let lm = fs.lmargin();
        if fs.point() > lm {
            fs.putc(b'\n');
        }
        anything = true;
    }
    if post && argp.has_filter {
        if let Some(text) = filter.filter(argp.id, KEY_HELP_EXTRA, None) {
            if anything || pre_blank {
                fs.putc(b'\n');
            }
            fs.write(&text);
            let lm = fs.lmargin();
            if fs.point() > lm {
                fs.putc(b'\n');
            }
            anything = true;
        }
    }
    for child in &argp.children {
        if first_only && anything {
            break;
        }
        anything |= argp_doc(&child.argp, post, anything || pre_blank, first_only, fs, filter);
    }
    anything
}

fn indent_to(fs: &mut Fmt, col: usize) {
    let point = fs.point();
    for _ in point..col {
        fs.putc(b' ');
    }
}

struct EntryPrinter<'a> {
    first: bool,
    entry: usize,
    hol: &'a Hol,
    up: &'a Uparams,
}

fn print_header(
    fs: &mut Fmt,
    hstate: &mut HelpState,
    up: &Uparams,
    filter: &mut dyn HelpFilter,
    text: Option<&[u8]>,
    argp_id: usize,
    has_filter: bool,
) {
    let fstr = filter_doc(filter, argp_id, has_filter, KEY_HELP_HEADER, text);
    if let Some(s) = fstr {
        if !s.is_empty() {
            if hstate.prev_entry.is_some() {
                fs.putc(b'\n');
            }
            indent_to(fs, up.header_col.max(0) as usize);
            fs.set_lmargin(up.header_col.max(0) as usize);
            fs.set_wmargin(up.header_col as isize);
            fs.write(&s);
            fs.set_lmargin(0);
            fs.putc(b'\n');
        }
        hstate.sep_groups = true;
    }
}

fn comma(
    p: &mut EntryPrinter<'_>,
    col: usize,
    fs: &mut Fmt,
    hstate: &mut HelpState,
    filter: &mut dyn HelpFilter,
) {
    if p.first {
        let entry = &p.hol.entries[p.entry];
        let pe = hstate.prev_entry.map(|i| &p.hol.entries[i]);
        if hstate.sep_groups
            && let Some(pe) = pe
            && entry.group != pe.group
        {
            fs.putc(b'\n');
        }
        if let Some(cl) = entry.cluster {
            let cluster = &p.hol.clusters[cl];
            if cluster.header.as_ref().is_some_and(|h| !h.is_empty())
                && pe.is_none_or(|pe| pe.cluster != Some(cl) && !p.hol.cluster_is_child(pe.cluster, cl))
            {
                let old_wm = fs.wmargin();
                let header = cluster.header.clone();
                print_header(
                    fs,
                    hstate,
                    p.up,
                    filter,
                    header.as_deref(),
                    cluster.argp_id,
                    cluster.has_filter,
                );
                fs.set_wmargin(old_wm);
            }
        }
        p.first = false;
    } else {
        fs.write(b", ");
    }
    indent_to(fs, col);
}

fn print_arg(fs: &mut Fmt, real: &HelpOption, req: (&[u8], &[u8]), opt: (&[u8], &[u8])) {
    if let Some(arg) = &real.arg {
        let (pre, post) = if real.flags & OPTION_ARG_OPTIONAL != 0 { opt } else { req };
        let mut s = pre.to_vec();
        s.extend_from_slice(arg);
        s.extend_from_slice(post);
        fs.printf(&s);
    }
}

fn hol_entry_help(
    hol: &Hol,
    idx: usize,
    up: &Uparams,
    fs: &mut Fmt,
    hstate: &mut HelpState,
    filter: &mut dyn HelpFilter,
) {
    let entry = &hol.entries[idx];
    let real = &entry.opts[0];
    let old_lm = fs.set_lmargin(0);
    let old_wm = fs.wmargin();
    let mut p = EntryPrinter {
        first: true,
        entry: idx,
        hol,
        up,
    };
    let have_long_opt = !odoc(real) && entry.opts.iter().any(|o| o.name.is_some() && ovisible(o));

    fs.set_wmargin(up.short_opt_col as isize);
    for (o, _) in entry_shorts(entry) {
        comma(&mut p, up.short_opt_col.max(0) as usize, fs, hstate, filter);
        fs.putc(b'-');
        fs.putc(o.key as u8);
        if !have_long_opt || up.dup_args {
            print_arg(fs, real, (b" ", b""), (b"[", b"]"));
        } else if real.arg.is_some() {
            hstate.suppressed_dup_arg = true;
        }
    }

    if odoc(real) {
        fs.set_wmargin(up.doc_opt_col as isize);
        for o in entry.opts.iter().filter(|o| o.name.is_some() && ovisible(o)) {
            comma(&mut p, up.doc_opt_col.max(0) as usize, fs, hstate, filter);
            fs.write(o.name.as_deref().unwrap_or(b""));
        }
    } else {
        fs.set_wmargin(up.long_opt_col as isize);
        for o in entry.opts.iter().filter(|o| o.name.is_some() && ovisible(o)) {
            comma(&mut p, up.long_opt_col.max(0) as usize, fs, hstate, filter);
            let mut s = b"--".to_vec();
            s.extend_from_slice(o.name.as_deref().unwrap_or(b""));
            fs.printf(&s);
            print_arg(fs, real, (b"=", b""), (b"[=", b"]"));
        }
    }

    fs.set_lmargin(0);
    if p.first {
        if !oshort(real) && real.name.is_none() {
            print_header(fs, hstate, up, filter, real.doc.as_deref(), entry.argp_id, entry.has_filter);
        } else {
            fs.set_lmargin(old_lm);
            fs.set_wmargin(old_wm);
            return;
        }
    } else {
        let fstr = filter_doc(filter, entry.argp_id, entry.has_filter, real.key, real.doc.as_deref());
        if let Some(s) = fstr.filter(|s| !s.is_empty()) {
            let col = fs.point();
            let doc_col = up.opt_doc_col.max(0) as usize;
            fs.set_lmargin(doc_col);
            fs.set_wmargin(up.opt_doc_col as isize);
            if col > doc_col + 3 {
                fs.putc(b'\n');
            } else if col >= doc_col {
                fs.write(b"   ");
            } else {
                indent_to(fs, doc_col);
            }
            fs.write(&s);
        }
        fs.set_lmargin(0);
        fs.putc(b'\n');
    }
    hstate.prev_entry = Some(idx);
    fs.set_lmargin(old_lm);
    fs.set_wmargin(old_wm);
}

fn hol_help(
    hol: &Hol,
    up: &Uparams,
    fs: &mut Fmt,
    filter: &mut dyn HelpFilter,
    dup_note_filter: Option<(usize, bool)>,
) {
    let mut hstate = HelpState {
        prev_entry: None,
        sep_groups: false,
        suppressed_dup_arg: false,
    };
    for idx in 0..hol.entries.len() {
        hol_entry_help(hol, idx, up, fs, &mut hstate, filter);
    }
    if hstate.suppressed_dup_arg && up.dup_args_note {
        let note: &[u8] = b"Mandatory or optional arguments to long options are also mandatory or optional for any corresponding short options.";
        let fstr = match dup_note_filter {
            Some((id, has)) => filter_doc(filter, id, has, KEY_HELP_DUP_ARGS_NOTE, Some(note)),
            None => Some(note.to_vec()),
        };
        if let Some(s) = fstr.filter(|s| !s.is_empty()) {
            fs.putc(b'\n');
            fs.write(&s);
            fs.putc(b'\n');
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opt(name: Option<&str>, key: i32, arg: Option<&str>, flags: i32, doc: &str) -> HelpOption {
        HelpOption {
            name: name.map(|n| n.as_bytes().to_vec()),
            key,
            arg: arg.map(|a| a.as_bytes().to_vec()),
            flags,
            doc: Some(doc.as_bytes().to_vec()),
            group: 0,
        }
    }

    fn plain() -> HelpArgp {
        HelpArgp {
            id: 0,
            options: vec![
                opt(Some("alpha"), b'A' as i32, None, 0, "first"),
                opt(Some("beta"), b'B' as i32, Some("ARG"), 0, "second"),
            ],
            args_doc: Some(b"database [key ...]".to_vec()),
            doc: Some(b"Get entries.".to_vec()),
            children: vec![],
            has_filter: false,
        }
    }

    fn ctx() -> HelpContext<'static> {
        HelpContext {
            params: Uparams::default(),
            name: b"prog",
            bug_address: Some(b"<bugs@example.test>"),
        }
    }

    #[test]
    fn plain_help_and_usage_match_glibc_layout() {
        let help = render(&plain(), 0x7a, &ctx(), &mut NoFilter, None);
        assert_eq!(
            String::from_utf8(help).unwrap(),
            "Usage: prog [OPTION...] database [key ...]\nGet entries.\n\n  \
             -A, --alpha                first\n  -B, --beta=ARG             second\n\n\
             Mandatory or optional arguments to long options are also mandatory or optional\n\
             for any corresponding short options.\n\nReport bugs to <bugs@example.test>.\n"
        );
        let usage = render(&plain(), HELP_USAGE, &ctx(), &mut NoFilter, None);
        assert_eq!(
            String::from_utf8(usage).unwrap(),
            "Usage: prog [-A] [-B ARG] [--alpha] [--beta=ARG] database [key ...]\n"
        );
    }

    #[test]
    fn fmt_wraps_words_and_keeps_overlong_words_whole() {
        let mut fs = Fmt::new(20);
        fs.set_wmargin(4);
        fs.write(b"aaaa bbbb cccc dddd eeee ffff");
        fs.putc(b'\n');
        fs.write(b"x0123456789012345678901234 y");
        fs.putc(b'\n');
        assert_eq!(
            String::from_utf8(fs.finish()).unwrap(),
            "aaaa bbbb cccc dddd\n    eeee ffff\nx0123456789012345678901234\n    y\n"
        );
    }

    #[test]
    fn help_fmt_parsing_is_cumulative_and_validated() {
        let mut up = Uparams::default();
        assert!(up.apply_help_fmt(b"rmargin=50, opt-doc-col=20,no-dup-args-note").is_empty());
        assert_eq!((up.rmargin, up.opt_doc_col, up.dup_args_note), (50, 20, false));
        assert!(up.apply_help_fmt(b"dup-args").is_empty());
        assert_eq!((up.rmargin, up.dup_args), (50, true));
        let d = up.apply_help_fmt(b"header-col=60");
        assert_eq!(d, [b"ARGP_HELP_FMT: rmargin value is less than or equal to header-col".to_vec()]);
        assert_eq!(up.header_col, 1, "rejected settings are not applied");
        let d = up.apply_help_fmt(b"bogus=3,rmargin,!x");
        assert_eq!(
            d,
            [
                b"bogus: Unknown ARGP_HELP_FMT parameter".to_vec(),
                b"rmargin: ARGP_HELP_FMT parameter requires a value".to_vec(),
                b"Garbage in ARGP_HELP_FMT: !x".to_vec(),
            ]
        );
    }
}
