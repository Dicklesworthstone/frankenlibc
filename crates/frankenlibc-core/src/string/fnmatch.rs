//! Shell-pattern matching with stack-safe GNU extended matching.
//!
//! Ordinary patterns retain the allocation-free byte matcher. Extended
//! patterns use an explicit evaluation stack and memoize completed states;
//! neither literal length, repetition count nor nesting consumes Rust stack.
//! The previous matcher remains the implementation of byte/bracket and wide
//! character semantics, and a bounded differential oracle in tests.

#[path = "fnmatch_legacy.rs"]
mod legacy;

pub use legacy::{FnmatchFlags, WideCtype, fnmatch_wide};

use std::collections::BTreeMap;
use std::rc::Rc;

/// Match a shell pattern, preserving POSIX/glibc flag bit assignments.
pub fn fnmatch_match(pattern: &[u8], text: &[u8], flags: FnmatchFlags) -> bool {
    if !flags.contains(FnmatchFlags::EXTMATCH)
        || !has_extglob(pattern, flags.contains(FnmatchFlags::NOESCAPE))
    {
        return legacy::fnmatch_match(pattern, text, flags);
    }
    evaluate(pattern, text, flags).0
}

fn has_extglob(pattern: &[u8], noescape: bool) -> bool {
    let mut i = 0;
    while i < pattern.len() {
        if pattern[i] == b'\\' && !noescape {
            i += 2;
        } else if matches!(pattern[i], b'?' | b'*' | b'+' | b'@' | b'!')
            && pattern.get(i + 1) == Some(&b'(')
        {
            return true;
        } else {
            i += 1;
        }
    }
    false
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Bracket {
    Closed(usize),
    Literal,
    Invalid,
}

/// Locate an atom without changing the existing matcher's bracket semantics.
/// In particular, a POSIX subexpression's inner `]` is not the outer closer.
fn bracket(pattern: &[u8], open: usize, noescape: bool) -> Bracket {
    let mut i = open + 1;
    if matches!(pattern.get(i), Some(b'!' | b'^')) {
        i += 1;
    }
    let mut count = 0usize;
    let mut last_dash = false;
    while let Some(&byte) = pattern.get(i) {
        if byte == b']' && count != 0 {
            return Bracket::Closed(i + 1);
        }
        if byte == b'[' && matches!(pattern.get(i + 1), Some(b':' | b'.' | b'=')) {
            let kind = pattern[i + 1];
            let mut end = i + 2;
            loop {
                match pattern.get(end) {
                    None => return Bracket::Literal,
                    Some(&b) if b == kind && pattern.get(end + 1) == Some(&b']') => break,
                    _ => end += 1,
                }
            }
            i = end + 2;
            count += 1;
            last_dash = false;
        } else if byte == b'\\' && !noescape && i + 1 < pattern.len() {
            i += 2;
            count += 1;
            last_dash = false;
        } else {
            last_dash = byte == b'-';
            count += 1;
            i += 1;
        }
    }
    if last_dash && count > 1 {
        Bracket::Invalid
    } else {
        Bracket::Literal
    }
}

#[derive(Debug)]
struct Group {
    operator: u8,
    alternatives: Vec<(usize, usize)>,
    next: usize,
}

/// Flat syntax index. Groups are closed once during a single left-to-right
/// scan rather than reparsing every ancestor's suffix at every nesting level.
/// Only real groups occupy the map; long literal prefixes allocate no entries.
type Groups = BTreeMap<usize, Rc<Group>>;

struct OpenGroup {
    position: usize,
    alternative_start: usize,
    alternatives: Vec<(usize, usize)>,
}

fn parse_groups(pattern: &[u8], noescape: bool) -> Groups {
    let mut groups = BTreeMap::new();
    let mut stack: Vec<OpenGroup> = Vec::new();
    let mut i = 0;
    while i < pattern.len() {
        match pattern[i] {
            b'\\' if !noescape => i += 2,
            b'[' => match bracket(pattern, i, noescape) {
                Bracket::Closed(next) => i = next,
                _ => {
                    // An unterminated bracket makes every enclosing group
                    // malformed. Matching can nevertheless reach later groups
                    // after consuming the malformed prefix as literal text.
                    stack.clear();
                    i += 1;
                }
            },
            b'?' | b'*' | b'+' | b'@' | b'!' if pattern.get(i + 1) == Some(&b'(') => {
                stack.push(OpenGroup {
                    position: i,
                    alternative_start: i + 2,
                    alternatives: Vec::new(),
                });
                i += 2;
            }
            b')' => {
                if let Some(mut open) = stack.pop() {
                    open.alternatives.push((open.alternative_start, i));
                    groups.insert(
                        open.position,
                        Rc::new(Group {
                            operator: pattern[open.position],
                            alternatives: open.alternatives,
                            next: i + 1,
                        }),
                    );
                }
                i += 1;
            }
            b'|' => {
                if let Some(open) = stack.last_mut() {
                    open.alternatives.push((open.alternative_start, i));
                    open.alternative_start = i + 1;
                }
                i += 1;
            }
            _ => i += 1,
        }
    }
    groups
}

fn group_at(state: State, groups: &Groups) -> Option<Rc<Group>> {
    groups
        .get(&state.p)
        .filter(|group| group.next <= state.pend)
        .cloned()
}

/// Text bounds and flags belong in the key: alternatives match fixed slices,
/// not a suffix of the original text, and do not inherit LEADING_DIR or an
/// outer wildcard's slack. `repeat` is the zero-or-more continuation of `+`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct State {
    p: usize,
    pend: usize,
    s: usize,
    start: usize,
    end: usize,
    bits: u32,
    star: bool,
    repeat: bool,
}

impl State {
    fn flag(self, flag: FnmatchFlags) -> bool {
        self.bits & flag.bits() != 0
    }

    fn suffix(self, p: usize, s: usize, star: bool) -> Self {
        Self {
            p,
            s,
            star,
            repeat: false,
            ..self
        }
    }

    fn at_leading(self, text: &[u8], s: usize) -> bool {
        s == self.start
            || (self.flag(FnmatchFlags::PATHNAME) && s > self.start && text[s - 1] == b'/')
    }

    fn period_blocked(self, text: &[u8]) -> bool {
        self.flag(FnmatchFlags::PERIOD)
            && self.s < self.end
            && text[self.s] == b'.'
            && self.at_leading(text, self.s)
    }

    fn alternative(self, range: (usize, usize), end: usize, text: &[u8]) -> Self {
        let mut bits = self.bits & !FnmatchFlags::LEADING_DIR.bits();
        if !self.at_leading(text, self.s) {
            bits &= !FnmatchFlags::PERIOD.bits();
        }
        Self {
            p: range.0,
            pend: range.1,
            s: self.s,
            start: self.s,
            end,
            bits,
            star: false,
            repeat: false,
        }
    }
}

#[derive(Clone, Copy)]
enum Phase {
    Scan,
    Star,
    Zero,
    Candidate,
    Alternatives,
    Follow,
}

struct Frame {
    key: State,
    state: State,
    phase: Phase,
    group: Option<Rc<Group>>,
    next: usize,
    split: usize,
    alternative: usize,
}

enum Step {
    Need(State),
    Done(bool),
}

impl Frame {
    fn new(key: State) -> Self {
        Self {
            key,
            state: key,
            phase: Phase::Scan,
            group: None,
            next: 0,
            split: 0,
            alternative: 0,
        }
    }

    fn advance(
        &mut self,
        pattern: &[u8],
        text: &[u8],
        groups: &Groups,
        completed: &BTreeMap<State, bool>,
    ) -> Step {
        loop {
            let state = self.state;
            match self.phase {
                Phase::Scan => {
                    if state.p == state.pend {
                        return Step::Done(
                            state.s == state.end
                                || (state.flag(FnmatchFlags::LEADING_DIR)
                                    && state.s < state.end
                                    && text[state.s] == b'/'),
                        );
                    }
                    if let Some(group) = group_at(state, groups) {
                        let op = if state.repeat { b'*' } else { group.operator };
                        if op == b'@' && state.star && state.s == state.end {
                            return Step::Done(false);
                        }
                        self.split = if op == b'*'
                            || (op == b'+' && state.star && state.s == state.end)
                        {
                            state.s + 1
                        } else {
                            state.s
                        };
                        self.phase = if matches!(op, b'*' | b'?') {
                            Phase::Zero
                        } else {
                            Phase::Candidate
                        };
                        self.group = Some(group);
                        continue;
                    }
                    let pc = pattern[state.p];
                    if pc == b'*' {
                        if state.period_blocked(text) {
                            return Step::Done(false);
                        }
                        let mut next = state.p + 1;
                        while next < state.pend
                            && pattern[next] == b'*'
                            && group_at(state.suffix(next, state.s, state.star), groups)
                                .is_none()
                        {
                            next += 1;
                        }
                        self.next = next;
                        self.split = state.s;
                        self.phase = Phase::Star;
                        continue;
                    }
                    if state.s == state.end {
                        return Step::Done(false);
                    }
                    let c = text[state.s];
                    let eq = |a: u8, b: u8| {
                        if state.flag(FnmatchFlags::CASEFOLD) {
                            a.eq_ignore_ascii_case(&b)
                        } else {
                            a == b
                        }
                    };
                    let mut next = state.p + 1;
                    let hit = match pc {
                        b'?' => {
                            !(state.flag(FnmatchFlags::PATHNAME) && c == b'/')
                                && !state.period_blocked(text)
                        }
                        b'[' => {
                            if (state.flag(FnmatchFlags::PATHNAME) && c == b'/')
                                || state.period_blocked(text)
                            {
                                return Step::Done(false);
                            }
                            match bracket(
                                &pattern[..state.pend],
                                state.p,
                                state.flag(FnmatchFlags::NOESCAPE),
                            ) {
                                Bracket::Closed(end) => {
                                    next = end;
                                    // Only single-byte atom semantics are delegated; this
                                    // can never enter the recursive extglob implementation.
                                    let flags = FnmatchFlags::from_bits(
                                        state.bits
                                            & (FnmatchFlags::NOESCAPE.bits()
                                                | FnmatchFlags::CASEFOLD.bits()),
                                    );
                                    legacy::fnmatch_match(&pattern[state.p..end], &[c], flags)
                                }
                                Bracket::Literal => eq(c, b'['),
                                Bracket::Invalid => false,
                            }
                        }
                        b'\\' if !state.flag(FnmatchFlags::NOESCAPE) => {
                            if next == state.pend {
                                return Step::Done(false);
                            }
                            next += 1;
                            eq(c, pattern[state.p + 1])
                        }
                        _ => eq(c, pc),
                    };
                    if !hit {
                        return Step::Done(false);
                    }
                    self.state = state.suffix(next, state.s + 1, pc == b'?' && state.star);
                }
                Phase::Star => {
                    let child = state.suffix(self.next, self.split, true);
                    match completed.get(&child).copied() {
                        None => return Step::Need(child),
                        Some(true) => return Step::Done(true),
                        Some(false) => {
                            if self.split == state.end
                                || (state.flag(FnmatchFlags::PATHNAME) && text[self.split] == b'/')
                            {
                                return Step::Done(false);
                            }
                            self.split += 1;
                        }
                    }
                }
                _ => {
                    let group = self.group.as_ref().expect("group phase has a group");
                    let op = if state.repeat { b'*' } else { group.operator };
                    match self.phase {
                        Phase::Zero => {
                            // A zero-count `*` preserves the wildcard slack. An
                            // occurrence, including a `?` zero-count branch, clears it.
                            let child = state.suffix(group.next, state.s, op == b'*' && state.star);
                            match completed.get(&child).copied() {
                                None => return Step::Need(child),
                                Some(true) => return Step::Done(true),
                                Some(false) => self.phase = Phase::Candidate,
                            }
                        }
                        Phase::Candidate => {
                            if self.split > state.end {
                                return Step::Done(false);
                            }
                            if op == b'!' {
                                let child = state.suffix(group.next, self.split, false);
                                match completed.get(&child).copied() {
                                    None => return Step::Need(child),
                                    Some(false) => {
                                        self.split += 1;
                                        continue;
                                    }
                                    Some(true) => {}
                                }
                            }
                            self.alternative = 0;
                            self.phase = Phase::Alternatives;
                        }
                        Phase::Alternatives => {
                            let Some(&range) = group.alternatives.get(self.alternative) else {
                                if op == b'!' {
                                    return Step::Done(true);
                                }
                                self.split += 1;
                                self.phase = Phase::Candidate;
                                continue;
                            };
                            let child = state.alternative(range, self.split, text);
                            match completed.get(&child).copied() {
                                None => return Step::Need(child),
                                Some(false) => self.alternative += 1,
                                Some(true) if op == b'!' => {
                                    self.split += 1;
                                    self.phase = Phase::Candidate;
                                }
                                Some(true) => self.phase = Phase::Follow,
                            }
                        }
                        Phase::Follow => {
                            let child = if matches!(op, b'*' | b'+') && self.split > state.s {
                                State {
                                    s: self.split,
                                    star: false,
                                    repeat: true,
                                    ..state
                                }
                            } else {
                                state.suffix(group.next, self.split, false)
                            };
                            match completed.get(&child).copied() {
                                None => return Step::Need(child),
                                Some(true) => return Step::Done(true),
                                Some(false) => {
                                    self.split += 1;
                                    self.phase = Phase::Candidate;
                                }
                            }
                        }
                        Phase::Scan | Phase::Star => unreachable!(),
                    }
                }
            }
        }
    }
}

/// The second result is a deterministic work counter for regression tests.
/// No arbitrary recursion/work cutoff turns a valid match into a false miss.
fn evaluate(pattern: &[u8], text: &[u8], flags: FnmatchFlags) -> (bool, usize) {
    let root = State {
        p: 0,
        pend: pattern.len(),
        s: 0,
        start: 0,
        end: text.len(),
        bits: flags.bits(),
        star: false,
        repeat: false,
    };
    let mut completed = BTreeMap::new();
    let groups = parse_groups(pattern, flags.contains(FnmatchFlags::NOESCAPE));
    let mut stack = vec![Frame::new(root)];
    loop {
        let frame = stack.last_mut().expect("root frame remains until return");
        match frame.advance(pattern, text, &groups, &completed) {
            Step::Need(state) => stack.push(Frame::new(state)),
            Step::Done(value) => {
                let frame = stack.pop().expect("completed frame exists");
                completed.insert(frame.key, value);
                if stack.is_empty() {
                    return (value, completed.len());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXT: FnmatchFlags = FnmatchFlags::EXTMATCH;

    #[test]
    fn long_literal_and_repeated_groups_do_not_use_the_call_stack() {
        let text = vec![b'a'; 16_384];
        let mut literal = text.clone();
        literal.extend_from_slice(b"@()");
        assert!(fnmatch_match(&literal, &text, EXT));
        assert!(fnmatch_match(b"+(a)", &text, EXT));
    }

    #[test]
    fn deeply_nested_groups_use_heap_frames() {
        let mut pattern = b"@(".repeat(2048);
        pattern.push(b'x');
        pattern.extend(std::iter::repeat_n(b')', 2048));
        assert!(fnmatch_match(&pattern, b"x", EXT));
        assert!(!fnmatch_match(&pattern, b"y", EXT));
    }

    #[test]
    fn ambiguous_repetition_failure_has_polynomial_state_count() {
        let (small, small_work) = evaluate(b"+(a|aa)b", &[b'a'; 32], EXT);
        let (large, large_work) = evaluate(b"+(a|aa)b", &[b'a'; 64], EXT);
        assert!(!small && !large);
        assert!(large_work < 10_000, "{large_work} distinct states");
        assert!(large_work < 5 * small_work, "{small_work} -> {large_work}");
    }

    #[test]
    fn nullable_repetition_and_wildcard_slack_terminate() {
        for (pattern, text, expected) in [
            ("+(|a)", "aaaa", true), ("*()", "", true),
            ("+()", "", true), ("*+()", "bb", false),
            ("*@(b|)", "ba", false), ("*a@(b|)", "ba", true),
            ("*+()?+()", "bc", true), ("**(!()", "anything", false),
            ("!(a|b)", "ab", true), ("!(a|b)", "a", false),
        ] {
            assert_eq!(fnmatch_match(pattern.as_bytes(), text.as_bytes(), EXT), expected,
                "{pattern:?} {text:?}");
        }
    }

    #[test]
    fn bounded_differential_corpus_preserves_existing_flag_semantics() {
        let patterns: &[&[u8]] = &[
            b"@(a|b)", b"?(a|)", b"+(a|aa)", b"*(a|?)b", b"!(a|b)",
            b"@(@(a)|+(b))", b"+(|a)", b"*(|?)", b"!(a*)/b", b"a@(.*|?)",
            b"*@(b|)", b"*?@(b|)", b"*a@(b|)", b"*+()?+()", b"**(!()",
            b"@([[:alpha:]]|[.])", b"@([])]|[|])", b"@([a-z]|\\?)",
            b"@(a|[a-)", b"@([![:upper:]\\]|a)", b"@(a/b|a)", b"*(a)/?",
            b"!(|a)", b"+(!(a))", b"@(\\|a)", b"*@(a|b)*", b"a\\@(b)",
        ];
        let mut texts = vec![Vec::new()];
        for _ in 0..3 {
            let previous = texts.clone();
            for text in previous {
                for &byte in b"ab./" {
                    let mut next = text.clone();
                    next.push(byte);
                    if !texts.contains(&next) {
                        texts.push(next);
                    }
                }
            }
        }
        for bits in 32..64 {
            let flags = FnmatchFlags::from_bits(bits);
            for pattern in patterns {
                for text in &texts {
                    assert_eq!(fnmatch_match(pattern, text, flags),
                        legacy::fnmatch_match(pattern, text, flags),
                        "pattern={pattern:?} text={text:?} flags={bits}");
                }
            }
        }
    }

    #[test]
    fn syntax_index_stores_groups_not_literal_positions() {
        let mut pattern = vec![b'a'; 131_072];
        pattern.extend_from_slice(b"@(x)");
        let groups = parse_groups(&pattern, false);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[&131_072].next, pattern.len());
    }

    #[test]
    fn syntax_index_handles_large_nesting_and_malformed_outer_groups() {
        let depth = 16_384;
        let mut pattern = b"@(".repeat(depth);
        pattern.push(b'x');
        pattern.extend(std::iter::repeat_n(b')', depth));
        let groups = parse_groups(&pattern, false);
        assert_eq!(groups.len(), depth);
        assert_eq!(groups[&0].next, pattern.len());
        assert_eq!(groups[&(2 * (depth - 1))].next, 2 * depth + 2);

        let malformed = b"@([@(a)";
        let groups = parse_groups(malformed, false);
        assert!(!groups.contains_key(&0));
        assert_eq!(groups[&3].next, malformed.len());
        assert!(fnmatch_match(malformed, b"@([a", EXT));
        assert!(!fnmatch_match(malformed, b"@([b", EXT));
    }

    #[test]
    fn generated_malformed_patterns_preserve_legacy_matching() {
        let mut seed = 0x62bb_e572_1cad_903fu64;
        let mut draw = |limit: usize| {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            (seed >> 32) as usize % limit
        };
        let alphabet = br"@*!+?()|[]:-=.^/\ab";
        let text_alphabet = b"ab./[]()|*?@!";
        for _ in 0..12_000 {
            let length = 1 + draw(23);
            let mut pattern: Vec<u8> = (0..length)
                .map(|_| alphabet[draw(alphabet.len())])
                .collect();
            if draw(2) == 0 {
                pattern.splice(0..0, b"@(".iter().copied());
                pattern.push(b')');
            }
            let length = draw(7);
            let text: Vec<u8> = (0..length)
                .map(|_| text_alphabet[draw(text_alphabet.len())])
                .collect();
            let flags = FnmatchFlags::from_bits(32 + draw(32) as u32);
            assert_eq!(
                fnmatch_match(&pattern, &text, flags),
                legacy::fnmatch_match(&pattern, &text, flags),
                "pattern={pattern:?} text={text:?} flags={flags:?}",
            );
        }
    }
}
