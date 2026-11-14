//! Unicode 16 IDNA2008 properties, compiled from the unmodified Unicode data.
//!
//! The const parser keeps the original, auditable property corpus in the
//! repository while putting only accepted numeric ranges in the binary. No
//! runtime file access, allocation, initialization lock or host Unicode library
//! is involved. Update the Unicode backend pins together with this data.
//!
//! Source: https://unicode.org/Public/idna/idna2008derived/Idna2008-16.0.0.txt
//! SHA-256: b83a25cd1511077910ddb431d0744ea4fa7cee01e103b3e62f1a19df2866bfa3
//! Unicode-3.0 terms are retained in data/LICENSE-UNICODE.

const DATA: &[u8] = include_bytes!("data/Idna2008-16.0.0.txt");

const fn word_at(offset: usize, word: &[u8]) -> bool {
    if offset + word.len() > DATA.len() {
        return false;
    }
    let mut index = 0;
    while index < word.len() {
        if DATA[offset + index] != word[index] {
            return false;
        }
        index += 1;
    }
    true
}

const fn hex_digit(byte: u8) -> u32 {
    match byte {
        b'0'..=b'9' => (byte - b'0') as u32,
        b'A'..=b'F' => (byte - b'A' + 10) as u32,
        _ => panic!("invalid Unicode IDNA2008 range"),
    }
}

// Return the next line offset and its accepted range, if any. Data includes
// every scalar as PVALID, CONTEXTJ, CONTEXTO, DISALLOWED or UNASSIGNED.
const fn next_range(mut offset: usize) -> (usize, Option<(u32, u32)>) {
    let start = offset;
    while offset < DATA.len() && DATA[offset] != b'\n' {
        offset += 1;
    }
    let end = offset;
    let next = if offset < DATA.len() {
        offset + 1
    } else {
        offset
    };
    if start == end || DATA[start] == b'#' {
        return (next, None);
    }
    let mut position = start;
    let mut first = 0;
    while position < end && matches!(DATA[position], b'0'..=b'9' | b'A'..=b'F') {
        first = first * 16 + hex_digit(DATA[position]);
        position += 1;
    }
    let mut last = first;
    if position < end && DATA[position] == b'.' {
        position += 2;
        last = 0;
        while position < end && matches!(DATA[position], b'0'..=b'9' | b'A'..=b'F') {
            last = last * 16 + hex_digit(DATA[position]);
            position += 1;
        }
    }
    while position < end && DATA[position] != b';' {
        position += 1;
    }
    position += 1;
    while position < end && DATA[position] == b' ' {
        position += 1;
    }
    if word_at(position, b"PVALID")
        || word_at(position, b"CONTEXTJ")
        || word_at(position, b"CONTEXTO")
    {
        assert!(first <= last && last <= 0x10ffff);
        (next, Some((first, last)))
    } else {
        assert!(word_at(position, b"DISALLOWED") || word_at(position, b"UNASSIGNED"));
        (next, None)
    }
}

const fn range_count() -> usize {
    let mut offset = 0;
    let mut count = 0;
    while offset < DATA.len() {
        let (next, range) = next_range(offset);
        offset = next;
        if range.is_some() {
            count += 1;
        }
    }
    count
}

const RANGE_COUNT: usize = range_count();

const fn ranges() -> [(u32, u32); RANGE_COUNT] {
    let mut output = [(0, 0); RANGE_COUNT];
    let mut offset = 0;
    let mut index = 0;
    while offset < DATA.len() {
        let (next, range) = next_range(offset);
        offset = next;
        if let Some(range) = range {
            if index != 0 {
                assert!(output[index - 1].1 < range.0);
            }
            output[index] = range;
            index += 1;
        }
    }
    output
}

const RANGES: [(u32, u32); RANGE_COUNT] = ranges();

pub(super) fn allowed(character: char) -> bool {
    let value = u32::from(character);
    RANGES
        .binary_search_by(|&(first, last)| {
            if value < first {
                core::cmp::Ordering::Greater
            } else if value > last {
                core::cmp::Ordering::Less
            } else {
                core::cmp::Ordering::Equal
            }
        })
        .is_ok()
}
