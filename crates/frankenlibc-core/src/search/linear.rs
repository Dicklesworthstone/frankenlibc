//! POSIX `lsearch` / `lfind` linear-search algorithm.
//!
//! Operates on a `&[u8]` view of the user's array so no unsafe is
//! required in core. The abi layer adapts raw `*const c_void` and a
//! C comparator into a closure passed here.

/// POSIX `lfind` — linear scan over `nel` fixed-width records.
///
/// `base` is the underlying byte buffer (must be at least
/// `nel * width` bytes). `matches(record_bytes, idx)` is called for
/// each record; returning `true` selects that record's index.
///
/// Returns the matching index or `None`.
pub fn lfind_index<F: FnMut(&[u8], usize) -> bool>(
    base: &[u8],
    width: usize,
    nel: usize,
    mut matches: F,
) -> Option<usize> {
    if width == 0 {
        return None;
    }
    if nel
        .checked_mul(width)
        .map(|n| n > base.len())
        .unwrap_or(true)
    {
        // Defensive: caller's nel*width exceeds the slice we were given.
        return None;
    }
    for i in 0..nel {
        let start = i * width;
        let end = start + width;
        if matches(&base[start..end], i) {
            return Some(i);
        }
    }
    None
}

/// POSIX `lsearch` semantics — find or append.
///
/// Like [`lfind_index`] but if no match is found, returns
/// `Some(nel)` (the index just past the last existing record) so the
/// caller can append a new record there. The append itself happens
/// in the caller (since it requires a mutable buffer with extra
/// capacity, owned by the user, not by us).
pub fn lsearch_or_append_index<F: FnMut(&[u8], usize) -> bool>(
    base: &[u8],
    width: usize,
    nel: usize,
    matches: F,
) -> SearchOrAppend {
    match lfind_index(base, width, nel, matches) {
        Some(idx) => SearchOrAppend::Found(idx),
        None => SearchOrAppend::AppendAt(nel),
    }
}

/// Outcome of [`lsearch_or_append_index`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SearchOrAppend {
    /// Existing record matched at this index.
    Found(usize),
    /// No match; append a new record at this index.
    AppendAt(usize),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_eq_first_byte(target: u8) -> impl FnMut(&[u8], usize) -> bool {
        move |rec, _| rec.first().copied() == Some(target)
    }

    #[test]
    fn lfind_finds_existing() {
        let base = [10u8, 20, 30, 40, 50];
        assert_eq!(lfind_index(&base, 1, 5, key_eq_first_byte(30)), Some(2));
    }

    #[test]
    fn lfind_misses_returns_none() {
        let base = [10u8, 20, 30];
        assert_eq!(lfind_index(&base, 1, 3, key_eq_first_byte(99)), None);
    }

    #[test]
    fn lfind_zero_width_returns_none() {
        let base = [10u8, 20];
        assert_eq!(lfind_index(&base, 0, 2, |_, _| true), None);
    }

    #[test]
    fn lfind_oversize_nel_returns_none() {
        let base = [10u8, 20];
        assert_eq!(lfind_index(&base, 1, 99, |_, _| true), None);
    }

    #[test]
    fn lsearch_existing_returns_found() {
        let base = [10u8, 20, 30];
        assert_eq!(
            lsearch_or_append_index(&base, 1, 3, key_eq_first_byte(20)),
            SearchOrAppend::Found(1)
        );
    }

    #[test]
    fn lsearch_missing_returns_append_at_end() {
        let base = [10u8, 20, 30, 0, 0]; // 5-byte buffer with 3 elements
        assert_eq!(
            lsearch_or_append_index(&base, 1, 3, key_eq_first_byte(99)),
            SearchOrAppend::AppendAt(3)
        );
    }

    #[test]
    fn lfind_multibyte_records() {
        // 3 records of 4 bytes each: [1,2,3,4] [5,6,7,8] [9,10,11,12]
        let base: Vec<u8> = (1..=12).collect();
        assert_eq!(
            lfind_index(&base, 4, 3, |rec, _| rec == [5, 6, 7, 8]),
            Some(1)
        );
    }
}
