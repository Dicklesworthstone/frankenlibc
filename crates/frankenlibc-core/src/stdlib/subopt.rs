//! `getsubopt` — parse suboption arguments from a string.
//!
//! Implements the POSIX `getsubopt()` function which parses comma-separated
//! suboptions from an option argument string.

/// `getsubopt` — parse a suboption from a comma-delimited string.
///
/// `optionp`: mutable reference to the remaining option string (advanced past consumed token).
/// `tokens`: list of recognized suboption names.
///
/// Returns `(token_index, value)` where:
/// - `token_index` is the index into `tokens` of the matched token, or -1 if unrecognized.
/// - `value` is the part after '=' if present, or empty.
/// - `optionp` is advanced past the consumed suboption (and its trailing comma).
pub fn getsubopt<'a>(optionp: &mut &'a [u8], tokens: &[&[u8]]) -> (i32, &'a [u8]) {
    if optionp.is_empty() || optionp[0] == 0 {
        return (-1, &[]);
    }

    // Find the end of this suboption (comma or NUL).
    let end = optionp
        .iter()
        .position(|&c| c == b',' || c == 0)
        .unwrap_or(optionp.len());

    let suboption = &optionp[..end];

    // Find '=' separator for value.
    let eq_pos = suboption.iter().position(|&c| c == b'=');
    let (name, value) = match eq_pos {
        Some(pos) => (&suboption[..pos], &suboption[pos + 1..]),
        None => (suboption, &[][..]),
    };

    // Advance past this suboption.
    if end < optionp.len() && optionp[end] == b',' {
        *optionp = &optionp[end + 1..];
    } else {
        *optionp = &optionp[end..];
    }

    // Match against tokens.
    for (i, token) in tokens.iter().enumerate() {
        if name == *token {
            return (i as i32, value);
        }
    }

    (-1, value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_getsubopt_basic() {
        let tokens: &[&[u8]] = &[b"ro", b"rw", b"size"];
        let input = b"rw,size=1024,ro";
        let mut remaining: &[u8] = input;

        let (idx, val) = getsubopt(&mut remaining, tokens);
        assert_eq!(idx, 1); // "rw"
        assert!(val.is_empty());

        let (idx, val) = getsubopt(&mut remaining, tokens);
        assert_eq!(idx, 2); // "size"
        assert_eq!(val, b"1024");

        let (idx, val) = getsubopt(&mut remaining, tokens);
        assert_eq!(idx, 0); // "ro"
        assert!(val.is_empty());
    }

    #[test]
    fn test_getsubopt_unknown() {
        let tokens: &[&[u8]] = &[b"foo", b"bar"];
        let mut remaining: &[u8] = b"baz";
        let (idx, _) = getsubopt(&mut remaining, tokens);
        assert_eq!(idx, -1);
    }

    #[test]
    fn test_getsubopt_empty() {
        let tokens: &[&[u8]] = &[b"foo"];
        let mut remaining: &[u8] = b"";
        let (idx, _) = getsubopt(&mut remaining, tokens);
        assert_eq!(idx, -1);
    }
}
