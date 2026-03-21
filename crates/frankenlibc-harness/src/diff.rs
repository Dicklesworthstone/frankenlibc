//! Diff rendering for fixture comparison.

/// Render a text diff between expected and actual output.
#[must_use]
pub fn render_diff(expected: &str, actual: &str) -> String {
    #[cfg(feature = "frankentui-ui")]
    {
        #[allow(clippy::needless_return)]
        return ftui_harness::diff_text(expected, actual);
    }

    #[cfg(not(feature = "frankentui-ui"))]
    {
        if expected == actual {
            return String::from("[identical]");
        }

        let mut out = String::new();
        out.push_str("--- expected\n");
        out.push_str("+++ actual\n");
        for (i, (e, a)) in expected.lines().zip(actual.lines()).enumerate() {
            if e != a {
                out.push_str(&format!("@@ line {} @@\n", i + 1));
                out.push_str(&format!("-{e}\n"));
                out.push_str(&format!("+{a}\n"));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_strings_produce_identical_marker() {
        let diff = render_diff("hello", "hello");
        assert_eq!(diff, "[identical]");
    }

    #[test]
    fn identical_multiline_produces_identical_marker() {
        let diff = render_diff("line1\nline2\nline3", "line1\nline2\nline3");
        assert_eq!(diff, "[identical]");
    }

    #[test]
    fn empty_identical_strings() {
        let diff = render_diff("", "");
        assert_eq!(diff, "[identical]");
    }

    #[test]
    fn single_line_diff() {
        let diff = render_diff("hello", "world");
        assert!(diff.contains("--- expected"));
        assert!(diff.contains("+++ actual"));
        assert!(diff.contains("-hello"));
        assert!(diff.contains("+world"));
    }

    #[test]
    fn multiline_diff_shows_changed_lines_only() {
        let expected = "line1\nline2\nline3";
        let actual = "line1\nCHANGED\nline3";
        let diff = render_diff(expected, actual);
        assert!(diff.contains("@@ line 2 @@"));
        assert!(diff.contains("-line2"));
        assert!(diff.contains("+CHANGED"));
        // Unchanged lines should not appear
        assert!(!diff.contains("-line1"));
        assert!(!diff.contains("-line3"));
    }

    #[test]
    fn diff_header_present_when_different() {
        let diff = render_diff("a", "b");
        assert!(diff.starts_with("--- expected\n+++ actual\n"));
    }

    #[test]
    fn diff_all_lines_changed() {
        let expected = "a\nb\nc";
        let actual = "x\ny\nz";
        let diff = render_diff(expected, actual);
        assert!(diff.contains("@@ line 1 @@"));
        assert!(diff.contains("@@ line 2 @@"));
        assert!(diff.contains("@@ line 3 @@"));
    }
}
