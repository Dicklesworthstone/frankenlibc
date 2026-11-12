//! Diff rendering for fixture comparison.

/// Render the raw companion `ftui_harness::diff_text` line delta when `frankentui-ui` is enabled.
#[cfg(feature = "frankentui-ui")]
#[must_use]
pub fn render_ftui_raw_diff(expected: &str, actual: &str) -> String {
    ftui_harness::diff_text(expected, actual)
}

/// Render a text diff between expected and actual output.
#[must_use]
pub fn render_diff(expected: &str, actual: &str) -> String {
    if expected == actual {
        #[cfg(feature = "frankentui-ui")]
        debug_assert!(ftui_harness::diff_text(expected, actual).is_empty());
        return String::from("[identical]");
    }

    #[cfg(feature = "frankentui-ui")]
    let _ftui_raw = ftui_harness::diff_text(expected, actual);

    let mut out = String::new();
    out.push_str("--- expected\n");
    out.push_str("+++ actual\n");

    let exp_lines: Vec<&str> = expected.lines().collect();
    let act_lines: Vec<&str> = actual.lines().collect();
    let max_lines = exp_lines.len().max(act_lines.len());

    for i in 0..max_lines {
        let e = exp_lines.get(i).copied().unwrap_or("");
        let a = act_lines.get(i).copied().unwrap_or("");
        let e_missing = i >= exp_lines.len();
        let a_missing = i >= act_lines.len();

        if e != a || e_missing || a_missing {
            out.push_str(&format!("@@ line {} @@\n", i + 1));
            if a_missing {
                out.push_str(&format!("-{e}\n"));
                out.push_str("+[missing]\n");
            } else if e_missing {
                out.push_str("-[missing]\n");
                out.push_str(&format!("+{a}\n"));
            } else {
                out.push_str(&format!("-{e}\n"));
                out.push_str(&format!("+{a}\n"));
            }
        }
    }

    if expected.ends_with('\n') != actual.ends_with('\n') {
        let trailing_line = max_lines.max(1);
        out.push_str(&format!("@@ line {trailing_line} (trailing newline) @@\n"));
        if expected.ends_with('\n') {
            out.push_str("+\\ No newline at end of file\n");
        } else {
            out.push_str("-\\ No newline at end of file\n");
        }
    }
    out
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

    #[test]
    fn diff_expected_longer_than_actual() {
        let expected = "line1\nline2\nline3\nline4";
        let actual = "line1\nline2";
        let diff = render_diff(expected, actual);
        // Lines 3 and 4 are missing from actual — must be reported.
        assert!(diff.contains("@@ line 3 @@"), "missing line 3 not reported");
        assert!(diff.contains("-line3"), "expected line3 not shown");
        assert!(diff.contains("@@ line 4 @@"), "missing line 4 not reported");
        assert!(diff.contains("-line4"), "expected line4 not shown");
    }

    #[test]
    fn diff_actual_longer_than_expected() {
        let expected = "line1";
        let actual = "line1\nextra";
        let diff = render_diff(expected, actual);
        assert!(diff.contains("@@ line 2 @@"), "extra line not reported");
        assert!(diff.contains("+extra"), "extra line not shown");
    }

    #[test]
    fn trailing_newline_mismatch_renders_explicit_difference() {
        let missing_actual_nl = render_diff("alpha\n", "alpha");
        assert_ne!(missing_actual_nl, "[identical]");
        assert!(missing_actual_nl.contains("trailing newline"));
        assert!(missing_actual_nl.contains("+\\ No newline at end of file"));

        let missing_expected_nl = render_diff("alpha", "alpha\n");
        assert_ne!(missing_expected_nl, "[identical]");
        assert!(missing_expected_nl.contains("trailing newline"));
        assert!(missing_expected_nl.contains("-\\ No newline at end of file"));
    }
}
