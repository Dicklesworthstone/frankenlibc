//! Differential probe: frankenlibc regex capture-group offsets vs glibc
//! regexec(nmatch>1). Exercises POSIX submatch semantics — unmatched groups
//! (-1,-1), leftmost-longest alternation, last-iteration of a repeated group,
//! greedy quantifiers, and nested groups. glibc reference (rm_so,rm_eo per
//! group) captured from a C probe.

use frankenlibc_core::string::regex::{REG_EXTENDED, RegMatch, regex_compile, regex_exec};

struct Case {
    pat: &'static str,
    ngroups: usize,
    input: &'static str,
}

fn run(c: &Case) -> String {
    let compiled = match regex_compile(c.pat.as_bytes(), REG_EXTENDED) {
        Ok(c) => c,
        Err(_) => return "ERR".to_string(),
    };
    let mut m = [RegMatch {
        rm_so: -1,
        rm_eo: -1,
    }; 16];
    let r = regex_exec(&compiled, c.input.as_bytes(), &mut m, 0);
    if r != 0 {
        return "NOMATCH".to_string();
    }
    (0..=c.ngroups)
        .map(|g| format!("{},{}", m[g].rm_so, m[g].rm_eo))
        .collect::<Vec<_>>()
        .join(" ")
}

#[test]
fn regex_capture_differential_battery() {
    macro_rules! c {
        ($p:expr, $n:expr, $i:expr) => {
            Case {
                pat: $p,
                ngroups: $n,
                input: $i,
            }
        };
    }
    let cases = [
        c!("(a)(b)(c)", 3, "abc"),
        c!("(a)|(b)", 2, "b"),
        c!("(a*)(b*)", 2, "aabb"),
        c!("(a|ab)(c|bcd)", 2, "abcd"),
        c!("(ab)*", 1, "ababab"),
        c!("(a)(b)?", 2, "a"),
        c!("((a)(b))", 3, "ab"),
        c!("(foo|foobar)", 1, "foobar"),
        c!("x(y)?z", 1, "xz"),
        c!("(a+)(a+)", 2, "aaaa"),
        c!("(a)(b)(c)(d)", 4, "abcd"),
        c!("(.*)(b)", 2, "abab"),
    ];
    let glibc = [
        "0,3 0,1 1,2 2,3",
        "0,1 -1,-1 0,1",
        "0,4 0,2 2,4",
        "0,4 0,1 1,4",
        "0,6 4,6",
        "0,1 0,1 -1,-1",
        "0,2 0,2 0,1 1,2",
        "0,6 0,6",
        "0,2 -1,-1",
        "0,4 0,3 3,4",
        "0,4 0,1 1,2 2,3 3,4",
        "0,4 0,3 3,4",
    ];

    assert_eq!(cases.len(), glibc.len(), "battery length mismatch");

    let mut diffs = Vec::new();
    for (i, c) in cases.iter().enumerate() {
        let got = run(c);
        if got != glibc[i] {
            diffs.push(format!(
                "case {i}: pat={:?} in={:?} -> frankenlibc={got:?} glibc={:?}",
                c.pat, c.input, glibc[i]
            ));
        }
    }
    assert!(
        diffs.is_empty(),
        "regex capture groups diverge from glibc in {} case(s):\n{}",
        diffs.len(),
        diffs.join("\n")
    );
}
