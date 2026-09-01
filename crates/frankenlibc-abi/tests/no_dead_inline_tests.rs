//! Ratchet: a module declared `#[cfg(not(test))]` must not contain an inline
//! `#[cfg(test)]` block (bd-0z7a1y).
//!
//! `crates/frankenlibc-abi/src/lib.rs` gates most ABI modules with
//! `#[cfg(not(test))] pub mod <name>;`. An inner `#[cfg(test)]` block in such a
//! module is dead BY CONSTRUCTION — the two cfgs are mutually exclusive, so the
//! block compiles in neither build. Tests written there never run, never appear
//! in `cargo test -p frankenlibc-abi --lib -- --list`, and are never reported as
//! skipped. That is the failure mode that hid 293 tests for weeks (bd-r71n1b),
//! reached here through a cfg pair rather than a link error.
//!
//! This is a RATCHET, not a clean bill of health. The modules in
//! `KNOWN_DEAD_INLINE_TESTS` already carry the pattern and are recorded as debt
//! with their `#[test]` counts; the test fails if a module NOT on that list
//! acquires it, if a listed module is cleaned up but left on the list, and — as
//! of 2026-09-01 — if a listed module's count moves in EITHER direction. So the
//! list cannot rot into a permanent excuse, and it also cannot quietly absorb
//! new dead tests written into a block that is already known to be dead, which
//! is how `iconv_abi` and `stdio_abi` grew by three between them while every
//! assertion here stayed green.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Modules still carrying dead inline `#[cfg(test)]` blocks, with the number of
/// `#[test]` functions stranded in each. 54 when this ratchet was introduced
/// across 11 modules; 23 across 5 today. Burning these down is tracked separately —
/// each needs its assertions moved to `crates/frankenlibc-abi/tests/`, which is
/// not mechanical because many touch module-private items.
/// `err_abi` and `malloc_abi` are deliberately ABSENT: their only occurrences of
/// the attribute are inside COMMENTS (err_abi's comment records this very trap,
/// per bd-ul4pyl). A first pass of this survey counted them because it scanned
/// raw text — the same comment-blindness the support-matrix scanner had in
/// bd-4habm0 — and the ratchet's own `cleaned` check caught the mistake.
/// The counts are ASSERTED, not decorative — see
/// `known_dead_inline_test_counts_have_not_grown`. They were decorative until
/// 2026-09-01, and in that window `iconv_abi` grew 6 -> 7 and `stdio_abi` 6 -> 8
/// with nothing to notice: the ratchet only ever asked whether a module HAS a
/// dead block, so three more tests were written into blocks already known to be
/// dead and the debt total silently drifted from 27 to 30.
const KNOWN_DEAD_INLINE_TESTS: &[(&str, usize)] = &[
    ("glibc_internal_abi", 2),
    ("iconv_abi", 7),
    ("io_internal_abi", 5),
    ("pthread_abi", 6),
    ("stdio_abi", 3),
];
// BURNED DOWN (bd-xh08pf):
//   fenv_abi (11)      -> 10 retired against existing coverage in
//                         tests/fenv_abi_test.rs and tests/conformance_fenv_traps.rs
//                         (per-test map left in fenv_abi.rs); the 11th, the
//                         FE_DFL_ENV sentinel path, was genuinely uncovered and is
//                         now tests/fenv_abi_test.rs::
//                         fesetenv_with_fe_dfl_env_resets_to_default_rounding
//   wchar_abi (2)      -> tests/wchar_abi_test.rs::swprintf_wide_format_replaces_invalid_codepoint
//                         and ::swprintf_reused_format_buffer_does_not_leak_between_calls
//                         (rewritten through swprintf; the originals drove the
//                          private pooled converter directly)
//   grp_abi (2)        -> tests/grp_abi_test.rs::getgrent_skips_malformed_and_comment_lines
//                         and ::getgrent_restarts_when_the_group_file_changes_mid_iteration
//                         (rewritten against the public ABI, not relocated: the
//                          originals read GrpStorage internals. The restart test
//                          was verified by mutation — deleting BOTH iter_idx
//                          resets makes it fail with the stale entry.)
//   unistd_abi (1)     -> tests/resolv_abi_test.rs::res_init_reports_success_bd_xh08pf
//                         (pure relocation; only touched the public `res_init`)
//   c11threads_abi (5) -> tests/c11threads_abi_test.rs
//                         (3 relocated unchanged; 2 rewritten against public
//                          entry points instead of widening the ABI surface to
//                          reach `pthread_rc_to_thrd` and the THRD_*/MTX_*
//                          constants)
//   termios_abi (6)    -> tests/termios_abi_test.rs::
//                         cfsetospeed_records_illegal_cooked_speed_transition
//                         and ::tcsetattr_cbreak_raw_restore_sequence_on_pty
//                         (rewritten through public ABI calls; the originals
//                          inspected private tracker state directly)
//   unistd_abi, AGAIN (1) -> and the repeat is the point: this module appears
//                         TWICE in this list. It was burned down once (the
//                         res_init entry above), and a NEW dead #[cfg(test)] mod
//                         getrandom_tests was later written into it. That is the
//                         regression `no_new_module_gains_a_dead_inline_test_block`
//                         exists for, and it caught it — the ratchet had been
//                         RED on unistd_abi since roughly 2026-08-24.
//                         RETIRED, not relocated. Its one test asserted
//                         strict_getrandom_passthrough(NULL, 0, 0) == 0, and the
//                         public getrandom short-circuits `buflen == 0 &&
//                         flags == 0` with an immediate return BEFORE consulting
//                         strict_passthrough_active() — so that helper is
//                         unreachable with those arguments and the test pinned a
//                         branch production cannot enter. The reachable half,
//                         (NULL, 0, nonzero_flags), is covered against LIVE
//                         glibc by tests/conformance_diff_vdso_getrandom.rs::
//                         fl_getrandom_zero_length_and_invalid_flags_match_live_glibc
//                         and tests/conformance_diff_getrandom.rs::
//                         diff_getrandom_zero_length_null_and_flag_contract.
//                         A per-test map is left in unistd_abi.rs where the
//                         block stood.
//   glibc_internal_abi, HALF (2 of 4) -> tests/conformance_diff_hostname_id.rs::
//                         sethostid_rejects_out_of_32_bit_range_like_glibc
//                         (rewritten against the public entry point; the
//                          originals drove the private hostid_to_i32). The
//                          module's OTHER dead block, adjtime_abi_tests, is not
//                          burned down: its two helpers convert between a
//                          `struct timeval` delta and microseconds, and the only
//                          public route to the setting direction is `adjtime`,
//                          which CHANGES THE SYSTEM CLOCK. These tests run on
//                          shared rch workers; skewing a build worker's clock to
//                          cover a unit conversion is not a trade worth making,
//                          and the read-only route (`adjtime(NULL, &old)`)
//                          reaches only one of the two helpers. It needs a
//                          different instrument, not more of this one.
//   stdio_abi, PARTIAL (2 of 8) -> tests/conformance_diff_snprintf_fused.rs
//                         (rewritten against the public `snprintf` and LIVE
//                          glibc; the originals drove the private
//                          `is_strict_direct_snprintf_format` and
//                          `StrictDirectSnprintfWriter`). Motivated: the fused
//                          emitter was deleted 2026-08-03 and not restored until
//                          2026-08-30, and for that month these two dead tests
//                          were the only ones naming it.
//   stdio_abi, PARTIAL again (3 more of 8) -> tests/conformance_diff_printf_direct.rs
//                         (the three printf_direct_* tests, rewritten against
//                          the public snprintf/fprintf and live glibc; the
//                          stream arm uses a temp file, NOT stdout capture,
//                          which is flaky under libtest parallelism)
// 54 -> 23 stranded tests, 11 -> 5 modules.

fn src_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

/// Blank out `//` and `/* */` comments before scanning for the attribute.
///
/// Without this the ratchet reports a module that merely *documents* the trap —
/// including efun_abi.rs, whose replacement comment quotes the attribute it is
/// warning about. Same comment-blindness defect as bd-4habm0, where the
/// support-matrix scanner counted a doc comment as a host call.
fn strip_comments(text: &str) -> String {
    let b = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'/' && i + 1 < b.len() && b[i + 1] == b'/' {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
        } else if b[i] == b'/' && i + 1 < b.len() && b[i + 1] == b'*' {
            i += 2;
            while i + 1 < b.len() && !(b[i] == b'*' && b[i + 1] == b'/') {
                i += 1;
            }
            i = (i + 2).min(b.len());
        } else {
            out.push(b[i] as char);
            i += 1;
        }
    }
    out
}

/// Does this module carry a real (non-comment) inline `#[cfg(test)]` block?
fn has_dead_inline_block(text: &str) -> bool {
    strip_comments(text).contains("#[cfg(test)]")
}

/// Module names declared `#[cfg(not(test))] pub mod <name>;` in lib.rs.
fn gated_modules() -> BTreeSet<String> {
    let lib = std::fs::read_to_string(src_dir().join("lib.rs")).expect("read lib.rs");
    let lines: Vec<&str> = lib.lines().collect();
    let mut out = BTreeSet::new();
    for (i, line) in lines.iter().enumerate() {
        if !line.contains("cfg(not(test))") {
            continue;
        }
        // The declaration is on one of the next couple of lines (other
        // attributes may intervene).
        for probe in lines.iter().skip(i + 1).take(3) {
            let t = probe.trim();
            if let Some(rest) = t.strip_prefix("pub mod ")
                && let Some(name) = rest.strip_suffix(';')
            {
                out.insert(name.to_string());
                break;
            }
            if !t.starts_with('#') {
                break;
            }
        }
    }
    assert!(
        out.len() > 20,
        "only {} gated modules found; the lib.rs parse is probably broken, \
         which would make this ratchet vacuous",
        out.len()
    );
    out
}

#[test]
fn no_new_module_gains_a_dead_inline_test_block() {
    let known: BTreeSet<&str> = KNOWN_DEAD_INLINE_TESTS.iter().map(|(m, _)| *m).collect();
    let mut offenders = Vec::new();
    let mut cleaned = Vec::new();

    for module in gated_modules() {
        let path = src_dir().join(format!("{module}.rs"));
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue; // directory module or otherwise not a single file
        };
        let has_dead_block = has_dead_inline_block(&text);
        let listed = known.contains(module.as_str());

        if has_dead_block && !listed {
            let n = strip_comments(&text).matches("#[test]").count();
            offenders.push(format!(
                "{module} ({n} #[test] fns stranded) — this module is \
                 #[cfg(not(test))] in lib.rs, so its #[cfg(test)] block can \
                 never compile"
            ));
        }
        if !has_dead_block && listed {
            cleaned.push(module);
        }
    }

    assert!(
        offenders.is_empty(),
        "new dead inline test block(s) added to #[cfg(not(test))] module(s):\n  {}\n\
         Put the assertions in crates/frankenlibc-abi/tests/ instead, where they \
         actually run.",
        offenders.join("\n  ")
    );
    assert!(
        cleaned.is_empty(),
        "these modules no longer contain a dead #[cfg(test)] block and must be \
         REMOVED from KNOWN_DEAD_INLINE_TESTS so the ratchet keeps tightening: {cleaned:?}"
    );
}

/// The debt list must describe reality: every listed module has to exist and
/// still be gated, otherwise the list is quietly protecting nothing.
#[test]
fn known_dead_inline_test_list_is_accurate() {
    let gated = gated_modules();
    for (module, _) in KNOWN_DEAD_INLINE_TESTS {
        assert!(
            gated.contains(*module),
            "{module} is on the known-dead list but is not #[cfg(not(test))]-gated \
             in lib.rs; the list is stale"
        );
        let path = src_dir().join(format!("{module}.rs"));
        assert!(path.is_file(), "{module}.rs listed but missing at {path:?}");
    }
}

/// A listed module may not GROW. Without this the ratchet is one-sided: it
/// catches a module acquiring a dead block and catches one being cleaned but
/// left listed, and says nothing at all about writing more tests into a block
/// already known to be dead. That is not hypothetical — between this file's
/// introduction and 2026-09-01, `iconv_abi` went 6 -> 7 and `stdio_abi` 6 -> 8
/// while every assertion here stayed green, because the counts in
/// `KNOWN_DEAD_INLINE_TESTS` were never read.
///
/// The check is one-directional on purpose. Growth fails. SHRINKAGE also fails,
/// with a different message, because a burn-down that forgets to lower the
/// number leaves the list overstating the debt and hides the next regression
/// underneath the slack.
#[test]
fn known_dead_inline_test_counts_have_not_grown() {
    let mut wrong = Vec::new();
    for (module, recorded) in KNOWN_DEAD_INLINE_TESTS {
        let path = src_dir().join(format!("{module}.rs"));
        let text = std::fs::read_to_string(&path).expect("read listed module");
        let actual = strip_comments(&text).matches("#[test]").count();
        if actual > *recorded {
            let n = actual - recorded;
            wrong.push(format!(
                "{module}: {actual} dead #[test] fns, list says {recorded} — {n} \
                 {} ADDED to a block that already could not compile. Put {} in \
                 crates/frankenlibc-abi/tests/ instead.",
                if n == 1 { "was" } else { "were" },
                if n == 1 { "it" } else { "them" },
            ));
        } else if actual < *recorded {
            let n = recorded - actual;
            wrong.push(format!(
                "{module}: {actual} dead #[test] fns, list says {recorded} — the \
                 burn-down landed but the count was not lowered, so the list now \
                 overstates the debt and would hide {n} new dead {}.",
                if n == 1 { "test" } else { "tests" },
            ));
        }
    }
    assert!(wrong.is_empty(), "KNOWN_DEAD_INLINE_TESTS is out of date:\n  {}", wrong.join("\n  "));
}

/// The module this bead named must be clean: its dead `test_helpers` block is
/// gone and its real coverage lives in `tests/efun_abi_test.rs`.
#[test]
fn efun_abi_has_no_dead_inline_block() {
    let text = std::fs::read_to_string(src_dir().join("efun_abi.rs")).expect("read efun_abi.rs");
    assert!(
        !has_dead_inline_block(&text),
        "efun_abi.rs regained a #[cfg(test)] block; it is #[cfg(not(test))]-gated, \
         so the block cannot compile"
    );
}
