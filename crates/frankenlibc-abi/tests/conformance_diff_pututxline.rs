#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc utmpx oracle + real temp utmp files

//! Differential gate for pututxline overwrite-vs-append (bd-mx8ikd). Writing a
//! record and then writing it again with the SAME ut_id must OVERWRITE in place
//! (1 record on disk), not append a duplicate; two DISTINCT ut_ids must produce
//! two records. fl must match host glibc on the resulting file size. fl and
//! glibc keep independent utmp state (separate utmpxname paths), so the two are
//! driven on separate temp files. No mocks.
//!
//! ## Every arm owns a private ut_id / ut_line namespace — do not reuse (bd-hdb4c3)
//!
//! glibc caches the LAST RECORD it wrote in process-global state, and that
//! cache survives `endutxent()`, `utmpxname()` and `setutxent()`. The next
//! `pututxline` consults it through the same matching rule the on-disk search
//! uses, so a record written by an EARLIER TEST can decide whether a later
//! test's first write appends or replaces. Nothing in the file API resets it.
//!
//! That made `pututxline_same_id_without_rewind_appends` intermittently red:
//! its glibc arm returned 1 record instead of 2, i.e. the ORACLE's own premise
//! assertion failed and fl was never reached. Measured directly against live
//! glibc 2.42 by replaying "predecessor, then the arm" in one process — only
//! the two predecessors that also used `ut_id = "t1"` broke it:
//!
//! ```text
//!   cold (no predecessor)            -> 2   the documented behaviour
//!   after matches_on_id_over_line    -> 1   ut_id t1  <-- breaks
//!   after overwrites_same_id_after_rewind -> 1   ut_id t1  <-- breaks
//!   after dead_over_user (t2) / boot_type_only (bt,ZZ) /
//!         boot_then_runlvl (rl) / empty_id ("") / distinct_ids (t1 then t2)
//!                                    -> 2   no matching id, unaffected
//! ```
//!
//! Note distinct_ids WRITES t1 first and still does not break the arm: what
//! survives is the LAST record written, which for that arm is t2. Only a
//! predecessor whose final record matches decides the next arm's first write.
//!
//! It looked load-dependent only because libtest's thread scheduling decides
//! which arm runs first: alone it always passed, under `--test-threads=1`
//! (fixed alphabetical order, so both t1 arms run first) it always FAILED, and
//! with sibling binaries competing for CPU it failed intermittently. The
//! UTMPX_PATH_LOCK below is still required — it serialises the process-global
//! *path* — but serialising does not clear the record cache, which is why
//! hoisting that lock did not fix this.
//!
//! The fix is that each arm now uses ids and lines no other arm can match
//! (`a*` distinct, `b*` id-over-line, `c*` dead-over-user, `d*` boot, `e*`
//! empty-id, `f*` rewound, `g*` no-rewind), so no ordering can prime the cache
//! into a match. Verified against live glibc: every predecessor still produces
//! its own expected record count, and the no-rewind arm still yields 2 after
//! each one individually and after all of them in sequence. If you add an arm,
//! give it a fresh letter — reusing an id reintroduces this exactly.

use std::ffi::{CString, c_char, c_int};
use std::sync::atomic::{AtomicU64, Ordering};

mod g {
    use super::*;
    unsafe extern "C" {
        pub fn utmpxname(file: *const c_char) -> c_int;
        pub fn setutxent();
        pub fn pututxline(ut: *const libc::utmpx) -> *mut libc::utmpx;
        pub fn endutxent();
    }
}
use frankenlibc_abi::unistd_abi as fl;

/// Serialises every test in this file.
///
/// utmpxname sets a process-global path inside BOTH impls, so two of these
/// running concurrently each redirect the other. This lock used to live inside
/// `assert_same_file`, which covered only the four tests that go through it —
/// the two driven by `fl_run`/`glibc_run` took no lock at all and raced against
/// them. That made pututxline_same_id_without_rewind_appends intermittently
/// red: it failed in a nine-gate batch and passed when run with fewer.
///
/// Hoisted to module scope so both entry points share it. Poison-tolerant, and
/// acquired EXACTLY once per test — std's Mutex is not reentrant, so a helper
/// taking it again under a test that already holds it would deadlock.
static UTMPX_PATH_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn utmpx_guard() -> std::sync::MutexGuard<'static, ()> {
    UTMPX_PATH_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

static CNT: AtomicU64 = AtomicU64::new(0);
fn tmp_path(tag: &str) -> (std::path::PathBuf, CString) {
    let n = CNT.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!("fl-utmpx-{}-{}-{}", std::process::id(), tag, n));
    let _ = std::fs::remove_file(&p);
    // The file must EXIST and be empty. glibc's utmp file backend opens the
    // database O_RDWR without O_CREAT, so against a missing path every
    // pututxline returns NULL and the glibc arm silently writes nothing —
    // which is exactly what the "glibc wrote 0 records" premise assertions
    // below caught. fl opens with O_CREAT and so worked either way, meaning a
    // harness that skipped this compared fl against an arm that never ran.
    std::fs::write(&p, b"").expect("create empty scratch utmpx");
    let c = CString::new(p.to_string_lossy().as_bytes()).unwrap();
    (p, c)
}

fn rec(id: &[u8], line: &[u8], pid: c_int) -> libc::utmpx {
    let mut u: libc::utmpx = unsafe { std::mem::zeroed() };
    u.ut_type = libc::USER_PROCESS;
    u.ut_pid = pid;
    for (i, b) in id.iter().take(u.ut_id.len()).enumerate() {
        u.ut_id[i] = *b as c_char;
    }
    for (i, b) in line.iter().take(u.ut_line.len()).enumerate() {
        u.ut_line[i] = *b as c_char;
    }
    u
}

const RS: u64 = std::mem::size_of::<libc::utmpx>() as u64;

fn fl_run(seq: &[(&[u8], &[u8], c_int)]) -> u64 {
    let (path, c) = tmp_path("f");
    // Close any file a PREVIOUS test in this process left open before renaming.
    // utmpxname behaves differently depending on whether a database is
    // currently open, so without this the read cursor these semantics depend on
    // is inherited from whichever test ran before — which is what made
    // pututxline_same_id_without_rewind_appends intermittently red.
    unsafe { fl::endutxent() };
    unsafe { fl::utmpxname(c.as_ptr()) };
    unsafe { fl::setutxent() };
    for (id, line, pid) in seq {
        unsafe { fl::pututxline(&rec(id, line, *pid)) };
    }
    unsafe { fl::endutxent() };
    let len = std::fs::metadata(&path)
        .map(|m| m.len())
        .unwrap_or(u64::MAX);
    let _ = std::fs::remove_file(&path);
    len
}

fn glibc_run(seq: &[(&[u8], &[u8], c_int)]) -> u64 {
    let (path, c) = tmp_path("g");
    // See fl_run: drop any inherited open database before renaming, so the
    // oracle starts from a known cursor rather than the previous test's.
    unsafe { g::endutxent() };
    unsafe { g::utmpxname(c.as_ptr()) };
    unsafe { g::setutxent() };
    for (id, line, pid) in seq {
        unsafe { g::pututxline(&rec(id, line, *pid)) };
    }
    unsafe { g::endutxent() };
    let len = std::fs::metadata(&path)
        .map(|m| m.len())
        .unwrap_or(u64::MAX);
    let _ = std::fs::remove_file(&path);
    len
}

#[test]
fn pututxline_same_id_without_rewind_appends() {
    // Same ut_id twice with ONE setutxent() up front. This arm previously
    // asserted glibc collapses that to a single record; measured against live
    // glibc 2.42, it does NOT:
    //
    //   setutxent(); put(alice id=t1); put(bob id=t1)              -> TWO records
    //   setutxent(); put(alice id=t1); setutxent(); put(bob id=t1) -> ONE record
    //
    // pututxline searches from the CURRENT read cursor, and after the first
    // write the cursor is already past that record, so the second appends. The
    // overwrite case is pututxline_overwrites_same_id_after_rewind below.
    // Corrected premise, not a relaxed one: this still pins fl to glibc, and
    // the arm now fails for an implementation that ignores the cursor.
    //
    // The `g*` namespace is load-bearing — see the module docs. With `t1` here
    // this arm inherited glibc's record cache from whichever t1 arm libtest
    // happened to schedule first and asserted 1 == 2 (bd-hdb4c3).
    let _guard = utmpx_guard();
    let seq: &[(&[u8], &[u8], c_int)] = &[(b"g1", b"gt/1", 100), (b"g1", b"gt/1", 200)];
    let f = fl_run(seq);
    let gg = glibc_run(seq);
    assert_eq!(gg, 2 * RS, "glibc: same-id without a rewind appends");
    assert_eq!(
        f,
        gg,
        "fl produced {} records, glibc {} (RS={RS})",
        f / RS,
        gg / RS
    );
}

#[test]
fn pututxline_appends_distinct_ids() {
    // Distinct ut_ids -> two records. Private `a*` namespace (module docs).
    let _guard = utmpx_guard();
    let seq: &[(&[u8], &[u8], c_int)] = &[(b"a1", b"at/1", 100), (b"a2", b"at/2", 200)];
    let f = fl_run(seq);
    let gg = glibc_run(seq);
    assert_eq!(gg, 2 * RS, "glibc: distinct ids -> 2 records");
    assert_eq!(f, gg, "fl produced {} records, glibc {}", f / RS, gg / RS);
}

// ---------------------------------------------------------------------------
// bd-mx8ikd, remainder of the matching rule.
//
// The two arms above compare file SIZE only, and cover just the ut_id case.
// glibc's rule (internal_getut_r + __utmp_equal) has three parts, all measured
// against live glibc 2.42 on a scratch utmpx file before being asserted here:
//
//   * RUN_LVL/BOOT_TIME/OLD_TIME/NEW_TIME match on TYPE ALONE, ignoring ut_id;
//   * otherwise BOTH records must be in the process class (INIT/LOGIN/USER/
//     DEAD), which is why a DEAD_PROCESS overwrites the USER_PROCESS it closes
//     out -- the logout-after-login case that unbounded appending breaks;
//   * within that class ut_id decides when both are non-empty (so the same id
//     on a DIFFERENT line still matches and the stored line is updated), and
//     the comparison falls back to ut_line only when an id is empty.
//
// These arms also compare file CONTENTS, not just length: a size-only check
// passes an implementation that writes the right number of records with the
// wrong bytes in them, e.g. overwriting the wrong slot.
// ---------------------------------------------------------------------------

fn typed_rec(ut_type: i16, id: &[u8], line: &[u8], user: &[u8]) -> libc::utmpx {
    let mut u = rec(id, line, 1234);
    u.ut_type = ut_type;
    for (i, b) in user.iter().take(u.ut_user.len()).enumerate() {
        u.ut_user[i] = *b as c_char;
    }
    u
}

fn fl_bytes(seq: &[libc::utmpx]) -> Vec<u8> {
    let (path, c) = tmp_path("fb");
    unsafe { fl::utmpxname(c.as_ptr()) };
    for e in seq {
        unsafe {
            fl::setutxent();
            fl::pututxline(e);
        }
    }
    unsafe { fl::endutxent() };
    let out = std::fs::read(&path).unwrap_or_default();
    let _ = std::fs::remove_file(&path);
    out
}

fn glibc_bytes(seq: &[libc::utmpx]) -> Vec<u8> {
    let (path, c) = tmp_path("gb");
    unsafe { g::utmpxname(c.as_ptr()) };
    for e in seq {
        unsafe {
            g::setutxent();
            g::pututxline(e);
        }
    }
    unsafe { g::endutxent() };
    let out = std::fs::read(&path).unwrap_or_default();
    let _ = std::fs::remove_file(&path);
    out
}

/// Compare fl and glibc byte-for-byte over the same script.
///
/// Serialised: utmpxname sets a process-global path inside each impl, so two of
/// these running concurrently would each redirect the other.
fn assert_same_file(tag: &str, seq: &[libc::utmpx], expected_records: usize) {
    let _guard = utmpx_guard();

    let gg = glibc_bytes(seq);
    let f = fl_bytes(seq);
    let rs = RS as usize;
    assert_eq!(
        gg.len() / rs,
        expected_records,
        "[{tag}] glibc wrote {} records, expected {expected_records}: the arm's premise is \
         wrong, not fl",
        gg.len() / rs
    );
    assert_eq!(
        f.len() / rs,
        gg.len() / rs,
        "[{tag}] record COUNT differs: fl={} glibc={} (appending instead of overwriting \
         shows up here first)",
        f.len() / rs,
        gg.len() / rs
    );
    assert_eq!(f, gg, "[{tag}] record CONTENTS differ from glibc");
}

#[test]
fn pututxline_matches_on_id_over_line() {
    // Same id, DIFFERENT line: ut_id wins while both are non-empty, and the
    // stored ut_line is updated in place rather than a second record appearing.
    assert_same_file(
        "id_beats_line",
        &[
            typed_rec(libc::USER_PROCESS, b"b1", b"bt/1", b"alice"),
            typed_rec(libc::USER_PROCESS, b"b1", b"bt/X", b"dave"),
        ],
        1,
    );
}

#[test]
fn pututxline_dead_process_overwrites_the_user_process() {
    // Logout closing out a login: the case unbounded appending breaks, leaving
    // stale sessions visible to who(1).
    assert_same_file(
        "dead_over_user",
        &[
            typed_rec(libc::USER_PROCESS, b"c1", b"ct/1", b"carol"),
            typed_rec(libc::DEAD_PROCESS, b"c1", b"ct/1", b""),
        ],
        1,
    );
}

#[test]
fn pututxline_boot_time_matches_on_type_alone() {
    // BOOT_TIME ignores ut_id entirely: the second replaces the first even
    // though every string field differs.
    assert_same_file(
        "boot_type_only",
        &[
            typed_rec(libc::BOOT_TIME, b"d1", b"dt/1", b"reboot"),
            typed_rec(libc::BOOT_TIME, b"d2", b"dt/2", b"reboot2"),
        ],
        1,
    );
    // Control for that: a DIFFERENT type in the same family still appends, so
    // the arm is measuring type equality rather than "type-class always wins".
    assert_same_file(
        "boot_then_runlvl",
        &[
            typed_rec(libc::BOOT_TIME, b"d1", b"dt/1", b"reboot"),
            typed_rec(libc::RUN_LVL, b"d3", b"dt/3", b"runlevel"),
        ],
        2,
    );
}

#[test]
fn pututxline_falls_back_to_line_when_id_is_empty() {
    assert_same_file(
        "empty_id",
        &[
            typed_rec(libc::USER_PROCESS, b"", b"et/9", b"eve"),
            typed_rec(libc::USER_PROCESS, b"", b"et/9", b"frank"),
        ],
        1,
    );
}

#[test]
fn pututxline_overwrites_same_id_after_rewind() {
    // The counterpart to pututxline_same_id_without_rewind_appends: rewinding
    // before the second write makes it find and replace the first record.
    // Together the two arms pin the cursor semantics rather than just the
    // matching rule — an implementation that always searched from offset 0
    // would pass this one and fail its partner.
    assert_same_file(
        "same_id_rewound",
        &[
            typed_rec(libc::USER_PROCESS, b"f1", b"ft/1", b"alice"),
            typed_rec(libc::USER_PROCESS, b"f1", b"ft/1", b"bob"),
        ],
        1,
    );
}
