#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live libresolv oracle

//! Which RR types must `ns_sprintrrf` REFUSE rather than render generically.
//!
//! bd-9kuafg was filed against a single case — SOA with 3 bytes of rdata, where
//! glibc refuses and fl fell through to the RFC 3597 generic form — and stated
//! the fix as needing "glibc's known-type set". Probing says otherwise, and the
//! difference is the whole point of this gate.
//!
//! Sweeping every type 1..=299 through live `libresolv.so.2` with a valid
//! message and a deliberately malformed 3-byte rdata:
//!
//! ```text
//!   REFUSED: 2 5 6 7 8 9 12 14 15 17 18 21 26 39 249 250
//!   GENERIC: everything else, INCLUDING A(1), AAAA(28) and TXT(16)
//! ```
//!
//! A, AAAA and TXT are types glibc plainly knows — it has formatters for all
//! three — and it still renders them generically when the rdata does not fit.
//! So knownness does not decide it. Every refusing type embeds a DOMAIN NAME in
//! its rdata, and the refusal is name decompression failing, which is a hard
//! error rather than a formatting mismatch.
//!
//! The sweep is re-run here rather than pinned as a list alone, so a libresolv
//! that changes its mind fails this gate instead of silently disagreeing with
//! the sixteen-entry rule fl now implements.

use std::ffi::{c_char, c_int, c_ulong};

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;
use dlsym_oracle::host_fn;

type SprintrrfFn = unsafe extern "C" fn(
    *const u8,
    usize,
    *const c_char,
    c_int,
    c_int,
    c_ulong,
    *const u8,
    usize,
    *const c_char,
    *const c_char,
    *mut c_char,
    usize,
) -> c_int;

/// The types fl refuses, from `rdata_embeds_a_domain_name`.
const NAME_BEARING: &[u16] = &[2, 5, 6, 7, 8, 9, 12, 14, 15, 17, 18, 21, 26, 39, 249, 250];

fn host_sprintrrf() -> SprintrrfFn {
    // SAFETY: the signature matches libresolv's declaration, and fl's own
    // export is passed so the oracle refuses to resolve back to fl (bd-v0388t).
    unsafe {
        host_fn(
            c"ns_sprintrrf",
            frankenlibc_abi::resolv_abi::ns_sprintrrf as *const (),
        )
    }
}

/// A wire message holding one uncompressed name, so `dn_expand` can succeed
/// when the rdata is well formed.
fn message() -> Vec<u8> {
    let mut msg = b"\x03www\x07example\x03com\x00".to_vec();
    msg.resize(msg.len() + 128, 0);
    msg
}

/// Render one type with deliberately malformed rdata through both libraries.
fn render_both(ty: u16) -> (c_int, c_int) {
    let msg = message();
    // Three bytes: too short for every type that has a presentation format.
    let rdata = [1u8, 2, 3];
    let name = c"w.example.";
    let mut host_buf = [0 as c_char; 8192];
    let mut fl_buf = [0 as c_char; 8192];

    // SAFETY: all buffers are live and sized as passed; the message and rdata
    // slices outlive the calls.
    unsafe {
        let host_rc = host_sprintrrf()(
            msg.as_ptr(),
            msg.len(),
            name.as_ptr(),
            1,
            c_int::from(ty),
            0,
            rdata.as_ptr(),
            rdata.len(),
            std::ptr::null(),
            std::ptr::null(),
            host_buf.as_mut_ptr(),
            host_buf.len(),
        );
        let fl_rc = frankenlibc_abi::resolv_abi::ns_sprintrrf(
            msg.as_ptr(),
            msg.len(),
            name.as_ptr(),
            1,
            c_int::from(ty),
            0,
            rdata.as_ptr(),
            rdata.len(),
            std::ptr::null(),
            std::ptr::null(),
            fl_buf.as_mut_ptr(),
            fl_buf.len(),
        );
        (fl_rc, host_rc)
    }
}

/// The sweep that produced the rule, re-run against the live oracle.
#[test]
fn malformed_rdata_refusal_matches_libresolv_across_every_type() {
    let mut divergences = Vec::new();
    for ty in 1u16..=299 {
        let (fl_rc, host_rc) = render_both(ty);
        // Compare the DECISION, not the length: a rendered string's byte count
        // is covered by resolv_abi_test's per-type arms.
        if (fl_rc <= 0) != (host_rc <= 0) {
            divergences.push(format!(
                "  type {ty}: fl {} / glibc {}",
                if fl_rc <= 0 { "refused" } else { "rendered" },
                if host_rc <= 0 { "refused" } else { "rendered" },
            ));
        }
    }
    assert!(
        divergences.is_empty(),
        "refuse-vs-render divergences on malformed rdata:\n{}",
        divergences.join("\n")
    );
}

/// The rule fl implements must be exactly the set libresolv refuses — no more,
/// no fewer. A drift in either direction is a divergence even if every
/// individual type still agrees by accident.
#[test]
fn the_name_bearing_set_is_exactly_what_libresolv_refuses() {
    let mut observed = Vec::new();
    for ty in 1u16..=299 {
        if render_both(ty).1 <= 0 {
            observed.push(ty);
        }
    }
    assert_eq!(
        observed, NAME_BEARING,
        "libresolv's refusal set moved; fl's rdata_embeds_a_domain_name must \
         move with it rather than being widened to make this pass"
    );
}

/// The case the bead was filed on, kept as its own arm so a regression names it.
#[test]
fn soa_with_malformed_rdata_is_refused() {
    let (fl_rc, host_rc) = render_both(6);
    assert!(host_rc <= 0, "glibc must refuse SOA with 3 bytes of rdata");
    assert!(
        fl_rc <= 0,
        "fl rendered SOA generically where glibc refuses (bd-9kuafg)"
    );
}

/// A, AAAA and TXT are known to glibc and still render generically. This is the
/// arm that would fail if someone "fixed" this by refusing every known type.
#[test]
fn known_but_fixed_width_types_still_render_generically() {
    for (ty, label) in [(1u16, "A"), (28, "AAAA"), (16, "TXT")] {
        let (fl_rc, host_rc) = render_both(ty);
        assert!(
            host_rc > 0,
            "glibc renders {label} generically on bad rdata; the probe is wrong \
             if this fails"
        );
        assert!(
            fl_rc > 0,
            "{label} must NOT be refused — knownness is not the discriminator, \
             an embedded domain name is (bd-9kuafg)"
        );
    }
}
