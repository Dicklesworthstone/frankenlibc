#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc res_mkquery oracle

//! The DNS query AD bit is DERIVED from resolv.conf, not constant (bd-b275vh).
//!
//! WHY THIS EXISTS WHEN `conformance_diff_res_mkquery` ALREADY COMPARES FLAGS.
//! That gate diffs fl's packet against live glibc's from offset 2 onward, so
//! the flag word is inside its comparison — and it was GREEN for as long as fl
//! hardcoded `0x0120`. It could not be otherwise: it compares against glibc
//! under whatever resolv.conf this host happens to have, and every machine on
//! this fleet runs systemd-resolved, which writes `trust-ad`. A constant that
//! is right for one configuration passes a one-configuration gate forever.
//!
//! So this gate adds the dimension that one structurally cannot reach:
//!
//!   1. it drives BOTH resolver configurations through fl, so the derivation is
//!      exercised whichever kind of host the run lands on; and
//!   2. it pins the RULE against the live incumbent — glibc's AD bit must equal
//!      the presence of `trust-ad` in this host's resolv.conf — rather than
//!      pinning the value, which is what goes stale.
//!
//! Measured, glibc 2.42, `res_mkquery(QUERY, "example.com", IN, A)`:
//!     resolv.conf with    `options edns0 trust-ad` -> flags 0x0120  AD=1
//!     resolv.conf without `trust-ad`               -> flags 0x0100  AD=0
//! (the second by bind-mounting a resolv.conf lacking the option under bwrap).
//! No mocks.

use std::ffi::{CString, c_char, c_int, c_void};

mod g {
    use super::*;
    unsafe extern "C" {
        // Plain `res_init` is a header macro; only `__res_init` is exported.
        // See conformance_diff_res_mkquery for the link failure this avoids.
        #[link_name = "__res_init"]
        pub fn res_init() -> c_int;
        #[allow(clippy::too_many_arguments)]
        pub fn res_mkquery(
            op: c_int,
            dname: *const c_char,
            class: c_int,
            typ: c_int,
            data: *const c_void,
            datalen: c_int,
            newrr: *const c_void,
            buf: *mut c_void,
            buflen: c_int,
        ) -> c_int;
    }
}

use frankenlibc_core::resolv::ResolverConfig;
use frankenlibc_core::resolv::dns::DnsHeader;

/// Byte 3 of a DNS header is RA(7) Z(6) AD(5) CD(4) RCODE(3..0).
const AD: u16 = 0x0020;
/// RD, which both configurations must keep set.
const RD: u16 = 0x0100;

/// Flag word glibc puts in a fresh query on THIS host, right now.
fn glibc_query_flags() -> u16 {
    let dn = CString::new("example.com").unwrap();
    let mut buf = vec![0u8; 512];
    let n = unsafe {
        g::res_init();
        g::res_mkquery(
            0, // QUERY
            dn.as_ptr(),
            1, // IN
            1, // A
            std::ptr::null(),
            0,
            std::ptr::null(),
            buf.as_mut_ptr() as *mut c_void,
            512,
        )
    };
    assert!(
        n > 4,
        "host premise: glibc res_mkquery must build a packet, got {n}"
    );
    u16::from_be_bytes([buf[2], buf[3]])
}

/// Whether this host's resolv.conf actually asks for `trust-ad`.
///
/// Read with an independent scan rather than through `ResolverConfig`, because
/// `ResolverConfig` is one of the things under test here.
fn host_resolv_conf_has_trust_ad() -> bool {
    let Ok(text) = std::fs::read_to_string("/etc/resolv.conf") else {
        return false;
    };
    text.lines()
        .filter(|l| !l.trim_start().starts_with('#') && !l.trim_start().starts_with(';'))
        .filter_map(|l| l.split_once("options"))
        .any(|(_, opts)| opts.split_whitespace().any(|o| o == "trust-ad"))
}

/// The rule, pinned against the incumbent on whatever host runs this.
#[test]
fn glibc_sets_the_ad_bit_exactly_when_resolv_conf_asks_for_it() {
    let configured = host_resolv_conf_has_trust_ad();
    let flags = glibc_query_flags();
    println!(
        "res_mkquery: glibc flags=0x{flags:04x} AD={} /etc/resolv.conf trust-ad={configured}",
        flags & AD != 0
    );
    assert_eq!(
        flags & RD,
        RD,
        "host premise: glibc must set RD on a query, flags=0x{flags:04x}"
    );
    // This is the assertion that would have caught the old constant, and it is
    // the one that stays true when a future host flips the other way.
    assert_eq!(
        flags & AD != 0,
        configured,
        "host premise: glibc's AD bit must track `trust-ad` in resolv.conf, but flags=0x{flags:04x} \
         with trust-ad={configured}. If this fails, the derivation rule fl now implements has \
         changed in the incumbent and fl must follow it"
    );
}

/// fl must agree with the live incumbent, on this host, in this run.
#[test]
fn fl_query_header_matches_live_glibc_on_this_host() {
    let glibc_flags = glibc_query_flags();

    // fl's own parse of the same file the incumbent read.
    let config = match std::fs::read("/etc/resolv.conf") {
        Ok(content) => ResolverConfig::parse(&content),
        Err(_) => ResolverConfig::default(),
    };
    let fl_flags = DnsHeader::new_query_with_trust_ad(0x1234, config.trust_ad).flags;

    assert_eq!(
        fl_flags, glibc_flags,
        "fl query flags 0x{fl_flags:04x} != glibc 0x{glibc_flags:04x} (fl parsed trust_ad={})",
        config.trust_ad
    );
}

/// BOTH configurations, so the derivation is exercised on any host.
///
/// The live arms above can only ever see the configuration this machine has.
/// These two cases are what make a run on a `trust-ad` host say anything about
/// a host without it, and vice versa — which is precisely what the hardcoded
/// constant escaped.
#[test]
fn fl_derives_the_ad_bit_from_the_resolver_configuration() {
    const WITH: &[u8] = b"nameserver 127.0.0.53\noptions edns0 trust-ad\n";
    const WITHOUT: &[u8] = b"nameserver 127.0.0.53\noptions edns0\n";

    let with = ResolverConfig::parse(WITH);
    let without = ResolverConfig::parse(WITHOUT);
    assert!(with.trust_ad, "`options ... trust-ad` must set trust_ad");
    assert!(
        !without.trust_ad,
        "trust_ad must NOT be set without the option -- this is the half that was wrong: \
         RES_TRUSTAD is not in RES_DEFAULT"
    );

    let flags_with = DnsHeader::new_query_with_trust_ad(1, with.trust_ad).flags;
    let flags_without = DnsHeader::new_query_with_trust_ad(1, without.trust_ad).flags;
    assert_eq!(flags_with, 0x0120, "trust-ad host: RD|AD");
    assert_eq!(flags_without, 0x0100, "default host: RD only, AD clear");

    // The two configurations must actually differ, or the case above could pass
    // with a constant on either side.
    assert_ne!(
        flags_with, flags_without,
        "the two resolver configurations must produce different flag words, or this gate is \
         testing nothing"
    );
}

/// The no-configuration constructor answers glibc's DEFAULT, not this fleet's.
///
/// `DnsHeader::new_query` is what the conformance fixture `dns_header_query`
/// drives, and that fixture expects 256. It expected 256 all along; fl answered
/// 288 because the bit was pinned on.
#[test]
fn new_query_without_configuration_is_glibc_default_ad_clear() {
    let flags = DnsHeader::new_query(0x1234).flags;
    assert_eq!(
        flags, 0x0100,
        "an unconfigured query header must be RD only (0x0100 = 256); 0x0120 = 288 is the \
         `trust-ad` answer and must not be the default"
    );
}
