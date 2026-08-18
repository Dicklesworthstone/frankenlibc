//! HMAC-SHA-256 and PBKDF2-HMAC-SHA-256.
//!
//! Written for [`crate::crypt::scrypt`], which needs PBKDF2 at both ends of the
//! construction. Neither primitive has a constant table — HMAC is two padded
//! SHA-256 passes and PBKDF2 is a counter loop over it — so both are written
//! directly from their specifications (RFC 2104, RFC 8018) rather than ported.
//!
//! Kept separate from the `$5$`/`$6$` SHA-crypt schemes on purpose: those are a
//! different construction that happens to share a hash, and folding them
//! together would invite a change to one silently altering the other.

use sha2::{Digest, Sha256};

/// SHA-256's block size, which is what HMAC pads the key to.
const BLOCK_LEN: usize = 64;
/// SHA-256's output size.
pub const HASH_LEN: usize = 32;

/// HMAC-SHA-256 of `message` under `key`.
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; HASH_LEN] {
    // A key longer than the block is replaced by its own hash; a shorter one is
    // zero-padded. Both are RFC 2104, and getting the long-key case wrong is
    // invisible until someone uses a password over 64 bytes.
    let mut padded = [0u8; BLOCK_LEN];
    if key.len() > BLOCK_LEN {
        let digest = Sha256::digest(key);
        padded[..HASH_LEN].copy_from_slice(&digest);
    } else {
        padded[..key.len()].copy_from_slice(key);
    }

    let mut inner_pad = [0x36u8; BLOCK_LEN];
    let mut outer_pad = [0x5cu8; BLOCK_LEN];
    for i in 0..BLOCK_LEN {
        inner_pad[i] ^= padded[i];
        outer_pad[i] ^= padded[i];
    }

    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(message);
    let inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner_digest);

    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(&outer.finalize());
    out
}

/// PBKDF2-HMAC-SHA-256, filling `out` with derived key material.
///
/// `iterations` must be at least 1; scrypt calls this with exactly 1 at both
/// ends, where the whole cost lives in the memory-hard middle instead.
pub fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) {
    let mut block_index: u32 = 1;
    let mut written = 0usize;

    while written < out.len() {
        // U1 = PRF(P, S || INT_32_BE(i)). The counter is BIG-endian; little
        // would produce a plausible key that matches no other implementation.
        let mut salted = Vec::with_capacity(salt.len() + 4);
        salted.extend_from_slice(salt);
        salted.extend_from_slice(&block_index.to_be_bytes());

        let mut u = hmac_sha256(password, &salted);
        let mut acc = u;
        for _ in 1..iterations {
            u = hmac_sha256(password, &u);
            for (a, b) in acc.iter_mut().zip(u.iter()) {
                *a ^= *b;
            }
        }

        let take = (out.len() - written).min(HASH_LEN);
        out[written..written + take].copy_from_slice(&acc[..take]);
        written += take;
        block_index += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// RFC 4231 test case 1. Generated here from Python's `hmac`, and it is the
    /// value the RFC prints — an independent implementation agreeing with the
    /// document, not this file agreeing with itself.
    #[test]
    fn hmac_matches_rfc4231_case1() {
        let got = hmac_sha256(&[0x0b; 20], b"Hi There");
        assert_eq!(
            hex(&got),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    /// A key longer than the 64-byte block must be hashed first. This case is
    /// invisible with short passwords, which is exactly why it is pinned.
    #[test]
    fn hmac_long_key_is_hashed_first() {
        let long = [0xaa; 131];
        let short = Sha256::digest(long);
        assert_eq!(
            hmac_sha256(&long, b"probe"),
            hmac_sha256(&short, b"probe"),
            "a >block-length key must be replaced by its own digest"
        );
    }

    /// PBKDF2-HMAC-SHA-256, generated from OpenSSL via Python's hashlib.
    #[test]
    fn pbkdf2_matches_independent_implementation() {
        let cases: &[(&[u8], &[u8], u32, &str)] = &[
            (b"passwd", b"salt", 1,
             "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc\
              49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"),
            (b"Password", b"NaCl", 80000,
             "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56\
              a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d"),
        ];
        for (password, salt, iterations, expected) in cases {
            let mut out = [0u8; 64];
            pbkdf2_hmac_sha256(password, salt, *iterations, &mut out);
            let want: String = expected.chars().filter(|c| !c.is_whitespace()).collect();
            assert_eq!(hex(&out), want, "pbkdf2 {password:?}/{salt:?}/{iterations}");
        }
    }

    /// The block counter is BIG-endian. A little-endian counter still produces
    /// 32 bytes per block and still looks like a key, so pin the boundary where
    /// the difference first shows: two output blocks rather than one.
    #[test]
    fn pbkdf2_second_block_differs_from_first() {
        let mut two = [0u8; 64];
        pbkdf2_hmac_sha256(b"passwd", b"salt", 1, &mut two);
        let mut one = [0u8; 32];
        pbkdf2_hmac_sha256(b"passwd", b"salt", 1, &mut one);
        assert_eq!(&two[..32], &one[..], "first block must not depend on length");
        assert_ne!(&two[..32], &two[32..], "the counter must advance");
    }
}
