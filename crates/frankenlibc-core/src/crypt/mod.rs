//! `<crypt.h>` — password-hash building blocks.
//!
//! Pure-safe Rust port of the salt prefix parsing, crypt(3)-style base-64
//! encoding, and the password hashing schemes: SHA-512 (`$6$`), SHA-256
//! (`$5$`), MD5 (`$1$`), bcrypt (`$2*$`), traditional and BSDI extended DES
//! (two-character and `_` settings) and NTHASH (`$3$`), plus the scrypt KDF and its
//! PBKDF2-HMAC-SHA-256 dependency, which `$7$` and `$y$` are built on.
//! The SHA/MD5 schemes lived inline in frankenlibc-abi/src/unistd_abi.rs
//! before being lifted here. The abi `crypt()` entry point is a thin
//! shim that dispatches on the salt prefix and packs the result into
//! a thread-local `*mut c_char` buffer.

pub mod base64;
pub mod bcrypt;
pub mod blowfish;
pub mod des;
pub mod md4;
pub mod md5;
pub mod pbkdf2;
pub mod salt;
pub mod scrypt;
pub mod scrypt_crypt;
pub mod sha256;
pub mod sha512;
pub mod yescrypt_params;

/// May `ch` appear in a setting, outside the fields a scheme parses itself?
///
/// Printable ASCII minus five characters:
///
/// ```text
///     !  *  :  ;  \
/// ```
///
/// This is a property of libxcrypt as a whole, not of any one scheme — measured
/// identically for traditional DES, BSDI extended DES and NTHASH, over all 256
/// byte values at several positions each. `:` and `;` separate fields in
/// `/etc/passwd` and `/etc/shadow`, `\` could escape one, and `!` and `*` are
/// the conventional locked- and disabled-account markers, so a hash string
/// containing any of them cannot be stored and read back as the same record —
/// and one beginning `*` could not be told apart from the failure token.
///
/// It is deliberately WEAKER than "must be a base-64 digit". A scheme validates
/// its own parameter characters strictly and then holds the remainder to this,
/// which is why `crypt("password", "ab$")` is accepted and hashes as `"ab"`
/// while `crypt("password", "ab:")` is refused. Getting this backwards rejects
/// settings the incumbent accepts, i.e. a stored password stops verifying.
pub(crate) fn valid_hash_string_byte(ch: u8) -> bool {
    matches!(ch, 0x21..=0x7e) && !matches!(ch, b'!' | b'*' | b':' | b';' | b'\\')
}
