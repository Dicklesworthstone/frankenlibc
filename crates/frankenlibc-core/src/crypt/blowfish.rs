//! Blowfish, as bcrypt's `EksBlowfish` uses it.
//!
//! This is NOT a general-purpose Blowfish: it exposes exactly what
//! [`crate::crypt::bcrypt`] needs — the expensive key schedule with a salt
//! (`expand_key`), the plain key schedule (`expand_key_no_salt`), and ECB block
//! encryption. Decryption is deliberately absent; bcrypt never decrypts.
//!
//! ## Where the constants come from
//!
//! `P_INIT` and `S_INIT_*` are the hexadecimal fraction of pi — that IS their
//! definition in the Blowfish specification, not a lookup table someone chose.
//! They were DERIVED here rather than transcribed, by computing pi with Machin's
//! formula in exact integer arithmetic and slicing 1042 consecutive 32-bit
//! words out of the fraction, then checked against anchors that every published
//! implementation agrees on:
//!
//! ```text
//!   w[   0] 243f6a88   w[  15] b5470917   w[  16] 9216d5d9   w[  17] 8979fb1b
//!   w[  18] d1310ba6   w[  19] 98dfb5ac   w[1041] 3ac372e6
//! ```
//!
//! The anchors bracket every boundary that matters: the first two words, the
//! last two of the 18-word P-array, the first two of the S-boxes, and the final
//! word of the last S-box. An off-by-one in the split or a truncated derivation
//! moves at least one of them. (One of my own anchors was wrong on the first
//! attempt — I had `9216d5d9` at index 17 rather than 16 — and the derivation
//! was what corrected it, which is the right way round.)

include!("blowfish_tables.rs");

/// Blowfish state: the key-dependent P-array and four S-boxes.
#[derive(Clone)]
pub struct Blowfish {
    p: [u32; 18],
    s: [[u32; 256]; 4],
}

impl Blowfish {
    /// A state initialised to the raw pi constants, before any key schedule.
    pub fn new_unkeyed() -> Self {
        Self {
            p: P_INIT,
            s: [S_INIT_0, S_INIT_1, S_INIT_2, S_INIT_3],
        }
    }

    #[inline]
    fn f(&self, x: u32) -> u32 {
        let a = self.s[0][(x >> 24) as usize];
        let b = self.s[1][((x >> 16) & 0xff) as usize];
        let c = self.s[2][((x >> 8) & 0xff) as usize];
        let d = self.s[3][(x & 0xff) as usize];
        (a.wrapping_add(b) ^ c).wrapping_add(d)
    }

    /// Encrypt one 64-bit block in place, as `(left, right)`.
    pub fn encrypt_block(&self, left: &mut u32, right: &mut u32) {
        let mut l = *left;
        let mut r = *right;
        for round in 0..16 {
            l ^= self.p[round];
            r ^= self.f(l);
            core::mem::swap(&mut l, &mut r);
        }
        core::mem::swap(&mut l, &mut r);
        r ^= self.p[16];
        l ^= self.p[17];
        *left = l;
        *right = r;
    }

    /// Fold `key` into the P-array, cycling the key as needed.
    fn xor_key(&mut self, key: &[u8], key_pos: &mut usize) {
        for slot in self.p.iter_mut() {
            let mut word = 0u32;
            for _ in 0..4 {
                // An EMPTY key must not divide by zero. bcrypt always appends a
                // NUL to the password so `key` is never empty in practice, but
                // this primitive must not depend on its caller for soundness.
                let byte = if key.is_empty() {
                    0
                } else {
                    let b = key[*key_pos % key.len()];
                    *key_pos += 1;
                    b
                };
                word = (word << 8) | u32::from(byte);
            }
            *slot ^= word;
        }
    }

    /// Re-key every P entry and S entry by encrypting a running block.
    ///
    /// `salt` is consumed 64 bits at a time and XORed into the running block
    /// before each encryption; passing an empty salt gives the plain Blowfish
    /// key schedule.
    fn rekey(&mut self, salt: &[u8]) {
        let mut l = 0u32;
        let mut r = 0u32;
        let mut salt_pos = 0usize;

        let mut next_salt_pair = |salt_pos: &mut usize| -> (u32, u32) {
            if salt.is_empty() {
                return (0, 0);
            }
            let mut words = [0u32; 2];
            for word in words.iter_mut() {
                for _ in 0..4 {
                    let byte = salt[*salt_pos % salt.len()];
                    *salt_pos += 1;
                    *word = (*word << 8) | u32::from(byte);
                }
            }
            (words[0], words[1])
        };

        let mut i = 0;
        while i < 18 {
            let (sl, sr) = next_salt_pair(&mut salt_pos);
            l ^= sl;
            r ^= sr;
            self.encrypt_block(&mut l, &mut r);
            self.p[i] = l;
            self.p[i + 1] = r;
            i += 2;
        }

        for box_index in 0..4 {
            let mut j = 0;
            while j < 256 {
                let (sl, sr) = next_salt_pair(&mut salt_pos);
                l ^= sl;
                r ^= sr;
                self.encrypt_block(&mut l, &mut r);
                self.s[box_index][j] = l;
                self.s[box_index][j + 1] = r;
                j += 2;
            }
        }
    }

    /// The plain Blowfish key schedule: fold in the key, then re-key with no salt.
    pub fn expand_key_no_salt(&mut self, key: &[u8]) {
        let mut key_pos = 0usize;
        self.xor_key(key, &mut key_pos);
        self.rekey(&[]);
    }

    /// bcrypt's salted key schedule — the "expensive" half of `EksBlowfish`.
    pub fn expand_key(&mut self, salt: &[u8], key: &[u8]) {
        let mut key_pos = 0usize;
        self.xor_key(key, &mut key_pos);
        self.rekey(salt);
    }
}
