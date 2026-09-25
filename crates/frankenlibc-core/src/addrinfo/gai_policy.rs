//! Native `/etc/gai.conf` policy for destination address selection.
//!
//! Each nonempty custom table replaces its corresponding built-in table, not
//! the other tables. Missing catchall entries retain glibc's fallback values
//! (precedence 40, label 1, IPv4 scope 14). Lookup is longest-prefix-first,
//! independent of configuration line order. See gai.conf(5) and RFC 3484.

use std::fs::{self, File, Metadata};
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};

#[derive(Clone, Debug)]
struct Entry {
    network: u128,
    bits: u8,
    value: u32,
}

impl Entry {
    fn matches(&self, address: u128) -> bool {
        let mask = prefix_mask(self.bits);
        address & mask == self.network & mask
    }
}

fn prefix_mask(bits: u8) -> u128 {
    if bits == 0 { 0 } else { u128::MAX << (128 - bits) }
}

/// Immutable policy snapshot. Parsing is independent of the filesystem and
/// does not consult the process locale or perform any hostname resolution.
#[derive(Clone, Debug, Default)]
pub struct DestinationPolicy {
    precedence: Vec<Entry>,
    labels: Vec<Entry>,
    scope_v4: Vec<Entry>,
    reload: bool,
}

impl DestinationPolicy {
    /// Parse gai.conf directives. Invalid/unknown lines are ignored and cannot
    /// disable a default table. Numeric values are nonnegative signed ints,
    /// not u8: valid preferences above 255 must not wrap or be discarded.
    pub fn parse(text: &str) -> Self {
        let mut policy = Self::default();
        for line in text.lines() {
            let line = line.split('#').next().unwrap_or("");
            let mut fields = line.split_ascii_whitespace();
            let Some(kind) = fields.next() else { continue };
            let Some(prefix) = fields.next() else { continue };
            if kind == "reload" {
                match prefix {
                    "yes" => policy.reload = true,
                    "no" => policy.reload = false,
                    _ => {}
                }
                continue;
            }
            let Some(value) = fields.next().and_then(decimal) else { continue };
            if value > i32::MAX as u32 {
                continue;
            }
            let entry = if kind == "scopev4" {
                parse_scope_prefix(prefix)
            } else if matches!(kind, "label" | "precedence") {
                parse_v6_prefix(prefix)
            } else {
                None
            };
            let Some((network, bits)) = entry else { continue };
            let entry = Entry { network, bits, value };
            match kind {
                "precedence" => policy.precedence.push(entry),
                "label" => policy.labels.push(entry),
                "scopev4" => policy.scope_v4.push(entry),
                _ => {}
            }
        }
        policy
    }

    pub fn reload_enabled(&self) -> bool {
        self.reload
    }

    pub fn precedence(&self, address: IpAddr) -> u32 {
        if self.precedence.is_empty() {
            u32::from(super::precedence(address))
        } else {
            lookup(&self.precedence, address_number(address), 40)
        }
    }

    pub fn label(&self, address: IpAddr) -> u32 {
        if self.labels.is_empty() {
            u32::from(super::label(address))
        } else {
            lookup(&self.labels, address_number(address), 1)
        }
    }

    pub fn scope(&self, address: IpAddr) -> u32 {
        match address {
            IpAddr::V4(v4) if !self.scope_v4.is_empty() => {
                lookup(&self.scope_v4, u128::from(v4.to_ipv6_mapped()), 14)
            }
            _ => u32::from(super::scope(address)),
        }
    }
}

fn decimal(text: &str) -> Option<u32> {
    let digits = text.strip_prefix('+').unwrap_or(text);
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

fn parse_v6_prefix(text: &str) -> Option<(u128, u8)> {
    let (address, bits) = match text.split_once('/') {
        Some((address, bits)) => (address, decimal(bits)?),
        None => (text, 128),
    };
    if bits > 128 {
        return None;
    }
    Some((u128::from(address.parse::<Ipv6Addr>().ok()?), bits as u8))
}

fn parse_scope_prefix(text: &str) -> Option<(u128, u8)> {
    let (address, bits) = match text.split_once('/') {
        Some((address, bits)) => (address, Some(decimal(bits)?)),
        None => (text, None),
    };
    if let Ok(address) = address.parse::<Ipv4Addr>() {
        let bits = bits.unwrap_or(32);
        if bits > 32 {
            return None;
        }
        return Some((u128::from(address.to_ipv6_mapped()), bits as u8 + 96));
    }
    let address = address.parse::<Ipv6Addr>().ok()?;
    let bits = bits.unwrap_or(128);
    if address.to_ipv4_mapped().is_none() || !(96..=128).contains(&bits) {
        return None;
    }
    Some((u128::from(address), bits as u8))
}

fn address_number(address: IpAddr) -> u128 {
    u128::from(Ipv6Addr::from(super::as_v6_octets(address)))
}

fn lookup(table: &[Entry], address: u128, fallback: u32) -> u32 {
    let mut best: Option<&Entry> = None;
    for entry in table {
        // Strict comparison preserves the first entry for duplicate prefixes,
        // matching the observed glibc table order rather than reversing it.
        if best.is_none_or(|previous| entry.bits > previous.bits) && entry.matches(address) {
            best = Some(entry);
        }
    }
    best.map_or(fallback, |entry| entry.value)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FileStamp {
    device: u64,
    inode: u64,
    length: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

impl From<Metadata> for FileStamp {
    fn from(metadata: Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            length: metadata.len(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        }
    }
}

struct CachedPolicy {
    policy: Arc<DestinationPolicy>,
    stamp: Option<FileStamp>,
}

impl CachedPolicy {
    fn load(path: &Path) -> Self {
        let loaded = (|| {
            let mut file = File::open(path).ok()?;
            // The stamp belongs to the opened inode, not a possibly replaced
            // pathname. An atomic config replacement is noticed next time.
            let stamp = file.metadata().ok().map(FileStamp::from);
            let mut text = String::new();
            file.read_to_string(&mut text).ok()?;
            Some((DestinationPolicy::parse(&text), stamp))
        })();
        let (policy, stamp) = loaded.unwrap_or_default();
        Self { policy: Arc::new(policy), stamp }
    }

    fn snapshot(&mut self, path: &Path) -> Arc<DestinationPolicy> {
        // No stat/open/read at all after the initial load unless the
        // administrator explicitly selected reload=yes.
        if self.policy.reload_enabled() {
            let stamp = fs::metadata(path).ok().map(FileStamp::from);
            if stamp != self.stamp {
                *self = Self::load(path);
            }
        }
        Arc::clone(&self.policy)
    }
}

/// Obtain one immutable system policy for the entire sort. The cache lock is
/// released before comparisons, so concurrent reloads cannot change comparator
/// results halfway through a sort or invalidate another thread's table storage.
pub(super) fn system_policy() -> Arc<DestinationPolicy> {
    static CACHE: OnceLock<Mutex<CachedPolicy>> = OnceLock::new();
    let path = Path::new("/etc/gai.conf");
    let cache = CACHE.get_or_init(|| Mutex::new(CachedPolicy::load(path)));
    let mut cached = cache.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    cached.snapshot(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addrinfo::{DestinationCandidate, destination_order_with_policy};

    fn ip(text: &str) -> IpAddr { text.parse().unwrap() }
    fn loopbacks() -> [DestinationCandidate; 2] {
        [
            DestinationCandidate {
                dest: ip("127.0.0.2"), source: Some(ip("127.0.0.1")), source_prefix_len: Some(8),
            },
            DestinationCandidate {
                dest: ip("::1"), source: Some(ip("::1")), source_prefix_len: None,
            },
        ]
    }

    #[test]
    fn empty_policy_keeps_existing_default_tables() {
        let policy = DestinationPolicy::parse("# empty\n");
        assert_eq!(policy.precedence(ip("::1")), 50);
        assert_eq!(policy.precedence(ip("127.0.0.2")), 10);
        assert_eq!(policy.label(ip("fc00::1")), 6);
        assert_eq!(policy.scope(ip("127.0.0.2")), 2);
        assert_eq!(destination_order_with_policy(&loopbacks(), &policy), [1, 0]);
    }

    #[test]
    fn custom_precedence_replaces_only_its_table_and_retains_catchall() {
        let policy = DestinationPolicy::parse("precedence ::ffff:0:0/96 45\n");
        assert_eq!(policy.precedence(ip("::1")), 40);
        assert_eq!(policy.precedence(ip("192.0.2.1")), 45);
        assert_eq!(policy.label(ip("fc00::1")), 6);
        assert_eq!(destination_order_with_policy(&loopbacks(), &policy), [0, 1]);
    }

    #[test]
    fn lookup_uses_longest_prefix_and_full_integer_values() {
        let policy = DestinationPolicy::parse(
            "precedence ::/0 200\nprecedence ::1/128 2147483647\nprecedence ::/96 300\n",
        );
        assert_eq!(policy.precedence(ip("::1")), i32::MAX as u32);
        assert_eq!(policy.precedence(ip("::2")), 300);
        assert_eq!(policy.precedence(ip("2001:db8::1")), 200);
    }

    #[test]
    fn malformed_rows_do_not_disable_defaults() {
        let policy = DestinationPolicy::parse(
            "precedence ::1/129 500\nprecedence ::1/128 -1\nprecedence ::1/128 2147483648\n\
             label invalid 3\nscopev4 ::1/128 1\nscopev4 127.0.0.0/33 1\nreload maybe\n",
        );
        assert_eq!(policy.precedence(ip("::1")), 50);
        assert_eq!(policy.label(ip("::1")), 0);
        assert_eq!(policy.scope(ip("127.0.0.2")), 2);
        assert!(!policy.reload_enabled());
    }

    #[test]
    fn host_prefixes_nonbyte_masks_and_duplicate_order() {
        let policy = DestinationPolicy::parse(
            "precedence ::ffff:127.0.0.99/104 100\nprecedence ::ffff:127.0.0.0/104 20\n\
             precedence ::1 600\nlabel fcff::/7 19\n",
        );
        assert_eq!(policy.precedence(ip("127.0.0.2")), 100);
        assert_eq!(policy.precedence(ip("::1")), 600);
        assert_eq!(policy.label(ip("fd00::1")), 19);
        assert_eq!(policy.label(ip("fe00::1")), 1);
    }

    #[test]
    fn matching_labels_outrank_precedence() {
        let policy = DestinationPolicy::parse(
            "precedence ::ffff:0:0/96 100\nlabel ::ffff:127.0.0.2/128 9\n",
        );
        assert_eq!(policy.label(ip("127.0.0.2")), 9);
        assert_eq!(policy.label(ip("127.0.0.1")), 1);
        assert_eq!(destination_order_with_policy(&loopbacks(), &policy), [1, 0]);
    }

    #[test]
    fn ipv4_scope_accepts_both_notations_and_replaces_defaults() {
        for prefix in ["127.0.0.0/8", "::ffff:127.0.0.0/104"] {
            let policy = DestinationPolicy::parse(&format!("precedence ::/0 40\nscopev4 {prefix} 1\n"));
            assert_eq!(policy.scope(ip("127.0.0.2")), 1);
            assert_eq!(policy.scope(ip("169.254.1.2")), 14);
            assert_eq!(policy.scope(ip("::1")), 2);
            assert_eq!(destination_order_with_policy(&loopbacks(), &policy), [0, 1]);
        }
    }

    #[test]
    fn scope_match_precedes_a_higher_precedence() {
        let policy = DestinationPolicy::parse(
            "precedence ::ffff:0:0/96 100\nscopev4 127.0.0.2/32 1\n",
        );
        assert_eq!(destination_order_with_policy(&loopbacks(), &policy), [1, 0]);
    }

    #[test]
    fn whitespace_comments_and_reload_directives() {
        let policy = DestinationPolicy::parse(
            "# comment\n\tprecedence\t::ffff:0:0/96\t100 # suffix\nreload yes\nreload no\n",
        );
        assert!(!policy.reload_enabled());
        assert!(DestinationPolicy::parse("reload yes\n").reload_enabled());
        assert_eq!(destination_order_with_policy(&loopbacks(), &policy), [0, 1]);
    }
}
