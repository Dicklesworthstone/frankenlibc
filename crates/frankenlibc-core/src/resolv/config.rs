//! /etc/resolv.conf parser.
//!
//! Clean-room implementation of resolv.conf parsing per the resolver(5) man page.
//!
//! # Supported Directives
//!
//! - `nameserver <ip>`: DNS server address (up to 3)
//! - `domain <name>`: Local domain name
//! - `search <name>...`: Search list for hostname lookup
//! - `options <opt>...`: Various options (ndots, timeout, attempts)
//!
//! # Default Behavior
//!
//! If no nameservers are specified, defaults to 127.0.0.1.

use std::net::IpAddr;

// ---------------------------------------------------------------------------
// Configuration Limits
// ---------------------------------------------------------------------------

/// Maximum number of nameservers (matches glibc)
pub const MAX_NAMESERVERS: usize = 3;

/// Maximum number of search domains (matches glibc)
pub const MAX_SEARCH_DOMAINS: usize = 6;

/// Default DNS port
pub const DNS_PORT: u16 = 53;

/// Default timeout in seconds
pub const DEFAULT_TIMEOUT_SECS: u32 = 5;

/// Default number of retry attempts
pub const DEFAULT_ATTEMPTS: u32 = 2;

/// Default ndots threshold
pub const DEFAULT_NDOTS: u32 = 1;

// ---------------------------------------------------------------------------
// Resolver Configuration
// ---------------------------------------------------------------------------

/// Parsed resolver configuration from /etc/resolv.conf.
#[derive(Debug, Clone)]
pub struct ResolverConfig {
    /// List of nameserver IP addresses (up to MAX_NAMESERVERS)
    pub nameservers: Vec<IpAddr>,
    /// Local domain name
    pub domain: Option<String>,
    /// Search list for hostname lookup
    pub search: Vec<String>,
    /// ndots threshold: queries with >= ndots dots are tried as absolute first
    pub ndots: u32,
    /// Timeout for each query attempt in seconds
    pub timeout: u32,
    /// Number of query attempts before giving up
    pub attempts: u32,
    /// Rotate nameservers on each query
    pub rotate: bool,
    /// Use TCP instead of UDP
    pub use_vc: bool,
}

impl Default for ResolverConfig {
    fn default() -> Self {
        Self {
            nameservers: vec!["127.0.0.1".parse().unwrap()],
            domain: None,
            search: Vec::new(),
            ndots: DEFAULT_NDOTS,
            timeout: DEFAULT_TIMEOUT_SECS,
            attempts: DEFAULT_ATTEMPTS,
            rotate: false,
            use_vc: false,
        }
    }
}

impl ResolverConfig {
    /// Create a new empty configuration (no nameservers).
    pub fn empty() -> Self {
        Self {
            nameservers: Vec::new(),
            domain: None,
            search: Vec::new(),
            ndots: DEFAULT_NDOTS,
            timeout: DEFAULT_TIMEOUT_SECS,
            attempts: DEFAULT_ATTEMPTS,
            rotate: false,
            use_vc: false,
        }
    }

    /// Parse configuration from /etc/resolv.conf content.
    pub fn parse(content: &[u8]) -> Self {
        let mut config = Self::empty();

        for line in content.split(|&b| b == b'\n') {
            config.parse_line(line);
        }

        // Apply defaults if no nameservers were specified
        if config.nameservers.is_empty() {
            config.nameservers.push("127.0.0.1".parse().unwrap());
        }

        // If domain is set but search is empty, use domain as search
        if config.search.is_empty()
            && let Some(ref domain) = config.domain
        {
            config.search.push(domain.clone());
        }

        config
    }

    /// Parse a single line from resolv.conf.
    fn parse_line(&mut self, line: &[u8]) {
        // Skip empty lines and comments
        let line = trim_whitespace(line);
        if line.is_empty() || line.starts_with(b"#") || line.starts_with(b";") {
            return;
        }

        // Split on whitespace
        let mut parts = line
            .split(|&b| b == b' ' || b == b'\t')
            .filter(|p| !p.is_empty());

        let keyword = match parts.next() {
            Some(k) => k,
            None => return,
        };

        match keyword {
            b"nameserver" => {
                if self.nameservers.len() < MAX_NAMESERVERS
                    && let Some(addr) = parts.next()
                    && let Ok(ip) = parse_ip_addr(addr)
                {
                    self.nameservers.push(ip);
                }
            }
            b"domain" => {
                if let Some(name) = parts.next()
                    && let Ok(s) = core::str::from_utf8(name)
                {
                    self.domain = Some(s.to_string());
                }
            }
            b"search" => {
                self.search.clear();
                for name in parts.take(MAX_SEARCH_DOMAINS) {
                    if let Ok(s) = core::str::from_utf8(name) {
                        self.search.push(s.to_string());
                    }
                }
            }
            b"options" => {
                for opt in parts {
                    self.parse_option(opt);
                }
            }
            _ => {
                // Unknown directive, ignore
            }
        }
    }

    /// Parse a single option from the options directive.
    fn parse_option(&mut self, opt: &[u8]) {
        if opt.starts_with(b"ndots:")
            && let Some(val) = opt.get(6..)
            && let Ok(n) = parse_u32(val)
        {
            self.ndots = n.min(15);
        } else if opt.starts_with(b"timeout:")
            && let Some(val) = opt.get(8..)
            && let Ok(n) = parse_u32(val)
        {
            self.timeout = n.clamp(1, 30);
        } else if opt.starts_with(b"attempts:")
            && let Some(val) = opt.get(9..)
            && let Ok(n) = parse_u32(val)
        {
            self.attempts = n.clamp(1, 5);
        } else if opt == b"rotate" {
            self.rotate = true;
        } else if opt == b"use-vc" {
            self.use_vc = true;
        }
        // Other options are silently ignored
    }

    /// Get the total timeout for a single query (per nameserver).
    pub fn query_timeout(&self) -> core::time::Duration {
        core::time::Duration::from_secs(self.timeout as u64)
    }

    /// Get the total budget for resolving a name (all retries).
    pub fn total_budget(&self) -> core::time::Duration {
        let per_attempt = self.timeout as u64 * self.nameservers.len() as u64;
        core::time::Duration::from_secs(per_attempt * self.attempts as u64)
    }

    /// Check if a hostname should be tried as absolute first.
    ///
    /// Returns true if the name has >= ndots dots.
    pub fn should_try_absolute_first(&self, name: &str) -> bool {
        let dots = name.bytes().filter(|&b| b == b'.').count();
        dots >= self.ndots as usize
    }
}

// ---------------------------------------------------------------------------
// Helper Functions
// ---------------------------------------------------------------------------

/// Parse an IP address from bytes.
fn parse_ip_addr(bytes: &[u8]) -> Result<IpAddr, ()> {
    let s = core::str::from_utf8(bytes).map_err(|_| ())?;
    s.parse().map_err(|_| ())
}

/// Parse a u32 from bytes.
fn parse_u32(bytes: &[u8]) -> Result<u32, ()> {
    let s = core::str::from_utf8(bytes).map_err(|_| ())?;
    s.parse().map_err(|_| ())
}

/// Trim leading and trailing ASCII whitespace.
fn trim_whitespace(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|&b| !b.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|&b| !b.is_ascii_whitespace())
        .map(|i| i + 1)
        .unwrap_or(0);
    if start >= end {
        &[]
    } else {
        &bytes[start..end]
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ResolverConfig::default();
        assert_eq!(config.nameservers.len(), 1);
        assert_eq!(config.nameservers[0].to_string(), "127.0.0.1");
        assert_eq!(config.ndots, 1);
        assert_eq!(config.timeout, 5);
        assert_eq!(config.attempts, 2);
    }

    #[test]
    fn test_parse_empty() {
        let config = ResolverConfig::parse(b"");
        assert_eq!(config.nameservers.len(), 1);
        assert_eq!(config.nameservers[0].to_string(), "127.0.0.1");
    }

    #[test]
    fn test_parse_single_nameserver() {
        let config = ResolverConfig::parse(b"nameserver 8.8.8.8\n");
        assert_eq!(config.nameservers.len(), 1);
        assert_eq!(config.nameservers[0].to_string(), "8.8.8.8");
    }

    #[test]
    fn test_parse_multiple_nameservers() {
        let content = b"nameserver 8.8.8.8\nnameserver 8.8.4.4\nnameserver 1.1.1.1\n";
        let config = ResolverConfig::parse(content);
        assert_eq!(config.nameservers.len(), 3);
        assert_eq!(config.nameservers[0].to_string(), "8.8.8.8");
        assert_eq!(config.nameservers[1].to_string(), "8.8.4.4");
        assert_eq!(config.nameservers[2].to_string(), "1.1.1.1");
    }

    #[test]
    fn test_parse_max_nameservers() {
        let content =
            b"nameserver 1.1.1.1\nnameserver 2.2.2.2\nnameserver 3.3.3.3\nnameserver 4.4.4.4\n";
        let config = ResolverConfig::parse(content);
        // Should only take first 3
        assert_eq!(config.nameservers.len(), 3);
    }

    #[test]
    fn test_parse_ipv6_nameserver() {
        let config = ResolverConfig::parse(b"nameserver 2001:4860:4860::8888\n");
        assert_eq!(config.nameservers.len(), 1);
        assert!(config.nameservers[0].is_ipv6());
    }

    #[test]
    fn test_parse_domain() {
        let config = ResolverConfig::parse(b"domain example.com\n");
        assert_eq!(config.domain, Some("example.com".to_string()));
        // Domain should be added to search if search is empty
        assert_eq!(config.search, vec!["example.com".to_string()]);
    }

    #[test]
    fn test_parse_search() {
        let config = ResolverConfig::parse(b"search local.domain example.com\n");
        assert_eq!(config.search.len(), 2);
        assert_eq!(config.search[0], "local.domain");
        assert_eq!(config.search[1], "example.com");
    }

    #[test]
    fn test_parse_options_ndots() {
        let config = ResolverConfig::parse(b"options ndots:3\n");
        assert_eq!(config.ndots, 3);
    }

    #[test]
    fn test_parse_options_timeout() {
        let config = ResolverConfig::parse(b"options timeout:10\n");
        assert_eq!(config.timeout, 10);
    }

    #[test]
    fn test_parse_options_attempts() {
        let config = ResolverConfig::parse(b"options attempts:3\n");
        assert_eq!(config.attempts, 3);
    }

    #[test]
    fn test_parse_options_rotate() {
        let config = ResolverConfig::parse(b"options rotate\n");
        assert!(config.rotate);
    }

    #[test]
    fn test_parse_options_multiple() {
        let config = ResolverConfig::parse(b"options ndots:2 timeout:3 rotate\n");
        assert_eq!(config.ndots, 2);
        assert_eq!(config.timeout, 3);
        assert!(config.rotate);
    }

    #[test]
    fn test_parse_comments() {
        let content = b"# This is a comment\nnameserver 1.2.3.4\n; Another comment\n";
        let config = ResolverConfig::parse(content);
        assert_eq!(config.nameservers.len(), 1);
        assert_eq!(config.nameservers[0].to_string(), "1.2.3.4");
    }

    #[test]
    fn test_parse_full_file() {
        let content = b"\
# /etc/resolv.conf
nameserver 8.8.8.8
nameserver 8.8.4.4
domain corp.example.com
search corp.example.com example.com
options ndots:2 timeout:3 attempts:2 rotate
";
        let config = ResolverConfig::parse(content);
        assert_eq!(config.nameservers.len(), 2);
        assert_eq!(config.domain, Some("corp.example.com".to_string()));
        assert_eq!(config.search.len(), 2);
        assert_eq!(config.ndots, 2);
        assert_eq!(config.timeout, 3);
        assert!(config.rotate);
    }

    #[test]
    fn test_should_try_absolute_first() {
        let config = ResolverConfig::parse(b"options ndots:2\n");

        // Single label (0 dots) - try search first
        assert!(!config.should_try_absolute_first("localhost"));

        // One dot - still try search first
        assert!(!config.should_try_absolute_first("host.local"));

        // Two dots - try absolute first
        assert!(config.should_try_absolute_first("host.example.com"));
    }

    #[test]
    fn test_query_timeout() {
        let config = ResolverConfig::parse(b"options timeout:7\n");
        assert_eq!(config.query_timeout(), core::time::Duration::from_secs(7));
    }

    #[test]
    fn test_total_budget() {
        let content = b"nameserver 1.1.1.1\nnameserver 2.2.2.2\noptions timeout:5 attempts:2\n";
        let config = ResolverConfig::parse(content);
        // 5 seconds * 2 nameservers * 2 attempts = 20 seconds
        assert_eq!(config.total_budget(), core::time::Duration::from_secs(20));
    }

    #[test]
    fn test_trim_whitespace() {
        assert_eq!(trim_whitespace(b"  hello  "), b"hello");
        assert_eq!(trim_whitespace(b"hello"), b"hello");
        assert_eq!(trim_whitespace(b"   "), &[] as &[u8]);
        assert_eq!(trim_whitespace(b""), &[] as &[u8]);
    }

    #[test]
    fn test_options_clamp() {
        // ndots clamped to 15
        let config = ResolverConfig::parse(b"options ndots:100\n");
        assert_eq!(config.ndots, 15);

        // timeout clamped to 1-30
        let config = ResolverConfig::parse(b"options timeout:0\n");
        assert_eq!(config.timeout, 1);
        let config = ResolverConfig::parse(b"options timeout:100\n");
        assert_eq!(config.timeout, 30);

        // attempts clamped to 1-5
        let config = ResolverConfig::parse(b"options attempts:0\n");
        assert_eq!(config.attempts, 1);
        let config = ResolverConfig::parse(b"options attempts:100\n");
        assert_eq!(config.attempts, 5);
    }

    // -----------------------------------------------------------------
    // resolver(5) conformance table (bd-x7jd)
    // -----------------------------------------------------------------
    //
    // Spec source: resolver(5) man page — "The resolver configuration
    // file contains information that is read by the resolver routines
    // the first time they are invoked by a process."
    //
    // Each case exercises one documented directive or limit and cites
    // the relevant clause of resolver(5) (or the MAXNS/MAXDNSRCH
    // constants in <resolv.h>) so reviewers can audit conformance.

    enum ResolvConfAssertion {
        Nameservers(&'static [&'static str]),
        NdotsEquals(u32),
        TimeoutEquals(u32),
        AttemptsEquals(u32),
        SearchEquals(&'static [&'static str]),
        DomainEquals(Option<&'static str>),
    }

    struct ResolvConfCase {
        id: &'static str,
        spec_ref: &'static str,
        input: &'static [u8],
        assertion: ResolvConfAssertion,
    }

    const RESOLV_CONF_CONFORMANCE_TABLE: &[ResolvConfCase] = &[
        // ---- nameserver directive ----
        ResolvConfCase {
            id: "RESOLV-CONF-NS-001",
            spec_ref: "resolver(5) ¶nameserver — single IPv4",
            input: b"nameserver 8.8.8.8\n",
            assertion: ResolvConfAssertion::Nameservers(&["8.8.8.8"]),
        },
        ResolvConfCase {
            id: "RESOLV-CONF-NS-002",
            spec_ref: "resolver(5) ¶nameserver — IPv6 address",
            input: b"nameserver 2001:4860:4860::8888\n",
            assertion: ResolvConfAssertion::Nameservers(&["2001:4860:4860::8888"]),
        },
        ResolvConfCase {
            id: "RESOLV-CONF-NS-003",
            // <resolv.h> MAXNS == 3; excess nameservers are silently dropped.
            spec_ref: "resolver(5) + <resolv.h> MAXNS=3 cap on nameservers",
            input: b"nameserver 1.1.1.1\nnameserver 2.2.2.2\nnameserver 3.3.3.3\nnameserver 4.4.4.4\n",
            assertion: ResolvConfAssertion::Nameservers(&["1.1.1.1", "2.2.2.2", "3.3.3.3"]),
        },
        // ---- options directive clamps ----
        ResolvConfCase {
            id: "RESOLV-CONF-OPT-001",
            spec_ref: "resolver(5) ¶options ndots:n — default 1",
            input: b"options ndots:3\n",
            assertion: ResolvConfAssertion::NdotsEquals(3),
        },
        ResolvConfCase {
            id: "RESOLV-CONF-OPT-002",
            // glibc clamps ndots at 15; higher values are pinned down.
            spec_ref: "resolver(5) ¶options ndots — glibc hard cap at 15",
            input: b"options ndots:100\n",
            assertion: ResolvConfAssertion::NdotsEquals(15),
        },
        ResolvConfCase {
            id: "RESOLV-CONF-OPT-003",
            // glibc clamps timeout to [1, 30] seconds.
            spec_ref: "resolver(5) ¶options timeout:n — min 1s per glibc",
            input: b"options timeout:0\n",
            assertion: ResolvConfAssertion::TimeoutEquals(1),
        },
        ResolvConfCase {
            id: "RESOLV-CONF-OPT-004",
            spec_ref: "resolver(5) ¶options timeout:n — max 30s per glibc",
            input: b"options timeout:100\n",
            assertion: ResolvConfAssertion::TimeoutEquals(30),
        },
        ResolvConfCase {
            id: "RESOLV-CONF-OPT-005",
            spec_ref: "resolver(5) ¶options attempts:n — min 1 per glibc",
            input: b"options attempts:0\n",
            assertion: ResolvConfAssertion::AttemptsEquals(1),
        },
        ResolvConfCase {
            id: "RESOLV-CONF-OPT-006",
            spec_ref: "resolver(5) ¶options attempts:n — max 5 per glibc",
            input: b"options attempts:100\n",
            assertion: ResolvConfAssertion::AttemptsEquals(5),
        },
        // ---- search + domain directives ----
        ResolvConfCase {
            id: "RESOLV-CONF-SEARCH-001",
            spec_ref: "resolver(5) ¶search — space-separated domain list",
            input: b"search example.com local.domain\n",
            assertion: ResolvConfAssertion::SearchEquals(&["example.com", "local.domain"]),
        },
        ResolvConfCase {
            id: "RESOLV-CONF-DOMAIN-001",
            spec_ref: "resolver(5) ¶domain — single local domain name",
            input: b"domain example.com\n",
            assertion: ResolvConfAssertion::DomainEquals(Some("example.com")),
        },
        // ---- comments and blank lines ----
        ResolvConfCase {
            id: "RESOLV-CONF-COMMENT-001",
            // resolver(5): "Lines that contain a semicolon (;) or hash
            //  character (#) in the first column are treated as comments."
            spec_ref: "resolver(5) ¶Description — '#' and ';' start comments",
            input: b"# nameserver 9.9.9.9\n; nameserver 4.4.4.4\nnameserver 1.1.1.1\n",
            assertion: ResolvConfAssertion::Nameservers(&["1.1.1.1"]),
        },
    ];

    #[test]
    fn resolv_conf_conformance_table() {
        let mut fails = Vec::new();
        for case in RESOLV_CONF_CONFORMANCE_TABLE {
            let config = ResolverConfig::parse(case.input);
            let pass = match &case.assertion {
                ResolvConfAssertion::Nameservers(expected) => {
                    config.nameservers.len() == expected.len()
                        && config
                            .nameservers
                            .iter()
                            .zip(expected.iter())
                            .all(|(got, want)| got.to_string() == *want)
                }
                ResolvConfAssertion::NdotsEquals(want) => config.ndots == *want,
                ResolvConfAssertion::TimeoutEquals(want) => config.timeout == *want,
                ResolvConfAssertion::AttemptsEquals(want) => config.attempts == *want,
                ResolvConfAssertion::SearchEquals(expected) => {
                    config.search.len() == expected.len()
                        && config
                            .search
                            .iter()
                            .zip(expected.iter())
                            .all(|(got, want)| got == *want)
                }
                ResolvConfAssertion::DomainEquals(want) => {
                    config.domain.as_deref() == *want
                }
            };
            if !pass {
                fails.push(format!(
                    "{} [{}]: expected {} — got config.nameservers={:?} ndots={} timeout={} attempts={} search={:?} domain={:?}",
                    case.id,
                    case.spec_ref,
                    match &case.assertion {
                        ResolvConfAssertion::Nameservers(e) => format!("nameservers={e:?}"),
                        ResolvConfAssertion::NdotsEquals(n) => format!("ndots={n}"),
                        ResolvConfAssertion::TimeoutEquals(t) => format!("timeout={t}"),
                        ResolvConfAssertion::AttemptsEquals(a) => format!("attempts={a}"),
                        ResolvConfAssertion::SearchEquals(s) => format!("search={s:?}"),
                        ResolvConfAssertion::DomainEquals(d) => format!("domain={d:?}"),
                    },
                    config.nameservers,
                    config.ndots,
                    config.timeout,
                    config.attempts,
                    config.search,
                    config.domain,
                ));
            }
        }
        assert!(
            fails.is_empty(),
            "resolver(5) conformance failures:\n  {}",
            fails.join("\n  ")
        );
    }
}
