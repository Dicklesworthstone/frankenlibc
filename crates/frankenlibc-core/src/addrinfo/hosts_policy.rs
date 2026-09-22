//! Native `hosts:` source ordering and status actions from nsswitch.conf.
//!
//! Clean-room implementation from the GNU libc manual, "Actions in the NSS
//! configuration", and live glibc probes. No dynamic NSS modules are loaded:
//! unknown services are retained as unavailable steps, not silently skipped.
//! Parsing and dispatch are safe, input-linear, nonrecursive, and independent
//! of filesystem/network I/O. The ABI supplies one configuration snapshot and
//! owns backend errors, including errno. Only files and DNS are native here.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    Files,
    Dns,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Success,
    NotFound,
    Unavailable,
    TryAgain,
}

impl Status {
    const ALL: [Self; 4] = [Self::Success, Self::NotFound, Self::Unavailable, Self::TryAgain];

    fn parse(token: &[u8]) -> Option<Self> {
        [b"success".as_slice(), b"notfound", b"unavail", b"tryagain"]
            .iter()
            .position(|name| token.eq_ignore_ascii_case(name))
            .map(|index| Self::ALL[index])
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Action {
    Return,
    Continue,
    Merge,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Service {
    backend: Backend,
    actions: [Action; 4],
}

impl Service {
    fn new(backend: Backend) -> Self {
        Self {
            backend,
            actions: [Action::Return, Action::Continue, Action::Continue, Action::Continue],
        }
    }
}

/// Distinguish an absent hosts entry (default files/DNS) from an explicitly
/// empty entry (no sources). Never replace an explicit policy with a default
/// merely because its selected source cannot answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostsPolicy {
    services: Vec<Service>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseError;

/// Backend status and payload travel together; failed or explicitly discarded
/// successful payloads are dropped before the next backend is invoked.
#[derive(Debug, PartialEq, Eq)]
pub enum BackendResult<T, E> {
    Success(T),
    NotFound(E),
    Unavailable(E),
    TryAgain(E),
}

impl<T, E> BackendResult<T, E> {
    fn status(&self) -> Status {
        match self {
            Self::Success(_) => Status::Success,
            Self::NotFound(_) => Status::NotFound,
            Self::Unavailable(_) => Status::Unavailable,
            Self::TryAgain(_) => Status::TryAgain,
        }
    }

    fn into_result(self) -> Result<T, E> {
        match self {
            Self::Success(value) => Ok(value),
            Self::NotFound(error) | Self::Unavailable(error) | Self::TryAgain(error) => Err(error),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum LookupError<E> {
    Backend(E),
    NoServices,
    /// GNU merge is defined for group membership, not hosts. A matched merge
    /// with a following service must fail instead of inventing host semantics.
    UnsupportedMerge,
}

impl Default for HostsPolicy {
    fn default() -> Self {
        Self { services: vec![Service::new(Backend::Files), Service::new(Backend::Dns)] }
    }
}

impl HostsPolicy {
    pub fn parse(config: &[u8]) -> Result<Self, ParseError> {
        // The last hosts line wins. A malformed earlier line cannot invalidate
        // a later complete override. Inline comments are NSS syntax, unlike
        // the resolv.conf option-token rules.
        let mut selected = None;
        for line in config.split(|&b| b == b'\n') {
            let line = line.split(|&b| b == b'#').next().unwrap_or_default();
            if let Some(colon) = line.iter().position(|&b| b == b':')
                && trim(&line[..colon]) == b"hosts"
            {
                selected = Some(&line[colon + 1..]);
            }
        }
        let Some(line) = selected else { return Ok(Self::default()) };
        let mut input = Scanner { bytes: line, position: 0 };
        let mut services = Vec::new();
        loop {
            input.whitespace();
            if input.end() { break; }
            let name = input.word();
            if name.is_empty() || !name.iter().all(|b| b.is_ascii_alphanumeric() || matches!(*b, b'_' | b'-')) {
                return Err(ParseError);
            }
            let backend = match name {
                b"files" => Backend::Files,
                b"dns" => Backend::Dns,
                _ => Backend::Unavailable,
            };
            let mut service = Service::new(backend);
            input.whitespace();
            while input.take(b'[') {
                let mut count = 0;
                loop {
                    input.whitespace();
                    if input.take(b']') {
                        if count == 0 { return Err(ParseError); }
                        break;
                    }
                    let negate = input.take(b'!');
                    input.whitespace();
                    let status = Status::parse(input.word()).ok_or(ParseError)?;
                    input.whitespace();
                    if !input.take(b'=') { return Err(ParseError); }
                    input.whitespace();
                    let token = input.word();
                    let action = if token.eq_ignore_ascii_case(b"return") {
                        Action::Return
                    } else if token.eq_ignore_ascii_case(b"continue") {
                        Action::Continue
                    } else if token.eq_ignore_ascii_case(b"merge") {
                        Action::Merge
                    } else {
                        return Err(ParseError);
                    };
                    for candidate in Status::ALL {
                        if (candidate == status) != negate {
                            service.actions[candidate as usize] = action;
                        }
                    }
                    count += 1;
                }
                input.whitespace();
            }
            services.push(service);
        }
        Ok(Self { services })
    }

    pub fn lookup<T, E>(
        &self,
        lookup: impl FnMut(Backend) -> BackendResult<T, E>,
    ) -> Result<T, LookupError<E>> {
        self.lookup_inner(lookup, false)
    }

    /// getaddrinfo has a measured terminal-merge exception: unlike reverse
    /// host lookup, it returns the last backend result when no next source
    /// exists. Keep that ABI-specific difference explicit.
    pub fn lookup_forward<T, E>(
        &self,
        lookup: impl FnMut(Backend) -> BackendResult<T, E>,
    ) -> Result<T, LookupError<E>> {
        self.lookup_inner(lookup, true)
    }

    fn lookup_inner<T, E>(
        &self,
        mut lookup: impl FnMut(Backend) -> BackendResult<T, E>,
        terminal_merge_returns: bool,
    ) -> Result<T, LookupError<E>> {
        for (index, service) in self.services.iter().enumerate() {
            let result = lookup(service.backend);
            let action = service.actions[result.status() as usize];
            if index + 1 == self.services.len() && (action != Action::Merge || terminal_merge_returns) {
                return result.into_result().map_err(LookupError::Backend);
            }
            match action {
                Action::Return => return result.into_result().map_err(LookupError::Backend),
                Action::Continue => drop(result),
                Action::Merge => return Err(LookupError::UnsupportedMerge),
            }
        }
        Err(LookupError::NoServices)
    }
}

fn trim(bytes: &[u8]) -> &[u8] {
    let start = bytes.iter().position(|b| !b.is_ascii_whitespace()).unwrap_or(bytes.len());
    let end = bytes.iter().rposition(|b| !b.is_ascii_whitespace()).map_or(start, |i| i + 1);
    &bytes[start..end]
}

struct Scanner<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Scanner<'a> {
    fn end(&self) -> bool { self.position == self.bytes.len() }
    fn whitespace(&mut self) {
        while self.bytes.get(self.position).is_some_and(u8::is_ascii_whitespace) {
            self.position += 1;
        }
    }
    fn take(&mut self, byte: u8) -> bool {
        if self.bytes.get(self.position) == Some(&byte) {
            self.position += 1;
            true
        } else { false }
    }
    fn word(&mut self) -> &'a [u8] {
        let start = self.position;
        while self.bytes.get(self.position).is_some_and(|b| {
            !b.is_ascii_whitespace() && !matches!(*b, b'[' | b']' | b'=' | b'!')
        }) {
            self.position += 1;
        }
        &self.bytes[start..self.position]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(line: &str) -> HostsPolicy {
        HostsPolicy::parse(format!("hosts: {line}\n").as_bytes()).unwrap()
    }

    #[test]
    fn absent_entry_defaults_but_explicit_empty_does_not() {
        assert_eq!(HostsPolicy::parse(b"services: files\n# hosts: dns\n").unwrap(), HostsPolicy::default());
        let result: Result<(), LookupError<()>> = policy("").lookup(|_| panic!("no source"));
        assert_eq!(result, Err(LookupError::NoServices));
    }

    #[test]
    fn last_entry_overrides_even_a_malformed_prior_entry() {
        let p = HostsPolicy::parse(b"hosts: files [broken\n hosts \t: dns # files\n").unwrap();
        assert_eq!(p, policy("dns"));
        assert_eq!(HostsPolicy::parse(b"hosts: dns\nhosts:\n").unwrap(), policy(""));
    }

    #[test]
    fn database_and_backend_names_are_case_sensitive() {
        assert_eq!(HostsPolicy::parse(b"HOSTS: dns\n").unwrap(), HostsPolicy::default());
        assert_eq!(policy("FILES").services[0].backend, Backend::Unavailable);
    }

    #[test]
    fn source_order_and_unknown_services_are_preserved() {
        let p = policy("dns missing [UNAVAIL=continue] files dns");
        assert_eq!(p.services.iter().map(|s| s.backend).collect::<Vec<_>>(),
                   vec![Backend::Dns, Backend::Unavailable, Backend::Files, Backend::Dns]);
    }

    #[test]
    fn default_actions_cover_each_status() {
        for status in Status::ALL {
            let mut calls = 0;
            let got = policy("files dns").lookup(|_| {
                calls += 1;
                if calls == 2 { return BackendResult::Success(2); }
                match status {
                    Status::Success => BackendResult::Success(1),
                    Status::NotFound => BackendResult::NotFound(-1),
                    Status::Unavailable => BackendResult::Unavailable(-2),
                    Status::TryAgain => BackendResult::TryAgain(-3),
                }
            });
            assert_eq!(calls, if status == Status::Success { 1 } else { 2 });
            assert_eq!(got, Ok(calls));
        }
    }

    #[test]
    fn return_on_notfound_never_calls_dns() {
        let got: Result<(), _> = policy("files [NOTFOUND=return] dns").lookup(|source| {
            assert_eq!(source, Backend::Files);
            BackendResult::NotFound("missing")
        });
        assert_eq!(got, Err(LookupError::Backend("missing")));
    }

    #[test]
    fn return_on_unavailable_is_not_a_skipped_source() {
        let got: Result<(), _> = policy("unknown [UNAVAIL=return] files dns").lookup(|source| {
            assert_eq!(source, Backend::Unavailable);
            BackendResult::Unavailable(7)
        });
        assert_eq!(got, Err(LookupError::Backend(7)));
    }

    #[test]
    fn negation_and_case_insensitive_spaced_actions() {
        let p = policy("dns [ !UNavail = REturn TRYAGAIN = continue ] files");
        assert_eq!(p.services[0].actions,
                   [Action::Return, Action::Return, Action::Continue, Action::Continue]);
    }

    #[test]
    fn later_actions_override_negated_actions() {
        let p = policy("files [!SUCCESS=return NOTFOUND=continue] dns");
        assert_eq!(p.services[0].actions,
                   [Action::Return, Action::Continue, Action::Return, Action::Return]);
    }

    #[test]
    fn success_continue_discards_payload_before_next_callback() {
        use std::cell::Cell;
        struct Value<'a>(&'a Cell<bool>);
        impl Drop for Value<'_> { fn drop(&mut self) { self.0.set(true); } }
        let dropped = Cell::new(false);
        let result = policy("files [SUCCESS=continue] dns").lookup(|source| {
            if source == Backend::Files { BackendResult::Success(Value(&dropped)) }
            else {
                assert!(dropped.get());
                BackendResult::NotFound("terminal miss")
            }
        });
        assert!(matches!(result, Err(LookupError::Backend("terminal miss"))));
    }

    #[test]
    fn terminal_continue_returns_last_success_or_error() {
        let p = policy("files [!UNAVAIL=continue]");
        assert_eq!(p.lookup(|_| BackendResult::<_, ()>::Success(9)), Ok(9));
        assert_eq!(p.lookup(|_| BackendResult::<(), _>::TryAgain(8)), Err(LookupError::Backend(8)));
    }

    #[test]
    fn hosts_merge_is_rejected_without_querying_the_next_backend() {
        let mut calls = 0;
        let result = policy("files [SUCCESS=merge] dns").lookup(|_| {
            calls += 1;
            BackendResult::<_, ()>::Success(7)
        });
        assert_eq!(result, Err(LookupError::UnsupportedMerge));
        assert_eq!(calls, 1);
        assert_eq!(policy("files [SUCCESS=merge]").lookup(|_| BackendResult::<_, ()>::Success(7)), Err(LookupError::UnsupportedMerge));
        assert_eq!(policy("files [SUCCESS=merge]").lookup_forward(|_| BackendResult::<_, ()>::Success(7)), Ok(7));
    }

    #[test]
    fn malformed_actions_fail_closed() {
        for line in ["[NOTFOUND=return] dns", "files [] dns", "files [NOTFOUND=return",
                     "files [UNKNOWN=return] dns", "files [SUCCESS=other] dns",
                     "files [SUCCESS return] dns", "files ] dns", "files [!=return] dns"] {
            assert!(HostsPolicy::parse(format!("hosts: {line}\n").as_bytes()).is_err(), "{line}");
        }
    }

    #[test]
    fn every_action_status_and_negation_pair_has_the_expected_truth_table() {
        for (name, status) in [("SUCCESS", Status::Success), ("NOTFOUND", Status::NotFound),
                               ("UNAVAIL", Status::Unavailable), ("TRYAGAIN", Status::TryAgain)] {
            for negate in [false, true] {
                for (action_name, action) in [("return", Action::Return), ("continue", Action::Continue)] {
                    let p = policy(&format!("files [{}{name}={action_name}] dns", if negate { "!" } else { "" }));
                    let defaults = Service::new(Backend::Files).actions;
                    for candidate in Status::ALL {
                        let expected = if (candidate == status) != negate { action } else { defaults[candidate as usize] };
                        assert_eq!(p.services[0].actions[candidate as usize], expected);
                    }
                }
            }
        }
    }

    #[test]
    fn arbitrary_byte_inputs_are_bounded_and_never_panic() {
        let mut state = 0x9e3779b97f4a7c15u64;
        for length in 0..512 {
            let mut bytes = b"hosts: ".to_vec();
            for _ in 0..length {
                state ^= state << 13; state ^= state >> 7; state ^= state << 17;
                bytes.push(state as u8);
            }
            if let Ok(p) = HostsPolicy::parse(&bytes) {
                assert!(p.services.len() <= bytes.len());
            }
        }
    }
}
