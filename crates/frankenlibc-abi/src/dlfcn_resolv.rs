//! Address resolution frontends for native network plugins.
//!
//! Keep getaddrinfo and freeaddrinfo in one ownership domain. A native lookup
//! must never pair FrankenLibC's address-list allocator with the host's release
//! function. The existing resolver owns numeric, hosts-file and DNS policy;
//! this table only makes that implementation reachable by native DSOs.

use crate::{inet_abi as inet, resolv_abi as resolv};

pub(super) fn address(name: &str, version: Option<&str>) -> Option<u64> {
    let baseline = if cfg!(target_arch = "aarch64") {
        "GLIBC_2.17"
    } else {
        "GLIBC_2.2.5"
    };
    if version.is_some_and(|version| version != baseline) {
        return None;
    }
    let function = match name {
        "getaddrinfo" => resolv::getaddrinfo as *const (),
        "freeaddrinfo" => resolv::freeaddrinfo as *const (),
        "getnameinfo" => resolv::getnameinfo as *const (),
        "gai_strerror" => resolv::gai_strerror as *const (),
        "inet_pton" => inet::inet_pton as *const (),
        "inet_ntop" => inet::inet_ntop as *const (),
        _ => return None,
    };
    Some(function as usize as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_resolver_uses_matching_owned_frontends_and_versions() {
        let baseline = if cfg!(target_arch = "aarch64") {
            "GLIBC_2.17"
        } else {
            "GLIBC_2.2.5"
        };
        for (name, function) in [
            ("getaddrinfo", resolv::getaddrinfo as *const ()),
            ("freeaddrinfo", resolv::freeaddrinfo as *const ()),
            ("getnameinfo", resolv::getnameinfo as *const ()),
            ("gai_strerror", resolv::gai_strerror as *const ()),
            ("inet_pton", inet::inet_pton as *const ()),
            ("inet_ntop", inet::inet_ntop as *const ()),
        ] {
            let expected = Some(function as usize as u64);
            assert_eq!(address(name, None), expected, "{name}");
            assert_eq!(address(name, Some(baseline)), expected, "{name}");
            assert_eq!(super::super::address(name, Some(baseline)), expected);
            for version in ["GLIBC_2.34", "GLIBC_PRIVATE", "GLIBC_9.99", ""] {
                assert_eq!(address(name, Some(version)), None, "{name}");
                assert_eq!(super::super::address(name, Some(version)), None);
            }
        }
        assert_eq!(address("not_a_resolver_function", None), None);
        assert_eq!(address("socket", None), None);
    }

    #[test]
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn native_resolver_dso_resolves_connects_and_releases_address_lists() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        use std::process::Command;
        use std::time::{SystemTime, UNIX_EPOCH};

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "frankenlibc-native-resolver-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir(&directory).unwrap();
        let source = directory.join("network.c");
        let library = directory.join("network.so");
        std::fs::write(&source, NETWORK).unwrap();
        let output = Command::new("cc")
            .args([
                "-shared",
                "-fPIC",
                "-nostdlib",
                "-O2",
                "-fno-stack-protector",
                "-fno-builtin",
                "-Wall",
                "-Wextra",
                "-Werror",
            ])
            .arg(&source)
            .arg("-o")
            .arg(&library)
            .output()
            .expect("C compiler required for the native network DSO test");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let name = CString::new(library.as_os_str().as_bytes()).unwrap();
        // SAFETY: the compiled fixture exports the declared C function. Keep
        // its mapping alive through all resolver allocation and release calls.
        unsafe {
            let handle = crate::dlfcn_abi::dlopen(name.as_ptr(), libc::RTLD_NOW);
            assert!(!handle.is_null(), "native network DSO failed to load");
            assert_eq!(handle as usize & 0xff, 0x4d, "host fallback is not a pass");
            let entry = crate::dlfcn_abi::dlsym(handle, c"native_resolver_frontends".as_ptr());
            assert!(!entry.is_null());
            let run: unsafe extern "C" fn() -> i32 = std::mem::transmute(entry);
            let result = run();
            assert_eq!(crate::dlfcn_abi::dlclose(handle), 0);
            assert_eq!(result, 0, "native network fixture failed");
        }
        // Keep unique temporary fixtures available for failure diagnosis.
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    const NETWORK: &str = r#"
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <dlfcn.h>

static int transfer(int sender, int receiver) {
    const char payload[] = "native resolver to socket";
    char received[sizeof(payload)];
    size_t sent = 0, got = 0;
    while (sent < sizeof(payload)) {
        ssize_t n = send(sender, payload + sent, sizeof(payload) - sent, MSG_NOSIGNAL);
        if (n <= 0) return 1;
        sent += (size_t)n;
    }
    while (got < sizeof(payload)) {
        ssize_t n = recv(receiver, received + got, sizeof(payload) - got, 0);
        if (n <= 0) return 2;
        got += (size_t)n;
    }
    return memcmp(payload, received, sizeof(payload)) != 0;
}

int native_resolver_frontends(void) {
    struct addrinfo hints = {0}, *answer = 0;
    struct sockaddr_storage bound;
    struct timeval timeout = {2, 0};
    socklen_t bound_size = sizeof(bound);
    char host[NI_MAXHOST], service[NI_MAXSERV], text[INET6_ADDRSTRLEN];
    unsigned char address[16];
    int listener = -1, client = -1, peer = -1, result = 0;
#define REQUIRE(test, code) do { if (!(test)) { result = (code); goto done; } } while (0)
    hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    REQUIRE(getaddrinfo("127.0.0.1", "0", &hints, &answer) == 0 && answer, 1);
    listener = socket(answer->ai_family, answer->ai_socktype, answer->ai_protocol);
    REQUIRE(listener >= 0, 2);
    REQUIRE(setsockopt(listener, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0, 3);
    REQUIRE(bind(listener, answer->ai_addr, answer->ai_addrlen) == 0, 4);
    freeaddrinfo(answer);
    answer = 0;
    REQUIRE(listen(listener, 1) == 0, 5);
    REQUIRE(getsockname(listener, (struct sockaddr *)&bound, &bound_size) == 0, 6);
    REQUIRE(getnameinfo((struct sockaddr *)&bound, bound_size, host, sizeof(host),
                        service, sizeof(service), NI_NUMERICHOST | NI_NUMERICSERV) == 0, 7);
    REQUIRE(strcmp(host, "127.0.0.1") == 0 && strcmp(service, "0") != 0, 8);
    REQUIRE(inet_pton(AF_INET, host, address) == 1, 9);
    REQUIRE(inet_ntop(AF_INET, address, text, sizeof(text)) == text, 10);
    REQUIRE(strcmp(text, host) == 0, 11);
    REQUIRE(getaddrinfo(host, service, &hints, &answer) == 0 && answer, 12);
    client = socket(answer->ai_family, answer->ai_socktype, answer->ai_protocol);
    REQUIRE(client >= 0, 13);
    REQUIRE(setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0, 14);
    REQUIRE(connect(client, answer->ai_addr, answer->ai_addrlen) == 0, 15);
    freeaddrinfo(answer);
    answer = 0;
    peer = accept(listener, 0, 0);
    REQUIRE(peer >= 0, 16);
    REQUIRE(setsockopt(peer, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0, 17);
    REQUIRE(transfer(client, peer) == 0, 18);

    /* IPv6 formatting/resolution requires no IPv6 route or external DNS. */
    hints.ai_family = AF_INET6;
    REQUIRE(getaddrinfo("::1", "443", &hints, &answer) == 0 && answer, 19);
    REQUIRE(getnameinfo(answer->ai_addr, answer->ai_addrlen, host, sizeof(host),
                        service, sizeof(service), NI_NUMERICHOST | NI_NUMERICSERV) == 0, 20);
    REQUIRE(strcmp(host, "::1") == 0 && strcmp(service, "443") == 0, 21);
    REQUIRE(inet_pton(AF_INET6, host, address) == 1, 22);
    REQUIRE(inet_ntop(AF_INET6, address, text, sizeof(text)) == text, 23);
    REQUIRE(strcmp(text, host) == 0, 24);
    freeaddrinfo(answer);
    answer = 0;
    REQUIRE(getaddrinfo("not-numeric.invalid", "443", &hints, &answer) == EAI_NONAME, 25);
    REQUIRE(gai_strerror(EAI_NONAME) && *gai_strerror(EAI_NONAME), 26);
    errno = 0;
    REQUIRE(inet_ntop(AF_INET6, address, text, 1) == 0 && errno == ENOSPC, 27);
    REQUIRE(dlsym(RTLD_DEFAULT, "getaddrinfo") == (void *)getaddrinfo, 28);
    REQUIRE(dlsym(RTLD_DEFAULT, "freeaddrinfo") == (void *)freeaddrinfo, 29);
#if defined(__aarch64__)
    const char *baseline = "GLIBC_2.17";
#else
    const char *baseline = "GLIBC_2.2.5";
#endif
    REQUIRE(dlvsym(RTLD_DEFAULT, "getaddrinfo", baseline) == (void *)getaddrinfo, 30);
    REQUIRE(dlvsym(RTLD_DEFAULT, "getaddrinfo", "GLIBC_2.34") == 0, 31);
    REQUIRE(dlerror() != 0 && dlerror() == 0, 32);
done:
    if (answer) freeaddrinfo(answer);
    if (peer >= 0) close(peer);
    if (client >= 0) close(client);
    if (listener >= 0) close(listener);
    return result;
#undef REQUIRE
}
"#;
}
