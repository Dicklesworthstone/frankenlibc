#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use frankenlibc_abi::{
    dlfcn_abi as dl, glibc_internal_abi as internal, inet_abi as inet, resolv_abi as resolv,
    unistd_abi as unistd,
};
use frankenlibc_core::elf::ElfLoader;

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

type Open = unsafe extern "C" fn(*const c_char, c_int) -> *mut c_void;
type Close = unsafe extern "C" fn(*mut c_void) -> c_int;
type Sym = unsafe extern "C" fn(*mut c_void, *const c_char) -> *mut c_void;
type Run = unsafe extern "C" fn() -> c_int;
type Function = unsafe extern "C" fn(u32) -> *mut c_void;
type Dynamic = unsafe extern "C" fn(*const c_char, *const c_char) -> *mut c_void;
type HostCalls = unsafe extern "C" fn(usize, c_int, c_int, c_int) -> c_int;

const HOSTS: &str = "\
192.0.2.10 fl-native-one fl-native-alias\n\
198.51.100.20 fl-native-two\n\
2001:db8::30 fl-native-six fl-native-v6-alias\n";
const NETWORKS: &str = "\
fl-native-net 192.0.2.0 fl-native-net-alias\n\
fl-native-second 198.51.100.0\n\
fl-native-third 198.18.0.0\n";

const SOURCE: &str = r#"#define _GNU_SOURCE
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <dlfcn.h>

#define CHECK(condition) do { if (!(condition)) return __LINE__; } while (0)
static const unsigned char v4[] = {192, 0, 2, 10};
static const unsigned char v6[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x30};
struct guarded {
    unsigned char before[16];
    _Alignas(void *) char buffer[8192];
    unsigned char after[16];
};
static int guards(const struct guarded *s) {
    for (size_t i = 0; i < 16; ++i)
        if (s->before[i] != 0xA5 || s->after[i] != 0xA5) return 0;
    return 1;
}
static int untouched_after(const struct guarded *s, size_t capacity) {
    if (!guards(s)) return 0;
    for (size_t i = capacity; i < sizeof s->buffer; ++i)
        if ((unsigned char)s->buffer[i] != 0xA5) return 0;
    return 1;
}
static int within(const void *p, const char *buffer, size_t size, size_t width) {
    uintptr_t address = (uintptr_t)p, start = (uintptr_t)buffer;
    return address >= start && address - start <= size && width <= size - (address - start);
}
static int string_in(const char *s, const char *buffer, size_t size) {
    if (!within(s, buffer, size, 1)) return 0;
    return memchr(s, '\0', size - ((uintptr_t)s - (uintptr_t)buffer)) != NULL;
}
static int vector_in(char **vector, size_t count, const char *buffer, size_t size) {
    return (uintptr_t)vector % _Alignof(char *) == 0
        && within(vector, buffer, size, (count + 1) * sizeof(char *))
        && vector[count] == NULL;
}
static int host_in(const struct hostent *h, const char *buffer, size_t size,
                   const char *name, int family, const unsigned char *address,
                   size_t addresses, size_t aliases) {
    size_t length = family == AF_INET ? 4 : 16;
    if (h->h_addrtype != family || h->h_length != (int)length
        || !string_in(h->h_name, buffer, size) || strcmp(h->h_name, name)
        || !vector_in(h->h_addr_list, addresses, buffer, size)
        || !vector_in(h->h_aliases, aliases, buffer, size)) return 0;
    for (size_t i = 0; i < addresses; ++i)
        if (!within(h->h_addr_list[i], buffer, size, length)) return 0;
    for (size_t i = 0; i < aliases; ++i)
        if (!string_in(h->h_aliases[i], buffer, size)) return 0;
    return !memcmp(h->h_addr_list[0], address, length);
}
static int network_in(const struct netent *n, const char *buffer, size_t size,
                      const char *name, uint32_t number, size_t aliases) {
    if (n->n_addrtype != AF_INET || n->n_net != number
        || !string_in(n->n_name, buffer, size) || strcmp(n->n_name, name)
        || !vector_in(n->n_aliases, aliases, buffer, size)) return 0;
    for (size_t i = 0; i < aliases; ++i)
        if (!string_in(n->n_aliases[i], buffer, size)) return 0;
    return 1;
}

int netdb_files(void) {
    struct hostent *h = gethostbyname("fl-native-alias");
    CHECK(h && !strcmp(h->h_name, "fl-native-one") && h->h_addrtype == AF_INET && h->h_length == 4);
    CHECK(h->h_addr_list[0] && !memcmp(h->h_addr_list[0], v4, 4) && h->h_addr_list[1] == NULL);
    h = gethostbyname2("fl-native-v6-alias", AF_INET6);
    CHECK(h && !strcmp(h->h_name, "fl-native-six") && h->h_length == 16);
    CHECK(!memcmp(h->h_addr_list[0], v6, 16));
    h = gethostbyaddr(v4, sizeof v4, AF_INET);
    CHECK(h && !strcmp(h->h_name, "fl-native-one"));
    h_errno = 777;
    CHECK(gethostbyname("fl-native-missing.invalid") == NULL && h_errno == HOST_NOT_FOUND);

    struct guarded storage;
    memset(&storage, 0xA5, sizeof storage);
    struct hostent record, *found = (struct hostent *)(uintptr_t)1;
    int error = 711;
    CHECK(gethostbyname_r("fl-native-one", &record, storage.buffer, 1, &found, &error) == ERANGE);
    CHECK(found == NULL && untouched_after(&storage, 1));
    CHECK(gethostbyname_r("fl-native-one", &record, storage.buffer, sizeof storage.buffer, &found, &error) == 0);
    CHECK(found == &record && error == 0);
    CHECK(host_in(&record, storage.buffer, sizeof storage.buffer, "fl-native-one", AF_INET, v4, 1, 1));
    CHECK(!strcmp(record.h_aliases[0], "fl-native-alias"));
    CHECK(gethostbyname2_r("fl-native-six", AF_INET6, &record, storage.buffer, sizeof storage.buffer, &found, &error) == 0);
    CHECK(found == &record && host_in(&record, storage.buffer, sizeof storage.buffer, "fl-native-six", AF_INET6, v6, 1, 1));
    CHECK(gethostbyaddr_r(v4, sizeof v4, AF_INET, &record, storage.buffer, sizeof storage.buffer, &found, &error) == 0);
    CHECK(found == &record && record.h_addrtype == AF_INET && !strcmp(record.h_name, "fl-native-one"));
    CHECK(gethostbyname_r("fl-native-missing.invalid", &record, storage.buffer, sizeof storage.buffer, &found, &error) == 0);
    CHECK(found == NULL && error == HOST_NOT_FOUND && guards(&storage));

    /* GNU enumeration reports through global h_errno, preserving the argument. */
    sethostent(0);
    memset(&storage, 0xA5, sizeof storage);
    error = 711; h_errno = 619;
    CHECK(gethostent_r(&record, storage.buffer, 1, &found, &error) == ERANGE);
    CHECK(found == NULL && error == 711 && h_errno == NETDB_INTERNAL);
    CHECK(untouched_after(&storage, 1));
    CHECK(gethostent_r(&record, storage.buffer, sizeof storage.buffer, &found, &error) == 0);
    CHECK(found == &record && !strcmp(record.h_name, "fl-native-one") && error == 711);
    CHECK(gethostent_r(&record, storage.buffer, sizeof storage.buffer, &found, &error) == 0);
    CHECK(found == &record && !strcmp(record.h_name, "fl-native-two"));
    CHECK(gethostent_r(&record, storage.buffer, sizeof storage.buffer, &found, &error) == ENOENT && found == NULL);
    CHECK(error == 711); /* A normal IPv6 files row is not part of this AF_INET iterator. */
    endhostent();

    struct netent *n = getnetbyname("fl-native-net-alias");
    CHECK(n && !strcmp(n->n_name, "fl-native-net") && n->n_net == 0xc0000200U);
    n = getnetbyaddr(0xc6336400U, AF_INET);
    CHECK(n && !strcmp(n->n_name, "fl-native-second"));
    h_errno = 777;
    CHECK(getnetbyname("fl-native-missing") == NULL && h_errno == HOST_NOT_FOUND);
    struct netent network, *net_found = (struct netent *)(uintptr_t)1;
    memset(&storage, 0xA5, sizeof storage);
    error = 711;
    CHECK(getnetbyname_r("fl-native-net", &network, storage.buffer, 1, &net_found, &error) == ERANGE);
    CHECK(net_found == NULL && untouched_after(&storage, 1));
    CHECK(getnetbyname_r("fl-native-net-alias", &network, storage.buffer, sizeof storage.buffer, &net_found, &error) == 0);
    CHECK(net_found == &network && network_in(&network, storage.buffer, sizeof storage.buffer, "fl-native-net", 0xc0000200U, 1));
    CHECK(!strcmp(network.n_aliases[0], "fl-native-net-alias"));
    CHECK(getnetbyaddr_r(0xc6336400U, AF_INET, &network, storage.buffer, sizeof storage.buffer, &net_found, &error) == 0);
    CHECK(net_found == &network && network_in(&network, storage.buffer, sizeof storage.buffer, "fl-native-second", 0xc6336400U, 0));
    CHECK(getnetbyname_r("fl-native-missing", &network, storage.buffer, sizeof storage.buffer, &net_found, &error) == 0);
    CHECK(net_found == NULL && error == HOST_NOT_FOUND);
    setnetent(0);
    memset(&storage, 0xA5, sizeof storage);
    error = 711; h_errno = 619;
    CHECK(getnetent_r(&network, storage.buffer, 1, &net_found, &error) == ERANGE);
    CHECK(net_found == NULL && error == 711 && h_errno == NETDB_INTERNAL);
    CHECK(untouched_after(&storage, 1));
    const uint32_t numbers[] = {0xc0000200U, 0xc6336400U, 0xc6120000U};
    for (size_t i = 0; i < 3; ++i) {
        CHECK(getnetent_r(&network, storage.buffer, sizeof storage.buffer, &net_found, &error) == 0);
        CHECK(net_found == &network && network.n_net == numbers[i] && error == 711);
    }
    CHECK(getnetent_r(&network, storage.buffer, sizeof storage.buffer, &net_found, &error) == ENOENT && net_found == NULL);
    CHECK(error == 711 && guards(&storage));
    endnetent();
    return 0;
}

int netdb_errors(void) {
    CHECK(__h_errno_location() != NULL);
    CHECK(!strcmp(hstrerror(HOST_NOT_FOUND), "Unknown host"));
    CHECK(!strcmp(hstrerror(TRY_AGAIN), "Host name lookup failure"));
    int channels[2];
    CHECK(pipe(channels) == 0);
    int saved = dup(STDERR_FILENO);
    if (saved < 0) { close(channels[0]); close(channels[1]); return __LINE__; }
    if (dup2(channels[1], STDERR_FILENO) < 0) {
        close(saved); close(channels[0]); close(channels[1]); return __LINE__;
    }
    close(channels[1]);
    h_errno = HOST_NOT_FOUND;
    herror("native-netdb");
    int restored = dup2(saved, STDERR_FILENO);
    close(saved);
    char output[128];
    ssize_t count = read(channels[0], output, sizeof output);
    close(channels[0]);
    static const char expected[] = "native-netdb: Unknown host\n";
    CHECK(restored == STDERR_FILENO && count == sizeof expected - 1);
    CHECK(!memcmp(output, expected, sizeof expected - 1));
    return 0;
}

int netdb_sources_block_files(void) {
    CHECK(gethostbyname("fl-native-one") == NULL);
    CHECK(getnetbyname("fl-native-net") == NULL);
    return 0;
}

void netdb_reset(void) { sethostent(0); setnetent(0); }
void netdb_end(void) { endhostent(); endnetent(); }
const char *netdb_next_host(void) {
    struct hostent *entry = gethostent();
    return entry ? entry->h_name : NULL;
}
uint32_t netdb_next_network(void) {
    struct netent *entry = getnetent();
    return entry ? entry->n_net : UINT32_MAX;
}
uint32_t netdb_network_number(const struct netent *entry) { return entry->n_net; }
int *netdb_error_cell(void) { return __h_errno_location(); }
int netdb_set_error(int value) { int previous = h_errno; h_errno = value; return previous; }

/* The provider deliberately reports TRY_AGAIN with ERANGE for these large
 * keyed host records. GNU returns EAGAIN, whereas NETDB_INTERNAL would mean
 * a buffer-only ERANGE retry. No private scratch may conceal that distinction. */
int netdb_module_host_calls(size_t capacity, int wanted_result, int wanted_found,
                           int wanted_error) {
    const unsigned char reverse4[] = {192, 0, 2, 42};
    const unsigned char reverse6[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x42};
    const unsigned char first4[] = {192, 0, 2, 41};
    const unsigned char first6[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x41};
    CHECK(capacity <= sizeof ((struct guarded *)0)->buffer);
    for (int operation = 0; operation < 5; ++operation) {
        struct guarded storage;
        memset(&storage, 0xA5, sizeof storage);
        struct hostent host, *found = (struct hostent *)(uintptr_t)1;
        int error = 711, result;
        errno = 619;
        h_errno = 811;
        int family = operation == 2 || operation == 4 ? AF_INET6 : AF_INET;
        if (operation == 0)
            result = gethostbyname_r("fltest-large", &host, storage.buffer, capacity, &found, &error);
        else if (operation < 3)
            result = gethostbyname2_r("fltest-large", family, &host, storage.buffer, capacity, &found, &error);
        else
            result = gethostbyaddr_r(family == AF_INET ? reverse4 : reverse6,
                                    family == AF_INET ? 4 : 16, family, &host,
                                    storage.buffer, capacity, &found, &error);
        CHECK(result == wanted_result && errno == wanted_result && error == wanted_error);
        CHECK(h_errno == 811 && untouched_after(&storage, capacity));
        if (wanted_found) {
            CHECK(found == &host);
            CHECK(host_in(&host, storage.buffer, capacity, "fltest-host.example", family,
                          family == AF_INET ? first4 : first6, 2, 3));
            CHECK(strlen(host.h_aliases[2]) == 3072);
        } else {
            CHECK(found == NULL);
        }
    }
    return 0;
}

/* Large records and enumeration use the same caller-owned storage across retries. */
int netdb_module(void) {
    int check = netdb_module_host_calls(1024, EAGAIN, 0, TRY_AGAIN);
    if (check) return check;
    check = netdb_module_host_calls(8192, 0, 1, NETDB_SUCCESS);
    if (check) return check;
    struct guarded storage;
    memset(&storage, 0xA5, sizeof storage);
    struct hostent host, *found = (struct hostent *)(uintptr_t)1;
    int error = 711;
    const unsigned char address[] = {192, 0, 2, 41};
    struct hostent *published = gethostbyname2("fltest-host", AF_INET6);
    CHECK(published && published->h_addrtype == AF_INET6 && published->h_length == 16);
    CHECK((unsigned char)published->h_addr_list[0][15] == 0x41);
    published = gethostbyaddr(address, sizeof address, AF_INET);
    CHECK(published && !strcmp(published->h_name, "fltest-host.example"));
    struct netent network, *net_found = (struct netent *)(uintptr_t)1;
    memset(&storage, 0xA5, sizeof storage);
    CHECK(getnetbyname_r("fltest-large-network", &network, storage.buffer, 1024, &net_found, &error) == ERANGE && net_found == NULL);
    CHECK(untouched_after(&storage, 1024));
    CHECK(getnetbyname_r("fltest-large-network", &network, storage.buffer, sizeof storage.buffer, &net_found, &error) == 0);
    CHECK(net_found == &network && network_in(&network, storage.buffer, sizeof storage.buffer, "fltest-network", 0xfedcba98U, 3));
    CHECK(strlen(network.n_aliases[2]) == 3072);
    struct netent *net_published = getnetbyaddr(0xdeadbeefU, AF_INET);
    CHECK(net_published && !strcmp(net_published->n_name, "fltest-network"));

    sethostent(0);
    CHECK(gethostent_r(&host, storage.buffer, sizeof storage.buffer, &found, &error) == 0);
    CHECK(found == &host && !strcmp(host.h_name, "fltest-host-small"));
    memset(&storage, 0xA5, sizeof storage);
    error = 711;
    CHECK(gethostent_r(&host, storage.buffer, 1024, &found, &error) == ERANGE && found == NULL);
    CHECK(error == 711 && h_errno == NETDB_INTERNAL);
    CHECK(untouched_after(&storage, 1024));
    CHECK(gethostent_r(&host, storage.buffer, sizeof storage.buffer, &found, &error) == 0);
    CHECK(found == &host && !strcmp(host.h_name, "fltest-host-large") && host.h_addrtype == AF_INET6);
    endhostent();
    setnetent(0);
    CHECK(getnetent_r(&network, storage.buffer, sizeof storage.buffer, &net_found, &error) == 0);
    CHECK(net_found == &network && network.n_net == 0xdeadbeefU);
    memset(&storage, 0xA5, sizeof storage);
    error = 711;
    CHECK(getnetent_r(&network, storage.buffer, 1024, &net_found, &error) == ERANGE && net_found == NULL);
    CHECK(error == 711 && h_errno == NETDB_INTERNAL);
    CHECK(untouched_after(&storage, 1024));
    CHECK(getnetent_r(&network, storage.buffer, sizeof storage.buffer, &net_found, &error) == 0);
    CHECK(net_found == &network && network.n_net == 0xfedcba98U);
    endnetent();
    CHECK(guards(&storage));
    return 0;
}

void *netdb_function(unsigned index) {
    switch (index) {
        case 0: return (void *)__h_errno_location;
        case 1: return (void *)hstrerror;
        case 2: return (void *)herror;
        case 3: return (void *)gethostbyname;
        case 4: return (void *)gethostbyname2;
        case 5: return (void *)gethostbyaddr;
        case 6: return (void *)gethostbyname_r;
        case 7: return (void *)gethostbyname2_r;
        case 8: return (void *)gethostbyaddr_r;
        case 9: return (void *)sethostent;
        case 10: return (void *)gethostent;
        case 11: return (void *)gethostent_r;
        case 12: return (void *)endhostent;
        case 13: return (void *)getnetent;
        case 14: return (void *)getnetent_r;
        case 15: return (void *)getnetbyname;
        case 16: return (void *)getnetbyname_r;
        case 17: return (void *)getnetbyaddr;
        case 18: return (void *)getnetbyaddr_r;
        case 19: return (void *)setnetent;
        case 20: return (void *)endnetent;
        default: return NULL;
    }
}
void *netdb_dynamic(const char *name, const char *version) {
    return version ? dlvsym(RTLD_DEFAULT, name, version) : dlsym(RTLD_DEFAULT, name);
}
"#;

fn symbols() -> [(&'static str, *const ()); 21] {
    [
        (
            "__h_errno_location",
            resolv::__h_errno_location as *const (),
        ),
        ("hstrerror", unistd::hstrerror as *const ()),
        ("herror", unistd::herror as *const ()),
        ("gethostbyname", resolv::gethostbyname as *const ()),
        ("gethostbyname2", unistd::gethostbyname2 as *const ()),
        ("gethostbyaddr", resolv::gethostbyaddr as *const ()),
        ("gethostbyname_r", inet::gethostbyname_r as *const ()),
        ("gethostbyname2_r", unistd::gethostbyname2_r as *const ()),
        ("gethostbyaddr_r", inet::gethostbyaddr_r as *const ()),
        ("sethostent", unistd::sethostent as *const ()),
        ("gethostent", unistd::gethostent as *const ()),
        ("gethostent_r", unistd::gethostent_r as *const ()),
        ("endhostent", unistd::endhostent as *const ()),
        ("getnetent", unistd::getnetent as *const ()),
        ("getnetent_r", unistd::getnetent_r as *const ()),
        ("getnetbyname", unistd::getnetbyname as *const ()),
        ("getnetbyname_r", unistd::getnetbyname_r as *const ()),
        ("getnetbyaddr", unistd::getnetbyaddr as *const ()),
        ("getnetbyaddr_r", unistd::getnetbyaddr_r as *const ()),
        ("setnetent", unistd::setnetent as *const ()),
        ("endnetent", unistd::endnetent as *const ()),
    ]
}

#[derive(Clone, Copy)]
struct Api {
    open: Open,
    close: Close,
    sym: Sym,
    native: bool,
}

impl Api {
    fn new(native: bool) -> Self {
        if native {
            Self {
                open: dl::dlopen,
                close: dl::dlclose,
                sym: dl::dlsym,
                native,
            }
        } else {
            unsafe {
                Self {
                    open: dlsym_oracle::host_fn(c"dlopen", dl::dlopen as *const ()),
                    close: dlsym_oracle::host_fn(c"dlclose", dl::dlclose as *const ()),
                    sym: dlsym_oracle::host_fn(c"dlsym", dl::dlsym as *const ()),
                    native,
                }
            }
        }
    }

    fn open(self, path: &Path) -> *mut c_void {
        let name = CString::new(path.as_os_str().as_bytes()).unwrap();
        let handle = unsafe { (self.open)(name.as_ptr(), libc::RTLD_NOW) };
        assert!(!handle.is_null(), "open {path:?}");
        if self.native {
            assert!(dl::native_dso_handle_for_tests(handle), "host fallback");
        }
        handle
    }

    fn close(self, handle: *mut c_void) {
        assert_eq!(unsafe { (self.close)(handle) }, 0);
    }

    fn symbol(self, handle: *mut c_void, name: &CStr) -> *mut c_void {
        let address = unsafe { (self.sym)(handle, name.as_ptr()) };
        assert!(!address.is_null(), "symbol {name:?}");
        address
    }

    fn run(self, handle: *mut c_void, name: &CStr) -> c_int {
        let run: Run = unsafe { std::mem::transmute(self.symbol(handle, name)) };
        unsafe { run() }
    }

    fn configure(self, sources: &CStr) {
        type Configure = unsafe extern "C" fn(*const c_char, *const c_char) -> c_int;
        let configure: Configure = if self.native {
            internal::__nss_configure_lookup
        } else {
            unsafe {
                dlsym_oracle::host_fn(
                    c"__nss_configure_lookup",
                    internal::__nss_configure_lookup as *const (),
                )
            }
        };
        for database in [c"hosts", c"networks"] {
            assert_eq!(unsafe { configure(database.as_ptr(), sources.as_ptr()) }, 0);
        }
    }
}

struct Fixture {
    dir: PathBuf,
    plt: PathBuf,
    got: PathBuf,
}

impl Fixture {
    fn at(dir: PathBuf) -> Self {
        Self {
            plt: dir.join("netdb.so"),
            got: dir.join("netdb-got.so"),
            dir,
        }
    }

    fn new(module: bool) -> Self {
        let fixture = Self::at(std::env::temp_dir().join(format!(
            "frankenlibc-netdb-runtime-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
        )));
        std::fs::create_dir(&fixture.dir).unwrap();
        std::fs::write(fixture.dir.join("hosts"), HOSTS).unwrap();
        std::fs::write(fixture.dir.join("networks"), NETWORKS).unwrap();
        std::fs::write(
            fixture.dir.join("nsswitch.conf"),
            "hosts: files [NOTFOUND=return]\nnetworks: files [NOTFOUND=return]\n",
        )
        .unwrap();
        let source = fixture.dir.join("netdb.c");
        std::fs::write(&source, SOURCE).unwrap();
        for (path, flags) in [(&fixture.plt, &[][..]), (&fixture.got, &["-fno-plt"][..])] {
            compile(&source, path, flags, true);
            let object = ElfLoader::new(0)
                .parse(&std::fs::read(path).unwrap())
                .unwrap();
            assert!(
                object.needed_libraries.is_empty(),
                "client must not import a host runtime"
            );
            for (name, _) in symbols() {
                assert!(
                    object
                        .dynsym
                        .iter()
                        .any(|symbol| object.symbol_name(symbol) == Some(name)),
                    "missing import {name}"
                );
            }
        }
        if module {
            let source = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/integration/fixture_nss_module_lib.c");
            compile(
                &source,
                &fixture.dir.join("libnss_fltest.so.2"),
                &["-DSERVICE=fltest"],
                false,
            );
        }
        fixture
    }
}

fn compile(source: &Path, output: &Path, flags: &[&str], native_client: bool) {
    let mut command = Command::new("gcc");
    command.args([
        "-shared",
        "-fPIC",
        "-O2",
        "-fno-builtin",
        "-Wl,--hash-style=both",
    ]);
    if native_client {
        command.arg("-nostdlib");
    }
    let output = command
        .args(flags)
        .arg(source)
        .arg("-o")
        .arg(output)
        .output()
        .expect("gcc is required");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn isolated(name: &str, native_only: bool, module: bool, scenario: fn(Api, &Fixture)) {
    if let Ok(mode) = std::env::var("FRANKENLIBC_NETDB_CHILD") {
        assert!(matches!(mode.as_str(), "host" | "native"));
        let fixture = Fixture::at(
            std::env::var_os("FRANKENLIBC_NETDB_FIXTURE")
                .unwrap()
                .into(),
        );
        scenario(Api::new(mode == "native"), &fixture);
        return;
    }
    let fixture = Fixture::new(module);
    let modes: &[&str] = if native_only {
        &["native"]
    } else {
        &["host", "native"]
    };
    for mode in modes {
        let mut libraries = vec![fixture.dir.clone()];
        if let Some(previous) = std::env::var_os("LD_LIBRARY_PATH") {
            libraries.extend(std::env::split_paths(&previous));
        }
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--nocapture"])
            .env("FRANKENLIBC_NETDB_CHILD", mode)
            .env("FRANKENLIBC_NETDB_FIXTURE", &fixture.dir)
            .env("FRANKENLIBC_HOSTS_PATH", fixture.dir.join("hosts"))
            .env("FRANKENLIBC_NETWORKS_PATH", fixture.dir.join("networks"))
            .env(
                "FRANKENLIBC_NSSWITCH_CONF",
                fixture.dir.join("nsswitch.conf"),
            )
            .env("LD_LIBRARY_PATH", std::env::join_paths(libraries).unwrap())
            .env("FLTEST_STATUS", "")
            .env("FLTEST_HOST_ENUM", "")
            .env("FLTEST_NETWORK_ENUM", "")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let start = Instant::now();
        loop {
            if child.try_wait().unwrap().is_some() {
                let output = child.wait_with_output().unwrap();
                assert!(
                    output.status.success(),
                    "{name}: {mode}: {}\nstdout:\n{}\nstderr:\n{}",
                    output.status,
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
                assert!(
                    String::from_utf8_lossy(&output.stdout)
                        .contains("test result: ok. 1 passed; 0 failed;"),
                    "{name}: {mode}: child did not execute its scenario:\n{}",
                    String::from_utf8_lossy(&output.stdout)
                );
                break;
            }
            if start.elapsed() > Duration::from_secs(40) {
                child.kill().unwrap();
                let _ = child.wait_with_output();
                panic!("{name}: {mode}: timeout");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

fn assert_providers(api: Api, handle: *mut c_void) {
    let imported: Function = unsafe { std::mem::transmute(api.symbol(handle, c"netdb_function")) };
    for (index, (name, expected)) in symbols().into_iter().enumerate() {
        let actual = unsafe { imported(index as u32) };
        assert!(!actual.is_null(), "missing runtime {name}");
        if api.native {
            assert_eq!(actual as usize, expected as usize, "wrong provider: {name}");
        } else {
            let name = CString::new(name).unwrap();
            let host = unsafe { dlsym_oracle::host_addr(&name, expected) };
            assert_eq!(actual, host, "wrong provider: {name:?}");
        }
    }
}

#[test]
fn native_netdb_files_and_source_policies_work_through_plt_and_got() {
    isolated(
        "native_netdb_files_and_source_policies_work_through_plt_and_got",
        true,
        false,
        |api, fixture| {
            for path in [&fixture.plt, &fixture.got] {
                let handle = api.open(path);
                assert_providers(api, handle);
                assert_eq!(api.run(handle, c"netdb_files"), 0);
                assert_eq!(api.run(handle, c"netdb_errors"), 0);
                api.configure(c"frankenlibc_missing_native_netdb [UNAVAIL=return] files");
                assert_eq!(api.run(handle, c"netdb_sources_block_files"), 0);
                api.configure(c"files");
                api.close(handle);
            }
        },
    );
}

#[test]
fn native_netdb_provider_versions_and_error_messages_match_gnu() {
    isolated(
        "native_netdb_provider_versions_and_error_messages_match_gnu",
        false,
        false,
        |api, fixture| {
            let handle = api.open(&fixture.plt);
            assert_providers(api, handle);
            let imported: Function =
                unsafe { std::mem::transmute(api.symbol(handle, c"netdb_function")) };
            let dynamic: Dynamic =
                unsafe { std::mem::transmute(api.symbol(handle, c"netdb_dynamic")) };
            for (index, (name, _)) in symbols().into_iter().enumerate() {
                let name = CString::new(name).unwrap();
                let expected = unsafe { imported(index as u32) };
                for version in [std::ptr::null(), c"GLIBC_2.2.5".as_ptr()] {
                    assert_eq!(unsafe { dynamic(name.as_ptr(), version) }, expected);
                }
                for version in [
                    c"GLIBC_2.34",
                    c"GLIBC_PRIVATE",
                    c"FRANKENLIBC_NO_SUCH_VERSION",
                ] {
                    assert!(
                        unsafe { dynamic(name.as_ptr(), version.as_ptr()) }.is_null(),
                        "unsupported version: {name:?}: {version:?}"
                    );
                }
            }
            assert_eq!(api.run(handle, c"netdb_errors"), 0);
            api.close(handle);
        },
    );
}

#[test]
fn native_netdb_error_cells_and_cursors_cross_dso_boundaries() {
    isolated(
        "native_netdb_error_cells_and_cursors_cross_dso_boundaries",
        true,
        false,
        |api, fixture| unsafe {
            let first = api.open(&fixture.plt);
            let second = api.open(&fixture.got);
            assert_providers(api, first);
            assert_providers(api, second);
            type Cell = unsafe extern "C" fn() -> *mut c_int;
            type SetError = unsafe extern "C" fn(c_int) -> c_int;
            type Void = unsafe extern "C" fn();
            type NextHost = unsafe extern "C" fn() -> *const c_char;
            type NextNetwork = unsafe extern "C" fn() -> u32;
            type NetworkNumber = unsafe extern "C" fn(*const c_void) -> u32;
            let first_cell: Cell = std::mem::transmute(api.symbol(first, c"netdb_error_cell"));
            let second_cell: Cell = std::mem::transmute(api.symbol(second, c"netdb_error_cell"));
            let first_error: SetError = std::mem::transmute(api.symbol(first, c"netdb_set_error"));
            let second_error: SetError =
                std::mem::transmute(api.symbol(second, c"netdb_set_error"));
            let caller_cell = resolv::__h_errno_location();
            assert_eq!(first_cell(), caller_cell);
            assert_eq!(second_cell(), caller_cell);
            *caller_cell = 1337;
            assert_eq!(first_error(711), 1337);
            assert_eq!(*caller_cell, 711);
            assert_eq!(second_error(619), 711);
            assert_eq!(*caller_cell, 619);

            let reset: Void = std::mem::transmute(api.symbol(second, c"netdb_reset"));
            let end: Void = std::mem::transmute(api.symbol(second, c"netdb_end"));
            let first_host: NextHost = std::mem::transmute(api.symbol(first, c"netdb_next_host"));
            let second_host: NextHost = std::mem::transmute(api.symbol(second, c"netdb_next_host"));
            let first_net: NextNetwork =
                std::mem::transmute(api.symbol(first, c"netdb_next_network"));
            let second_net: NextNetwork =
                std::mem::transmute(api.symbol(second, c"netdb_next_network"));
            let number: NetworkNumber =
                std::mem::transmute(api.symbol(first, c"netdb_network_number"));
            reset();
            let entry = unistd::gethostent().cast::<libc::hostent>();
            assert!(!entry.is_null());
            assert_eq!(CStr::from_ptr((*entry).h_name), c"fl-native-one");
            let name = first_host();
            assert!(!name.is_null());
            assert_eq!(CStr::from_ptr(name), c"fl-native-two");
            assert!(second_host().is_null());
            let entry = unistd::getnetent();
            assert!(!entry.is_null());
            assert_eq!(number(entry), 0xc0000200);
            assert_eq!(first_net(), 0xc6336400);
            assert_eq!(second_net(), 0xc6120000);
            assert_eq!(first_net(), u32::MAX);
            reset();
            let name = second_host();
            assert!(!name.is_null());
            assert_eq!(CStr::from_ptr(name), c"fl-native-one");
            assert_eq!(second_net(), 0xc0000200);
            end();
            api.close(first);
            api.close(second);
        },
    );
}

#[test]
fn native_netdb_selected_nss_module_matches_gnu() {
    isolated(
        "native_netdb_selected_nss_module_matches_gnu",
        false,
        true,
        |api, fixture| {
            for path in [&fixture.plt, &fixture.got] {
                let handle = api.open(path);
                assert_providers(api, handle);
                api.configure(c"fltest");
                assert_eq!(api.run(handle, c"netdb_module"), 0);
                let calls: HostCalls =
                    unsafe { std::mem::transmute(api.symbol(handle, c"netdb_module_host_calls")) };
                for (sources, capacity, result, found, error) in [
                    (c"fltest [TRYAGAIN=return] files", 1024, libc::EAGAIN, 0, 2),
                    (c"fltest [TRYAGAIN=continue] files", 1024, 0, 0, 1),
                    (c"fltest [SUCCESS=continue] files", 8192, 0, 0, 1),
                    (
                        c"fltest [SUCCESS=continue] frankenlibc_missing_netdb_provider",
                        8192,
                        0,
                        1,
                        0,
                    ),
                    (
                        c"fltest frankenlibc_missing_netdb_provider",
                        1024,
                        libc::EAGAIN,
                        0,
                        2,
                    ),
                    (
                        c"frankenlibc_missing_netdb_provider [UNAVAIL=return] fltest",
                        8192,
                        619,
                        0,
                        -1,
                    ),
                ] {
                    api.configure(sources);
                    assert_eq!(
                        unsafe { calls(capacity, result, found, error) },
                        0,
                        "source transition {sources:?}"
                    );
                }
                api.close(handle);
            }
        },
    );
}
