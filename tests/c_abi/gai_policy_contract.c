#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* Each child has its own /etc and its own first getaddrinfo call. Nothing in
 * the real /etc is changed. Real sockets probe the loopback source addresses;
 * DNS and network access outside the host are not required. */
static const char hosts[] = "127.0.0.2 policy.test\n::1 policy.test\n";
static char jail[1024];
static unsigned stamp;
static unsigned passed, failed, skipped;
static void die(const char *what) { perror(what); exit(2); }
static void put(const char *path, const char *text) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) die("open fixture");
    size_t length = strlen(text), written = 0;
    while (written < length) {
        ssize_t n = write(fd, text + written, length - written);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) die("write fixture");
        written += (size_t)n;
    }
    ++stamp;
    struct timespec times[2] = {{1900000000 + (time_t)stamp, 0}, {1900000000 + (time_t)stamp, 0}};
    if (futimens(fd, times) || close(fd)) die("close fixture");
}
static void outside_put(const char *name, const char *text) {
    char path[2048];
    if (snprintf(path, sizeof path, "%s/etc/%s", jail, name) >= (int)sizeof path) die("path");
    put(path, text);
}
static int snapshot(char result[128]) {
    struct addrinfo hints = {0}, *list = NULL;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    int rc = getaddrinfo("policy.test", NULL, &hints, &list);
    if (rc) { fprintf(stderr, "getaddrinfo: %s (%d)\n", gai_strerror(rc), rc); return 1; }
    result[0] = '\0';
    size_t used = 0;
    for (struct addrinfo *ai = list; ai; ai = ai->ai_next) {
        char address[INET6_ADDRSTRLEN];
        const void *p;
        if (ai->ai_family == AF_INET) p = &((struct sockaddr_in *)ai->ai_addr)->sin_addr;
        else if (ai->ai_family == AF_INET6) p = &((struct sockaddr_in6 *)ai->ai_addr)->sin6_addr;
        else { freeaddrinfo(list); return 1; }
        if (!inet_ntop(ai->ai_family, p, address, sizeof address)) die("inet_ntop");
        int n = snprintf(result + used, 128 - used, "%s%s", used ? "," : "", address);
        if (n < 0 || (size_t)n >= 128 - used) { freeaddrinfo(list); return 1; }
        used += (size_t)n;
    }
    freeaddrinfo(list);
    return 0;
}
struct test_case { const char *name, *config, *replacement, *expected, *expected_after; };
#define V6_FIRST "::1,127.0.0.2"
#define V4_FIRST "127.0.0.2,::1"
static const struct test_case cases[] = {
    {"default", "", NULL, V6_FIRST, NULL},
    {"prefer_ipv4", "precedence ::ffff:0:0/96 100\n", NULL, V4_FIRST, NULL},
    {"custom_table_keeps_default_catchall", "precedence ::ffff:0:0/96 30\n", NULL, V6_FIRST, NULL},
    {"precedence_replaces_not_merges", "precedence ::ffff:0:0/96 45\n", NULL, V4_FIRST, NULL},
    {"longest_prefix_unsorted", "precedence ::/0 200\nprecedence ::ffff:0:0/96 300\nprecedence ::1/128 400\n", NULL, V6_FIRST, NULL},
    {"large_precedence_values", "precedence ::1/128 256\nprecedence ::ffff:0:0/96 255\n", NULL, V6_FIRST, NULL},
    {"label_overrides_precedence", "precedence ::ffff:0:0/96 100\nlabel ::ffff:127.0.0.2/128 9\n", NULL, V6_FIRST, NULL},
    {"independent_label_and_precedence_tables", "label ::/0 7\n", NULL, V6_FIRST, NULL},
    {"mapped_scope_override", "precedence ::/0 40\nscopev4 ::ffff:127.0.0.0/104 1\n", NULL, V4_FIRST, NULL},
    {"native_ipv4_scope_override", "precedence ::/0 40\nscopev4 127.0.0.0/8 1\n", NULL, V4_FIRST, NULL},
    {"scope_match_before_precedence", "precedence ::ffff:0:0/96 100\nscopev4 ::ffff:127.0.0.2/128 1\n", NULL, V6_FIRST, NULL},
    {"comments_and_whitespace", "  # comment\n\tprecedence\t::ffff:0:0/96\t100  # prefer v4\n", NULL, V4_FIRST, NULL},
    {"invalid_entries_keep_defaults", "precedence ::ffff:0:0/129 100\nlabel nonsense 8\nprecedence ::1/128 -1\nprecedence ::1/128 2147483648\n", NULL, V6_FIRST, NULL},
    {"missing_prefix_length_is_host", "precedence ::ffff:127.0.0.2 100\n", NULL, V4_FIRST, NULL},
    {"first_duplicate_prefix_wins", "precedence ::ffff:0:0/96 100\nprecedence ::ffff:0:0/96 20\n", NULL, V4_FIRST, NULL},
    {"scope_table_replaces_defaults", "precedence ::/0 40\nscopev4 169.254.0.0/16 2\n", NULL, V6_FIRST, NULL},
    {"host_bits_in_prefix_are_masked", "precedence ::ffff:127.0.0.99/104 100\n", NULL, V4_FIRST, NULL},
    {"reload_disabled", "precedence ::ffff:0:0/96 100\n", "precedence ::1/128 100\n", V4_FIRST, V4_FIRST},
    {"reload_enabled", "reload yes\nprecedence ::ffff:0:0/96 100\n", "reload yes\nprecedence ::1/128 100\n", V4_FIRST, V6_FIRST},
};
static void run_case(const struct test_case *test) {
    outside_put("gai.conf", test->config);
    fflush(NULL);
    pid_t child = fork();
    if (child < 0) die("fork");
    if (!child) {
        alarm(10);
        if (chroot(jail) || chdir("/")) {
            if (errno == EPERM || errno == EACCES) _exit(77);
            die("chroot");
        }
        char result[128];
        if (snapshot(result)) _exit(1);
        printf("%s initial=%s\n", test->name, result);
        int okay = !strcmp(result, test->expected);
        if (test->replacement) {
            put("/etc/gai.conf", test->replacement);
            if (snapshot(result)) _exit(1);
            printf("%s after=%s\n", test->name, result);
            okay &= !strcmp(result, test->expected_after);
        }
        fflush(NULL);
        _exit(okay ? 0 : 1);
    }
    int status;
    while (waitpid(child, &status, 0) < 0) { if (errno != EINTR) die("waitpid"); }
    if (WIFEXITED(status) && WEXITSTATUS(status) == 77) {
        ++skipped; printf("SKIP %s: chroot permission unavailable\n", test->name);
    } else if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        ++passed; printf("PASS %s\n", test->name);
    } else { ++failed; printf("FAIL %s status=%d\n", test->name, status); }
}

/* UDP connect/getsockname asks the kernel for its selected source. No packets
 * are sent, no external services are contacted, and no routes are modified. */
static int source_for(uint32_t destination, uint32_t *source) {
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return 0;
    struct sockaddr_in peer = {.sin_family = AF_INET, .sin_port = htons(9)}, local;
    peer.sin_addr.s_addr = htonl(destination);
    socklen_t length = sizeof local;
    int okay = connect(fd, (struct sockaddr *)&peer, sizeof peer) == 0 &&
        getsockname(fd, (struct sockaddr *)&local, &length) == 0;
    if (okay) *source = ntohl(local.sin_addr.s_addr);
    close(fd);
    return okay;
}
static void ipv4_pair(const char *name, uint32_t first, uint32_t second, int reverse) {
    char a[INET_ADDRSTRLEN], b[INET_ADDRSTRLEN], records[256], expected[128];
    struct in_addr aa = {htonl(first)}, bb = {htonl(second)};
    if (!inet_ntop(AF_INET, &aa, a, sizeof a) || !inet_ntop(AF_INET, &bb, b, sizeof b)) die("pair address");
    snprintf(records, sizeof records, "%s policy.test\n%s policy.test\n", a, b);
    snprintf(expected, sizeof expected, "%s,%s", reverse ? b : a, reverse ? a : b);
    outside_put("hosts", records);
    const struct test_case test = {name, "", NULL, expected, NULL};
    run_case(&test);
}
static void prefix_contract(void) {
    const uint32_t off_a = 0xc0000201u, off_b = 0xc6336401u; /* Documentation networks. */
    uint32_t source, other, mask = 0;
    if (!source_for(off_a, &source) || !source_for(off_b, &other) || source != other) goto unavailable;
    struct ifaddrs *interfaces = NULL;
    if (getifaddrs(&interfaces)) goto unavailable;
    for (struct ifaddrs *it = interfaces; it; it = it->ifa_next) {
        if (it->ifa_addr && it->ifa_netmask && it->ifa_addr->sa_family == AF_INET &&
            ntohl(((struct sockaddr_in *)it->ifa_addr)->sin_addr.s_addr) == source) {
            mask = ntohl(((struct sockaddr_in *)it->ifa_netmask)->sin_addr.s_addr);
            break;
        }
    }
    freeifaddrs(interfaces);
    uint32_t near = source ^ 1u, far = source ^ 3u, hostmask = ~mask;
    if (!mask || hostmask < 7 || (hostmask & (hostmask + 1)) != 0 ||
        (source >> 24) == 127 || (source >> 16) == 0xa9fe ||
        (near & mask) != (source & mask) || (far & mask) != (source & mask) ||
        !(near & hostmask) || (near & hostmask) == hostmask ||
        !(far & hostmask) || (far & hostmask) == hostmask ||
        (off_a & mask) == (source & mask) || (off_b & mask) == (source & mask) ||
        !source_for(near, &other) || other != source ||
        !source_for(far, &other) || other != source) goto unavailable;
    ipv4_pair("prefix_on_link_beats_off_link", off_a, near, 1);
    ipv4_pair("prefix_on_link_keeps_priority", near, off_a, 0);
    ipv4_pair("prefix_longer_match_first", far, near, 1);
    ipv4_pair("prefix_off_link_order_preserved", off_a, off_b, 0);
    ipv4_pair("prefix_off_link_reverse_order_preserved", off_b, off_a, 0);
    return;
unavailable:
    ++skipped;
    puts("SKIP IPv4 prefix cases: need a shared source route and an ordinary IPv4 subnet");
}
int main(void) {
    char template[] = "/tmp/frankenlibc-gai-policy-XXXXXX";
    char *created = mkdtemp(template);
    if (!created) die("mkdtemp");
    if (snprintf(jail, sizeof jail, "%s", created) >= (int)sizeof jail) die("jail path");
    char directory[2048];
    snprintf(directory, sizeof directory, "%s/etc", jail);
    if (mkdir(directory, 0700)) die("mkdir");
    outside_put("hosts", hosts);
    outside_put("nsswitch.conf", "hosts: files\n");
    outside_put("host.conf", "multi on\n");
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; ++i) {
        run_case(&cases[i]);
    }
    prefix_contract();
    const char *names[] = {"hosts", "nsswitch.conf", "gai.conf", "host.conf"};
    for (size_t i = 0; i < 4; ++i) {
        snprintf(directory, sizeof directory, "%s/etc/%s", jail, names[i]);
        if (unlink(directory)) die("unlink fixture");
    }
    snprintf(directory, sizeof directory, "%s/etc", jail);
    if (rmdir(directory) || rmdir(jail)) die("rmdir fixture");
    printf("SUMMARY passed=%u failed=%u skipped=%u\n", passed, failed, skipped);
    return failed ? 1 : (passed ? 0 : 77);
}
