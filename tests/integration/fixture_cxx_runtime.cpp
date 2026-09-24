// fixture_cxx_runtime.cpp — C++ runtime smoke under LD_PRELOAD (bd-rc0923-epic-eeuy4f.2)
//
// Every C++ program depends on libc paths that no C fixture touches:
// libstdc++ static init creates its C locale with newlocale(1 << LC_ALL, "C", 0)
// inside pthread_once, and every `throw` locates unwind tables through
// _dl_find_object. Both were broken under preload for months (the first
// aborted every C++ binary at load, the second every exception) with no gate
// noticing, because no fixture was C++.
#include <cstdio>
#include <cstdlib>
#include <locale>
#include <map>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

static int failures = 0;
#define CHECK(cond, what)                                              \
    do {                                                               \
        if (!(cond)) {                                                 \
            std::printf("FAIL: %s\n", what);                           \
            failures++;                                                \
        } else {                                                       \
            std::printf("ok: %s\n", what);                             \
        }                                                              \
    } while (0)

static int thrower(int depth) {
    if (depth == 0) throw std::out_of_range("deep");
    return thrower(depth - 1) + 1;
}

int main() {
    // 1. iostream + classic locale formatting (static init already ran).
    std::ostringstream os;
    os.imbue(std::locale::classic());
    os << 1234567 << ' ' << 3.25;
    CHECK(os.str() == "1234567 3.25", "ostringstream classic formatting");

    // 2. exceptions: simple, nested frames, rethrow, catch-all.
    bool caught = false;
    try { throw std::runtime_error("boom"); } catch (const std::exception &e) { caught = std::string(e.what()) == "boom"; }
    CHECK(caught, "throw/catch runtime_error");
    caught = false;
    try { (void)thrower(32); } catch (const std::out_of_range &) { caught = true; }
    CHECK(caught, "throw through 32 frames");
    caught = false;
    try {
        try { throw 42; } catch (...) { throw; }
    } catch (int v) { caught = v == 42; }
    CHECK(caught, "rethrow");

    // 3. threads, mutex, exception inside a thread.
    std::mutex mu;
    int sum = 0, thread_catches = 0;
    std::vector<std::thread> ts;
    for (int i = 0; i < 8; ++i)
        ts.emplace_back([&, i] {
            try { if (i % 2) throw std::logic_error("odd"); } catch (const std::logic_error &) {
                std::lock_guard<std::mutex> g(mu); thread_catches++;
            }
            std::lock_guard<std::mutex> g(mu); sum += i;
        });
    for (auto &t : ts) t.join();
    CHECK(sum == 28 && thread_catches == 4, "threads + per-thread exceptions");

    // 4. std::call_once (pthread_once underneath).
    std::once_flag once; int once_count = 0;
    for (int i = 0; i < 3; ++i) std::call_once(once, [&] { once_count++; });
    CHECK(once_count == 1, "std::call_once");

    // 5. allocator-heavy containers.
    std::map<int, std::string> m;
    for (int i = 0; i < 2000; ++i) m[i] = std::to_string(i * 3);
    CHECK(m[1999] == "5997" && m.size() == 2000, "map<int,string> churn");

    std::printf("fixture_cxx_runtime: %s\n", failures == 0 ? "PASS" : "FAIL");
    return failures == 0 ? 0 : 1;
}
