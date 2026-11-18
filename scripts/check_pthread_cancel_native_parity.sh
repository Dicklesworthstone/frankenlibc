#!/usr/bin/env bash
# End-to-end cancellation parity gate for bd-rc0923-epic-eeuy4f.24.
# Exercises deployed C and C++ cancellation points, LIFO C cleanup handlers,
# C++ RAII / abi::__forced_unwind / catch(...), owned-startup main-thread
# cancellation and last-thread exit(0), C11 thrd_* cancellation, and narrow/wide
# stdio stream lock release across BOTH hosted (FRANKENLIBC_THREAD_NATIVE=0)
# and native clone (FRANKENLIBC_THREAD_NATIVE=1) backends in strict and hardened
# modes against live host glibc.
set -euo pipefail
exec 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&- 2>/dev/null || true

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
library="${1:-${LIB:-$root/target/release/libfrankenlibc_abi.so}}"
if [[ ! -f $library ]]; then
  echo "error: candidate library not found at $library" >&2
  exit 2
fi
library=$(realpath -e -- "$library")
out=${FRANKENLIBC_CANCEL_PARITY_OUT_DIR:-"$root/target/pthread-cancel-native-parity"}
mkdir -p -- "$out"

"${CC:-cc}" -std=c11 -O2 -Wall -Wextra -Werror -pthread \
  "$root/tests/integration/fixture_pthread_cancel.c" -ldl -o "$out/fixture_pthread_cancel"
"${CXX:-c++}" -std=c++17 -O2 -Wall -Wextra -Werror -pthread \
  "$root/tests/integration/fixture_cancel_forced_unwind.cpp" -ldl -o "$out/fixture_cancel_forced_unwind"
"${CC:-cc}" -std=c11 -O2 -Wall -Wextra -Werror -pthread \
  "$root/tests/integration/fixture_c11_thread_cancel.c" -ldl -o "$out/c11_sleep"
"${CC:-cc}" -std=c11 -O2 -Wall -Wextra -Werror -pthread \
  "$root/tests/integration/fixture_c11_thread_cancel_lifecycle.c" -ldl -o "$out/c11_lifecycle"
"${CXX:-c++}" -std=c++17 -O2 -Wall -Wextra -Werror -pthread \
  "$root/tests/integration/fixture_c11_thread_cancel_cpp.cpp" -ldl -o "$out/c11_cpp"
"${CC:-cc}" -std=c11 -O2 -Wall -Wextra -Werror -pthread \
  "$root/tests/integration/fixture_stdio_cancel.c" -ldl -o "$out/stdio_c"
"${CXX:-c++}" -x c++ -std=c++17 -O2 -Wall -Wextra -Werror -pthread \
  "$root/tests/integration/fixture_stdio_cancel.c" -ldl -o "$out/stdio_cpp"

sha256sum "$library" \
  "$out/fixture_pthread_cancel" \
  "$out/fixture_cancel_forced_unwind" \
  "$out/c11_sleep" "$out/c11_lifecycle" "$out/c11_cpp" \
  "$out/stdio_c" "$out/stdio_cpp" > "$out/input-sha256.txt"

# 1. Full POSIX/GNU cancellation point + owned-startup main-thread matrix.
env -u LD_PRELOAD -u FRANKENLIBC_MODE -u FRANKENLIBC_THREAD_NATIVE \
  timeout --kill-after=3s 30s "$out/fixture_pthread_cancel" > "$out/cancel-host.out" 2> "$out/cancel-host.err"
test ! -s "$out/cancel-host.err"

for backend in 0 1; do
  for mode in strict hardened; do
    timeout --kill-after=3s 30s env LD_PRELOAD="$library" \
      FRANKENLIBC_MODE="$mode" FRANKENLIBC_THREAD_NATIVE="$backend" \
      "$out/fixture_pthread_cancel" > "$out/cancel-b${backend}-${mode}.out" 2> "$out/cancel-b${backend}-${mode}.err"
    diff -u "$out/cancel-host.out" "$out/cancel-b${backend}-${mode}.out"
    test ! -s "$out/cancel-b${backend}-${mode}.err"
  done
done

# 2. system() signal-disposition & child-reaping overlap/cancellation matrix.
for sigcase in inherited-int inherited-quit overlap-first overlap-second cancel-first cancel-second; do
  env -u LD_PRELOAD -u FRANKENLIBC_MODE -u FRANKENLIBC_THREAD_NATIVE \
    timeout --kill-after=2s 15s "$out/fixture_pthread_cancel" system-signals "$sigcase" \
    > "$out/syssig-host-${sigcase}.out" 2> "$out/syssig-host-${sigcase}.err"
  for backend in 0 1; do
    for mode in strict hardened; do
      timeout --kill-after=2s 15s env LD_PRELOAD="$library" \
        FRANKENLIBC_MODE="$mode" FRANKENLIBC_THREAD_NATIVE="$backend" \
        FRANKENLIBC_TEST_LIBRARY="$library" \
        "$out/fixture_pthread_cancel" system-signals "$sigcase" \
        > "$out/syssig-b${backend}-${mode}-${sigcase}.out" 2> "$out/syssig-b${backend}-${mode}-${sigcase}.err"
      diff -u "$out/syssig-host-${sigcase}.out" "$out/syssig-b${backend}-${mode}-${sigcase}.out"
      diff -u "$out/syssig-host-${sigcase}.err" "$out/syssig-b${backend}-${mode}-${sigcase}.err"
    done
  done
done

# 3. C++ forced unwind (RAII, abi::__forced_unwind, catch(...)) + /proc/self/task/<tid>/syscall probes.
env -u LD_PRELOAD -u FRANKENLIBC_MODE -u FRANKENLIBC_THREAD_NATIVE \
  timeout --kill-after=2s 15s "$out/fixture_cancel_forced_unwind" > "$out/unwind-host.out" 2> "$out/unwind-host.err"
test ! -s "$out/unwind-host.err"

for backend in 0 1; do
  for mode in strict hardened; do
    timeout --kill-after=2s 15s env LD_PRELOAD="$library" \
      FRANKENLIBC_MODE="$mode" FRANKENLIBC_THREAD_NATIVE="$backend" \
      "$out/fixture_cancel_forced_unwind" > "$out/unwind-b${backend}-${mode}.out" 2> "$out/unwind-b${backend}-${mode}.err"
    diff -u "$out/unwind-host.out" "$out/unwind-b${backend}-${mode}.out"
    test ! -s "$out/unwind-b${backend}-${mode}.err"
  done
done

for probe in \
  native-cancel-blocked-eventfd-read \
  native-cancel-blocked-eventfd-write \
  native-cancel-disabled-blocked-eventfd-read \
  native-cancel-disabled-blocked-eventfd-write \
  native-cancel-internal-read \
  native-cancel-catch-all-read \
  native-exit-siblings; do
  for mode in strict hardened; do
    timeout --kill-after=2s 15s env LD_PRELOAD="$library" \
      FRANKENLIBC_MODE="$mode" FRANKENLIBC_THREAD_NATIVE=1 \
      "$out/fixture_cancel_forced_unwind" "$probe" "$library" \
      > "$out/probe-${mode}-${probe}.out" 2> "$out/probe-${mode}-${probe}.err"
    grep -qx "pthread-native-unwind:${probe}:PASS" "$out/probe-${mode}-${probe}.out"
    test ! -s "$out/probe-${mode}-${probe}.err"
  done
done

# 3b. Asynchronous cancellation (PTHREAD_CANCEL_ASYNCHRONOUS) CPU-spin + sigmask
# restoration + main-thread async cancellation across hosted and native backends.
cat > "$out/async_cancel_probe.cpp" <<'EOF'
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>

static std::atomic<int> g_spin_ready{0};
static std::atomic<int> g_c_cleanup_ran{0};
static std::atomic<int> g_cpp_dtor_ran{0};
static std::atomic<int> g_user_sigmask_ok{0};
static std::atomic<int> g_nested_cancel_ok{0};

__attribute__((noinline)) static void spin_forever() {
    while (true) {
        asm volatile("" ::: "memory");
    }
}

struct RaiiWitness {
    std::atomic<int> *flag;
    ~RaiiWitness() { flag->store(1, std::memory_order_release); }
};

struct NestedPipeCtx {
    int rfd;
    std::atomic<int> *entered;
};

static void *nested_reader(void *arg) {
    auto *ctx = static_cast<NestedPipeCtx *>(arg);
    ctx->entered->store(1, std::memory_order_release);
    char ch = 0;
    ssize_t n = read(ctx->rfd, &ch, 1);
    (void)n;
    return nullptr;
}

static void worker_cleanup(void *) {
    g_c_cleanup_ran.store(1, std::memory_order_release);
    sigset_t cur;
    sigemptyset(&cur);
    if (pthread_sigmask(SIG_SETMASK, nullptr, &cur) == 0 &&
        sigismember(&cur, SIGUSR1) == 1 &&
        sigismember(&cur, SIGUSR2) == 0) {
        g_user_sigmask_ok.store(1, std::memory_order_release);
    }
    int fds[2] = {-1, -1};
    if (pipe(fds) == 0) {
        std::atomic<int> entered{0};
        NestedPipeCtx ctx{fds[0], &entered};
        pthread_t child{};
        if (pthread_create(&child, nullptr, nested_reader, &ctx) == 0) {
            while (entered.load(std::memory_order_acquire) == 0) {
                usleep(1000);
            }
            usleep(5000);
            if (pthread_cancel(child) == 0) {
                void *res = nullptr;
                if (pthread_join(child, &res) == 0 && res == PTHREAD_CANCELED) {
                    g_nested_cancel_ok.store(1, std::memory_order_release);
                }
            }
        }
        close(fds[0]);
        close(fds[1]);
    }
}

static void *async_spin_worker(void *) {
    RaiiWitness guard{&g_cpp_dtor_ran};
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGUSR1);
    pthread_sigmask(SIG_BLOCK, &mask, nullptr);
    int rc = 0;
    pthread_cleanup_push(worker_cleanup, nullptr);
    rc = pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, nullptr);
    if (rc == 0) {
        g_spin_ready.store(1, std::memory_order_release);
        void (*volatile spin_fn)() = spin_forever;
        spin_fn();
    }
    pthread_cleanup_pop(0);
    return reinterpret_cast<void *>(static_cast<intptr_t>(rc));
}

struct MainCancelCtx {
    pthread_t main_thr;
    std::atomic<int> *ready;
};

static std::atomic<int> g_main_cleanup_ran{0};
static void main_cleanup(void *) {
    g_main_cleanup_ran.store(1, std::memory_order_release);
}
static void main_atexit_check() {
    if (g_main_cleanup_ran.load(std::memory_order_acquire) == 1) {
        const char msg[] = "async-main-cancel:PASS\n";
        ssize_t n = write(STDOUT_FILENO, msg, sizeof(msg) - 1);
        (void)n;
    }
}

static void *main_canceller(void *arg) {
    auto *ctx = static_cast<MainCancelCtx *>(arg);
    pthread_detach(pthread_self());
    while (ctx->ready->load(std::memory_order_acquire) == 0) {
        usleep(1000);
    }
    usleep(5000);
    pthread_cancel(ctx->main_thr);
    return nullptr;
}

int main(int argc, char **argv) {
    if (argc == 2 && std::strcmp(argv[1], "main-async") == 0) {
        std::atexit(main_atexit_check);
        static std::atomic<int> s_main_ready{0};
        static MainCancelCtx ctx{pthread_self(), &s_main_ready};
        pthread_t helper{};
        if (pthread_create(&helper, nullptr, main_canceller, &ctx) != 0) {
            return 2;
        }
        pthread_cleanup_push(main_cleanup, nullptr);
        if (pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, nullptr) != 0) {
            return 3;
        }
        s_main_ready.store(1, std::memory_order_release);
        void (*volatile spin_fn)() = spin_forever;
        spin_fn();
        pthread_cleanup_pop(0);
        return 1;
    }

    pthread_t th{};
    if (pthread_create(&th, nullptr, async_spin_worker, nullptr) != 0) {
        return 2;
    }
    while (g_spin_ready.load(std::memory_order_acquire) == 0) {
        usleep(1000);
    }
    usleep(5000);
    if (pthread_cancel(th) != 0) {
        return 3;
    }
    void *res = nullptr;
    if (pthread_join(th, &res) != 0 || res != PTHREAD_CANCELED) {
        std::fprintf(stderr, "async join failed: res=%p\n", res);
        return 4;
    }
    if (g_c_cleanup_ran.load() != 1 || g_cpp_dtor_ran.load() != 1 ||
        g_user_sigmask_ok.load() != 1 || g_nested_cancel_ok.load() != 1) {
        std::fprintf(stderr, "async flags: c=%d cpp=%d sigmask=%d nested=%d\n",
                     g_c_cleanup_ran.load(), g_cpp_dtor_ran.load(),
                     g_user_sigmask_ok.load(), g_nested_cancel_ok.load());
        return 5;
    }
    std::printf("async-worker-cancel:PASS\n");
    return 0;
}
EOF
"${CXX:-c++}" -std=c++17 -O2 -Wall -Wextra -Werror -pthread \
  "$out/async_cancel_probe.cpp" -o "$out/async_cancel_probe"

for backend in 0 1; do
  for mode in strict hardened; do
    timeout --kill-after=2s 10s env LD_PRELOAD="$library" \
      FRANKENLIBC_MODE="$mode" FRANKENLIBC_THREAD_NATIVE="$backend" \
      "$out/async_cancel_probe" > "$out/async-w-b${backend}-${mode}.out" 2> "$out/async-w-b${backend}-${mode}.err"
    grep -qx "async-worker-cancel:PASS" "$out/async-w-b${backend}-${mode}.out"
    test ! -s "$out/async-w-b${backend}-${mode}.err"

    timeout --kill-after=2s 10s env LD_PRELOAD="$library" \
      FRANKENLIBC_MODE="$mode" FRANKENLIBC_THREAD_NATIVE="$backend" \
      "$out/async_cancel_probe" main-async > "$out/async-m-b${backend}-${mode}.out" 2> "$out/async-m-b${backend}-${mode}.err"
    grep -qx "async-main-cancel:PASS" "$out/async-m-b${backend}-${mode}.out"
    test ! -s "$out/async-m-b${backend}-${mode}.err"
  done
done

# 4. C11 thread cancellation & lifecycle parity across hosted and native backends.
run_c11_case() {
  local bin=$1 case=$2 backend mode
  env -u LD_PRELOAD -u FRANKENLIBC_MODE -u FRANKENLIBC_THREAD_NATIVE -u FRANKENLIBC_TEST_LIBRARY \
    timeout --kill-after=2s 12s "$bin" "$case" > "$out/c11-host-${case}.out" 2> "$out/c11-host-${case}.err"
  for backend in 0 1; do
    for mode in strict hardened; do
      timeout --kill-after=2s 12s env LD_PRELOAD="$library" \
        FRANKENLIBC_MODE="$mode" FRANKENLIBC_THREAD_NATIVE="$backend" \
        FRANKENLIBC_TEST_LIBRARY="$library" \
        "$bin" "$case" > "$out/c11-b${backend}-${mode}-${case}.out" 2> "$out/c11-b${backend}-${mode}-${case}.err"
      diff -u "$out/c11-host-${case}.out" "$out/c11-b${backend}-${mode}-${case}.out"
      diff -u "$out/c11-host-${case}.err" "$out/c11-b${backend}-${mode}-${case}.err"
    done
  done
}

for case in sleep-values sleep-pending sleep-blocked sleep-disabled sleep-signal; do
  run_c11_case "$out/c11_sleep" "$case"
done
for case in create-return create-exit create-pthread-exit create-cancel-pending \
  create-cancel-blocked join-pending join-blocked; do
  run_c11_case "$out/c11_lifecycle" "$case"
done
for case in cpp-return cpp-exit cpp-cancel; do
  run_c11_case "$out/c11_cpp" "$case"
done

# 5. Narrow & wide C/C++ stdio cancellation + stream lock release across hosted and native backends.
stdio_cases=0
run_stdio_case() {
  local lang=$1 sym=$2 phase=$3 path=$4 backend mode
  local pfx="$out/stdio-${lang}-${sym}-${phase}-${path}"
  env -u LD_PRELOAD -u FRANKENLIBC_MODE -u FRANKENLIBC_THREAD_NATIVE -u FRANKENLIBC_TEST_LIBRARY \
    timeout --kill-after=2s 8s "$out/stdio_${lang}" "$sym" "$phase" "$path" \
    > "${pfx}-host.out" 2> "${pfx}-host.err"
  grep -qx "PASS $sym $phase $path" "${pfx}-host.out"
  test ! -s "${pfx}-host.err"
  for backend in 0 1; do
    for mode in strict hardened; do
      timeout --kill-after=2s 8s env LD_PRELOAD="$library" \
        FRANKENLIBC_MODE="$mode" FRANKENLIBC_THREAD_NATIVE="$backend" \
        FRANKENLIBC_TEST_LIBRARY="$library" \
        "$out/stdio_${lang}" "$sym" "$phase" "$path" \
        > "${pfx}-b${backend}-${mode}.out" 2> "${pfx}-b${backend}-${mode}.err"
      cmp "${pfx}-host.out" "${pfx}-b${backend}-${mode}.out"
      cmp "${pfx}-host.err" "${pfx}-b${backend}-${mode}.err"
    done
  done
  stdio_cases=$((stdio_cases + 1))
}

for lang in c cpp; do
  for sym in fgetc fgets fread getline fscanf fgetwc fgetws fwscanf __fgets_chk __uflow; do
    run_stdio_case "$lang" "$sym" blocked warm
    run_stdio_case "$lang" "$sym" pending cold
    run_stdio_case "$lang" "$sym" disabled warm
    run_stdio_case "$lang" "$sym" buffered warm
  done
  for sym in fgetc fgets fread; do
    run_stdio_case "$lang" "$sym" blocked unbuffered
  done
  for sym in fgetwc fgetws fwscanf; do
    run_stdio_case "$lang" "$sym" blocked partial
  done
  for sym in fputc fputs fwrite fflush fclose fprintf dprintf fputwc fputws fwprintf __fprintf_chk __overflow; do
    run_stdio_case "$lang" "$sym" blocked warm
    run_stdio_case "$lang" "$sym" pending cold
    run_stdio_case "$lang" "$sym" disabled warm
  done
  for sym in fputc fputs fwrite fprintf fputwc fputws fwprintf; do
    run_stdio_case "$lang" "$sym" blocked line
  done
done

echo "PASS: pthread_cancel native+hosted parity gate verified ($library, stdio_cases=$stdio_cases)"
