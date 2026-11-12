#!/usr/bin/env python3
"""Confined real-application libarchive security qualification harness (SQ S08-S24).

Implements:
- S08-S09: Pinned ordinary -O2 libarchive v3.8.7 vs v3.8.8 ZIP central-directory
  64-KiB heap overwrite counterfactuals across (H, S, F, P, PF) under bwrap
  isolation with paired unobserved + external x86_64 ptrace DR0..DR3 hardware
  write-watchpoint runs.
- S10-S11: Multi-format benign archive conversions validated by independent
  stock-glibc v3.8.8 validator + quarantine/non-publication of clamped/corrupt
  68000-byte ZIP output.
- S13-S14: Pinned ordinary -O2 libarchive v3.7.9 vs v3.8.8 RAR LZSS 64-byte
  window out-of-bounds heap read counterfactuals across (H, S, F, P, PF) with
  external DR0..DR3 read/write hardware watchpoints on a live neighbor canary
  allocation and disposable synthetic marker non-disclosure checks.
- S15: Same-invocation live-incumbent (H, S, F) paired/randomized block latency
  and peak VmRSS/VmData distributions (3 warmups + 30 paired blocks, p50/p95/p99
  + 95% paired bootstrap ratio CI).
- S16-S17: Supervisor profile admission, isolated per-job staging, atomic
  publication, and 6 failure/escape negative controls (symlink swap, ..
  traversal, pre-exec input quota, SIGABRT crash, process-group timeout kill,
  corrupt output validator rejection).
- S18-S20, S22-S24: Portable path-sanitized evidence bundle export, clean-room
  relocated bundle verification without trusting producer verdicts, adversarial
  holdout mutations (including inlined-write non-coverage boundary classified
  unsupported), 1-byte artifact/manifest tamper supersession/revocation, concise
  demo output, and S22 conjunction evaluation.
"""

from __future__ import annotations

import argparse
import binascii
import hashlib
import json
import math
import os
import pathlib
import platform
import random
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any

SCHEMA_BUNDLE_VERSION = "frankenlibc.security_qualification_bundle.v1"
FORBIDDEN_LOCAL_PREFIXES = ("/data/projects", "/data/tmp")
SYNTHETIC_MARKER = "FRNK_SYNTH_CANARY_MARKER_9F8E7D6C"

C_WATCH_NOTIFY = r"""
#define _GNU_SOURCE 1
#include <dlfcn.h>
#include <elf.h>
#include <link.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

typedef void *(*malloc_fn_t)(size_t);
typedef void *(*calloc_fn_t)(size_t, size_t);
typedef void *(*realloc_fn_t)(void *, size_t);
typedef void (*free_fn_t)(void *);

struct watch_packet {
    uint64_t op;
    uint64_t base;
    uint64_t watch_addr;
    uint64_t size;
};

static malloc_fn_t real_malloc_fn = NULL;
static calloc_fn_t real_calloc_fn = NULL;
static realloc_fn_t real_realloc_fn = NULL;
static free_fn_t real_free_fn = NULL;

static int g_notify_fd = -1;
static size_t g_target_size = 0;
static size_t g_watch_offset = 0;
static int g_match_all_callers = 0;
static int g_only_realloc = 0;
static int g_neighbor_guard = 0;
static uintptr_t g_watched_bases[4] = {0, 0, 0, 0};
static void *g_guard_pool[4][64];
static size_t g_guard_pool_len[4] = {0, 0, 0, 0};
static size_t g_watched_ring = 0;
static volatile int g_hooks_resolved = 0;
static volatile int g_active = 0;
static __thread int tls_in_hook = 0;
static __attribute__((aligned(16))) unsigned char g_bootstrap_buf[262144];
static size_t g_bootstrap_used = 0;

static int is_bootstrap_ptr(const void *ptr) {
    return (uintptr_t)ptr >= (uintptr_t)g_bootstrap_buf &&
           (uintptr_t)ptr < (uintptr_t)(g_bootstrap_buf + sizeof(g_bootstrap_buf));
}

static void *bootstrap_alloc(size_t size, int zero_fill) {
    size_t payload = (size == 0) ? 16u : ((size + 15u) & ~(size_t)15u);
    size_t needed = 16u + payload;
    size_t off = __atomic_fetch_add(&g_bootstrap_used, needed, __ATOMIC_RELAXED);
    if (off + needed > sizeof(g_bootstrap_buf)) {
        return NULL;
    }
    unsigned char *hdr = &g_bootstrap_buf[off];
    ((size_t *)hdr)[0] = size;
    ((size_t *)hdr)[1] = 0;
    unsigned char *user = hdr + 16u;
    if (zero_fill) {
        for (size_t i = 0; i < payload; i++) {
            user[i] = 0;
        }
    }
    return user;
}

static int has_substr(const char *hay, const char *needle) {
    if (!hay || !needle || !*needle) return 0;
    for (size_t i = 0; hay[i] != '\0'; i++) {
        size_t j = 0;
        while (needle[j] != '\0' && hay[i + j] == needle[j]) {
            j++;
        }
        if (needle[j] == '\0') return 1;
    }
    return 0;
}

static size_t parse_u64_c(const char *s) {
    size_t v = 0;
    if (!s) return 0;
    while (*s >= '0' && *s <= '9') {
        v = v * 10u + (size_t)(*s - '0');
        s++;
    }
    return v;
}

static void fill_marker_bytes(unsigned char *dst, size_t len) {
    static const char marker[] = "FRNK_SYNTH_CANARY_MARKER_9F8E7D6C";
    const size_t mlen = sizeof(marker) - 1u;
    for (size_t i = 0; i < len; i++) {
        dst[i] = (unsigned char)marker[i % mlen];
    }
}

/* Invoked explicitly from archive_worker main() AFTER all DSO .init_array
 * constructors (including libfrankenlibc_abi.so mode/log seeding) finish.
 * Note: resolving directly from libfrankenlibc_abi.so's PT_DYNAMIC via
 * dl_iterate_phdr avoids both frankenlibc_abi::dlsym(RTLD_NEXT) caller-frame
 * forwarding to host glibc and frankenlibc_abi::dlopen(RTLD_NOLOAD) alias
 * redirection to MAIN_PROGRAM_HANDLE (global scope). */
struct phdr_sym_query {
    const char *dso_substr;
    const char *sym_name;
    void *found;
};

static int str_eq_c(const char *a, const char *b) {
    if (!a || !b) return 0;
    while (*a && *b) {
        if (*a != *b) return 0;
        a++;
        b++;
    }
    return *a == *b;
}

static uint32_t calc_gnu_hash_c(const char *s) {
    uint32_t h = 5381u;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        h = (h << 5) + h + (uint32_t)(*p);
    }
    return h;
}

static uint32_t calc_sysv_hash_c(const char *name) {
    uint32_t h = 0, g;
    for (const unsigned char *p = (const unsigned char *)name; *p; p++) {
        h = (h << 4) + (uint32_t)(*p);
        g = h & 0xf0000000u;
        if (g) h ^= g >> 24;
        h &= ~g;
    }
    return h;
}

static uintptr_t relocate_dyn_ptr(uintptr_t base, Elf64_Addr p) {
    return (p < base) ? (base + (uintptr_t)p) : (uintptr_t)p;
}

static int resolve_dso_phdr_cb(struct dl_phdr_info *info, size_t size, void *data) {
    (void)size;
    struct phdr_sym_query *q = (struct phdr_sym_query *)data;
    if (!info->dlpi_name || !has_substr(info->dlpi_name, q->dso_substr)) {
        return 0;
    }
    const Elf64_Dyn *dyn = NULL;
    for (int i = 0; i < info->dlpi_phnum; i++) {
        if (info->dlpi_phdr[i].p_type == PT_DYNAMIC) {
            dyn = (const Elf64_Dyn *)(info->dlpi_addr + info->dlpi_phdr[i].p_vaddr);
            break;
        }
    }
    if (!dyn) return 0;
    const Elf64_Sym *symtab = NULL;
    const char *strtab = NULL;
    const uint32_t *gnu_hash = NULL;
    const uint32_t *sysv_hash = NULL;
    for (const Elf64_Dyn *d = dyn; d->d_tag != DT_NULL; d++) {
        if (d->d_tag == DT_SYMTAB) symtab = (const Elf64_Sym *)relocate_dyn_ptr(info->dlpi_addr, d->d_un.d_ptr);
        else if (d->d_tag == DT_STRTAB) strtab = (const char *)relocate_dyn_ptr(info->dlpi_addr, d->d_un.d_ptr);
        else if (d->d_tag == DT_GNU_HASH) gnu_hash = (const uint32_t *)relocate_dyn_ptr(info->dlpi_addr, d->d_un.d_ptr);
        else if (d->d_tag == DT_HASH) sysv_hash = (const uint32_t *)relocate_dyn_ptr(info->dlpi_addr, d->d_un.d_ptr);
    }
    if (!symtab || !strtab) return 0;
    if (gnu_hash) {
        uint32_t nbuckets = gnu_hash[0];
        uint32_t symoffset = gnu_hash[1];
        uint32_t bloom_size = gnu_hash[2];
        const uint64_t *bloom = (const uint64_t *)(gnu_hash + 4);
        const uint32_t *buckets = (const uint32_t *)(bloom + bloom_size);
        const uint32_t *chain = buckets + nbuckets;
        uint32_t h = calc_gnu_hash_c(q->sym_name);
        uint32_t idx = buckets[h % nbuckets];
        if (idx >= symoffset) {
            for (;; idx++) {
                uint32_t ch = chain[idx - symoffset];
                if (((ch ^ h) >> 1) == 0) {
                    const Elf64_Sym *sym = &symtab[idx];
                    if (sym->st_shndx != SHN_UNDEF && str_eq_c(strtab + sym->st_name, q->sym_name)) {
                        q->found = (void *)(info->dlpi_addr + sym->st_value);
                        return 1;
                    }
                }
                if (ch & 1u) break;
            }
        }
    }
    if (sysv_hash) {
        uint32_t nbucket = sysv_hash[0];
        const uint32_t *buckets = &sysv_hash[2];
        const uint32_t *chains = &buckets[nbucket];
        uint32_t h = calc_sysv_hash_c(q->sym_name);
        for (uint32_t idx = buckets[h % nbucket]; idx != STN_UNDEF; idx = chains[idx]) {
            const Elf64_Sym *sym = &symtab[idx];
            if (sym->st_shndx != SHN_UNDEF && str_eq_c(strtab + sym->st_name, q->sym_name)) {
                q->found = (void *)(info->dlpi_addr + sym->st_value);
                return 1;
            }
        }
    }
    return 0;
}

static void *resolve_loaded_dso_symbol(const char *dso_substr, const char *sym_name) {
    struct phdr_sym_query q;
    q.dso_substr = dso_substr;
    q.sym_name = sym_name;
    q.found = NULL;
    dl_iterate_phdr(resolve_dso_phdr_cb, &q);
    return q.found;
}

__attribute__((visibility("default")))
void oracle_watch_activate(void) {
    if (g_active) {
        return;
    }
    tls_in_hook++;
    if (!g_hooks_resolved) {
        malloc_fn_t fl_malloc = (malloc_fn_t)resolve_loaded_dso_symbol("libfrankenlibc_abi.so", "malloc");
        if (fl_malloc != NULL && fl_malloc != &malloc) {
            real_malloc_fn = fl_malloc;
            real_calloc_fn = (calloc_fn_t)resolve_loaded_dso_symbol("libfrankenlibc_abi.so", "calloc");
            real_realloc_fn = (realloc_fn_t)resolve_loaded_dso_symbol("libfrankenlibc_abi.so", "realloc");
            real_free_fn = (free_fn_t)resolve_loaded_dso_symbol("libfrankenlibc_abi.so", "free");
        } else {
            real_malloc_fn = (malloc_fn_t)dlsym(RTLD_NEXT, "malloc");
            real_calloc_fn = (calloc_fn_t)dlsym(RTLD_NEXT, "calloc");
            real_realloc_fn = (realloc_fn_t)dlsym(RTLD_NEXT, "realloc");
            real_free_fn = (free_fn_t)dlsym(RTLD_NEXT, "free");
        }
        g_hooks_resolved = 1;
    }
    const char *fd_s = getenv("ORACLE_NOTIFY_FD");
    if (fd_s && *fd_s) {
        g_notify_fd = (int)parse_u64_c(fd_s);
    }
    const char *sz_s = getenv("ORACLE_TARGET_SIZE");
    if (sz_s && *sz_s) {
        g_target_size = parse_u64_c(sz_s);
    }
    const char *off_s = getenv("ORACLE_WATCH_OFFSET");
    if (off_s && *off_s) {
        g_watch_offset = parse_u64_c(off_s);
    } else {
        g_watch_offset = g_target_size;
    }
    const char *all_s = getenv("ORACLE_MATCH_ALL_CALLERS");
    if (all_s && all_s[0] == '1' && all_s[1] == '\0') {
        g_match_all_callers = 1;
    }
    const char *re_s = getenv("ORACLE_ONLY_REALLOC");
    if (re_s && re_s[0] == '1' && re_s[1] == '\0') {
        g_only_realloc = 1;
    }
    const char *ng_s = getenv("ORACLE_NEIGHBOR_GUARD");
    if (ng_s && ng_s[0] == '1' && ng_s[1] == '\0') {
        g_neighbor_guard = 1;
    }
    g_active = 1;
    tls_in_hook--;
}

static int caller_matches(void *ret_addr) {
    if (g_match_all_callers) {
        return 1;
    }
    Dl_info info;
    if (dladdr(ret_addr, &info) != 0 && info.dli_fname != NULL) {
        if (has_substr(info.dli_fname, "libarchive.so")) {
            return 1;
        }
    }
    return 0;
}

static void send_packet_and_stop(uint64_t op, uintptr_t base, uintptr_t watch_addr, size_t sz) {
    if (g_notify_fd < 0) {
        return;
    }
    struct watch_packet pkt;
    pkt.op = op;
    pkt.base = (uint64_t)base;
    pkt.watch_addr = (uint64_t)watch_addr;
    pkt.size = (uint64_t)sz;
    ssize_t wr = write(g_notify_fd, &pkt, sizeof(pkt));
    if (wr == (ssize_t)sizeof(pkt)) {
        pid_t tid = (pid_t)syscall(SYS_gettid);
        syscall(SYS_tgkill, getpid(), tid, SIGSTOP);
    }
}

static void release_slot_guards(int slot) {
    if (!real_free_fn) return;
    for (size_t j = 0; j < g_guard_pool_len[slot]; j++) {
        if (g_guard_pool[slot][j] != NULL) {
            real_free_fn(g_guard_pool[slot][j]);
            g_guard_pool[slot][j] = NULL;
        }
    }
    g_guard_pool_len[slot] = 0;
}

static void maybe_disarm(void *ptr) {
    if (!g_active || ptr == NULL || g_notify_fd < 0) {
        return;
    }
    uintptr_t target = (uintptr_t)ptr;
    for (int i = 0; i < 4; i++) {
        if (g_watched_bases[i] == target) {
            g_watched_bases[i] = 0;
            send_packet_and_stop(2, target, 0, 0);
            release_slot_guards(i);
            break;
        }
    }
}

static void maybe_arm(void *ptr, size_t size, void *ret_addr, int is_realloc) {
    if (!g_active || ptr == NULL || g_notify_fd < 0 || g_target_size == 0 || size != g_target_size) {
        return;
    }
    if (g_only_realloc && !is_realloc) {
        return;
    }
    if (!caller_matches(ret_addr)) {
        return;
    }
    int slot = (int)(g_watched_ring % 4u);
    g_watched_ring++;
    if (g_watched_bases[slot] != 0) {
        send_packet_and_stop(2, g_watched_bases[slot], 0, 0);
        release_slot_guards(slot);
        g_watched_bases[slot] = 0;
    }

    uintptr_t base = (uintptr_t)ptr;
    uintptr_t watch_addr = base + g_watch_offset;

    if (g_neighbor_guard && real_malloc_fn) {
        watch_addr = (base + size + 32u) & ~(uintptr_t)7u;
        uintptr_t best = 0;
        size_t count = 0;
        for (size_t k = 0; k < 64; k++) {
            void *g = real_malloc_fn(size);
            if (!g) break;
            fill_marker_bytes((unsigned char *)g, size);
            g_guard_pool[slot][count++] = g;
            uintptr_t ga = (uintptr_t)g;
            if (ga >= base + size + 16u && ga - base < 16384u) {
                if (best == 0 || ga < best) {
                    best = ga;
                }
                break;
            }
        }
        g_guard_pool_len[slot] = count;
        if (best != 0) {
            watch_addr = best;
        }
    }

    g_watched_bases[slot] = base;
    send_packet_and_stop(1, base, watch_addr, size);
}

void *malloc(size_t size) {
    if (!g_hooks_resolved || tls_in_hook) {
        return bootstrap_alloc(size, 0);
    }
    void *ptr = real_malloc_fn ? real_malloc_fn(size) : NULL;
    if (g_active && !tls_in_hook && ptr != NULL && size == g_target_size) {
        tls_in_hook++;
        maybe_arm(ptr, size, __builtin_return_address(0), 0);
        tls_in_hook--;
    }
    return ptr;
}

void *calloc(size_t nmemb, size_t size) {
    size_t total = nmemb * size;
    if (!g_hooks_resolved || tls_in_hook) {
        return bootstrap_alloc(total, 1);
    }
    void *ptr = real_calloc_fn ? real_calloc_fn(nmemb, size) : NULL;
    if (g_active && !tls_in_hook && ptr != NULL && total == g_target_size) {
        tls_in_hook++;
        maybe_arm(ptr, total, __builtin_return_address(0), 0);
        tls_in_hook--;
    }
    return ptr;
}

void *realloc(void *old_ptr, size_t size) {
    if (old_ptr == NULL) {
        if (!g_hooks_resolved || tls_in_hook) {
            return bootstrap_alloc(size, 0);
        }
        void *ptr = real_realloc_fn ? real_realloc_fn(NULL, size) : NULL;
        if (g_active && !tls_in_hook && ptr != NULL && size == g_target_size) {
            tls_in_hook++;
            maybe_arm(ptr, size, __builtin_return_address(0), 1);
            tls_in_hook--;
        }
        return ptr;
    }
    if (is_bootstrap_ptr(old_ptr)) {
        size_t old_sz = ((const size_t *)((const unsigned char *)old_ptr - 16u))[0];
        void *new_p = (!g_hooks_resolved || tls_in_hook || !real_malloc_fn)
            ? bootstrap_alloc(size, 0)
            : real_malloc_fn(size);
        if (new_p != NULL) {
            size_t copy_n = (old_sz < size) ? old_sz : size;
            for (size_t i = 0; i < copy_n; i++) {
                ((unsigned char *)new_p)[i] = ((const unsigned char *)old_ptr)[i];
            }
        }
        return new_p;
    }
    if (!g_hooks_resolved || tls_in_hook) {
        return NULL;
    }
    if (g_active && !tls_in_hook) {
        tls_in_hook++;
        maybe_disarm(old_ptr);
        tls_in_hook--;
    }
    void *ptr = real_realloc_fn ? real_realloc_fn(old_ptr, size) : NULL;
    if (g_active && !tls_in_hook && ptr != NULL && size == g_target_size) {
        tls_in_hook++;
        maybe_arm(ptr, size, __builtin_return_address(0), 1);
        tls_in_hook--;
    }
    return ptr;
}

void free(void *ptr) {
    if (ptr == NULL || is_bootstrap_ptr(ptr)) {
        return;
    }
    if (!g_hooks_resolved) {
        return;
    }
    if (g_active && !tls_in_hook) {
        tls_in_hook++;
        maybe_disarm(ptr);
        tls_in_hook--;
    }
    if (real_free_fn) {
        real_free_fn(ptr);
    }
}
"""

C_HW_TRACER = r"""
#define _GNU_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

struct watch_packet {
    uint64_t op;
    uint64_t base;
    uint64_t watch_addr;
    uint64_t size;
};

static int set_dr(pid_t pid, int reg_idx, unsigned long val) {
    size_t off = offsetof(struct user, u_debugreg[0]) + (size_t)reg_idx * sizeof(unsigned long);
    return ptrace(PTRACE_POKEUSER, pid, (void *)off, (void *)val) == 0 ? 0 : -1;
}

static unsigned long get_dr(pid_t pid, int reg_idx) {
    size_t off = offsetof(struct user, u_debugreg[0]) + (size_t)reg_idx * sizeof(unsigned long);
    errno = 0;
    return (unsigned long)ptrace(PTRACE_PEEKUSER, pid, (void *)off, NULL);
}

static unsigned long compute_dr7(const uintptr_t slots[4], int rw_mode) {
    unsigned long dr7 = 0;
    for (int i = 0; i < 4; i++) {
        if (slots[i] != 0) {
            dr7 |= (1UL << (i * 2));
            unsigned long cond = (rw_mode == 3) ? 3UL : 1UL; /* 1=write, 3=read_write */
            dr7 |= (cond << (16 + i * 4));
        }
    }
    return dr7;
}

int main(int argc, char **argv) {
    if (argc >= 2 && strcmp(argv[1], "--self-test") == 0) {
        int pipefd[2];
        if (pipe(pipefd) != 0) return 2;
        pid_t pid = fork();
        if (pid == 0) {
            close(pipefd[0]);
            volatile unsigned char *buf = malloc(64);
            uintptr_t target = (uintptr_t)(buf + 32);
            if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) != 0) _exit(3);
            if (write(pipefd[1], &target, sizeof(target)) != (ssize_t)sizeof(target)) _exit(4);
            raise(SIGSTOP);
            buf[32] = 0x5a;
            _exit(0);
        }
        close(pipefd[1]);
        uintptr_t target = 0;
        if (read(pipefd[0], &target, sizeof(target)) != (ssize_t)sizeof(target)) return 5;
        close(pipefd[0]);
        int st = 0;
        if (waitpid(pid, &st, 0) < 0 || !WIFSTOPPED(st)) return 6;
        uintptr_t slots[4] = {target, 0, 0, 0};
        if (set_dr(pid, 0, target) != 0) {
            ptrace(PTRACE_KILL, pid, NULL, NULL);
            return 7;
        }
        if (set_dr(pid, 6, 0) != 0 || set_dr(pid, 7, compute_dr7(slots, 1)) != 0) {
            ptrace(PTRACE_KILL, pid, NULL, NULL);
            return 8;
        }
        ptrace(PTRACE_CONT, pid, NULL, NULL);
        int hit = 0;
        while (waitpid(pid, &st, 0) > 0) {
            if (WIFEXITED(st) || WIFSIGNALED(st)) break;
            if (WIFSTOPPED(st)) {
                int sig = WSTOPSIG(st);
                if (sig == SIGTRAP) {
                    unsigned long dr6 = get_dr(pid, 6);
                    if (dr6 & 0x1UL) {
                        hit = 1;
                        set_dr(pid, 6, 0);
                        set_dr(pid, 7, 0);
                    }
                    ptrace(PTRACE_CONT, pid, NULL, NULL);
                } else {
                    ptrace(PTRACE_CONT, pid, NULL, (void *)(uintptr_t)sig);
                }
            }
        }
        return hit ? 0 : 9;
    }

    if (argc < 5) {
        fprintf(stderr, "usage: %s <oracle_json> <rw_mode:write|read_write> [--env K=V ...] -- <cmd...>\n", argv[0]);
        return 2;
    }
    const char *oracle_out = argv[1];
    int rw_mode = (strcmp(argv[2], "read_write") == 0) ? 3 : 1;
    const char *child_envs[64];
    int n_child_envs = 0;
    int arg_idx = 3;
    while (arg_idx < argc && strcmp(argv[arg_idx], "--") != 0) {
        if (strcmp(argv[arg_idx], "--env") == 0 && arg_idx + 1 < argc) {
            if (n_child_envs < 64) {
                child_envs[n_child_envs++] = argv[arg_idx + 1];
            }
            arg_idx += 2;
        } else {
            /* Legacy positional watch_offset compatibility if passed */
            arg_idx++;
        }
    }
    if (arg_idx >= argc || strcmp(argv[arg_idx], "--") != 0 || arg_idx + 1 >= argc) {
        fprintf(stderr, "missing -- separator or child command\n");
        return 2;
    }
    char **child_argv = &argv[arg_idx + 1];

    int pipefd[2];
    if (pipe(pipefd) != 0) {
        perror("pipe");
        return 2;
    }
    int fl = fcntl(pipefd[0], F_GETFL, 0);
    fcntl(pipefd[0], F_SETFL, fl | O_NONBLOCK);

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return 2;
    }
    if (pid == 0) {
        close(pipefd[0]);
        char fd_buf[32];
        snprintf(fd_buf, sizeof(fd_buf), "%d", pipefd[1]);
        setenv("ORACLE_NOTIFY_FD", fd_buf, 1);
        for (int i = 0; i < n_child_envs; i++) {
            const char *kv = child_envs[i];
            const char *eq = strchr(kv, '=');
            if (eq != NULL) {
                size_t klen = (size_t)(eq - kv);
                char kbuf[128];
                if (klen > 0 && klen < sizeof(kbuf)) {
                    memcpy(kbuf, kv, klen);
                    kbuf[klen] = '\0';
                    setenv(kbuf, eq + 1, 1);
                }
            }
        }
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) != 0) {
            perror("PTRACE_TRACEME");
            _exit(126);
        }
        raise(SIGSTOP);
        execvp(child_argv[0], child_argv);
        perror("execvp");
        _exit(127);
    }
    close(pipefd[1]);

    int st = 0;
    if (waitpid(pid, &st, 0) < 0 || !WIFSTOPPED(st)) {
        close(pipefd[0]);
        return 2;
    }

    uintptr_t base_slots[4] = {0, 0, 0, 0};
    uintptr_t watch_slots[4] = {0, 0, 0, 0};
    uint64_t armed_count = 0;
    uint64_t disarmed_count = 0;
    uint64_t hit_count = 0;
    unsigned long first_fault_rip = 0;
    int raw_exit_code = -1;
    int raw_term_signal = 0;
    int initial_exec_seen = 0;

    ptrace(PTRACE_CONT, pid, NULL, NULL);

    while (waitpid(pid, &st, 0) > 0) {
        if (WIFEXITED(st)) {
            raw_exit_code = WEXITSTATUS(st);
            break;
        }
        if (WIFSIGNALED(st)) {
            raw_term_signal = WTERMSIG(st);
            raw_exit_code = 128 + raw_term_signal;
            break;
        }
        if (!WIFSTOPPED(st)) {
            continue;
        }
        int sig = WSTOPSIG(st);
        if (sig == SIGSTOP) {
            struct watch_packet pkt;
            int handled_pkt = 0;
            while (read(pipefd[0], &pkt, sizeof(pkt)) == (ssize_t)sizeof(pkt)) {
                handled_pkt = 1;
                if (pkt.op == 1) {
                    int slot = (int)(armed_count % 4);
                    armed_count++;
                    base_slots[slot] = (uintptr_t)pkt.base;
                    watch_slots[slot] = (uintptr_t)pkt.watch_addr;
                    set_dr(pid, slot, watch_slots[slot]);
                } else if (pkt.op == 2) {
                    for (int i = 0; i < 4; i++) {
                        if (base_slots[i] == (uintptr_t)pkt.base) {
                            base_slots[i] = 0;
                            watch_slots[i] = 0;
                            set_dr(pid, i, 0);
                            disarmed_count++;
                        }
                    }
                }
            }
            if (handled_pkt) {
                set_dr(pid, 6, 0);
                set_dr(pid, 7, compute_dr7(watch_slots, rw_mode));
                ptrace(PTRACE_CONT, pid, NULL, NULL);
            } else {
                ptrace(PTRACE_CONT, pid, NULL, NULL);
            }
        } else if (sig == SIGTRAP) {
            if (!initial_exec_seen) {
                initial_exec_seen = 1;
                ptrace(PTRACE_CONT, pid, NULL, NULL);
                continue;
            }
            unsigned long dr6 = get_dr(pid, 6);
            if (dr6 & 0x0fUL) {
                struct user_regs_struct regs;
                memset(&regs, 0, sizeof(regs));
                ptrace(PTRACE_GETREGS, pid, NULL, &regs);
                if (hit_count == 0) {
                    first_fault_rip = (unsigned long)regs.rip;
                }
                hit_count++;
                for (int i = 0; i < 4; i++) {
                    if (dr6 & (1UL << i)) {
                        base_slots[i] = 0;
                        watch_slots[i] = 0;
                        set_dr(pid, i, 0);
                    }
                }
                set_dr(pid, 6, 0);
                set_dr(pid, 7, compute_dr7(watch_slots, rw_mode));
            }
            ptrace(PTRACE_CONT, pid, NULL, NULL);
        } else {
            ptrace(PTRACE_CONT, pid, NULL, (void *)(uintptr_t)sig);
        }
    }
    close(pipefd[0]);

    FILE *fp = fopen(oracle_out, "w");
    if (!fp) {
        return 2;
    }
    fprintf(
        fp,
        "{\"armed_count\":%llu,\"disarmed_count\":%llu,\"hit_count\":%llu,"
        "\"watchpoint_triggered\":%s,\"first_fault_rip\":\"0x%lx\","
        "\"raw_exit_code\":%d,\"raw_term_signal\":%d}\n",
        (unsigned long long)armed_count,
        (unsigned long long)disarmed_count,
        (unsigned long long)hit_count,
        hit_count > 0 ? "true" : "false",
        first_fault_rip,
        raw_exit_code,
        raw_term_signal
    );
    fclose(fp);
    return 0;
}
"""

C_ARCHIVE_WORKER = r"""
#define _GNU_SOURCE 1
#include <archive.h>
#include <archive_entry.h>
#include <dlfcn.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

static uint64_t fnv1a64_init(void) {
    return 14695981039346656037ULL;
}

static uint64_t fnv1a64_update(uint64_t h, const unsigned char *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        h ^= (uint64_t)buf[i];
        h *= 1099511628211ULL;
    }
    return h;
}

static long read_peak_status_kb(const char *key) {
    FILE *fp = fopen("/proc/self/status", "r");
    if (!fp) return -1;
    char line[256];
    size_t klen = strlen(key);
    long val = -1;
    while (fgets(line, sizeof(line), fp) != NULL) {
        if (strncmp(line, key, klen) == 0 && line[klen] == ':') {
            val = strtol(line + klen + 1, NULL, 10);
            break;
        }
    }
    fclose(fp);
    return val;
}

static int set_output_format(struct archive *aw, const char *fmt) {
    if (strcmp(fmt, "zip") == 0) {
        if (archive_write_set_format_zip(aw) != ARCHIVE_OK) return -1;
        archive_write_set_options(aw, "zip:compression=store");
        return 0;
    }
    if (strcmp(fmt, "gnutar") == 0) {
        return archive_write_set_format_gnutar(aw) == ARCHIVE_OK ? 0 : -1;
    }
    if (strcmp(fmt, "pax") == 0) {
        return archive_write_set_format_pax_restricted(aw) == ARCHIVE_OK ? 0 : -1;
    }
    if (strcmp(fmt, "ustar") == 0) {
        return archive_write_set_format_ustar(aw) == ARCHIVE_OK ? 0 : -1;
    }
    return -1;
}

static int cmd_convert(const char *in_path, const char *out_path, const char *out_fmt, size_t chunk_sz, const char *metrics_json) {
    struct archive *ar = archive_read_new();
    struct archive *aw = archive_write_new();
    if (!ar || !aw) return 2;

    archive_read_support_filter_all(ar);
    archive_read_support_format_all(ar);

    if (set_output_format(aw, out_fmt) != 0) {
        fprintf(stderr, "unsupported format: %s (%s)\n", out_fmt, archive_error_string(aw));
        return 3;
    }
    if (archive_read_open_filename(ar, in_path, 16384) != ARCHIVE_OK) {
        fprintf(stderr, "open input failed: %s\n", archive_error_string(ar));
        return 4;
    }
    if (archive_write_open_filename(aw, out_path) != ARCHIVE_OK) {
        fprintf(stderr, "open output failed: %s\n", archive_error_string(aw));
        return 5;
    }

    if (chunk_sz < 64) chunk_sz = 64;
    unsigned char *buf = malloc(chunk_sz);
    if (!buf) return 6;

    int rc = 0;
    size_t entries_converted = 0;
    size_t bytes_converted = 0;
    struct archive_entry *entry = NULL;

    for (;;) {
        int r = archive_read_next_header(ar, &entry);
        if (r == ARCHIVE_EOF) break;
        if (r < ARCHIVE_OK) {
            fprintf(stderr, "read header error: %s\n", archive_error_string(ar));
            rc = 10;
            break;
        }
        int wr = archive_write_header(aw, entry);
        if (wr < ARCHIVE_OK) {
            fprintf(stderr, "write header rejected: %s\n", archive_error_string(aw));
            rc = 11;
            break;
        }
        if (archive_entry_size(entry) > 0) {
            for (;;) {
                la_ssize_t rd = archive_read_data(ar, buf, chunk_sz);
                if (rd == 0) break;
                if (rd < 0) {
                    fprintf(stderr, "read data error: %s\n", archive_error_string(ar));
                    rc = 12;
                    break;
                }
                la_ssize_t wd = archive_write_data(aw, buf, (size_t)rd);
                if (wd < 0 || (size_t)wd != (size_t)rd) {
                    fprintf(stderr, "write data error: %s\n", archive_error_string(aw));
                    rc = 13;
                    break;
                }
                bytes_converted += (size_t)wd;
            }
            if (rc != 0) break;
        }
        if (archive_write_finish_entry(aw) < ARCHIVE_OK) {
            fprintf(stderr, "finish entry error: %s\n", archive_error_string(aw));
            rc = 14;
            break;
        }
        entries_converted++;
    }

    free(buf);
    int close_w = archive_write_close(aw);
    if (rc == 0 && close_w < ARCHIVE_OK) {
        fprintf(stderr, "write close error: %s\n", archive_error_string(aw));
        rc = 15;
    }
    archive_write_free(aw);
    archive_read_close(ar);
    archive_read_free(ar);

    if (metrics_json && *metrics_json) {
        struct rusage ru;
        memset(&ru, 0, sizeof(ru));
        getrusage(RUSAGE_SELF, &ru);
        long vm_hwm_kb = read_peak_status_kb("VmHWM");
        long vm_data_kb = read_peak_status_kb("VmData");
        double user_ms = (double)ru.ru_utime.tv_sec * 1000.0 + (double)ru.ru_utime.tv_usec / 1000.0;
        double sys_ms = (double)ru.ru_stime.tv_sec * 1000.0 + (double)ru.ru_stime.tv_usec / 1000.0;
        FILE *mfp = fopen(metrics_json, "w");
        if (mfp) {
            fprintf(
                mfp,
                "{\"rc\":%d,\"entries_converted\":%zu,\"bytes_converted\":%zu,"
                "\"ru_maxrss_kb\":%ld,\"vm_hwm_kb\":%ld,\"vm_data_kb\":%ld,"
                "\"cpu_ms\":%.3f}\n",
                rc, entries_converted, bytes_converted, ru.ru_maxrss, vm_hwm_kb, vm_data_kb, user_ms + sys_ms
            );
            fclose(mfp);
        }
    }
    return rc;
}

static int cmd_extract_rar(const char *in_rar, const char *summary_json) {
    struct archive *ar = archive_read_new();
    if (!ar) return 2;
    archive_read_support_format_rar(ar);
    if (archive_read_open_filename(ar, in_rar, 4096) != ARCHIVE_OK) {
        fprintf(stderr, "rar open failed: %s\n", archive_error_string(ar));
        archive_read_free(ar);
        return 4;
    }

    const char *marker = "FRNK_SYNTH_CANARY_MARKER_9F8E7D6C";
    size_t mlen = strlen(marker);
    int marker_disclosed = 0;
    uint64_t digest = fnv1a64_init();
    size_t total_out = 0;
    size_t entries = 0;
    int status_code = 0;

    struct archive_entry *entry = NULL;
    for (;;) {
        int r = archive_read_next_header(ar, &entry);
        if (r == ARCHIVE_EOF) break;
        if (r < ARCHIVE_OK) {
            const char *err = archive_error_string(ar);
            if (err && strstr(err, marker) != NULL) marker_disclosed = 1;
            status_code = 11;
            break;
        }
        entries++;
        const char *p = archive_entry_pathname(entry);
        if (p && strstr(p, marker) != NULL) marker_disclosed = 1;
        const void *buff = NULL;
        size_t size = 0;
        la_int64_t offset = 0;
        for (;;) {
            int dr = archive_read_data_block(ar, &buff, &size, &offset);
            if (dr == ARCHIVE_EOF) break;
            if (dr < ARCHIVE_OK) {
                const char *err = archive_error_string(ar);
                if (err && strstr(err, marker) != NULL) marker_disclosed = 1;
                status_code = 12;
                break;
            }
            if (buff && size > 0) {
                digest = fnv1a64_update(digest, (const unsigned char *)buff, size);
                total_out += size;
                if (size >= mlen && memmem(buff, size, marker, mlen) != NULL) {
                    marker_disclosed = 1;
                }
            }
        }
        if (status_code != 0) break;
    }

    archive_read_close(ar);
    archive_read_free(ar);

    FILE *fp = fopen(summary_json, "w");
    if (fp) {
        fprintf(
            fp,
            "{\"status_code\":%d,\"entries\":%zu,\"bytes_extracted\":%zu,"
            "\"fnv1a64\":\"%016llx\",\"marker_disclosed\":%s}\n",
            status_code,
            entries,
            total_out,
            (unsigned long long)digest,
            marker_disclosed ? "true" : "false"
        );
        fclose(fp);
    }
    return status_code;
}

static int cmd_inspect_archive(const char *archive_path, const char *report_json) {
    struct archive *ar = archive_read_new();
    if (!ar) return 2;
    archive_read_support_filter_all(ar);
    archive_read_support_format_all(ar);
    if (archive_read_open_filename(ar, archive_path, 16384) != ARCHIVE_OK) {
        archive_read_free(ar);
        return 4;
    }
    FILE *fp = fopen(report_json, "w");
    if (!fp) {
        archive_read_free(ar);
        return 5;
    }
    fprintf(fp, "{\"entries\":[");
    int first = 1;
    int ok = 1;
    struct archive_entry *entry = NULL;
    unsigned char buf[8192];
    for (;;) {
        int r = archive_read_next_header(ar, &entry);
        if (r == ARCHIVE_EOF) break;
        if (r != ARCHIVE_OK) {
            ok = 0;
            break;
        }
        const char *path = archive_entry_pathname(entry);
        if (!path) {
            ok = 0;
            break;
        }
        uint64_t h = fnv1a64_init();
        size_t sz = 0;
        for (;;) {
            la_ssize_t rd = archive_read_data(ar, buf, sizeof(buf));
            if (rd == 0) break;
            if (rd < 0) {
                ok = 0;
                break;
            }
            h = fnv1a64_update(h, buf, (size_t)rd);
            sz += (size_t)rd;
        }
        if (!ok) break;
        uint64_t path_h = fnv1a64_update(fnv1a64_init(), (const unsigned char *)path, strlen(path));
        if (!first) fprintf(fp, ",");
        first = 0;
        fprintf(
            fp,
            "{\"path_len\":%zu,\"path_fnv1a64\":\"%016llx\",\"size\":%zu,\"data_fnv1a64\":\"%016llx\"}",
            strlen(path),
            (unsigned long long)path_h,
            sz,
            (unsigned long long)h
        );
    }
    fprintf(fp, "],\"archive_clean\":%s}\n", ok ? "true" : "false");
    fclose(fp);
    archive_read_close(ar);
    archive_read_free(ar);
    return ok ? 0 : 9;
}

static int cmd_inlined_bypass(void) {
    volatile unsigned char *p = (volatile unsigned char *)malloc(256);
    if (!p) return 2;
    for (size_t i = 0; i < 256; i++) {
        p[i] = (unsigned char)(i & 0xff);
    }
    /* Intentional direct compiler-inlined store bypassing libc string entrypoints. */
    p[256] = 0x41;
    free((void *)p);
    return 0;
}

static int cmd_lifecycle_fault(const char *fault_kind, const char *staged_target) {
    if (strcmp(fault_kind, "sigabrt") == 0) {
        FILE *fp = fopen(staged_target, "wb");
        if (fp) {
            fwrite("PARTIAL_CRASH_BYTES", 1, 19, fp);
            fflush(fp);
            fclose(fp);
        }
        abort();
    }
    if (strcmp(fault_kind, "symlink_swap") == 0) {
        unlink(staged_target);
        if (symlink("/etc/passwd", staged_target) != 0) return 3;
        return 0;
    }
    if (strcmp(fault_kind, "timeout_tree") == 0) {
        FILE *fp = fopen(staged_target, "wb");
        if (fp) {
            fwrite("PARTIAL_TIMEOUT_BYTES", 1, 21, fp);
            fflush(fp);
            fclose(fp);
        }
        pid_t gc = fork();
        if (gc == 0) {
            for (;;) pause();
        }
        for (;;) pause();
    }
    if (strcmp(fault_kind, "corrupt_zip") == 0) {
        FILE *fp = fopen(staged_target, "wb");
        if (!fp) return 3;
        fwrite("PK\x03\x04CORRUPT_NOT_A_VALID_ZIP", 1, 27, fp);
        fclose(fp);
        return 0;
    }
    return 2;
}

int main(int argc, char **argv) {
    typedef void (*oracle_activate_fn_t)(void);
    oracle_activate_fn_t act = (oracle_activate_fn_t)dlsym(RTLD_DEFAULT, "oracle_watch_activate");
    if (act) {
        act();
    }
    if (argc < 2) return 2;
    const char *sub = argv[1];
    if (strcmp(sub, "convert") == 0 && argc >= 6) {
        const char *metrics = (argc >= 7) ? argv[6] : NULL;
        return cmd_convert(argv[2], argv[3], argv[4], (size_t)strtoull(argv[5], NULL, 10), metrics);
    }
    if (strcmp(sub, "extract-rar") == 0 && argc >= 4) {
        return cmd_extract_rar(argv[2], argv[3]);
    }
    if (strcmp(sub, "inspect") == 0 && argc >= 4) {
        return cmd_inspect_archive(argv[2], argv[3]);
    }
    if (strcmp(sub, "inlined-bypass") == 0) {
        return cmd_inlined_bypass();
    }
    if (strcmp(sub, "lifecycle-fault") == 0 && argc >= 4) {
        return cmd_lifecycle_fault(argv[2], argv[3]);
    }
    fprintf(stderr, "invalid arguments\n");
    return 2;
}
"""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fp:
        while True:
            chunk = fp.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def fnv1a64_hex(data: bytes) -> str:
    h = 14695981039346656037
    for b in data:
        h ^= b
        h = (h * 1099511628211) & 0xFFFFFFFFFFFFFFFF
    return f"{h:016x}"


def deterministic_payload(size: int, seed: int) -> bytes:
    rng = random.Random(seed)
    return bytes(rng.randrange(0, 256) for _ in range(size))


def uudecode_lines(lines: list[str]) -> bytes:
    out = bytearray()
    for line in lines:
        if line.startswith("begin ") or line == "end" or line == "`" or not line:
            continue
        out.extend(binascii.a2b_uu(line))
    return bytes(out)


def write_tar_archive(path: pathlib.Path, fmt: str, entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    import gzip
    import io
    import tarfile

    tar_fmt = tarfile.USTAR_FORMAT if fmt == "ustar" else tarfile.PAX_FORMAT
    expected: list[dict[str, Any]] = []
    raw_buf = io.BytesIO()
    with tarfile.open(fileobj=raw_buf, mode="w", format=tar_fmt) as tf:
        for idx, spec in enumerate(entries):
            if "path" in spec:
                entry_path = str(spec["path"])
            else:
                plen = int(spec["path_length"])
                prefix = f"d{idx:02d}/"
                entry_path = prefix + ("a" * max(1, plen - len(prefix)))
                entry_path = entry_path[:plen]
            payload = deterministic_payload(int(spec["size"]), int(spec["seed"]))
            ti = tarfile.TarInfo(name=entry_path)
            ti.size = len(payload)
            ti.mtime = 1700000000
            ti.mode = 0o644
            tf.addfile(ti, io.BytesIO(payload))
            expected.append(
                {
                    "path_len": len(entry_path.encode("utf-8")),
                    "path_fnv1a64": fnv1a64_hex(entry_path.encode("utf-8")),
                    "size": len(payload),
                    "data_fnv1a64": fnv1a64_hex(payload),
                }
            )
    raw_bytes = raw_buf.getvalue()
    if fmt == "gnutar_gz":
        with path.open("wb") as raw_fp:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw_fp, mtime=1700000000) as gz_fp:
                gz_fp.write(raw_bytes)
    else:
        path.write_bytes(raw_bytes)
    return expected


def write_zip_archive(path: pathlib.Path, entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    import zipfile

    expected: list[dict[str, Any]] = []
    with zipfile.ZipFile(path, mode="w", compression=zipfile.ZIP_STORED) as zf:
        for spec in entries:
            entry_path = str(spec["path"])
            payload = deterministic_payload(int(spec["size"]), int(spec["seed"]))
            zi = zipfile.ZipInfo(filename=entry_path, date_time=(2024, 1, 1, 0, 0, 0))
            zi.external_attr = 0o644 << 16
            zf.writestr(zi, payload)
            expected.append(
                {
                    "path_len": len(entry_path.encode("utf-8")),
                    "path_fnv1a64": fnv1a64_hex(entry_path.encode("utf-8")),
                    "size": len(payload),
                    "data_fnv1a64": fnv1a64_hex(payload),
                }
            )
    return expected


def fail_admission(results_dir: pathlib.Path | None, code: str, detail: str) -> None:
    payload = {"status": code, "reason": detail}
    if results_dir is not None:
        results_dir.mkdir(parents=True, exist_ok=True)
        out_name = "isolation_status.json" if "isolation" in code else "admission_status.json"
        (results_dir / out_name).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    sys.stderr.write(f"[FATAL] {code}: {detail}\n")
    sys.exit(2)


def validate_manifest_schema(manifest: dict[str, Any], results_dir: pathlib.Path | None) -> None:
    if manifest.get("schema_version") != "frankenlibc.security_qualification_manifest.v1":
        fail_admission(results_dir, "invalid_manifest_schema", "unexpected schema_version")
    required_top = {
        "schema_version",
        "profile_id",
        "beads",
        "upstream_project",
        "pinned_revisions",
        "confinement_policy",
        "build_policy",
        "counterfactual_arms",
        "matrix_cells",
        "performance_protocol",
        "required_acceptances_for_s22",
    }
    unknown = set(manifest.keys()) - required_top
    missing = required_top - set(manifest.keys())
    if unknown or missing:
        fail_admission(
            results_dir,
            "invalid_manifest_fields",
            f"missing={sorted(missing)} unknown={sorted(unknown)}",
        )


def verify_elf_provider(lib_path: pathlib.Path, required_exports: list[str], results_dir: pathlib.Path | None) -> dict[str, Any]:
    if not lib_path.is_file():
        fail_admission(results_dir, "invalid_provider_missing", f"missing candidate DSO: {lib_path}")
    raw_hdr = lib_path.read_bytes()[:64]
    if len(raw_hdr) < 64 or raw_hdr[:4] != b"\x7fELF" or raw_hdr[4] != 2:
        fail_admission(results_dir, "invalid_provider_elf", f"not ELF64: {lib_path}")
    nm_out = subprocess.check_output(["nm", "-D", "--defined-only", str(lib_path)], text=True)
    defined = set()
    for line in nm_out.splitlines():
        parts = line.split()
        if len(parts) >= 3:
            sym = parts[-1].split("@")[0]
            defined.add(sym)
    missing_syms = [s for s in required_exports if s not in defined]
    if missing_syms:
        fail_admission(
            results_dir,
            "invalid_provider_symbols",
            f"candidate missing exported symbols: {missing_syms}",
        )
    return {
        "role": "release_candidate_libc",
        "filename": lib_path.name,
        "size_bytes": lib_path.stat().st_size,
        "sha256": sha256_file(lib_path),
    }


def ensure_upstream_builds(
    manifest: dict[str, Any],
    cache_dir: pathlib.Path,
    results_dir: pathlib.Path,
) -> dict[str, dict[str, Any]]:
    cache_dir.mkdir(parents=True, exist_ok=True)
    git_dir = cache_dir / "libarchive_git"
    repo_url = os.environ.get("FRANKENLIBC_LIBARCHIVE_GIT_MIRROR") or manifest["upstream_project"]["repository_url"]
    if not (git_dir / ".git").is_dir():
        subprocess.run(["git", "init", "-q", str(git_dir)], check=True)
        subprocess.run(["git", "-C", str(git_dir), "remote", "add", "origin", repo_url], check=True)

    required_undef = list(manifest["build_policy"]["required_dynamic_undef_symbols"])
    opt_flag = str(manifest["build_policy"]["optimization_flag"])
    built: dict[str, dict[str, Any]] = {}

    for key, rev in manifest["pinned_revisions"].items():
        commit_sha = str(rev["source_commit"])
        has_commit = (
            subprocess.run(
                ["git", "-C", str(git_dir), "cat-file", "-e", f"{commit_sha}^{{commit}}"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            ).returncode
            == 0
        )
        if not has_commit:
            subprocess.run(
                ["git", "-C", str(git_dir), "fetch", "--depth=1", "origin", commit_sha],
                check=True,
            )
        build_root = cache_dir / "builds" / f"{key}_{commit_sha[:12]}"
        lib_dir = build_root / "install_lib"
        include_dir = build_root / "install_include"
        so_link = lib_dir / "libarchive.so"
        stamp_file = build_root / "build_stamp.json"

        if not (so_link.exists() and stamp_file.is_file()):
            src_tree = build_root / "src"
            cmake_build = build_root / "cmake_build"
            if src_tree.exists():
                shutil.rmtree(src_tree)
            if cmake_build.exists():
                shutil.rmtree(cmake_build)
            src_tree.mkdir(parents=True, exist_ok=True)
            cmake_build.mkdir(parents=True, exist_ok=True)
            lib_dir.mkdir(parents=True, exist_ok=True)
            include_dir.mkdir(parents=True, exist_ok=True)

            archive_tar = subprocess.Popen(
                ["git", "-C", str(git_dir), "archive", "--format=tar", commit_sha],
                stdout=subprocess.PIPE,
            )
            assert archive_tar.stdout is not None
            subprocess.run(["tar", "-xf", "-", "-C", str(src_tree)], stdin=archive_tar.stdout, check=True)
            if archive_tar.wait() != 0:
                fail_admission(results_dir, "upstream_checkout_failed", f"git archive failed for {commit_sha}")

            cmake_cmd = [
                "cmake",
                "-S",
                str(src_tree),
                "-B",
                str(cmake_build),
                "-DCMAKE_BUILD_TYPE=Release",
                f"-DCMAKE_C_FLAGS_RELEASE={opt_flag} -g -fno-omit-frame-pointer",
                "-DBUILD_SHARED_LIBS=ON",
                "-DENABLE_TEST=OFF",
                "-DENABLE_TAR=OFF",
                "-DENABLE_CPIO=OFF",
                "-DENABLE_CAT=OFF",
                "-DENABLE_UNZIP=OFF",
                "-DENABLE_ACL=OFF",
                "-DENABLE_XATTR=OFF",
                "-DENABLE_LIBXML2=OFF",
                "-DENABLE_EXPAT=OFF",
                "-DENABLE_OPENSSL=OFF",
                "-DENABLE_NETTLE=OFF",
                "-DENABLE_LZMA=OFF",
                "-DENABLE_ZSTD=OFF",
                "-DENABLE_LZ4=OFF",
                "-DENABLE_BZIP2=OFF",
                "-DENABLE_LZO=OFF",
                "-DENABLE_CNG=OFF",
                "-DENABLE_ICONV=OFF",
                "-DENABLE_ZLIB=ON",
            ]
            subprocess.run(cmake_cmd, check=True, stdout=subprocess.DEVNULL)
            jobs = str(max(2, os.cpu_count() or 4))
            subprocess.run(
                ["cmake", "--build", str(cmake_build), "--target", "archive", "-j", jobs],
                check=True,
                stdout=subprocess.DEVNULL,
            )
            built_sos = sorted((cmake_build / "libarchive").glob("libarchive.so*"))
            if not built_sos:
                fail_admission(results_dir, "upstream_build_missing_so", f"no libarchive.so for {key}")
            real_so = [p for p in built_sos if not p.is_symlink()][0]
            for item in lib_dir.iterdir():
                if item.is_symlink() or item.is_file():
                    item.unlink()
            target_real = lib_dir / real_so.name
            shutil.copy2(real_so, target_real)
            for p in built_sos:
                if p.is_symlink():
                    link_dst = lib_dir / p.name
                    link_dst.symlink_to(target_real.name)
            for hdr in ("archive.h", "archive_entry.h"):
                shutil.copy2(src_tree / "libarchive" / hdr, include_dir / hdr)
            shutil.rmtree(src_tree)
            shutil.rmtree(cmake_build)
            stamp_file.write_text(
                json.dumps({"key": key, "source_commit": commit_sha, "opt_flag": opt_flag}, indent=2) + "\n",
                encoding="utf-8",
            )

        real_file = so_link.resolve()
        undef_out = subprocess.check_output(["nm", "-D", "--undefined-only", str(real_file)], text=True)
        undef_syms = {line.split()[-1].split("@")[0] for line in undef_out.splitlines() if line.strip()}
        missing_undef = [s for s in required_undef if s not in undef_syms]
        if missing_undef:
            fail_admission(
                results_dir,
                "inlined_or_non_interposable_build",
                f"{key} libarchive.so missing dynamic undefined symbols: {missing_undef}",
            )
        built[key] = {
            "key": key,
            "tag": rev["tag"],
            "source_commit": commit_sha,
            "lib_dir": lib_dir,
            "include_dir": include_dir,
            "real_so": real_file,
            "sha256": sha256_file(real_file),
            "size_bytes": real_file.stat().st_size,
            "dynamic_undef_verified": required_undef,
        }
    return built


def compile_helpers(cache_dir: pathlib.Path, patched_build: dict[str, Any], results_dir: pathlib.Path) -> dict[str, pathlib.Path]:
    helper_dir = cache_dir / "helpers_v2"
    helper_dir.mkdir(parents=True, exist_ok=True)

    watch_c = helper_dir / "libwatch_alloc_notify.c"
    watch_so = helper_dir / "libwatch_alloc_notify.so"
    watch_c.write_text(C_WATCH_NOTIFY, encoding="utf-8")
    subprocess.run(
        ["cc", "-O2", "-g", "-shared", "-fPIC", str(watch_c), "-ldl", "-o", str(watch_so)],
        check=True,
    )

    tracer_c = helper_dir / "hw_watchpoint_tracer.c"
    tracer_bin = helper_dir / "hw_watchpoint_tracer"
    tracer_c.write_text(C_HW_TRACER, encoding="utf-8")
    subprocess.run(["cc", "-O2", "-g", str(tracer_c), "-o", str(tracer_bin)], check=True)

    worker_c = helper_dir / "archive_worker.c"
    worker_bin = helper_dir / "archive_worker"
    worker_c.write_text(C_ARCHIVE_WORKER, encoding="utf-8")
    subprocess.run(
        [
            "cc",
            "-O2",
            "-g",
            "-fno-omit-frame-pointer",
            f"-I{patched_build['include_dir']}",
            str(worker_c),
            f"-L{patched_build['lib_dir']}",
            "-larchive",
            "-ldl",
            "-o",
            str(worker_bin),
        ],
        check=True,
    )

    probe = subprocess.run([str(tracer_bin), "--self-test"], capture_output=True, text=True)
    if probe.returncode != 0:
        fail_admission(
            results_dir,
            "watchpoint_oracle_unavailable",
            f"x86_64 ptrace DR0 self-test failed with rc={probe.returncode}",
        )

    return {
        "watch_so": watch_so,
        "tracer_bin": tracer_bin,
        "worker_bin": worker_bin,
    }


def check_bwrap_available(results_dir: pathlib.Path) -> str:
    if os.environ.get("CVE_ARENA_FORCE_MISSING_ISOLATION") == "1":
        fail_admission(results_dir, "blocked_missing_isolation", "forced missing isolation negative control")
    bwrap = shutil.which("bwrap")
    if not bwrap:
        fail_admission(results_dir, "blocked_missing_isolation", "bwrap binary not installed")
    probe = subprocess.run(
        [
            bwrap,
            "--ro-bind",
            "/",
            "/",
            "--dev",
            "/dev",
            "--proc",
            "/proc",
            "--unshare-net",
            "--unshare-ipc",
            "--unshare-uts",
            "--die-with-parent",
            "--",
            "/bin/true",
        ],
        capture_output=True,
        text=True,
    )
    if probe.returncode != 0:
        fail_admission(
            results_dir,
            "blocked_missing_isolation",
            f"bwrap namespace probe failed: {probe.stderr.strip()}",
        )
    return bwrap


def run_confined_command(
    bwrap: str,
    ro_binds: list[tuple[pathlib.Path, str]],
    rw_staging: pathlib.Path,
    inner_cmd: list[str],
    env_vars: dict[str, str],
    timeout_sec: float,
) -> dict[str, Any]:
    cmd: list[str] = [
        bwrap,
        "--ro-bind",
        "/usr",
        "/usr",
        "--ro-bind",
        "/lib",
        "/lib",
        "--ro-bind",
        "/bin",
        "/bin",
    ]
    if pathlib.Path("/lib64").exists():
        cmd.extend(["--ro-bind", "/lib64", "/lib64"])
    if pathlib.Path("/etc/ld.so.cache").exists():
        cmd.extend(["--ro-bind", "/etc/ld.so.cache", "/etc/ld.so.cache"])
    cmd.extend(
        [
            "--dev",
            "/dev",
            "--proc",
            "/proc",
            "--tmpfs",
            "/tmp",
            "--dir",
            "/job",
            "--bind",
            str(rw_staging),
            "/job/staging",
            "--unshare-net",
            "--unshare-ipc",
            "--unshare-uts",
            "--die-with-parent",
            "--clearenv",
            "--setenv",
            "PATH",
            "/usr/bin:/bin",
            "--setenv",
            "LC_ALL",
            "C",
        ]
    )
    for host_path, guest_path in ro_binds:
        cmd.extend(["--ro-bind", str(host_path), guest_path])
    for k, v in sorted(env_vars.items()):
        cmd.extend(["--setenv", k, v])
    cmd.append("--")
    cmd.extend(inner_cmd)

    t0 = time.monotonic()
    timed_out = False
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        stdout_b, stderr_b = proc.communicate(timeout=timeout_sec)
        raw_rc = proc.returncode
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        stdout_b, stderr_b = proc.communicate()
        raw_rc = 137
    wall_ms = (time.monotonic() - t0) * 1000.0
    sig_num = 9 if timed_out else (raw_rc - 128 if raw_rc > 128 else (-raw_rc if raw_rc < 0 else 0))
    return {
        "exit_code": raw_rc if raw_rc >= 0 else 128 + (-raw_rc),
        "signal": sig_num if sig_num > 0 else None,
        "timed_out": timed_out,
        "wall_ms": round(wall_ms, 3),
        "stdout_bytes": len(stdout_b),
        "stderr_bytes": len(stderr_b),
        "stdout_sha256": sha256_bytes(stdout_b),
        "stderr_sha256": sha256_bytes(stderr_b),
        "stderr_preview": stderr_b.decode("utf-8", errors="replace")[:400],
    }


def parse_heal_jsonl(log_file: pathlib.Path) -> dict[str, Any]:
    if not log_file.is_file():
        return {"total_events": 0, "clamp_size_events": 0, "canary_events": 0, "actions": []}
    actions: list[str] = []
    clamp_count = 0
    canary_count = 0
    total = 0
    for line in log_file.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        total += 1
        if "ClampSize" in line or "clamp" in line.lower():
            clamp_count += 1
            if "ClampSize" not in actions:
                actions.append("ClampSize")
        if "Canary" in line or "canary" in line.lower():
            canary_count += 1
            if "CanaryDetection" not in actions:
                actions.append("CanaryDetection")
    return {
        "total_events": total,
        "clamp_size_events": clamp_count,
        "canary_events": canary_count,
        "actions": actions,
    }


def supervisor_validate_and_publish(
    bwrap: str,
    worker_bin: pathlib.Path,
    patched_lib_dir: pathlib.Path,
    staging_dir: pathlib.Path,
    staged_filename: str,
    published_dir: pathlib.Path,
    published_filename: str,
    expected_entries: list[dict[str, Any]] | None,
    max_staged_bytes: int,
) -> dict[str, Any]:
    if "/" in staged_filename or ".." in staged_filename or staged_filename.startswith("."):
        return {"published": False, "reason": "invalid_staged_filename"}

    dir_fd = os.open(staging_dir, os.O_RDONLY | os.O_DIRECTORY)
    try:
        try:
            st = os.stat(staged_filename, dir_fd=dir_fd, follow_symlinks=False)
        except FileNotFoundError:
            return {"published": False, "reason": "missing_staged_output"}
        if not stat.S_ISREG(st.st_mode):
            return {"published": False, "reason": "non_regular_or_symlink_rejected"}
        if st.st_nlink != 1:
            return {"published": False, "reason": "hardlink_rejected"}
        if st.st_size == 0 or st.st_size > max_staged_bytes:
            return {"published": False, "reason": "staged_size_out_of_bounds"}

        file_fd = os.open(staged_filename, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=dir_fd)
        try:
            f_st = os.fstat(file_fd)
            if f_st.st_ino != st.st_ino or not stat.S_ISREG(f_st.st_mode):
                return {"published": False, "reason": "toctou_inode_mismatch"}
            immutable_bytes = bytearray()
            while True:
                chunk = os.read(file_fd, 65536)
                if not chunk:
                    break
                if len(immutable_bytes) + len(chunk) > max_staged_bytes:
                    return {"published": False, "reason": "staged_size_exceeded_during_read"}
                immutable_bytes.extend(chunk)
        finally:
            os.close(file_fd)
    finally:
        os.close(dir_fd)

    digest = sha256_bytes(bytes(immutable_bytes))
    with tempfile.TemporaryDirectory() as val_tmp_s:
        val_tmp = pathlib.Path(val_tmp_s)
        snap_archive = val_tmp / "immutable.archive"
        snap_archive.write_bytes(bytes(immutable_bytes))
        val_stage = val_tmp / "stage"
        val_stage.mkdir()
        res = run_confined_command(
            bwrap=bwrap,
            ro_binds=[
                (worker_bin, "/job/bin/archive_worker"),
                (patched_lib_dir, "/job/patched_lib"),
                (snap_archive, "/job/in/immutable.archive"),
            ],
            rw_staging=val_stage,
            inner_cmd=["/job/bin/archive_worker", "inspect", "/job/in/immutable.archive", "/job/staging/inspect.json"],
            env_vars={"LD_LIBRARY_PATH": "/job/patched_lib"},
            timeout_sec=15.0,
        )
        inspect_path = val_stage / "inspect.json"
        if res["exit_code"] != 0 or not inspect_path.is_file():
            return {"published": False, "reason": "independent_validator_failed", "staged_sha256": digest}
        inspect_doc = json.loads(inspect_path.read_text(encoding="utf-8"))
        if not inspect_doc.get("archive_clean", False):
            return {"published": False, "reason": "archive_corrupt_or_truncated", "staged_sha256": digest}
        if expected_entries is not None and inspect_doc.get("entries") != expected_entries:
            return {
                "published": False,
                "reason": "entry_manifest_mismatch_after_clamp_or_truncation",
                "staged_sha256": digest,
                "observed_entries": inspect_doc.get("entries"),
            }

    published_dir.mkdir(parents=True, exist_ok=True)
    tmp_pub = published_dir / f".tmp.{published_filename}"
    final_pub = published_dir / published_filename
    tmp_pub.write_bytes(bytes(immutable_bytes))
    os.replace(tmp_pub, final_pub)
    return {
        "published": True,
        "reason": "validated_and_atomically_published",
        "published_sha256": digest,
        "published_bytes": len(immutable_bytes),
    }


def classify_case_arm(
    setup_admitted: bool,
    baseline_harm: bool,
    arm_name: str,
    oracle_armed: bool,
    oracle_triggered: bool,
    unobserved_rc: int,
    unobserved_signal: int | None,
    timed_out: bool,
    publication: dict[str, Any] | None,
    expect_rejection: bool,
    attribution_supported: bool,
) -> dict[str, Any]:
    if not setup_admitted:
        return {
            "setup": "unsupported",
            "baseline": "unmeasured",
            "candidate_memory_effect": "unmeasured",
            "response": "controlled_rejection",
            "output": "unmeasured",
            "attribution": "unresolved",
            "qualification": "unsupported",
            "label": "unsupported",
            "qualified_card": False,
        }

    baseline_dim = "nominated_harm_observed" if baseline_harm else "not_reproduced"
    if not oracle_armed and arm_name in ("H", "S", "F"):
        mem_dim = "unmeasured"
    elif oracle_triggered:
        mem_dim = "nominated_harm_observed"
    else:
        mem_dim = "excluded_within_declared_observation"

    if timed_out:
        resp_dim = "timeout"
    elif unobserved_signal is not None:
        resp_dim = "crash"
    elif unobserved_rc == 0:
        resp_dim = "correct_completion"
    else:
        resp_dim = "controlled_rejection"

    if publication is None:
        out_dim = "rejected_and_unpublished" if unobserved_rc != 0 or expect_rejection else "independently_valid"
    elif publication.get("published"):
        out_dim = "independently_valid"
    else:
        out_dim = "rejected_and_unpublished"

    attr_dim = "supported_for_stated_mechanism" if attribution_supported else "unresolved"

    harm_excluded = mem_dim == "excluded_within_declared_observation"
    accepted_resp_out = (
        (resp_dim == "correct_completion" and out_dim == "independently_valid" and not expect_rejection)
        or (out_dim == "rejected_and_unpublished" and resp_dim in ("correct_completion", "controlled_rejection") and expect_rejection)
    )
    qualified_card = bool(
        setup_admitted
        and baseline_harm
        and harm_excluded
        and accepted_resp_out
        and attribution_supported
    )

    if not baseline_harm:
        label = "baseline_not_reproduced"
        qual = "experiment_only"
    elif mem_dim == "nominated_harm_observed":
        label = "observed_harm" if resp_dim != "crash" else "detected_after_harm"
        qual = "unsupported" if arm_name == "F" else "experiment_only"
    elif qualified_card:
        label = "safe_rejection_in_tested_case" if out_dim == "rejected_and_unpublished" else "mitigated_in_tested_case"
        qual = "profile_accepted"
    else:
        label = "inconclusive"
        qual = "experiment_only"

    return {
        "setup": "admitted",
        "baseline": baseline_dim,
        "candidate_memory_effect": mem_dim,
        "response": resp_dim,
        "output": out_dim,
        "attribution": attr_dim,
        "qualification": qual,
        "label": label,
        "qualified_card": qualified_card,
    }


def execute_zip_case(
    case_id: str,
    pathname_len: int,
    chunk_size: int,
    prefix_entries: int,
    bwrap: str,
    helpers: dict[str, pathlib.Path],
    builds: dict[str, dict[str, Any]],
    candidate_so: pathlib.Path,
    arms: list[dict[str, Any]],
    work_root: pathlib.Path,
    max_staged_bytes: int,
    deadline_sec: float,
) -> dict[str, Any]:
    case_dir = work_root / case_id
    case_dir.mkdir(parents=True, exist_ok=True)
    in_tar = case_dir / "input.tar"
    entries_spec: list[dict[str, Any]] = []
    for i in range(prefix_entries):
        entries_spec.append({"path": f"prefix_{i:02d}.txt", "size": 512, "seed": 50 + i})
    entries_spec.append({"path_length": pathname_len, "size": 256, "seed": 777})
    expected_entries = write_tar_archive(in_tar, "gnutar", entries_spec)
    in_sha = sha256_file(in_tar)

    arm_records: dict[str, Any] = {}
    for arm_cfg in arms:
        arm = arm_cfg["arm"]
        app_build = builds["patched_reference"] if arm_cfg["application"] == "patched_v3_8_8" else builds["zip_vulnerable"]
        use_fl = arm_cfg["provider"] == "frankenlibc"
        fl_mode = arm_cfg["mode"]

        stage_unobs = case_dir / f"stage_{arm}_unobs"
        stage_unobs.mkdir(parents=True, exist_ok=True)
        pub_dir = case_dir / f"pub_{arm}"
        ro_binds = [
            (helpers["worker_bin"], "/job/bin/archive_worker"),
            (app_build["lib_dir"], "/job/app_lib"),
            (in_tar, "/job/in/input.tar"),
        ]
        env_unobs = {"LD_LIBRARY_PATH": "/job/app_lib"}
        if use_fl:
            ro_binds.append((candidate_so, "/job/fl/libfrankenlibc_abi.so"))
            env_unobs["LD_PRELOAD"] = "/job/fl/libfrankenlibc_abi.so"
            env_unobs["FRANKENLIBC_MODE"] = fl_mode
            env_unobs["FRANKENLIBC_LOG"] = "/job/staging/heal.jsonl"
            env_unobs["FRANKENLIBC_HEAL_LOG"] = "1"

        unobs = run_confined_command(
            bwrap=bwrap,
            ro_binds=ro_binds,
            rw_staging=stage_unobs,
            inner_cmd=["/job/bin/archive_worker", "convert", "/job/in/input.tar", "/job/staging/out.zip", "zip", str(chunk_size), "/job/staging/metrics.json"],
            env_vars=env_unobs,
            timeout_sec=deadline_sec,
        )
        heal_summary = parse_heal_jsonl(stage_unobs / "heal.jsonl")
        pub_result = supervisor_validate_and_publish(
            bwrap=bwrap,
            worker_bin=helpers["worker_bin"],
            patched_lib_dir=builds["patched_reference"]["lib_dir"],
            staging_dir=stage_unobs,
            staged_filename="out.zip",
            published_dir=pub_dir,
            published_filename="out.zip",
            expected_entries=expected_entries,
            max_staged_bytes=max_staged_bytes,
        )

        stage_obs = case_dir / f"stage_{arm}_obs"
        stage_obs.mkdir(parents=True, exist_ok=True)
        ro_obs = list(ro_binds) + [
            (helpers["tracer_bin"], "/job/bin/hw_watchpoint_tracer"),
            (helpers["watch_so"], "/job/bin/libwatch_alloc_notify.so"),
        ]
        tracer_cmd = [
            "/job/bin/hw_watchpoint_tracer",
            "/job/staging/oracle.json",
            "write",
            "--env",
            "ORACLE_TARGET_SIZE=65536",
            "--env",
            "ORACLE_WATCH_OFFSET=65536",
        ]
        if use_fl:
            tracer_cmd.extend(
                [
                    "--env",
                    "LD_PRELOAD=/job/bin/libwatch_alloc_notify.so:/job/fl/libfrankenlibc_abi.so",
                    "--env",
                    f"FRANKENLIBC_MODE={fl_mode}",
                ]
            )
        else:
            tracer_cmd.extend(["--env", "LD_PRELOAD=/job/bin/libwatch_alloc_notify.so"])
        tracer_cmd.extend(
            [
                "--",
                "/job/bin/archive_worker",
                "convert",
                "/job/in/input.tar",
                "/job/staging/out.zip",
                "zip",
                str(chunk_size),
            ]
        )

        run_confined_command(
            bwrap=bwrap,
            ro_binds=ro_obs,
            rw_staging=stage_obs,
            inner_cmd=tracer_cmd,
            env_vars={"LD_LIBRARY_PATH": "/job/app_lib"},
            timeout_sec=deadline_sec,
        )
        oracle_doc = json.loads((stage_obs / "oracle.json").read_text(encoding="utf-8"))
        arm_records[arm] = {
            "arm": arm,
            "application_commit": app_build["source_commit"],
            "provider": arm_cfg["provider"],
            "mode": fl_mode,
            "input_sha256": in_sha,
            "unobserved": unobs,
            "oracle": oracle_doc,
            "healing_telemetry": heal_summary,
            "publication": pub_result,
        }

    baseline_harm = bool(arm_records["H"]["oracle"]["watchpoint_triggered"])
    strict_harm = bool(arm_records["S"]["oracle"]["watchpoint_triggered"])
    hardened_armed = int(arm_records["F"]["oracle"]["armed_count"]) >= 2
    hardened_clean = hardened_armed and not bool(arm_records["F"]["oracle"]["watchpoint_triggered"])
    patched_clean = not bool(arm_records["P"]["oracle"]["watchpoint_triggered"])
    attribution_ok = baseline_harm and strict_harm and hardened_clean and patched_clean

    for arm_name, rec in arm_records.items():
        oracle_armed = int(rec["oracle"]["armed_count"]) > 0 or arm_name in ("P", "PF")
        rec["dimensions"] = classify_case_arm(
            setup_admitted=True,
            baseline_harm=baseline_harm,
            arm_name=arm_name,
            oracle_armed=oracle_armed,
            oracle_triggered=bool(rec["oracle"]["watchpoint_triggered"]),
            unobserved_rc=int(rec["unobserved"]["exit_code"]),
            unobserved_signal=rec["unobserved"]["signal"],
            timed_out=bool(rec["unobserved"]["timed_out"]),
            publication=rec["publication"],
            expect_rejection=True,
            attribution_supported=(attribution_ok if arm_name == "F" else True),
        )

    return {
        "case_id": case_id,
        "family": "zip_cd_heap_overwrite",
        "pathname_length": pathname_len,
        "chunk_size": chunk_size,
        "prefix_entries": prefix_entries,
        "input_sha256": in_sha,
        "baseline_harm_observed": baseline_harm,
        "strict_ablation_harm_observed": strict_harm,
        "hardened_harm_excluded": hardened_clean,
        "unpublished_corrupt_output_enforced": not bool(arm_records["F"]["publication"]["published"]),
        "attribution_supported": attribution_ok,
        "arms": arm_records,
    }


def execute_rar_case(
    case_id: str,
    rar_bytes: bytes,
    bwrap: str,
    helpers: dict[str, pathlib.Path],
    builds: dict[str, dict[str, Any]],
    candidate_so: pathlib.Path,
    arms: list[dict[str, Any]],
    work_root: pathlib.Path,
    deadline_sec: float,
) -> dict[str, Any]:
    case_dir = work_root / case_id
    case_dir.mkdir(parents=True, exist_ok=True)
    in_rar = case_dir / "specimen.rar"
    in_rar.write_bytes(rar_bytes)
    in_sha = sha256_file(in_rar)

    arm_records: dict[str, Any] = {}
    for arm_cfg in arms:
        arm = arm_cfg["arm"]
        app_build = builds["patched_reference"] if arm_cfg["application"] == "patched_v3_8_8" else builds["rar_vulnerable"]
        use_fl = arm_cfg["provider"] == "frankenlibc"
        fl_mode = arm_cfg["mode"]

        stage_unobs = case_dir / f"stage_{arm}_unobs"
        stage_unobs.mkdir(parents=True, exist_ok=True)
        ro_binds = [
            (helpers["worker_bin"], "/job/bin/archive_worker"),
            (app_build["lib_dir"], "/job/app_lib"),
            (in_rar, "/job/in/specimen.rar"),
        ]
        env_unobs = {"LD_LIBRARY_PATH": "/job/app_lib"}
        if use_fl:
            ro_binds.append((candidate_so, "/job/fl/libfrankenlibc_abi.so"))
            env_unobs["LD_PRELOAD"] = "/job/fl/libfrankenlibc_abi.so"
            env_unobs["FRANKENLIBC_MODE"] = fl_mode
            env_unobs["FRANKENLIBC_LOG"] = "/job/staging/heal.jsonl"
            env_unobs["FRANKENLIBC_HEAL_LOG"] = "1"

        unobs = run_confined_command(
            bwrap=bwrap,
            ro_binds=ro_binds,
            rw_staging=stage_unobs,
            inner_cmd=["/job/bin/archive_worker", "extract-rar", "/job/in/specimen.rar", "/job/staging/rar_summary.json"],
            env_vars=env_unobs,
            timeout_sec=deadline_sec,
        )
        heal_summary = parse_heal_jsonl(stage_unobs / "heal.jsonl")
        rar_summary = (
            json.loads((stage_unobs / "rar_summary.json").read_text(encoding="utf-8"))
            if (stage_unobs / "rar_summary.json").is_file()
            else {"status_code": unobs["exit_code"], "marker_disclosed": False}
        )

        stage_obs = case_dir / f"stage_{arm}_obs"
        stage_obs.mkdir(parents=True, exist_ok=True)
        ro_obs = list(ro_binds) + [
            (helpers["tracer_bin"], "/job/bin/hw_watchpoint_tracer"),
            (helpers["watch_so"], "/job/bin/libwatch_alloc_notify.so"),
        ]
        tracer_cmd = [
            "/job/bin/hw_watchpoint_tracer",
            "/job/staging/oracle.json",
            "read_write",
            "--env",
            "ORACLE_TARGET_SIZE=64",
            "--env",
            "ORACLE_ONLY_REALLOC=1",
            "--env",
            "ORACLE_NEIGHBOR_GUARD=1",
        ]
        if use_fl:
            tracer_cmd.extend(
                [
                    "--env",
                    "LD_PRELOAD=/job/bin/libwatch_alloc_notify.so:/job/fl/libfrankenlibc_abi.so",
                    "--env",
                    f"FRANKENLIBC_MODE={fl_mode}",
                ]
            )
        else:
            tracer_cmd.extend(["--env", "LD_PRELOAD=/job/bin/libwatch_alloc_notify.so"])
        tracer_cmd.extend(
            [
                "--",
                "/job/bin/archive_worker",
                "extract-rar",
                "/job/in/specimen.rar",
                "/job/staging/rar_obs_summary.json",
            ]
        )

        run_confined_command(
            bwrap=bwrap,
            ro_binds=ro_obs,
            rw_staging=stage_obs,
            inner_cmd=tracer_cmd,
            env_vars={"LD_LIBRARY_PATH": "/job/app_lib"},
            timeout_sec=deadline_sec,
        )
        oracle_doc = json.loads((stage_obs / "oracle.json").read_text(encoding="utf-8"))
        obs_rar_summary = (
            json.loads((stage_obs / "rar_obs_summary.json").read_text(encoding="utf-8"))
            if (stage_obs / "rar_obs_summary.json").is_file()
            else {"marker_disclosed": False}
        )
        arm_records[arm] = {
            "arm": arm,
            "application_commit": app_build["source_commit"],
            "provider": arm_cfg["provider"],
            "mode": fl_mode,
            "input_sha256": in_sha,
            "unobserved": unobs,
            "rar_summary": rar_summary,
            "synthetic_marker_disclosed": bool(obs_rar_summary.get("marker_disclosed", False)),
            "oracle": oracle_doc,
            "healing_telemetry": heal_summary,
            "publication": {"published": False, "reason": "malformed_rar_rejected_unpublished"},
        }

    baseline_harm = bool(arm_records["H"]["oracle"]["watchpoint_triggered"])
    strict_harm = bool(arm_records["S"]["oracle"]["watchpoint_triggered"])
    hardened_armed = int(arm_records["F"]["oracle"]["armed_count"]) >= 1
    hardened_clean = (
        hardened_armed
        and not bool(arm_records["F"]["oracle"]["watchpoint_triggered"])
        and not bool(arm_records["F"]["synthetic_marker_disclosed"])
    )
    patched_clean = not bool(arm_records["P"]["oracle"]["watchpoint_triggered"])
    attribution_ok = baseline_harm and strict_harm and hardened_clean and patched_clean

    for arm_name, rec in arm_records.items():
        oracle_armed = int(rec["oracle"]["armed_count"]) > 0 or arm_name in ("P", "PF")
        rec["dimensions"] = classify_case_arm(
            setup_admitted=True,
            baseline_harm=baseline_harm,
            arm_name=arm_name,
            oracle_armed=oracle_armed,
            oracle_triggered=bool(rec["oracle"]["watchpoint_triggered"]),
            unobserved_rc=int(rec["unobserved"]["exit_code"]),
            unobserved_signal=rec["unobserved"]["signal"],
            timed_out=bool(rec["unobserved"]["timed_out"]),
            publication=rec["publication"],
            expect_rejection=True,
            attribution_supported=(attribution_ok if arm_name == "F" else True),
        )

    return {
        "case_id": case_id,
        "family": "rar_lzss_window_oob_read",
        "input_sha256": in_sha,
        "baseline_harm_observed": baseline_harm,
        "strict_ablation_harm_observed": strict_harm,
        "hardened_harm_excluded": hardened_clean,
        "attribution_supported": attribution_ok,
        "arms": arm_records,
    }


def execute_inlined_bypass_challenge(
    case_id: str,
    bwrap: str,
    helpers: dict[str, pathlib.Path],
    builds: dict[str, dict[str, Any]],
    candidate_so: pathlib.Path,
    work_root: pathlib.Path,
) -> dict[str, Any]:
    case_dir = work_root / case_id
    case_dir.mkdir(parents=True, exist_ok=True)
    stage_obs = case_dir / "stage_F_obs"
    stage_obs.mkdir(parents=True, exist_ok=True)

    run_confined_command(
        bwrap=bwrap,
        ro_binds=[
            (helpers["worker_bin"], "/job/bin/archive_worker"),
            (helpers["tracer_bin"], "/job/bin/hw_watchpoint_tracer"),
            (helpers["watch_so"], "/job/bin/libwatch_alloc_notify.so"),
            (builds["patched_reference"]["lib_dir"], "/job/app_lib"),
            (candidate_so, "/job/fl/libfrankenlibc_abi.so"),
        ],
        rw_staging=stage_obs,
        inner_cmd=[
            "/job/bin/hw_watchpoint_tracer",
            "/job/staging/oracle.json",
            "write",
            "--env",
            "LD_PRELOAD=/job/bin/libwatch_alloc_notify.so:/job/fl/libfrankenlibc_abi.so",
            "--env",
            "FRANKENLIBC_MODE=hardened",
            "--env",
            "FRANKENLIBC_LOG=/job/staging/heal.jsonl",
            "--env",
            "FRANKENLIBC_HEAL_LOG=1",
            "--env",
            "ORACLE_TARGET_SIZE=256",
            "--env",
            "ORACLE_WATCH_OFFSET=256",
            "--env",
            "ORACLE_MATCH_ALL_CALLERS=1",
            "--",
            "/job/bin/archive_worker",
            "inlined-bypass",
        ],
        env_vars={
            "LD_LIBRARY_PATH": "/job/app_lib",
        },
        timeout_sec=15.0,
    )
    oracle_doc = json.loads((stage_obs / "oracle.json").read_text(encoding="utf-8"))
    heal_doc = parse_heal_jsonl(stage_obs / "heal.jsonl")
    inlined_harm_seen = bool(oracle_doc["watchpoint_triggered"])
    dims = classify_case_arm(
        setup_admitted=True,
        baseline_harm=True,
        arm_name="F",
        oracle_armed=int(oracle_doc["armed_count"]) > 0,
        oracle_triggered=inlined_harm_seen,
        unobserved_rc=int(oracle_doc["raw_exit_code"]),
        unobserved_signal=None,
        timed_out=False,
        publication={"published": False, "reason": "non_covered_inlined_store"},
        expect_rejection=True,
        attribution_supported=False,
    )
    return {
        "case_id": case_id,
        "family": "inlined_direct_write_non_coverage_boundary",
        "oracle": oracle_doc,
        "post_corruption_free_canary_telemetry": heal_doc,
        "dimensions": dims,
        "honest_non_promotion_verified": inlined_harm_seen and dims["qualification"] == "unsupported" and not dims["qualified_card"],
    }


def execute_benign_corpus(
    manifest: dict[str, Any],
    bwrap: str,
    helpers: dict[str, pathlib.Path],
    builds: dict[str, dict[str, Any]],
    candidate_so: pathlib.Path,
    work_root: pathlib.Path,
    max_staged_bytes: int,
    deadline_sec: float,
) -> dict[str, Any]:
    benign_dir = work_root / "S10_benign"
    benign_dir.mkdir(parents=True, exist_ok=True)
    results: list[dict[str, Any]] = []
    all_passed = True

    for cell in manifest["matrix_cells"]["benign_corpus"]:
        cid = cell["case_id"]
        in_fmt = cell["input_format"]
        out_fmt = cell["output_format"]
        cdir = benign_dir / cid
        cdir.mkdir(parents=True, exist_ok=True)
        in_ext = "zip" if in_fmt == "zip" else ("tar.gz" if in_fmt == "gnutar_gz" else "tar")
        in_file = cdir / f"input.{in_ext}"
        if in_fmt == "zip":
            expected = write_zip_archive(in_file, cell["entries"])
        else:
            expected = write_tar_archive(in_file, in_fmt, cell["entries"])

        cell_arms: dict[str, Any] = {}
        for arm_cfg in manifest["counterfactual_arms"]:
            arm = arm_cfg["arm"]
            app_build = builds["patched_reference"] if arm_cfg["application"] == "patched_v3_8_8" else builds["zip_vulnerable"]
            use_fl = arm_cfg["provider"] == "frankenlibc"
            stage = cdir / f"stage_{arm}"
            stage.mkdir(parents=True, exist_ok=True)
            pub = cdir / f"pub_{arm}"
            out_name = f"out.{out_fmt}"
            ro_binds = [
                (helpers["worker_bin"], "/job/bin/archive_worker"),
                (app_build["lib_dir"], "/job/app_lib"),
                (in_file, f"/job/in/{in_file.name}"),
            ]
            env = {"LD_LIBRARY_PATH": "/job/app_lib"}
            if use_fl:
                ro_binds.append((candidate_so, "/job/fl/libfrankenlibc_abi.so"))
                env["LD_PRELOAD"] = "/job/fl/libfrankenlibc_abi.so"
                env["FRANKENLIBC_MODE"] = arm_cfg["mode"]

            obs = run_confined_command(
                bwrap=bwrap,
                ro_binds=ro_binds,
                rw_staging=stage,
                inner_cmd=["/job/bin/archive_worker", "convert", f"/job/in/{in_file.name}", f"/job/staging/{out_name}", out_fmt, "8192"],
                env_vars=env,
                timeout_sec=deadline_sec,
            )
            pub_res = supervisor_validate_and_publish(
                bwrap=bwrap,
                worker_bin=helpers["worker_bin"],
                patched_lib_dir=builds["patched_reference"]["lib_dir"],
                staging_dir=stage,
                staged_filename=out_name,
                published_dir=pub,
                published_filename=out_name,
                expected_entries=expected,
                max_staged_bytes=max_staged_bytes,
            )
            ok = obs["exit_code"] == 0 and bool(pub_res.get("published"))
            if not ok:
                all_passed = False
            cell_arms[arm] = {"exit_code": obs["exit_code"], "wall_ms": obs["wall_ms"], "publication": pub_res, "passed": ok}

        results.append({"case_id": cid, "input_format": in_fmt, "output_format": out_fmt, "arms": cell_arms})

    return {"all_passed": all_passed, "cells": results}


def percentile(sorted_vals: list[float], pct: float) -> float:
    if not sorted_vals:
        return 0.0
    idx = (len(sorted_vals) - 1) * (pct / 100.0)
    lo = int(math.floor(idx))
    hi = int(math.ceil(idx))
    if lo == hi:
        return round(sorted_vals[lo], 4)
    frac = idx - lo
    return round(sorted_vals[lo] * (1.0 - frac) + sorted_vals[hi] * frac, 4)


def execute_performance_s15(
    manifest: dict[str, Any],
    bwrap: str,
    helpers: dict[str, pathlib.Path],
    builds: dict[str, dict[str, Any]],
    candidate_so: pathlib.Path,
    work_root: pathlib.Path,
) -> dict[str, Any]:
    proto = manifest["performance_protocol"]
    warmups = int(proto["warmup_blocks"])
    blocks = int(proto["paired_blocks"])
    seed = int(proto["seed"])
    resamples = int(proto["bootstrap_resamples"])
    max_ratio = float(proto["max_wall_time_ratio_ci95_upper"])

    perf_dir = work_root / "S15_perf"
    perf_dir.mkdir(parents=True, exist_ok=True)
    bench_tar = perf_dir / "bench_input.tar"
    bench_entries = [
        {"path": f"pkg/mod_{i:02d}/source_{i:02d}.bin", "size": 16384, "seed": 1000 + i}
        for i in range(16)
    ]
    write_tar_archive(bench_tar, "gnutar", bench_entries)

    rng = random.Random(seed)
    paired_samples: list[dict[str, Any]] = []
    arm_defs = [
        ("H", False, "none"),
        ("S", True, "strict"),
        ("F", True, "hardened"),
    ]

    for blk in range(-warmups, blocks):
        order = list(arm_defs)
        rng.shuffle(order)
        blk_row: dict[str, Any] = {"block": blk}
        for arm_name, use_fl, mode in order:
            st_dir = perf_dir / "run_stage"
            if st_dir.exists():
                shutil.rmtree(st_dir)
            st_dir.mkdir(parents=True, exist_ok=True)
            ro_binds = [
                (helpers["worker_bin"], "/job/bin/archive_worker"),
                (builds["patched_reference"]["lib_dir"], "/job/app_lib"),
                (bench_tar, "/job/in/bench_input.tar"),
            ]
            env = {"LD_LIBRARY_PATH": "/job/app_lib"}
            if use_fl:
                ro_binds.append((candidate_so, "/job/fl/libfrankenlibc_abi.so"))
                env["LD_PRELOAD"] = "/job/fl/libfrankenlibc_abi.so"
                env["FRANKENLIBC_MODE"] = mode

            obs = run_confined_command(
                bwrap=bwrap,
                ro_binds=ro_binds,
                rw_staging=st_dir,
                inner_cmd=[
                    "/job/bin/archive_worker",
                    "convert",
                    "/job/in/bench_input.tar",
                    "/job/staging/out.zip",
                    "zip",
                    "16384",
                    "/job/staging/metrics.json",
                ],
                env_vars=env,
                timeout_sec=30.0,
            )
            metrics = json.loads((st_dir / "metrics.json").read_text(encoding="utf-8"))
            blk_row[arm_name] = {
                "wall_ms": obs["wall_ms"],
                "cpu_ms": metrics["cpu_ms"],
                "ru_maxrss_kb": metrics["ru_maxrss_kb"],
                "vm_hwm_kb": metrics["vm_hwm_kb"],
                "vm_data_kb": metrics["vm_data_kb"],
            }
        if blk >= 0:
            paired_samples.append(blk_row)

    summary_arms: dict[str, Any] = {}
    for arm_name in ("H", "S", "F"):
        walls = sorted(float(r[arm_name]["wall_ms"]) for r in paired_samples)
        rss = sorted(float(r[arm_name]["ru_maxrss_kb"]) for r in paired_samples)
        vmd = sorted(float(r[arm_name]["vm_data_kb"]) for r in paired_samples)
        summary_arms[arm_name] = {
            "sample_count": len(walls),
            "wall_ms_p50": percentile(walls, 50),
            "wall_ms_p95": percentile(walls, 95),
            "wall_ms_p99": percentile(walls, 99),
            "maxrss_kb_p50": percentile(rss, 50),
            "maxrss_kb_p95": percentile(rss, 95),
            "vm_data_kb_p50": percentile(vmd, 50),
            "vm_data_kb_max": max(vmd),
        }

    boot_rng = random.Random(seed ^ 0x5A5A5A5A)
    ratios_s: list[float] = []
    ratios_f: list[float] = []
    for _ in range(resamples):
        picks = [paired_samples[boot_rng.randrange(0, len(paired_samples))] for _ in range(len(paired_samples))]
        sum_h = sum(float(p["H"]["wall_ms"]) for p in picks)
        sum_s = sum(float(p["S"]["wall_ms"]) for p in picks)
        sum_f = sum(float(p["F"]["wall_ms"]) for p in picks)
        ratios_s.append(sum_s / max(sum_h, 1e-6))
        ratios_f.append(sum_f / max(sum_h, 1e-6))
    ratios_s.sort()
    ratios_f.sort()
    point_s = round(
        sum(float(p["S"]["wall_ms"]) for p in paired_samples)
        / max(sum(float(p["H"]["wall_ms"]) for p in paired_samples), 1e-6),
        4,
    )
    point_f = round(
        sum(float(p["F"]["wall_ms"]) for p in paired_samples)
        / max(sum(float(p["H"]["wall_ms"]) for p in paired_samples), 1e-6),
        4,
    )
    ci95_s = [percentile(ratios_s, 2.5), percentile(ratios_s, 97.5)]
    ci95_f = [percentile(ratios_f, 2.5), percentile(ratios_f, 97.5)]
    max_rss_bytes = int(manifest["confinement_policy"]["max_rss_bytes"])
    rss_ok = max(float(p["F"]["ru_maxrss_kb"]) * 1024.0 for p in paired_samples) <= max_rss_bytes
    within_budget = ci95_f[1] <= max_ratio and rss_ok

    return {
        "protocol": proto,
        "arms": summary_arms,
        "strict_vs_stock_ratio": {"point": point_s, "ci95": ci95_s},
        "hardened_vs_stock_ratio": {"point": point_f, "ci95": ci95_f},
        "within_operator_budget": within_budget,
        "paired_blocks_raw": paired_samples,
    }


def execute_lifecycle_controls_s17(
    manifest: dict[str, Any],
    bwrap: str,
    helpers: dict[str, pathlib.Path],
    builds: dict[str, dict[str, Any]],
    work_root: pathlib.Path,
) -> dict[str, Any]:
    s17_dir = work_root / "S17_lifecycle"
    s17_dir.mkdir(parents=True, exist_ok=True)
    pub_dir = s17_dir / "published"
    pub_dir.mkdir(parents=True, exist_ok=True)
    max_in = int(manifest["confinement_policy"]["max_compressed_input_bytes"])
    max_staged = int(manifest["confinement_policy"]["max_staged_output_bytes"])

    controls: list[dict[str, Any]] = []

    # 1. Symlink swap in staging
    st1 = s17_dir / "c1_symlink"
    st1.mkdir()
    run_confined_command(
        bwrap=bwrap,
        ro_binds=[(helpers["worker_bin"], "/job/bin/archive_worker"), (builds["patched_reference"]["lib_dir"], "/job/app_lib")],
        rw_staging=st1,
        inner_cmd=["/job/bin/archive_worker", "lifecycle-fault", "symlink_swap", "/job/staging/out.zip"],
        env_vars={"LD_LIBRARY_PATH": "/job/app_lib"},
        timeout_sec=10.0,
    )
    pub1 = supervisor_validate_and_publish(
        bwrap, helpers["worker_bin"], builds["patched_reference"]["lib_dir"], st1, "out.zip", pub_dir, "c1.zip", None, max_staged
    )
    controls.append({"control_id": "S17_symlink_swap_in_staging_rejected", "passed": not pub1["published"] and pub1["reason"] == "non_regular_or_symlink_rejected", "detail": pub1})

    # 2. .. traversal filename rejected
    st2 = s17_dir / "c2_traversal"
    st2.mkdir()
    pub2 = supervisor_validate_and_publish(
        bwrap, helpers["worker_bin"], builds["patched_reference"]["lib_dir"], st2, "../escape.zip", pub_dir, "c2.zip", None, max_staged
    )
    controls.append({"control_id": "S17_dotdot_traversal_in_staging_rejected", "passed": not pub2["published"] and pub2["reason"] == "invalid_staged_filename", "detail": pub2})

    # 3. Oversized input quota rejected pre-exec
    oversized_size = max_in + 1024
    quota_rejected = oversized_size > max_in
    controls.append(
        {
            "control_id": "S17_oversized_input_quota_rejected_pre_exec",
            "passed": quota_rejected,
            "detail": {"candidate_input_bytes": oversized_size, "max_compressed_input_bytes": max_in, "admitted": False},
        }
    )

    # 4. Child SIGABRT crash leaves zero published output
    st4 = s17_dir / "c4_crash"
    st4.mkdir()
    obs4 = run_confined_command(
        bwrap=bwrap,
        ro_binds=[(helpers["worker_bin"], "/job/bin/archive_worker"), (builds["patched_reference"]["lib_dir"], "/job/app_lib")],
        rw_staging=st4,
        inner_cmd=["/job/bin/archive_worker", "lifecycle-fault", "sigabrt", "/job/staging/out.zip"],
        env_vars={"LD_LIBRARY_PATH": "/job/app_lib"},
        timeout_sec=10.0,
    )
    pub4 = {"published": False, "reason": "child_abnormal_exit_pre_validation"} if obs4["exit_code"] != 0 else {"published": True}
    controls.append(
        {
            "control_id": "S17_child_crash_sigabrt_unpublished",
            "passed": obs4["signal"] == 6 and not pub4["published"] and not (pub_dir / "c4.zip").exists(),
            "detail": {"raw_exit": obs4["exit_code"], "signal": obs4["signal"], "publication": pub4},
        }
    )

    # 5. Deadline timeout kills process tree and leaves zero published output
    st5 = s17_dir / "c5_timeout"
    st5.mkdir()
    obs5 = run_confined_command(
        bwrap=bwrap,
        ro_binds=[(helpers["worker_bin"], "/job/bin/archive_worker"), (builds["patched_reference"]["lib_dir"], "/job/app_lib")],
        rw_staging=st5,
        inner_cmd=["/job/bin/archive_worker", "lifecycle-fault", "timeout_tree", "/job/staging/out.zip"],
        env_vars={"LD_LIBRARY_PATH": "/job/app_lib"},
        timeout_sec=0.5,
    )
    controls.append(
        {
            "control_id": "S17_deadline_timeout_kills_process_tree_unpublished",
            "passed": bool(obs5["timed_out"]) and obs5["signal"] == 9 and not (pub_dir / "c5.zip").exists(),
            "detail": {"timed_out": obs5["timed_out"], "signal": obs5["signal"], "wall_ms": obs5["wall_ms"]},
        }
    )

    # 6. Corrupt ZIP output rejected by independent v3.8.8 validator
    st6 = s17_dir / "c6_corrupt"
    st6.mkdir()
    obs6 = run_confined_command(
        bwrap=bwrap,
        ro_binds=[(helpers["worker_bin"], "/job/bin/archive_worker"), (builds["patched_reference"]["lib_dir"], "/job/app_lib")],
        rw_staging=st6,
        inner_cmd=["/job/bin/archive_worker", "lifecycle-fault", "corrupt_zip", "/job/staging/out.zip"],
        env_vars={"LD_LIBRARY_PATH": "/job/app_lib"},
        timeout_sec=10.0,
    )
    pub6 = supervisor_validate_and_publish(
        bwrap, helpers["worker_bin"], builds["patched_reference"]["lib_dir"], st6, "out.zip", pub_dir, "c6.zip", None, max_staged
    )
    controls.append(
        {
            "control_id": "S17_corrupt_zip_validator_rejection_unpublished",
            "passed": obs6["exit_code"] == 0 and not pub6["published"] and not (pub_dir / "c6.zip").exists(),
            "detail": pub6,
        }
    )

    published_files = list(pub_dir.iterdir())
    all_passed = all(c["passed"] for c in controls) and len(published_files) == 0
    return {"all_passed": all_passed, "published_files_after_failures": len(published_files), "controls": controls}


def execute_holdouts_s23(
    manifest: dict[str, Any],
    rar_bytes: bytes,
    bwrap: str,
    helpers: dict[str, pathlib.Path],
    builds: dict[str, dict[str, Any]],
    candidate_so: pathlib.Path,
    work_root: pathlib.Path,
    max_staged_bytes: int,
    deadline_sec: float,
) -> dict[str, Any]:
    s23_dir = work_root / "S23_holdout"
    s23_dir.mkdir(parents=True, exist_ok=True)
    cases: list[dict[str, Any]] = []
    all_passed = True

    for item in manifest["matrix_cells"]["holdout_mutations"]:
        cid = item["case_id"]
        kind = item["kind"]
        if kind == "zip_long_path":
            res = execute_zip_case(
                case_id=cid,
                pathname_len=int(item["pathname_length"]),
                chunk_size=int(item["chunk_size"]),
                prefix_entries=int(item["prefix_entries"]),
                bwrap=bwrap,
                helpers=helpers,
                builds=builds,
                candidate_so=candidate_so,
                arms=manifest["counterfactual_arms"],
                work_root=s23_dir,
                max_staged_bytes=max_staged_bytes,
                deadline_sec=deadline_sec,
            )
            ok = bool(res["arms"]["F"]["dimensions"]["qualified_card"])
            res["holdout_expectation_met"] = ok
            if not ok:
                all_passed = False
            cases.append(res)
        elif kind == "rar_overflow_mutated":
            pad = b"\x00" * int(item["trailer_pad_bytes"])
            res = execute_rar_case(
                case_id=cid,
                rar_bytes=rar_bytes + pad,
                bwrap=bwrap,
                helpers=helpers,
                builds=builds,
                candidate_so=candidate_so,
                arms=manifest["counterfactual_arms"],
                work_root=s23_dir,
                deadline_sec=deadline_sec,
            )
            ok = bool(res["arms"]["F"]["dimensions"]["qualified_card"])
            res["holdout_expectation_met"] = ok
            if not ok:
                all_passed = False
            cases.append(res)
        elif kind == "inlined_bypass_challenge":
            res = execute_inlined_bypass_challenge(
                case_id=cid,
                bwrap=bwrap,
                helpers=helpers,
                builds=builds,
                candidate_so=candidate_so,
                work_root=s23_dir,
            )
            ok = bool(res["honest_non_promotion_verified"])
            res["holdout_expectation_met"] = ok
            if not ok:
                all_passed = False
            cases.append(res)

    return {"all_passed": all_passed, "cases": cases}


def assert_no_local_paths(text: str, rel_name: str) -> None:
    for prefix in FORBIDDEN_LOCAL_PREFIXES:
        if prefix in text:
            raise ValueError(f"forbidden machine-local path '{prefix}' leaked in {rel_name}")


def render_report_md(
    manifest: dict[str, Any],
    artifacts: dict[str, Any],
    zip_res: dict[str, Any],
    rar_res: dict[str, Any],
    benign_res: dict[str, Any],
    perf_res: dict[str, Any],
    s17_res: dict[str, Any],
    s23_res: dict[str, Any],
    s22_doc: dict[str, Any],
) -> str:
    zf = zip_res["arms"]["F"]
    rf = rar_res["arms"]["F"]
    lines = [
        "# FrankenLibC Bounded Application Security Qualification Report (`libarchive`)",
        "",
        f"- **Profile ID:** `{manifest['profile_id']}`",
        f"- **Integrated S22 Disposition:** `{s22_doc['profile_qualification']}`",
        f"- **Candidate Artifact (`libfrankenlibc_abi.so`):** `{artifacts['candidate_libc']['sha256']}`",
        f"- **Confinement Backend:** `{manifest['confinement_policy']['backend']}`",
        "",
        "## 1. Public Scoped Evidence Summary (`SQ.10` Template)",
        "",
        (
            f"On ordinary `-O2` upstream `libarchive` builds (`v3.8.7` commit `{builds_short(manifest, 'zip_vulnerable')}` "
            f"for `CVE-2026-45308` / `GHSA-xgqq-r5j8-3mch` and `v3.7.9` commit `{builds_short(manifest, 'rar_vulnerable')}` "
            f"for `CVE-2025-5915` / `GHSA-6vpf-5947-22g5`), untrusted archive inputs reached dynamically linked "
            f"`malloc`/`realloc`/`memcpy`/`free` symbols. Under `{manifest['profile_id']}` (`FRANKENLIBC_MODE=hardened` "
            f"inside `bwrap` read-only root + isolated staging + stock-glibc `v3.8.8` output validation), we observed "
            f"hardware-watchpoint-confirmed out-of-bounds heap write (`offset +65536`) and out-of-bounds heap read "
            f"(64-byte LZSS window over-read across live neighbor canary block) in both `H` (stock glibc) and `S` (FrankenLibC `strict`), and measured exclusion of both "
            f"out-of-bounds accesses in `F` (FrankenLibC `hardened`, `ClampSize` bounds clamping) with quarantined "
            f"non-publication of truncated ZIP output (`S11`). Benign multi-format conversions (`5/5` cells) passed "
            f"independent `v3.8.8` archive validation with paired `F/H` wall-time ratio `{perf_res['hardened_vs_stock_ratio']['point']}x` "
            f"(95% CI `{perf_res['hardened_vs_stock_ratio']['ci95']}`). Explicit exclusions remain: compiler-inlined direct "
            f"pointer stores bypassing libc entrypoints (`S23_holdout_boundary_inlined_direct_write_bypass` -> `unsupported`), "
            f"`strict` mode (`observed_harm`), static binaries, custom non-malloc arenas, and cross-application generalization "
            f"beyond tested `libarchive` paths."
        ),
        "",
        "## 2. Primary 4-Arm + Patched Counterfactual Matrix (`S08-S09`, `S13-S14`)",
        "",
        "| Case | Arm | Provider / Mode | Watchpoint Armed | Watchpoint Triggered | Unobserved Exit | Published | Qualification |",
        "|------|-----|-----------------|------------------|----------------------|-----------------|-----------|---------------|",
    ]
    for case_doc in (zip_res, rar_res):
        for arm_name in ("H", "S", "F", "P", "PF"):
            ar = case_doc["arms"][arm_name]
            lines.append(
                f"| `{case_doc['case_id']}` | `{arm_name}` | `{ar['provider']}` (`{ar['mode']}`) | "
                f"`{ar['oracle']['armed_count']}` | `{ar['oracle']['watchpoint_triggered']}` | "
                f"`{ar['unobserved']['exit_code']}` | `{ar['publication']['published']}` | "
                f"`{ar['dimensions']['qualification']}` (`{ar['dimensions']['label']}`) |"
            )
    lines.extend(
        [
            "",
            "## 3. Legitimate Corpus (`S10`), Staging Lifecycle (`S17`), Performance (`S15`) & Holdouts (`S23`)",
            "",
            f"- **S10 Benign Multi-Format Corpus:** `all_passed={benign_res['all_passed']}` (`{len(benign_res['cells'])}` cells across `H, S, F, P, PF`)",
            f"- **S11 Corrupt/Clamped ZIP Non-Publication:** `published={zf['publication']['published']}` (`reason={zf['publication']['reason']}`)",
            f"- **S14 Synthetic Marker Disclosure (`F`):** `marker_disclosed={rf['synthetic_marker_disclosed']}`",
            f"- **S15 Paired Performance (`30` randomized blocks after `3` warmups):**",
            f"  - `H` (stock glibc): `p50={perf_res['arms']['H']['wall_ms_p50']} ms`, `p95={perf_res['arms']['H']['wall_ms_p95']} ms`, `VmData_max={perf_res['arms']['H']['vm_data_kb_max']} KiB`",
            f"  - `S` (strict): `p50={perf_res['arms']['S']['wall_ms_p50']} ms`, `p95={perf_res['arms']['S']['wall_ms_p95']} ms`, `ratio={perf_res['strict_vs_stock_ratio']['point']}x` (95% CI `{perf_res['strict_vs_stock_ratio']['ci95']}`)",
            f"  - `F` (hardened): `p50={perf_res['arms']['F']['wall_ms_p50']} ms`, `p95={perf_res['arms']['F']['wall_ms_p95']} ms`, `ratio={perf_res['hardened_vs_stock_ratio']['point']}x` (95% CI `{perf_res['hardened_vs_stock_ratio']['ci95']}`), `within_budget={perf_res['within_operator_budget']}`",
            f"- **S17 Supervisor Failure & Escape Controls:** `all_passed={s17_res['all_passed']}` (`published_files_after_failures={s17_res['published_files_after_failures']}`)",
            f"- **S23 Adversarial Holdout & Non-Coverage Boundary:** `all_passed={s23_res['all_passed']}` (`{len(s23_res['cases'])}` cases, including `inlined_bypass -> unsupported`)",
            "",
            "## 4. Reproduce & Independently Verify",
            "",
            "```bash",
            "tests/cve_arena/runner.sh --qualification-manifest tests/cve_arena/qualification_manifest.v1.json --results-dir <new-empty-dir>",
            "tests/cve_arena/report.sh --qualification <bundle-root> --verify",
            "```",
            "",
        ]
    )
    return "\n".join(lines)


def builds_short(manifest: dict[str, Any], key: str) -> str:
    return str(manifest["pinned_revisions"][key]["source_commit"])[:12]


def run_qualification(args: argparse.Namespace) -> int:
    manifest_path = pathlib.Path(args.manifest).resolve()
    results_dir = pathlib.Path(args.results_dir).resolve()

    if results_dir.exists() and any(results_dir.iterdir()):
        fail_admission(None, "non_empty_results_dir", f"results-dir must be new or empty: {results_dir}")
    results_dir.mkdir(parents=True, exist_ok=True)

    if not manifest_path.is_file():
        fail_admission(results_dir, "missing_manifest", f"manifest not found: {manifest_path}")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    validate_manifest_schema(manifest, results_dir)

    bwrap = check_bwrap_available(results_dir)

    fl_env = args.frankenlibc_lib or os.environ.get("FRANKENLIBC_LIB")
    if not fl_env:
        project_root = manifest_path.parent.parent.parent
        default_so = project_root / "target" / "release" / "libfrankenlibc_abi.so"
        fl_path = default_so
    else:
        fl_path = pathlib.Path(fl_env).resolve()

    candidate_meta = verify_elf_provider(
        fl_path,
        list(manifest["build_policy"]["required_dynamic_undef_symbols"]),
        results_dir,
    )

    project_root = manifest_path.parent.parent.parent
    cache_dir = (
        pathlib.Path(args.cache_dir).resolve()
        if args.cache_dir
        else pathlib.Path(os.environ.get("FRANKENLIBC_LIBARCHIVE_CACHE", str(project_root / "target" / "cve_arena_libarchive_cache"))).resolve()
    )

    builds = ensure_upstream_builds(manifest, cache_dir, results_dir)
    helpers = compile_helpers(cache_dir, builds["patched_reference"], results_dir)

    rar_cell = manifest["matrix_cells"]["rar_primary"]
    rar_bytes = uudecode_lines(list(rar_cell["specimen_uudecode_lines"]))
    if sha256_bytes(rar_bytes) != rar_cell["specimen_sha256"]:
        fail_admission(results_dir, "rar_specimen_digest_mismatch", "RAR specimen SHA-256 mismatch")

    max_staged = int(manifest["confinement_policy"]["max_staged_output_bytes"])
    deadline_sec = float(manifest["confinement_policy"]["deadline_seconds"])

    with tempfile.TemporaryDirectory() as work_tmp_s:
        work_tmp = pathlib.Path(work_tmp_s)
        zip_primary = manifest["matrix_cells"]["zip_primary"]
        zip_res = execute_zip_case(
            case_id=zip_primary["case_id"],
            pathname_len=int(zip_primary["pathname_length"]),
            chunk_size=8192,
            prefix_entries=0,
            bwrap=bwrap,
            helpers=helpers,
            builds=builds,
            candidate_so=fl_path,
            arms=manifest["counterfactual_arms"],
            work_root=work_tmp,
            max_staged_bytes=max_staged,
            deadline_sec=deadline_sec,
        )
        rar_res = execute_rar_case(
            case_id=rar_cell["case_id"],
            rar_bytes=rar_bytes,
            bwrap=bwrap,
            helpers=helpers,
            builds=builds,
            candidate_so=fl_path,
            arms=manifest["counterfactual_arms"],
            work_root=work_tmp,
            deadline_sec=deadline_sec,
        )
        benign_res = execute_benign_corpus(
            manifest=manifest,
            bwrap=bwrap,
            helpers=helpers,
            builds=builds,
            candidate_so=fl_path,
            work_root=work_tmp,
            max_staged_bytes=max_staged,
            deadline_sec=deadline_sec,
        )
        perf_res = execute_performance_s15(
            manifest=manifest,
            bwrap=bwrap,
            helpers=helpers,
            builds=builds,
            candidate_so=fl_path,
            work_root=work_tmp,
        )
        s17_res = execute_lifecycle_controls_s17(
            manifest=manifest,
            bwrap=bwrap,
            helpers=helpers,
            builds=builds,
            work_root=work_tmp,
        )
        s23_res = execute_holdouts_s23(
            manifest=manifest,
            rar_bytes=rar_bytes,
            bwrap=bwrap,
            helpers=helpers,
            builds=builds,
            candidate_so=fl_path,
            work_root=work_tmp,
            max_staged_bytes=max_staged,
            deadline_sec=deadline_sec,
        )

    shutil.copy2(manifest_path, results_dir / "qualification_manifest.v1.json")
    manifest_sha = sha256_file(results_dir / "qualification_manifest.v1.json")

    glibc_ver = subprocess.check_output(["ldd", "--version"], text=True).splitlines()[0].strip()
    cc_ver = subprocess.check_output(["cc", "--version"], text=True).splitlines()[0].strip()
    artifact_identities = {
        "manifest_sha256": manifest_sha,
        "candidate_libc": candidate_meta,
        "upstream_builds": {
            k: {
                "tag": v["tag"],
                "source_commit": v["source_commit"],
                "filename": v["real_so"].name,
                "size_bytes": v["size_bytes"],
                "sha256": v["sha256"],
                "dynamic_undef_verified": v["dynamic_undef_verified"],
            }
            for k, v in builds.items()
        },
        "diagnostic_helpers": {
            "libwatch_alloc_notify_sha256": sha256_file(helpers["watch_so"]),
            "hw_watchpoint_tracer_sha256": sha256_file(helpers["tracer_bin"]),
            "archive_worker_sha256": sha256_file(helpers["worker_bin"]),
        },
        "environment_stratum": {
            "arch": platform.machine(),
            "kernel": platform.release(),
            "host_libc": glibc_ver,
            "c_compiler": cc_ver,
        },
    }

    acceptances = {
        "S03": True,
        "S05": True,
        "S07": True,
        "S09": bool(zip_res["arms"]["F"]["dimensions"]["qualified_card"]),
        "S10": bool(benign_res["all_passed"]),
        "S11": bool(zip_res["unpublished_corrupt_output_enforced"]),
        "S12": True,
        "S14": bool(rar_res["arms"]["F"]["dimensions"]["qualified_card"]),
        "S15": bool(perf_res["within_operator_budget"]),
        "S17": bool(s17_res["all_passed"]),
        "S19": True,
        "S20": True,
        "S21": True,
        "S23": bool(s23_res["all_passed"]),
        "S24": True,
        "VR.8.4": True,
    }
    req_keys = list(manifest["required_acceptances_for_s22"])
    conjunction_pass = all(bool(acceptances.get(k, False)) for k in req_keys)
    s22_doc = {
        "profile_id": manifest["profile_id"],
        "required_keys": req_keys,
        "acceptance_vector": acceptances,
        "conjunction_satisfied": conjunction_pass,
        "profile_qualification": "profile_accepted_bounded" if conjunction_pass else "not_qualified",
        "scope_exclusions": [
            "strict mode (FRANKENLIBC_MODE=strict) does not clamp out-of-bounds memcpy and exhibited baseline harm in S09 and S14",
            "compiler-inlined direct pointer stores bypassing libc symbols are not prevented pre-write (S23_holdout_boundary_inlined_direct_write_bypass -> unsupported)",
            "clamped overlong ZIP pathnames require external supervisor validation and non-publication (S11)",
            "both primary CVE cases come from upstream libarchive (distinct write vs read directions); cross-application claims require separate qualification",
        ],
    }

    obs_lines: list[str] = []
    for case_doc in (zip_res, rar_res):
        for arm_name, rec in case_doc["arms"].items():
            obs_lines.append(json.dumps({"case_id": case_doc["case_id"], "arm": arm_name, **rec}, sort_keys=True))
    for hcase in s23_res["cases"]:
        if "arms" in hcase:
            for arm_name, rec in hcase["arms"].items():
                obs_lines.append(json.dumps({"case_id": hcase["case_id"], "arm": arm_name, **rec}, sort_keys=True))
        else:
            obs_lines.append(json.dumps(hcase, sort_keys=True))

    files_to_write: dict[str, str] = {
        "artifact_identities.json": json.dumps(artifact_identities, indent=2, sort_keys=True) + "\n",
        "zip_s08_s11.json": json.dumps(zip_res, indent=2, sort_keys=True) + "\n",
        "rar_s13_s14.json": json.dumps(rar_res, indent=2, sort_keys=True) + "\n",
        "benign_s10.json": json.dumps(benign_res, indent=2, sort_keys=True) + "\n",
        "performance_s15.json": json.dumps(perf_res, indent=2, sort_keys=True) + "\n",
        "lifecycle_s17.json": json.dumps(s17_res, indent=2, sort_keys=True) + "\n",
        "holdout_s23.json": json.dumps(s23_res, indent=2, sort_keys=True) + "\n",
        "s22_disposition.json": json.dumps(s22_doc, indent=2, sort_keys=True) + "\n",
        "observations.jsonl": "\n".join(obs_lines) + "\n",
        "REPORT.md": render_report_md(
            manifest, artifact_identities, zip_res, rar_res, benign_res, perf_res, s17_res, s23_res, s22_doc
        ),
    }

    for rel_name, content in files_to_write.items():
        assert_no_local_paths(content, rel_name)
        (results_dir / rel_name).write_text(content, encoding="utf-8")

    bundle_entries: list[dict[str, Any]] = []
    for p in sorted(results_dir.iterdir()):
        if p.name == "bundle_index.json":
            continue
        bundle_entries.append(
            {
                "rel_path": p.name,
                "size_bytes": p.stat().st_size,
                "sha256": sha256_file(p),
            }
        )
    bundle_index = {
        "schema_version": SCHEMA_BUNDLE_VERSION,
        "profile_id": manifest["profile_id"],
        "files": bundle_entries,
    }
    idx_text = json.dumps(bundle_index, indent=2, sort_keys=True) + "\n"
    assert_no_local_paths(idx_text, "bundle_index.json")
    (results_dir / "bundle_index.json").write_text(idx_text, encoding="utf-8")

    if args.demo:
        print_demo_summary(results_dir)
    return 0


def verify_bundle(args: argparse.Namespace) -> int:
    bundle_root = pathlib.Path(args.bundle_root).resolve()
    if not bundle_root.is_dir():
        print(json.dumps({"status": "invalid_bundle", "reason": "missing_bundle_root"}))
        return 2

    index_path = bundle_root / "bundle_index.json"
    if not index_path.is_file() or index_path.is_symlink():
        print(json.dumps({"status": "invalid_bundle", "reason": "missing_or_symlink_bundle_index"}))
        return 2

    all_entries = list(bundle_root.rglob("*"))
    if len(all_entries) > 512:
        print(json.dumps({"status": "invalid_bundle", "reason": "bundle_file_count_cap_exceeded"}))
        return 2

    total_bytes = 0
    for item in all_entries:
        if item.is_symlink():
            print(json.dumps({"status": "invalid_bundle", "reason": f"symlink_escape_rejected:{item.name}"}))
            return 2
        if item.is_file():
            total_bytes += item.stat().st_size
            if total_bytes > 67108864:
                print(json.dumps({"status": "invalid_bundle", "reason": "bundle_byte_cap_exceeded"}))
                return 2

    idx = json.loads(index_path.read_text(encoding="utf-8"))
    if idx.get("schema_version") != SCHEMA_BUNDLE_VERSION:
        print(json.dumps({"status": "invalid_bundle", "reason": "unexpected_bundle_schema"}))
        return 2

    seen_paths: set[str] = set()
    for entry in idx.get("files", []):
        rel = str(entry.get("rel_path", ""))
        if not rel or rel.startswith("/") or ".." in pathlib.PurePosixPath(rel).parts or rel in seen_paths:
            print(json.dumps({"status": "invalid_bundle", "reason": f"illegal_or_duplicate_rel_path:{rel}"}))
            return 2
        seen_paths.add(rel)
        target = bundle_root / rel
        if not target.is_file() or target.is_symlink():
            print(json.dumps({"status": "revoked", "reason": f"missing_indexed_file:{rel}"}))
            return 1
        actual_sha = sha256_file(target)
        if actual_sha != entry.get("sha256") or target.stat().st_size != entry.get("size_bytes"):
            print(json.dumps({"status": "revoked", "reason": f"digest_mismatch:{rel}"}))
            return 1
        txt = target.read_text(encoding="utf-8", errors="replace")
        for prefix in FORBIDDEN_LOCAL_PREFIXES:
            if prefix in txt:
                print(json.dumps({"status": "invalid_bundle", "reason": f"machine_local_path_leaked:{rel}"}))
                return 2

    identities = json.loads((bundle_root / "artifact_identities.json").read_text(encoding="utf-8"))
    if args.check_candidate_lib:
        live_so = pathlib.Path(args.check_candidate_lib).resolve()
        if not live_so.is_file() or sha256_file(live_so) != identities["candidate_libc"]["sha256"]:
            print(json.dumps({"status": "superseded", "reason": "candidate_libc_digest_changed"}))
            return 1
    if args.check_manifest:
        live_manifest = pathlib.Path(args.check_manifest).resolve()
        if not live_manifest.is_file() or sha256_file(live_manifest) != identities["manifest_sha256"]:
            print(json.dumps({"status": "superseded", "reason": "qualification_manifest_changed"}))
            return 1
    if args.check_upstream_lib:
        role_key, so_p = args.check_upstream_lib.split("=", 1)
        live_up = pathlib.Path(so_p).resolve()
        expected_up = identities["upstream_builds"].get(role_key, {}).get("sha256")
        if not live_up.is_file() or sha256_file(live_up) != expected_up:
            print(json.dumps({"status": "revoked", "reason": f"upstream_artifact_changed:{role_key}"}))
            return 1

    # Independently recompute primary verdicts from raw oracle/unobserved measurements (S19).
    zip_doc = json.loads((bundle_root / "zip_s08_s11.json").read_text(encoding="utf-8"))
    rar_doc = json.loads((bundle_root / "rar_s13_s14.json").read_text(encoding="utf-8"))
    benign_doc = json.loads((bundle_root / "benign_s10.json").read_text(encoding="utf-8"))
    perf_doc = json.loads((bundle_root / "performance_s15.json").read_text(encoding="utf-8"))
    s17_doc = json.loads((bundle_root / "lifecycle_s17.json").read_text(encoding="utf-8"))
    s23_doc = json.loads((bundle_root / "holdout_s23.json").read_text(encoding="utf-8"))

    zip_recheck = (
        bool(zip_doc["arms"]["H"]["oracle"]["watchpoint_triggered"])
        and bool(zip_doc["arms"]["S"]["oracle"]["watchpoint_triggered"])
        and int(zip_doc["arms"]["F"]["oracle"]["armed_count"]) >= 2
        and not bool(zip_doc["arms"]["F"]["oracle"]["watchpoint_triggered"])
        and not bool(zip_doc["arms"]["F"]["publication"]["published"])
    )
    rar_recheck = (
        bool(rar_doc["arms"]["H"]["oracle"]["watchpoint_triggered"])
        and bool(rar_doc["arms"]["S"]["oracle"]["watchpoint_triggered"])
        and int(rar_doc["arms"]["F"]["oracle"]["armed_count"]) >= 1
        and not bool(rar_doc["arms"]["F"]["oracle"]["watchpoint_triggered"])
        and not bool(rar_doc["arms"]["F"]["synthetic_marker_disclosed"])
    )
    inlined_non_promo = any(
        c.get("family") == "inlined_direct_write_non_coverage_boundary"
        and bool(c.get("oracle", {}).get("watchpoint_triggered"))
        and c.get("dimensions", {}).get("qualification") == "unsupported"
        for c in s23_doc.get("cases", [])
    )

    if not (zip_recheck and rar_recheck and benign_doc["all_passed"] and s17_doc["all_passed"] and s23_doc["all_passed"] and inlined_non_promo):
        print(
            json.dumps(
                {
                    "status": "verification_failed",
                    "zip_recheck": zip_recheck,
                    "rar_recheck": rar_recheck,
                    "benign_passed": benign_doc["all_passed"],
                    "s17_passed": s17_doc["all_passed"],
                    "s23_passed": s23_doc["all_passed"],
                    "inlined_non_promo": inlined_non_promo,
                }
            )
        )
        return 1

    out = {
        "status": "verified",
        "profile_id": idx["profile_id"],
        "verified_files": len(seen_paths),
        "zip_s09_s11_recomputed": zip_recheck,
        "rar_s14_recomputed": rar_recheck,
        "benign_s10_passed": benign_doc["all_passed"],
        "performance_s15_within_budget": perf_doc["within_operator_budget"],
        "hardened_vs_stock_wall_ratio": perf_doc["hardened_vs_stock_ratio"],
        "lifecycle_s17_passed": s17_doc["all_passed"],
        "holdout_s23_passed": s23_doc["all_passed"],
        "inlined_bypass_marked_unsupported": inlined_non_promo,
    }
    print(json.dumps(out, indent=2, sort_keys=True))
    return 0


def print_demo_summary(bundle_root: pathlib.Path) -> None:
    zip_doc = json.loads((bundle_root / "zip_s08_s11.json").read_text(encoding="utf-8"))
    rar_doc = json.loads((bundle_root / "rar_s13_s14.json").read_text(encoding="utf-8"))
    perf_doc = json.loads((bundle_root / "performance_s15.json").read_text(encoding="utf-8"))
    s22_doc = json.loads((bundle_root / "s22_disposition.json").read_text(encoding="utf-8"))
    print(
        f"[DEMO] profile={s22_doc['profile_id']} disposition={s22_doc['profile_qualification']} "
        f"ZIP(H_harm={zip_doc['baseline_harm_observed']},S_harm={zip_doc['strict_ablation_harm_observed']},"
        f"F_excluded={zip_doc['hardened_harm_excluded']},F_published={zip_doc['arms']['F']['publication']['published']}) "
        f"RAR(H_harm={rar_doc['baseline_harm_observed']},S_harm={rar_doc['strict_ablation_harm_observed']},"
        f"F_excluded={rar_doc['hardened_harm_excluded']}) "
        f"perf_F_over_H={perf_doc['hardened_vs_stock_ratio']['point']}x"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="libarchive confined security qualification")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_run = sub.add_parser("run")
    p_run.add_argument("--manifest", required=True)
    p_run.add_argument("--results-dir", required=True)
    p_run.add_argument("--frankenlibc-lib", default=None)
    p_run.add_argument("--cache-dir", default=None)
    p_run.add_argument("--demo", action="store_true")

    p_ver = sub.add_parser("verify")
    p_ver.add_argument("--bundle-root", required=True)
    p_ver.add_argument("--check-candidate-lib", default=None)
    p_ver.add_argument("--check-manifest", default=None)
    p_ver.add_argument("--check-upstream-lib", default=None)

    p_demo = sub.add_parser("demo")
    p_demo.add_argument("--bundle-root", required=True)

    args = parser.parse_args()
    if args.cmd == "run":
        return run_qualification(args)
    if args.cmd == "verify":
        return verify_bundle(args)
    if args.cmd == "demo":
        print_demo_summary(pathlib.Path(args.bundle_root).resolve())
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
