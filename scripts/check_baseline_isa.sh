#!/usr/bin/env bash
# check_baseline_isa.sh — the shipped libfrankenlibc_abi.so runs on baseline
# x86-64 (bd-rc0923-epic-eeuy4f.13).
#
# The release artifact is built for baseline x86-64 and reaches SSE4.x/AVX/AVX2/
# FMA/AVX-512 code only through run-time CPU dispatch. Two ways that breaks, two
# checks:
#
#   1. STATIC: every function in the .so that contains an instruction beyond
#      baseline x86-64 must be one of the dispatch-guarded kernels named in
#      ALLOWED below (a `#[target_feature]` function, an AVX2+FMA math twin, or
#      CPU detection itself). A new one fails here until it is reviewed and
#      listed -- an unguarded `vzeroupper` in memcpy is how this started.
#   2. DYNAMIC: the C fixture suite (scripts/c_fixture_suite.sh, strict and
#      hardened) and a few real programs run under qemu-user on CPU models
#      without those extensions, where any such instruction is SIGILL. This
#      catches a guarded kernel whose CALLER forgot the guard, which (1) cannot.
#
# With V3_LIB pointing at a `--profile release-x86-64-v3` build, also checks
# that such a build refuses to start on a pre-AVX2 CPU with its message and
# exit 127, and runs on an AVX2 one.
#
# Consumer: the `release-builds` job in .github/workflows/ci.yml, after it
# builds the release artifact.
#
# Env: LIB (default target/release/libfrankenlibc_abi.so), QEMU (default
# qemu-x86_64; must be statically linked), QEMU_CPUS (default "Nehalem qemu64",
# x86-64-v2 without AVX, and plain x86-64), V3_LIB (optional), TIMEOUT_SECONDS.
#
# Exit codes: 0 pass, 1 check failed, 2 setup error.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIB="${LIB:-${CARGO_TARGET_DIR:-${ROOT}/target}/release/libfrankenlibc_abi.so}"
QEMU="${QEMU:-qemu-x86_64}"
QEMU_CPUS="${QEMU_CPUS-Nehalem qemu64}"
V3_LIB="${V3_LIB:-}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-300}"

for tool in objdump readelf python3 "${QEMU}"; do
  if ! command -v "${tool}" >/dev/null 2>&1; then
    echo "check_baseline_isa: required tool '${tool}' not found" >&2
    exit 2
  fi
done
if [[ ! -f "${LIB}" ]]; then
  echo "check_baseline_isa: ${LIB} not found (cargo build -p frankenlibc-abi --release)" >&2
  exit 2
fi
# LD_PRELOAD is set on the emulator's command line and must reach only the
# guest: a dynamically linked emulator would preload the library into itself,
# natively, and the check would prove nothing.
if readelf -l "$(command -v "${QEMU}")" 2>/dev/null | grep -q 'INTERP'; then
  echo "check_baseline_isa: ${QEMU} is dynamically linked; use a static build (qemu-user-static)" >&2
  exit 2
fi

failures=0
echo "=== Baseline x86-64 ISA gate (bd-rc0923-epic-eeuy4f.13) ==="
echo "lib=${LIB}"
echo "sha256=$(sha256sum "${LIB}" | cut -d' ' -f1)"
echo ""

work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

echo "--- Check 1: non-baseline instructions only in dispatch-guarded functions ---"
objdump -d -C -M intel --no-show-raw-insn "${LIB}" > "${work}/lib.dis"
if ! python3 - "${work}/lib.dis" <<'PY'
import re
import sys

# Mnemonics beyond baseline x86-64 (SSE2), by extension. Anything VEX/EVEX
# encoded (AVX, AVX2, FMA, F16C, AVX-512) starts with "v" or is an opmask "k"
# instruction. `tzcnt` is deliberately absent: LLVM emits its encoding
# (`rep bsf`) in baseline code only where the operand is non-zero, and older
# CPUs execute it as `bsf` with the same result.
EXT = {
    "sse3": "addsubpd addsubps haddpd haddps hsubpd hsubps lddqu movddup movshdup movsldup fisttp",
    "ssse3": "pabsb pabsw pabsd palignr phaddw phaddd phaddsw phsubw phsubd phsubsw pmaddubsw pmulhrsw pshufb psignb psignw psignd",
    "sse4.1": "blendpd blendps blendvpd blendvps dppd dpps extractps insertps movntdqa mpsadbw packusdw pblendvb pblendw pcmpeqq pextrb pextrd pextrq phminposuw pinsrb pinsrd pinsrq pmaxsb pmaxsd pmaxud pmaxuw pminsb pminsd pminud pminuw pmovsxbw pmovsxbd pmovsxbq pmovsxwd pmovsxwq pmovsxdq pmovzxbw pmovzxbd pmovzxbq pmovzxwd pmovzxwq pmovzxdq pmuldq pmulld ptest roundpd roundps roundsd roundss",
    "sse4.2": "crc32 pcmpestri pcmpestrm pcmpistri pcmpistrm pcmpgtq",
    "popcnt": "popcnt",
    "lzcnt": "lzcnt",
    "bmi": "andn bextr blsi blsmsk blsr bzhi mulx pdep pext rorx sarx shlx shrx",
    "movbe": "movbe",
    "cx16": "cmpxchg16b",
    "rtm": "xbegin xend xabort xtest",
    "xsave": "xgetbv xsave xsave64 xsavec xsavec64 xsaveopt xsaveopt64 xsaves xsaves64 xrstor xrstor64 xrstors xrstors64",
    "adx": "adcx adox",
    "aes": "aesenc aesenclast aesdec aesdeclast aesimc aeskeygenassist pclmulqdq",
    "sha": "sha1rnds4 sha1nexte sha1msg1 sha1msg2 sha256rnds2 sha256msg1 sha256msg2",
    "rdrand": "rdrand rdseed",
    "pku": "rdpkru wrpkru",
}
MNEMONIC = {m: ext for ext, ms in EXT.items() for m in ms.split()}

# Functions allowed to contain them: each is reached only after a run-time
# CPUID check. Patterns match the demangled name without its hash.
ALLOWED = [
    # string_abi #[target_feature] kernels; callers check the CPU first.
    r"frankenlibc_abi::string_abi::(copy_unaligned_64|raw_avx512_copy|raw_avx512_copy_backward"
    r"|raw_avx_copy|raw_avx_copy_backward|raw_avx_copy_backward_disjoint|raw_avx_copy_forward"
    r"|raw_avx_memset|memcmp_avx2|scan_c_string_for_byte_avx2|scan_c_string_pshufb"
    r"|span_probe_cmpistri|span_probe_wide|span_probe_scan_bank)\b",
    # Kernels compiled a second time with AVX2(+FMA): avx2_fma_dispatch! (core
    # math) and avx2_dispatch! / scan_strcmp (string_abi).
    r"::avx2(_fma)?_twin(::<[^>]*>)?$",
    # fma/fmaf: the instruction behind is_x86_feature_detected!("fma").
    r"math_abi::hardware_fmaf?::fused$",
    # HTM fast path: RTM behind is_x86_feature_detected!("rtm").
    r"frankenlibc_abi::htm_fast_path::",
    # CPU detection itself (std_detect, the hwcaps classifier, cpu guard).
    r"std_detect::detect::",
    r"hwcaps::detect\b",
    r"^__frankenlibc_cpu_guard_resolve$",
    # TLS descriptor trampoline (asm): xgetbv/xsave only after CPUID reports
    # XSAVE+OSXSAVE, fxsave otherwise.
    r"^frankenlibc_native_tlsdesc$",
    # Out-of-line core::arch intrinsics, called only from the kernels above.
    r"^core::core_arch::x86(_64)?::",
    # Dependencies with their own CPUID dispatch: libm's fma, sha2 (cpufeatures).
    r"^libm::math::arch::x86::fma::",
    r"^sha2::sha(256|512)::x86_",
    # pkey_get/pkey_set: RDPKRU/WRPKRU only after the arguments validate, the
    # order glibc uses; a valid-key call faults without OSPKE under glibc too
    # (unistd_abi.rs, `pkey_arg_is_valid`). Not a dispatch: the caller asked.
    r"^pkey_(get|set)$",
]
allowed = [re.compile(p) for p in ALLOWED]

func = None
hits = {}
header = re.compile(r"^[0-9a-f]+ <(.+)>:$")
insn = re.compile(r"^\s+[0-9a-f]+:\s+(?:(?:lock|rep|repe|repne|notrack|bnd|data16|cs|ds|ss|es|fs|gs)\s+)*([a-z0-9]+)\b")
for line in open(sys.argv[1], encoding="utf-8", errors="replace"):
    m = header.match(line)
    if m:
        func = re.sub(r"::h[0-9a-f]{16}$", "", m.group(1))
        func = re.sub(r"\.(?:cold|llvm\.\d+)(?:\.\d+)?$", "", func)
        continue
    m = insn.match(line)
    if not m or func is None:
        continue
    mn = m.group(1)
    ext = MNEMONIC.get(mn)
    if ext is None and (mn.startswith("v") and mn not in ("verr", "verw")):
        ext = "avx"
    if ext is None and re.match(r"^k(mov|and|or|xor|not|shift|test|unpck|add)", mn):
        ext = "avx512"
    if ext:
        hits.setdefault(func, {}).setdefault(ext, 0)
        hits[func][ext] += 1

bad = 0
for func in sorted(hits):
    ok = any(p.search(func) for p in allowed)
    exts = ",".join(f"{e}x{n}" for e, n in sorted(hits[func].items()))
    tag = "ok  " if ok else "FAIL"
    print(f"{tag} {func} [{exts}]")
    bad += 0 if ok else 1
print(f"functions_with_extensions={len(hits)} unlisted={bad}")
sys.exit(1 if bad else 0)
PY
then
  echo "FAIL: a function outside the dispatch allow-list uses non-baseline instructions"
  failures=$((failures + 1))
else
  echo "PASS: every non-baseline instruction is inside a dispatch-guarded function"
fi
echo ""

echo "--- Check 2: runs on CPUs without the extensions (qemu-user) ---"
corpus_dir="${work}"
printf 'pear\napple\nfig\n' > "${corpus_dir}/sort.in"

# Runs the C fixture suite against LIB, natively or under a runner, and prints
# the path of its results.json.
run_fixture_suite() {
  local label="$1" runner="$2" log="${corpus_dir}/fixtures-$1.log"
  FRANKENLIBC_LIB="${LIB}" FIXTURE_RUNNER="${runner}" TIMEOUT_SECONDS="${TIMEOUT_SECONDS}" \
    bash "${ROOT}/scripts/c_fixture_suite.sh" > "${log}" 2>&1 || true
  local run_dir
  run_dir="$(sed -n 's/^run_dir=//p' "${log}")"
  if [[ -z "${run_dir}" || ! -f "${run_dir}/results.json" ]]; then
    echo "check_baseline_isa: c_fixture_suite.sh (${label}) produced no results" >&2
    tail -n 20 "${log}" >&2
    exit 2
  fi
  echo "${run_dir}/results.json"
}

# An emulated CPU must change no fixture outcome. Each fixture/mode exit code
# is compared with a native run of the same suite against the same library: a
# fixture that already fails natively is listed, not hidden, and fails this gate
# only if the emulated CPU changes how it ends (an ISA fault is rc 132).
native_results="$(run_fixture_suite native "")"
for cpu in ${QEMU_CPUS}; do
  echo "[cpu=${cpu}] C fixture suite vs native"
  cpu_results="$(run_fixture_suite "${cpu}" "${QEMU} -cpu ${cpu}")"
  if python3 - "${native_results}" "${cpu_results}" "${cpu}" <<'PY'
import json
import sys

def outcomes(path):
    report = json.load(open(path, encoding="utf-8"))
    return {(f["name"], f["mode"]): f["exit_code"] for f in report["fixtures"]}

native, emulated, cpu = outcomes(sys.argv[1]), outcomes(sys.argv[2]), sys.argv[3]
changed = 0
for key in sorted(native.keys() | emulated.keys()):
    want, got = native.get(key), emulated.get(key)
    if want != got:
        changed += 1
        print(f"  CHANGED {key[0]} mode={key[1]}: native rc={want} cpu={cpu} rc={got}")
    elif want != 0:
        print(f"  note: {key[0]} mode={key[1]} rc={want} natively too (not an ISA failure)")
print(f"  runs={len(emulated)} unchanged={len(emulated) - changed} changed={changed}")
sys.exit(1 if changed else 0)
PY
  then
    echo "PASS: cpu=${cpu} every fixture ends as it does natively"
  else
    echo "FAIL: cpu=${cpu} fixture outcomes differ from native"
    failures=$((failures + 1))
  fi
  for cmd in "/bin/echo baseline-isa" "/bin/ls -la /" "/usr/bin/sort ${corpus_dir}/sort.in" \
      "/usr/bin/python3 -c print(sum(range(100)))"; do
    read -r -a argv <<< "${cmd}"
    [[ -x "${argv[0]}" ]] || continue
    for mode in strict hardened; do
      set +e
      timeout "${TIMEOUT_SECONDS}" env FRANKENLIBC_MODE="${mode}" LD_PRELOAD="${LIB}" \
        "${QEMU}" -cpu "${cpu}" "${argv[@]}" > /dev/null 2> "${corpus_dir}/stderr"
      rc=$?
      set -e
      if [[ "${rc}" -ne 0 ]]; then
        echo "FAIL: cpu=${cpu} mode=${mode} rc=${rc}: ${cmd}"
        head -n 5 "${corpus_dir}/stderr"
        failures=$((failures + 1))
      fi
    done
  done
done
echo ""

if [[ -n "${V3_LIB}" ]]; then
  echo "--- Check 3: an x86-64-v3 build refuses pre-AVX2 CPUs instead of SIGILL ---"
  set +e
  env LD_PRELOAD="${V3_LIB}" "${QEMU}" -cpu Nehalem /bin/true 2> "${corpus_dir}/v3.stderr"
  rc=$?
  env LD_PRELOAD="${V3_LIB}" "${QEMU}" -cpu Haswell /bin/echo ok > /dev/null 2>&1
  rc_v3=$?
  set -e
  if [[ "${rc}" -eq 127 ]] && grep -q 'frankenlibc: this libfrankenlibc_abi.so was compiled for x86-64 extensions' "${corpus_dir}/v3.stderr"; then
    echo "PASS: Nehalem rc=127: $(head -c 200 "${corpus_dir}/v3.stderr")"
  else
    echo "FAIL: Nehalem rc=${rc} (want 127 and the refusal message): $(head -c 200 "${corpus_dir}/v3.stderr")"
    failures=$((failures + 1))
  fi
  if [[ "${rc_v3}" -eq 0 ]]; then
    echo "PASS: Haswell rc=0"
  else
    echo "FAIL: Haswell rc=${rc_v3}"
    failures=$((failures + 1))
  fi
  echo ""
fi

if [[ "${failures}" -gt 0 ]]; then
  echo "check_baseline_isa: FAILED (${failures})"
  exit 1
fi
echo "check_baseline_isa: PASS"
