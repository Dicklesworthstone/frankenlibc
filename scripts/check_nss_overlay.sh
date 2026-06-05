#!/bin/bash
# bd-gq1kz7.15: NSS unsupported overlay exhaustiveness checker
# Verifies all NSS-related symbols have explicit support or unsupported-overlay semantics.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
MATRIX="$PROJECT_ROOT/support_matrix.json"

if [[ ! -f "$MATRIX" ]]; then
    echo '{"status":"error","message":"support_matrix.json not found"}'
    exit 1
fi

# NSS service families and their expected behavior
# These are the public API functions that use NSS backends
NSS_FAMILIES=(
    # passwd/shadow/group
    "getpwnam:files"
    "getpwuid:files"
    "getpwent:files"
    "getspnam:files"
    "getspent:files"
    "getgrnam:files"
    "getgrgid:files"
    "getgrent:files"
    # hosts
    "gethostbyname:files,dns"
    "gethostbyaddr:files,dns"
    "gethostent:files"
    # services
    "getservbyname:files"
    "getservbyport:files"
    "getservent:files"
    # protocols
    "getprotobyname:files"
    "getprotobynumber:files"
    "getprotoent:files"
    # networks
    "getnetbyname:files"
    "getnetbyaddr:files"
    "getnetent:files"
    # aliases
    "getaliasbyname:files"
    "getaliasent:files"
    # netgroup
    "getnetgrent:files"
    "setnetgrent:files"
    "endnetgrent:files"
)

# NSS backends that are NOT supported (plugin-based)
UNSUPPORTED_BACKENDS=(
    "ldap"
    "nis"
    "nisplus"
    "compat"
    "hesiod"
    "db"
    "winbind"
    "systemd"
    "sss"      # SSSD
    "extrausers"
)

is_accepted_nss_status() {
    case "$1" in
        Implemented | RawSyscall | WrapsHostLibc)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

json_array_from_lines() {
    if [[ $# -eq 0 ]]; then
        echo "[]"
    else
        printf '%s\n' "$@" | jq -R . | jq -s .
    fi
}

generate_report() {
    local timestamp
    timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)

    # Check each NSS family function
    local implemented=()
    local missing=()
    local wrong_status=()

    for family in "${NSS_FAMILIES[@]}"; do
        local func="${family%%:*}"
        local backends="${family##*:}"

        # Check base function
        local status
        status=$(jq -r --arg f "$func" '.symbols[] | select(.symbol == $f) | .status' "$MATRIX" 2>/dev/null || echo "MISSING")

        if is_accepted_nss_status "$status"; then
            implemented+=("$func")
        elif [[ "$status" == "MISSING" || -z "$status" ]]; then
            missing+=("$func")
        else
            wrong_status+=("$func:$status")
        fi

        # Check _r variant
        local func_r="${func}_r"
        status=$(jq -r --arg f "$func_r" '.symbols[] | select(.symbol == $f) | .status' "$MATRIX" 2>/dev/null || echo "MISSING")

        if is_accepted_nss_status "$status"; then
            implemented+=("$func_r")
        elif [[ "$status" == "MISSING" || -z "$status" ]]; then
            # _r variants are optional for some functions
            :
        else
            wrong_status+=("$func_r:$status")
        fi
    done

    # Build JSON arrays
    local impl_json
    impl_json=$(json_array_from_lines "${implemented[@]}")
    local miss_json
    miss_json=$(json_array_from_lines "${missing[@]}")
    local wrong_json
    wrong_json=$(json_array_from_lines "${wrong_status[@]}")
    local unsup_json
    unsup_json=$(printf '%s\n' "${UNSUPPORTED_BACKENDS[@]}" | jq -R . | jq -s .)

    local pass="true"
    if [[ ${#missing[@]} -gt 0 ]] || [[ ${#wrong_status[@]} -gt 0 ]]; then
        pass="false"
    fi

    cat <<EOF
{
  "status": "$([ "$pass" = "true" ] && echo "pass" || echo "fail")",
  "timestamp": "$timestamp",
  "gate": "bd-gq1kz7.15",
  "summary": {
    "nss_families_checked": ${#NSS_FAMILIES[@]},
    "implemented": ${#implemented[@]},
    "missing": ${#missing[@]},
    "wrong_status": ${#wrong_status[@]}
  },
  "nss_overlay_policy": {
    "files_backend": "supported",
    "dns_backend": "supported",
    "unsupported_backends": $unsup_json,
    "unsupported_reason": "NSS plugin model requires host glibc; standalone mode uses direct /etc file parsing"
  },
  "implemented_functions": $impl_json,
  "missing_functions": $miss_json,
  "wrong_status_functions": $wrong_json
}
EOF
}

generate_report | jq .
