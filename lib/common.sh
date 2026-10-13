#!/usr/bin/env bash

HC_WARNINGS=()
HC_DETAILS=()
HC_ERRORS=0
HC_ERROR_MESSAGES=()
HC_WARNING_COUNT=0 HC_CRITICAL_COUNT=0
HC_RESULTS_MESSAGES=0 HC_RESULTS_BYTES=0 HC_RESULTS_TRUNCATED=0
declare -A HC_RESULT_COUNTS=([PASS]=0 [INFO]=0 [WARNING]=0 [CRITICAL]=0 [ERROR]=0)
# Shared retained presentation budget, independent of complete severity counters.
HC_RESULTS_MAX_MESSAGES=1000 HC_RESULTS_MAX_BYTES=3932160
HC_NOT_APPLICABLE=0
HC_DISCOVERY_FAILED=0

# Escape values only at presentation boundaries; classification keeps raw input.
hc_present() {
    local value char escaped octal i
    hc_redact "$1"
    value="$HC_PRESENT_VALUE"
    value="${value//$'\n'/\\n}"
    value="${value//$'\r'/\\r}"
    value="${value//$'\t'/\\t}"
    for ((i=1; i<32; i++)); do
        [ "$i" = 9 ] || [ "$i" = 10 ] || [ "$i" = 13 ] || {
            printf -v octal '%03o' "$i"
            printf -v char '%b' "\\$octal"
            printf -v escaped '\\x%02x' "$i"
            value="${value//"$char"/"$escaped"}"
        }
    done
    value="${value//$'\177'/\\x7f}"
    printf '%s' "$value"
}

hc_warn() {
    hc_status WARNING "$1"
}

# Raw input belongs to immediate check logic. Only redacted presentation leaves
# this function. Longest known secret first prevents overlapping partial leaks.
hc_redact() {
    local value="$1" first="${TELEGRAM_BOT_TOKEN:-}" second="${TELEGRAM_CHAT_ID:-}" swap
    local LC_ALL=C
    if [ "${#second}" -gt "${#first}" ]; then swap="$first"; first="$second"; second="$swap"; fi
    [ -z "$first" ] || value="${value//"$first"/[REDACTED]}"
    [ -z "$second" ] || value="${value//"$second"/[REDACTED]}"
    HC_PRESENT_VALUE="$value"
    return 0
}

# Bound bytes without splitting a valid UTF-8 sequence, under every locale.
hc_presentation_prefix() {
    local LC_ALL=C value="$1" limit="${2:-4096}" index byte width available
    HC_PRESENT_VALUE="$value" HC_PRESENT_TRUNCATED=0
    [ "${#value}" -gt "$limit" ] || return 0
    HC_PRESENT_TRUNCATED=1
    value="${value:0:$limit}"; index=$((limit - 1))
    while [ "$index" -ge "$((limit - 4))" ]; do
        printf -v byte '%d' "'${value:$index:1}"
        [ "$byte" -ge 128 ] && [ "$byte" -le 191 ] || break
        index=$((index - 1))
    done
    width=1
    if [ "$byte" -ge 240 ] && [ "$byte" -le 244 ]; then width=4
    elif [ "$byte" -ge 224 ] && [ "$byte" -le 239 ]; then width=3
    elif [ "$byte" -ge 194 ] && [ "$byte" -le 223 ]; then width=2; fi
    available=$((limit - index))
    [ "$width" -le "$available" ] || value="${value:0:$index}"
    HC_PRESENT_VALUE="$value"
}

hc_detail() { hc_status INFO "$1"; }

hc_status() {
    local level="$1" message bytes LC_ALL=C
    # Record outcome before any presentation omission.
    case "$level" in PASS|INFO|WARNING|CRITICAL|ERROR)
        HC_RESULT_COUNTS[$level]=$(( ${HC_RESULT_COUNTS[$level]} + 1 ));;
    esac
    case "$level" in
        WARNING) HC_WARNING_COUNT=$((HC_WARNING_COUNT + 1));;
        CRITICAL) HC_CRITICAL_COUNT=$((HC_CRITICAL_COUNT + 1));;
        ERROR) HC_ERRORS=$((HC_ERRORS + 1));;
    esac
    hc_redact "$2"
    hc_presentation_prefix "$HC_PRESENT_VALUE"
    [ "$HC_PRESENT_TRUNCATED" = 0 ] || HC_RESULTS_TRUNCATED=1
    [ "${HC_JSON_FILE:-}" = "" ] || hc_json_finding "$level" "$HC_PRESENT_VALUE"
    message="$(hc_present "$HC_PRESENT_VALUE")"
    bytes=$(( ${#level} + ${#message} + 1 ))
    if [ "$HC_RESULTS_MESSAGES" -ge "$HC_RESULTS_MAX_MESSAGES" ] ||
       [ "$((HC_RESULTS_BYTES + bytes))" -gt "$HC_RESULTS_MAX_BYTES" ]; then
        HC_RESULTS_TRUNCATED=1
        return 0
    fi
    HC_RESULTS_MESSAGES=$((HC_RESULTS_MESSAGES + 1))
    HC_RESULTS_BYTES=$((HC_RESULTS_BYTES + bytes))
    printf '  %s %s\n' "$level" "$message"
    case "$level" in
        INFO) HC_DETAILS+=("$message");;
        WARNING|CRITICAL) HC_WARNINGS+=("$level $message");;
        ERROR) HC_ERROR_MESSAGES+=("$level $message");;
    esac
    return 0
}

# Summary construction never joins the entire retained result set. Reserve space
# for a final truncation notice and full critical counter.
hc_summary_append() {
    hc_presentation_prefix "$message$1" 16128
    message="$HC_PRESENT_VALUE"
    [ "$HC_PRESENT_TRUNCATED" = 0 ] || HC_RESULTS_TRUNCATED=1
    return 0
}

# Bound shell processing of already validated snapshots, without spawning a clock.
hc_budget_expired() {
    local start="$1" budget="${SSHC_READ_SECONDS:-20}"
    hc_uint "$budget" && [ "$budget" -gt 0 ] || return 0
    [ "$((SECONDS - start))" -ge "$budget" ]
}

hc_uint() { [[ "$1" =~ ^(0|[1-9][0-9]{0,11})$ ]]; }

hc_duration() {
    printf '%sh %sm' "$(( $1 / 3600 ))" "$(( $1 % 3600 / 60 ))"
}

hc_age_seconds() {
    hc_uint "$1" && [ "$1" -le "$(date +%s)" ] || return 1
    printf '%s\n' "$(( $(date +%s) - $1 ))"
}

# Configuration is data, never shell code. Only documented names may be assigned;
# quotes are delimiters, not instructions to expand variables or run commands.
_hc_load_config_data() {
    local file="$1" line key value rest number=0 contents parse_started=$SECONDS
    contents="$(hc_data_parse bounded "$file" 2>/dev/null)" || { hc_status ERROR "Configuration input UNKNOWN: $file"; return 1; }
    local assignment='^[[:space:]]*([A-Z][A-Z0-9_]*)[[:space:]]*=[[:space:]]*(.*)$'
    while IFS= read -r line || [ -n "$line" ]; do
        if hc_budget_expired "$parse_started"; then hc_status ERROR 'Configuration processing budget exceeded'; return 1; fi
        number=$((number + 1))
        line="${line%$'\r'}"
        [[ "$line" =~ ^[[:space:]]*(#|$) ]] && continue
        [[ "$line" =~ $assignment ]] || { hc_status ERROR "$file:$number: expected KEY=value"; return 1; }
        key="${BASH_REMATCH[1]}" value="${BASH_REMATCH[2]}"
        # Even legacy/manual allowlist additions cannot create an unregistered
        # enabled check. DIRECTADMIN_WEBROOTS is an existing LMD subcheck.
        if [[ "$key" = CHECK_* && "$key" != CHECK_DIRECTADMIN_WEBROOTS ]] && [ -z "${HC_REG_KEY[$key]:-}" ]; then
            hc_status ERROR "$file:$number: unknown configuration key $key (no check registry entry)"
            return 1
        fi
        if [ "$key" = LMD_ENABLED ] && [ "${HC_REG_KEY[CHECK_LMD]:-}" != lmd ]; then
            hc_status ERROR 'LMD_ENABLED compatibility alias lacks its LMD registry entry'
            return 1
        fi
        case "$key" in
            LOOKBACK_HOURS|NOTIFY_TELEGRAM|TELEGRAM_BOT_TOKEN|TELEGRAM_CHAT_ID|\
            APACHE_SERVICE|RSPAMD_SERVICE|PUREFTP_UPLOADSCAN_SERVICE|\
            EXIM_SERVICE|MAILQUEUE_WARN|DISK_WARN_PERCENT|DISK_PATHS|\
            CLAMAV_SERVICE|CLAMAV_CONFIG_FILE|CLAM_SIG_MAX_AGE_HOURS|FRESHCLAM_MAX_AGE_HOURS|\
            FRESHCLAM_SERVICE|FRESHCLAM_TIMER|FRESHCLAM_ONESHOT_SERVICE|\
            LMD_ENABLED|LMD_SERVICE|LMD_BIN|LMD_DIR|LMD_AUDIT|LMD_MONITOR_LIST|LMD_WEBROOT_LIST|\
            LMD_SIG_MAX_AGE_HOURS|LMD_SIGUP_MAX_AGE_HOURS|LMD_UPDATE_FAILURE_LOOKBACK_HOURS|\
            FULLSCAN_MAX_AGE_DAYS|CHECK_DIRECTADMIN_WEBROOTS|DIRECTADMIN_HOME|LMD_MONITOR_REQUIRED|\
            LMD_MONITOR_MAX_IDLE_MINUTES|LMD_MONITOR_PROCESS_PATTERN|LMD_EVENT_LOG|LMD_SESSION_DIR|\
            LMD_FULLSCAN_MAX_AGE_HOURS|LMD_FULLSCAN_MAX_RUNTIME_HOURS|LMD_EXPECTED_FULLSCAN_PATH|\
            LMD_FULLSCAN_RETENTION_MARGIN_HOURS|\
            LMD_PROGRAM_UPDATE_EXPECTED|LMD_EXPECT_QUARANTINE_ENABLED|\
            LMD_CONFIG_CHECK_ENABLED|LMD_CONFIG_FILE|LMD_CRON_CONFIG_FILE|LMD_COMPAT_CONFIG_FILE|\
            LMD_SYSCONFIG_FILE|LMD_DEFAULT_FILE|LMD_DAILY_CRON_FILE|LMD_SIGUP_CRON_FILE|LMD_FULLSCAN_CRON_FILE|\
            LMD_EXPECT_EMAIL_ALERT|LMD_EXPECT_AUTOUPDATE_SIGNATURES|LMD_EXPECT_SIGUP_INTERVAL|\
            LMD_EXPECT_AUTOUPDATE_VERSION|LMD_EXPECT_CRON_AUTOUPDATE_VERSION|LMD_EXPECT_CRON_AUTOUPDATE_SIGNATURES|\
            LMD_EXPECT_SCAN_CLAMSCAN|LMD_EXPECT_SCAN_WORKERS|LMD_EXPECT_QUARANTINE_CLEAN|\
            LMD_EXPECT_QUARANTINE_SUSPEND_USER|LMD_EXPECT_QUARANTINE_ON_ERROR|LMD_EXPECT_MONITOR_MODE|\
            LMD_EXPECT_INOTIFY_SLEEP|LMD_EXPECT_INOTIFY_RELOADTIME|LMD_EXPECT_IMPORT_CONFIG_URL|\
            LMD_EXPECT_POST_SCAN_HOOK|LMD_EXPECT_CRON_PRUNE_DAYS|LMD_EXPECT_SIGUP_SCHEDULE|LMD_EXPECT_FULLSCAN_SCHEDULE) ;;
            *) [ -n "${HC_REG_KEY[$key]:-}" ] || { hc_status ERROR "$file:$number: unknown configuration key $key"; return 1; } ;;
        esac
        if [[ "$value" = \"* || "$value" = \'* ]]; then
            local quote="${value:0:1}"
            value="${value:1}"
            [[ "$value" = *"$quote"* ]] || { hc_status ERROR "$file:$number: unclosed quote"; return 1; }
            rest="${value#*"$quote"}"
            value="${value%%"$quote"*}"
            [[ "$rest" =~ ^[[:space:]]*(#.*)?$ ]] || { hc_status ERROR "$file:$number: unexpected text after quote"; return 1; }
        else
            value="${value%%[[:space:]]#*}"
            value="${value%"${value##*[![:space:]]}"}"
        fi
        # Reject shell constructs explicitly, even though printf -v never executes them.
        [[ "$value" != *'$'* && "$value" != *'`'* && "$value" != *';'* ]] || {
            hc_status ERROR "$file:$number: shell expressions are not supported"; return 1;
        }
        case "$key" in
            LMD_EXPECT_SCAN_WORKERS|LMD_EXPECT_CRON_PRUNE_DAYS) ;; # informational preferences, not enforced
            LMD_EXPECT_EMAIL_ALERT|LMD_EXPECT_AUTOUPDATE_SIGNATURES|LMD_EXPECT_AUTOUPDATE_VERSION|\
            LMD_EXPECT_CRON_AUTOUPDATE_VERSION|LMD_EXPECT_CRON_AUTOUPDATE_SIGNATURES|LMD_EXPECT_QUARANTINE_ENABLED|\
            LMD_EXPECT_QUARANTINE_CLEAN|LMD_EXPECT_QUARANTINE_SUSPEND_USER|LMD_EXPECT_QUARANTINE_ON_ERROR)
                [[ "$value" =~ ^(0|1|ignore)$ ]] || { hc_status ERROR "Invalid $key"; return 1; } ;;
            LMD_EXPECT_SCAN_CLAMSCAN)
                [[ "$value" =~ ^(0|1|auto|ignore)$ ]] || { hc_status ERROR "Invalid $key"; return 1; } ;;
            LMD_EXPECT_SIGUP_INTERVAL|LMD_EXPECT_INOTIFY_SLEEP|LMD_EXPECT_INOTIFY_RELOADTIME)
                if [ "$value" != ignore ]; then
                    hc_uint "$value" && [ "$value" -gt 0 ] || { hc_status ERROR "$key must be positive or ignore"; return 1; }
                fi ;;
            *_HOURS|*_MINUTES|*_DAYS|MAILQUEUE_WARN|DISK_WARN_PERCENT)
                hc_uint "$value" && [ "$value" -gt 0 ] || { hc_status ERROR "$key must be a positive decimal integer"; return 1; } ;;
            NOTIFY_TELEGRAM|LMD_MONITOR_REQUIRED|CHECK_DISK|CHECK_DIRECTADMIN_WEBROOTS|LMD_CONFIG_CHECK_ENABLED) [[ "$value" =~ ^[01]$ ]] || { hc_status ERROR "$key must be 0 or 1"; return 1; } ;;
            CHECK_*|LMD_ENABLED) [[ "$value" =~ ^(0|1|auto)$ ]] || { hc_status ERROR "$key must be 0, 1 or auto"; return 1; } ;;
            LMD_PROGRAM_UPDATE_EXPECTED) [[ "$value" =~ ^(enabled|disabled|ignore)$ ]] || { hc_status ERROR "Invalid $key"; return 1; } ;;
        esac
        printf -v "$key" '%s' "$value"
    done <<< "$contents"
}

# Disable tracing before even reading credential-bearing configuration lines.
hc_load_config() {
    local tracing=0 result
    case $- in *x*) tracing=1; set +x ;; esac
    if hc_registry_load; then _hc_load_config_data "$@"; result=$?; else result=1; fi
    [ "$tracing" = 0 ] || set -x
    return "$result"
}

hc_require_dependencies() {
    local dependency
    for dependency in date stat hostname awk grep sed find sort comm wc mktemp rm head tail cut df; do
        hc_have "$dependency" || hc_status ERROR "Required dependency missing: $dependency"
    done
    [ "$HC_ERRORS" -eq 0 ] || return 1
    date -d '2000-01-01' +%s >/dev/null 2>&1 || {
        hc_status ERROR 'GNU date is required (Linux coreutils)'; return 1;
    }
}

hc_log() {
    printf '%s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$(hc_present "$*")"
}

hc_have() {
    command -v "$1" >/dev/null 2>&1
}

hc_enabled() {
    [ "${1:-0}" = "1" ]
}

# Unit operands are single arguments, never command options. Template names and
# systemd's escaped names remain supported; whitespace/control bytes are invalid.
hc_unit_valid() {
    [[ "$1" =~ ^[a-zA-Z0-9_.:@\\-]+$ ]] && [[ "$1" != -* ]]
}

hc_systemctl() {
    local operation="$1" unit="$2"
    shift 2
    hc_unit_valid "$unit" || return 2
    systemctl "$operation" "$@" -- "$unit"
}

hc_service_active() {
    hc_systemctl is-active "$1" --quiet >/dev/null 2>&1
}

hc_check_service() {
    local unit="$1" label="$2"

    if ! hc_have systemctl; then
        hc_status ERROR "${label}: systemctl is not available"
        return 1
    fi

    if ! hc_service_active "$unit"; then
        hc_warn "${label}: service '${unit}' is not active"
        return 1
    fi
    return 0
}

hc_file_age_hours() {
    local file="$1" now mtime
    now="$(date +%s)"
    mtime="$(stat -c %Y "$file" 2>/dev/null)" || return 1
    hc_uint "$mtime" && [ "$mtime" -le "$now" ] || return 1
    echo $(( (now - mtime) / 3600 ))
}

# Resolve beside this installed common module, never from caller-controlled cwd.
HC_DATA_PARSER="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/checks/health_data.py"
hc_data_parse() {
    hc_have python3 && [ -r "$HC_DATA_PARSER" ] || return 1
    python3 "$HC_DATA_PARSER" "$@"
}

hc_json_event_count_since() {
    local event_type="$1" file="$2" hours="$3" now
    hc_uint "$hours" || return 1
    now="$(date +%s)" || return 1
    hc_uint "$now" || return 1
    hc_data_parse audit "$file" "$event_type" "$hours" "$now" 2>/dev/null
}

hc_register_check() {
    HC_REGISTERED_CHECKS+=("$1")
}

hc_mode() {
    case "${1:-auto}" in
        1) echo on ;;
        0) echo off ;;
        *) echo auto ;;
    esac
}

hc_service_present() {
    local unit="${1%.service}" bin output name state extra
    shift
    for bin in "$@"; do
        hc_have "$bin" && return 0
    done
    if ! hc_have systemctl || ! output="$(hc_systemctl list-unit-files "$unit.service" --no-legend --no-pager 2>/dev/null)"; then
        HC_DISCOVERY_FAILED=$((HC_DISCOVERY_FAILED + 1))
        hc_status ERROR "Discovery failed: $unit"
        return 2
    fi
    if [ -z "$output" ]; then
        HC_NOT_APPLICABLE=$((HC_NOT_APPLICABLE + 1))
        hc_detail "NOT_APPLICABLE: $unit (no service or executable found)"
        return 1
    fi
    while read -r name state extra; do
        if [[ "$name" != "$unit.service" ]] ||
           [[ ! "$state" =~ ^(enabled|disabled|static|masked|indirect|generated|transient|alias|linked|enabled-runtime|linked-runtime|masked-runtime)$ ]] ||
           [[ ! "$extra" =~ ^(enabled|disabled|ignored|-)?$ ]]; then
            HC_DISCOVERY_FAILED=$((HC_DISCOVERY_FAILED + 1))
            hc_status ERROR "Discovery failed: $unit (malformed unit listing)"
            return 2
        fi
    done <<< "$output"
    return 0
}

# extdebug adds definition file/line to declare -F. Preserve the caller's option.
hc_function_from() {
    local function="$1" expected="$2" declaration name line origin debugging=0
    shopt -q extdebug && debugging=1
    shopt -s extdebug
    declaration="$(declare -F "$function")"
    [ "$debugging" = 1 ] || shopt -u extdebug
    read -r name line origin <<< "$declaration"
    [ "$name" = "$function" ] && [ "$origin" = "$expected" ]
}

# Literal registry data: never eval/source it. Installer and runtime share this
# parser, contract loader and generated ownership manifest.
HC_REGISTRY_ROOT="$(cd -P -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
declare -a HC_REG_NAMES=()
declare -A HC_REG_MODULE=() HC_REG_FUNCTION=() HC_REG_KEY=() HC_REG_DEFAULT=() HC_REG_KIND=() HC_REG_DEP=() HC_REG_CONFIG=()
HC_REGISTRY_READY=0
hc_registry_load() {
    [ "$HC_REGISTRY_READY" = 0 ] || return 0
    local LC_ALL=C contents line name module function key default kind dependency extra
    local -A modules=() functions=()
    contents="$(hc_data_parse bounded "$HC_REGISTRY_ROOT/checks.registry")" || {
        hc_status ERROR 'Check registry missing or unreadable'; return 1;
    }
    HC_REG_NAMES=(); HC_REG_KEY=()
    while IFS= read -r line; do
        [[ "$line" = \#* || -z "$line" ]] && continue
        IFS='|' read -r name module function key default kind dependency extra <<< "$line"
        if [[ ! "$line" =~ ^[^\|]+\|[^\|]+\|[^\|]+\|[^\|]+\|[^\|]+\|[^\|]+\|[^\|]+$ ]] ||
           [[ ! "$name" =~ ^[a-z][a-z0-9_]*$ || ! "$module" =~ ^checks/[a-z][a-z0-9_]*\.sh$ ||
              ! "$function" =~ ^[a-zA-Z_][a-zA-Z0-9_]*$ || ! "$kind" =~ ^(builtin|custom|helper)$ ]] ||
           [ "${#name}" -gt 128 ] || [ "${#module}" -gt 255 ] || [ "${#function}" -gt 128 ] ||
           [ "${#key}" -gt 128 ] || [ "${#dependency}" -gt 128 ] ||
           [ -n "${HC_REG_MODULE[$name]:-}" ] || [ -n "${modules[$module]:-}" ] || [ -n "${functions[$function]:-}" ]; then
            hc_status ERROR "Invalid or duplicate check registry entry: $line"; return 1
        fi
        if [ "$kind" = helper ]; then
            [ "$key:$default:$dependency" = '-:-:-' ] || { hc_status ERROR 'Invalid helper registry entry'; return 1; }
        elif [[ ! "$key" =~ ^CHECK_[A-Z][A-Z0-9_]*$ || ! "$default" =~ ^(0|1|auto)$ ]] ||
             [ "$key" = CHECK_DIRECTADMIN_WEBROOTS ] || [ -n "${HC_REG_KEY[$key]:-}" ] ||
             { [ "$dependency" != - ] && [ "${HC_REG_KIND[$dependency]:-}" != helper ]; }; then
            hc_status ERROR "Invalid registry config/dependency: $name"; return 1
        else
            HC_REG_KEY[$key]="$name"
        fi
        HC_REG_NAMES+=("$name"); modules[$module]=1; functions[$function]=1
        HC_REG_MODULE[$name]="$module"; HC_REG_FUNCTION[$name]="$function"
        HC_REG_CONFIG[$name]="$key"; HC_REG_DEFAULT[$name]="$default"; HC_REG_KIND[$name]="$kind"; HC_REG_DEP[$name]="$dependency"
    done <<< "$contents"
    [ "${#HC_REG_NAMES[@]}" -gt 0 ] || { hc_status ERROR 'Empty check registry'; return 1; }
    HC_REGISTRY_READY=1
}

hc_registry_module_load() {
    local name="$1" module="$2/${HC_REG_MODULE[$1]}" function="${HC_REG_FUNCTION[$1]}"
    local start=${#HC_REGISTERED_CHECKS[@]} status source_failed=0
    if [ ! -f "$module" ]; then hc_status ERROR "Required check module missing: $module"; return 1; fi
    if [ ! -r "$module" ]; then hc_status ERROR "Check module unreadable: $module"; return 1; fi
    bash -n "$module" || { hc_status ERROR "Check module syntax error: $module"; return 1; }
    unset -f "$function"
    # A failing dependency source followed by a successful registration must not
    # mask failure. Called outside conditionals so ERR observes those failures.
    set -E
    trap 'source_failed=1' ERR
    source "$module"
    status=$?
    trap - ERR
    set +E
    if [ "$status" != 0 ] || [ "$source_failed" != 0 ]; then
        hc_status ERROR "Check module source failed: $module"; return 1
    fi
    if ! hc_function_from "$function" "$module"; then
        hc_status ERROR "Check module function missing or unexpected provenance; not registered: $name"
        [ "$name" != lmd_policy ] || hc_status ERROR 'LMD policy module function missing'
        return 1
    fi
    if [ "${HC_REG_KIND[$name]}" = helper ]; then
        [ "${#HC_REGISTERED_CHECKS[@]}" = "$start" ] || { hc_status ERROR "Unexpected helper registration: $name"; return 1; }
    elif [ "${#HC_REGISTERED_CHECKS[@]}" != "$((start + 1))" ] || [ "${HC_REGISTERED_CHECKS[$start]:-}" != "$name" ]; then
        hc_status ERROR "Check module not registered with expected name: $name"; return 1
    fi
    return 0
}

hc_runtime_manifest() {
    local root="$1" contents relative name
    local -A owned=()
    contents="$(hc_data_parse bounded "$root/runtime.manifest")" || { hc_status ERROR 'Runtime manifest unavailable'; return 1; }
    while IFS= read -r relative; do
        [[ "$relative" =~ ^(common\.sh|output\.sh|checks\.registry|checks/[a-z_]+\.py|notify/[a-z_]+\.sh)$ ]] &&
        [ -z "${owned[$relative]:-}" ] || { hc_status ERROR 'Invalid or duplicated runtime manifest'; return 1; }
        owned[$relative]=1
        printf '%s\n' "$relative"
    done <<< "$contents"
    [ "${owned[common.sh]:-0}" = 1 ] && [ "${owned[checks.registry]:-0}" = 1 ] || {
        hc_status ERROR 'Runtime manifest lacks common/registry'; return 1;
    }
    for name in "${HC_REG_NAMES[@]}"; do printf '%s\n' "${HC_REG_MODULE[$name]}"; done
}

# Output helpers share one functional contract between staging and JSON startup.
HC_OUTPUT_FUNCTIONS=(hc_json_init hc_json_record hc_json_utf8_prefix hc_json_finding hc_json_clock hc_json_finish)
hc_output_contract() {
    local root="$1" function
    for function in "${HC_OUTPUT_FUNCTIONS[@]}"; do
        hc_function_from "$function" "$root/output.sh" || {
            if [ "${2:-}" = quiet ]; then
                printf '%s\n' "ERROR output helper function missing or unexpected provenance: $function" >&2
            else hc_status ERROR "Output helper function missing or unexpected provenance: $function"; fi
            return 1;
        }
    done
}
hc_output_load() {
    local root="$1" function status failed=0 response
    for function in output.sh checks/output.py; do
        [ -f "$root/$function" ] && [ -r "$root/$function" ] || {
            hc_status ERROR "Output helper missing or unreadable: $function"; return 1;
        }
    done
    bash -n "$root/output.sh" || { hc_status ERROR 'Output helper syntax failed'; return 1; }
    for function in "${HC_OUTPUT_FUNCTIONS[@]}"; do unset -f "$function"; done
    # Validate source completion in a child first: exit/errexit/nounset cannot
    # bypass the parent's explicit ERROR/2 bootstrap boundary.
    response="$(
        HC_JSON_FILE=''
        failed=0
        set -E
        trap 'failed=1' ERR
        source "$root/output.sh"
        status=$?
        trap - ERR
        set +E
        [ "$status" = 0 ] && [ "$failed" = 0 ] || exit 1
        hc_output_contract "$root" quiet || exit 1
        printf '%s' SSHC_OUTPUT_SOURCE_COMPLETE
    )"
    status=$?
    [ "$status" = 0 ] && [ "$response" = SSHC_OUTPUT_SOURCE_COMPLETE ] || {
        hc_status ERROR 'Output helper source/contract validation failed'; return 1;
    }
    set -E
    trap 'failed=1' ERR
    source "$root/output.sh"
    status=$?
    trap - ERR
    set +E
    [ "$status" = 0 ] && [ "$failed" = 0 ] || { hc_status ERROR 'Output helper source failed'; return 1; }
    hc_output_contract "$root" || return 1
    python3 - "$root/checks/output.py" <<'PY_CONTRACT'
import ast, sys
with open(sys.argv[1], 'rb') as stream:
    tree = ast.parse(stream.read(), filename=sys.argv[1])
required = {'clock', 'duration', 'render', 'verify', 'validate', 'main'}
assert required.issubset({n.name for n in tree.body if isinstance(n, ast.FunctionDef)}), 'Incomplete Python output helper'
PY_CONTRACT
    status=$?
    [ "$status" = 0 ] || { hc_status ERROR 'Python output helper contract failed'; return 1; }
    response="$(python3 "$root/checks/output.py" self-test)"
    status=$?
    [ "$status" = 0 ] && [ "$response" = SSHC_JSON_SCHEMA_1 ] || {
        hc_status ERROR 'Python output helper self-test failed'; return 1;
    }
}

hc_output_runtime_guard() {
    hc_output_contract "$LIB_DIR" quiet && return 0
    trap - EXIT
    rm -f -- "$HC_JSON_FILE" "$HC_JSON_RENDERED"
    rmdir -- "$HC_JSON_DIR"
    exit 2
}
