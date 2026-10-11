#!/usr/bin/env bash

HC_WARNINGS=()
HC_DETAILS=()
HC_ERRORS=0
HC_ERROR_MESSAGES=()
HC_NOT_APPLICABLE=0
HC_DISCOVERY_FAILED=0

# Escape values only at presentation boundaries; classification keeps raw input.
hc_present() {
    local value="$1" char escaped octal i
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

hc_detail() {
    local message
    message="$(hc_present "$1")"
    HC_DETAILS+=("$message")
    printf '  INFO %s\n' "$message"
}

hc_status() {
    local level="$1" message
    message="$(hc_present "$2")"
    printf '  %s %s\n' "$level" "$message"
    case "$level" in
        WARNING|CRITICAL) HC_WARNINGS+=("$level $message") ;;
        ERROR)
            HC_ERRORS=$((HC_ERRORS + 1))
            HC_ERROR_MESSAGES+=("$level $message")
            ;;
    esac
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
        case "$key" in
            LOOKBACK_HOURS|NOTIFY_TELEGRAM|TELEGRAM_BOT_TOKEN|TELEGRAM_CHAT_ID|\
            CHECK_APACHE|APACHE_SERVICE|CHECK_RSPAMD|RSPAMD_SERVICE|CHECK_PUREFTP|PUREFTP_UPLOADSCAN_SERVICE|\
            CHECK_EXIM|EXIM_SERVICE|MAILQUEUE_WARN|CHECK_DISK|DISK_WARN_PERCENT|DISK_PATHS|\
            CHECK_CLAMAV|CLAMAV_SERVICE|CLAMAV_CONFIG_FILE|CLAM_SIG_MAX_AGE_HOURS|FRESHCLAM_MAX_AGE_HOURS|\
            FRESHCLAM_SERVICE|FRESHCLAM_TIMER|FRESHCLAM_ONESHOT_SERVICE|\
            CHECK_LMD|LMD_ENABLED|LMD_SERVICE|LMD_BIN|LMD_DIR|LMD_AUDIT|LMD_MONITOR_LIST|LMD_WEBROOT_LIST|\
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
            *) hc_status ERROR "$file:$number: unknown configuration key $key"; return 1 ;;
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
    _hc_load_config_data "$@"; result=$?
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

hc_service_active() {
    systemctl is-active --quiet -- "$1" >/dev/null 2>&1
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
    if ! hc_have systemctl || ! output="$(systemctl list-unit-files "$unit.service" --no-legend --no-pager 2>/dev/null)"; then
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
