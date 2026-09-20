#!/usr/bin/env bash

HC_WARNINGS=()
HC_DETAILS=()
HC_ERRORS=0

hc_warn() {
    hc_status WARNING "$1"
}

hc_detail() {
    HC_DETAILS+=("$1")
    printf '  INFO %s\n' "$1"
}

hc_status() {
    local level="$1" message="$2"
    printf '  %s %s\n' "$level" "$message"
    case "$level" in
        WARNING|CRITICAL) HC_WARNINGS+=("$level $message") ;;
        ERROR) HC_ERRORS=$((HC_ERRORS + 1)) ;;
    esac
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
hc_load_config() {
    local file="$1" line key value rest number=0
    local assignment='^[[:space:]]*([A-Z][A-Z0-9_]*)[[:space:]]*=[[:space:]]*(.*)$'
    while IFS= read -r line || [ -n "$line" ]; do
        number=$((number + 1))
        line="${line%$'\r'}"
        [[ "$line" =~ ^[[:space:]]*(#|$) ]] && continue
        [[ "$line" =~ $assignment ]] || { hc_status ERROR "$file:$number: expected KEY=value"; return 1; }
        key="${BASH_REMATCH[1]}" value="${BASH_REMATCH[2]}"
        case "$key" in
            LOOKBACK_HOURS|NOTIFY_TELEGRAM|TELEGRAM_BOT_TOKEN|TELEGRAM_CHAT_ID|\
            CHECK_APACHE|APACHE_SERVICE|CHECK_RSPAMD|RSPAMD_SERVICE|CHECK_PUREFTP|PUREFTP_UPLOADSCAN_SERVICE|\
            CHECK_EXIM|EXIM_SERVICE|MAILQUEUE_WARN|CHECK_DISK|DISK_WARN_PERCENT|DISK_PATHS|\
            CHECK_CLAMAV|CLAMAV_SERVICE|CLAM_SIG_MAX_AGE_HOURS|FRESHCLAM_MAX_AGE_HOURS|\
            FRESHCLAM_SERVICE|FRESHCLAM_TIMER|FRESHCLAM_ONESHOT_SERVICE|\
            CHECK_LMD|LMD_ENABLED|LMD_SERVICE|LMD_BIN|LMD_DIR|LMD_AUDIT|LMD_MONITOR_LIST|LMD_WEBROOT_LIST|\
            LMD_SIG_MAX_AGE_HOURS|LMD_SIGUP_MAX_AGE_HOURS|LMD_UPDATE_FAILURE_LOOKBACK_HOURS|\
            FULLSCAN_MAX_AGE_DAYS|CHECK_DIRECTADMIN_WEBROOTS|DIRECTADMIN_HOME|LMD_MONITOR_REQUIRED|\
            LMD_MONITOR_MAX_IDLE_MINUTES|LMD_MONITOR_PROCESS_PATTERN|LMD_EVENT_LOG|LMD_SESSION_DIR|\
            LMD_FULLSCAN_MAX_AGE_HOURS|LMD_FULLSCAN_MAX_RUNTIME_HOURS|LMD_EXPECTED_FULLSCAN_PATH|\
            LMD_PROGRAM_UPDATE_EXPECTED|LMD_EXPECT_QUARANTINE_ENABLED) ;;
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
            *_HOURS|*_MINUTES|*_DAYS|MAILQUEUE_WARN|DISK_WARN_PERCENT)
                hc_uint "$value" && [ "$value" -gt 0 ] || { hc_status ERROR "$key must be a positive decimal integer"; return 1; } ;;
            NOTIFY_TELEGRAM|LMD_MONITOR_REQUIRED|CHECK_DISK|CHECK_DIRECTADMIN_WEBROOTS) [[ "$value" =~ ^[01]$ ]] || { hc_status ERROR "$key must be 0 or 1"; return 1; } ;;
            CHECK_*|LMD_ENABLED) [[ "$value" =~ ^(0|1|auto)$ ]] || { hc_status ERROR "$key must be 0, 1 or auto"; return 1; } ;;
            LMD_PROGRAM_UPDATE_EXPECTED) [[ "$value" =~ ^(enabled|disabled|ignore)$ ]] || { hc_status ERROR "Invalid $key"; return 1; } ;;
            LMD_EXPECT_QUARANTINE_ENABLED) [[ "$value" =~ ^(0|1|ignore)$ ]] || { hc_status ERROR "Invalid $key"; return 1; } ;;
        esac
        printf -v "$key" '%s' "$value"
    done < "$file"
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
    printf '%s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"
}

hc_have() {
    command -v "$1" >/dev/null 2>&1
}

hc_enabled() {
    [ "${1:-0}" = "1" ]
}

hc_service_active() {
    systemctl is-active --quiet "$1"
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

hc_json_event_count_since() {
    local event_type="$1" file="$2" hours="$3"
    local now since line ts ts_epoch count=0

    [ -f "$file" ] || {
        echo 0
        return
    }

    now="$(date +%s)"
    since="$((now - hours * 3600))"

    while IFS= read -r line; do
        ts="$(printf '%s\n' "$line" | sed -n 's/.*"ts"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
        [ -n "$ts" ] || continue
        ts_epoch="$(date -d "$ts" +%s 2>/dev/null || echo 0)"
        [ "$ts_epoch" -ge "$since" ] && count=$((count + 1))
    done < <(grep -E "\"type\"[[:space:]]*:[[:space:]]*\"${event_type}\"" "$file" 2>/dev/null || true)

    echo "$count"
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
    local unit="$1" bin
    shift

    if hc_have systemctl && systemctl cat "$unit" >/dev/null 2>&1; then
        return 0
    fi

    for bin in "$@"; do
        hc_have "$bin" && return 0
    done

    return 1
}
