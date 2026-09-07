#!/usr/bin/env bash

HC_WARNINGS=()
HC_DETAILS=()

hc_warn() {
    HC_WARNINGS+=("$1")
}

hc_detail() {
    HC_DETAILS+=("$1")
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
        hc_warn "${label}: systemctl is not available"
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
        ts="$(printf '%s\n' "$line" | sed -n 's/.*"ts":"\([^"]*\)".*/\1/p')"
        [ -n "$ts" ] || continue
        ts_epoch="$(date -d "$ts" +%s 2>/dev/null || echo 0)"
        [ "$ts_epoch" -ge "$since" ] && count=$((count + 1))
    done < <(grep -F "\"type\":\"${event_type}\"" "$file" 2>/dev/null || true)

    echo "$count"
}

hc_register_check() {
    HC_REGISTERED_CHECKS+=("$1")
}
