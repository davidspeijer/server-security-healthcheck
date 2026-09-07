#!/usr/bin/env bash
hc_register_check lmd

_lmd_check_service() {
    hc_check_service "${LMD_SERVICE:-maldet}" "LMD" || true

    if hc_service_active "${LMD_SERVICE:-maldet}" 2>/dev/null; then
        if ! pgrep -f 'inotifywait.*fromfile' >/dev/null 2>&1; then
            hc_warn "LMD: service active but no inotifywait monitor process found"
        fi
    fi
}

_lmd_check_events() {
    local threats failures
    threats="$(hc_json_event_count_since threat_detected "${LMD_AUDIT:-/var/log/maldet/audit.log}" "${LOOKBACK_HOURS:-24}")"
    failures="$(hc_json_event_count_since alert_failed "${LMD_AUDIT:-/var/log/maldet/audit.log}" "${LOOKBACK_HOURS:-24}")"

    hc_detail "LMD threats last ${LOOKBACK_HOURS:-24}h: $threats"
    hc_detail "LMD alert failures last ${LOOKBACK_HOURS:-24}h: $failures"

    [ "$threats" -gt 0 ] &&
        hc_warn "LMD: $threats threat_detected event(s) in last ${LOOKBACK_HOURS:-24}h"

    [ "$failures" -gt 0 ] &&
        hc_warn "LMD: $failures alert_failed event(s) in last ${LOOKBACK_HOURS:-24}h"
}

_lmd_check_signatures() {
    local sig_file age

    sig_file="$(
        find "${LMD_DIR:-/usr/local/maldetect}/sigs" -maxdepth 1 -type f \
            \( -name 'md5v2.dat' -o -name 'hex.dat' -o -name 'rfxn.hdb' \
               -o -name 'rfxn.ndb' -o -name 'rfxn.yara' \) \
            -printf '%T@ %p\n' 2>/dev/null |
        sort -nr |
        head -n1 |
        cut -d' ' -f2-
    )"

    if [ -z "$sig_file" ]; then
        hc_warn "LMD: no recognized signature file found"
        return
    fi

    age="$(hc_file_age_hours "$sig_file" || echo -1)"
    hc_detail "LMD newest signature age: ${age}h"

    if [ "$age" -gt "${LMD_SIG_MAX_AGE_HOURS:-24}" ]; then
        hc_warn "LMD signatures are ${age}h old (threshold ${LMD_SIG_MAX_AGE_HOURS:-24}h)"
    fi
}

_lmd_check_webroots() {
    hc_enabled "${CHECK_DIRECTADMIN_WEBROOTS:-0}" || return 0

    local actual monitored missing stale actual_count monitored_count
    actual="$(mktemp)"
    monitored="$(mktemp)"

    find "${DIRECTADMIN_HOME:-/home}" \
        -mindepth 4 -maxdepth 4 -type d \
        -path '*/domains/*/public_html' \
        ! -path '*/domains/autodiscover.*/public_html' \
        ! -path '*/domains/autoconfig.*/public_html' \
        ! -path '*/domains/mail.*/public_html' \
        -print 2>/dev/null |
        sort -u > "$actual"

    if [ ! -f "${LMD_MONITOR_LIST:-/usr/local/maldetect/directadmin-webroots}" ]; then
        hc_warn "LMD monitor list not found"
        rm -f "$actual" "$monitored"
        return
    fi

    sed '/^[[:space:]]*$/d; /^[[:space:]]*#/d' \
        "${LMD_MONITOR_LIST:-/usr/local/maldetect/directadmin-webroots}" |
        sort -u > "$monitored"

    actual_count="$(wc -l < "$actual")"
    monitored_count="$(wc -l < "$monitored")"
    hc_detail "Webroots: ${actual_count} actual / ${monitored_count} monitored"

    missing="$(comm -23 "$actual" "$monitored" || true)"
    stale="$(comm -13 "$actual" "$monitored" || true)"

    if [ -n "$missing" ]; then
        hc_warn "LMD webroots: $(printf '%s\n' "$missing" | sed '/^$/d' | wc -l) actual webroot(s) missing"
    fi

    if [ -n "$stale" ]; then
        hc_warn "LMD webroots: $(printf '%s\n' "$stale" | sed '/^$/d' | wc -l) stale monitor path(s)"
    fi

    rm -f "$actual" "$monitored"
}

_lmd_check_fullscan() {
    local lmd_bin report line scan_id d t epoch now age_days
    lmd_bin="${LMD_BIN:-/usr/local/sbin/maldet}"

    if [ ! -x "$lmd_bin" ]; then
        hc_warn "LMD binary not executable: $lmd_bin"
        return
    fi

    report="$("$lmd_bin" --report list 2>/dev/null || true)"
    line="$(printf '%s\n' "$report" | grep -F '/home/?/domains/?/public_html/' | head -n1)"

    if [ -z "$line" ]; then
        hc_warn "LMD: no matching full webroot scan found"
        return
    fi

    scan_id="$(printf '%s\n' "$line" | grep -oE '[0-9]{6}-[0-9]{4}\.[0-9]+' | head -n1)"

    if [ -z "$scan_id" ]; then
        hc_warn "LMD: unable to identify full scan ID"
        return
    fi

    d="${scan_id:0:6}"
    t="${scan_id:7:4}"
    epoch="$(date -d "20${d:0:2}-${d:2:2}-${d:4:2} ${t:0:2}:${t:2:2}" +%s 2>/dev/null || echo 0)"
    now="$(date +%s)"

    if [ "$epoch" -le 0 ]; then
        hc_warn "LMD: unable to parse full scan date"
        return
    fi

    age_days="$(( (now - epoch) / 86400 ))"
    hc_detail "Last LMD full scan: ${scan_id} (${age_days}d old)"

    if [ "$age_days" -gt "${FULLSCAN_MAX_AGE_DAYS:-8}" ]; then
        hc_warn "LMD full scan is ${age_days} days old (threshold ${FULLSCAN_MAX_AGE_DAYS:-8})"
    fi
}

check_lmd() {
    hc_enabled "${CHECK_LMD:-0}" || return 0

    _lmd_check_service
    _lmd_check_events
    _lmd_check_signatures
    _lmd_check_webroots
    _lmd_check_fullscan
}
