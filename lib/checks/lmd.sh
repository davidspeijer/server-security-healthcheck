#!/usr/bin/env bash
hc_register_check lmd

_lmd_event_log_path() {
    if [ -f "${LMD_DIR:-/usr/local/maldetect}/logs/event_log" ]; then
        printf '%s\n' "${LMD_DIR:-/usr/local/maldetect}/logs/event_log"
    elif [ -f /var/log/maldet/event_log ]; then
        printf '%s\n' /var/log/maldet/event_log
    else
        return 1
    fi
}

_lmd_check_service() {
    hc_check_service "${LMD_SERVICE:-maldet}" "LMD" || true
    if hc_service_active "${LMD_SERVICE:-maldet}" 2>/dev/null; then
        if ! pgrep -f 'inotifywait.*fromfile' >/dev/null 2>&1; then
            hc_warn "LMD: service active but no inotifywait monitor process found"
        else
            hc_detail "LMD realtime monitor: active"
        fi
    fi
}

_lmd_check_events() {
    local threats failures
    threats="$(hc_json_event_count_since threat_detected "${LMD_AUDIT:-/var/log/maldet/audit.log}" "${LOOKBACK_HOURS:-24}")"
    failures="$(hc_json_event_count_since alert_failed "${LMD_AUDIT:-/var/log/maldet/audit.log}" "${LOOKBACK_HOURS:-24}")"
    hc_detail "LMD threats last ${LOOKBACK_HOURS:-24}h: $threats"
    hc_detail "LMD alert failures last ${LOOKBACK_HOURS:-24}h: $failures"
    [ "$threats" -gt 0 ] && hc_warn "LMD: $threats threat_detected event(s) in last ${LOOKBACK_HOURS:-24}h"
    [ "$failures" -gt 0 ] && hc_warn "LMD: $failures alert_failed event(s) in last ${LOOKBACK_HOURS:-24}h"
}

_lmd_last_sigup_success_epoch() {
    local log line ts
    log="$(_lmd_event_log_path || true)"
    [ -n "$log" ] || return 1
    line="$(
        grep -E '\{sigup\} (latest signature set already installed|signature set updated|update completed|downloaded .*maldet\.sigs\.ver)' "$log" 2>/dev/null |
        tail -n1
    )"
    [ -n "$line" ] || return 1
    ts="$(printf '%s\n' "$line" | awk '{print $1, $2, $3, $4}')"
    date -d "$ts" +%s 2>/dev/null
}

_lmd_check_signature_updater() {
    local now last age sig_file sig_age version
    last="$(_lmd_last_sigup_success_epoch || true)"
    if [ -n "$last" ]; then
        now="$(date +%s)"
        age="$(( (now - last) / 3600 ))"
        hc_detail "LMD sigup last successful check: ${age}h ago"
        if [ "$age" -gt "${LMD_SIGUP_MAX_AGE_HOURS:-8}" ]; then
            hc_warn "LMD sigup: last successful check was ${age}h ago (threshold ${LMD_SIGUP_MAX_AGE_HOURS:-8}h)"
        fi
    else
        hc_warn "LMD sigup: no recent successful signature update check found"
    fi

    sig_file="$(
        find "${LMD_DIR:-/usr/local/maldetect}/sigs" -maxdepth 1 -type f \
            \( -name 'md5v2.dat' -o -name 'hex.dat' -o -name 'rfxn.hdb' -o -name 'rfxn.ndb' -o -name 'rfxn.yara' \) \
            -printf '%T@ %p\n' 2>/dev/null |
        sort -nr | head -n1 | cut -d' ' -f2-
    )"

    if [ -n "$sig_file" ]; then
        sig_age="$(hc_file_age_hours "$sig_file" || echo -1)"
        hc_detail "LMD signature file age: ${sig_age}h"
        if [ -z "$last" ] && [ "$sig_age" -gt "${LMD_SIG_MAX_AGE_HOURS:-72}" ]; then
            hc_warn "LMD signature files are ${sig_age}h old and updater health is unknown"
        fi
    else
        hc_warn "LMD: no recognized signature file found"
    fi

    if [ -f "${LMD_DIR:-/usr/local/maldetect}/sigs/maldet.sigs.ver" ]; then
        version="$(cat "${LMD_DIR:-/usr/local/maldetect}/sigs/maldet.sigs.ver" 2>/dev/null || true)"
        [ -n "$version" ] && hc_detail "LMD signature set version: ${version}"
    fi
}

_lmd_check_program_updater() {
    local log cutoff now line ts ts_epoch failures=0
    log="$(_lmd_event_log_path || true)"
    [ -n "$log" ] || return 0
    now="$(date +%s)"
    cutoff="$((now - ${LMD_UPDATE_FAILURE_LOOKBACK_HOURS:-48} * 3600))"
    while IFS= read -r line; do
        ts="$(printf '%s\n' "$line" | awk '{print $1, $2, $3, $4}')"
        ts_epoch="$(date -d "$ts" +%s 2>/dev/null || echo 0)"
        [ "$ts_epoch" -ge "$cutoff" ] || continue
        failures=$((failures + 1))
    done < <(
        grep -Ei '\{update\} .*failed|\{update\} .*unable to verify|sha256.*failed|unable to verify sha256' "$log" 2>/dev/null || true
    )

    if [ "$failures" -gt 0 ]; then
        hc_warn "LMD updater: ${failures} program update failure event(s) in last ${LMD_UPDATE_FAILURE_LOOKBACK_HOURS:-48}h"
    else
        hc_detail "LMD program updater: no recent failures"
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
        -print 2>/dev/null | sort -u > "$actual"

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
    [ -n "$missing" ] && hc_warn "LMD webroots: $(printf '%s\n' "$missing" | sed '/^$/d' | wc -l) actual webroot(s) missing"
    [ -n "$stale" ] && hc_warn "LMD webroots: $(printf '%s\n' "$stale" | sed '/^$/d' | wc -l) stale monitor path(s)"
    rm -f "$actual" "$monitored"
}

_lmd_check_fullscan() {
    local lmd_bin report line scan_id d t epoch now age_days
    lmd_bin="${LMD_BIN:-/usr/local/sbin/maldet}"
    [ -x "$lmd_bin" ] || { hc_warn "LMD binary not executable: $lmd_bin"; return; }

    report="$("$lmd_bin" --report list 2>/dev/null || true)"
    line="$(printf '%s\n' "$report" | grep -F '/home/?/domains/?/public_html/' | head -n1)"
    [ -n "$line" ] || { hc_warn "LMD: no matching full webroot scan found"; return; }

    scan_id="$(printf '%s\n' "$line" | grep -oE '[0-9]{6}-[0-9]{4}\.[0-9]+' | head -n1)"
    [ -n "$scan_id" ] || { hc_warn "LMD: unable to identify full scan ID"; return; }

    d="${scan_id:0:6}"
    t="${scan_id:7:4}"
    epoch="$(date -d "20${d:0:2}-${d:2:2}-${d:4:2} ${t:0:2}:${t:2:2}" +%s 2>/dev/null || echo 0)"
    now="$(date +%s)"
    [ "$epoch" -gt 0 ] || { hc_warn "LMD: unable to parse full scan date"; return; }

    age_days="$(( (now - epoch) / 86400 ))"
    hc_detail "Last LMD full scan: ${scan_id} (${age_days}d old)"
    [ "$age_days" -gt "${FULLSCAN_MAX_AGE_DAYS:-8}" ] &&
        hc_warn "LMD full scan is ${age_days} days old (threshold ${FULLSCAN_MAX_AGE_DAYS:-8})"
}

check_lmd() {
    hc_enabled "${CHECK_LMD:-0}" || return 0
    _lmd_check_service
    _lmd_check_events
    _lmd_check_signature_updater
    _lmd_check_program_updater
    _lmd_check_webroots
    _lmd_check_fullscan
}
