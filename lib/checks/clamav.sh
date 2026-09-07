#!/usr/bin/env bash
hc_register_check clamav

_clamav_find_newest_db() {
    find /var/lib/clamav /var/clamav /usr/local/share/clamav /usr/share/clamav \
        -maxdepth 1 -type f \
        \( -name 'daily.cvd' -o -name 'daily.cld' \
           -o -name 'main.cvd' -o -name 'main.cld' \
           -o -name 'bytecode.cvd' -o -name 'bytecode.cld' \) \
        -printf '%T@ %p\n' 2>/dev/null |
    sort -nr | head -n1 | cut -d' ' -f2-
}

_clamav_last_success_epoch() {
    local line ts
    line="$(
        journalctl \
            -u "${FRESHCLAM_ONESHOT_SERVICE:-clamav-freshclam-once.service}" \
            -u "${FRESHCLAM_SERVICE:-clamav-freshclam.service}" \
            --since "7 days ago" --no-pager -o short-iso 2>/dev/null |
        grep -Ei 'updated \(|up-to-date|database.*up-to-date|Database test passed' |
        tail -n1
    )"
    [ -n "$line" ] || return 1
    ts="$(printf '%s\n' "$line" | awk '{print $1}')"
    date -d "$ts" +%s 2>/dev/null
}

check_clamav() {
    hc_enabled "${CHECK_CLAMAV:-0}" || return 0

    hc_check_service "${CLAMAV_SERVICE:-clamd@scan}" "ClamAV" || true

    local sig_file sig_age updater_detected=0 last now age_hours
    sig_file="$(_clamav_find_newest_db)"

    if [ -z "$sig_file" ]; then
        hc_warn "ClamAV: no recognized official signature database found"
    else
        sig_age="$(hc_file_age_hours "$sig_file" || echo -1)"
        hc_detail "ClamAV official database age: ${sig_age}h"
        if [ "$sig_age" -gt "${CLAM_SIG_MAX_AGE_HOURS:-48}" ]; then
            hc_warn "ClamAV official signatures are ${sig_age}h old (threshold ${CLAM_SIG_MAX_AGE_HOURS:-48}h)"
        fi
    fi

    if hc_have freshclam; then
        hc_detail "FreshClam: installed"
    else
        hc_warn "FreshClam: binary not installed"
        return
    fi

    if systemctl list-unit-files "${FRESHCLAM_TIMER:-clamav-freshclam-once.timer}" --no-legend 2>/dev/null | grep -q .; then
        if systemctl is-enabled --quiet "${FRESHCLAM_TIMER:-clamav-freshclam-once.timer}" 2>/dev/null; then
            updater_detected=1
            hc_detail "FreshClam timer: enabled"
        else
            hc_warn "FreshClam timer exists but is not enabled"
        fi
    fi

    if systemctl list-unit-files "${FRESHCLAM_SERVICE:-clamav-freshclam.service}" --no-legend 2>/dev/null | grep -q .; then
        if systemctl is-enabled --quiet "${FRESHCLAM_SERVICE:-clamav-freshclam.service}" 2>/dev/null; then
            updater_detected=1
            if systemctl is-active --quiet "${FRESHCLAM_SERVICE:-clamav-freshclam.service}"; then
                hc_detail "FreshClam daemon: active"
            else
                hc_warn "FreshClam daemon is enabled but not active"
            fi
        fi
    fi

    [ "$updater_detected" -eq 1 ] || hc_warn "FreshClam: no enabled automatic updater detected"

    last="$(_clamav_last_success_epoch || true)"
    if [ -n "$last" ]; then
        now="$(date +%s)"
        age_hours="$(( (now - last) / 3600 ))"
        hc_detail "FreshClam last successful update/check: ${age_hours}h ago"
        if [ "$age_hours" -gt "${FRESHCLAM_MAX_AGE_HOURS:-36}" ]; then
            hc_warn "FreshClam: last successful update/check was ${age_hours}h ago (threshold ${FRESHCLAM_MAX_AGE_HOURS:-36}h)"
        fi
    else
        hc_warn "FreshClam: no successful update/check found in recent journal"
    fi
}
