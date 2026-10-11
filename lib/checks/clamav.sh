#!/usr/bin/env bash
hc_register_check clamav

_clamav_database_directory() {
    local unit='' config defaults='' directory instance service="${CLAMAV_SERVICE:-clamd@scan}"
    if [ -z "${CLAMAV_CONFIG_FILE:-}" ]; then
        unit="$(systemctl cat "$service" 2>/dev/null)" || return 1
    fi
    instance="${service#*@}"; instance="${instance%.service}"
    config="$(hc_data_parse clam-config "${CLAMAV_CONFIG_FILE:-}" "$instance" <<< "$unit" 2>/dev/null)" || return 1
    if directory="$(hc_data_parse database "$config" '' 2>/dev/null)"; then
        printf '%s\n' "$directory"
        return 0
    fi
    # Packaging changes the generated example name. Both names describe clamd;
    # never use a default belonging to freshclam or another database consumer.
    hc_have clamconf || return 1
    local template
    for template in clamd.conf clamd.d/scan.conf; do
        defaults="$(clamconf -g "$template" 2>/dev/null)" || return 1
        defaults="$(sed -n 's/^#DatabaseDirectory[[:space:]]\+//p' <<< "$defaults")"
        [ -z "$defaults" ] || break
    done
    directory="$(hc_data_parse database "$config" "$defaults" 2>/dev/null)" || return 1
    printf '%s\n' "$directory"
}

_clamav_check_databases() {
    local directory name file found age
    directory="$(_clamav_database_directory)" || {
        hc_status ERROR 'ClamAV active database directory/configuration UNKNOWN'; return;
    }
    hc_detail "ClamAV active database directory: $directory"
    [ -d "$directory" ] && [ -r "$directory" ] && [ -x "$directory" ] || {
        hc_status ERROR 'ClamAV active database directory unavailable/unreadable'; return;
    }
    # daily freshness is essential; main is a required baseline with independent
    # presence/read/timestamp checks, but naturally ages between rare releases.
    # bytecode is optional. Never select another component/directory as daily.
    for name in daily main bytecode; do
        found=0
        for file in "$directory/$name.cvd" "$directory/$name.cld"; do
            [ -e "$file" ] || continue
            found=1
            if [ ! -f "$file" ] || [ ! -r "$file" ] || [ ! -s "$file" ] || ! age="$(hc_file_age_hours "$file")"; then
                hc_status ERROR "ClamAV $name database unreadable, empty or timestamp unavailable/in the future"
                continue
            fi
            hc_detail "ClamAV $name database age: ${age}h ($file)"
            if [ "$name" = daily ] && [ "$age" -gt "${CLAM_SIG_MAX_AGE_HOURS:-48}" ]; then
                hc_warn "ClamAV daily signatures are ${age}h old (threshold ${CLAM_SIG_MAX_AGE_HOURS:-48}h)"
            fi
        done
        if [ "$found" = 0 ] && [ "$name" != bytecode ]; then
            hc_status ERROR "ClamAV required $name database missing from active directory"
        fi
    done
    return 0
}

_clamav_last_success_epoch() {
    local now
    now="$(date +%s)" || return 1
    ( set -o pipefail
      journalctl \
        -u "${FRESHCLAM_ONESHOT_SERVICE:-clamav-freshclam-once.service}" \
        -u "${FRESHCLAM_SERVICE:-clamav-freshclam.service}" \
        --since '7 days ago' --no-pager -o short-iso 2>/dev/null |
        hc_data_parse freshclam "$now" 2>/dev/null
    )
}

check_clamav() {
    local mode dependency
    mode="$(hc_mode "${CHECK_CLAMAV:-0}")"
    [ "$mode" = off ] && return 0
    if [ "$mode" = auto ] && ! hc_service_present "${CLAMAV_SERVICE:-clamd@scan}" clamd freshclam; then return 0; fi
    for dependency in systemctl journalctl; do
        hc_have "$dependency" || { hc_status ERROR "ClamAV dependency missing: $dependency"; return; }
    done

    hc_check_service "${CLAMAV_SERVICE:-clamd@scan}" "ClamAV" || true

    local updater_detected=0 last now age_hours
    _clamav_check_databases

    if hc_have freshclam; then
        hc_detail "FreshClam: installed"
    else
        hc_warn "FreshClam: binary not installed"
        return
    fi

    if systemctl cat "${FRESHCLAM_TIMER:-clamav-freshclam-once.timer}" >/dev/null 2>&1; then
        if systemctl is-enabled --quiet "${FRESHCLAM_TIMER:-clamav-freshclam-once.timer}" 2>/dev/null; then
            if hc_service_active "${FRESHCLAM_TIMER:-clamav-freshclam-once.timer}"; then
                updater_detected=1
                hc_detail "FreshClam timer: enabled and active"
                if ! systemctl cat "${FRESHCLAM_ONESHOT_SERVICE:-clamav-freshclam-once.service}" >/dev/null 2>&1; then
                    hc_warn 'FreshClam timer: associated oneshot service missing'
                elif systemctl is-failed --quiet "${FRESHCLAM_ONESHOT_SERVICE:-clamav-freshclam-once.service}"; then
                    hc_warn 'FreshClam timer: associated oneshot service failed'
                fi
            else
                hc_warn 'FreshClam timer is enabled but not active'
            fi
        else
            hc_warn "FreshClam timer exists but is not enabled"
        fi
    fi

    if systemctl cat "${FRESHCLAM_SERVICE:-clamav-freshclam.service}" >/dev/null 2>&1; then
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

    if last="$(_clamav_last_success_epoch)" && now="$(date +%s)" &&
       hc_uint "$now" && hc_uint "$last" && [ "$last" -le "$now" ]; then
        age_hours="$(( (now - last) / 3600 ))"
        hc_detail "FreshClam last successful update/check: ${age_hours}h ago"
        if [ "$age_hours" -gt "${FRESHCLAM_MAX_AGE_HOURS:-36}" ]; then
            hc_warn "FreshClam: last successful update/check was ${age_hours}h ago (threshold ${FRESHCLAM_MAX_AGE_HOURS:-36}h)"
        fi
    else
        hc_warn "FreshClam: latest update/check failed, incomplete or journal unavailable/invalid (UNKNOWN)"
    fi
    return 0
}
