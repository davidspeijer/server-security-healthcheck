#!/usr/bin/env bash
hc_register_check clamav

check_clamav() {
    hc_enabled "${CHECK_CLAMAV:-0}" || return 0

    hc_check_service "${CLAMAV_SERVICE:-clamd@scan}" "ClamAV" || true

    local sig_file age

    sig_file="$(
        find /var/lib/clamav /var/clamav /usr/local/share/clamav /usr/share/clamav \
            -maxdepth 1 -type f \
            \( -name 'daily.cvd' -o -name 'daily.cld' \
               -o -name 'main.cvd' -o -name 'main.cld' \
               -o -name 'bytecode.cvd' -o -name 'bytecode.cld' \) \
            -printf '%T@ %p\n' 2>/dev/null |
        sort -nr |
        head -n1 |
        cut -d' ' -f2-
    )"

    if [ -z "$sig_file" ]; then
        hc_warn "ClamAV: no recognized signature database found"
        return
    fi

    age="$(hc_file_age_hours "$sig_file" || echo -1)"
    hc_detail "ClamAV newest database age: ${age}h"

    if [ "$age" -gt "${CLAM_SIG_MAX_AGE_HOURS:-48}" ]; then
        hc_warn "ClamAV signatures are ${age}h old (threshold ${CLAM_SIG_MAX_AGE_HOURS:-48}h)"
    fi
}
