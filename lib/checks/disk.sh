#!/usr/bin/env bash
hc_register_check disk

check_disk() {
    hc_enabled "${CHECK_DISK:-0}" || return 0

    local fs size used avail percent mountpoint pct

    # shellcheck disable=SC2086
    while read -r fs size used avail percent mountpoint; do
        pct="${percent%\%}"
        [[ "$pct" =~ ^[0-9]+$ ]] || continue

        if [ "$pct" -ge "${DISK_WARN_PERCENT:-80}" ]; then
            hc_warn "Disk: ${mountpoint} is ${pct}% full (${avail} available)"
        fi
    done < <(
        df -P -h ${DISK_PATHS:-"/ /home /var /tmp"} 2>/dev/null |
        awk 'NR>1' |
        sort -u -k6,6
    )
}
