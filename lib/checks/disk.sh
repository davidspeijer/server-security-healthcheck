#!/usr/bin/env bash
hc_register_check disk

check_disk() {
    hc_enabled "${CHECK_DISK:-0}" || return 0
    local fs size used avail percent mountpoint pct output line threshold record count=0 first=1
    local -a paths
    local -A fullness available
    threshold="${DISK_WARN_PERCENT:-80}"
    hc_uint "$threshold" && [ "$threshold" -gt 0 ] && [ "$threshold" -le 100 ] || { hc_status ERROR 'Invalid disk threshold'; return; }
    read -r -a paths <<< "${DISK_PATHS:-/ /home /var /tmp}"
    output="$(LC_ALL=C df -P -h -- "${paths[@]}" 2>/dev/null)" || { hc_status ERROR 'Disk usage check failed'; return; }
    record='^[[:space:]]*([^[:space:]]+)[[:space:]]+([^[:space:]]+)[[:space:]]+([^[:space:]]+)[[:space:]]+([^[:space:]]+)[[:space:]]+([^[:space:]]+)[[:space:]]+(/.*)$'
    while IFS= read -r line; do
        if [ "$first" = 1 ]; then
            first=0
            [[ "$line" = Filesystem* ]] || hc_status ERROR 'Disk output header malformed'
            continue
        fi
        [ -n "$line" ] || continue
        if [[ ! "$line" =~ $record ]]; then
            hc_status ERROR 'Disk output contains a malformed record'
            continue
        fi
        fs="${BASH_REMATCH[1]}" size="${BASH_REMATCH[2]}" used="${BASH_REMATCH[3]}"
        avail="${BASH_REMATCH[4]}" percent="${BASH_REMATCH[5]}" mountpoint="${BASH_REMATCH[6]}"
        if [[ ! "$percent" =~ ^[0-9]{1,3}%$ ]] || [ -z "$fs" ] ||
           [[ ! "$size" =~ ^[0-9]+([.][0-9]+)?[KMGTPEZY]?$ ]] ||
           [[ ! "$used" =~ ^[0-9]+([.][0-9]+)?[KMGTPEZY]?$ ]] ||
           [[ ! "$avail" =~ ^[0-9]+([.][0-9]+)?[KMGTPEZY]?$ ]] || [[ "$mountpoint" != /* ]]; then
            hc_status ERROR 'Disk output contains a malformed record'
            continue
        fi
        pct="$((10#${percent%\%}))"
        [ "$pct" -le 100 ] || { hc_status ERROR 'Disk percentage out of range'; continue; }
        count=$((count + 1))
        if [ -z "${fullness[$mountpoint]+present}" ] || [ "$pct" -gt "${fullness[$mountpoint]}" ]; then
            fullness[$mountpoint]="$pct" available[$mountpoint]="$avail"
        fi
    done <<< "$output"
    [ "$count" -gt 0 ] || { hc_status ERROR 'Disk output contains no usable records'; return; }
    for mountpoint in "${!fullness[@]}"; do
        pct="${fullness[$mountpoint]}"
        if [ "$pct" -ge "$threshold" ]; then
            hc_warn "Disk: ${mountpoint} is ${pct}% full (${available[$mountpoint]} available)"
        fi
    done
    return 0
}
