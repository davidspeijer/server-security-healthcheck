#!/usr/bin/env bash
hc_register_check lmd

# Never source metadata: it is append-only key=value data, not shell code.
# Exact key matching and last assignment wins (notably running -> completed).
_lmd_meta_get() {
    awk -v key="$2" 'index($0, key "=")==1 {v=substr($0,length(key)+2); sub(/\r$/, "", v)} END {print v}' "$1"
}

_lmd_event_log_path() {
    if [ -n "${LMD_EVENT_LOG:-}" ]; then
        printf '%s\n' "$LMD_EVENT_LOG"
    elif [ -f "${LMD_DIR:-/usr/local/maldetect}/logs/event_log" ]; then
        printf '%s\n' "${LMD_DIR:-/usr/local/maldetect}/logs/event_log"
    else
        printf '%s\n' /var/log/maldet/event_log
    fi
}

# Read the entire current log for each requested outcome, retaining its last
# matching record. Do not tail the input: unrelated busy monitor traffic
# must not hide older update events. Logs are assumed append-ordered; timestamps
# are local server time for legacy LMD, or explicit ISO timestamps when supplied.
_lmd_last_event() {
    local log="$1" tag="$2" pattern="$3" line timestamp
    [ -r "$log" ] || return 1
    line="$(awk -v tag="{$tag}" -v pattern="$pattern" '
        index($0,tag) {body=substr($0,index($0,tag)+length(tag)); if (tolower(body) ~ pattern) last=$0}
        END {print last}' "$log")"
    [ -n "$line" ] || return 1
    if [[ "$line" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T ]]; then
        timestamp="${line%% *}"
    elif [[ "$line" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}[[:space:]] ]]; then
        timestamp="$(awk '{print $1, $2}' <<< "$line")"
    else
        timestamp="$(awk '{print $1, $2, $3, $4}' <<< "$line")"
    fi
    date -d "$timestamp" +%s 2>/dev/null || {
        # Distinguish an event with a broken timestamp from no matching event.
        # In particular, an unparseable failure must not become healthy evidence.
        printf '%s\n' unknown
        return 1
    }
}

_lmd_failure_unresolved() {
    local log="$1" tag="$2" success_pattern="$3" failure_pattern="$4" failure="$5" success="$6"
    [ "$failure" -lt "$success" ] && return 1
    [ "$failure" -gt "$success" ] && return 0
    # Logs only record seconds. On ties use append order, so a failure after a
    # same-second success remains visible and a later success really clears it.
    awk -v tag="{$tag}" -v good="$success_pattern" -v bad="$failure_pattern" '
        index($0,tag) {
            body=tolower(substr($0,index($0,tag)+length(tag)))
            if (body ~ good) s=NR
            if (body ~ bad) f=NR
        }
        END {exit !(f>0 && f>=s)}' "$log"
}

_lmd_check_service() {
    if ! hc_enabled "${LMD_MONITOR_REQUIRED:-1}"; then
        hc_detail 'LMD realtime monitoring not required by configuration'
        return
    fi
    local service="${LMD_SERVICE:-maldet.service}" log last age process_status
    if ! systemctl cat "$service" >/dev/null 2>&1; then
        hc_status CRITICAL "LMD realtime service missing: $service"
    elif ! hc_service_active "$service"; then
        hc_status CRITICAL "LMD realtime service is not active: $service"
    else
        pgrep -f -- "${LMD_MONITOR_PROCESS_PATTERN:-inotifywait.*(--fromfile|--from-file)}" >/dev/null 2>&1
        process_status=$?
        case "$process_status" in
            0) hc_status PASS 'LMD realtime service and monitor process active' ;;
            1) hc_status CRITICAL 'LMD service active but no matching inotifywait monitor process found' ;;
            *) hc_status ERROR 'LMD monitor process check failed (check process pattern)' ;;
        esac
    fi
    log="$(_lmd_event_log_path)"
    last="$(_lmd_last_event "$log" mon '^[[:space:]]*(scanned|filtered)[[:space:]]' || true)"
    if ! age="$(hc_age_seconds "$last")"; then
        hc_warn 'LMD realtime monitor: no parseable scan/filter heartbeat (reload alone is insufficient)'
    elif [ "$age" -gt "$(( ${LMD_MONITOR_MAX_IDLE_MINUTES:-90} * 60 ))" ]; then
        hc_warn "LMD realtime monitor: last scan/filter activity $((age / 60))m ago"
    else
        hc_status PASS "LMD realtime monitor activity: $((age / 60))m ago"
    fi
}

_lmd_check_events() {
    local threats failures audit="${LMD_AUDIT:-/var/log/maldet/audit.log}"
    [ -e "$audit" ] || return 0
    [ -r "$audit" ] || { hc_warn "LMD audit log unreadable: $audit"; return; }
    threats="$(hc_json_event_count_since threat_detected "$audit" "${LOOKBACK_HOURS:-24}")"
    failures="$(hc_json_event_count_since alert_failed "$audit" "${LOOKBACK_HOURS:-24}")"
    hc_detail "LMD audit last ${LOOKBACK_HOURS:-24}h: $threats threat_detected, $failures alert_failed"
    [ "$threats" -eq 0 ] || hc_warn "LMD audit: $threats detection event(s); audit count does not classify malware"
    [ "$failures" -eq 0 ] || hc_warn "LMD audit: $failures notification failure event(s)"
    return 0
}

_lmd_check_signature_updater() {
    local log last failure current updated generic age failure_age version result file found=0
    local success_pattern='(latest signature set already installed|signature set update completed|signature set updated|signature update completed|^[[:space:]]*update completed)'
    local failure_pattern='(fail(ed|ure)|unable to|could not|aborting|error handling)'
    log="$(_lmd_event_log_path)"
    current="$(_lmd_last_event "$log" sigup 'latest signature set already installed' || true)"
    updated="$(_lmd_last_event "$log" sigup '(signature set update completed|signature set updated|signature update completed)' || true)"
    generic="$(_lmd_last_event "$log" sigup '^[[:space:]]*update completed' || true)"
    failure="$(_lmd_last_event "$log" sigup "$failure_pattern" || true)"
    # A download announcement/version-file download is not a successful install.
    last=0 result='unknown success status'
    if hc_age_seconds "$generic" >/dev/null; then last="$generic"; fi
    if hc_age_seconds "$updated" >/dev/null && [ "$updated" -ge "$last" ]; then last="$updated"; result=updated; fi
    if hc_age_seconds "$current" >/dev/null && [ "$current" -ge "$last" ]; then last="$current"; result='already current'; fi
    if [ -r "${LMD_DIR:-/usr/local/maldetect}/sigs/maldet.sigs.ver" ]; then
        IFS= read -r version < "${LMD_DIR:-/usr/local/maldetect}/sigs/maldet.sigs.ver" || true
        hc_detail "LMD local signature version: ${version:-unknown}"
    else
        hc_warn 'LMD local signature version unavailable'
    fi
    for file in "${LMD_DIR:-/usr/local/maldetect}"/sigs/{md5v2.dat,hex.dat,rfxn.hdb,rfxn.ndb,rfxn.yara}; do
        if [ -r "$file" ] && [ -s "$file" ]; then found=1; break; fi
    done
    [ "$found" -eq 1 ] || hc_warn 'LMD: no readable nonempty recognized signature file found'
    if [ -n "$failure" ] && ! hc_age_seconds "$failure" >/dev/null; then
        hc_warn 'LMD signature updater: UNKNOWN failure timestamp; cannot establish recovery'
    elif failure_age="$(hc_age_seconds "$failure")" &&
        [ "$failure_age" -le "$(( ${LMD_UPDATE_FAILURE_LOOKBACK_HOURS:-48} * 3600 ))" ] &&
        _lmd_failure_unresolved "$log" sigup "$success_pattern" "$failure_pattern" "$failure" "$last"; then
        hc_status CRITICAL 'LMD signature update failed without a later successful check'
    elif [ "$last" -eq 0 ] || ! age="$(hc_age_seconds "$last")"; then
        hc_warn 'LMD signature updater: UNKNOWN, no parseable successful check'
    elif [ "$age" -gt "$(( ${LMD_SIGUP_MAX_AGE_HOURS:-8} * 3600 ))" ]; then
        hc_warn "LMD signature check stale: $(hc_duration "$age") ago ($result)"
    else
        hc_status PASS "LMD signatures: $result; last check $(date -d "@$last" '+%F %T %Z')"
    fi
}

_lmd_check_program_updater() {
    local expected="${LMD_PROGRAM_UPDATE_EXPECTED:-disabled}" log last failure age
    local success_pattern='(latest version already installed|completed update|update and config import completed)'
    local failure_pattern='(fail(ed|ure)|unable to|could not|aborting)'
    case "$expected" in
        ignore) return 0 ;;
        disabled) hc_detail 'LMD automatic program update intentionally disabled'; return ;;
    esac
    log="$(_lmd_event_log_path)"
    last="$(_lmd_last_event "$log" update "$success_pattern" || true)"
    hc_age_seconds "$last" >/dev/null || last=0
    failure="$(_lmd_last_event "$log" update "$failure_pattern" || true)"
    if [ -n "$failure" ] && ! hc_age_seconds "$failure" >/dev/null; then
        hc_warn 'LMD automatic program updater: UNKNOWN failure timestamp; cannot establish recovery'
    elif age="$(hc_age_seconds "$failure")" &&
        [ "$age" -le "$(( ${LMD_UPDATE_FAILURE_LOOKBACK_HOURS:-48} * 3600 ))" ] &&
        _lmd_failure_unresolved "$log" update "$success_pattern" "$failure_pattern" "$failure" "$last"; then
        hc_warn 'LMD automatic program updater: recent failure without later success'
    elif [ ! -r "$log" ]; then
        hc_warn 'LMD automatic program updater: event log unavailable'
    else
        hc_detail 'LMD automatic program updater: no unresolved recent failure found'
    fi
}

_lmd_check_webroots() {
    hc_enabled "${CHECK_DIRECTADMIN_WEBROOTS:-0}" || return 0
    local temporary actual monitored missing stale expected_count configured_count covered
    local list="${LMD_WEBROOT_LIST:-${LMD_MONITOR_LIST:-${LMD_DIR:-/usr/local/maldetect}/directadmin-webroots}}"
    [ -r "$list" ] || { hc_warn "LMD monitor list unavailable: $list"; return; }
    temporary="$(mktemp -d)" || { hc_status ERROR 'Cannot create coverage scratch directory'; return; }
    actual="$temporary/actual" monitored="$temporary/monitored"
    # Both sets use the same bytewise collation. One path per line matches LMD's
    # own --fromfile format; embedded newlines are not representable in that format.
    if ! find "${DIRECTADMIN_HOME:-/home}" -mindepth 4 -maxdepth 4 -type d \
        -path '*/domains/*/public_html' \
        ! -path '*/domains/autodiscover.*/public_html' \
        ! -path '*/domains/autoconfig.*/public_html' \
        ! -path '*/domains/mail.*/public_html' -print > "$temporary/discovered"; then
        hc_status ERROR 'DirectAdmin webroot discovery failed; coverage cannot be evaluated'
    elif ! LC_ALL=C sort -u "$temporary/discovered" > "$actual" ||
        ! sed 's/\r$//; /^[[:space:]]*$/d; /^[[:space:]]*#/d; s:/*$::' "$list" | LC_ALL=C sort -u > "$monitored"; then
        hc_status ERROR 'LMD coverage set preparation failed'
    else
        if ! expected_count="$(wc -l < "$actual")" ||
            ! configured_count="$(wc -l < "$monitored")" ||
            ! missing="$(LC_ALL=C comm -23 "$actual" "$monitored")" ||
            ! stale="$(LC_ALL=C comm -13 "$actual" "$monitored")" ||
            ! covered="$(LC_ALL=C comm -12 "$actual" "$monitored" | wc -l)"; then
            hc_status ERROR 'LMD coverage set comparison failed'
        else
            hc_detail "LMD realtime coverage: $((covered))/$((expected_count)) webroots monitored; configured: $((configured_count))"
            if [ -n "$missing$stale" ]; then
                hc_warn 'LMD realtime coverage mismatch'
                [ -z "$missing" ] || printf '       Missing:\n%s\n' "$missing"
                [ -z "$stale" ] || printf '       Stale/out-of-scope entries:\n%s\n' "$stale"
            else
                hc_status PASS 'LMD realtime coverage matches DirectAdmin webroots'
            fi
        fi
    fi
    rm -f -- "$temporary/actual" "$temporary/monitored" "$temporary/discovered"
    rmdir -- "$temporary" || hc_status ERROR 'Could not remove coverage scratch directory'
}

_lmd_test_signature() { [[ "${1,,}" = *eicar* ]]; }

_lmd_check_hits() {
    local file="$1" hits="$2" quarantine="$3" line signature path rest quarantine_path kind
    local count=0 tests=0 real=0 malformed=0 owner
    hc_uint "$hits" || { hc_warn 'LMD full scan hit count unavailable/invalid'; return; }
    if [ "$hits" -eq 0 ]; then hc_status PASS 'LMD full scan: no hits'; return; fi
    [ -r "$file" ] || { hc_status CRITICAL "LMD full scan reports $hits hit(s), but session details are unavailable: $file"; return; }
    IFS= read -r line < "$file" || true
    [[ "$line" = '#LMD:v1'$'\t'* ]] || { hc_status CRITICAL 'LMD hit session format unknown; detections cannot be classified'; return; }
    # First columns: signature, file, quarantine path, type, type label. Split
    # explicitly: read with tab IFS collapses empty fields and can shift columns.
    while IFS= read -r line || [ -n "$line" ]; do
        [[ "$line" = \#* || -z "$line" ]] && continue
        [[ "$line" = *$'\t'* ]] || { malformed=$((malformed + 1)); continue; }
        signature="${line%%$'\t'*}" rest="${line#*$'\t'}"
        path="${rest%%$'\t'*}"
        if [[ "$rest" = *$'\t'* ]]; then rest="${rest#*$'\t'}"; else rest=''; fi
        quarantine_path="${rest%%$'\t'*}"
        if [[ "$rest" = *$'\t'* ]]; then rest="${rest#*$'\t'}"; else rest=''; fi
        kind="${rest%%$'\t'*}"
        if [ -z "$signature" ] || [[ "$path" != /* ]]; then malformed=$((malformed + 1)); continue; fi
        count=$((count + 1))
        if _lmd_test_signature "$signature"; then tests=$((tests + 1)); else real=$((real + 1)); fi
        # Owner is read from the current file when available, not guessed from a
        # version-dependent extra TSV column. This is not the historical owner.
        owner="$(stat -c %U -- "$path" 2>/dev/null || true)"
        printf '       Signature: %s\n       File: %s\n       Type: %s; current owner: %s; quarantine path: %s\n' \
            "$signature" "$path" "${kind:-unknown}" "${owner:-unknown}" "${quarantine_path:--}"
    done < "$file"
    if [ "$real" -gt 0 ]; then
        hc_status CRITICAL "LMD full scan found malware: $real non-test detection(s), $tests EICAR/test detection(s)"
        if [ "$quarantine" = 0 ]; then
            hc_detail 'Automatic quarantine is disabled; detected files may still be accessible.'
        else
            hc_detail 'Quarantine policy is not proof of removal; verify the reported quarantine paths.'
        fi
    elif [ "$tests" -gt 0 ]; then
        hc_warn "Full scan contains $tests EICAR/test detections (not classified as real malware)"
    fi
    if [ "$count" -ne "$hits" ] || [ "$malformed" -gt 0 ]; then
        hc_status CRITICAL "LMD full scan hit details incomplete: metadata=$hits, parsed=$count, malformed=$malformed; unclassified detections remain"
    fi
}

_lmd_scan_details() {
    local file="$1" state="$2" started completed elapsed hits quarantine options value
    started="$(_lmd_meta_get "$file" started)" completed="$(_lmd_meta_get "$file" completed)"
    elapsed="$(_lmd_meta_get "$file" elapsed)" hits="$(_lmd_meta_get "$file" hits)"
    quarantine="$(_lmd_meta_get "$file" quarantine_enabled)"
    if [ -z "$quarantine" ]; then
        options="$(_lmd_meta_get "$file" options)"
        quarantine="$(awk -v text="$options" 'BEGIN {n=split(text,a,","); for(i=1;i<=n;i++) if(a[i] ~ /^quarantine_hits=/) v=substr(a[i],17); print v}')"
    fi
    hc_detail "LMD full scan ID: ${file##*/scan.meta.}; state: $state"
    hc_detail "LMD full scan hits: ${hits:-unknown}"
    for value in total_files engine sig_version; do
        local field
        field="$(_lmd_meta_get "$file" "$value")"
        hc_detail "LMD full scan $value: ${field:-unknown}"
        [ -n "$field" ] || hc_warn "LMD full scan metadata missing: $value"
        if [ "$value" = total_files ] && ! hc_uint "$field"; then hc_warn 'LMD full scan total_files is invalid'; fi
    done
    if ! hc_uint "$elapsed" && hc_uint "$started" && hc_uint "$completed" && [ "$completed" -ge "$started" ]; then
        elapsed=$((completed - started))
    fi
    if hc_uint "$elapsed"; then
        hc_detail "LMD full scan runtime: $(hc_duration "$elapsed") ($elapsed seconds)"
        [ "$elapsed" -le "$(( ${LMD_FULLSCAN_MAX_RUNTIME_HOURS:-12} * 3600 ))" ] || hc_warn 'LMD full scan runtime exceeds configured threshold'
    elif [ "$state" = completed ]; then
        hc_warn 'LMD full scan runtime unavailable'
    fi
    case "$quarantine" in
        0) hc_detail 'LMD automatic quarantine disabled by scan policy' ;;
        1) hc_detail 'LMD automatic quarantine enabled by scan policy' ;;
        *) quarantine=unknown; hc_detail 'LMD automatic quarantine status unknown' ;;
    esac
    if [ "${LMD_EXPECT_QUARANTINE_ENABLED:-0}" != ignore ] && [ "$quarantine" != "${LMD_EXPECT_QUARANTINE_ENABLED:-0}" ]; then
        hc_warn "LMD quarantine policy mismatch: expected ${LMD_EXPECT_QUARANTINE_ENABLED:-0}, metadata $quarantine"
    fi
    if [ "$state" = completed ] || { hc_uint "$hits" && [ "$hits" -gt 0 ]; }; then
        _lmd_check_hits "${file%/*}/session.tsv.${file##*/scan.meta.}" "$hits" "$quarantine"
    fi
}

_lmd_check_fullscan() {
    local directory="${LMD_SESSION_DIR:-${LMD_DIR:-/usr/local/maldetect}/sess}"
    local expected="${LMD_EXPECTED_FULLSCAN_PATH:-/home/?/domains/?/public_html/}"
    local file path started completed order state latest='' latest_order=0 latest_completed='' completed_order=0
    local invalid=0 mismatched=0 now age runtime max_age
    now="$(date +%s)"
    max_age="${LMD_FULLSCAN_MAX_AGE_HOURS:-$(( ${FULLSCAN_MAX_AGE_DAYS:-8} * 24 ))}"
    [ -d "$directory" ] && [ -r "$directory" ] && [ -x "$directory" ] || { hc_warn "LMD full scan session directory unavailable: $directory"; return; }
    # Filename mtime is deliberately ignored. Literal path equality (apart from
    # trailing slash) prevents a monitor/partial scan from satisfying fullscan health.
    for file in "$directory"/scan.meta.*; do
        [ -e "$file" ] || continue
        [ -f "$file" ] && [ -r "$file" ] || { invalid=$((invalid + 1)); continue; }
        path="$(_lmd_meta_get "$file" path)"
        if [ "${path%/}" != "${expected%/}" ]; then mismatched=$((mismatched + 1)); continue; fi
        started="$(_lmd_meta_get "$file" started)" completed="$(_lmd_meta_get "$file" completed)"
        state="$(_lmd_meta_get "$file" state)"
        if ! hc_uint "$started" || [ "$started" -eq 0 ] || [ "$started" -gt "$now" ]; then invalid=$((invalid + 1)); continue; fi
        order="$started"
        if [ "$state" = completed ] && hc_uint "$completed" && [ "$completed" -ge "$started" ] && [ "$completed" -le "$now" ]; then
            order="$completed"
            if [ "$completed" -ge "$completed_order" ]; then latest_completed="$file"; completed_order="$completed"; fi
        fi
        if [ "$order" -ge "$latest_order" ]; then latest="$file"; latest_order="$order"; fi
    done
    [ "$invalid" -eq 0 ] || hc_warn "LMD full scan: $invalid unreadable/invalid metadata file(s); selection may be incomplete"
    if [ -z "$latest" ]; then
        hc_warn "LMD: no matching full scan metadata; expected path $expected ($mismatched other scan path(s))"
        return
    fi
    state="$(_lmd_meta_get "$latest" state)"
    started="$(_lmd_meta_get "$latest" started)" completed="$(_lmd_meta_get "$latest" completed)"
    case "$state" in
        completed)
            if ! hc_uint "$completed" || [ "$completed" -lt "$started" ] || [ "$completed" -gt "$now" ]; then
                hc_warn 'LMD completed full scan has missing/invalid completed timestamp'
            else
                age=$((now - completed))
                if [ "$age" -gt "$((max_age * 3600))" ]; then hc_warn "LMD completed full scan stale: $(hc_duration "$age") ago"
                else hc_status PASS "LMD weekly full scan completed: $(date -d "@$completed" '+%F %T %Z')"; fi
            fi ;;
        running|started|paused)
            runtime=$((now - started))
            if [ "$runtime" -gt "$(( ${LMD_FULLSCAN_MAX_RUNTIME_HOURS:-12} * 3600 ))" ]; then
                hc_status CRITICAL "LMD stale $state full scan: started $(hc_duration "$runtime") ago; exceeds maximum runtime"
            else hc_detail "LMD full scan currently $state: $(hc_duration "$runtime") since start (within allowed runtime)"; fi
            if [ "$completed_order" -eq 0 ] || [ "$((now - completed_order))" -gt "$((max_age * 3600))" ]; then
                hc_warn 'LMD has no completed full scan within the age threshold; running is not proof of completion'
            fi ;;
        failed|aborted|killed|error|cancelled|canceled)
            hc_status CRITICAL "LMD latest full scan explicitly $state" ;;
        *) hc_warn "LMD latest full scan not completed: state ${state:-unknown}" ;;
    esac
    _lmd_scan_details "$latest" "$state"
    # A new running/failed scan must not hide malware in the most recent completed
    # scan. Keep reporting that completed scan until a newer completed scan exists.
    if [ -n "$latest_completed" ] && [ "$latest_completed" != "$latest" ]; then
        hc_detail 'LMD previous completed scan findings:'
        _lmd_scan_details "$latest_completed" completed
    fi
}

check_lmd() {
    local mode dependency
    mode="$(hc_mode "${LMD_ENABLED:-${CHECK_LMD:-0}}")"
    [ "$mode" = off ] && return 0
    if [ ! -d "${LMD_DIR:-/usr/local/maldetect}" ]; then
        [ "$mode" = auto ] || hc_warn 'LMD integration enabled but installation directory is unavailable'
        return
    fi
    _lmd_check_configuration
    hc_have rmdir || { hc_status ERROR 'LMD dependency missing: rmdir'; return; }
    if hc_enabled "${LMD_MONITOR_REQUIRED:-1}"; then
        for dependency in systemctl pgrep; do
            hc_have "$dependency" || { hc_status ERROR "LMD dependency missing: $dependency"; return; }
        done
    fi
    _lmd_check_service
    _lmd_check_events
    _lmd_check_signature_updater
    _lmd_check_program_updater
    _lmd_check_webroots
    _lmd_check_fullscan
    return 0
}
