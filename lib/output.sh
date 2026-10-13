#!/usr/bin/env bash
# COLLECTING -> FINALIZING -> RENDERING -> PUBLISHED. No journal writes after verification.
hc_json_init() {
    HC_JSON_DIR="$(mktemp -d)" || return 1
    HC_JSON_FILE="$HC_JSON_DIR/journal"
    HC_JSON_RENDERED="$HC_JSON_DIR/result.json"
    if ! (umask 077; : > "$HC_JSON_FILE" && : > "$HC_JSON_RENDERED"); then
        rm -f -- "$HC_JSON_FILE" "$HC_JSON_RENDERED"
        rmdir -- "$HC_JSON_DIR"
        return 1
    fi
    readonly HC_JSON_DIR HC_JSON_FILE HC_JSON_RENDERED HC_JSON_HELPER
    HC_JSON_PID=$BASHPID
    HC_JSON_CURRENT=''
    HC_JSON_EVENTS=0 HC_JSON_TRUNCATED=0 HC_JSON_FAILED=0 HC_JSON_CLOCK_FAILED=0
    HC_JSON_BYTES=0 HC_JSON_STATE=COLLECTING
    HC_JSON_MAX_BYTES=4194304 HC_JSON_RESERVE_BYTES=262144 HC_JSON_MAX_RECORD=8192
    declare -g -A HC_JSON_RANK=()
    declare -g -A HC_JSON_COUNTS=([PASS]=0 [INFO]=0 [WARNING]=0 [CRITICAL]=0 [ERROR]=0)
}
hc_json_record() {
    local LC_ALL=C bytes
    bytes=$(( ${#1} + ${#2} + ${#3} + ${#4} + 4 ))
    if [ "$HC_JSON_STATE" != COLLECTING ] && [ "$HC_JSON_STATE" != FINALIZING ]; then
        HC_JSON_FAILED=1; return 0
    fi
    if [ "${#2}" -gt 128 ] || [ "$bytes" -gt "$HC_JSON_MAX_RECORD" ] ||
       [ "$((HC_JSON_BYTES + bytes))" -gt "$HC_JSON_MAX_BYTES" ]; then
        HC_JSON_FAILED=1; return 0
    fi
    if [ "$1" = finding ] && [ "$((HC_JSON_BYTES + bytes))" -gt "$((HC_JSON_MAX_BYTES - HC_JSON_RESERVE_BYTES))" ]; then
        HC_JSON_TRUNCATED=1; return 0
    fi
    if printf '%s\0%s\0%s\0%s\0' "$1" "$2" "$3" "$4" >> "$HC_JSON_FILE"; then
        HC_JSON_BYTES=$((HC_JSON_BYTES + bytes))
    else HC_JSON_FAILED=1; fi
}
# Bound retained UTF-8 bytes while preserving the first 1024 codepoints.
# Final codepoint truncation is done by Python. This prefix never splits valid UTF-8.
hc_json_utf8_prefix() {
    hc_presentation_prefix "$1"
    HC_JSON_VALUE="$HC_PRESENT_VALUE"
    [ "$HC_PRESENT_TRUNCATED" = 0 ] || HC_JSON_TRUNCATED=1
    return 0
}
hc_json_finding() {
    [ "$BASHPID" = "$HC_JSON_PID" ] || return 0
    local level="$1" value tracing=0 rank previous
    case $- in *x*) tracing=1; set +x;; esac
    hc_redact "$2"
    value="$HC_PRESENT_VALUE"
    case "$level" in PASS) rank=1;; INFO) rank=2;; WARNING) rank=3;; CRITICAL) rank=4;; ERROR) rank=5;;
        *) HC_JSON_FAILED=1; [ "$tracing" = 0 ] || set -x; return 0;; esac
    HC_JSON_COUNTS[$level]=$(( ${HC_JSON_COUNTS[$level]} + 1 ))
    if [ -n "$HC_JSON_CURRENT" ]; then
        previous="${HC_JSON_RANK[$HC_JSON_CURRENT]:-0}"
        if [ "$rank" -gt "$previous" ]; then
            HC_JSON_RANK[$HC_JSON_CURRENT]=$rank
            hc_json_record state "$HC_JSON_CURRENT" "${level,,}" ''
        fi
    fi
    if [ "$HC_JSON_EVENTS" -lt 1000 ]; then
        hc_json_utf8_prefix "$value"
        hc_json_record finding "$HC_JSON_CURRENT" "$level" "$HC_JSON_VALUE"
        HC_JSON_EVENTS=$((HC_JSON_EVENTS + 1))
    else HC_JSON_TRUNCATED=1; fi
    [ "$tracing" = 0 ] || set -x
}
hc_json_clock() {
    local kind="$1" name="$2" value stamp tick
    local clock_pattern='^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}([.][0-9]+)?[+]00:00[|][0-9]+$'
    if value="$(python3 "$HC_JSON_HELPER" clock)" && [[ "$value" =~ $clock_pattern ]]; then
        IFS='|' read -r stamp tick <<< "$value"
        hc_json_record "$kind" "$name" "$stamp" "$tick"
    else
        HC_JSON_CLOCK_FAILED=1
        printf '%s\n' 'ERROR JSON timing helper failed' >&2
        hc_status ERROR 'JSON timing helper failed'
    fi
}
hc_json_finish() {
    local code=$? host='' payload=''
    trap - EXIT
    HC_JSON_STATE=FINALIZING
    if [ "$code" != 2 ] && { [ "${HC_JSON_COMPLETED:-0}" != 1 ] || [[ ! "$code" =~ ^[01]$ ]]; }; then
        code=2; hc_json_finding ERROR 'Healthcheck execution ended unexpectedly'
    fi
    HC_JSON_CURRENT=''
    hc_json_clock run-end ''
    [ "$HC_JSON_CLOCK_FAILED" = 0 ] || code=2
    if [ "$code" = 2 ] && [ "${HC_JSON_COUNTS[ERROR]}" = 0 ]; then
        hc_json_finding ERROR 'Healthcheck initialization or execution failed; see stderr'
    fi
    hc_json_record counts '' '' "${HC_JSON_COUNTS[PASS]},${HC_JSON_COUNTS[INFO]},${HC_JSON_COUNTS[WARNING]},${HC_JSON_COUNTS[CRITICAL]},${HC_JSON_COUNTS[ERROR]}"
    [ "${HC_RESULTS_TRUNCATED:-0}" = 0 ] || HC_JSON_TRUNCATED=1
    [ "$HC_JSON_TRUNCATED" = 0 ] || hc_json_record truncated '' '' ''
    # Every append opens/closes its descriptor synchronously. This is the LAST write check.
    if [ "$HC_JSON_FAILED" = 1 ]; then
        printf '%s\n' 'ERROR JSON journal failed; output not published' >&2
        code=2
    else
        HC_JSON_STATE=RENDERING
        host="$(hostname -f 2>/dev/null || hostname 2>/dev/null || true)"
        host="${host:0:255}"
        if python3 "$HC_JSON_HELPER" render "$HC_JSON_FILE" "$APP_NAME" "$APP_VERSION" "$code" "$host" "$HC_JSON_BYTES" > "$HC_JSON_RENDERED" &&
           payload="$(python3 "$HC_JSON_HELPER" verify "$HC_JSON_RENDERED" "$code" "$APP_NAME" "$APP_VERSION")" && [ -n "$payload" ]; then
            :
        else
            printf '%s\n' 'ERROR JSON rendering failed; output not published' >&2
            code=2; payload=''
        fi
    fi
    # Cleanup precedes publication; no filesystem operation can change a published status.
    if ! rm -f -- "$HC_JSON_FILE" "$HC_JSON_RENDERED" || ! rmdir -- "$HC_JSON_DIR"; then
        printf '%s\n' 'ERROR JSON scratch cleanup failed; output not published' >&2
        code=2; payload=''
    fi
    if [ -n "$payload" ]; then
        HC_JSON_STATE=PUBLISHED
        trap '' HUP INT TERM
        printf '%s' "$payload" >&3 || exit 2
    fi
    exit "$code"
}
