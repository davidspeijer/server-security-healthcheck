#!/usr/bin/env bash

_telegram_send() {
    local message="$1" value LC_ALL=C
    hc_enabled "${NOTIFY_TELEGRAM:-0}" || return 0
    if [[ ! "${TELEGRAM_BOT_TOKEN:-}" =~ ^[0-9]+:[A-Za-z0-9_-]+$ ]] ||
       [[ ! "${TELEGRAM_CHAT_ID:-}" =~ ^(-?[0-9]+|@[A-Za-z0-9_]+)$ ]]; then
        hc_log 'ERROR Telegram credentials missing or malformed'
        return 1
    fi
    hc_have curl || { hc_log 'ERROR curl is required for Telegram notifications'; return 1; }
    if [ "${#message}" -gt 3500 ]; then
        message="$(printf '%s' "${message:0:3500}" | hc_data_parse telegram-prefix)" || {
            hc_log 'ERROR Telegram message encoding failed'; return 1;
        }
        message="$message"$'\n… Truncated; see the healthcheck CLI/systemd journal for full details.'
    fi
    # Bash builtins write a config over stdin: no credential-bearing child argv,
    # exported environment, or temporary file. Suppress curl URL diagnostics.
    if ! ( set -o pipefail; {
        printf 'url = "https://api.telegram.org/bot%s/sendMessage"\n' "$TELEGRAM_BOT_TOKEN"
        printf 'data-urlencode = "chat_id=%s"\n' "$TELEGRAM_CHAT_ID"
        value="${message//\\/\\\\}"; value="${value//\"/\\\"}"
        value="${value//$'\n'/\\n}"; value="${value//$'\r'/\\r}"; value="${value//$'\t'/\\t}"
        printf 'data-urlencode = "text=%s"\n' "$value"
    } | curl --config - -fsS --max-time 20 -X POST 2>/dev/null | hc_data_parse telegram >/dev/null 2>&1 ); then
        hc_log 'ERROR Telegram application response failed (transport failed or API rejected)'
        return 1
    fi
}

notify_telegram() {
    local tracing=0 result
    case $- in *x*) tracing=1; set +x ;; esac
    _telegram_send "$@"; result=$?
    [ "$tracing" = 0 ] || set -x
    return "$result"
}

notify_test() {
    notify_telegram "Server Security Healthcheck test from $(hc_present "$(hostname -f 2>/dev/null || hostname)")"
}
