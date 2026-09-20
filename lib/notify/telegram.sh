#!/usr/bin/env bash

notify_telegram() {
    local message="$1"

    hc_enabled "${NOTIFY_TELEGRAM:-0}" || return 0

    if [ -z "${TELEGRAM_BOT_TOKEN:-}" ] || [ -z "${TELEGRAM_CHAT_ID:-}" ]; then
        hc_log "ERROR Telegram enabled but TELEGRAM_BOT_TOKEN/TELEGRAM_CHAT_ID missing"
        return 1
    fi

    if ! hc_have curl; then
        hc_log "ERROR curl is required for Telegram notifications"
        return 1
    fi

    # Telegram limits messages to 4096 characters. Keep bounded diagnostics in
    # notifications; the CLI/journal retains full paths and per-hit details.
    if [ "${#message}" -gt 3500 ]; then
        message="${message:0:3500}"$'\n… Truncated; see the healthcheck CLI/systemd journal for full details.'
    fi

    curl -fsS --max-time 20 \
        -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
        --data-urlencode "chat_id=${TELEGRAM_CHAT_ID}" \
        --data-urlencode "text=${message}" \
        >/dev/null
}

notify_test() {
    notify_telegram "Server Security Healthcheck test from $(hostname -f 2>/dev/null || hostname)"
}
