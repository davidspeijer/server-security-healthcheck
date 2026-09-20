#!/usr/bin/env bash
hc_register_check exim

check_exim() {
    local mode
    mode="$(hc_mode "${CHECK_EXIM:-0}")"
    [ "$mode" = off ] && return 0
    if [ "$mode" = auto ] && ! hc_service_present "${EXIM_SERVICE:-exim}" exim; then return 0; fi

    hc_check_service "${EXIM_SERVICE:-exim}" "Exim" || true

    if ! hc_have exim; then
        hc_warn "Exim: binary not found"
        return
    fi

    local queue
    queue="$(exim -bpc 2>/dev/null || echo -1)"

    if [[ "$queue" =~ ^[0-9]+$ ]]; then
        hc_detail "Exim queue: $queue"
        if [ "$queue" -ge "${MAILQUEUE_WARN:-25}" ]; then
            hc_warn "Exim: queue contains $queue messages (threshold ${MAILQUEUE_WARN:-25})"
        fi
    else
        hc_warn "Exim: unable to read mail queue"
    fi
}
