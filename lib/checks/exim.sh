#!/usr/bin/env bash
hc_register_check exim

check_exim() {
    hc_enabled "${CHECK_EXIM:-0}" || return 0

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
