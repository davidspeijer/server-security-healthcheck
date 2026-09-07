#!/usr/bin/env bash
hc_register_check pureftpd

check_pureftpd() {
    local mode
    mode="$(hc_mode "${CHECK_PUREFTP:-auto}")"
    [ "$mode" = "off" ] && return 0

    if [ "$mode" = "auto" ] &&
        ! hc_service_present "${PUREFTP_UPLOADSCAN_SERVICE:-pure-uploadscript}" pure-ftpd pure-uploadscript; then
        return 0
    fi

    hc_check_service "${PUREFTP_UPLOADSCAN_SERVICE:-pure-uploadscript}" "PureFTP upload scanner" || true
}
