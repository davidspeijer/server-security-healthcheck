#!/usr/bin/env bash
hc_register_check pureftpd

check_pureftpd() {
    hc_enabled "${CHECK_PUREFTP:-0}" || return 0
    hc_check_service "${PUREFTP_UPLOADSCAN_SERVICE:-pure-uploadscript}" "PureFTP upload scanner" || true
}
