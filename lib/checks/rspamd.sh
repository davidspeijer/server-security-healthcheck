#!/usr/bin/env bash
hc_register_check rspamd

check_rspamd() {
    hc_enabled "${CHECK_RSPAMD:-0}" || return 0
    hc_check_service "${RSPAMD_SERVICE:-rspamd}" "Rspamd" || true
}
