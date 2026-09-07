#!/usr/bin/env bash
hc_register_check rspamd

check_rspamd() {
    local mode
    mode="$(hc_mode "${CHECK_RSPAMD:-auto}")"
    [ "$mode" = "off" ] && return 0

    if [ "$mode" = "auto" ] &&
        ! hc_service_present "${RSPAMD_SERVICE:-rspamd}" rspamd rspamadm; then
        return 0
    fi

    hc_check_service "${RSPAMD_SERVICE:-rspamd}" "Rspamd" || true
}
