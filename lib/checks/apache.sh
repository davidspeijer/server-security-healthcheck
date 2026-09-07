#!/usr/bin/env bash
hc_register_check apache

check_apache() {
    local mode
    mode="$(hc_mode "${CHECK_APACHE:-auto}")"
    [ "$mode" = "off" ] && return 0

    if [ "$mode" = "auto" ] &&
        ! hc_service_present "${APACHE_SERVICE:-httpd}" httpd apachectl apache2ctl; then
        return 0
    fi

    hc_check_service "${APACHE_SERVICE:-httpd}" "Apache" || true
}
