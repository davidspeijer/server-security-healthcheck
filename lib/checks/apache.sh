#!/usr/bin/env bash
hc_register_check apache

check_apache() {
    hc_enabled "${CHECK_APACHE:-0}" || return 0
    hc_check_service "${APACHE_SERVICE:-httpd}" "Apache" || true
}
