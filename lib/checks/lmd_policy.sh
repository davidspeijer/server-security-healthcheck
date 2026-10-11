#!/usr/bin/env bash
# Helpers for the LMD check, not a separately registered integration.

_lmd_trim() {
    local value="$1"
    value="${value#"${value%%[![:space:]]*}"}"
    printf '%s' "${value%"${value##*[![:space:]]}"}"
}

# Parse literal assignments, never source/eval external configuration. Only the
# requested key is returned: credentials and unrelated values stay
# out of diagnostics. Missing, empty, dynamic and unreadable are distinct states.
# Non-assignment shell statements make the file unknown rather than approximating
# conditionals, includes or unset. Repeated unconditional assignments: last wins.
_lmd_config_get() {
    if [ "${lmd_cache_active:-0}" = 1 ] && [ "${lmd_file_status[$1]+set}" ]; then
        local entry="$1|$2" rc="${lmd_file_status[$1]}"
        [ "$rc" = 0 ] || return "$rc"
        rc="${lmd_key_status[$entry]:-1}"
        [ "$rc" = 0 ] || return "$rc"
        printf '%s' "${lmd_values[$entry]}"
        return 0
    fi
    [ -f "$1" ] && [ -r "$1" ] || return 3
    local contents
    contents="$(hc_data_parse bounded "$1" 2>/dev/null)" || return 3
    _lmd_config_stream "$2" <<< "$contents"
}

_lmd_config_stream() {
    local parse_started=$SECONDS
    local wanted="$1" cache_file="${2:-}" line key value quote rest entry found=0 invalid=0
    local assignment='^(export[[:space:]]+)?([a-zA-Z_][a-zA-Z0-9_]*)[[:space:]]*=(.*)$'
    value=''
    while IFS= read -r line || [ -n "$line" ]; do
        if hc_budget_expired "$parse_started"; then return 3; fi
        line="${line%$'\r'}"
        line="${line#"${line%%[![:space:]]*}"}"
        line="${line%"${line##*[![:space:]]}"}"
        [[ -z "$line" || "$line" = \#* ]] && continue
        [[ "$line" =~ $assignment ]] || return 2
        key="${BASH_REMATCH[2]}" rest="${BASH_REMATCH[3]}"
        [ -n "$cache_file" ] || [ "$key" = "$wanted" ] || continue
        found=1 invalid=0 quote=''
        value="${rest#"${rest%%[![:space:]]*}"}"
        value="${value%"${value##*[![:space:]]}"}"
        if [[ "$value" = \"* || "$value" = \'* ]]; then
            quote="${value:0:1}" value="${value:1}"
            if [[ "$value" != *"$quote"* ]]; then invalid=1; fi
            rest="${value#*"$quote"}" value="${value%%"$quote"*}"
            [[ "$rest" =~ ^[[:space:]]*(#.*)?$ ]] || invalid=1
        else
            value="${value%%[[:space:]]#*}"
            value="${value%"${value##*[![:space:]]}"}"
            [[ "$value" != *[[:space:]]* ]] || invalid=1
            case "$value" in *';'*|*'|'*|*'&'*|*'<'*|*'>'*|*'('*|*')'*) invalid=1 ;; esac
        fi
        # Reject expansions even inside quotes: their effective value would depend
        # on LMD's shell context, which a read-only policy check must not execute.
        case "$value" in *'$'*|*'`'*|*"\\"*) invalid=1 ;; esac
        if [ -n "$cache_file" ]; then
            entry="$cache_file|$key"
            lmd_key_status[$entry]=$((invalid * 2))
            lmd_values[$entry]="$value"
        fi
    done
    [ -z "$cache_file" ] || return 0
    [ "$found" -eq 1 ] || return 1
    [ "$invalid" -eq 0 ] || return 2
    printf '%s' "$value"
}

# Compatibility migrations are data only within this deliberately small grammar.
# Helpers use the caller's local maps; names originate from validated identifiers.
_lmd_compat_load() {
    local name="$1" result rc
    [ "${compat_state[$name]+set}" ] && return 0
    result="$(_lmd_config_get "$LMD_POLICY_MAIN" "$name")"; rc=$?
    case "$rc" in
        0|1) compat_state[$name]=known; compat_value[$name]="$result" ;;
        *) compat_state[$name]=unknown; compat_value[$name]='' ;;
    esac
}

# Patterns below intentionally contain literal shell variable syntax.
# shellcheck disable=SC2016
_lmd_compat_compute() {
    local parse_started=$SECONDS
    local contents
    local file="$1" line mode='' target='' source='' guard='' stage=0 value rc condition
    local fallback='^if \[ ! "\$([a-zA-Z_][a-zA-Z0-9_]*)" \] && \[ "\$([a-zA-Z_][a-zA-Z0-9_]*)" \]; then$'
    local assignment='^(export[[:space:]]+)?([a-zA-Z_][a-zA-Z0-9_]*)[[:space:]]*='
    [ -f "$file" ] && [ -r "$file" ] || return 3
    contents="$(hc_data_parse bounded "$file" 2>/dev/null)" || return 3
    while IFS= read -r line || [ -n "$line" ]; do
        if hc_budget_expired "$parse_started"; then return 3; fi
        line="${line%$'\r'}"
        line="${line#"${line%%[![:space:]]*}"}"
        line="${line%"${line##*[![:space:]]}"}"
        [[ -z "$line" || "$line" = \#* ]] && continue
        if [ "$stage" = 1 ]; then
            [ "$line" = "$target=\"\$$source\"" ] || return 2
            stage=2
            continue
        elif [ "$stage" = 2 ]; then
            [ "$line" = "fi" ] || return 2
            stage=0
            _lmd_compat_load "$target"
            _lmd_compat_load "$source"
            condition=yes
            if [ "$mode" = fallback ]; then
                if [ "${compat_state[$target]}" = unknown ]; then condition=unknown
                elif [ -n "${compat_value[$target]}" ]; then condition=no; fi
            elif [ "$mode" = depth ]; then
                _lmd_compat_load "$guard"
                if [ "${compat_state[$guard]}" = unknown ]; then condition=unknown
                elif [ "${compat_value[$guard]}" != 1 ]; then condition=no; fi
            fi
            # Every supported migration also requires a nonempty source.
            if [ "${compat_state[$source]}" = known ] && [ -z "${compat_value[$source]}" ]; then condition=no; fi
            [ "$condition" != no ] || continue
            compat_changed[$target]=1
            if [ "$condition" = unknown ] || [ "${compat_state[$source]}" = unknown ]; then
                compat_state[$target]=unknown
            else
                compat_state[$target]=known
                compat_value[$target]="${compat_value[$source]}"
            fi
            continue
        fi
        if [[ "$line" =~ $fallback ]]; then
            target="${BASH_REMATCH[1]}" source="${BASH_REMATCH[2]}" mode=fallback stage=1
        elif [ "$line" = 'if [ "${scan_hexfifo:-0}" = "1" ] && [ "$scan_hexfifo_depth" ]; then' ]; then
            target=scan_hexdepth source=scan_hexfifo_depth guard=scan_hexfifo mode=depth stage=1
        elif [ "$line" = 'if [ "$scan_hex_workers" ]; then' ]; then
            target=scan_workers source=scan_hex_workers mode=source stage=1
        elif [[ "$line" =~ $assignment ]]; then
            target="${BASH_REMATCH[2]}"
            value="$(_lmd_config_stream "$target" <<< "$line")"; rc=$?
            compat_changed[$target]=1
            compat_value[$target]="$value"
            if [ "$rc" = 0 ]; then compat_state[$target]=known; else return 2; fi
        else
            return 2
        fi
    done <<< "$contents"
    [ "$stage" = 0 ] || return 2
    return 0
}

_lmd_compat_get() {
    local wanted="$2" rc
    if [ "${lmd_cache_active:-0}" = 1 ] && [ "$1" = "$LMD_POLICY_COMPAT" ]; then
        rc="$lmd_compat_status"
    else
        local -A compat_state=() compat_value=() compat_changed=()
        _lmd_compat_compute "$1"; rc=$?
    fi
    [ "$rc" = 0 ] || return "$rc"
    [ "${compat_changed[$wanted]:-0}" = 1 ] || return 1
    [ "${compat_state[$wanted]}" = known ] || return 2
    printf '%s' "${compat_value[$wanted]}"
}

_lmd_policy_get() {
    if [ "$1" = "${LMD_POLICY_COMPAT:-}" ]; then
        _lmd_compat_get "$1" "$2"
    else
        _lmd_config_get "$1" "$2"
    fi
}

_lmd_policy_compare() {
    local file="$1" key="$2" expected="$3" label="$4" optional="${5:-0}" value status
    [ "$expected" = ignore ] && return 0
    value="$(_lmd_policy_get "$file" "$key")"; status=$?
    if [ "$status" -eq 1 ] && [ "$optional" = 1 ]; then return 0; fi
    case "$status" in
        1) hc_warn "LMD $label: $key missing in $file" ;;
        2) hc_warn "LMD $label: $key cannot be safely resolved in $file" ;;
        3) hc_warn "LMD $label: configuration unavailable: $file" ;;
        0)
            if [ "$value" = "$expected" ]; then
                case "$key" in
                    import_config_url|post_scan_hook) hc_status PASS "LMD $label: $key matches expected policy" ;;
                    *) hc_status PASS "LMD $label: $key=$value matches expected policy" ;;
                esac
            else
                # Do not print imported URLs, hook commands or other external
                # values: those may contain credentials or terminal control data.
                hc_warn "LMD $label: $key differs from expected policy ($file)"
            fi ;;
    esac
}

_lmd_policy_setting() {
    local key="$1" expected="$2" file
    _lmd_policy_compare "$LMD_POLICY_MAIN" "$key" "$expected" 'base configuration'
    # These overlays can affect normal maldet invocations or cron scans too.
    # Update switches intentionally differ in cron and are handled separately.
    for file in "$LMD_POLICY_COMPAT" "$LMD_POLICY_ENV" "$LMD_POLICY_CRON"; do
        [ -e "$file" ] || continue
        _lmd_policy_compare "$file" "$key" "$expected" 'configuration override' 1
    done
}

_lmd_effective_config_value() {
    local key="$1" scope="$2" file value='' next status
    local -a files=("$LMD_POLICY_MAIN" "$LMD_POLICY_COMPAT" "$LMD_POLICY_ENV")
    [ "$scope" != daily ] || files+=("$LMD_POLICY_CRON")
    for file in "${files[@]}"; do
        [ -e "$file" ] || continue
        next="$(_lmd_policy_get "$file" "$key")"; status=$?
        case "$status" in
            0) value="$next" ;;
            1) ;;
            *) return 2 ;;
        esac
    done
    [ -n "$value" ] || return 1
    printf '%s' "$value"
}

# Compare complete supported daily layouts; this is not a shell interpreter.
# Extra statements/control flow are UNKNOWN; never execute the cron script.
_lmd_daily_contract() {
    local file="$1"
    [ -f "$file" ] && [ -r "$file" ] && [ -x "$file" ] || return 1
    # Full-file bounded contract: no extra statements, wrappers or control flow.
    # Syntax checking parses only; it never executes the script.
    local actual expected contents
    contents="$(hc_data_parse bounded "$file" 2>/dev/null)" || return 1
    bash -n <<< "$contents" 2>/dev/null || return 1
    actual="$(sed '/^[[:space:]]*#/d; /^[[:space:]]*$/d' <<< "$contents")" || return 1
    expected="$(cat <<EOF
inspath='${LMD_DIR:-/usr/local/maldetect}'
intcnf="\$inspath/internals/internals.conf"
if [ -f "\$intcnf" ]; then
. \$intcnf
fi
if [ -f "\$cnf" ]; then
. \$cnf
if [ -f "\$compatcnf" ]; then
. \$compatcnf
fi
fi
if [ -f "/etc/sysconfig/maldet" ]; then
. /etc/sysconfig/maldet
elif [ -f "/etc/default/maldet" ]; then
. /etc/default/maldet
fi
if [ -f "\$cron_custom_conf" ]; then
. \$cron_custom_conf
fi
if [ "\$autoupdate_version" == "1" ]; then
\$inspath/maldet -d 1 2>&1 | tail -20 >> "\$maldet_log"
fi
if [ "\$autoupdate_signatures" == "1" ]; then
\$inspath/maldet -u 1 2>&1 | tail -20 >> "\$maldet_log"
fi
EOF
)" || return 1
    # Only leading/trailing whitespace is immaterial; quoting remains semantic.
    actual="$(sed 's/^[[:space:]]*//; s/[[:space:]]*$//' <<< "$actual")" || return 1
    [ "$actual" = "$expected" ] || hc_data_parse daily "$file" "${LMD_DIR:-/usr/local/maldetect}" >/dev/null 2>&1
}

_lmd_daily_bindings() {
    local file="${LMD_DIR:-/usr/local/maldetect}/internals/internals.conf"
    [ -r "$file" ] || return 1
    # Resolve only the documented variable bindings, not arbitrary shell paths.
    # This prevents treating a same-named but unused override file as effective.
    local contents
    contents="$(hc_data_parse bounded "$file" 2>/dev/null)" || return 1
    awk '
        BEGIN {
            want["confpath"]="$inspath"; want["cnffile"]="conf.maldet"
            want["cnf"]="$confpath/$cnffile"; want["libpath"]="$inspath/internals"
            want["compatcnf"]="$libpath/compat.conf"
            want["cron_custom_conf"]="$confpath/cron/conf.maldet.cron"
            want["cron_custom_exec"]="$confpath/cron/custom.cron"
        }
        /^[[:space:]]*#/ {next}
        {s=$0; gsub(/[[:space:]"\047]/,"",s); p=index(s,"="); if(p) {k=substr(s,1,p-1); if(k in want) {seen[k]=1; if(substr(s,p+1)!=want[k])bad=1}}}
        END {for(k in want)if(!seen[k])bad=1; exit bad}
    ' <<< "$contents"
}

# Tokenize only simple literal cron commands. Quotes preserve spaces; shell
# expansion, substitutions, control operators and cron percent expansion are
# rejected. Redirection tokens are validated separately, never interpreted.
_lmd_cron_tokens() {
    local input="$1" char quote='' token='' started=0 index
    LMD_CRON_TOKENS=()
    for ((index=0; index<${#input}; index++)); do
        char="${input:index:1}"
        case "$char" in '$'|'`'|"\\"|'%'|';'|'|'|'('|')') return 1 ;; esac
        if [ -n "$quote" ]; then
            if [ "$char" = "$quote" ]; then quote=''; else token+="$char"; fi
        else
            case "$char" in
                "'"|'"') quote="$char"; started=1 ;;
                '*'|'?'|'[') return 1 ;; # unquoted cron arguments would undergo shell globbing
                ' '|$'\t')
                    if [ "$started" -eq 1 ]; then LMD_CRON_TOKENS+=("$token"); token=''; started=0; fi ;;
                *) token+="$char"; started=1 ;;
            esac
        fi
    done
    [ -z "$quote" ] || return 1
    if [ "$started" -eq 1 ]; then LMD_CRON_TOKENS+=("$token"); fi
}

_lmd_cron_redirects() {
    local index="$1" token
    while [ "$index" -lt "${#LMD_CRON_TOKENS[@]}" ]; do
        token="${LMD_CRON_TOKENS[index]}"
        case "$token" in
            '>'|'>>'|'2>'|'2>>')
                index=$((index + 1))
                [[ "${LMD_CRON_TOKENS[index]:-}" = /* ]] || return 1
                case "${LMD_CRON_TOKENS[index]}" in *'&'*|*'<'*|*'>'*) return 1 ;; esac ;;
            '2>&1'|'>/dev/null'|'>>/dev/null') ;;
            *) return 1 ;;
        esac
        index=$((index + 1))
    done
}

_lmd_check_cron_rule() {
    local parse_started=$SECONDS
    local contents
    local file="$1" kind="$2" expected="$3" line min hour dom month dow user command schedule count=0 bad=0 index
    local binary="${LMD_DIR:-/usr/local/maldetect}/maldet"
    [ -r "$file" ] && [ -f "$file" ] || { hc_warn "LMD $kind cron file unavailable: $file"; return; }
    contents="$(hc_data_parse bounded "$file" 2>/dev/null)" || { hc_warn "LMD cron input UNKNOWN: $file"; return; }
    while IFS= read -r line || [ -n "$line" ]; do
        if hc_budget_expired "$parse_started"; then hc_warn 'LMD cron processing budget exceeded'; return; fi
        line="$(_lmd_trim "$line")"
        [[ -z "$line" || "$line" = \#* ]] && continue
        # Environment directives can change cron interpretation; do not silently
        # assert the usual local-time schedule for a CRON_TZ/custom-shell context.
        if [[ "$line" =~ ^[A-Za-z_][A-Za-z0-9_]*[[:space:]]*= ]]; then
            hc_warn "LMD $kind cron has environment directives; schedule context requires review ($file)"
            bad=1; continue
        fi
        count=$((count + 1))
        read -r min hour dom month dow user command <<< "$line"
        schedule="$min $hour $dom $month $dow"
        if { [ "$expected" != ignore ] && [ "$schedule" != "$expected" ]; } || [ "$user" != root ]; then
            hc_warn "LMD $kind cron schedule/user mismatch; expected '$expected root' ($file)"; bad=1
        fi
        if ! _lmd_cron_tokens "$command"; then
            hc_warn "LMD $kind cron command is not safely recognizable ($file)"; bad=1; continue
        fi
        index=0
        if [ "$kind" = fullscan ]; then
            if [ "${LMD_CRON_TOKENS[0]:-}" != /usr/bin/flock ] || [ "${LMD_CRON_TOKENS[1]:-}" != -n ] ||
                [[ "${LMD_CRON_TOKENS[2]:-}" != /* ]]; then
                hc_warn "LMD fullscan cron: expected /usr/bin/flock -n with an absolute lock path ($file)"; bad=1; continue
            fi
            index=3
        fi
        if [ "${LMD_CRON_TOKENS[index]:-}" != "$binary" ]; then
            hc_warn "LMD $kind cron executable mismatch or unsupported wrapper ($file)"; bad=1; continue
        fi
        index=$((index + 1))
        if [ "$kind" = sigup ]; then
            if [ "${LMD_CRON_TOKENS[index]:-}" != --cron-sigup ]; then
                hc_warn "LMD sigup cron: expected independent --cron-sigup command ($file)"; bad=1; continue
            fi
            index=$((index + 1))
        else
            if [ "${LMD_CRON_TOKENS[index]:-}" != -b ] || [ "${LMD_CRON_TOKENS[index+1]:-}" != -a ] ||
                [ "${LMD_CRON_TOKENS[index+2]:-}" != "${LMD_EXPECTED_FULLSCAN_PATH:-/home/?/domains/?/public_html/}" ]; then
                hc_warn "LMD fullscan cron arguments/target mismatch ($file)"; bad=1; continue
            fi
            index=$((index + 3))
        fi
        if ! _lmd_cron_redirects "$index"; then
            hc_warn "LMD $kind cron has unsupported trailing arguments/commands ($file)"; bad=1
        fi
    done <<< "$contents"
    if [ "$count" -ne 1 ]; then hc_warn "LMD $kind cron: expected exactly one active job, found $count ($file)"; bad=1; fi
    local final_newline
    final_newline="$(hc_data_parse final-newline "$file" 2>/dev/null)" || final_newline=unknown
    if [ "$final_newline" != 1 ]; then hc_warn "LMD $kind cron: missing final newline ($file)"; bad=1; fi
    [ "$bad" -ne 0 ] || hc_status PASS "LMD $kind cron definition matches expected schedule and command"
    return 0
}

_lmd_check_monitor_config() {
    hc_enabled "${LMD_MONITOR_REQUIRED:-1}" || return 0
    local sysconfig="$1" default="$2" expected="$3" value=''
    [ "$expected" = ignore ] && return 0
    [ "${LMD_MONITOR_AVAILABLE:-1}" = 1 ] || return 0
    hc_have systemctl || { hc_warn 'LMD monitor configuration: systemctl unavailable'; return; }
    if ! value="$(set -o pipefail; hc_systemctl cat "${LMD_SERVICE:-maldet.service}" 2>/dev/null |
        hc_data_parse monitor "${LMD_DIR:-/usr/local/maldetect}" "$sysconfig" "$default" 2>/dev/null)"; then
        hc_warn 'LMD monitor unit/environment is unsupported or unreadable (export is not a systemd EnvironmentFile assignment); effective MONITOR_MODE unknown'
        return
    fi
    if [ -z "$value" ]; then
        value="$(_lmd_effective_config_value default_monitor_mode runtime)" || {
            hc_warn 'LMD MONITOR_MODE and default_monitor_mode are missing/unreadable'; return;
        }
        hc_detail 'LMD monitor mode uses default_monitor_mode fallback'
    fi
    if [ "$value" = "$expected" ]; then hc_status PASS 'LMD effective MONITOR_MODE matches expected monitor target'
    else hc_warn 'LMD effective MONITOR_MODE differs from expected monitor target'; fi
}

_lmd_check_retention() {
    local max_age="${LMD_FULLSCAN_MAX_AGE_HOURS:-}" days="${FULLSCAN_MAX_AGE_DAYS:-8}"
    local margin="${LMD_FULLSCAN_RETENTION_MARGIN_HOURS:-24}" minimum scope value status origin
    if [ -z "$max_age" ]; then
        hc_uint "$days" && [ "$days" -gt 0 ] || { hc_status ERROR 'LMD fullscan age limit invalid'; return; }
        max_age=$((days * 24))
    fi
    if ! hc_uint "$max_age" || [ "$max_age" -eq 0 ] || ! hc_uint "$margin" || [ "$margin" -eq 0 ]; then
        hc_status ERROR 'LMD fullscan age limit or retention margin invalid'; return
    fi
    minimum=$((max_age + margin))
    # Cleanup can run during other non-hook scans too. Resolve both configured
    # contexts so a daily override cannot silently shorten weekly scan history.
    for scope in runtime daily; do
        origin='configured'
        value="$(_lmd_effective_config_value scan_meta_cleanup_age "$scope")"; status=$?
        case "$status" in
            0) ;;
            1) value=24; origin='LMD 2.0.1 fallback (missing/empty setting)' ;;
            *) hc_warn "LMD $scope scan_meta_cleanup_age UNKNOWN: configuration cannot be safely resolved"; continue ;;
        esac
        if ! hc_uint "$value"; then
            hc_warn "LMD $scope scan_meta_cleanup_age UNKNOWN: expected unsigned decimal hours or 0; minimum ${minimum}h"
        elif [ "$value" -eq 0 ]; then
            hc_status PASS "LMD $scope scan_meta_cleanup_age=0: lifecycle cleanup disabled"
        elif [ "$value" -lt "$minimum" ]; then
            hc_warn "LMD $scope scan_meta_cleanup_age=${value}h ($origin) is below required ${minimum}h (fullscan age ${max_age}h + margin ${margin}h); completion evidence may be removed too early"
        else
            hc_status PASS "LMD $scope scan_meta_cleanup_age=${value}h meets minimum ${minimum}h (fullscan age ${max_age}h + margin ${margin}h)"
        fi
    done
}

_lmd_check_configuration() {
    hc_enabled "${LMD_CONFIG_CHECK_ENABLED:-1}" || return 0
    local root="${LMD_DIR:-/usr/local/maldetect}" sysconfig default key value expected status file
    LMD_POLICY_MAIN="${LMD_CONFIG_FILE:-$root/conf.maldet}"
    LMD_POLICY_CRON="${LMD_CRON_CONFIG_FILE:-$root/cron/conf.maldet.cron}"
    LMD_POLICY_COMPAT="${LMD_COMPAT_CONFIG_FILE:-$root/internals/compat.conf}"
    sysconfig="${LMD_SYSCONFIG_FILE:-/etc/sysconfig/maldet}" default="${LMD_DEFAULT_FILE:-/etc/default/maldet}"
    # The daily script uses if/elif, unlike systemd EnvironmentFile processing.
    LMD_POLICY_ENV="$default"
    [ ! -e "$sysconfig" ] || LMD_POLICY_ENV="$sysconfig"
    [ -r "$LMD_POLICY_MAIN" ] || { hc_warn "LMD configuration unavailable: $LMD_POLICY_MAIN"; return; }

    # Build the snapshot in the parent shell, before command substitutions read it.
    # Dynamic local scope limits cache lifetime to this invocation (also on errors).
    local lmd_cache_active=1 lmd_compat_status=0
    local -A lmd_file_status=() lmd_key_status=() lmd_values=()
    local -A compat_state=() compat_value=() compat_changed=()
    for file in "$LMD_POLICY_MAIN" "$sysconfig" "$default" "$LMD_POLICY_CRON"; do
        [ ! "${lmd_file_status[$file]+set}" ] || continue
        if [ -f "$file" ] && [ -r "$file" ]; then
            # The file argument identifies the in-memory cache; no file is written.
            # shellcheck disable=SC2094
            if value="$(hc_data_parse bounded "$file" 2>/dev/null)"; then
                _lmd_config_stream '' "$file" <<< "$value"; status=$?
            else status=3; fi
        else
            status=3
        fi
        lmd_file_status[$file]="$status"
    done
    _lmd_compat_compute "$LMD_POLICY_COMPAT"; lmd_compat_status=$?

    _lmd_check_retention
    _lmd_policy_setting email_alert "${LMD_EXPECT_EMAIL_ALERT:-1}"
    _lmd_policy_setting scan_clamscan "${LMD_EXPECT_SCAN_CLAMSCAN:-auto}"
    _lmd_policy_setting quarantine_hits "${LMD_EXPECT_QUARANTINE_ENABLED:-0}"
    _lmd_policy_setting quarantine_clean "${LMD_EXPECT_QUARANTINE_CLEAN:-0}"
    _lmd_policy_setting quarantine_suspend_user "${LMD_EXPECT_QUARANTINE_SUSPEND_USER:-0}"
    _lmd_policy_setting quarantine_on_error "${LMD_EXPECT_QUARANTINE_ON_ERROR:-0}"
    _lmd_policy_setting inotify_sleep "${LMD_EXPECT_INOTIFY_SLEEP:-15}"
    _lmd_policy_setting inotify_reloadtime "${LMD_EXPECT_INOTIFY_RELOADTIME:-3600}"
    # Use '-' rather than ':-': an explicitly empty expectation is a real policy.
    _lmd_policy_setting import_config_url "${LMD_EXPECT_IMPORT_CONFIG_URL-}"
    _lmd_policy_setting post_scan_hook "${LMD_EXPECT_POST_SCAN_HOOK-}"
    _lmd_policy_compare "$LMD_POLICY_MAIN" autoupdate_signatures "${LMD_EXPECT_AUTOUPDATE_SIGNATURES:-1}" 'base signature policy'
    _lmd_policy_compare "$LMD_POLICY_MAIN" sigup_interval "${LMD_EXPECT_SIGUP_INTERVAL:-6}" 'signature interval'
    _lmd_policy_compare "$LMD_POLICY_MAIN" autoupdate_version "${LMD_EXPECT_AUTOUPDATE_VERSION:-1}" 'base program policy'
    _lmd_policy_compare "$LMD_POLICY_CRON" autoupdate_signatures "${LMD_EXPECT_CRON_AUTOUPDATE_SIGNATURES:-0}" 'daily signature override'
    _lmd_policy_compare "$LMD_POLICY_CRON" autoupdate_version "${LMD_EXPECT_CRON_AUTOUPDATE_VERSION:-0}" 'daily program override'

    for key in scan_workers scan_hashtype cron_prune_days email_addr email_subj; do
        value="$(_lmd_config_get "$LMD_POLICY_MAIN" "$key")"; status=$?
        case "$status" in
            0)
                case "$key" in
                    scan_workers) expected="${LMD_EXPECT_SCAN_WORKERS:-auto}" ;;
                    cron_prune_days) expected="${LMD_EXPECT_CRON_PRUNE_DAYS:-21}" ;;
                    *) expected='' ;;
                esac
                if [ "$key" = email_addr ] || [ "$key" = email_subj ]; then
                    if [ -n "$value" ]; then value=configured; else value=empty; fi
                fi
                hc_detail "LMD tuning $key: $value${expected:+ (preferred: $expected; not enforced)}" ;;
            *) hc_detail "LMD tuning $key: unavailable or not a literal assignment (not enforced)" ;;
        esac
    done
    _lmd_check_monitor_config "$sysconfig" "$default" "${LMD_EXPECT_MONITOR_MODE:-${LMD_WEBROOT_LIST:-${LMD_MONITOR_LIST:-$root/directadmin-webroots}}}"
    if _lmd_daily_bindings && _lmd_daily_contract "${LMD_DAILY_CRON_FILE:-/etc/cron.daily/maldet}"; then
        for key in autoupdate_version autoupdate_signatures; do
            value="$(_lmd_effective_config_value "$key" daily)" || { hc_warn "LMD effective daily $key is unknown"; continue; }
            if [ "$key" = autoupdate_version ]; then expected="${LMD_EXPECT_CRON_AUTOUPDATE_VERSION:-0}"
            else expected="${LMD_EXPECT_CRON_AUTOUPDATE_SIGNATURES:-0}"; fi
            if [ "$expected" = ignore ]; then continue; fi
            if [ "$value" != "$expected" ]; then hc_warn "LMD effective daily $key differs from expected policy"
            elif [ "$value" = 0 ]; then hc_detail "LMD daily $key intentionally disabled after configuration overrides"
            else hc_status PASS "LMD daily $key enabled after configuration overrides"; fi
            if [ "$key" = autoupdate_version ] && [ "${LMD_PROGRAM_UPDATE_EXPECTED:-disabled}" != ignore ]; then
                if { [ "${LMD_PROGRAM_UPDATE_EXPECTED:-disabled}" = disabled ] && [ "$value" != 0 ]; } ||
                    { [ "${LMD_PROGRAM_UPDATE_EXPECTED:-disabled}" = enabled ] && [ "$value" != 1 ]; }; then
                    hc_warn 'LMD effective daily program updates conflict with LMD_PROGRAM_UPDATE_EXPECTED'
                fi
            fi
        done
    else
        hc_warn 'LMD daily cron missing, not executable or unsupported source/guard layout; effective update behavior UNKNOWN'
    fi
    # A custom daily hook can bypass the checked update guards entirely.
    file="$root/cron/custom.cron"
    if [ -e "$file" ] || [ -L "$file" ]; then
        local hook_contents
        if ! hook_contents="$(hc_data_parse bounded "$file" 2>/dev/null)"; then
            hc_status ERROR 'LMD daily custom.cron input UNKNOWN: read/resource limit failure'
        else
            local hook_status
            grep -Eq '^[[:space:]]*[^#[:space:]]' <<< "$hook_contents" 2>/dev/null
            hook_status=$?
            case "$hook_status" in
                0) hc_warn 'LMD daily custom.cron contains commands or is unreadable; additional behavior requires review' ;;
                1) ;;
                *) hc_status ERROR 'LMD daily custom.cron classification failed' ;;
            esac
        fi
    fi
    if [ -d /usr/share/dtc ] && [ -e /var/lib/dtc/saved_install_config ]; then
        hc_warn 'LMD daily cron can import DTC configuration; additional behavior requires review'
    fi
    expected="0 */${LMD_EXPECT_SIGUP_INTERVAL:-6} * * *"
    [ "${LMD_EXPECT_SIGUP_INTERVAL:-6}" != ignore ] || expected=ignore
    _lmd_check_cron_rule "${LMD_SIGUP_CRON_FILE:-/etc/cron.d/maldet-sigup}" sigup "${LMD_EXPECT_SIGUP_SCHEDULE:-$expected}"
    _lmd_check_cron_rule "${LMD_FULLSCAN_CRON_FILE:-/etc/cron.d/maldet-fullscan}" fullscan "${LMD_EXPECT_FULLSCAN_SCHEDULE:-30 0 * * 0}"
    hc_detail 'LMD cron checks describe static definitions; scan completion and update activity are checked separately'
}
