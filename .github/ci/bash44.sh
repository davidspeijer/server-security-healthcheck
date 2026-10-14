#!/usr/bin/env bash
set -euo pipefail
[[ ${BASH_VERSINFO[0]} == 4 && ${BASH_VERSINFO[1]} == 4 && ${BASH_VERSINFO[2]} -ge 20 ]]
bash --version
while IFS= read -r file; do
    printf 'bash -n: %s\n' "$file"
    bash -n "$file"
done < "$1"
source lib/common.sh
declare -A sample=([key]=value)
indexed=(first second)
[[ ${sample[key]} == value && ${indexed[1]} == second ]]
[[ fixture =~ ^(fix)(ture)$ ]]
hc_detail ordinary
[[ ${BASH_REMATCH[1]}:${BASH_REMATCH[2]} == fix:ture ]]
TELEGRAM_BOT_TOKEN=fixture_secret
hc_warn $'fixture_secret\ncontrol'
[[ ${HC_WARNINGS[0]} == 'WARNING [REDACTED]\ncontrol' ]]
[[ ${HC_RESULT_COUNTS[INFO]} == 1 && ${HC_RESULT_COUNTS[WARNING]} == 1 ]]
[[ $(hc_present $'tab\tescape\033') == 'tab\tescape\x1b' ]]
(
    set +e
    set -E
    failed=0
    trap 'failed=1' ERR
    false
    [[ $failed == 1 ]] || exit 1
    trap - ERR
)
printf 'Bash 4.4 behavior contracts: PASS\n'
