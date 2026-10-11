#!/usr/bin/env python3
"""Bounded, read-only parsers. Python 3.6; never execute input as code."""
import datetime
import json
import os
import re
import shlex
import sys


class Invalid(ValueError):
    pass


def timestamp(value, now):
    if not isinstance(value, str):
        raise Invalid('invalid timestamp')
    match = re.fullmatch(r'(\d{4}-\d\d-\d\d)T(\d\d:\d\d:\d\d)(?:\.(\d{1,6}))?(Z|[+-]\d\d:?\d\d)', value)
    if not match:
        raise Invalid('invalid timestamp')
    zone = '+0000' if match.group(4) == 'Z' else match.group(4).replace(':', '')
    date_value = match.group(1) + 'T' + match.group(2)
    format_value = '%Y-%m-%dT%H:%M:%S'
    if match.group(3):
        date_value += '.' + match.group(3)
        format_value += '.%f'
    instant = datetime.datetime.strptime(date_value + zone, format_value + '%z').timestamp()
    # No future clock skew is silently accepted, in every time-based parser.
    if instant < 0 or instant > now:
        raise Invalid('timestamp in the future or before epoch')
    return instant


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Invalid('duplicate JSON key')
        result[key] = value
    return result


def invalid_constant(value):
    raise Invalid('non-standard JSON constant')


def audit(path, event, hours, now):
    count = 0
    if not os.path.isfile(path):
        raise Invalid('audit source missing or not a regular file')
    with open(path, encoding='utf-8') as stream:
        for line in stream:
            if not line.strip():
                continue
            item = json.loads(line, object_pairs_hook=unique_object, parse_constant=invalid_constant)
            if not isinstance(item, dict) or not isinstance(item.get('type'), str):
                raise Invalid('malformed audit event')
            epoch = timestamp(item.get('ts'), now)
            if item['type'] == event and now - hours * 3600 <= epoch <= now:
                count += 1
    return str(count)


def freshclam(text, now):
    previous = -1
    started = False
    completed = None
    databases = set()
    identity = None
    failed = False
    failure_pattern = r'ERROR:|Database update process failed|Database test FAILED|Update process terminated|(?:^|: )[Uu]pdate failed(?:[.:]|$)'
    for line in text.splitlines():
        if not re.search(r'ClamAV update process started|Database test passed|(?:daily|main|bytecode)\.(?:cvd|cld)|Database update completed successfully|' + failure_pattern, line):
            continue
        origin = re.search(r'\bfreshclam(?:\[(\d+)\])?:\s*', line)
        if not origin:
            raise Invalid('ambiguous FreshClam event origin')
        current_identity = origin.group(1) or 'daemon'
        epoch = timestamp(line.split()[0], now)
        if epoch < previous:
            raise Invalid('non-monotone FreshClam events')
        previous = epoch
        if 'ClamAV update process started' in line:
            if started and completed is None and identity != current_identity:
                raise Invalid('overlapping FreshClam attempts')
            identity = current_identity
            failed = False
            started = True
            databases.clear()
            completed = None
        elif identity is not None and identity != current_identity:
            raise Invalid('interleaved FreshClam process events')
        elif re.search(failure_pattern, line):
            identity = current_identity
            failed = True
            started = False
            completed = None
            databases.clear()
        elif 'Database test passed' in line:
            # An installation may still fail after this validation step.
            completed = None
        elif 'Database update completed successfully.' in line:
            if failed or not started:
                raise Invalid('completion without a valid started attempt')
            identity = current_identity
            completed = epoch
        else:
            match = re.search(r'\b(daily|main|bytecode)\.(?:cvd|cld) (?:updated\s*\(|database is up-to-date\s*\()', line)
            if started and match:
                databases.add(match.group(1))
                if databases == {'daily', 'main', 'bytecode'}:
                    completed = epoch
    if completed is None:
        raise Invalid('latest FreshClam attempt failed, incomplete, or unavailable')
    return str(int(completed))


def logical_lines(text):
    pending = ''
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(('#', ';')):
            continue
        if line.endswith('\\'):
            pending += line[:-1] + ' '
            continue
        yield pending + line
        pending = ''
    if pending:
        raise Invalid('unfinished continuation')


def words(value):
    # C escapes/specifiers require additional semantics: deliberately UNKNOWN.
    if '\\' in value or '%' in value:
        raise Invalid('unsupported escaping or specifier')
    # systemd quotes wrap whole words, unlike shell concatenated quotes.
    item = r'''(?:"[^"\n]*"|'[^'\n]*'|[^\s"']+)'''
    if not re.fullmatch(r'\s*(?:' + item + r'(?:\s+' + item + r')*)?\s*', value):
        raise Invalid('malformed quoting')
    return shlex.split(value)


def service_directives(text):
    service = False
    for line in logical_lines(text):
        if line.startswith('['):
            if not re.fullmatch(r'\[[A-Za-z]+\]', line):
                raise Invalid('malformed unit section')
            service = line == '[Service]'
            continue
        if not service:
            continue
        if '=' not in line:
            raise Invalid('malformed service directive')
        key, value = line.split('=', 1)
        if not re.fullmatch(r'[A-Za-z][A-Za-z0-9]*', key.strip()):
            raise Invalid('malformed service directive name')
        yield key.strip(), value.strip()


def monitor(text, root, sysconfig, default):
    inline = {}
    files = []
    starts = []
    passed = []
    unset = []
    for key, value in service_directives(text):
        if key == 'ExecStart':
            if not value:
                starts.clear()
            else:
                starts.append(value)
        elif key in ('Environment', 'EnvironmentFile', 'PassEnvironment', 'UnsetEnvironment'):
            items = words(value)
            if key == 'Environment':
                if not items:
                    inline.clear()
                for item in items:
                    if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*=.*', item):
                        raise Invalid('malformed Environment assignment')
                    name, val = item.split('=', 1)
                    inline[name] = val
            else:
                target = {'EnvironmentFile': files, 'PassEnvironment': passed, 'UnsetEnvironment': unset}[key]
                if not items:
                    target.clear()
                target.extend(items)
        elif key in ('PAMName', 'RootDirectory', 'RootImage', 'ExecStartPre', 'ExecCondition'):
            if value:
                raise Invalid('unsupported environment/execution override')
    if len(starts) != 1:
        raise Invalid('unsupported ExecStart count/reset')
    command = words(starts[0])
    if len(command) != 3 or command[0] != root + '/maldet' or command[1] != '--monitor' or command[2] not in ('${MONITOR_MODE}', '$MONITOR_MODE'):
        raise Invalid('unsupported ExecStart')
    value = inline.get('MONITOR_MODE')
    for filename in files:
        optional = filename.startswith('-')
        filename = filename[1:] if optional else filename
        if filename not in ('/etc/sysconfig/maldet', '/etc/default/maldet'):
            raise Invalid('unsupported EnvironmentFile')
        path = sysconfig if filename == '/etc/sysconfig/maldet' else default
        try:
            os.stat(path)
        except FileNotFoundError:
            if optional:
                continue
            raise
        with open(path, encoding='utf-8') as stream:
            for line in stream:
                line = line.strip()
                if not line or line.startswith(('#', ';')):
                    continue
                if line.startswith('export '):
                    raise Invalid('export is not a systemd EnvironmentFile assignment')
                if not re.match(r'[A-Za-z_][A-Za-z0-9_]*\s*=', line):
                    raise Invalid('malformed EnvironmentFile assignment')
                name, val = line.split('=', 1)
                # Validate every assignment: an unterminated unrelated quote
                # may consume a following MONITOR_MODE line in the real reader.
                if '\\' in val or '\n' in val:
                    raise Invalid('unsupported EnvironmentFile value')
                val = val.strip()
                if val.startswith(('"', "'")):
                    parsed = words(val)
                    if len(parsed) != 1:
                        raise Invalid('malformed EnvironmentFile value')
                    val = parsed[0]
                elif '"' in val or "'" in val:
                    raise Invalid('ambiguous EnvironmentFile quoting')
                if name.strip() == 'MONITOR_MODE':
                    value = val
    if 'MONITOR_MODE' in passed and value is None:
        raise Invalid('manager MONITOR_MODE unknown')
    # UnsetEnvironment is applied AFTER ExecStart expansion. The monitor argument
    # therefore still uses the pre-unset value; do not silently infer a fallback.
    if any(item == 'MONITOR_MODE' or item == 'MONITOR_MODE=' + (value or '') for item in unset):
        raise Invalid('MONITOR_MODE removed after command expansion')
    if command[2] == '$MONITOR_MODE' and value and re.search(r'\s', value):
        raise Invalid('unbraced monitor argument may split into multiple words')
    if value is not None and ('\n' in value or '\r' in value):
        raise Invalid('invalid MONITOR_MODE')
    return value or ''


def clam_config(text, explicit, instance):
    if explicit:
        path = explicit
    else:
        starts = []
        for key, value in service_directives(text):
            if key == 'ExecStart':
                if not value:
                    starts.clear()
                else:
                    starts.append(value)
            elif key in ('RootDirectory', 'RootImage', 'Environment', 'EnvironmentFile') and value:
                raise Invalid('unsupported clamd unit override')
        if len(starts) != 1:
            raise Invalid('active clamd ExecStart unavailable')
        # The sole supported specifier is the selected template instance.
        args = words(starts[0].replace('%i', instance))
        if len(args) != 3 or args[0] not in ('/usr/sbin/clamd', '/usr/bin/clamd', '/usr/local/sbin/clamd') or args[1] not in ('-c', '--config-file'):
            raise Invalid('unsupported clamd command/config selection')
        path = args[2]
    if not os.path.isabs(path):
        raise Invalid('clamd config must be absolute')
    return path


def database(path, default):
    values = []
    with open(path, encoding='utf-8') as stream:
        for line in stream:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if line == 'Example' or line.startswith('Include'):
                raise Invalid('unsupported ClamAV configuration')
            if line.startswith('DatabaseDirectory'):
                match = re.fullmatch(r'DatabaseDirectory\s+("[^"\n]+"|[^\s"#]+)', line)
                if not match:
                    raise Invalid('malformed DatabaseDirectory')
                values.append(match.group(1).strip('"'))
    if len(values) > 1:
        raise Invalid('ambiguous DatabaseDirectory')
    value = values[0] if values else default
    if not value or not os.path.isabs(value) or '\n' in value:
        raise Invalid('active DatabaseDirectory/default unavailable')
    return value


# Exact full 2.0.1 daily layout observed on this installation. This is comparison
# data only: no part is sourced/executed. Outer wrappers or extra statements fail.
DAILY_STOCK_2_0_1 = r'''#!/usr/bin/env bash
#
##
# Linux Malware Detect v2.0.1
#             (C) 2002-2026, R-fx Networks <proj@rfxn.com>
#             (C) 2026, Ryan MacDonald <ryan@rfxn.com>
# This program may be freely redistributed under the terms of the GNU GPL v2
##
#
export PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:$PATH
inspath='/usr/local/maldetect'
intcnf="$inspath/internals/internals.conf"

# prevent overlapping cron runs — use flock command form so the lock fd is
# CLOEXEC and never inherited by backgrounded maldet -b scans
LOCKFILE="$inspath/tmp/.cron.lock"
if command -v flock >/dev/null 2>&1 && [ -z "$_CRON_FLOCK" ]; then
	export _CRON_FLOCK=1
	flock -n "$LOCKFILE" "$0" "$@"
	rc=$?
	# flock -n exits 1 on lock contention; inner errors use exit 2
	if [ "$rc" -eq 1 ]; then
		exit 0
	fi
	exit "$rc"
fi

# Inner-script errors use exit 2 to distinguish from flock lock contention
# (exit 1). Do NOT use 'exit 1' for errors below the flock block.
if [ -f "$intcnf" ]; then
	. $intcnf
else
	echo "\$intcnf not found."
	exit 2
fi
if [ -f "$cnf" ]; then
	. $cnf
	if [ -f "$compatcnf" ]; then
	        . $compatcnf
	fi
else
	echo "could not find \$cnf, fatal error, bye."
	exit 2
fi

if [ -f "/etc/sysconfig/maldet" ]; then
	. /etc/sysconfig/maldet
elif [ -f "/etc/default/maldet" ]; then
	. /etc/default/maldet
fi

if [ -f "$cron_custom_conf" ]; then
	. $cron_custom_conf
fi

if [ -z "$scan_days" ]; then
	scan_days=1
fi

if [ -z "$cron_prune_days" ]; then
	cron_prune_days=21
fi

if [ "$find" ]; then
	# prune quarantine/session/tmp data older than $cron_prune_days days
	tmpdirs="$tmpdir $varlibpath/sess $varlibpath/quarantine $varlibpath/pub"
	for dir in $tmpdirs; do
	 if [ -d "$dir" ]; then
	  $find "$dir" -type f -mtime +${cron_prune_days} -delete 2>/dev/null
	 fi
	done
fi

if [ "$autoupdate_version" == "1" ] || [ "$autoupdate_signatures" == "1" ]; then
	# sleep for random 1-999s interval to better distribute upstream load
	sleep $(echo $RANDOM | cut -c1-3) >> /dev/null 2>&1
fi

if [ "$autoupdate_version" == "1" ]; then
	$inspath/maldet -d 1 2>&1 | tail -20 >> "$maldet_log"
	if [ "${PIPESTATUS[0]}" -ne 0 ]; then
		echo "$(date) cron.daily: maldet -d (version update) failed" >> "$maldet_log"
	fi
fi

if [ "$autoupdate_signatures" == "1" ]; then
	$inspath/maldet -u 1 2>&1 | tail -20 >> "$maldet_log"
	if [ "${PIPESTATUS[0]}" -ne 0 ]; then
		echo "$(date) cron.daily: maldet -u (signature update) failed" >> "$maldet_log"
	fi
fi

# Maintenance: rotate oversized history files, clean stale scan metadata,
# compress/archive old sessions
$inspath/maldet --maintenance >> /dev/null 2>&1  # safe: maintenance output logged internally

# Hook scan digest — fire if hook.hits.log has content since last sweep
if [ "${cron_digest_hook:-1}" == "1" ] && [ -f "$sessdir/hook.hits.log" ] && [ -s "$sessdir/hook.hits.log" ]; then
	echo "$(date) cron.daily: hook digest: checking for new detections" >> "$maldet_log"
	$inspath/maldet --digest >> /dev/null 2>&1
fi

# if we're running inotify monitoring, send daily hit summary
if [ "$(ps -A --user root -o "cmd" | grep -E maldetect | grep -E inotifywait)" ]; then
        $inspath/maldet --monitor-report >> /dev/null 2>&1
elif [ "$cron_daily_scan" == "1" ]; then
	if [ -d "/home/virtual" ] && [ -d "/usr/lib/opcenter" ]; then
		# ensim
	        $inspath/maldet -b -r /home/virtual/?/fst/var/www/html/,/home/virtual/?/fst/home/?/public_html/ $scan_days >> /dev/null 2>&1
	elif [ -d "/etc/psa" ] && [ -d "/var/lib/psa" ]; then
		# psa
		$inspath/maldet -b -r /var/www/vhosts/?/ $scan_days >> /dev/null 2>&1
        elif [ -d "/usr/local/directadmin" ]; then
                # DirectAdmin
                $inspath/maldet -b -r /home?/?/domains/?/public_html/,/var/www/html/?/ $scan_days >> /dev/null 2>&1
	elif [ -d "/var/www/clients" ]; then
		# ISPConfig
                $inspath/maldet -b -r /var/www/clients/?/web?/web,/var/www/clients/?/web?/subdomains,/var/www $scan_days >> /dev/null 2>&1
	elif [ -d "/etc/webmin/virtual-server" ]; then
		# Virtualmin
                $inspath/maldet -b -r /home/?/public_html/,/home/?/domains/?/public_html/ $scan_days >> /dev/null 2>&1
	elif [ -d "/usr/local/ispmgr" ] || [ -d "/usr/local/mgr5" ]; then
		# ISPmanager
		$inspath/maldet -b -r /var/www/?/data/,/home/?/data/ $scan_days >> /dev/null 2>&1
	elif [ -d "/var/customers/webs" ]; then
		# froxlor
		$inspath/maldet -b -r /var/customers/webs/ $scan_days >> /dev/null 2>&1
	elif [ -d "/opt/webdir" ] && [ -d "/etc/nginx/bx" ]; then
		# Bitrix
		$inspath/maldet -b -r /home/bitrix/www/,/home/bitrix/ext_www/?/ $scan_days >> /dev/null 2>&1
        elif [ -d "/usr/local/vesta" ] || [ -d "/usr/local/hestia" ]; then
                # VestaCP or HestiaCP
                $inspath/maldet -b -r /home/?/web/?/public_html/,/home/?/web/?/public_shtml/,/home/?/tmp/,/home/?/web/?/private/ $scan_days >> /dev/null 2>&1
        elif [ -d "/usr/share/dtc" ]; then
                # DTC
                if [ -f /var/lib/dtc/saved_install_config ]; then
                    . /var/lib/dtc/saved_install_config
                fi
                $inspath/maldet -b -r ${conf_hosting_path:-/var/www/sites}/?/?/subdomains/?/html/ $scan_days >> /dev/null 2>&1
	elif [ -d "/usr/local/cpanel" ] || [ -d "/var/cpanel" ]; then
		# cPanel: parse /etc/userdatadomains for all document roots
		# format: domain: user==owner==type==parent==/docroot==ip:port==
		cpanel_paths="/home?/?/public_html/"
		if [ -f /etc/userdatadomains ]; then
			cpanel_extra=$(awk -F'==' '{gsub(/^[[:space:]]+|[[:space:]]+$/, "", $5); if ($5 != "" && $5 != "/") print $5}' /etc/userdatadomains | sort -u | while IFS= read -r docroot; do
				# skip paths already covered by the public_html glob
				case "$docroot" in
					/home*/public_html|/home*/public_html/*) continue ;;
				esac
				[ -d "$docroot" ] && printf '%s/,' "$docroot"
			done)
			cpanel_extra="${cpanel_extra%,}"
			if [ -n "$cpanel_extra" ]; then
				cpanel_paths="${cpanel_paths},${cpanel_extra}"
			fi
		fi
		$inspath/maldet -b -r ${cpanel_paths},/var/www/,/usr/local/apache/htdocs/ $scan_days >> /dev/null 2>&1
	else
		# interworx and other standard home/user/public_html setups
	        $inspath/maldet -b -r /home?/?/public_html/,/var/www/,/usr/local/apache/htdocs/ $scan_days >> /dev/null 2>&1
	fi
fi

if [ -f "$cron_custom_exec" ]; then
	. $cron_custom_exec
fi
'''

def daily_contract(path, root):
    def normalized(text):
        return [line.strip() for line in text.splitlines()
                if line.strip() and not line.lstrip().startswith('#')]
    expected = DAILY_STOCK_2_0_1.replace("inspath='/usr/local/maldetect'", "inspath='" + root + "'", 1)
    with open(path, encoding='utf-8') as stream:
        if normalized(stream.read()) != normalized(expected):
            raise Invalid('unsupported full daily contract')
    return 'supported full daily contract'


def main():
    mode = sys.argv[1]
    if mode == 'audit':
        result = audit(sys.argv[2], sys.argv[3], int(sys.argv[4]), int(sys.argv[5]))
    elif mode == 'freshclam':
        result = freshclam(sys.stdin.read(), int(sys.argv[2]))
    elif mode == 'monitor':
        result = monitor(sys.stdin.read(), *sys.argv[2:5])
    elif mode == 'clam-config':
        result = clam_config(sys.stdin.read(), *sys.argv[2:4])
    elif mode == 'database':
        result = database(*sys.argv[2:4])
    elif mode == 'daily':
        result = daily_contract(*sys.argv[2:4])
    else:
        raise Invalid('unknown parser')
    print(result)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, UnicodeError, IndexError) as error:
        # No raw records/config contents in diagnostics.
        print('Source read/parse failure: ' + (str(error) if isinstance(error, Invalid) else type(error).__name__), file=sys.stderr)
        sys.exit(1)
