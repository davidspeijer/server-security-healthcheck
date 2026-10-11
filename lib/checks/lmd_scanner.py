"""Read LMD scanner logs as data. Compatible with production Python >=3.6.

No stat of reported paths, subprocesses, imports from logs, or writes. The log
has no scan ID: only a single non-overlapping block inside the session interval
can establish a result. Rotation order is explicit, never based on file mtime.
"""
import gzip
import locale
import re
import sys
import time
from pathlib import Path

MARKER = re.compile(r'^(...\s+\d{1,2} \d{4} \d{2}:\d{2}:\d{2}) (\S+) clamscan (start|end return ([012]))$')
EXECUTED = re.compile(r'^(...\s+\d{1,2} \d{4} \d{2}:\d{2}:\d{2}) (\S+) executed: (.+)$')
ACCESS = re.compile(r"^ERROR: Can't access file (/[^\t\r\n]+)$")
VOLATILE = re.compile(r'/(?:tmp|cache|upgrade)/|/wp-content/uploads/elementor/css/')


def local_epoch(stamp):
    parsed = time.strptime(stamp, '%b %d %Y %H:%M:%S')
    normalized = time.strftime('%b %d %Y %H:%M:%S', parsed)
    epochs = set()
    for dst in (0, 1):
        epoch = int(time.mktime(parsed[:8] + (dst,)))
        if time.strftime('%b %d %Y %H:%M:%S', time.localtime(epoch)) == normalized:
            epochs.add(epoch)
    if len(epochs) != 1:
        raise ValueError('ambiguous timestamp')
    return epochs.pop()


def result(directory, started, ended):
    if not 0 < started <= ended:
        raise ValueError('invalid interval')
    files = []
    for path in Path(directory).glob('clamscan_log*'):
        suffix = path.name[len('clamscan_log'):]
        if not suffix:
            key = (2, 0)
        elif re.fullmatch(r'-\d{8}(?:\.gz)?', suffix):
            key = (0, int(suffix[1:9]))
        elif re.fullmatch(r'\.\d+(?:\.gz)?', suffix):
            key = (1, -int(suffix.split('.')[1]))
        else:
            raise ValueError('unsupported rotation')
        files.append((key, path))
    if not files or len({key for key, _ in files}) != len(files):
        raise ValueError('missing or duplicate logs')
    if any(key[0] == 0 for key, _ in files) and any(key[0] == 1 for key, _ in files):
        raise ValueError('mixed rotation')
    active = None
    candidates = []
    previous_epoch = 0
    for _, path in sorted(files):
        opener = gzip.open if path.name.endswith('.gz') else open
        with opener(str(path), 'rt', encoding='utf-8', errors='strict') as log:
            for raw in log:
                line = raw.rstrip('\n')
                marker = MARKER.fullmatch(line)
                if marker:
                    stamp, host, kind, code = marker.groups()
                    # Local LMD timestamps lack an offset. DST ambiguity must
                    # not silently select the wrong scan interval.
                    epoch = local_epoch(stamp)
                    if epoch < previous_epoch:
                        raise ValueError('unordered markers')
                    previous_epoch = epoch
                    if kind == 'start':
                        if active is not None:
                            raise ValueError('overlapping scans')
                        active = dict(start=epoch, host=host, access=0, volatile=0,
                                      other=0, executed=0, executed_epoch=epoch)
                    else:
                        if active is not None:
                            if active['host'] != host:
                                raise ValueError('host conflict')
                            if not active['start'] <= active['executed_epoch'] <= epoch:
                                raise ValueError('invocation timestamp conflict')
                            if started <= active['start'] <= epoch <= ended:
                                active['exit'] = int(code)
                                candidates.append(active)
                            elif active['start'] <= ended and epoch >= started:
                                raise ValueError('interval overlap')
                        elif started <= epoch <= ended:
                            raise ValueError('missing start')
                        active = None
                elif 'clamscan start' in line or 'clamscan end' in line:
                    raise ValueError('malformed marker')
                elif active is not None:
                    access = ACCESS.fullmatch(line)
                    if access:
                        active['access'] += 1
                        active['volatile'] += int(bool(VOLATILE.search(access.group(1))))
                    elif EXECUTED.fullmatch(line):
                        stamp, host, command = EXECUTED.fullmatch(line).groups()
                        if host != active['host'] or not re.search(
                                r'(?:^|\s)(?:/\S*/)?(?:clamdscan|clamscan)(?:\s|$)', command):
                            raise ValueError('invocation conflict')
                        active['executed_epoch'] = local_epoch(stamp)
                        active['executed'] += 1
                    elif line.strip():
                        # Unknown stderr, warnings and retries are not evidence
                        # of an access-only outcome.
                        active['other'] += 1
    if active is not None and active['start'] <= ended:
        raise ValueError('missing end')
    if len(candidates) != 1 or candidates[0]['executed'] != 1:
        raise ValueError('ambiguous scanner invocation')
    item = candidates[0]
    code, access, other = item['exit'], item['access'], item['other']
    if other or (code == 2 and not access) or (code == 0 and access):
        state = 'failure'
    elif access:
        state = 'access_errors'
    else:
        state = 'clean' if code == 0 else 'detections'
    return state, code, access, item['volatile'], other


if __name__ == '__main__':
    locale.setlocale(locale.LC_TIME, 'C')
    try:
        print('\t'.join(map(str, result(sys.argv[1], int(sys.argv[2]), int(sys.argv[3])))))
    except (OSError, EOFError, ValueError, OverflowError, IndexError):
        print('unknown\t-\t0\t0\t0')
