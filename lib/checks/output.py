"""Optional JSON journal renderer; Python 3.6 standard library only."""
import datetime
import json
import sys
import time

MAX_JOURNAL_BYTES = 4 * 1024 * 1024
MAX_OUTPUT_BYTES = 16 * 1024 * 1024

LEVELS = ('pass', 'info', 'warning', 'critical', 'error')


def clock():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(), int(time.monotonic() * 1000000000)


def duration(start, end):
    return max(0, (int(end) - int(start)) // 1000000)


def render(data, name, version, code, hostname):
    fields = data.decode('utf-8', 'replace').split('\0')
    if fields[-1] != '' or (len(fields) - 1) % 4:
        raise ValueError('invalid journal')
    checks = {}
    events = []
    counts = dict((level, 0) for level in LEVELS)
    start = finish = None
    seen_counts = False
    truncated = False
    for i in range(0, len(fields) - 1, 4):
        kind, identifier, key, value = fields[i:i + 4]
        if kind == 'run-start':
            start = (key, value)
        elif kind == 'run-end':
            finish = (key, value)
        elif kind == 'counts':
            values = [int(n) for n in value.split(',')]
            if seen_counts or len(values) != 5 or any(n < 0 for n in values):
                raise ValueError('invalid final counters')
            seen_counts = True
            counts = dict(zip(LEVELS, values))
        elif kind == 'truncated':
            truncated = True
        elif kind in ('check', 'start', 'end', 'state', 'finding'):
            if identifier and identifier not in checks:
                checks[identifier] = dict(id=identifier, name=identifier, status='pass',
                                          started_at=None, finished_at=None, duration_ms=0,
                                          findings=[])
            check = checks.get(identifier)
            if kind == 'start':
                check['started_at'] = key
                check['_start'] = value
            elif kind == 'end':
                check['finished_at'] = key
                check['duration_ms'] = duration(check.pop('_start', value), value)
            elif kind == 'state':
                previous = check['status']
                if previous not in ('warning', 'critical', 'error') or key in ('warning', 'critical', 'error'):
                    check['status'] = key
            elif kind == 'finding':
                if len(value) > 1024:
                    value = value[:1024]
                    truncated = True
                finding = dict(severity=key.lower(), message=value, details={})
                if check is None:
                    events.append(finding)
                else:
                    check['findings'].append(finding)
                    level = key.lower()
                    previous = check['status']
                    if level in LEVELS and (previous not in LEVELS or LEVELS.index(level) >= LEVELS.index(previous)):
                        check['status'] = level
    if not seen_counts:
        raise ValueError('missing final counters')
    if start is None or finish is None:
        fallback = clock()
        start = start or fallback
        finish = finish or fallback
    for check in checks.values():
        check.pop('_start', None)
    status = 'error' if code == 2 else ('critical' if counts['critical'] else 'warning') if code == 1 else 'pass'
    counts['total'] = sum(counts.values())
    return dict(schema_version=1, application=dict(name=name, version=version),
                run=dict(started_at=start[0], finished_at=finish[0],
                         duration_ms=duration(start[1], finish[1]), exit_code=code, status=status),
                host=dict(hostname=hostname), summary=counts, checks=list(checks.values()),
                findings=events, truncated=truncated)


def verify(path, code, name=None, version=None):
    with open(path, 'rb') as stream:
        raw = stream.read(MAX_OUTPUT_BYTES + 1)
    if len(raw) > MAX_OUTPUT_BYTES:
        raise ValueError('output budget exceeded')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate JSON key')
            result[key] = value
        return result
    def invalid_constant(value):
        raise ValueError('non-JSON numeric constant')
    result = json.loads(raw.decode('utf-8'), object_pairs_hook=unique,
                        parse_constant=invalid_constant)
    return validate(result, code, name, version)



def validate(result, code, name=None, version=None):
    required = {'schema_version', 'application', 'run', 'host', 'summary', 'checks', 'findings', 'truncated'}
    if not required.issubset(result) or type(result['truncated']) is not bool:
        raise ValueError('incomplete output')
    if type(result['run']['exit_code']) is not int:
        raise ValueError('invalid exitcode type')
    if name is not None and result['application']['name'] != name:
        raise ValueError('application mismatch')
    if version is not None and result['application']['version'] != version:
        raise ValueError('version mismatch')
    allowed = ('pass', 'info', 'warning', 'critical', 'error', 'skipped', 'not_applicable')
    for obj in [result['run']] + result['checks']:
        for field in ('started_at', 'finished_at'):
            stamp = obj[field]
            if stamp is not None:
                if not isinstance(stamp, str) or not stamp.endswith('+00:00'):
                    raise ValueError('invalid UTC timestamp')
                wall = stamp[:-6]
                pattern = '%Y-%m-%dT%H:%M:%S.%f' if '.' in wall else '%Y-%m-%dT%H:%M:%S'
                datetime.datetime.strptime(wall, pattern)
        if obj['status'] not in allowed or type(obj['duration_ms']) is not int or obj['duration_ms'] < 0:
            raise ValueError('invalid status/timing')
    for finding in result['findings'] + [f for c in result['checks'] for f in c['findings']]:
        if finding['severity'] not in LEVELS or not isinstance(finding['message'], str) or not isinstance(finding['details'], dict):
            raise ValueError('invalid finding')
    if type(result['schema_version']) is not int or result['schema_version'] != 1 or result['run']['exit_code'] != code:
        raise ValueError('output exitcode/schema mismatch')
    expected = 'error' if code == 2 else None
    if expected and result['run']['status'] != expected:
        raise ValueError('output status mismatch')
    summary = result['summary']
    if any(type(summary[key]) is not int or summary[key] < 0 for key in LEVELS):
        raise ValueError('invalid summary')
    if summary['total'] != sum(summary[key] for key in LEVELS):
        raise ValueError('summary mismatch')
    return result


def main():
    mode = sys.argv[1]
    if mode == 'clock':
        stamp, tick = clock()
        print('{}|{}'.format(stamp, tick))
    elif mode == 'self-test':
        stamp, tick = clock()
        fields = ['run-start', '', stamp, str(tick), 'run-end', '', stamp, str(tick),
                  'counts', '', '', '0,0,0,0,0', '']
        result = render('\0'.join(fields).encode(), 'test', 'test', 0, 'host')
        validate(json.loads(json.dumps(result)), 0, 'test', 'test')
        print('SSHC_JSON_SCHEMA_1')
    elif mode == 'verify':
        result = verify(sys.argv[2], int(sys.argv[3]), sys.argv[4], sys.argv[5])
        encoded = json.dumps(result, ensure_ascii=True)
        if len(encoded) > MAX_OUTPUT_BYTES:
            raise ValueError('encoded output budget exceeded')
        print(encoded)
    elif mode == 'render':
        with open(sys.argv[2], 'rb') as stream:
            data = stream.read(MAX_JOURNAL_BYTES + 1)
        if len(data) != int(sys.argv[7]):
            raise ValueError('journal byte count mismatch')
        if len(data) > MAX_JOURNAL_BYTES:
            raise ValueError('journal budget exceeded')
        result = render(data, sys.argv[3], sys.argv[4], int(sys.argv[5]), sys.argv[6])
        print(json.dumps(result, ensure_ascii=True))
    else:
        raise ValueError('unknown output operation')


if __name__ == '__main__':
    main()
