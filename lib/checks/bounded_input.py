"""Regular-file input budgets; Python 3.6, symlinks retain regular targets only."""
import gzip
import os
import signal
import stat
import time


class BudgetExceeded(Exception):
    """Abort the entire invocation; interval classifiers must not swallow this."""
    pass


def limit(name, default):
    value = int(os.environ.get('SSHC_' + name, default))
    if value <= 0:
        raise ValueError('invalid input budget')
    return value


def lines(path):
    maximum = limit('MAX_FILE_BYTES', 64 * 1024 * 1024)
    expanded = limit('MAX_EXPANDED_BYTES', 128 * 1024 * 1024)
    record = limit('MAX_RECORD_BYTES', 64 * 1024)
    records = limit('MAX_RECORDS', 1000000)
    deadline = time.monotonic() + limit('READ_SECONDS', 20)
    # O_NONBLOCK closes the stat/open FIFO race; fstat checks the opened target.
    if not stat.S_ISREG(os.stat(path).st_mode):
        raise ValueError('input is not regular')
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
            raise ValueError('input file budget exceeded or not regular')
        stream = gzip.GzipFile(fileobj=source) if str(path).endswith('.gz') else source
        total = 0
        count = 0
        try:
            while True:
                raw = stream.readline(record + 1)
                if not raw:
                    break
                total += len(raw)
                count += 1
                if len(raw) > record or total > expanded or count > records or time.monotonic() > deadline:
                    raise ValueError('input resource budget exceeded')
                yield raw.decode('utf-8', errors='strict')
        finally:
            if stream is not source:
                stream.close()


def text(path):
    value = ''.join(lines(path))
    if '\x00' in value:
        raise ValueError('NUL is not representable in shell records')
    return value


def stdin_text():
    import sys
    maximum = limit('MAX_EXPANDED_BYTES', 128 * 1024 * 1024)
    record = limit('MAX_RECORD_BYTES', 65536)
    count_limit = limit('MAX_RECORDS', 1000000)
    chunks = []
    total = 0
    while True:
        raw = sys.stdin.buffer.readline(record + 1)
        if not raw:
            break
        total += len(raw)
        if len(raw) > record or total > maximum or len(chunks) >= count_limit:
            raise ValueError('stdin resource budget exceeded')
        chunks.append(raw.decode('utf-8', errors='strict'))
    return ''.join(chunks)


def arm_timeout():
    def expired(signum, frame):
        raise BudgetExceeded('input time budget exceeded')
    signal.signal(signal.SIGALRM, expired)
    signal.alarm(limit('READ_SECONDS', 20))


def snapshot(directory, destination):
    total = 0
    for name in sorted(os.listdir(directory)):
        if not (name == 'session.index' or name.startswith(('scan.meta.', 'session.tsv.'))):
            continue
        value = text(os.path.join(directory, name))
        total += len(value.encode('utf-8'))
        if total > limit('MAX_EXPANDED_BYTES', 128 * 1024 * 1024):
            raise ValueError('metadata snapshot budget exceeded')
        with open(os.path.join(destination, name), 'w', encoding='utf-8') as output:
            output.write(value)


if __name__ == '__main__':
    import sys
    try:
        arm_timeout()
        if sys.argv[1] == '--snapshot':
            snapshot(sys.argv[2], sys.argv[3])
            sys.exit(0)
        # Preflight for legacy shell readers; never print source contents.
        for item in lines(sys.argv[1]):
            pass
    except (OSError, ValueError, EOFError, BudgetExceeded):
        sys.exit(1)
