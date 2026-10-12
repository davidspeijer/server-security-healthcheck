"""Deterministic subprocess boundaries; fixtures never contact host services."""
import os
from pathlib import Path
import shlex
import shutil

ROOT = Path(__file__).resolve().parents[1]
NOW = 1789891200


def isolated_env(work, timezone='UTC'):
    work = Path(work)
    commands = work/'mock-commands'
    commands.mkdir(exist_ok=True)
    date = shutil.which('date')
    scripts = {
        'hostname': "printf '%s\\n' fixture.example\n",
        'systemctl': 'exit 1\n',
        'curl': 'exit 99\n',
        'pgrep': 'exit 1\n',
        'journalctl': 'exit 1\n',
        'clamconf': 'exit 1\n',
        'exim': 'exit 1\n',
        'date': 'if [ "$*" = +%s ]; then printf "%s\\n" 1789891200; else exec '+shlex.quote(date)+' "$@"; fi\n',
    }
    for name, body in scripts.items():
        path = commands/name
        path.write_text('#!/bin/sh\n'+body)
        path.chmod(0o755)
    return dict(PATH=str(commands)+os.pathsep+os.environ['PATH'],
                TZ=timezone, LC_ALL='C', PYTHONDONTWRITEBYTECODE='1',
                TMPDIR=str(ROOT/'tmp'))
