#!/usr/bin/python3 -I
"""Restricted sudo entry point: forward session metadata, never caller code or paths."""

import ipaddress
import json
import os
from pathlib import Path
import pwd
import sys

FIELDS = ('SSH_CONNECTION', 'SSH_CLIENT', 'SSH_TTY', 'SSH_ORIGINAL_COMMAND',
          'SSH_TUNNEL', 'SSH_USER', 'SSH_KEY_FINGERPRINT', 'SSH_KEY_COMMENT')


def session_environment(payload, caller_uid):
    account = pwd.getpwuid(caller_uid)
    if not isinstance(payload, dict) or set(payload) - set(FIELDS):
        raise ValueError('Unsupported session metadata')
    environment = {
        'PATH': '/usr/sbin:/usr/bin:/sbin:/bin',
        'LANG': 'C.UTF-8',
        'HOME': account.pw_dir,
        'USER': account.pw_name,
        'LOGNAME': account.pw_name,
        'SSH_LOGIN_USER': account.pw_name,
    }
    for field, value in payload.items():
        if not isinstance(value, str) or '\0' in value or len(value) > 8192:
            raise ValueError('Invalid session metadata')
        environment[field] = value
    for field, count in (('SSH_CONNECTION', 4), ('SSH_CLIENT', 3)):
        if field not in payload:
            continue
        parts = payload[field].split()
        if len(parts) != count:
            raise ValueError('Invalid connection metadata')
        ipaddress.ip_address(parts[0])
        ports = (parts[1], parts[3]) if count == 4 else (parts[1], parts[2])
        if count == 4:
            ipaddress.ip_address(parts[2])
        if any(not port.isdigit() or not 0 < int(port) < 65536 for port in ports):
            raise ValueError('Invalid connection port')
    if not payload.get('SSH_CONNECTION') and not payload.get('SSH_CLIENT'):
        raise ValueError('Missing SSH connection metadata')
    return environment


def main():
    if os.geteuid() != 0 or len(sys.argv) != 1:
        print('This helper requires root and accepts no arguments', file=sys.stderr)
        return 1
    try:
        raw = sys.stdin.buffer.read(65537)
        if len(raw) > 65536:
            raise ValueError('Session metadata is too large')
        caller_uid = int(os.environ.get('SUDO_UID', str(os.getuid())))
        environment = session_environment(json.loads(raw.decode('utf-8')), caller_uid)
    except (ValueError, KeyError) as error:
        print('Invalid SSH session: {}'.format(error), file=sys.stderr)
        return 1
    script = str(Path(__file__).resolve().with_name('ssh-alert-enhanced.sh'))
    os.execve('/bin/bash', ['/bin/bash', script], environment)


if __name__ == '__main__':
    sys.exit(main())
