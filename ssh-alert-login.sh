#!/bin/sh
# This unprivileged SSH hook sends only session metadata to the root helper.
[ -z "${SSH_ALERT_DISABLED:-}" ] || exit 0
[ -n "${SSH_CONNECTION:-}${SSH_CLIENT:-}" ] || exit 0

python3 - <<'PY' | sudo -n /opt/ssh-alert/ssh-alert-session.py
import json
import os
import sys

fields = ('SSH_CONNECTION', 'SSH_CLIENT', 'SSH_TTY', 'SSH_ORIGINAL_COMMAND',
          'SSH_TUNNEL', 'SSH_USER', 'SSH_KEY_FINGERPRINT', 'SSH_KEY_COMMENT')
json.dump({field: os.environ[field] for field in fields if field in os.environ}, sys.stdout)
PY
