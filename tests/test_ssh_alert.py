import base64
import hashlib
import io
import json
import logging
import os
from pathlib import Path
import pwd
import runpy
import shlex
import shutil
import struct
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
PARSER = runpy.run_path(str(ROOT / 'key-parser.py'))
HELPER = runpy.run_path(str(ROOT / 'ssh-alert-session.py'))
EDITOR = runpy.run_path(str(ROOT / 'sshrc-editor.py'))
SSHKeyParser = PARSER['SSHKeyParser']
AuthLogParser = PARSER['AuthLogParser']
logging.disable(logging.CRITICAL)


def bash(script, *args):
    return subprocess.run(['bash', '-s', '--'] + list(args), input=script,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          universal_newlines=True, cwd=str(ROOT), timeout=15)


class KeyParserTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'authorized_keys'
        self.blob = struct.pack('>I', 11) + b'ssh-ed25519' + struct.pack('>I', 32) + bytes(range(32))
        self.data = base64.b64encode(self.blob).decode('ascii')
        self.line = 'ssh-ed25519 ' + self.data + ' Alice laptop key'
        self.path.write_text(self.line + '\n')
        self.parser = SSHKeyParser(str(self.path))

    def test_plain_key_preserves_full_comment_and_fingerprint(self):
        key = self.parser._parse_authorized_key_line(self.line)
        self.assertEqual(key['comment'], 'Alice laptop key')
        expected = base64.b64encode(hashlib.sha256(self.blob).digest()).decode('ascii').rstrip('=')
        self.assertEqual(key['fingerprint'], expected)
        self.assertEqual(self.parser.find_key_by_fingerprint('SHA256:' + expected)['data'], self.data)

    def test_options_with_spaces_commas_and_escapes(self):
        options = r'command="echo \"hello, world\"",no-pty,environment="SSH_USER=alice@example.com"'
        key = self.parser._parse_authorized_key_line(options + ' ' + self.line)
        self.assertEqual(key['type'], 'ssh-ed25519')
        self.assertEqual(key['options']['command'], 'echo "hello, world"')
        self.assertTrue(key['options']['no-pty'])
        self.assertEqual(key['options']['SSH_USER'], 'alice@example.com')
        self.assertEqual(key['comment'], 'Alice laptop key')
        self.assertEqual(self.parser._find_key_by_data(self.data)['data'], self.data)

    def test_malformed_key_is_not_cached_as_unknown(self):
        self.assertIsNone(self.parser._parse_authorized_key_line('ssh-ed25519 notbase64! bad'))

    def test_no_arbitrary_recent_key_fallback(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(self.parser.get_recent_key())

    def test_source_port_selects_matching_authentication(self):
        log = Path(self.temp.name) / 'auth.log'
        fingerprint = next(iter(self.parser.key_cache))
        log.write_text('host sshd[1]: Accepted publickey for alice from 198.51.100.25 '
                       'port 10001 ssh2: ED25519 SHA256:' + fingerprint + '\n'
                       'host sshd[2]: Accepted publickey for bob from 198.51.100.25 '
                       'port 10002 ssh2: ED25519 SHA256:wrong\n'
                       'host sshd[3]: Accepted password for alice from 198.51.100.25 '
                       'port 10003 ssh2\n')
        self.parser.auth_log_path = str(log)
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(self.parser.find_key_by_ip_and_user('198.51.100.25', 'alice', '10001')['data'], self.data)
            self.assertIsNone(self.parser.find_key_by_ip_and_user('198.51.100.25', 'alice', '10003'))
            self.assertIsNone(self.parser.find_key_by_ip_and_user('198.51.100.25', 'carol', '10002'))

    def test_authentication_requires_exact_account_ip_and_port(self):
        parser = AuthLogParser(str(Path(self.temp.name) / 'auth.log'))
        line = 'host sshd[1]: Accepted publickey for bob from 198.51.100.250 port 12345 ssh2'
        self.assertFalse(parser._is_ssh_connection_line(line, '198.51.100.250', 'alice'))
        self.assertFalse(parser._is_ssh_connection_line(line, '198.51.100.25', 'bob'))
        self.assertFalse(parser._is_ssh_connection_line(line, '198.51.100.250', 'bob', '12346'))
        self.assertTrue(parser._is_ssh_connection_line(line, '198.51.100.250', 'bob', '12345'))

    def test_configuration_paths_and_account_selection(self):
        account = pwd.getpwuid(os.getuid())
        with patch.dict(os.environ, {'SSH_LOGIN_USER': account.pw_name,
                                    'SSH_AUTH_LOG_PATH': '/custom/auth.log'}, clear=True):
            with patch.object(SSHKeyParser, '_load_authorized_keys'):
                parser = SSHKeyParser()
            self.assertEqual(parser.authorized_keys_path, account.pw_dir + '/.ssh/authorized_keys')
            self.assertEqual(parser.auth_log_path, '/custom/auth.log')

    def test_system_account_is_separate_from_key_label(self):
        with patch.dict(os.environ, {'USER': 'alice', 'SSH_USER': 'alice@example.com'}, clear=True):
            self.assertEqual(PARSER['SSHConnectionDetector']._get_username(), 'alice')

    def test_empty_ssh_user_is_a_string(self):
        env = {'USER': 'alice', 'SSH_CONNECTION': '198.51.100.25 12345 203.0.113.10 22', 'SSH_TTY': '/dev/pts/1'}
        with patch.dict(os.environ, env, clear=True):
            info = PARSER['SSHConnectionDetector'].get_connection_info()
        self.assertEqual(info['ssh_user'], '')
        self.assertEqual(info['connection_type'], 'Interactive shell')


class NotificationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        self.marker = self.path / 'sent'
        self.release = self.path / 'release'

    def script(self, ip='198.51.100.25', username='alice', extra='', sender=None, label=None):
        connection = json.dumps({'ip_address': ip, 'username': username,
                                 'connection_type': 'Interactive shell', 'ssh_user': None})
        key = json.dumps({'fingerprint': 'test-key', 'comment': 'Alice laptop', 'ssh_user': label})
        if sender is None:
            sender = 'printf "%s\\n" "$1" >> ' + shlex.quote(str(self.marker))
        return '''
source ./ssh-alert-enhanced.sh
LOG_FILE={log}
RATE_LIMIT_DIR={rate}
IGNORE_LOCAL_IPS=false
EXCLUDED_IPS=''
EXCLUDED_USERNAMES=''
EXCLUDED_KEY_COMMENTS=''
SERVER_NAME=test-host
SERVER_DOMAIN=''
curl() {{ printf '203.0.113.10'; }}
hostname() {{ printf '203.0.113.10'; }}
send_telegram_message() {{ {sender}; }}
{extra}
send_ssh_alert {connection} {key}
'''.format(log=shlex.quote(str(self.path / 'alert.log')),
           rate=shlex.quote(str(self.path / 'rate')), sender=sender,
           extra=extra, connection=shlex.quote(connection), key=shlex.quote(key))

    def start(self, script):
        process = subprocess.Popen(['bash'], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, universal_newlines=True, cwd=str(ROOT))
        process.stdin.write(script)
        process.stdin.close()
        process.stdin = None
        return process

    def wait_for_lines(self, filename, count):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if filename.exists() and len(filename.read_text().splitlines()) >= count:
                return
            time.sleep(0.02)
        self.fail('Notification did not reach the synchronization point')

    def test_null_optional_user_preserves_excluded_account(self):
        result = bash(self.script(extra='EXCLUDED_USERNAMES=alice'))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.marker.exists())
        self.assertIn('excluded username: alice', (self.path / 'alert.log').read_text())

    def test_account_exclusion_still_applies_with_person_label(self):
        result = bash(self.script(extra='EXCLUDED_USERNAMES=alice', label='alice@example.com'))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.marker.exists())

    def test_success_keeps_correct_user_and_handles_quotes_in_json(self):
        result = bash(self.script(extra="JSON_LOGGING=true\nSERVER_NAME=\"host's\"", label="Alice's laptop"))
        self.assertEqual(result.returncode, 0, result.stderr)
        entries = (self.path / 'alert.log').read_text().splitlines()
        event = json.loads(entries[-1])
        self.assertEqual(event['username'], "Alice's laptop")
        self.assertEqual(event['server_name'], "host's")
        self.assertTrue(event['notification_sent'])

    def test_failed_delivery_does_not_suppress_next_attempt(self):
        result = bash(self.script(sender='return 1'))
        self.assertEqual(result.returncode, 1)
        result = bash(self.script())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.marker.exists())

    def test_rate_state_error_is_reported_without_sending(self):
        obstruction = self.path / 'not-a-directory'
        obstruction.write_text('blocked')
        result = bash(self.script(extra='RATE_LIMIT_DIR=' + shlex.quote(str(obstruction / 'rate'))))
        self.assertEqual(result.returncode, 2)
        self.assertFalse(self.marker.exists())
        self.assertIn('Could not access rate limiting state', result.stderr)

    def test_missing_evidence_does_not_select_first_authorized_key(self):
        keys = self.path / 'authorized_keys'
        blob = struct.pack('>I', 11) + b'ssh-ed25519' + struct.pack('>I', 32) + bytes(range(32))
        keys.write_text('ssh-ed25519 ' + base64.b64encode(blob).decode() + ' wrong-person\n')
        auth = self.path / 'auth.log'
        auth.write_text('')
        result = bash('source ./ssh-alert-enhanced.sh\n'
                      'export SSH_AUTHORIZED_KEYS_PATH="$1" SSH_AUTH_LOG_PATH="$2"\n'
                      'get_key_info 198.51.100.25 alice 12345\n', str(keys), str(auth))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['comment'], 'unknown')

    def test_different_connections_send_while_first_is_pending(self):
        started = self.path / 'started'
        sender = ('printf "started\\n" >> {started}; '
                  'while [[ ! -f {release} ]]; do sleep 0.02; done; '
                  'printf "sent\\n" >> {marker}').format(
                      started=shlex.quote(str(started)), release=shlex.quote(str(self.release)),
                      marker=shlex.quote(str(self.marker)))
        first = self.start(self.script(sender=sender))
        second = self.start(self.script(ip='198.51.100.26', sender=sender))
        try:
            self.wait_for_lines(started, 2)
        finally:
            self.release.touch()
            first.communicate(timeout=10)
            second.communicate(timeout=10)
        self.assertEqual(first.returncode, 0)
        self.assertEqual(second.returncode, 0)
        self.assertEqual(len(self.marker.read_text().splitlines()), 2)

    def test_duplicate_connection_waits_and_is_suppressed_after_success(self):
        started = self.path / 'started'
        sender = ('printf "started\\n" >> {started}; '
                  'while [[ ! -f {release} ]]; do sleep 0.02; done; '
                  'printf "sent\\n" >> {marker}').format(
                      started=shlex.quote(str(started)), release=shlex.quote(str(self.release)),
                      marker=shlex.quote(str(self.marker)))
        first = self.start(self.script(sender=sender))
        second = None
        try:
            self.wait_for_lines(started, 1)
            second = self.start(self.script(sender=sender))
            self.assertIsNone(second.poll())
        finally:
            self.release.touch()
            first.communicate(timeout=10)
            if second is not None:
                second.communicate(timeout=10)
        self.assertEqual(first.returncode, 0)
        self.assertEqual(second.returncode, 0)
        self.assertEqual(len(self.marker.read_text().splitlines()), 1)


class HelperTests(unittest.TestCase):
    def setUp(self):
        self.account = pwd.getpwuid(os.getuid())
        self.payload = {'SSH_CONNECTION': '198.51.100.25 12345 203.0.113.10 22',
                        'SSH_TTY': '/dev/pts/1'}

    def test_caller_account_and_minimal_environment(self):
        env = HELPER['session_environment'](self.payload, self.account.pw_uid)
        self.assertEqual(env['SSH_LOGIN_USER'], self.account.pw_name)
        self.assertEqual(env['USER'], self.account.pw_name)
        self.assertEqual(env['HOME'], self.account.pw_dir)
        self.assertEqual(set(env), {'PATH', 'LANG', 'HOME', 'USER', 'LOGNAME', 'SSH_LOGIN_USER', 'SSH_CONNECTION', 'SSH_TTY'})

    def test_rejects_code_paths_identity_overrides_and_bad_values(self):
        for field, value in [('BASH_ENV', '/tmp/payload'), ('PYTHONPATH', '/tmp/modules'),
                             ('SSH_LOGIN_USER', 'root'), ('SSH_TTY', None), ('SSH_USER', 'bad\0value')]:
            with self.subTest(field=field):
                with self.assertRaises(ValueError):
                    HELPER['session_environment'](dict(self.payload, **{field: value}), self.account.pw_uid)

    def test_rejects_invalid_connections(self):
        for connection in ['invalid', '198.51.100.25 0 203.0.113.10 22',
                           '198.51.100.25 12345 invalid 22', '198.51.100.25 65536 203.0.113.10 22']:
            with self.subTest(connection=connection):
                with self.assertRaises(ValueError):
                    HELPER['session_environment']({'SSH_CONNECTION': connection}, self.account.pw_uid)

    def test_accepts_ipv6_metadata(self):
        payload = {'SSH_CONNECTION': '2001:db8::1 12345 2001:db8::2 22'}
        self.assertEqual(HELPER['session_environment'](payload, self.account.pw_uid)['SSH_CONNECTION'], payload['SSH_CONNECTION'])

    def test_exec_drops_inherited_environment(self):
        stream = io.TextIOWrapper(io.BytesIO(json.dumps(self.payload).encode()))
        with patch.object(HELPER['os'], 'geteuid', return_value=0), \
             patch.object(HELPER['sys'], 'argv', ['ssh-alert-session.py']), \
             patch.object(HELPER['sys'], 'stdin', stream), \
             patch.dict(os.environ, {'SUDO_UID': str(self.account.pw_uid), 'BASH_ENV': '/tmp/payload'}, clear=True), \
             patch.object(HELPER['os'], 'execve') as execute:
            HELPER['main']()
        executable, argv, environment = execute.call_args[0]
        self.assertEqual(executable, '/bin/bash')
        self.assertEqual(argv[1], str(ROOT / 'ssh-alert-enhanced.sh'))
        self.assertNotIn('BASH_ENV', environment)

    def test_helper_rejects_nonroot_execution_and_arguments(self):
        for uid, arguments in [(1000, ['helper']), (0, ['helper', '--config=/tmp/untrusted'])]:
            with self.subTest(uid=uid, arguments=arguments):
                with patch.object(HELPER['os'], 'geteuid', return_value=uid), \
                     patch.object(HELPER['sys'], 'argv', arguments), \
                     patch.object(HELPER['sys'], 'stderr', io.StringIO()):
                    self.assertEqual(HELPER['main'](), 1)

    @unittest.skipUnless(os.geteuid() == 0, 'Root is required to exercise root-only configuration access')
    def test_privileged_helper_reads_private_config_for_nonroot_account(self):
        account = pwd.getpwnam('nobody')
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            config = directory / 'config.conf'
            log = directory / 'alert.log'
            auth = directory / 'auth.log'
            keys = directory / 'authorized_keys'
            auth.write_text('')
            keys.write_text('')
            config.write_text('TELEGRAM_BOT_TOKEN=test-only\nTELEGRAM_CHAT_ID=123\nIGNORE_LOCAL_IPS=false\n'
                              'LOG_FILE=' + shlex.quote(str(log)) + '\n'
                              'SSH_AUTHORIZED_KEYS_PATH=' + shlex.quote(str(keys)) + '\n'
                              'SSH_AUTH_LOG_PATH=' + shlex.quote(str(auth)) + '\n')
            config.chmod(0o600)
            for name in ['ssh-alert-session.py', 'key-parser.py']:
                shutil.copyfile(str(ROOT / name), str(directory / name))
            script = (ROOT / 'ssh-alert-enhanced.sh').read_text()
            script = script.replace('CONFIG_FILE="/etc/ssh-alert/config.conf"', 'CONFIG_FILE=' + shlex.quote(str(config)))
            script = script.replace('RATE_LIMIT_DIR="/run/ssh-alert/rate-limit"', 'RATE_LIMIT_DIR=' + shlex.quote(str(directory / 'rate')))
            script = script.replace('# Script entry point', '''
curl() { if [[ "$*" == *sendMessage* ]]; then printf '{"ok":true}\\n200'; else printf '203.0.113.10'; fi; }
hostname() { printf 'test-host'; }
# Script entry point''')
            (directory / 'ssh-alert-enhanced.sh').write_text(script)
            result = subprocess.run(['/usr/bin/python3', '-I', str(directory / 'ssh-alert-session.py')],
                                    input=json.dumps(self.payload), env={'SUDO_UID': str(account.pw_uid)},
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    universal_newlines=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('SSH alert sent: nobody@', log.read_text())
            self.assertEqual(config.stat().st_mode & 0o777, 0o600)


class InstallationTests(unittest.TestCase):
    def test_python_versions_use_components(self):
        for version, expected in [((3, 5), 1), ((3, 6), 0), ((3, 9), 0),
                                  ((3, 10), 0), ((3, 11), 0), ((3, 14), 0), ((4, 0), 0)]:
            with self.subTest(version=version):
                script = '''source ./install.sh
command() { if [[ "$1" == '-v' ]]; then return 0; fi; builtin command "$@"; }
python3() { /usr/bin/python3 -c 'import sys; sys.version_info = VERSION; exec(sys.argv[1])' "$2"; }
check_requirements
'''.replace('VERSION', repr(version))
                result = bash(script)
                self.assertEqual(result.returncode, expected, result.stderr)

    def test_upgrade_preserves_credentials_and_exclusions(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / 'config.conf'
            original = 'TELEGRAM_BOT_TOKEN=existing\nEXCLUDED_USERNAMES=alice\n'
            config.write_text(original)
            result = bash('source ./install.sh\nCONFIG_DIR="$1"\nchown() { :; }\ninteractive_config\n', tmp)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(config.read_text(), original)
            self.assertEqual(config.stat().st_mode & 0o777, 0o600)

    def test_all_runtime_and_management_files_are_installed(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = '''source ./install.sh
INSTALL_DIR="$1/opt"
CONFIG_DIR="$1/etc"
LOG_DIR="$1/log"
chown() { :; }
create_directories
install_files
'''
            result = bash(script, tmp)
            self.assertEqual(result.returncode, 0, result.stderr)
            for name in ['ssh-alert-enhanced.sh', 'ssh-alert-session.py', 'ssh-alert-login.sh',
                         'sshrc-editor.py', 'check-log-rotation.sh', 'manage-exclusions.sh', 'uninstall.sh']:
                path = Path(tmp) / 'opt' / name
                self.assertTrue(path.exists(), name)
                self.assertEqual(path.stat().st_mode & 0o777, 0o755)

    def test_sshrc_install_and_remove_preserve_unrelated_commands(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'sshrc'
            original = '#!/bin/sh\necho custom-setup\n'
            path.write_text(original)
            script = 'python3 ./sshrc-editor.py install "$1"\npython3 ./sshrc-editor.py install "$1"\n'
            result = bash(script, str(path))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(path.read_text().count('# BEGIN SSH Alert'), 1)
            self.assertIn(original, path.read_text())
            result = bash('python3 ./sshrc-editor.py remove "$1"\n', str(path))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(path.read_text(), original)

    def test_legacy_hook_migration_preserves_custom_commands(self):
        old = '''#!/bin/bash
# SSH Alert Integration
# This script runs on every SSH login

# Only run for interactive sessions or when explicitly requested
if [ -n "${SSH_ALERT_DISABLED:-}" ]; then
    exit 0
fi

# Run SSH Alert in background
/opt/ssh-alert/ssh-alert-enhanced.sh &
echo custom-setup
'''
        cleaned = EDITOR['clean_hook'](old)
        self.assertIn('echo custom-setup', cleaned)
        self.assertNotIn('SSH_ALERT_DISABLED', cleaned)
        self.assertNotIn('/opt/ssh-alert', cleaned)

    @unittest.skipUnless(shutil.which('visudo'), 'visudo is unavailable')
    def test_sudo_policy_is_valid_and_restricts_helper_arguments(self):
        with tempfile.TemporaryDirectory() as tmp:
            policy = Path(tmp) / 'ssh-alert'
            result = bash('''source ./install.sh
SUDOERS_FILE="$1"
install() { /usr/bin/install -m 440 "${@: -2}"; }
configure_privileges
''', str(policy))
            self.assertEqual(result.returncode, 0, result.stderr)
            text = policy.read_text()
            self.assertIn('NOPASSWD: NOSETENV: /opt/ssh-alert/ssh-alert-session.py ""', text)
            self.assertNotIn('ssh-alert-enhanced.sh', text)


if __name__ == '__main__':
    unittest.main()
