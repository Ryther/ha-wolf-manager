"""Disposable Community analysis and safe paginated Sonar diagnostics.

The scanner lifecycle adapts HAPatchY's fresh-token/finally-revoke flow;
its project-wide gate is replaced by Wolf's exact CE/revision/import verifier.
"""
import argparse
import base64
from contextlib import contextmanager
import os
from pathlib import Path
import re
import secrets
import subprocess
import time
import urllib.parse
import urllib.request
from scripts.ci import evidence_output as e, producer as p, sonar_gate as s, verify_candidate as v

SCANNER = 'sonarsource/sonar-scanner-cli@sha256:a3f4215076706c95a17a68c19322ee916e40a3acd081a8c1a1e839e0194afa57'


@contextmanager
def temporary_token(api):
    name = 'ephemeral-ci-' + secrets.token_hex(16)
    # Revocation covers malformed generation responses as well as failed scans.
    try:
        result = api('/api/user_tokens/generate', {'name': name}, post=True)
        token = result.get('token')
        v.require(isinstance(token, str) and 0 < len(token) <= 4096
                  and not any(ord(c) < 33 or ord(c) == 127 for c in token), 'sonar_token')
        yield token
    finally:
        api('/api/user_tokens/revoke', {'name': name}, post=True)


def pages(fetch, endpoint, params, field):
    """Reuse reference _pages, with bounded and stable complete pagination."""
    rows = []
    page, total = 1, None
    while True:
        response = fetch(endpoint, {**params, 'p': page, 'ps': 500})
        paging = response.get('paging', {})
        observed = paging.get('total', response.get('total'))
        v.require(type(observed) is int and 0 <= observed <= 50000
                  and paging.get('pageIndex', page) == page
                  and paging.get('pageSize', 500) == 500, 'sonar_diagnostic_paging')
        if total is None:
            total = observed
        batch = response.get(field)
        v.require(observed == total and isinstance(batch, list) and len(batch) <= 500
                  and all(isinstance(row, dict) for row in batch), 'sonar_diagnostic_paging')
        rows.extend(batch)
        v.require(len(rows) <= total, 'sonar_diagnostic_paging')
        if len(rows) == total:
            return rows
        v.require(bool(batch), 'sonar_diagnostic_paging')
        page += 1


def finding(row, project):
    component = row.get('component', '')
    # Hotspot APIs may use opaque component IDs. Keep no unverified path.
    path = component[len(project) + 1:] if component.startswith(project + ':') else ''
    if path:
        v.safe_path(path)
    rule = row.get('rule', row.get('ruleKey', ''))
    v.require(isinstance(rule, str) and re.fullmatch(r'[A-Za-z0-9_.:-]{0,200}', rule), 'sonar_diagnostic_rule')
    line = row.get('line')
    v.require(line is None or type(line) is int and 0 < line <= 10000000, 'sonar_diagnostic_line')
    severity = row.get('severity', '')
    v.require(severity in ('', 'INFO', 'MINOR', 'MAJOR', 'CRITICAL', 'BLOCKER'), 'sonar_diagnostic_severity')
    return {'rule': rule, 'path': path, 'line': line, 'severity': severity}


def diagnostics(fetch, project):
    v.require(isinstance(project, str) and re.fullmatch(r'[A-Za-z0-9_.:-]{1,200}', project), 'sonar_identity')
    issues = pages(fetch, '/api/issues/search', {'componentKeys': project, 'resolved': 'false'}, 'issues')
    hotspots = pages(fetch, '/api/hotspots/search', {'projectKey': project}, 'hotspots')
    return {'issues': [finding(row, project) for row in issues],
            'hotspots': [finding(row, project) for row in hotspots]}


def token_fetch(path, params):
    return s.get(path + '?' + urllib.parse.urlencode(params))


class LocalAdmin:
    """Only the disposable loopback server can receive bootstrap credentials."""
    def __init__(self):
        login = os.environ.get('SONAR_LOCAL_ADMIN_LOGIN', 'admin')
        password = os.environ['SONAR_LOCAL_ADMIN_PASSWORD']
        v.require(isinstance(login, str) and re.fullmatch(r'[A-Za-z0-9_.-]{1,100}', login)
                  and password and len(password) <= 4096, 'sonar_local_admin')
        self.authorization = 'Basic ' + base64.b64encode((login + ':' + password).encode()).decode()

    def __call__(self, path, params=None, post=False):
        v.require(path in ('/api/system/status', '/api/projects/create',
                          '/api/user_tokens/generate', '/api/user_tokens/revoke'), 'sonar_local_api')
        data = urllib.parse.urlencode(params or {}).encode() if post else None
        request = urllib.request.Request(s.COMMUNITY + path, data=data,
                                         headers={'Authorization': self.authorization})
        with urllib.request.build_opener(urllib.request.ProxyHandler({}), v._NoRedirect).open(request, timeout=30) as response:
            raw = response.read(8 * 1024 * 1024 + 1)
            return {} if response.status == 204 else v.json_bytes(raw)


def ready(api):
    for _ in range(120):
        try:
            if api('/api/system/status').get('status') == 'UP':
                return
        except (OSError, KeyError, ValueError):
            pass
        time.sleep(2)
    raise v.VerificationError('sonar_local_not_ready')


def report_path(path):
    name = v.safe_path(str(path))
    s.report_bytes(Path(name), 'sonar_report_required')
    return str(Path.cwd() / name)


def scanner(args, token):
    """Run inert source analysis; no candidate settings, scripts or Clippy execution."""
    work = e.Output(args.work)
    descriptor = e.descend(work.parts, exclusive=True)
    os.close(descriptor)
    settings = ('sonar.projectKey=' + args.project + '\nsonar.sources=crates,web,scripts,installer\n'
                'sonar.sourceEncoding=UTF-8\nsonar.exclusions=**/tests/**,web/tests/**,scripts/ci/addon.schema.json\n'
                'sonar.rust.clippy.enabled=false\nsonar.qualitygate.wait=true\nsonar.qualitygate.timeout=600\n')
    e.Output(str(args.work) + '/sonar-project.properties').write_file(settings.encode())
    command = ['docker', 'run', '--rm', '--memory', '2g', '--cpus', '2', '--network', 'host', '--user', str(os.geteuid()) + ':' + str(os.getegid()),
               '--workdir', str(Path.cwd()), '--mount', 'type=bind,source=' + str(Path.cwd()) + ',target=' + str(Path.cwd()) + ',readonly',
               '--mount', 'type=bind,source=' + str(Path.cwd() / args.work) + ',target=/sonar-work',
               '-e', 'SONAR_TOKEN', '-e', 'SONAR_HOST_URL=' + s.COMMUNITY,
               '-e', 'SONAR_USER_HOME=/sonar-work/cache', SCANNER,
               '-Dproject.settings=/sonar-work/sonar-project.properties',
               '-Dsonar.working.directory=/sonar-work/analysis', '-Dsonar.projectVersion=' + args.sha,
               '-Dsonar.scm.revision=' + args.sha, '-Dsonar.rust.lcov.reportPaths=' + report_path(args.rust_lcov),
               '-Dsonar.javascript.lcov.reportPaths=' + report_path(args.javascript_lcov),
               '-Dsonar.python.coverage.reportPaths=' + report_path(args.python_xml)]
    # Raw scanner output can contain source snippets; never store or upload it.
    result = subprocess.run(command, env={'PATH': os.defpath, 'SONAR_TOKEN': token},
                            stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, timeout=900, check=False)
    v.require(result.returncode == 0, 'sonar_local_scanner_failed')
    return Path(args.work) / 'analysis/report-task.txt'


def scan(args):
    v.require(v.HEX40.fullmatch(args.sha) and re.fullmatch(r'[A-Za-z0-9_.:-]{1,200}', args.project), 'sonar_identity')
    output = e.Output(args.output)
    diagnostic_output = e.Output(args.diagnostics)
    api = LocalAdmin()
    ready(api)
    api('/api/projects/create', {'project': args.project, 'name': args.project}, post=True)
    with temporary_token(api) as token, s.server(s.COMMUNITY, token):
        try:
            task = scanner(args, token)
            result = s.verify(task, args.project, args.sha, args.rust_lcov, args.javascript_lcov, args.python_xml)
            output.write_file(p.encoded(result))
        finally:
            diagnostic_output.write_file(p.encoded(diagnostics(token_fetch, args.project)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    analysis = commands.add_parser('scan')
    for name in ('project', 'sha'):
        analysis.add_argument('--' + name, required=True)
    for name in ('rust-lcov', 'javascript-lcov', 'python-xml', 'work', 'output', 'diagnostics'):
        analysis.add_argument('--' + name, required=True, type=Path)
    export = commands.add_parser('diagnostics')
    export.add_argument('--project', required=True)
    export.add_argument('--output', required=True, type=Path)
    export.add_argument('--server-url', choices=(s.CLOUD, s.COMMUNITY), default=s.CLOUD)
    args = parser.parse_args()
    try:
        if args.command == 'scan':
            scan(args)
        else:
            output = e.Output(args.output)
            token = os.environ['SONAR_TOKEN' if args.server_url == s.CLOUD else 'SONAR_LOCAL_TOKEN']
            with s.server(args.server_url, token):
                output.write_file(p.encoded(diagnostics(token_fetch, args.project)))
    except Exception:
        raise SystemExit('Sonar operation refused; credentials and raw remote errors are not logged.') from None


if __name__ == '__main__':
    main()
