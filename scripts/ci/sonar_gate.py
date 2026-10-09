"""Bind Sonar's completed gate and imported language coverage to the exact SHA."""
import argparse
from contextlib import contextmanager, nullcontext
from contextvars import ContextVar
import math
import os
from pathlib import Path
import re
import xml.etree.ElementTree as ET
import urllib.parse
import urllib.request
from scripts.ci import evidence_output as e, producer as p, verify_candidate as v

SERVER = ContextVar('sonar_server', default='https://sonarcloud.io')
TOKEN = ContextVar('sonar_token', default=None)
COMMUNITY = 'http://127.0.0.1:9000'


@contextmanager
def server(url, token):
    v.require(url in ('https://sonarcloud.io', COMMUNITY), 'sonar_server_origin')
    v.require(isinstance(token, str) and 0 < len(token) <= 4096
              and not any(ord(c) < 33 or ord(c) == 127 for c in token), 'sonar_token')
    endpoint = SERVER.set(url)
    credential = TOKEN.set(token)
    try:
        yield
    finally:
        TOKEN.reset(credential)
        SERVER.reset(endpoint)


def get(path):
    v.require(path.startswith('/api/') and '\r' not in path and '\n' not in path, 'sonar_api_path')
    token = TOKEN.get()
    if token is None:
        token = os.environ['SONAR_TOKEN']
    request = urllib.request.Request(SERVER.get() + path,
        headers={'Authorization': 'Bearer ' + token})
    with urllib.request.build_opener(urllib.request.ProxyHandler({}), v._NoRedirect).open(request, timeout=30) as response:
        return v.json_bytes(response.read(8 * 1024 * 1024 + 1))


def report_bytes(path, code):
    if path is None:
        raise v.VerificationError(code)
    v.require(path.is_file() and path.stat().st_size <= 16 * 1024 * 1024, code)
    return path.read_bytes()


def lcov_source(value):
    candidate = Path(value)
    if candidate.is_absolute():
        try:
            candidate = candidate.relative_to(Path.cwd())
        except ValueError:
            raise v.VerificationError('sonar_lcov_source') from None
    name = candidate.as_posix()
    v.safe_path(name)
    return name


def add_lcov_line(value, lines):
    fields = value.split(',')
    v.require(len(fields) in (2, 3) and fields[0].isdigit() and fields[1].isdigit(), 'sonar_lcov_line')
    number, hits = int(fields[0]), int(fields[1])
    v.require(number > 0 and number not in lines, 'sonar_lcov_line')
    lines[number] = hits


def covered_source(source, language):
    if language == 'rust':
        return re.fullmatch(r'crates/[^/]+/src/.+\.rs', source) and '/tests/' not in source
    return language == 'js' and re.fullmatch(r'(?:web/[^/]+\.js|scripts/ci/[^/]+\.cjs)', source)


def lcov_records(raw):
    source = None
    lines = {}
    for line in raw.decode('utf-8').splitlines():
        if line.startswith('SF:'):
            v.require(source is None, 'sonar_lcov_record')
            source = lcov_source(line[3:])
            lines = {}
        elif line.startswith('DA:'):
            v.require(source is not None, 'sonar_lcov_record')
            add_lcov_line(line[3:], lines)
        elif line == 'end_of_record':
            v.require(source is not None, 'sonar_lcov_record')
            yield source, lines
            source = None
            lines = {}
    v.require(source is None, 'sonar_lcov_record')


def rust_lcov(path, language='rust'):
    raw = report_bytes(path, 'sonar_rust_lcov_required')
    files = {}
    for source, lines in lcov_records(raw):
        if covered_source(source, language) and lines:
            v.require(source not in files, 'sonar_lcov_duplicate')
            files[source] = (len(lines), sum(hits == 0 for hits in lines.values()))
    v.require(files and sum(total - missed for total, missed in files.values()) > 0,
              'sonar_lcov_no_covered_rust')
    return files, v.sha256(raw)


def python_class(item):
    name = item.get('filename', '')
    if not name.startswith('scripts/ci/'):
        name = 'scripts/ci/' + name
    v.safe_path(name)
    v.require(re.fullmatch(r'scripts/ci/[^/]+\.py', name), 'sonar_python_source')
    lines = item.findall('./lines/line')
    numbers = set()
    missed = 0
    for line in lines:
        number, hits = line.get('number', ''), line.get('hits', '')
        v.require(number.isdigit() and hits.isdigit() and int(number) > 0 and number not in numbers,
                  'sonar_python_line')
        numbers.add(number)
        missed += int(hits) == 0
    return name, (len(lines), missed)


def python_xml(path):
    raw = report_bytes(path, 'sonar_python_report_required')
    root = ET.fromstring(raw)
    files = {}
    for item in root.findall('.//class'):
        name, counts = python_class(item)
        v.require(name not in files, 'sonar_python_source')
        if counts[0]:
            files[name] = counts
    v.require(files and sum(total - missed for total, missed in files.values()) > 0,
              'sonar_python_no_coverage')
    return files, v.sha256(raw)


def measure_page(result, page, total, seen):
    paging = result.get('paging', {})
    v.require(paging.get('pageIndex') == page and paging.get('pageSize') == 500 and
              isinstance(paging.get('total'), int) and 0 <= paging['total'] <= 50000, 'sonar_file_paging')
    if total is None:
        total = paging['total']
    v.require(paging['total'] == total and isinstance(result.get('components'), list), 'sonar_file_paging')
    components = result['components']
    seen += len(components)
    v.require(seen <= total and len(components) <= 500, 'sonar_file_paging')
    return components, total, seen


def component_counts(component, expected, found, language):
    if component.get('language') != language:
        return None
    name = component.get('path', '')
    v.safe_path(name)
    measures = component.get('measures', [])
    values = {item['metric']: item.get('value') for item in measures}
    v.require(len(values) == len(measures), 'sonar_file_measures')
    if values.get('lines_to_cover') in (None, '0'):
        return None
    v.require(component.get('qualifier') == 'FIL' and name in expected and name not in found,
              'sonar_rust_file')
    v.require(all(isinstance(values.get(key), str) and values[key].isdigit()
                  for key in ('lines_to_cover', 'uncovered_lines')), 'sonar_file_measures')
    observed = (int(values['lines_to_cover']), int(values['uncovered_lines']))
    v.require(observed == expected[name], 'sonar_rust_lcov_mismatch')
    return name, observed


def rust_measures(project, expected, language='rust'):
    found = {}
    page, total, seen = 1, None, 0
    while True:
        result = get('/api/measures/component_tree?component=' + urllib.parse.quote(project, safe='') +
                     '&qualifiers=FIL&strategy=leaves&metricKeys=lines_to_cover,uncovered_lines&ps=500&p=' + str(page))
        components, total, seen = measure_page(result, page, total, seen)
        for component in components:
            counts = component_counts(component, expected, found, language)
            if counts is not None:
                name, observed = counts
                found[name] = observed
        if seen == total:
            break
        v.require(bool(components), 'sonar_file_paging')
        page += 1
    v.require(set(found) == set(expected), 'sonar_rust_import_missing')
    return sum(total - missed for total, missed in found.values())


def completed_analysis(task_path, project, sha):
    v.require(v.HEX40.fullmatch(sha) and re.fullmatch(r'[A-Za-z0-9_.:-]{1,200}', project), 'sonar_identity')
    pairs = [line.split('=', 1) for line in task_path.read_text().splitlines() if '=' in line]
    v.require(len({key for key, _ in pairs}) == len(pairs), 'sonar_task_metadata')
    task = dict(pairs)
    v.require(task.get('serverUrl', '').rstrip('/') == SERVER.get()
              and task.get('projectKey') == project and re.fullmatch(r'[A-Za-z0-9_-]{1,200}', task.get('ceTaskId', '')),
              'sonar_task_metadata')
    completed = get('/api/ce/task?id=' + task['ceTaskId'])['task']
    v.require(completed.get('status') == 'SUCCESS' and completed.get('componentKey') == project,
              'sonar_completed_task')
    analysis_id = completed.get('analysisId', '')
    v.require(re.fullmatch(r'[A-Za-z0-9_-]{1,200}', analysis_id), 'sonar_analysis_id')
    analyses = get('/api/project_analyses/search?project=' + urllib.parse.quote(project, safe='') + '&ps=100')
    matches = [a for a in analyses.get('analyses', []) if a.get('key') == analysis_id]
    v.require(len(matches) == 1, 'sonar_exact_analysis')
    gate = get('/api/qualitygates/project_status?analysisId=' + analysis_id)
    p.sonar_identity(matches[0], gate, sha)
    return analysis_id


def project_coverage(project):
    component = get('/api/measures/component?component=' + urllib.parse.quote(project, safe='') +
                    '&metricKeys=coverage,lines_to_cover')['component']
    measures = {item['metric']: item.get('value') for item in component.get('measures', [])}
    coverage = float(measures.get('coverage', 'nan'))
    lines = int(measures.get('lines_to_cover', '0'))
    v.require(math.isfinite(coverage) and 0 <= coverage <= 100 and lines > 0, 'sonar_imported_coverage')
    v.require(coverage >= 80, 'sonar_project_coverage_below_80')
    return coverage, lines


def mixed_imports(project, javascript_path, python_path):
    expected_js, js_digest = rust_lcov(javascript_path, 'js')
    expected_python, python_digest = python_xml(python_path)
    return {'javascript_covered_lines': rust_measures(project, expected_js, 'js'),
            'javascript_files': len(expected_js), 'javascript_lcov_sha256': js_digest,
            'python_covered_lines': rust_measures(project, expected_python, 'py'),
            'python_files': len(expected_python), 'python_xml_sha256': python_digest}


def verify(task_path, project, sha, lcov_path=None, javascript_path=None, python_path=None):
    expected_rust, lcov_digest = rust_lcov(lcov_path)
    analysis_id = completed_analysis(task_path, project, sha)
    coverage, lines = project_coverage(project)
    covered_rust = rust_measures(project, expected_rust)
    imported = {}
    if javascript_path is not None or python_path is not None:
        imported = mixed_imports(project, javascript_path, python_path)
    # A concurrent newer analysis invalidates these project-level measurements.
    latest = get('/api/project_analyses/search?project=' + urllib.parse.quote(project, safe='') + '&ps=1')
    v.require(len(latest.get('analyses', [])) == 1 and latest['analyses'][0].get('key') == analysis_id,
              'sonar_measure_analysis_race')
    return {'candidate_sha': sha, 'analysis_id': analysis_id, 'quality_gate': 'OK',
            'coverage': coverage, 'lines_to_cover': lines, 'rust_files': len(expected_rust),
            'rust_covered_lines': covered_rust, 'rust_lcov_sha256': lcov_digest, **imported}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--task', type=Path, required=True)
    parser.add_argument('--sha', required=True)
    parser.add_argument('--project', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--rust-lcov', type=Path, required=True)
    parser.add_argument('--javascript-lcov', type=Path, required=True)
    parser.add_argument('--python-xml', type=Path, required=True)
    parser.add_argument('--server-url', choices=('https://sonarcloud.io', COMMUNITY), default='https://sonarcloud.io')
    args = parser.parse_args()
    try:
        output = e.Output(args.output)
        context = (server(COMMUNITY, os.environ['SONAR_LOCAL_TOKEN'])
                   if args.server_url == COMMUNITY else nullcontext())
        with context:
            output.write_file(p.encoded(verify(args.task, args.project, args.sha, args.rust_lcov,
                                             args.javascript_lcov, args.python_xml)))
    except Exception:
        raise SystemExit('Sonar exact-candidate gate refused; credentials and raw API errors are not logged.')


if __name__ == '__main__':
    main()
