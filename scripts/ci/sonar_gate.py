"""Bind Sonar's completed quality gate and imported Rust coverage to exact SHA."""
import argparse
import math
import os
from pathlib import Path
import re
import urllib.parse
import urllib.request
from scripts.ci import producer as p, verify_candidate as v


def get(path):
    v.require(path.startswith('/api/') and '\r' not in path and '\n' not in path, 'sonar_api_path')
    request = urllib.request.Request('https://sonarcloud.io' + path,
        headers={'Authorization': 'Bearer ' + os.environ['SONAR_TOKEN']})
    with urllib.request.build_opener(v._NoRedirect).open(request, timeout=30) as response:
        return v.json_bytes(response.read(8 * 1024 * 1024 + 1))


def rust_lcov(path):
    v.require(path is not None and path.is_file() and path.stat().st_size <= 16 * 1024 * 1024,
              'sonar_rust_lcov_required')
    raw = path.read_bytes()
    files = {}; source = None; lines = {}
    for line in raw.decode('utf-8').splitlines():
        if line.startswith('SF:'):
            v.require(source is None, 'sonar_lcov_record')
            candidate = Path(line[3:])
            if candidate.is_absolute():
                try: candidate = candidate.relative_to(Path.cwd())
                except ValueError: raise v.VerificationError('sonar_lcov_source') from None
            name = candidate.as_posix(); v.safe_path(name)
            source = name; lines = {}
        elif line.startswith('DA:'):
            v.require(source is not None, 'sonar_lcov_record')
            fields = line[3:].split(',')
            v.require(len(fields) in (2, 3) and fields[0].isdigit() and fields[1].isdigit(),
                      'sonar_lcov_line')
            number, hits = int(fields[0]), int(fields[1])
            v.require(number > 0 and number not in lines, 'sonar_lcov_line')
            lines[number] = hits
        elif line == 'end_of_record':
            v.require(source is not None, 'sonar_lcov_record')
            if re.fullmatch(r'crates/[^/]+/src/.+\.rs', source) and '/tests/' not in source and lines:
                v.require(source not in files, 'sonar_lcov_duplicate')
                files[source] = (len(lines), sum(hits == 0 for hits in lines.values()))
            source = None; lines = {}
    v.require(source is None and bool(files) and sum(total - missed for total, missed in files.values()) > 0,
              'sonar_lcov_no_covered_rust')
    return files, v.sha256(raw)


def rust_measures(project, expected):
    found = {}; page = 1; total = None; seen = 0
    while True:
        result = get('/api/measures/component_tree?component=' + urllib.parse.quote(project, safe='') +
                     '&qualifiers=FIL&strategy=leaves&metricKeys=lines_to_cover,uncovered_lines&ps=500&p=' + str(page))
        paging = result.get('paging', {})
        v.require(paging.get('pageIndex') == page and paging.get('pageSize') == 500 and
                  isinstance(paging.get('total'), int) and 0 <= paging['total'] <= 50000,
                  'sonar_file_paging')
        if total is None: total = paging['total']
        v.require(paging['total'] == total and isinstance(result.get('components'), list), 'sonar_file_paging')
        components = result['components']; seen += len(components)
        v.require(seen <= total and len(components) <= 500, 'sonar_file_paging')
        for component in components:
            if component.get('language') != 'rust': continue
            name = component.get('path', ''); v.safe_path(name)
            measures = component.get('measures', [])
            values = {item['metric']: item.get('value') for item in measures}
            v.require(len(values) == len(measures), 'sonar_file_measures')
            if values.get('lines_to_cover') in (None, '0'): continue
            v.require(component.get('qualifier') == 'FIL' and name in expected and name not in found,
                      'sonar_rust_file')
            v.require(all(isinstance(values.get(key), str) and values[key].isdigit()
                          for key in ('lines_to_cover', 'uncovered_lines')), 'sonar_file_measures')
            observed = (int(values['lines_to_cover']), int(values['uncovered_lines']))
            v.require(observed == expected[name], 'sonar_rust_lcov_mismatch')
            found[name] = observed
        if seen == total: break
        v.require(bool(components), 'sonar_file_paging'); page += 1
    v.require(set(found) == set(expected), 'sonar_rust_import_missing')
    return sum(total - missed for total, missed in found.values())


def verify(task_path, project, sha, lcov_path=None):
    expected_rust, lcov_digest = rust_lcov(lcov_path)
    v.require(v.HEX40.fullmatch(sha) and re.fullmatch(r'[A-Za-z0-9_.:-]{1,200}', project), 'sonar_identity')
    lines = task_path.read_text().splitlines()
    pairs = [line.split('=', 1) for line in lines if '=' in line]
    v.require(len({key for key, _ in pairs}) == len(pairs), 'sonar_task_metadata')
    task = dict(pairs)
    v.require(task.get('serverUrl', '').rstrip('/') == 'https://sonarcloud.io'
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
    # Analysis-specific project measures must be read immediately; any later
    # project analysis would invalidate this gate, rather than borrow coverage.
    component = get('/api/measures/component?component=' + urllib.parse.quote(project, safe='') +
                    '&metricKeys=coverage,lines_to_cover')['component']
    measures = {item['metric']: item.get('value') for item in component.get('measures', [])}
    coverage = float(measures.get('coverage', 'nan')); lines = int(measures.get('lines_to_cover', '0'))
    v.require(math.isfinite(coverage) and 0 <= coverage <= 100 and lines > 0, 'sonar_imported_coverage')
    covered_rust = rust_measures(project, expected_rust)
    latest = get('/api/project_analyses/search?project=' + urllib.parse.quote(project, safe='') + '&ps=1')
    v.require(len(latest.get('analyses', [])) == 1 and latest['analyses'][0].get('key') == analysis_id,
              'sonar_measure_analysis_race')
    return {'candidate_sha': sha, 'analysis_id': analysis_id, 'quality_gate': 'OK',
            'coverage': coverage, 'lines_to_cover': lines, 'rust_files': len(expected_rust),
            'rust_covered_lines': covered_rust, 'rust_lcov_sha256': lcov_digest}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--task', type=Path, required=True); parser.add_argument('--sha', required=True)
    parser.add_argument('--project', required=True); parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--rust-lcov', type=Path, required=True)
    args = parser.parse_args()
    try: args.output.write_bytes(p.encoded(verify(args.task, args.project, args.sha, args.rust_lcov)))
    except Exception:
        raise SystemExit('Sonar exact-candidate gate refused; credentials and raw API errors are not logged.')
