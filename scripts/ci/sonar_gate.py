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


def verify(task_path, project, sha):
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
    latest = get('/api/project_analyses/search?project=' + urllib.parse.quote(project, safe='') + '&ps=1')
    v.require(len(latest.get('analyses', [])) == 1 and latest['analyses'][0].get('key') == analysis_id,
              'sonar_measure_analysis_race')
    return {'candidate_sha': sha, 'analysis_id': analysis_id, 'quality_gate': 'OK',
            'coverage': coverage, 'lines_to_cover': lines}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--task', type=Path, required=True); parser.add_argument('--sha', required=True)
    parser.add_argument('--project', required=True); parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try: args.output.write_bytes(p.encoded(verify(args.task, args.project, args.sha)))
    except Exception:
        raise SystemExit('Sonar exact-candidate gate refused; credentials and raw API errors are not logged.')
