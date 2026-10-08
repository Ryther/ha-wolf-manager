"""Fail CodeQL SARIF on high/critical security findings or invalid reports."""
import argparse
from pathlib import Path
from scripts.ci import verify_candidate as v


def sarif_gate(reports):
    v.require(bool(reports), 'codeql_no_reports')
    count = 0
    for raw in reports:
        report = v.json_bytes(raw)
        v.require(report.get('version') == '2.1.0' and isinstance(report.get('runs'), list)
                  and bool(report['runs']), 'codeql_report')
        for run in report['runs']:
            rules = {item['id']: item for item in run['tool']['driver'].get('rules', [])}
            v.require(isinstance(run.get('results'), list), 'codeql_results')
            for result in run['results']:
                rule = rules.get(result.get('ruleId'), {})
                severity = rule.get('properties', {}).get('security-severity', '0')
                try: severity = float(severity)
                except (TypeError, ValueError): raise v.VerificationError('codeql_severity') from None
                v.require(severity < 7 and result.get('level') != 'error', 'codeql_high_finding')
            count += 1
    return count


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path); args = parser.parse_args()
    print('Verified CodeQL SARIF runs:', sarif_gate([p.read_bytes() for p in args.directory.rglob('*.sarif')]))
