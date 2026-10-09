"""Fail CodeQL SARIF on high/critical security findings or invalid reports."""
import argparse
import math
from pathlib import Path
from scripts.ci import verify_candidate as v


def indexed(items, index, code):
    v.require(type(index) is int and 0 <= index < len(items), code)
    return items[index]


def check_identity(item, reference, fields, code):
    for field in fields:
        if field in reference:
            v.require(isinstance(reference[field], str) and reference[field]
                      and item.get(field) == reference[field], code)


def component_for(tool, reference):
    """SARIF 3.54: index addresses extensions; an absent selector means driver."""
    v.require(isinstance(tool, dict) and isinstance(reference, dict), 'codeql_component')
    driver = tool.get('driver')
    extensions = tool.get('extensions', [])
    v.require(isinstance(driver, dict) and isinstance(extensions, list)
              and all(isinstance(item, dict) for item in extensions), 'codeql_component')
    for component in [driver, *extensions]:
        v.require(isinstance(component.get('name'), str) and component['name'].strip(), 'codeql_component')
    if 'index' in reference:
        component = indexed(extensions, reference['index'], 'codeql_component')
    elif 'guid' in reference:
        matches = [item for item in [driver, *extensions] if item.get('guid') == reference['guid']]
        v.require(len(matches) == 1, 'codeql_component')
        component = matches[0]
    else:
        component = driver
    check_identity(component, reference, ('name', 'guid'), 'codeql_component')
    return component


def rule_reference(result):
    v.require(isinstance(result, dict), 'codeql_result')
    reference = result.get('rule', {})
    v.require(isinstance(reference, dict), 'codeql_rule')
    reference = dict(reference)
    for source, target in [('ruleId', 'id'), ('ruleIndex', 'index')]:
        if source in result:
            v.require(target not in reference or reference[target] == result[source], 'codeql_rule')
            reference[target] = result[source]
    v.require(any(field in reference for field in ('id', 'index', 'guid')), 'codeql_rule')
    return reference


def rule_for(tool, result):
    reference = rule_reference(result)
    component = component_for(tool, reference.get('toolComponent', {}))
    rules = component.get('rules', [])
    v.require(isinstance(rules, list) and all(isinstance(rule, dict) for rule in rules), 'codeql_rule')
    identities = [rule.get('id') for rule in rules]
    v.require(all(isinstance(identity, str) and identity for identity in identities)
              and len(set(identities)) == len(identities), 'codeql_rule')
    if 'index' in reference:
        rule = indexed(rules, reference['index'], 'codeql_rule')
    else:
        matches = [rule for rule in rules if all(rule.get(field) == reference[field]
                   for field in ('id', 'guid') if field in reference)]
        v.require(len(matches) == 1, 'codeql_rule')
        rule = matches[0]
    check_identity(rule, reference, ('id', 'guid'), 'codeql_rule')
    return rule


def security_severity(rule):
    properties = rule.get('properties', {})
    v.require(isinstance(properties, dict), 'codeql_severity')
    tags = properties.get('tags', [])
    v.require(isinstance(tags, list) and all(isinstance(tag, str) for tag in tags), 'codeql_severity')
    value = properties.get('security-severity')
    if value is None:
        v.require('security-severity' not in properties and 'security' not in tags, 'codeql_severity')
        return 0.0
    v.require(type(value) in (str, int, float), 'codeql_severity')
    try:
        severity = float(value)
    except (TypeError, ValueError):
        raise v.VerificationError('codeql_severity') from None
    v.require(math.isfinite(severity) and 0 <= severity <= 10, 'codeql_severity')
    return severity


def check_result(tool, result):
    rule = rule_for(tool, result)
    defaults = rule.get('defaultConfiguration', {})
    v.require(isinstance(defaults, dict), 'codeql_result')
    level = result.get('level', defaults.get('level', 'warning'))
    v.require(level in ('none', 'note', 'warning', 'error'), 'codeql_result')
    v.require(security_severity(rule) < 7 and level != 'error', 'codeql_high_finding')


def check_notifications(invocation):
    for field in ('toolExecutionNotifications', 'toolConfigurationNotifications'):
        notifications = invocation.get(field, [])
        v.require(isinstance(notifications, list), 'codeql_execution')
        for notification in notifications:
            v.require(isinstance(notification, dict), 'codeql_execution')
            level = notification.get('level', 'warning')
            v.require(level in ('none', 'note', 'warning'), 'codeql_execution')


def check_invocations(run):
    if 'invocations' not in run:
        return
    invocations = run['invocations']
    v.require(isinstance(invocations, list), 'codeql_execution')
    for invocation in invocations:
        v.require(isinstance(invocation, dict)
                  and invocation.get('executionSuccessful') is True, 'codeql_execution')
        check_notifications(invocation)


def sarif_gate(reports):
    v.require(bool(reports), 'codeql_no_reports')
    count = 0
    for raw in reports:
        report = v.json_bytes(raw)
        v.require(report.get('version') == '2.1.0' and isinstance(report.get('runs'), list)
                  and bool(report['runs']), 'codeql_report')
        for run in report['runs']:
            v.require(isinstance(run, dict) and isinstance(run.get('results'), list), 'codeql_results')
            check_invocations(run)
            tool = run.get('tool')
            component_for(tool, {})
            for result in run['results']:
                check_result(tool, result)
            count += 1
    return count


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path); args = parser.parse_args()
    print('Verified CodeQL SARIF runs:', sarif_gate([p.read_bytes() for p in args.directory.rglob('*.sarif')]))
