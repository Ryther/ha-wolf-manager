"""Require coverage and exactly the event's selected Sonar scanner."""
import os


def _flag(name):
    value = os.environ[name]
    if value not in {'true', 'false'}:
        raise SystemExit('Invalid Sonar routing flag')
    return value == 'true'


def evaluate(event_name, trusted_pr, coverage, cloud, community, report_present):
    # Reused from HAPatchY's required scanner aggregate, including dispatch.
    if coverage != 'success' or not report_present:
        return False
    if event_name in {'push', 'workflow_dispatch'}:
        return cloud == 'success' and community == 'skipped'
    if event_name == 'pull_request':
        if trusted_pr:
            return cloud == 'success' and community == 'skipped'
        return community == 'success' and cloud == 'skipped'
    return False


def main():
    if not evaluate(os.environ['SONAR_EVENT_NAME'], _flag('SONAR_TRUSTED_PR'),
                    os.environ['SONAR_COVERAGE_RESULT'], os.environ['SONAR_CLOUD_RESULT'],
                    os.environ['SONAR_COMMUNITY_RESULT'], _flag('SONAR_REPORT_PRESENT')):
        raise SystemExit('Required Sonar scan or report is missing or unsuccessful')


if __name__ == '__main__':
    main()
