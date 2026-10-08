"""Bind scheduled scans to the exact immutable image in a public release record."""
import argparse
from pathlib import Path
from scripts.ci import verify_candidate as v


def image_reference(raw, tag):
    record = v.json_bytes(raw)
    v.require(isinstance(tag, str) and tag.startswith('v')
              and v.SEMVER.fullmatch(tag[1:]), 'published_tag')
    v.require(record.get('schema_version') == 1 and record.get('version') == tag[1:]
              and v.HEX40.fullmatch(record.get('candidate_sha', ''))
              and v.positive_int(record.get('workflow_run_id')), 'published_identity')
    digest = v.parse_digest(record.get('image_index_digest'))
    platforms = record.get('platforms')
    v.require(isinstance(platforms, list) and len(platforms) == 2, 'published_platforms')
    architectures = set()
    for platform in platforms:
        v.require(isinstance(platform, dict) and platform.get('os') == 'linux'
                  and platform.get('architecture') in ('amd64', 'arm64'), 'published_platform')
        v.parse_digest(platform.get('digest'))
        architectures.add(platform['architecture'])
    v.require(architectures == {'amd64', 'arm64'}, 'published_platforms')
    return 'ghcr.io/ryther/ha-wolf-manager@sha256:' + digest


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--record', required=True, type=Path)
    parser.add_argument('--tag', required=True)
    args = parser.parse_args()
    print(image_reference(args.record.read_bytes(), args.tag))
