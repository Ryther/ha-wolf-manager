"""Bind local OCI scans to exact candidate platform bytes; never rebuild images."""
import argparse
import json
import os
from pathlib import Path
from scripts.ci import evidence_output as e, verify_candidate as v

MAX_REPORT = e.MAX_REPORT
ARCHITECTURES = ('amd64', 'arm64')
BLOB_PREFIX = 'oci/blobs/sha256/'
OCI_MANIFESTS = 'manifests'


def selected(files, image, architecture):
    v.require(architecture in ARCHITECTURES, 'trivy_architecture')
    v.verify_oci(files, image)
    index = v.json_bytes(files[BLOB_PREFIX + v.parse_digest(image['index_digest'])])
    descriptors = [p for p in index[OCI_MANIFESTS] if p['platform']['architecture'] == architecture]
    v.require(len(descriptors) == 1, 'trivy_platform')
    descriptor = descriptors[0]
    manifest = v.json_bytes(files[BLOB_PREFIX + v.parse_digest(descriptor['digest'])])
    return descriptor, manifest['config']['digest']


def selector(files, image, architecture):
    descriptor, _ = selected(files, image, architecture)
    manifest = v.json_bytes(files[BLOB_PREFIX + v.parse_digest(descriptor['digest'])])
    result = {'oci-layout': files['oci/oci-layout'], 'index.json': json.dumps(
        {'schemaVersion': 2, OCI_MANIFESTS: [descriptor]}, sort_keys=True, separators=(',', ':')).encode()}
    for item in [descriptor, manifest['config'], *manifest['layers']]:
        name = 'blobs/sha256/' + v.parse_digest(item['digest'])
        result[name] = files['oci/' + name]
    return result


def check_vulnerabilities(report):
    results = report.get('Results', [])  # Trivy omits Results for an empty scratch image.
    v.require(isinstance(results, list) and len(results) <= 10000, 'trivy_results')
    count = 0
    for result in results:
        v.require(isinstance(result, dict), 'trivy_result')
        vulnerabilities = result.get('Vulnerabilities', [])
        v.require(isinstance(vulnerabilities, list), 'trivy_vulnerabilities')
        count += len(vulnerabilities)
        v.require(count <= 100000, 'trivy_vulnerability_count')
        for item in vulnerabilities:
            v.require(isinstance(item, dict) and item.get('Severity') in
                      ('UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'), 'trivy_severity')
            v.require(item['Severity'] not in ('HIGH', 'CRITICAL'), 'trivy_high_critical')


def verify_report(files, image, architecture, raw):
    v.require(isinstance(raw, bytes) and 0 < len(raw) <= MAX_REPORT, 'trivy_report_size')
    _, config_digest = selected(files, image, architecture)
    report = v.json_bytes(raw)
    v.require(isinstance(report, dict) and type(report.get('SchemaVersion')) is int
              and report['SchemaVersion'] == 2 and report.get('ArtifactType') == 'container_image',
              'trivy_report_shape')
    metadata = report.get('Metadata')
    v.require(isinstance(metadata, dict), 'trivy_metadata')
    config = metadata.get('ImageConfig')
    v.require(isinstance(config, dict) and metadata.get('ImageID') == config_digest
              and config.get('architecture') == architecture and config.get('os') == 'linux',
              'trivy_image_identity')
    check_vulnerabilities(report)
    return {'architecture': architecture, 'config_digest': config_digest,
            'report_sha256': v.sha256(raw)}


def open_directory(parent, component):
    descriptor = os.open(component, e.DIRECTORY_FLAGS, dir_fd=parent)
    try:
        e.checked(os.fstat(descriptor), directory=True)
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def open_root(path):
    parts = v.safe_path(str(path)).split('/')
    v.require(len(parts) >= 2 and parts[0] == '_tmp', 'trivy_input_path')
    descriptor = os.open('.', e.DIRECTORY_FLAGS)
    try:
        e.checked(os.fstat(descriptor), directory=True)
        for part in parts:
            child = open_directory(descriptor, part)
            os.close(descriptor); descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def read_file(root, name, limit):
    parts = v.safe_path(name).split('/')
    parent = os.dup(root)
    try:
        for part in parts[:-1]:
            child = open_directory(parent, part)
            os.close(parent); parent = child
        descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
                             dir_fd=parent)
        with os.fdopen(descriptor, 'rb') as file:
            initial = os.fstat(file.fileno()); e.checked(initial)
            v.require(0 < initial.st_size <= limit, 'trivy_input_size')
            data = file.read(limit + 1)
            final = os.fstat(file.fileno())
            fields = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_uid', 'st_gid',
                      'st_size', 'st_mtime_ns', 'st_ctime_ns')
            v.require(len(data) == initial.st_size and
                      all(getattr(final, name) == getattr(initial, name) for name in fields),
                      'trivy_input_changed')
            return data
    finally:
        os.close(parent)


def read_blob(root, files, descriptor, limit):
    v.require(isinstance(descriptor, dict), 'trivy_input_descriptor')
    name = BLOB_PREFIX + v.parse_digest(descriptor.get('digest'))
    if name not in files:
        files[name] = read_file(root, name, limit)
        v.require(len(files) <= 10000 and sum(map(len, files.values())) <= v.MAX_BUNDLE,
                  'trivy_input_total')
    v.require(len(files[name]) == descriptor.get('size') and
              v.sha256(files[name]) == v.parse_digest(descriptor['digest']), 'trivy_input_digest')
    return files[name]


def read_graph(root):
    files = {name: read_file(root, name, MAX_REPORT)
             for name in ('image.json', 'oci/oci-layout', 'oci/index.json')}
    index = v.json_bytes(files['oci/index.json'])
    v.require(isinstance(index, dict) and isinstance(index.get(OCI_MANIFESTS), list)
              and len(index[OCI_MANIFESTS]) == 1, 'trivy_input_index')
    graph = v.json_bytes(read_blob(root, files, index[OCI_MANIFESTS][0], MAX_REPORT))
    v.require(isinstance(graph, dict) and isinstance(graph.get(OCI_MANIFESTS), list)
              and len(graph[OCI_MANIFESTS]) == 2, 'trivy_input_platforms')
    for platform in graph[OCI_MANIFESTS]:
        manifest = v.json_bytes(read_blob(root, files, platform, MAX_REPORT))
        v.require(isinstance(manifest, dict) and isinstance(manifest.get('layers'), list)
                  and len(manifest['layers']) <= 1000, 'trivy_input_manifest')
        read_blob(root, files, manifest.get('config'), MAX_REPORT)
        for layer in manifest['layers']: read_blob(root, files, layer, v.MAX_FILE)
    v.verify_oci(files, v.json_bytes(files['image.json']))
    return files


def read_candidate(path):
    try:
        root = open_root(path)
        try:
            return read_graph(root)
        finally:
            os.close(root)
    except (OSError, KeyError, TypeError, AttributeError):
        raise v.VerificationError('trivy_input_invalid') from None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    for command in ('select', 'verify'):
        child = commands.add_parser(command)
        child.add_argument('--candidate', type=Path, required=True)
        child.add_argument('--architecture', choices=ARCHITECTURES, required=True)
        if command == 'select': child.add_argument('--output', type=Path, required=True)
        else: child.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    try:
        files = read_candidate(args.candidate); image = v.json_bytes(files['image.json'])
        if args.command == 'select':
            e.Output(args.output).write_tree(selector(files, image, args.architecture))
        else:
            # Use the same bounded descriptor reader for the administrator-selected report.
            report_parent = open_root(args.report.parent)
            try: raw = read_file(report_parent, args.report.name, MAX_REPORT)
            finally: os.close(report_parent)
            print(json.dumps(verify_report(files, image, args.architecture, raw), sort_keys=True))
    except (v.VerificationError, OSError, KeyError, TypeError, AttributeError):
        parser.exit(1, 'Image scan verification refused. No candidate bytes were changed.\n')


if __name__ == '__main__':
    main()
