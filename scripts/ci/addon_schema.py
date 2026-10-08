"""Validate metadata using the pinned community Home Assistant app schema.

Schema source: frenck/action-app-linter v2.21.1, commit
b9cfd1bc62ba60d2c4fc96317b5f7ada5923f4a7. MIT license is retained beside it.
This proves schema compatibility, not live Supervisor execution.
"""
from pathlib import Path
import json
import yaml
from jsonschema import Draft7Validator
from scripts.ci.producer import metadata

if __name__ == '__main__':
    metadata(Path.cwd())
    schema = json.loads(Path('scripts/ci/addon.schema.json').read_text())
    Draft7Validator.check_schema(schema)
    config = yaml.safe_load(Path('wolf_manager/config.yaml').read_text())
    errors = list(Draft7Validator(schema).iter_errors(config))
    if errors:
        raise SystemExit('Add-on metadata fails the pinned Home Assistant community schema')
    print('Add-on schema and coordinated version validated')
