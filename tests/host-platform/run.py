#!/usr/bin/env python3
"""Run isolated distribution checks without exposing Docker or host state inside them."""
from __future__ import annotations

import argparse
import concurrent.futures
import json
from pathlib import Path
import subprocess
import uuid

ROOT = Path(__file__).resolve().parents[2]
MATRIX = json.loads((ROOT / "tests/host-platform/images.json").read_text())


def check(entry: dict[str, str], output: Path) -> dict[str, object]:
    name = f"wolf-platform-{entry['family']}-{uuid.uuid4().hex[:8]}"
    command = [
        "docker", "run", "--name", name, "--cap-drop=ALL",
        "--cap-add=CHOWN", "--cap-add=DAC_OVERRIDE", "--cap-add=FOWNER",
        "--cap-add=SETUID", "--cap-add=SETGID", "--cap-add=SYS_CHROOT",
        "--cap-add=AUDIT_WRITE", "--security-opt=no-new-privileges:false",
        "--pids-limit=256", "--memory=2g", "--tmpfs=/run",
        "--mount", f"type=bind,source={ROOT / 'installer/templates'},target=/templates,readonly",
        "--mount", f"type=bind,source={ROOT / 'tests/host-platform'},target=/fixture,readonly",
        entry["image"], "/bin/sh", "/fixture/setup.sh", entry["family"],
    ]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=900, check=False)
        (output / f"{entry['family']}.log").write_text(result.stdout + result.stderr)
        status: dict[str, object] = {"family": entry["family"], "image": entry["image"], "returncode": result.returncode}
        if result.returncode:
            setup = subprocess.run(["docker", "cp", f"{name}:/tmp/wolf-platform-setup.log", str(output / f"{entry['family']}-setup.log")], capture_output=True, check=False)
            status["setup_log_saved"] = setup.returncode == 0
        else:
            status["evidence"] = json.loads(result.stdout.strip().splitlines()[-1])
        return status
    except (subprocess.TimeoutExpired, ValueError) as error:
        return {"family": entry["family"], "image": entry["image"], "returncode": 1, "error": str(error)}
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--family", choices=[entry["family"] for entry in MATRIX["images"]], action="append")
    parser.add_argument("--jobs", type=int, default=3)
    parser.add_argument("--output", type=Path, default=ROOT / "_tmp/host-platform")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    selected = [entry for entry in MATRIX["images"] if not args.family or entry["family"] in args.family]
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, min(args.jobs, 7))) as executor:
        results = list(executor.map(lambda entry: check(entry, args.output), selected))
    (args.output / "results.json").write_text(json.dumps({"scope": MATRIX["scope"], "verified_at": MATRIX["verified_at"], "results": results}, indent=2) + "\n")
    for result in results:
        print(f"{result['family']}: {'PASS' if result['returncode'] == 0 else 'FAIL'}")
    return 1 if any(result["returncode"] for result in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
