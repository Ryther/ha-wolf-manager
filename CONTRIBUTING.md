# Contributing to HA Wolf Manager

HA Wolf Manager contains an authenticated Rust manager, independently installed PC tools, an embedded browser UI and Home Assistant/MQTT integration. Keep manager authentication, root-owned PC authority and desired/staged/running settings distinct. Preserve Steam data, Wolf pairings, custom apps and retained recovery evidence.

## Reproduce changes safely

Use the repository [Dev Container](.devcontainer/devcontainer.json), or the toolchain and dependency inputs pinned in [rust-toolchain.toml](rust-toolchain.toml) and the lockfiles. Inspect a contribution before executing it, then reproduce its reported behavior at the exact commit in a disposable checkout. Do not give contributed code household Home Assistant, Steam, SSH, broker or Docker credentials. Document environment differences when a failure cannot be reproduced.

Tests use temporary state, native SSH/HTTP fixtures and a disposable broker. Browser API fixtures demonstrate the browser contract; they do not establish native backend, Home Assistant or streaming compatibility. Distribution containers check their declared fixture scope, not an installed workstation's GPU/encoder. Root installer tests require their documented opt-in disposable environment.

Read [AGENTS.md](AGENTS.md), the relevant [contracts](docs/contracts/integration-contract.md), and [development interfaces](docs/development/crate-contract.md) before altering shared behavior. Public source, comments, documentation and commit messages are English.

## Validate the affected behavior

From the repository root:

```sh
python3 -m venv _tmp/python-venv
. _tmp/python-venv/bin/activate
python -m pip install --only-binary ':all:' -r scripts/ci/requirements.txt
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
npm ci
npm run test:ui
python -m unittest discover -s tests/release -v
```

Run focused checks while developing, then the affected required checks before submitting. Report exact commands, results and limits. The live MQTT test uses a disposable broker selected through `WOLF_TEST_MQTT_HOST` and `WOLF_TEST_MQTT_PORT`; never point those variables at a household broker. Use [host platform fixtures](tests/host-platform/README.md) for their limited distribution checks. When changing workflows, validate syntax with the repository's pinned actionlint tooling and review permissions, fork behavior, subject identity and artifact boundaries.

Add regressions for meaningful behavioral changes, especially authorization, revision checks, filesystem recovery, journal reconciliation and candidate verification. Test observable results and retained bytes rather than duplicating implementation details. Do not modify real services to make a test pass.

## Submit a reviewable change

Explain the concrete problem, resulting behavior and evidence in the pull request. Identify compatibility limits, migrations and recovery behavior. Update the relevant public guide/contract with a behavioral change. Keep unrelated formatting, dependency updates and repository metadata out of the patch.

Use the repository's [.cz.yaml](.cz.yaml) convention, for example `fix(ssh): reject mismatched enrolled fingerprints`. Validate the message with:

```sh
cz check --message 'fix(ssh): reject mismatched enrolled fingerprints'
```

Release Please owns coordinated versions and changelogs. Do not run independent version bumps or update only one of Cargo, npm and add-on metadata. Dependency updates must include fresh primary-source verification, lockfile review and an explanation of intentional older constraints. See [release operations](docs/guides/releases.md).

PR workflows use read permissions and no release/Sonar secrets. Their evidence cannot authorize publication. Trusted main candidates run the independent release checks, including Sonar, before the protected publisher can transfer the exact bytes. A passing source test alone does not establish that an image has been released.

For suspected vulnerabilities, follow [SECURITY.md](SECURITY.md). Public issues should contain sanitized reproductions, never private keys, passwords, recovery bundles or raw database state.
