# Upstream default configuration

`config.v7.toml` is copied without changes from Games on Whales Wolf's stable
branch, commit `6a5053b4ebbb19f2c0f3bf1e8fbbd8babf109273`, path
`src/moonlight-server/state/default/config.v7.toml`, verified 2026-10-08.
The accompanying MIT license and upstream copyright must remain distributed.

The installer uses these defaults only when creating an absent configuration.
Adoption preserves the existing configuration, pairing identity and custom apps.
The upstream default applications use rolling `main`/`edge` images; these tags
are upstream compatibility choices, not independently versioned stable releases.
Operators should review the runner template before enabling applications.

The verified stable Wolf image currently advertises linux/amd64 only. Publishing
our own manager and host binaries for arm64 does not imply upstream Wolf GPU or
OS support on that architecture. An ARM host needs a separately verified,
compatible Wolf image; default installation must refuse incompatible images.
