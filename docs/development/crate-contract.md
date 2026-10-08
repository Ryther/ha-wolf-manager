# Shared implementation contract

Workspace Cargo.toml/Cargo.lock define shared dependencies. Keep crate responsibilities separate and review shared protocol changes together with their consumers. Preserve unrelated changes and review the complete dependency lock diff.

`wolf-core` provides pure, re-exported typed contracts:
- PcId, AppId and ParameterId validated string newtypes, `new`, `as_str`, Display and validated serde decoding. AppId preserves the prototype 1..12 decimal-digit bound.
- ParameterDefinition {label, launch_options, description}; DebugSettings {test_ball}; GameSettings {direct_launch, proton_cachyos, parameters}; Settings {debug, parameters, games} with defaults/built-ins, validate, build_overrides and revision helpers. Maps are deterministic BTreeMaps. Revision lower-hex SHA256 covers validated canonical desired settings and parameter/debug definitions. Legacy import is explicit and separate from strict live DTO decoding; follow captured normalizer behavior for FSR4/indicator and selected-parameter order.
- Revision validated lowerhex SHA256 newtype; canonical_json helper.
- RpcRequest {version, request_id, pc_id, operation/payload} with typed RpcOperation enum, closed v1 parsing and 64KiB limit; operation variants match public runtime contract, including RequestStatus. RpcResponse with typed safe result/error. No caller paths/units or shell.
- OperationKind/OperationState plus pure all-child reconciliation outcomes, host capability/status and catalog attributes/manifest DTOs. All possibly dispatched child evidence is required. Shared error codes are stable, descriptions safe.
- Pure topic/discovery builders include PC identity and app ID. Exact ASCII ON/OFF validator rejects retained messages and malformed payloads.

Keep modules ids/settings/rpc/operations/catalog/mqtt/error small and independently tested. All downstream components use these public contracts. Pure core has no filesystem/network/process calls. Compilation and focused fixtures do not establish complete runtime or OS compatibility; verify the affected adapter boundaries.

## Frontend/manager boundary

Vanilla HTML/CSS/JavaScript in web/index.html, web/app.js, web/styles.css; no runtime Node service. Manager embeds those assets and substitutes escaped __WOLF_BASE__ (absolute normalized path ending slash) and __WOLF_MODE__ (standalone/ingress) in meta/base elements. Prefix-safe same-origin API base is new URL('api/v1/', application base). Standalone challenge/login/bootstrap/cookies and Ingress X-Wolf-Origin nonce follow public API contract. No credentials in localStorage. Dashboard themes are self-contained CSS dark/light tokens, with neutral panels and a mint accent; package.json/package-lock define the verified Playwright 1.64.0 development dependency. Browser tests cover the documented APIs; generated evidence stays ignored. Resolve API ambiguity in the shared technical contract before introducing a route.

## Native SSH integration boundary

The ssh.rs module owns Endpoint {pc_id,host,port,user,host_key_algorithm,host_key_public,host_key_fingerprint}, Probe {algorithm,public_key,fingerprint}, native identity creation/read, unauthenticated bounded host-key probe, enrolled-key authenticated connect and ReadyClient::execute(&RpcRequest)->RpcResponse. Optional host-key fields are allowed only for probe/onboarding; connect requires the complete mutually consistent enrolled key. Server-key verification occurs before authentication/channel/command; command is exactly wolf-manager-rpc-v1, no PTY/forwarding/SFTP. A ready authenticated connection lets the coordinator persist child sending immediately before request submission. No arbitrary command/path accepts browser data.

Generate identities only at the manager-owned fixed keys/<pc_id>/id_ed25519 path with directory0700/file0600, aliases/hardlinks refused and no private bytes returned/logged. Probe is read-only and supplies standard SHA256 fingerprint plus OpenSSH public key; the user explicitly confirms that fingerprint before any authenticated mutation. Native transport has bounded connect/request/output/error paths; failed or interrupted dispatch never retries a mutation. Typed replies are validated against exact original request bytes/ID/PC/revision. Disposable SSH evidence is separate from household/Home Assistant compatibility.
