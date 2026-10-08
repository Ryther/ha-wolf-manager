# Shared implementation contract

Central integrator owns workspace Cargo.toml/Cargo.lock, AGENTS.md, README, public contracts/checklist/progress, shared metadata and development environment. Workers own only their assigned crate or slice; no reverting others. Crate manifests may consume verified workspace dependencies. Ask integrator to add a newly verified dependency rather than editing shared metadata.

`wolf-core` provides pure, re-exported typed contracts:
- PcId, AppId and ParameterId validated string newtypes, `new`, `as_str`, Display and validated serde decoding. AppId preserves the prototype 1..12 decimal-digit bound.
- ParameterDefinition {label, launch_options, description}; DebugSettings {test_ball}; GameSettings {direct_launch, proton_cachyos, parameters}; Settings {debug, parameters, games} with defaults/built-ins, validate, build_overrides and revision helpers. Maps are deterministic BTreeMaps. Revision lower-hex SHA256 covers validated canonical desired settings and parameter/debug definitions. Legacy import is explicit and separate from strict live DTO decoding; follow captured normalizer behavior for FSR4/indicator and selected-parameter order.
- Revision validated lowerhex SHA256 newtype; canonical_json helper.
- RpcRequest {version, request_id, pc_id, operation/payload} with typed RpcOperation enum, closed v1 parsing and 64KiB limit; operation variants match public runtime contract, including RequestStatus. RpcResponse with typed safe result/error. No caller paths/units or shell.
- OperationKind/OperationState plus pure all-child reconciliation outcomes, host capability/status and catalog attributes/manifest DTOs. All possibly dispatched child evidence is required. Shared error codes are stable, descriptions safe.
- Pure topic/discovery builders include PC identity and app ID. Exact ASCII ON/OFF validator rejects retained messages and malformed payloads.

Keep modules ids/settings/rpc/operations/catalog/mqtt/error small and independently tested. All downstream components use these public contracts. Pure core has no filesystem/network/process calls. Manager state/auth and host filesystem/journal/VDF adapters are being implemented as recorded in docs/progress.md; do not mistake compilation or fixture checks for a complete runtime.

## Frontend/manager boundary

Vanilla HTML/CSS/JavaScript in web/index.html, web/app.js, web/styles.css; no runtime Node service. Manager embeds those assets and substitutes escaped __WOLF_BASE__ (absolute normalized path ending slash) and __WOLF_MODE__ (standalone/ingress) in meta/base elements. Prefix-safe same-origin API base is new URL('api/v1/', application base). Standalone challenge/login/bootstrap/cookies and Ingress X-Wolf-Origin nonce follow public API contract. No credentials in localStorage. Dashboard themes are self-contained CSS dark/light tokens, with neutral panels and a mint accent; shared metadata remains central. Root package.json/package-lock owns verified Playwright 1.64.0 dev dependency. UI worker owns web/** only; test outputs stay ignored. Use exact documented APIs; any contract ambiguity goes to parent rather than introducing an alternate route.
