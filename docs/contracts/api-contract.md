# Canonical v1 API and authentication contract

This file replaces earlier proposals. API is same-origin /api/v1. Deployment mode ingress or standalone is immutable at startup; no cross-mode fallback. JSON DTOs reject unknown fields and invalid identifiers. Errors are {"error":{"code":"stable_code","message":"safe explanation","operation_id":"optional UUID"}}; never include credentials/raw external errors.

## Transport and auth

Standalone: native HTTPS with mounted cert/key or an explicitly configured TLS reverse proxy as sole published path, matching an exact configured public_origin. In proxy mode reject other TCP peers; trust forwarding only after allowed-peer admission. In native mode do not use forwarding headers. No plain-HTTP password/session mode in production. UI assets/public auth status/challenge are available unauthenticated; PC/catalog/settings/logs and mutations require admin cookie.

Ingress: listen0.0.0.0:8099 internally, require normalized TCP peer exactly172.30.32.2 BEFORE any route, else403 ingress_peer_forbidden. No published ports/host_network. After transport admission principal is ha-ingress; Supervisor already authenticated the session. X-Remote-User-* is optional audit context, not authorization. Disable standalone bootstrap/login/session/recovery routes. Normalize trusted X-Ingress-Path as absolute prefix with no query/fragment/dot components and trailing slash; generate prefix-safe relative asset/API/log URLs. Ingress CSRF issuance requires frontend X-Wolf-Origin set to window.location.origin. Validate an http/https origin with no userinfo, path, query or fragment, and bind its exact normalized value to the opaque CSRF token. Mutations require standard browser Origin equal to that token-bound origin. Do not infer an authorization origin from Forwarded headers or require household URL configuration. Transport admission is still exclusively the Supervisor peer ACL; X-Wolf-Origin is nonce binding, never identity. Issuance emits no CORS headers; a foreign browser origin cannot read a token or supply the custom header without a refused preflight.

Official authority: https://developers.home-assistant.io/docs/apps/presentation/ and https://github.com/home-assistant/supervisor/blob/9ce1060ba7cfb833899d0ba81d8dbaf9fa4eed15/supervisor/api/ingress.py. Mode-specific auth refusal tests must execute transport gate before route handlers; no header-only bypass.

## Auth flow table

| Route | Admission/payload | Result |
| --- | --- | --- |
| GET /bootstrap/status | Standalone only |200 {initialized:boolean}; no credentials. |
| GET /auth/login-challenge?purpose=login or bootstrap | Standalone; bounded active challenge rate |200 {challenge,expires_at}; random256-bit base64url, store digest+peer+purpose+expiry5min. |
| POST /bootstrap | Uninitialized, exact public_origin Origin, X-Wolf-CSRF=challenge bound to peer/purposebootstrap, Bearer protected bootstrap-token-file value, {password,challenge} |201 session cookie + {csrf_token,expires_at}; initialize administrator atomically, logical bootstrap disable. Wrong token401; initialized409 bootstrap_completed; no mounted-secret unlink. |
| POST /auth/login | Standalone, exact Origin, X-Wolf-CSRF=single-use challenge bound to peer/purposelogin, {password,challenge} |200 session cookie + {csrf_token,expires_at}; invalid401 login_failed,5failures/15minperpeer then429. Consume challenge before password verification. |
| GET /auth/session | Standalone authenticated cookie |200 {authenticated:true,expires_at}; no bearer token. |
| GET /auth/csrf | Standalone authenticated session OR transport-admitted Ingress principal |200 {csrf_token,expires_at}; hash token in session or ingress-CSRF record; Ingress requires X-Wolf-Origin and stores its normalized origin,30min expiry. |
| POST /auth/logout | Standalone authenticated cookie+Origin+CSRF |204; revoke session and expire cookie. |
| POST /auth/password | Standalone authenticated cookie+Origin+CSRF; {current_password,new_password} |204 after hash replacement and revocation of all sessions. |

Session cookie __Host-wolf_session: Secure,HttpOnly,SameSiteStrict,Path=/,noDomain. Random256-bit bearer token is persisted only by SHA256 digest; Argon2id versioned PHC password hashes. Idle12h/absolute7d. Unsafe authenticated standalone requests require exact configured Origin and session-bound X-Wolf-CSRF. Ingress mutations require a live ha-ingress CSRF digest and nonempty Origin exactly equal to its issuance-bound origin; no standalone cookie. No CORS response headers. Never require authentication cookie for pre-auth login/bootstrap; those use one-time peer/purpose challenge instead. Keep ephemeral records bounded and log no token/password.

## Authorized product routes and DTOs

All below inherit mode admission. Prefix paths shown relative to /api/v1.

| Method/path | DTO or query | Result |
| --- | --- | --- |
| GET /system/{health,ready,version} | No secrets; mode-specific peer admission applies |200 state/version/protocol1;503 unready. Exec healthcheck uses a private runtime marker if transport ACL would prevent loopback HTTP. |
| GET /pcs | None |200 {pcs:[Pc]} excluding keys/secretvalues. |
| POST /pcs | {pc_id,display_name,ssh_host,ssh_port,ssh_user} |201 Pc; validate identifiers/port/host and no privileged policy input. |
| PATCH /pcs/{pc_id} | {display_name,ssh_host,ssh_port,ssh_user} |200 Pc; endpoint changes invalidate pending probes/trust and require explicit re-enrollment before RPC. pc_id immutable. |
| DELETE /pcs/{pc_id} | None |204 archive and owned-discovery cleanup; no host state removal. Refuse active/unresolved operation409. |
| GET /pcs/{pc_id}/ssh/public-key | None |200 {public_key}; generated Ed25519 key private bytes never returned. |
| POST /pcs/{pc_id}/ssh/probe | None |200 {probe_id,algorithm,fingerprint,expires_at}; no saved trust/RPC. |
| POST /pcs/{pc_id}/ssh/enroll | {probe_id,fingerprint} |200 enrolled state; must match unexpired probe/endpoint/key exactly. |
| POST /pcs/{pc_id}/ssh/test | None |202 preflight operation only after enrollment. |
| GET /pcs/{pc_id}/status | None |200 last observed service/capabilities/revision/availability and timestamp, or503 no observation. |
| GET /pcs/{pc_id}/games | None |200 {games,catalog_generation,observed_at,availability}; stale is labeled, not empty. |
| GET /pcs/{pc_id}/settings | None |200 desired settings+desired_revision+staged/running observation. |
| PUT /pcs/{pc_id}/games/{app_id}/settings | {expected_desired_revision,direct_launch,proton_cachyos,parameters:[parameter_id]} |200 new desired revision; unsupported capability422 validation_failed; stale409. |
| GET /parameters | None |200 reusable definitions. |
| PUT /parameters/{parameter_id} | {label,launch_options,description} |200 definition + affected desired revisions. |
| DELETE /parameters/{parameter_id} | None |204 if unreferenced;409 parameter_in_use otherwise. |
| PUT /settings/debug | {test_ball} |200 globaldebug and affected desired revisions. |
| POST /pcs/{pc_id}/apply | {expected_desired_revision} |202 stage override operation; no implicit live restart. |
| POST /pcs/{pc_id}/service/{start,restart} | {expected_desired_revision} |202 operation; start on active desired state is idempotent, restart stages desired overrides first, then verifies/stops/restores/starts. |
| POST /pcs/{pc_id}/service/stop | Empty object |202 stop; not blocked by stale game revision, but serialize with in-progress operations. |
| GET /pcs/{pc_id}/operations | limit1..100/cursor |200 bounded result page. |
| GET /operations/{operation_id} | None |200 operation state/sanitized result. |
| GET /pcs/{pc_id}/logs | lines1..500 (default100) |200 bounded sanitized lines/truncated flag; SSH read<=1MiB. No unbounded follow endpoint in v1. |

Pc exposes configured endpoint/display, trust fingerprint/state and protocol, never password/private key. Operation JSON: operation_id,pc_id,kind,state,desired_revision,timestamps,sanitized_result. Received work returns202 {operation_id,state:queued}; conflicting mutation409 operation_in_progress with active ID. Manager restart marks pending/running unknown_interrupted; no auto replay. Revision is lowerhexSHA256 canonical settings. Input JSON<=64KiB except read-only responses bounded separately; request media typeapplication/json. Parameter launch_options<=4096UTF8bytes/noCRLF/NUL, selected IDs unique/inorder and present. Cover URLs are derived from verified Steam app ID/known CDN, not arbitrary proxy/SSRF fetch inputs.

Status codes:400 bad_request/validation_failed,401 unauthenticated/login_failed/invalid_bootstrap_token,403 forbidden/csrf_failed/ingress_peer_forbidden,404 not_found,409 stale_revision/operation_in_progress/host_key_mismatch/unknown_interrupted/bootstrap_completed/parameter_in_use,413 payload_too_large,415 unsupported_media_type,422 validation_failed for unsupported capability,429 login_rate_limited,503 host_unavailable. Internal failures return sanitized500 internal_error and keep operation recovery state.

## Reconciliation route

POST /operations/{operation_id}/reconcile with {} requires administrator or transport-admitted Ingress plus CSRF. It performs the read-only journal reconciliation in runtime-contract.md and returns 200 {operation,state,resolution}; host unavailable returns 503 and leaves uncertainty. A running conflicting mutation returns 409. No route fabricates a successful outcome, replays the mutation or removes unresolved records. Resolution records verified completion, verified non-execution or still unresolved evidence.

Reconciliation responses include each child request_id/kind/dispatch_phase/verified outcome (no secrets). The parent state follows the all-child rules in runtime-contract.md. No API lets the caller select or replace child IDs, digests, payloads or host policy.

## Verified stage-only completion

If staging is independently verified succeeded and the planned primary child remains durably not_dispatched, reconciliation terminates the parent as failed with code primary_not_dispatched and explicit stage_succeeded evidence. Desired/staged revision is visible, running revision remains the observed prior value. This is verified partial execution, never parent success or non-execution. No replay occurs; a subsequent explicit user action is a new operation after reconciliation. Any other possibly dispatched child must be terminally evidenced first; otherwise the parent remains unknown_interrupted. Test the crash after stage acknowledgment but before primary sending is committed.

## Read-response DTO completion

All timestamps are integer Unix milliseconds. Settings GET returns `{settings: Settings, desired_revision: string, staged_revision: string|null, running_revision: string|null}`. Status GET returns `{status: HostStatus, capabilities: HostCapabilities, availability: "online"|"offline"|"unknown", observed_at: integer}`; no observation still returns 503. Parameters GET returns `{parameters: {parameter_id: ParameterDefinition}}`. Operation pages return `{operations: [Operation], next_cursor: string|null}`. Operation timestamps use `submitted_at`, `started_at`, `completed_at` (last two nullable), with the already frozen fields above. These wrappers complete existing route shapes without changing product behavior or authority.

Games GET returns `{games: [CatalogAttributes], catalog_generation: integer, observed_at: integer, availability: "online"|"offline"|"unknown"}`; desired choices are from `settings.games[app_id]`, with shared defaults for absent settings.

SSH probe is a zero-body POST without a Content-Type requirement; CSRF and exact browser Origin remain mandatory. This exception is specific to the documented no-payload probe route. JSON-object endpoints continue requiring application/json.
