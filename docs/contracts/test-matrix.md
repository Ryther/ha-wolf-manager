# Required test/evidence matrix

| Slice | Positive and refusal cases | Evidence boundary |
| --- | --- | --- |
| Shared contracts/import | Prototype-equivalent settings; invalid IDs/types; unknown schema; unsupported Proton selection; preserved custom apps/identity. | Rust tests on synthetic/copied disposable bytes. |
| Filesystem transactions | Apply/restore; interrupted recovery; corruption/permission/disk failure; symlink/path refusal; no-loss/unchanged bytes; no implicit cleanup. | Temporary real files and crash/restart fault cases. |
| SSH/privilege | Native static client; key generation/enrollment; changed host key rejection; allowed operation; unknown unit/path/command; forwarding/PTY refusal; root-owned policy. | Disposable SSH host and bounded helper fixtures; no household account modifications. |
| Auth/Ingress | First-use setup, login/logout/recovery, CSRF, expired/revoked session, unauthenticated direct API, forged Ingress identity and path prefixes. | Disposable HA or authoritative source-backed faithful fixture; distinguish mock from real Supervisor evidence. |
| MQTT/multi-PC | Same game on two hosts; late subscriber, broker reconnect/HA birth, unavailable versus stopped, retained commands rejected, no duplicate command replay/publishers. | Disposable broker; verify retained wire state and actual outcomes. |
| Wolf lifecycle | Cached startup on registry timeout, no image refusal, apply/restore hooks, failures, service status and unchanged reconciliation without restart. | Real disposable systemd environment for lifecycle; isolate registry/CLI fixtures and identify simulated Wolf/hardware evidence. |
| UI | Two-host onboarding, game covers/settings/parameters, save/apply distinction, PC controls, diagnostics, errors and mobile/keyboard paths. | Browser screenshots/API checks against isolated runtime. |
| Scratch targets | amd64/arm64 static executable, no shell assumption, non-root writable data/secret files, TLS/SSH/MQTT, health and signals. | Per-target image startup/build/scan evidence; emulation labeled. |
| Distro compatibility | Arch, CachyOS, Debian, Ubuntu LTS, Fedora, openSUSE Tumbleweed and Leap install/adopt/idempotence/path/permission checks. | Exact image/release/result recorded per row; unavailable variants explicitly untested. Real OS/GPU streaming is separate. |
| Public guides/skills | Follow add-on/Docker/SSH/HA-control/voice/recovery instructions, correct expected UI/output, canonical/Claude skill identity. | Disposable observed procedures and MkDocs/link checks; no claim guide procedures ran because unit tests passed. |
| CI/release | Conventional commits, formatting/Clippy/tests, CodeQL, Gitleaks, Sonar correct report/exact SHA, image/Cargo vulnerability gate, candidate bytes/version identity and serialized drafts. | Local workflow/script contracts plus actual trusted GitHub checks when implemented. |

Each requirement needs executed checks appropriate to its boundary. Record commands, versions, scope, observed results and limitations in test or release evidence. Focused fixtures do not establish direct-OS or GPU streaming compatibility. Never include household secrets or raw private payloads.

## Domain-pass additional acceptance

- Manager process restart marks pending/running operations unknown_interrupted and sends no replayed remote mutation.
- Native static SSH connects only with enrolled expected key; changed key, original command, PTY/forwarding, unknown unit/path and oversized JSON refuse.
- Ingress peer ACL rejects forged trusted-user headers from other peers; proxied prefix-safe UI/API/log transport succeeds and no standalone cookie fallback is accepted.
- Two PCs with the same app ID have distinct catalog/settings/discovery; retained commands refuse and ON/OFF is idempotent.
- Repeated generated-app reconciliation does not restart Wolf; install/adopt verifies exact mappings and recovery before changing bytes.
- Each scratch architecture proves static linkage, native SSH/TLS/MQTT, writable protected state, exec-form health and signal shutdown.

## Focused auth/SSH refusal evidence

Ingress forged peer+headers returns403 before route processing; accepted Supervisor identity reaches prefixed UI/API/log transport and standalone auth endpoints remain unavailable. Standalone wrong/missing/replayed bootstrap, expiry/revocation, exact cookie flags, Origin/CSRF/CORS refusal and offline credential recovery preserve PC/key/settings records.

A real disposable sshd/helper fixture proves unknown/empty original command, malformed/oversized JSON, PTY/agent/local/remote/X11 forwarding, arbitrary units/paths/symlinks/direct helper/sudo/shell all refuse. Enrolled-key allowed operation succeeds; unconfirmed/mismatched host key sends no command and logs remain bounded.

## Canonical repair acceptance

Test the exact routes, SQL constraints, root policy, byte limits and topic payloads in the canonical contracts. Include pre-auth challenge replay/peer/purpose rejection, mounted bootstrap secret read-only behavior, Ingress origin-bound nonce and forbidden cross-origin preflight, optional remote-user headers, restart uncertainty and desired/staged/running distinctions. Use a real disposable MQTT v5 broker to test live retained publication with retain-as-published and retained-history exclusion; unsupported v5 must disable controls visibly. Use a real disposable sshd with a locked-password /bin/sh account and no-argument sudo rule: allowed RPC succeeds, generic shell and forwarding fail. Installer rollback must preserve fixture bytes and ownership. Verify Release Please workspace/add-on updater fixtures, OCI index/add-on architecture mapping and same-byte publication. No production gate may substitute a mock result for its declared real integration scope.

## Safety repair evidence

Prove authorized keys readable but not writable by restricted user; root journal crash/lookup/digest-reuse refusal; manager reconciliation never clears uncertainty from service state alone; restart stage/stop/restore/start failure boundaries; Steam restore drift preserves current and backup bytes; no RPC/hook lock deadlock; complete catalog generation ordering, empty success, failed scan and tombstones; global manager last will; independently retrieved GitHub check authority and malicious receipt/archives rejected.

Crash tests for a stage-then-restart parent: before stage send, after stage send before acknowledgment, after verified stage before primary send, during primary send, after host completion before manager commit. Verify every child has a stable distinct UUID/digest and reconciliation never clears a possibly dispatched stage merely because the primary is not_dispatched. Sent missing records remain unknown; complete journal evidence resolves only the appropriate succeeded/failed parent, with partial-stage outcome visible.

## Verified stage-only completion

If staging is independently verified succeeded and the planned primary child remains durably not_dispatched, reconciliation terminates the parent as failed with code primary_not_dispatched and explicit stage_succeeded evidence. Desired/staged revision is visible, running revision remains the observed prior value. This is verified partial execution, never parent success or non-execution. No replay occurs; a subsequent explicit user action is a new operation after reconciliation. Any other possibly dispatched child must be terminally evidenced first; otherwise the parent remains unknown_interrupted. Test the crash after stage acknowledgment but before primary sending is committed.

## Local acceptance snapshot — 2026-10-08

An isolated native KVM Home Assistant OS 18.3 VM with Supervisor 2026.09.2,
Core 2026.10.0 and Mosquitto app 7.1.1 installed and started the local manager
app using its scratch Dockerfile. Real authenticated Supervisor Ingress, the
sidebar shortcut, PC creation and host-key enrollment were exercised through
the browser. These checks do not yet establish complete lifecycle and catalog
acceptance, GPU streaming or native ARM compatibility.

On source revision `4615205`, 207 standard Rust tests and 13 selected disposable
broker/root cases passed. LLVM reported 73.87% line coverage and 68.75% region
coverage. The LCOV representation imported into local SonarQube covered
9,613 of 12,750 Rust lines (75.40%): core 94.22%, host 77.13%, manager 71.05%.
The different report representations have different executable-line denominators.
All 52 Rust source-file counts were checked against imported Sonar measures.

The full mixed-language project measured 68.5%, including JavaScript and Python
source without imported execution coverage. An explicitly configured local
overall-coverage gate at 80% failed. This local gate is separate from the hosted
project's quality-gate configuration. Coordinator and installer coverage remain
priorities; these measurements are a baseline, not release approval. Coverage
must be regenerated after subsequent fixes and additional safety tests.

Actual host-fixture failures found regression gaps in fresh Wolf configuration
paths, terminal newlines in public-key files and repeated effective SSH
`AcceptEnv` directives during installed-policy validation. The environment
restriction still refuses any additional client variable or wildcard; repeated
identical sentinel directives grant no extra authority.

The follow-up snapshot on `9f8b568` passed 214 standard tests and the same
13 selected opt-in cases. Rust LCOV increased to 9,797/12,768 lines (76.73%);
manager coverage increased to 74.37% and coordinator coverage to 94.6%.
Overall Sonar coverage increased to 69.7%, while new-code coverage was 94.7%.
These measurements precede the subsequently discovered native OpenSSH and
systemd catalog compatibility fixes. High line coverage does not prove that a
faithful protocol fixture exercises every message ordering seen on a real host.

The actual Debian VM demonstrated that OpenSSH sends a channel-window update
before exec acceptance. RPC input must still wait for explicit exec success.
The catalog sandbox also returned `ENOSYS` with `RestrictSUIDSGID=yes`:
[systemd documents](https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml)
that this restriction blocks `openat2` entirely. The catalog unit explicitly
disables that incompatible restriction while retaining its non-root UID,
`NoNewPrivileges`, protected filesystem and guarded descriptor-based I/O.
