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

## Verified isolated runtime

On 2026-10-08 an isolated native KVM Home Assistant OS 18.3 installation
exercised real Supervisor Ingress and MQTT discovery using the scratch manager
app and the official Mosquitto app. Home Assistant Core was 2026.10.0;
Supervisor was 2026.09.2 initially and 2026.09.3 after reboot. A separate
Debian VM ran the independently installed host toolkit and actual Wolf control
plane. Restricted SSH enrollment, preflight, settings staging, start, restart
and stop passed through the manager browser. The native catalog service
published complete, acknowledged generations with two synthetic Steam manifests.
The real HA device page observed the Wolf switch ON and both game sensors.

The documented screenshots are actual browser captures, not intercepted API
fixtures. The manifest entries do not establish that games were installed or
played. GPU encoding, Moonlight streaming and the complete ARM host-to-manager
installation remain untested. Expanded native amd64 and arm64 scratch fixtures
passed in [GitHub PR run 37863000299](https://github.com/Ryther/ha-wolf-manager/actions/runs/37863000299)
for head `226251c` and merge subject `07c3a67`. Each fixture exercised the exact
built image through verified HTTPS, pinned SSH, MQTT5 over TLS, protected writable
state, native healthcheck, drained SIGTERM and retained restart state. This PR
evidence must be repeated for the exact release candidate SHA before publication.
Other distribution evidence remains container-only as listed in the README.

Manager updates retained the same Supervisor `/data` mapping, byte-verified cold
backups and previous images. Native host upgrades retained reviewed installer
plans and preimages. No household service or persistent game data was used.

Compatibility regressions cover upstream Wolf's fresh configuration mapping,
normal public-key file endings, duplicate bounded SSH environment directives,
OpenSSH window updates before exec confirmation and inactive missing containers
being available OFF in MQTT. Unknown or inconsistent observations remain
unavailable. The catalog unit disables `RestrictSUIDSGID` because
[systemd documents](https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml)
that it blocks the guarded `openat2` I/O used by the service; the non-root UID,
`NoNewPrivileges` and protected filesystem remain enforced.

## Coverage scope

Measure full-workspace Rust coverage and documented opt-in broker/root cases
against a frozen source revision. Keep raw evidence private. Verify each imported
Rust source file's executable/uncovered-line counts against LCOV rather than
accepting a project-wide number as proof of successful Rust ingestion.

LLVM summary lines/regions and Sonar LCOV lines have distinct denominators.
Report both clearly; new-code coverage is a separate metric from overall
coverage. JavaScript/Python coverage must be measured and imported separately.
High line coverage does not replace real OS, protocol-ordering, crash-safety or
streaming checks. A configured overall-coverage gate must be reported honestly
when it fails.

Fresh reports from [GitHub PR run 37863000299](https://github.com/Ryther/ha-wolf-manager/actions/runs/37863000299),
head `226251c` and merge subject `07c3a67`, measured
**81.2% (12,691/15,625 executable lines)** across Rust LCOV execution records,
Python Cobertura and JavaScript LCOV. The original candidate-subject ZIP and its
artifact digests were independently verified before accepting the extracted
reports and their source identity. This PR workflow does not run SonarCloud;
fresh reports do not replace the trusted release candidate's analysis.

Separately, the local SonarQube Community analysis at `1ad8661` verified exact
per-file imports for all 52 Rust, two JavaScript and 11 Python report files,
reported the same 81.2% overall coverage and passed its overall 80% gate. It had
no unresolved findings, reported bugs, vulnerabilities or security hotspots.
This local result does not establish absence of defects or certify a later SHA.

| Component | Covered / executable lines | Line coverage |
| --- | ---: | ---: |
| Rust workspace | 11,142 / 13,904 | 80.14% |
| Core contracts | 660 / 700 | 94.29% |
| Host toolkit | 6,066 / 7,325 | 82.81% |
| Manager | 4,416 / 5,879 | 75.11% |
| Python release tooling | 1,185 / 1,346 | 88.04% |
| Browser and Node coverage converter | 364 / 375 | 97.07% |

The fresh PR execution passed 84 Python release tests and 34 Chromium browser
journeys, including keyboard/mobile controls, stale revisions,
authentication expiry, unknown observations and confirmed stopped hosts. V8
execution includes the Node converter itself; imported coverage is not generated
from an inventory of unexecuted code.

Fresh Rust execution in that PR run passed 242 tests: 220 standard tests and all
22 explicitly selected broker/root cases; strict workspace Clippy passed. LLVM
summary coverage was **78.89% (11,558/14,650 lines)**; its accounting differs from
the encoded LCOV execution-line denominator above. Neither report measures
branch coverage.
Integration-test files are excluded from the Rust
source report; inline test modules remain included. The executable denominator
therefore includes those inline tests and is not a production-only metric.
Vendored third-party source is excluded from owned product coverage.
Installer line coverage was 87.9%, coordinator 94.6%, SSH 94.0% and authentication
93.9%. Manager CLI/bootstrap and failure branches still have uncovered lines;
coverage is not a claim that every runtime path has been exercised.

The isolated HA app retained byte-exact cold backups, ownership and modes during
updates. Native toolkit upgrades retained guarded preview/apply/activate plans
and verified preimages. Actual HA MQTT ON/OFF and native SSH refresh passed after
the toolkit upgrade; Steam/Wolf files, pairing keys, policy and broker credentials
remained unchanged. The updated catalog executable was verified active with zero
failure restarts. These runtime checks complement the measured fixture execution;
they are not instrumented GPU/Moonlight tests.

The checked-in CI independently regenerates all three reports for trusted
candidates, enforces at least 80% combined coverage and verifies exact report
imports and analysis revision. A successful local Community analysis cannot
substitute for the required live SonarCloud analysis of a release candidate.
