## Problem and resulting behavior

Describe the concrete trigger and the behavior after this change.

## Validation

- Exact commands and results:
- Environment/commit tested:
- Simulated, container-only or native/live limits:
- User-visible steps, screenshots and affected guide/skill updates:

For a user journey change, describe the disposable environment, observed UI
outcome and relevant retained-byte checks. For documentation changes, record
the strict build and desktop/narrow-screen walkthrough. Review diagnostics and
screenshots before sharing them; exclude credentials and household details.

## State and compatibility

Explain changed contracts, migration/rollback steps and how Steam data, Wolf identity/custom apps, manager state and retained journals/backups are preserved. Write "No stateful behavior changes" when applicable.

## Review checklist

- [ ] The patch has a bounded scope and relevant public documentation.
- [ ] Authorization, revisions and failure/recovery paths are checked where affected.
- [ ] Tests use disposable fixtures and contain no household credentials/state.
- [ ] Commit messages follow `.cz.yaml`; coordinated versions remain Release Please's responsibility.
- [ ] Dependency changes include current primary sources and any compatibility constraint.
