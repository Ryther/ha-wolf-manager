# Use HA Wolf Manager

Choose one manager deployment, then install the host toolkit on each PC. The manager stores accounts, SSH identities, desired settings and operation history. The PC retains Wolf, Steam data and root-owned policy. Neither deployment requires Ansible.

- [Standalone HTTPS service](standalone.md): Docker Compose, protected files and first login.
- [Home Assistant add-on](home-assistant.md): Ingress, MQTT discovery and automation.
- [Install or adopt a PC](host-installation.md): local preview, restricted SSH and fingerprint enrollment.
- [Operate multiple PCs](operations.md): games, parameters, revisions and controls.
- [Back up and recover](backup-recovery.md): protected bundles, retained rollback state and explicit offline import of prototype settings.
- [Troubleshoot](troubleshooting.md): bounded logs, offline state and uncertain operations.

Use published artifacts only after checking their release checksums and provenance. These guides describe the implementation in this repository; they do not assert that an image or release is already available. Distribution checks in containers do not establish compatibility on a directly installed OS, GPU, encoder or Moonlight client. The isolated HAOS/Supervisor control plane has been exercised with a separate Debian test PC and synthetic Steam manifests. That evidence does not establish GPU streaming, game execution, a household deployment or every Home Assistant version. See the [test matrix](../contracts/test-matrix.md).

## Check your first successful setup

1. The manager is healthy and its intended authentication works: an HA administrator
   can open **Wolf Manager**, or the standalone account can **Sign in** over HTTPS.
2. The PC's independently verified SSH fingerprint is enrolled, **Test connection**
   has a recorded successful outcome, and **Refresh** shows a recent observation.
3. Catalog state is fresh and complete. With MQTT enabled, Home Assistant discovers
   the PC's **Wolf** switch and its observed value matches the actual host state.
4. For an explicit lifecycle test outside a gaming session, inspect **Operation
   history** and the PC's container state after Start/Stop. A button's admission
   notice or saved desired revision does not establish success.

These are control-plane checkpoints. Validate GPU/encoder access, game launch and
Moonlight streaming separately on the intended hardware before relying on it.
