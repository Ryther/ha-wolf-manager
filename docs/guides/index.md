# Use HA Wolf Manager

Choose one manager deployment, then install the host toolkit on each PC. The manager stores accounts, SSH identities, desired settings and operation history. The PC retains Wolf, Steam data and root-owned policy. Neither deployment requires Ansible.

- [Standalone HTTPS service](standalone.md): Docker Compose, protected files and first login.
- [Home Assistant add-on](home-assistant.md): Ingress, MQTT discovery and automation.
- [Install or adopt a PC](host-installation.md): local preview, restricted SSH and fingerprint enrollment.
- [Operate multiple PCs](operations.md): games, parameters, revisions and controls.
- [Back up and recover](backup-recovery.md): protected bundles, retained rollback state and explicit offline import of prototype settings.
- [Troubleshoot](troubleshooting.md): bounded logs, offline state and uncertain operations.

Use published artifacts only after checking their release checksums and provenance. These guides describe the implementation in this repository; they do not assert that an image or release is already available. Distribution checks in containers do not establish compatibility on a directly installed OS, GPU, encoder or Moonlight client. Native streaming and Home Assistant validation remain separate checks. See the [test matrix](../contracts/test-matrix.md).
