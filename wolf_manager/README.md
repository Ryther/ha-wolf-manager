# HA Wolf Manager add-on

Manage multiple Wolf PCs from Home Assistant through the administrator-only **Wolf Manager** Ingress panel. Configure Steam game options, review desired/staged/running revisions, inspect bounded logs and control Wolf through discovered MQTT switches.

This add-on is **experimental**. Repository code and local tests are not evidence of an already published image, direct-OS GPU compatibility or a validated Moonlight streaming session. Install only a verified published release after reviewing its notes and checks.

The add-on supports Supervisor-managed `amd64` and `aarch64` installations, uses the shared scratch manager image and obtains MQTT broker settings from Supervisor. It does not require Ansible, a manager Docker socket or an interactive SSH account. Each PC needs the independently installed host toolkit and an enrolled, independently verified SSH fingerprint.

See [add-on documentation](DOCS.md), the [Home Assistant guide](../docs/guides/home-assistant.md), [host installation](../docs/guides/host-installation.md) and [release verification](../docs/guides/releases.md). Home Assistant Container users can use the [standalone HTTPS service](../docs/guides/standalone.md).
