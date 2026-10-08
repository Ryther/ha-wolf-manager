# Home Assistant add-on and MQTT

[Documentation home](index.md) · [Next: install a PC](host-installation.md)

## Install the add-on

Use a Home Assistant installation that supports Supervisor add-ons and an administrator account. Home Assistant Container installations can use the [standalone service](standalone.md) instead. Configure a working MQTT broker and the Home Assistant MQTT integration first.

Once a verified release is published, add `https://github.com/Ryther/ha-wolf-manager` to the Supervisor add-on store's repository list and install **HA Wolf Manager**. Select the version whose release evidence you reviewed. Start it and open **Wolf Manager** from its panel. The add-on declares `amd64` and `aarch64`; that does not establish upstream Wolf streaming support on an ARM PC.

Ingress uses Home Assistant's administrator authentication. Do not supply a standalone bootstrap token, TLS settings or MQTT credentials to the add-on. It gets broker settings through Supervisor's MQTT service lookup. Its two options are:

```yaml
topic_base: wolf-manager/v1
discovery_prefix: homeassistant
```

Keep these identical to every host catalog publisher. The manager image is shared with the standalone deployment; the add-on selects Ingress mode. Ingress authorization checks the actual Supervisor proxy peer, not headers submitted by an arbitrary LAN client. There is no direct public listener declared by the add-on.

## Entities and automations

Install each PC's [host toolkit](host-installation.md), enable its catalog publisher and add the same immutable PC ID to the manager. The host publishes installed Steam games; the manager publishes the **Wolf** switch for that PC. MQTT discovery groups them under the PC device. The switch uses observed state, not optimistic UI state. Catalog or service unavailability is meaningful: a retained old value is not proof that a PC is currently reachable.

In Home Assistant, use the actual discovered switch entity in your automation. For example, select it as the target of the `switch.turn_on` or `switch.turn_off` action. Voice exposure depends on your existing Home Assistant voice/Google Home configuration; this project does not edit that configuration. Turning Wolf on does not power on a physically shut-down PC.

If you publish raw commands, the topic is `wolf-manager/v1/<pc-id>/service/command`, payload exactly `ON` or `OFF`, **retain false**. Retained commands are rejected to prevent delayed starts after reconnect. Operation admission and final service observation are separate; inspect the manager's operation history if a command fails or remains uncertain.

## Broker separation

Use separate broker identities for the manager, each host publisher, and Home Assistant. [Example Mosquitto ACLs](https://github.com/Ryther/ha-wolf-manager/blob/main/examples/mqtt/acl.example) show the fixed `gaming-pc` namespace. Replace usernames and PC IDs and merge them with your broker policy; the file contains no passwords. The host discovery ACL intentionally enumerates two example app IDs: extend it with every authorized installed game (and retain removed IDs until their cleanup is acknowledged). MQTT wildcards match whole topic levels, so a partial `wolf_manager_<pc>_game_+` pattern does not restrict a host correctly. Do not broaden it to every sensor to bypass this requirement. See the [official Mosquitto ACL syntax](https://mosquitto.org/man/mosquitto-conf-5.html). Do not grant a host publisher access to service command topics or other PCs. The manager needs command subscription, observed catalog subscription, discovery publication and manager/service availability publication. Home Assistant needs discovery/state reads and non-retained service command writes.

Keep broker backups and TLS credentials separate from the manager backup. For Supervisor backup, the add-on declares a cold backup so its process is stopped while state is captured. Also keep a verified manager bundle for independent recovery; see [backup and recovery](backup-recovery.md).
