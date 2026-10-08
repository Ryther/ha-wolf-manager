# Canonical v1 integration and MQTT contract

External user-owned broker; add-on gets supported Supervisor service data in Rust, standalone explicit broker config/secretfiles. Reject direct-secret/_FILE conflicts and missing/unreadable secretfiles. Installer never creates users/ACLs implicitly. Direct upstream services only: Wolf, HA, SSH, MQTT, GitHub/GHCR/Sonar/Pages. The product has no dependency on Ansible or a workstation provisioning repository.

## SSH enrollment

Manager probe does handshake only, returnsalgorithm+SHA256fingerprint+probeUUID+5minexpiry withouttrust or privilegedRPC. Enrollment echoesmatchingprobe/fingerprint/endpoint; storehostkeypublic bytes andfingerprint atomically. Subsequentmismatch refuses beforeauthcommand; explicitrotation repeatsprobe/confirm andauditrecord. PrivateEd25519key/data/keys/<pcid>/id_ed255190600 generatedperPC; GETpublickeyonly. Rootpolicy/authorizedkeys/operationlimits are runtimecontract authority; JSONcommandalwayswolf-manager-rpc-v1, no constructed shellsyntax.

## Exact MQTT topic table

Defaultbase wolf-manager/v1; configurablevalidated root with no wildcards. HAdiscoveryprefix default homeassistant; HAbirth homeassistant/status payloadonline. pc_id/app_id validate sharedcontract. Table spells defaultstrings; all producer/ACL/HAconfig functions derive identical configured roots.

| Topic | Owner/payload | QoS/retained |
| --- | --- | --- |
| wolf-manager/v1/<pcid>/host/availability | Host online/offline; retainedlastwilloffline |1/yes |
| wolf-manager/v1/<pcid>/catalog/<appid>/state | Host installed |1/yes |
| wolf-manager/v1/<pcid>/catalog/<appid>/attributes | Host {version:1,pc_id,app_id,name,cover_url,library_id,catalog_generation,observed_at_ms} |1/yes |
| homeassistant/sensor/wolf_manager_<pcid>_game_<appid>/config | Host game sensor discovery |1/yes |
| wolf-manager/v1/<pcid>/service/availability | Manager online/offline derivedSSH/statusavailability, not copiedhostwill |1/yes |
| wolf-manager/v1/<pcid>/service/state | Manager ON/OFF only from confirmedserviceobservation; unavailablepreservespriorstate |1/yes |
| wolf-manager/v1/<pcid>/service/attributes | Manager {version:1,pc_id,observed_at_ms,systemd_state,container_state,restart_count,staged_revision,running_revision,recovery_pending,last_operation_id} |1/yes |
| wolf-manager/v1/<pcid>/service/command | HA exactASCII ON/OFF; noJSON/whitespace/RESTART |0/no |
| wolf-manager/v1/<pcid>/service/result | Manager {version:1,pc_id,operation_id,state,code,observed_at_ms}; nosensitivebody |1/no |
| homeassistant/switch/wolf_manager_<pcid>_service/config | Manager switch discovery |1/yes |

Gameunique_id wolf_manager_<pcid>_game_<appid>, switchunique_id wolf_manager_<pcid>_service; shareddeviceidentifier wolf_manager_<pcid>, namePCdisplaylabel, manufacturerHAWolfManager. Gamestate installed, jsonattributes/covers, hostavailability. SwitchpayloadON/OFF, manageravailability andobservedstate, optimisticfalse; noMQTTrestartbutton. DashboardauthenticatedRESTrestartonly; HAswitch/voiceidempotentstartstop. Cataloggameexistsnotserviceavailability; actualsuccessfulgenerationcomparisonalonecleans removedowneddiscovery/state/attributes by retainedempty messages.

Manager subscribes ownPCcommandtopics andcatalogattributes/availability/HAbirth; host subscribesHAbirth. Both replayonlyowneddiscovery/state onbirth/reconnect. MQTTcommandsuseclean nonpersistent session, no offline queue, strictretained rejection andQoS0. To preserve publisher retain flag for live deliveries, MQTTv5 retain-as-published true and retain-handling do-not-send-retained apply to command subscription; broker must support this before controls becomeavailable. No insecure silentv3command fallback; catalogonlymodecanremainavailable. Freeze/exercise exactclientlibrary v5 API in dependencyspike. State/publicationcanQoS1; duplicateON/OFFatservicealreadytargetstate is no-op. Conflictingactiveoperationrejectsbusy, unknown_interrupted/recovery_pendingblocksstart/restartuntilobserved/reconciled; stop may be admitted only when it safely resolves recovery. A lostQoS0 command is visible through unchangedobservedstate, not speculativeUIstate.

## ACL templates

- Host identityforPCwritesexactitscatalogsubtree, hostavailability anditsgame discoveryconfigs; readsHAbirth. Cannotwriteservicecommands/state/anotherPC.
- Manager readsconfiguredcatalogsubtrees/hostavailability, exactconfiguredservicecommands andHAbirth; writesconfiguredservice availability/state/attributes/result andswitchconfigs. Cannotwritehostcatalogdiscovery.
- HA readsdiscovery/state/availability/attributes/results andwritesconfiguredcommandtopics withretainfalse/QoS0. Otherbrokerauthenticatedusersgetnocommandwriteunlessoperatorexplicitlygrantsit.

BrokerstandardACLcannotuniversallyenforceretainflag; subscriberprotocolvalidationisrequiredinadditiontoACL. Namespace publisherownershipisolatesPCsandcleanup. OfflineSSH/MQTT never meansconfirmedemptylibrary/OFF. Persisttimestamps/generationandlabelstaleprojection.

## Add-on protocol

Supervisoroptions/authserviceaccesshandlednativelyinRust; read/data/options.json, use SUPERVISOR_TOKEN onlyfor scopedserviceMQTT request at supportedSupervisorendpoint. Noexternalprogrambootstrap; no loggingtoken/brokerpassword. config declares services mqtt:need, ingress, initfalse andpaneladmintrue; runtime defaultmodeIngressselectedbyadd-on startup config, standaloneexplicitmode. Image/architectureversionmapping is rolloutcontract. TrustedSupervisorTCPpeeronly172.30.32.2; optionalremoteuserinfoauditonly, prefixdataforURLsonly. Configure/testOriginmechanics without header-onlyauth assumption.

User guides cover broker ACLs, host-key verification, voice controls and replacement of legacy command-line switches. Changes to existing Home Assistant automations require a separate, verified cutover.

## Complete catalog generation

Host additionally owns retained QoS1 wolf-manager/v1/<pcid>/catalog/manifest: {version:1,pc_id,catalog_generation,app_ids:[decimal strings],observed_at_ms,complete:true}. Generation is a monotonically increasing durable u64 counter stored in host catalog state, never reset on daemon restart; refuse overflow/corrupt state. Maximum 10000 IDs and 2 MiB manifest, unique sorted IDs. Scan successfully before publishing. Publish every listed game's generation-matching attributes/state and discovery, wait for QoS1 acknowledgment, then publish and acknowledge the complete manifest. Only then remove prior owned entries with empty retained discovery/state/attributes. Failed scans preserve previous generation and produce no manifest/cleanup. Empty manifest list is valid only after a successful scan.

Manager buffers attributes by PC/generation with bounded 10000-entry/16 MiB limits, and commits a complete generation atomically only when manifest and every listed attribute match generation/identity. Retained subscription ordering is arbitrary. Missing messages leave last committed catalog stale, never empty; timeout drops incomplete buffers and requests normal read-only replay. Lower generations refuse; equal generation must be identical, conflicting duplicate refuses. Empty retained attributes are tombstones, handled as projection removal only after an accepted complete manifest excludes that ID.

MQTT client identities: host wolf-manager-host-<pcid>; manager wolf-manager-manager-<durable instance UUID>. One manager owns its registered PCs; duplicate instance registration is an operator error documented in onboarding. Global manager availability topic wolf-manager/v1/manager/<instance_uuid>/availability has retained QoS1 online/offline and an offline last will. Service discovery requires both this global availability and the per-PC observed service availability (availability_mode all). Thus unclean manager loss cannot leave an apparently available control. Command subscription uses MQTT5 clean start/session expiry0, preserve_retain=true, retain handling2, QoS0. ACL templates add host manifest write and manager manifest read; manager alone writes its global availability.

## Command rejection before admission

A command rejected before a durable operation is created publishes the same closed result envelope with `operation_id: null`, `state: rejected`, the canonical safe error code and observation timestamp. It does not invent a UUID or history entry. Accepted commands publish only their actual durable operation identifier. Retained or malformed command payloads are never executed or included in result bodies. This clarifies the nullable identifier for pre-admission refusal; command QoS remains 0 and state/results QoS remains 1.
