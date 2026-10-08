# Documentation captures

`standalone-dashboard.png` and `standalone-sign-in.png` were captured with Chromium against an isolated, actual native HTTPS manager runtime in its scratch container on 2026-10-08. Browser certificate errors were ignored only for the synthetic local test certificate. API responses were not intercepted or simulated.

The session verified administrator bootstrap, saving synthetic PC metadata (`example.test`), saving a reusable parameter, sign-out and password sign-in. No SSH probe, host lifecycle operation, catalog publication or household service was used. The dashboard capture intentionally has unknown availability and observation time; it cannot demonstrate streaming or Home Assistant compatibility. Screenshots contain no credentials or private host names.

`home-assistant-manager.png` and `home-assistant-device.png` were captured
against an isolated native KVM Home Assistant OS 18.3 VM, Supervisor 2026.09.3
and Core 2026.10.0 on 2026-10-08. The locally built scratch app renders through
actual Supervisor Ingress; the device page uses the actual MQTT integration and
Mosquitto app. The manager captured Wolf running on a separate Debian VM after
restricted SSH enrollment, staging and startup. The actual HA switch was also
used to turn Wolf ON and OFF; terminal manager results and guest service/container
state were verified. The device captured the
observed Wolf switch ON and two installed catalog sensors.

Dota 2 and Portal 2 are synthetic Steam manifests, not installed or played games.
Their cover images are fetched by the regular UI. No browser responses were
intercepted, no household services were used, and no GPU/Moonlight streaming
was tested. All manager data and image mappings were preserved across the
validated local app rebuild.
