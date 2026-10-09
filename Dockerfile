# The candidate producer compiles each native architecture once. This Dockerfile
# packages those exact binaries; it deliberately contains no build stage.
FROM scratch

ARG VERSION
ARG REVISION
LABEL org.opencontainers.image.title="HA Wolf Manager" \
      org.opencontainers.image.description="Home Assistant and standalone management for Wolf hosts" \
      org.opencontainers.image.source="https://github.com/Ryther/ha-wolf-manager" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      io.hass.name="HA Wolf Manager" \
      io.hass.description="Manage Wolf hosts through restricted SSH and MQTT" \
      io.hass.type="addon" \
      io.hass.version="${VERSION}"

COPY --chmod=0755 build/ha-wolf-manager /ha-wolf-manager
COPY --chmod=0755 build/wolf-manager-host /wolf-manager-host
COPY LICENSE /LICENSE
COPY --chmod=0444 vendor/rumqttc/LICENSE /licenses/rumqttc.txt

ENV WOLF_DATA_DIR=/data \
    WOLF_MODE=ingress \
    RUST_LOG=info
VOLUME ["/data"]
EXPOSE 8099

# Native startup prepares an empty Supervisor volume and drops to UID/GID 1000
# before starting the runtime. Existing data is validated, never recursively
# reassigned. Standalone users may pre-own /data and start directly as 1000:1000.
USER 0:0
ENTRYPOINT ["/ha-wolf-manager"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 CMD ["/ha-wolf-manager", "healthcheck"]
