FROM rust:1.99.0-slim-trixie@sha256:24e632c09342c20abf8312cf4f61430a911c01ed3a5e4c02b87292b1c39c5273 AS rust
FROM mcr.microsoft.com/playwright:v1.64.0-noble@sha256:06a9939e57531807f8d5fd76ce44b53165ffb7d7501d87ab10e285c20b1e971f

# Copy the upstream GNU toolchain; use Ubuntu's own compiler and system libraries.
COPY --from=rust /usr/local/rustup /usr/local/rustup
COPY --from=rust /usr/local/cargo /usr/local/cargo
ENV RUSTUP_HOME=/usr/local/rustup
ENV PATH=/usr/local/cargo/bin:$PATH
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential pkg-config libssl-dev python3 python3-venv git openssh-client ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && rustup component add clippy rustfmt \
    && if getent passwd 1000 >/dev/null; then \
         account="$(getent passwd 1000 | cut -d: -f1)"; \
         usermod -l vscode -d /home/vscode -m "$account"; \
       else useradd -m -u 1000 -s /bin/bash vscode; fi \
    && mkdir -p /home/vscode/.cargo /home/vscode/.cache/wolf-target \
    && chown -R 1000:1000 /home/vscode \
    && chmod 700 /home/vscode/.cargo /home/vscode/.cache/wolf-target
ENV CARGO_HOME=/home/vscode/.cargo
ENV CARGO_TARGET_DIR=/home/vscode/.cache/wolf-target
USER vscode
WORKDIR /workspaces/ha-wolf-manager
