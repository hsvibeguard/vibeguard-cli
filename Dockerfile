# VibeGuard CLI — all-in-one security scanner image.
# Bundles vibeguard-cli + the "broad" scanner set so `docker run` scans work
# out of the box (no --ci empty-scan surprise).
#
#   docker run --rm -v "$(pwd):/repo" ghcr.io/hsvibeguard/vibeguard-cli
#
FROM python:3.11-slim

# Pinned for reproducible images (override at build time with --build-arg)
ARG GITLEAKS_VERSION=8.18.4
ARG TRIVY_VERSION=0.70.0
ARG TRUFFLEHOG_VERSION=3.63.7

RUN apt-get update && apt-get install -y --no-install-recommends \
      curl ca-certificates git tar \
    && rm -rf /var/lib/apt/lists/*

# VibeGuard in the main env; scanners isolated via pipx because checkov pins
# click==8.1.8, incompatible with vibeguard's typer (needs click>=8.2).
ENV PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin
RUN pip install --no-cache-dir vibeguard-cli==1.1.8 pipx \
    && pipx install semgrep \
    && pipx install bandit \
    && pipx install checkov

# Pinned binary scanners (multi-arch aware: amd64 + arm64)
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
      amd64) GL_ARCH=linux_x64;   TV_ARCH=Linux-64bit; TH_ARCH=linux_amd64 ;; \
      arm64) GL_ARCH=linux_arm64; TV_ARCH=Linux-ARM64; TH_ARCH=linux_arm64 ;; \
      *) echo "unsupported arch: $arch" >&2; exit 1 ;; \
    esac; \
    curl -sSfL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_${GL_ARCH}.tar.gz" \
      | tar -xz -C /usr/local/bin gitleaks; \
    curl -sSfL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_${TV_ARCH}.tar.gz" \
      | tar -xz -C /usr/local/bin trivy; \
    curl -sSfL "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_${TH_ARCH}.tar.gz" \
      | tar -xz -C /usr/local/bin trufflehog; \
    gitleaks version && trivy --version && trufflehog --version

WORKDIR /repo
ENTRYPOINT ["vibeguard"]
CMD ["scan", "/repo", "--ci"]
