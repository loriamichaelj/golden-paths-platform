# Scanner image: pinned Trivy and Checkov, plus gold-scan and gate.py.
# Build from the repository root:  docker build -f images/scanner/Dockerfile .
FROM python:3.13-slim@sha256:d98cc29d3266e535dd9da1099688d9cb3ca4753813571e071763d17725460962

ARG TRIVY_VERSION=0.76.0
ARG TRIVY_SHA256_AMD64=e24b1c51293c1b15e4ba8d45bbc7891ba053f90278ec2698f3562c993e145fe7
ARG TRIVY_SHA256_ARM64=aab21e677a7b7071fc79f1711480840754c18a1b9d9cefa7ccd06af63a0e8f4c
ARG CHECKOV_VERSION=3.3.27
ARG TARGETARCH

# Trivy: download the release, check it against the pinned checksum, install.
RUN set -eu; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates curl; \
    case "${TARGETARCH}" in \
      amd64) arch=64bit; sum="${TRIVY_SHA256_AMD64}" ;; \
      arm64) arch=ARM64; sum="${TRIVY_SHA256_ARM64}" ;; \
      *) echo "unsupported architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    file="trivy_${TRIVY_VERSION}_Linux-${arch}.tar.gz"; \
    curl -fsSL -o "/tmp/${file}" "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/${file}"; \
    echo "${sum}  /tmp/${file}" | sha256sum -c -; \
    tar -xzf "/tmp/${file}" -C /usr/local/bin trivy; \
    rm "/tmp/${file}"; \
    apt-get purge -y --auto-remove curl; \
    rm -rf /var/lib/apt/lists/*; \
    trivy --version

# Checkov, pinned by version. It never downloads policies at run time (--skip-download).
RUN pip install --no-cache-dir "checkov==${CHECKOV_VERSION}" && pip check

COPY --chmod=0755 images/scanner/gate.py /usr/local/bin/gate.py
COPY --chmod=0755 images/scanner/gold_scan.py /usr/local/bin/gold-scan
# The golden-path policies (CKV2_GP_*); gold-scan loads /opt/gold/checkov/custom automatically.
COPY policy/checkov/ /opt/gold/checkov/

RUN useradd --uid 10001 --create-home scanner
ENV PYTHONDONTWRITEBYTECODE=1 \
    TRIVY_CACHE_DIR=/home/scanner/.cache/trivy
USER scanner
WORKDIR /work
ENTRYPOINT ["gold-scan"]
