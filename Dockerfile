# CyberOps Kit — bundles every scanner so `pip install` users are not left
# assembling a toolchain by hand.
#
# Scanner binaries are copied from their official published images rather than
# curl|sh'd at build time: the digest of what we ship is then determined by the
# upstream image we pin, and is visible in this file.

FROM golang:1.23-alpine AS scanners
RUN apk add --no-cache git
RUN go install github.com/google/osv-scanner/cmd/osv-scanner@latest \
 && go install github.com/ossf/scorecard/v5@latest \
 && go install github.com/zricethezav/gitleaks/v8@latest

FROM anchore/syft:latest AS syft
FROM aquasec/trivy:latest AS trivy

FROM python:3.14-slim AS runtime

LABEL org.opencontainers.image.title="CyberOps Kit" \
      org.opencontainers.image.description="Reproducible, auditable security report cards." \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/OpenCyberOps/cyberops-kit"

RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY --from=scanners /go/bin/osv-scanner  /usr/local/bin/osv-scanner
COPY --from=scanners /go/bin/scorecard    /usr/local/bin/scorecard
COPY --from=scanners /go/bin/gitleaks     /usr/local/bin/gitleaks
COPY --from=syft     /syft                /usr/local/bin/syft
COPY --from=trivy    /usr/local/bin/trivy /usr/local/bin/trivy

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/
RUN pip install --no-cache-dir . semgrep

# Never run as root. The tool reads untrusted repositories; there is no reason for
# it to hold privileges it cannot use.
RUN useradd --create-home --uid 1001 cyberops
USER cyberops

WORKDIR /workspace
ENTRYPOINT ["cyberops"]
CMD ["--help"]
