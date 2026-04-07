# SPDX-License-Identifier: Apache-2.0
FROM python:3.14-slim AS builder

WORKDIR /app
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY rune_audit/ rune_audit/

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir .

FROM python:3.14-slim

LABEL org.opencontainers.image.source="https://github.com/lpasquali/rune-audit"
LABEL org.opencontainers.image.description="RUNE Audit — IEC 62443 compliance evidence collector and report generator"
LABEL org.opencontainers.image.licenses="Apache-2.0"

RUN groupadd -r rune && useradd -r -g rune -d /home/rune -s /sbin/nologin rune && \
    mkdir -p /home/rune/.rune-audit && \
    chown -R rune:rune /home/rune

COPY --from=builder /usr/local/lib/python3.14/site-packages /usr/local/lib/python3.14/site-packages
COPY --from=builder /usr/local/bin/rune-audit /usr/local/bin/rune-audit

USER rune
WORKDIR /home/rune

ENTRYPOINT ["rune-audit"]
CMD ["--help"]
