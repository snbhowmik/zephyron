# T-045 — QAVACH-owned image for Certipy (MIT), `ad.adcs`.
#
# Certipy is normally pip-installed, not container-distributed; the one
# community image (secure-77/Certipy-Docker) is unlicensed and stale (last
# push 2024-03-28) and must not be depended on (config/scanners.yaml).
# Pinned to the exact upstream commit whose `find` JSON schema QAVACH's
# parser was written against — so the schema being parsed is the schema
# being run — not to a PyPI release (5.1.0 predates that commit).

FROM python@sha256:23b5dc88c7dd47fec3f960b51dc30d19df9875cfbfc60f3b62d3e5b88cbccf62 AS build
ARG CERTIPY_REF=3ae34426c58d266a1979ff9607514c3d7fe1aa21
RUN apt-get update && apt-get install -y --no-install-recommends git build-essential libkrb5-dev \
 && rm -rf /var/lib/apt/lists/*
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir "git+https://github.com/ly4k/Certipy@${CERTIPY_REF}"

FROM python@sha256:23b5dc88c7dd47fec3f960b51dc30d19df9875cfbfc60f3b62d3e5b88cbccf62
RUN apt-get update && apt-get install -y --no-install-recommends libkrb5-3 && rm -rf /var/lib/apt/lists/*
COPY --from=build /opt/venv /opt/venv
COPY LICENSE /licenses/certipy.LICENSE
ENV PATH=/opt/venv/bin:$PATH HOME=/tmp
USER 65534:65534
ENTRYPOINT ["certipy"]
