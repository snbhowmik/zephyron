# T-037 — QAVACH-owned image for Opengrep (LGPL-2.1), `source_scan.opengrep`.
#
# Opengrep publishes no container image (verified against the live repo).
# The upstream release binary is fetched at build time and verified against
# the SHA-256 GitHub records for that release asset; the build fails on any
# mismatch. It is executed as a separate process only — never linked,
# vendored or imported (NFR-10, docs/THIRD_PARTY.md) — and its licence text
# ships in the image. The QAVACH rule pack (docker/opengrep/rules) is baked
# in so the image ID pins the rules as well as the engine. The rules live in
# config/opengrep-rules (the adapter reads the same file for rule metadata) and
# arrive as a named build context: `docker build --build-context
# rules=config/opengrep-rules docker/opengrep` (see `make build-images`).
#
# Release: opengrep v1.30.0, asset opengrep_manylinux_x86 (linux/amd64, glibc).

FROM debian@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251 AS fetch
ARG OPENGREP_VERSION=v1.30.0
ARG OPENGREP_SHA256=35779bdd72e92129c8df2a77f0c55e8c08356801ea92591ef32108d6b28d564c
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL -o /opengrep \
      "https://github.com/opengrep/opengrep/releases/download/${OPENGREP_VERSION}/opengrep_manylinux_x86" \
 && echo "${OPENGREP_SHA256}  /opengrep" | sha256sum -c - \
 && chmod 0555 /opengrep

FROM debian@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251
COPY --from=fetch /opengrep /usr/local/bin/opengrep
COPY LICENSE /licenses/opengrep.LICENSE
COPY --from=rules . /opt/qavach/rules
# The release binary unpacks its OCaml engine into $XDG_CACHE_HOME on first
# run and execs it from there. At scan time the only writable paths are the
# sandbox's noexec tmpfs mounts (SECURITY.md §3), so the exec would fail:
# unpack once at build time into the (read-only, executable) image instead.
ENV XDG_CACHE_HOME=/opt/opengrep-cache
RUN /usr/local/bin/opengrep scan --dump-engine-path \
 && chmod -R a+rX /opt/opengrep-cache
ENV LC_ALL=C.UTF-8 PYTHONUTF8=1 HOME=/tmp SEMGREP_SEND_METRICS=off OPENGREP_SEND_METRICS=off
USER 65534:65534
ENTRYPOINT ["opengrep"]
