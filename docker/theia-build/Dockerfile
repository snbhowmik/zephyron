# T-036c - cross-compiles CBOMkit-theia (Apache-2.0) for the deployed agent.
#
# Theia publishes no binary releases (verified: zero assets on v1.1.0-v1.1.2)
# and ships only as a container image, which the agent cannot run (ARCH.md
# 3a). NOTE.md OQ-11 chose option (a): build it from source, so the agent
# carries a companion binary. Go cross-compiles natively, so unlike the
# PyInstaller agent this needs no per-OS runner.
#
# Deliberately NOT upstream's Dockerfile, which sets GIT_SSL_NO_VERIFY,
# GOINSECURE=* and GONOSUMDB=* - i.e. it turns off TLS verification and the
# Go checksum database. Here module downloads keep both: go.sum is enforced
# against sum.golang.org, and TLS is verified. Pinned by full commit SHA and
# by builder-image digest. Output: `make build-theia`.

FROM golang@sha256:ef46d02b02ed68aa94b6a49ba5d3ec62003b8d5ce4b7497fe83e056f2e8fd378 AS build
ARG THEIA_REF=dcd95ac86d1cbe6e867ff3ee059b9ef77bac6a59
WORKDIR /src
RUN git init -q . \
 && git remote add origin https://github.com/cbomkit/cbomkit-theia.git \
 && git fetch -q --depth 1 origin "${THEIA_REF}" \
 && git checkout -q FETCH_HEAD \
 && test "$(git rev-parse HEAD)" = "${THEIA_REF}"
ENV CGO_ENABLED=0 GOFLAGS=-trimpath
RUN for target in linux/amd64 linux/arm64 windows/amd64 darwin/amd64 darwin/arm64; do \
      os="${target%/*}"; arch="${target#*/}"; ext=""; [ "$os" = windows ] && ext=".exe"; \
      GOOS="$os" GOARCH="$arch" go build -ldflags "-s -w" -o "/out/cbomkit-theia-${os}-${arch}${ext}" . || exit 1; \
    done \
 && cp LICENSE /out/LICENSE.cbomkit-theia \
 && (cd /out && sha256sum cbomkit-theia-* > SHA256SUMS)

FROM scratch AS artifacts
COPY --from=build /out /
