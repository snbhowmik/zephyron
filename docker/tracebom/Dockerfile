# T-044 - thin QAVACH layer over the pinned cdxgen image, for `runtime.tracebom`.
#
# tracebom (Apache-2.0, ships in the cdxgen image) drives a native helper,
# safer-exec-rt, that upstream ships as mode 0444 in a root-of-image tree
# owned by uid 1000. Upstream's own user can chmod it at run time; the
# sandbox runs every scanner as uid 65534 (SECURITY.md section 3), which
# cannot, and spawn fails with EACCES. Rather than weaken the sandbox, set
# the execute bit once, at build time. Nothing else is changed.

FROM ghcr.io/cdxgen/cdxgen@sha256:1d4418545662790662567f96af62bf0f8a444eb552bf2c4cb7b35eb0a7d6234e
USER root
RUN find /opt/cdxgen/node_modules -name safer-exec-rt -exec chmod 0555 {} + \
 && find /opt/cdxgen/node_modules -name safer-exec-rt -perm -u+x | grep -q .
USER cyclonedx
