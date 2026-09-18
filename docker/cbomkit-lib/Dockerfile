# T-038 — QAVACH-owned image wrapping cbomkit-lib (NOTE.md §3.2).
#
# The upstream artefact `com.ibm:sonar-cryptography-plugin` is published only
# to GitHub Packages, which requires a PAT even to *read*. Both projects are
# Apache-2.0, so QAVACH builds the plugin from its pinned release tag and
# installs it into the build stage's own local Maven repository: no
# credential is needed at build time, and none exists at scan time.
#
# Every input is pinned: base images by digest, sources by full commit SHA.

FROM maven@sha256:c2a2c58516d160f43b50f12baa427ca86989e0bc942609e04aff61da5d9a7d74 AS build

ARG SONAR_CRYPTO_REF=d1d1b8fad50d65e9f06e380e9f632974f32cb7de
ARG CBOMKIT_LIB_REF=8fbc617afa7fcf90838c68e56a9710f76b1c839d

RUN git clone https://github.com/cbomkit/sonar-cryptography /src/sonar-cryptography \
 && git -C /src/sonar-cryptography checkout ${SONAR_CRYPTO_REF} \
 && git clone https://github.com/cbomkit/cbomkit-lib /src/cbomkit-lib \
 && git -C /src/cbomkit-lib checkout ${CBOMKIT_LIB_REF}

# 1. The plugin, into the local repo (tests skipped: upstream's own CI runs them).
WORKDIR /src/sonar-cryptography
RUN mvn -B -q -DskipTests -Dspotless.check.skip=true -Dspotless.apply.skip=true \
        -Dcheckstyle.skip=true install

# 2. The library, then its runtime classpath.
WORKDIR /src/cbomkit-lib
RUN mvn -B -q -DskipTests -Dspotless.check.skip=true -Dspotless.apply.skip=true \
        -Dcheckstyle.skip=true package \
 && mvn -B -q dependency:copy-dependencies -DoutputDirectory=/out/lib \
 && ls -la target && find target -maxdepth 1 -name '*.jar' -exec cp {} /out/lib/ \;

# 3. QAVACH's entrypoint.
COPY QavachScan.java /src/QavachScan.java
RUN javac -cp "/out/lib/*" -d /out /src/QavachScan.java

FROM eclipse-temurin@sha256:49e21e16e3c86eb7816a44a67549910ed090fbeb40c29c525d58bf5e02e91b0f
COPY --from=build /out /opt/qavach
COPY --from=build /src/cbomkit-lib/LICENSE.txt /licenses/cbomkit-lib.LICENSE.txt
COPY --from=build /src/sonar-cryptography/LICENSE.txt /licenses/sonar-cryptography.LICENSE.txt
USER 65534:65534
ENTRYPOINT ["java", "-cp", "/opt/qavach:/opt/qavach/lib/*", "QavachScan"]
