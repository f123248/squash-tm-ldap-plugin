# ═══════════════════════════════════════════════════════════════════════
#  Stage 1 – Build the LDAP plugin jar
# ═══════════════════════════════════════════════════════════════════════
FROM maven:3.9-eclipse-temurin-21 AS builder

WORKDIR /build
COPY pom.xml .
COPY src ./src

RUN mvn -B -q package -DskipTests

# ═══════════════════════════════════════════════════════════════════════
#  Stage 2 – Squash TM 13 with plugin dropped in
# ═══════════════════════════════════════════════════════════════════════
FROM squashtest/squash:13.0.1

# Copy the shaded plugin jar into the plugins directory
COPY --from=builder /build/target/authentication.ldap.ad-1.0.0.jar \
     /opt/squash-tm/plugins/

# Configure via environment variables in docker-compose.yml
# See README.md for all available options.
