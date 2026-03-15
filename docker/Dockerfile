# ── Stage 1: Build ──────────────────────────────────────────────────────────
FROM maven:3.9-eclipse-temurin-17 AS builder

WORKDIR /build

# Cache Maven dependencies separately from source
COPY pom.xml .
RUN mvn dependency:go-offline --batch-mode --no-transfer-progress

COPY src ./src
RUN mvn clean package -DskipTests --batch-mode --no-transfer-progress

# ── Stage 2: Run ────────────────────────────────────────────────────────────
# Use distroless to minimise the attack surface (fewer OS packages = fewer CVEs)
FROM gcr.io/distroless/java17-debian12:nonroot

WORKDIR /app

# Copy only the runnable JAR
COPY --from=builder /build/target/*.jar app.jar

# Run as non-root user (uid 65532 = nonroot in distroless)
USER nonroot

EXPOSE 8080

ENTRYPOINT ["java", \
  "-Djava.security.egd=file:/dev/./urandom", \
  "-Dspring.profiles.active=production", \
  "-jar", "app.jar"]
