# ── Stage 2: Run ────────────────────────────────────────────────────────────
# смена distroless на минимальный Debian
FROM debian:bookworm-slim  

WORKDIR /app

# Устанавливаем OpenJDK 17 и Docker CLI
RUN apt-get update && apt-get install -y \
    openjdk-17-jdk \
    curl \
    gnupg \
    lsb-release \
    sudo \
    docker.io \
    && rm -rf /var/lib/apt/lists/*

# Копируем JAR из builder stage
COPY --from=builder /build/target/*.jar app.jar

USER 1000:1000 

EXPOSE 8080

ENTRYPOINT ["java", "-Djava.security.egd=file:/dev/./urandom", "-Dspring.profiles.active=production", "-jar", "app.jar"]
