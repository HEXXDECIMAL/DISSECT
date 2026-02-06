# Multi-stage Dockerfile for web-dissect
# Stage 1: Alpine base with dependencies (matches apko.yaml)
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    tzdata \
    radare2

# Create nonroot user (matches apko.yaml)
RUN addgroup -g 65532 -S nonroot && \
    adduser -u 65532 -S nonroot -G nonroot

# Set working directory
WORKDIR /app

# Copy pre-built binaries and templates
COPY dist/web-dissect /usr/local/bin/web-dissect
COPY dist/dissect /usr/local/bin/dissect
COPY templates/ /templates/

# Make binaries executable
RUN chmod +x /usr/local/bin/web-dissect /usr/local/bin/dissect

# Set up permissions
RUN chown -R nonroot:nonroot /templates

# Switch to nonroot user
USER nonroot

# Set environment variables (matches apko.yaml)
ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    PORT=8080 \
    SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

# Entrypoint
ENTRYPOINT ["/usr/local/bin/web-dissect"]
