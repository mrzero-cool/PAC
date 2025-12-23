# GOOD DOCKERFILE - Compliant with All 25 Security Checks
# Production-ready best practices

# DF_MULTI_001: Using multistage build
# DF_BASE_001: Specific version tag
# DF_BASE_002: Minimal base image (alpine)
# DF_BASE_003: Trusted registry (docker.io)
# DF_BASE_004: Digest pinning
# DF_BASE_005: Actively maintained image
FROM alpine:3.19@sha256:c5b1261d6d3e43071626931fc004f70149baeba2c8ec672bd4f27761f8e1ad6b AS builder

# DF_PKG_002: Pinning package versions
# DF_PKG_006: Only installing necessary build tools
RUN apk add --no-cache \
    python3=3.11.6-r0 \
    py3-pip=23.3.1-r0

# DF_FILE_002: Copying specific files only (no wildcard copy)
COPY requirements.txt /build/
COPY app.py /build/
COPY config /build/config

WORKDIR /build

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# ========== Final Stage ==========
# DF_MULTI_001: Second stage
FROM alpine:3.19@sha256:c5b1261d6d3e43071626931fc004f70149baeba2c8ec672bd4f27761f8e1ad6b

# Install only runtime dependencies with version pinning
RUN apk add --no-cache \
    python3=3.11.6-r0 \
    && rm -rf /var/cache/apk/*

# DF_USER_001: Create non-root user
RUN addgroup -g 1000 appuser && \
    adduser -D -u 1000 -G appuser appuser

# DF_FS_003: Set WORKDIR with proper ownership
WORKDIR /app
RUN chown -R appuser:appuser /app

# DF_MULTI_003: Copy specific files from builder
COPY --from=builder --chown=appuser:appuser /build/app.py /app/
COPY --from=builder --chown=appuser:appuser /build/config /app/config

# DF_FILE_003: Set restrictive permissions (not 777)
RUN chmod 755 /app && \
    chmod 644 /app/app.py

# DF_USER_003: Check & Remove SUID/SGID bits (if any existed, alpine is usually clean but good practice)
RUN find / -perm /6000 -type f -exec chmod a-s {} \; || true

# DF_CMD_003: No sudo usage (using standard commands)
# DF_CMD_004: No unnecessary root operations

# DF_USER_002: Switch to non-root user for runtime
USER appuser

# DF_SEC_001: No hardcoded secrets
# DF_SEC_002: No ARG secrets
# DF_SEC_003: Use secret mounts (demonstrated if needed: RUN --mount=type=secret...)
# DF_SEC_004: No .env/.ssh files copied
# DF_FILE_004: No curl | bash patterns

# DF_HEALTH_001: HEALTHCHECK instruction
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python3 /app/app.py --health || exit 1

# DF_CMD_002: Using exec form
ENTRYPOINT ["python3"]
CMD ["app.py"]
