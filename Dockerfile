# ==============================================================================
# DOCKERFILE - SECURITY PASS AND FAIL CASES (32 CHECKS TOTAL)
# ==============================================================================

# ------------------------------------------------------------------------------
# SECTION 1: FAIL CASES (Insecure Practices)
# ------------------------------------------------------------------------------

# [FAIL] DF_BASE_001: Using 'latest' tag
# [FAIL] DF_BASE_002: Not using a minimal image
# [FAIL] DF_BASE_003: Untrusted registry
# [FAIL] DF_BASE_005: Deprecated image (Ubuntu 18.04)
FROM registry.untrusted.com/library/ubuntu:latest

# [FAIL] DF_SEC_001: Hardcoded secret (Value is visible in image layers)
ENV DB_PASSWORD=my_very_secret_password

# [FAIL] DF_SEC_002: ARG with default secret value
ARG API_KEY=12345-abc-def

# [FAIL] DF_FILE_002: Wildcard COPY (Copies unnecessary files)
COPY . /app

# [FAIL] DF_SEC_004: Copying sensitive files (.env, private keys)
COPY .env /app/.env
COPY id_rsa /root/.ssh/id_rsa

# [FAIL] DF_PKG_002: Unpinned package version
# [FAIL] DF_PKG_006: Installing dev tools (curl/git) without cleanup
# [FAIL] DF_FILE_004: Pipe-to-shell pattern (Blind execution)
# [FAIL] DF_CMD_003: Using sudo in container
RUN apt-get update && \
    apt-get install -y curl git sudo && \
    curl -sSL https://install.example.com | bash

# [FAIL] DF_USER_001/002: Still running as 'root' (Default)
# [FAIL] DF_CMD_004: Excessive root operation (chmod 777)
# [FAIL] DF_FILE_003: Insecure file permissions
RUN chmod 777 /app/sensitive.sh

# [FAIL] DF_USER_003: Setting SUID/SGID bits
RUN chmod u+s /app/bin/unsafe_tool

# [FAIL] DF_FS_003: WORKDIR owned by root
WORKDIR /var/app

# [FAIL] DF_CMD_002: Shell form for CMD (Signals not handled correctly)
CMD python3 /app/main.py

# ------------------------------------------------------------------------------
# SECTION 2: PASS CASES (Secure Practices)
# ------------------------------------------------------------------------------

# Use Multistage builds to keep production images lean
# [PASS] DF_BASE_004: Pin by SHA256 digest
FROM alpine:3.19@sha256:c5b1261d6d314f3272a48a99974efaade9d8ee8551ff7440e619b8037c573f57 AS builder

# [PASS] Specific package pinning & Dev tool cleanup (using staging)
RUN apk add --no-cache \
    python3=3.11.10-r0 \
    gcc=13.2.1_git20231014-r0 \
    musl-dev=1.2.4_git20230717-r4

WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Final Stage: Use a distroless or minimal image
# [PASS] DF_BASE_002: Minimal image (Distroless)
FROM gcr.io/distroless/python3-debian12:latest@sha256:7f9b8c...

# [PASS] DF_USER_001/002: Run as non-root user
# [PASS] DF_FS_003: Correct WORKDIR ownership
WORKDIR /app
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /build/app .

# [PASS] DF_CMD_002: Exec form for CMD
ENTRYPOINT ["python3"]
CMD ["app.py"]
