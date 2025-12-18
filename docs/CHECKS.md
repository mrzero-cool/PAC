# Docker Security Checks Reference

Complete reference for all 21 Critical and High severity Dockerfile security checks.

## Critical Severity Checks (8)

### DF_BASE_001: Use Specific Version Tag

**Severity**: Critical  
**Description**: Always specify an explicit version tag for base images instead of using 'latest'.

**Bad**:

```dockerfile
FROM ubuntu:latest
FROM node
```

**Good**:

```dockerfile
FROM ubuntu:22.04
FROM node:18.19.0
```

---

### DF_BASE_003: Use Trusted Registry

**Severity**: Critical  
**Description**: Only pull base images from trusted official registries.

**Allowed**: `alpine`, `ubuntu`, `debian`, `node`, `python`, `gcr.io`, `quay.io`, etc.

---

### DF_USER_001: Create Non-Root User

**Severity**: Critical  
**Description**: Create a non-root user and ensure the container runs with this user.

**Bad**: No USER instruction  
**Good**:

```dockerfile
RUN adduser -D appuser
USER appuser
```

---

### DF_USER_002: Final USER Not Root

**Severity**: Critical  
**Description**: The last USER instruction must specify a non-root user.

**Bad**: `USER root` or `USER 0`  
**Good**: `USER appuser` or `USER 1000`

---

### DF_FILE_004: No Pipe to Shell

**Severity**: Critical  
**Description**: Avoid `curl | bash` or `wget | sh` patterns.

**Bad**: `RUN curl install.sh | bash`  
**Good**: `RUN curl -O install.sh && chmod +x install.sh && ./install.sh`

---

### DF_SEC_001: No Hardcoded Secrets

**Severity**: Critical  
**Description**: Never hardcode passwords, tokens, or API keys.

**Bad**:

```dockerfile
ENV API_KEY=abc123
ARG PASSWORD=secret
```

**Good**: Use Docker secrets or environment injection at runtime

---

### DF_SEC_002: No Secrets via ARG

**Severity**: Critical  
**Description**: Don't pass secrets via ARG with default values.

**Bad**: `ARG DB_PASSWORD=secret`  
**Good**: `ARG DB_HOST` (no default for secrets)

---

### DF_SEC_004: No Secret Files

**Severity**: Critical  
**Description**: Don't copy .env, .aws, .ssh files.

**Bad**: `COPY .env /app/`  
**Good**: Add to `.dockerignore`

---

## High Severity Checks (13)

### DF_BASE_002: Minimal Base Images

**Severity**: High  
**Description**: Prefer minimal images (alpine, distroless, scratch).

**Good**: `FROM alpine:3.19`

---

### DF_BASE_004: Digest Pinning

**Severity**: High  
**Description**: Pin images by SHA256 digest.

**Good**: `FROM alpine:3.19@sha256:abc123...`

---

### DF_BASE_005: Maintained Images

**Severity**: High  
**Description**: Avoid deprecated images.

**Bad**: `centos:6`, `ubuntu:14.04`, `python:2.7`

---

### DF_USER_003: No SUID/SGID

**Severity**: High  
**Description**: Remove setuid/setgid bits.

**Bad**: `RUN chmod u+s /bin/app`

---

### DF_FILE_002: Specific COPY

**Severity**: High  
**Description**: Copy specific files, not entire directories.

**Bad**: `COPY . /app`  
**Good**: `COPY app.py requirements.txt /app/`

---

### DF_FILE_003: Safe Permissions

**Severity**: High  
**Description**: Avoid world-writable permissions.

**Bad**: `chmod 777` or `chmod 666`  
**Good**: `chmod 755` or `chmod 644`

---

### DF_PKG_002: Pin Package Versions

**Severity**: High  
**Description**: Specify exact package versions.

**Good**: `apk add python3=3.11.6-r0`

---

### DF_PKG_006: Remove Dev Tools

**Severity**: High  
**Description**: Don't keep build tools in production.

**Bad**: Installing gcc, git without cleanup  
**Good**: Multistage builds or cleanup in same RUN

---

### DF_CMD_002: Exec Form

**Severity**: High  
**Description**: Use exec form for CMD/ENTRYPOINT.

**Bad**: `CMD python app.py`  
**Good**: `CMD ["python", "app.py"]`

---

### DF_CMD_003: No Sudo

**Severity**: High  
**Description**: Don't use sudo in containers.

---

### DF_CMD_004: Minimize Root

**Severity**: High  
**Description**: Run commands as non-root when possible.

---

### DF_FS_003: WORKDIR Ownership

**Severity**: High  
**Description**: Set WORKDIR ownership to non-root user.

**Good**: `RUN chown appuser:appuser /app`

---

### DF_MULTI_003: Specific Artifacts

**Severity**: High  
**Description**: In multistage builds, copy specific files.

**Bad**: `COPY --from=builder . /app`  
**Good**: `COPY --from=builder /build/app /app/`
