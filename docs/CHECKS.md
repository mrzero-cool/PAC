# Docker Security Checks Reference

Complete reference for all **32 security checks** covering Dockerfiles, docker-compose.yml files, and general validation.

## Table of Contents

- [Dockerfile Checks (13)](#dockerfile-checks-13)
  - [Critical Severity (9)](#critical-severity-9)
  - [High Severity (4)](#high-severity-4)
- [docker-compose.yml Checks (15)](#docker-composeyml-checks-15)
  - [Critical Severity (11)](#critical-severity-11)
  - [High Severity (4)](#high-severity-4-1)
- [General Validation (4)](#general-validation-4)
  - [Critical Severity (4)](#critical-severity-4)

---

# Dockerfile Checks (13)

## Critical Severity (9)

### DF_BASE_001: Use Specific Version Tag

**Severity**: Critical  
**Category**: Base Images  
**Description**: Always specify an explicit version tag for base images instead of using 'latest' tag to ensure reproducible builds and predictable behavior.

**Why It Matters**: Using 'latest' tag can introduce breaking changes when the base image is updated, potentially introducing vulnerabilities or breaking your application.

**Bad**:

```dockerfile
FROM ubuntu:latest
FROM node
FROM nginx
```

**Good**:

```dockerfile
FROM ubuntu:22.04
FROM node:20.10.0-alpine
FROM nginx:1.25.3-alpine
```

---

### DF_BASE_003: Use Trusted Registry

**Severity**: Critical  
**Category**: Base Images  
**Description**: Only pull base images from trusted official registries (Docker Hub Official, trusted vendors).

**Why It Matters**: Untrusted registries may contain compromised or malicious images leading to supply chain attacks.

**Allowed Registries**:

- Official Docker Hub: `alpine`, `ubuntu`, `debian`, `node`, `python`, `golang`, etc.
- Google Container Registry: `gcr.io`, `us.gcr.io`
- Microsoft: `mcr.microsoft.com`
- Quay: `quay.io`
- GitHub: `ghcr.io`
- Distroless: `gcr.io/distroless`
- Chainguard: `cgr.dev/chainguard`

**Bad**:

```dockerfile
FROM randomuser/suspicious-image:latest
FROM unknown-registry.com/app:1.0
```

**Good**:

```dockerfile
FROM alpine:3.19
FROM gcr.io/distroless/python3:latest
```

---

### DF_USER_001: Create Non-Root User

**Severity**: Critical  
**Category**: User & Permissions  
**Description**: Create a non-root user for the application and ensure the container runs with this user, not root.

**Why It Matters**: Running as root allows attackers to easily gain full system access if the container is compromised.

**Bad**: No USER instruction

**Good**:

```dockerfile
# Alpine
RUN adduser -D appuser
USER appuser

# Debian/Ubuntu
RUN useradd -m -u 1000 appuser
USER appuser

# Specify UID:GID
USER 1000:1000
```

---

### DF_USER_002: Final USER Not Root

**Severity**: Critical  
**Category**: User & Permissions  
**Description**: The last USER instruction in Dockerfile must specify a non-root user to prevent privilege escalation.

**Why It Matters**: Container will execute as root, enabling full host compromise if an escape vulnerability is exploited.

**Bad**:

```dockerfile
USER root
USER 0
USER 0:0
```

**Good**:

```dockerfile
USER appuser
USER 1000
USER 1000:1000
```

---

### DF_FILE_004: No Pipe to Shell

**Severity**: Critical  
**Category**: File Operations  
**Description**: Do not use patterns like 'curl | bash' or 'wget | sh' as they bypass verification and can execute malicious code.

**Why It Matters**: Pipe-based execution skips verification steps and can be intercepted to inject malicious commands.

**Bad**:

```dockerfile
RUN curl https://install.sh | bash
RUN wget -O - https://script.sh | sh
RUN curl -sSL get.docker.com | sh
```

**Good**:

```dockerfile
RUN curl -O https://install.sh && \
    sha256sum -c install.sh.sha256 && \
    chmod +x install.sh && \
    ./install.sh && \
    rm install.sh
```

---

### DF_SEC_001: No Hardcoded Secrets

**Severity**: Critical  
**Category**: Secrets Management  
**Description**: Never hardcode API keys, passwords, tokens, or certificates in Dockerfile or ENV instructions.

**Why It Matters**: Secrets persist in image layers forever and are accessible to anyone with image access.

**Bad**:

```dockerfile
ENV API_KEY=sk-abc123xyz
ENV DATABASE_PASSWORD=secret123
ARG AWS_SECRET_ACCESS_KEY=wJalrXUt...
```

**Good**:

```dockerfile
# Use environment variables at runtime
# docker run -e API_KEY=$API_KEY myapp

# Or use Docker secrets (Swarm/Kubernetes)
# No hardcoded values in Dockerfile
```

---

### DF_SEC_002: No Secrets via ARG

**Severity**: Critical  
**Category**: Secrets Management  
**Description**: Avoid using ARG for secrets as they persist in image layer metadata and build history.

**Why It Matters**: ARG values are visible in image history and can be extracted by attackers analyzing image layers.

**Bad**:

```dockerfile
ARG DB_PASSWORD=secret123
ARG API_TOKEN=default_token
```

**Good**:

```dockerfile
# ARG without default (passed at build time)
ARG DB_HOST
ARG APP_VERSION

# Or use BuildKit secrets (recommended)
# docker buildx build --secret id=mysecret,src=secret.txt .
RUN --mount=type=secret,id=mysecret cat /run/secrets/mysecret
```

---

### DF_SEC_004: No Secret Files

**Severity**: Critical  
**Category**: Secrets Management  
**Description**: Ensure .env, .aws, .ssh, and other secret files are listed in .dockerignore to prevent inclusion in build.

**Why It Matters**: Secret files accidentally copied into the image expose credentials to anyone with image access.

**Bad**:

```dockerfile
COPY . /app
COPY .env /app/
COPY ~/.ssh/id_rsa /root/.ssh/
```

**Good**:

```dockerfile
# .dockerignore
.env
.env.local
.env.*.local
.aws/
.ssh/
*.pem
*.key

# Dockerfile
COPY requirements.txt /app/
COPY src/ /app/src/
```

---

### DF_CMD_003: No Sudo

**Severity**: Critical  
**Category**: Commands  
**Description**: Never use sudo in RUN instructions; run commands directly as the appropriate user.

**Why It Matters**: Sudo in containers is unnecessary complexity and creates unnecessary attack surface.

**Bad**:

```dockerfile
RUN sudo apt-get update
RUN sudo -u appuser npm install
```

**Good**:

```dockerfile
# Run as root when needed
RUN apt-get update

# Switch to user for app commands
USER appuser
RUN npm install
```

---

## High Severity (4)

### DF_FILE_002: Specific COPY

**Severity**: High  
**Category**: File Operations  
**Description**: Copy only necessary files to container instead of copying entire directory with `COPY . .`

**Why It Matters**: Copying all files may inadvertently include secrets, credentials, or development artifacts in the production image.

**Bad**:

```dockerfile
COPY . /app
COPY ./ /app/
COPY * /app/
```

**Good**:

```dockerfile
COPY package.json package-lock.json /app/
COPY src/ /app/src/
COPY config/production.json /app/config/
```

---

### DF_CMD_002: Exec Form

**Severity**: High  
**Category**: Commands  
**Description**: Use exec form (JSON array syntax) for ENTRYPOINT and CMD to avoid shell processing.

**Why It Matters**: Shell form processes variables and enables shell injection attacks through environment variables.

**Bad** (Shell form):

```dockerfile
CMD python app.py
ENTRYPOINT /bin/sh -c "start.sh"
```

**Good** (Exec form):

```dockerfile
CMD ["python", "app.py"]
ENTRYPOINT ["/bin/sh", "start.sh"]
```

---

### DF_CMD_004: Minimize Root

**Severity**: High  
**Category**: Commands  
**Description**: Only run commands that absolutely require root with root; switch to non-root user for application.

**Why It Matters**: Unnecessarily running as root increases blast radius if container is compromised.

**Bad**:

```dockerfile
RUN chown root:root /app
RUN chmod 777 /data
```

**Good**:

```dockerfile
# Install packages as root
RUN apk add --no-cache python3

# Change to non-root for app
RUN adduser -D appuser && \
    chown -R appuser:appuser /app
USER appuser
```

---

### DF_FS_003: WORKDIR Ownership

**Severity**: High  
**Category**: Filesystem  
**Description**: Ensure WORKDIR is owned by the non-root user running the application.

**Why It Matters**: If WORKDIR is owned by root, non-root user cannot write to it, breaking the application.

**Bad**:

```dockerfile
WORKDIR /app
USER appuser
# /app is owned by root
```

**Good**:

```dockerfile
WORKDIR /app
RUN chown -R appuser:appuser /app
USER appuser
```

---

# docker-compose.yml Checks (15)

## Critical Severity (11)

### DC_IMG_001: Use Specific Image Version Tags

**Severity**: Critical  
**Category**: Images  
**Description**: Always specify explicit image version tags (e.g., myapp:1.0.0) instead of 'latest' or no tag.

**Why It Matters**: Without explicit tags, composition may use different image versions causing unpredictable behavior.

**Bad**:

```yaml
services:
  web:
    image: nginx:latest
  db:
    image: postgres  # defaults to :latest
```

**Good**:

```yaml
services:
  web:
    image: nginx:1.25.3-alpine
  db:
    image: postgres:16.1-alpine
```

---

### DC_USER_001: Run Services as Non-Root

**Severity**: Critical  
**Category**: User & Permissions  
**Description**: Set 'user: UID:GID' (e.g., user: 1000:1000) to run service as non-root user.

**Why It Matters**: Services running as root allow full system compromise if container is exploited.

**Bad**:

```yaml
services:
  app:
    image: myapp:1.0
    # No user specified - runs as root
```

**Good**:

```yaml
services:
  app:
    image: myapp:1.0
    user: "1000:1000"
```

---

### DC_USER_002: No Privileged Mode

**Severity**: Critical  
**Category**: User & Permissions  
**Description**: Never set 'privileged: true' as it grants full host access; use capabilities instead.

**Why It Matters**: Privileged containers disable all isolation features, allowing complete host compromise.

**Bad**:

```yaml
services:
  app:
    privileged: true
```

**Good**:

```yaml
services:
  app:
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
```

---

### DC_SEC_002: Drop All Capabilities

**Severity**: Critical  
**Category**: Security Options  
**Description**: Always drop all capabilities with 'cap_drop: [ALL]' and add back only required ones.

**Why It Matters**: Unnecessary Linux capabilities allow privilege escalation and unauthorized system access.

**Bad**:

```yaml
services:
  app:
    # No cap_drop specified
```

**Good**:

```yaml
services:
  app:
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE  # Only if needed
```

---

### DC_SEC_003: Only Required Capabilities

**Severity**: Critical  
**Category**: Security Options  
**Description**: Use 'cap_add' to add back only specific capabilities needed (e.g., NET_BIND_SERVICE, CHOWN).

**Why It Matters**: Added capabilities expand attack surface; only essential capabilities should be granted.

**Dangerous Capabilities**:

- SYS_ADMIN, SYS_MODULE, SYS_RAWIO
- NET_ADMIN, MAC_ADMIN, DAC_OVERRIDE
- SETUID, SETGID, SYS_PTRACE

**Bad**:

```yaml
services:
  app:
    cap_add:
      - SYS_ADMIN
      - NET_ADMIN
      - DAC_OVERRIDE
```

**Good**:

```yaml
services:
  app:
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE  # To bind to port 80/443
```

---

### DC_NET_005: Network Mode

**Severity**: Critical  
**Category**: Network  
**Description**: Avoid 'network_mode: host' which disables network isolation; only use bridge (default).

**Why It Matters**: Host network mode disables network isolation allowing direct access to host network.

**Bad**:

```yaml
services:
  app:
    network_mode: host
```

**Good**:

```yaml
services:
  app:
    # Use default bridge networking (omit network_mode)
    networks:
      - frontend
```

---

### DC_VOL_002: No Writable Host Mounts

**Severity**: Critical  
**Category**: Volumes  
**Description**: Do not mount host directories with write access (rw flag); use read-only (:ro) when possible.

**Why It Matters**: Write access to host filesystem allows attackers to modify or delete host files.

**Bad**:

```yaml
services:
  app:
    volumes:
      - /etc:/container-etc  # Writable!
      - /home:/backup        # Writable!
```

**Good**:

```yaml
services:
  app:
    volumes:
      - ./config:/app/config:ro  # Read-only
      - app-data:/data           # Named volume
```

---

### DC_VOL_003: No Docker Socket

**Severity**: Critical  
**Category**: Volumes  
**Description**: Never mount '/var/run/docker.sock' in container as it grants full Docker daemon access.

**Why It Matters**: Docker socket access allows container to manage all containers and access host directly.

**Bad**:

```yaml
services:
  app:
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
```

**Good**:

```yaml
services:
  app:
    volumes:
      - app-data:/data  # Named volumes only
```

---

### DC_VOL_004: No Host Root Mount

**Severity**: Critical  
**Category**: Volumes  
**Description**: Never mount '/' (host root) into container as it allows complete host compromise.

**Why It Matters**: Root filesystem mount allows attackers to modify host system and persist attacks.

**Bad**:

```yaml
services:
  app:
    volumes:
      - /:/host
      - /:/mnt/host
```

**Good**:

```yaml
services:
  app:
    volumes:
      - ./app:/usr/src/app:ro
```

---

### DC_ENV_001: No Environment Secrets

**Severity**: Critical  
**Category**: Environment & Secrets  
**Description**: Never store passwords, tokens, API keys in 'environment' section; use external secret management.

**Why It Matters**: Environment variables are visible in process list, container inspect, and logs.

**Bad**:

```yaml
services:
  app:
    environment:
      - DATABASE_PASSWORD=secret123
      - API_KEY=sk-abc123
```

**Good**:

```yaml
services:
  app:
    env_file:
      - .env.production  # In .gitignore
    # Or use Docker secrets
    secrets:
      - db_password
```

---

### DC_ENV_003: No Committed .env Files

**Severity**: Critical  
**Category**: Environment & Secrets  
**Description**: Add .env, .env.local, .env.*.local to .gitignore to prevent committing configuration files.

**Why It Matters**: Committed .env files expose all configuration including secrets to repository access.

**Good .gitignore**:

```
# Environment files
.env
.env.local
.env.*.local
.env.production
.env.staging
```

**Good docker-compose.yml**:

```yaml
services:
  app:
    env_file:
      - .env.production  # Ensure in .gitignore!
```

---

## High Severity (4)

### DC_SEC_001: Prevent Privilege Escalation

**Severity**: High  
**Category**: Security Options  
**Description**: Set 'security_opt: [no-new-privileges:true]' to prevent processes gaining new privileges.

**Why It Matters**: Without no-new-privileges, exploits can escalate from current user to root or other users.

**Bad**:

```yaml
services:
  app:
    # No security_opt specified
```

**Good**:

```yaml
services:
  app:
    security_opt:
      - no-new-privileges:true
```

---

### DC_NET_002: No Unnecessary Ports

**Severity**: High  
**Category**: Network  
**Description**: Only expose ports that are required for external access; avoid exposing debug or management ports.

**Why It Matters**: Exposed ports increase attack surface and may allow unauthorized access to services.

**Dangerous Ports**:

- 22 (SSH), 23 (Telnet), 3389 (RDP)
- 3306 (MySQL), 5432 (PostgreSQL), 27017 (MongoDB)
- 6379 (Redis), 9200 (Elasticsearch)

**Bad**:

```yaml
services:
  app:
    ports:
      - "3306:3306"  # Database exposed!
      - "6379:6379"  # Redis exposed!
```

**Good**:

```yaml
services:
  app:
    ports:
      - "8080:80"  # Only application port
    # Database on internal network only
```

---

### DC_NET_004: No SSH Port

**Severity**: High  
**Category**: Network  
**Description**: Never expose port 22; use 'docker-compose exec' for container access.

**Why It Matters**: Exposed SSH port allows unauthorized remote access to containers.

**Bad**:

```yaml
services:
  app:
    ports:
      - "22:22"
      - "2222:22"
```

**Good**:

```yaml
services:
  app:
    # No SSH exposed
    # Access via: docker-compose exec app sh
```

---

### DC_LOG_003: No Sensitive Logging

**Severity**: High  
**Category**: Environment & Secrets  
**Description**: Ensure application does not log passwords, tokens, or sensitive data in logs.

**Why It Matters**: Logged secrets are visible in logs and centralized logging systems.

**Bad**:

```yaml
services:
  app:
    logging:
      options:
        env: "PASSWORD,SECRET_KEY"  # Logs env vars!
        level: "debug"               # Debug may log secrets
```

**Good**:

```yaml
services:
  app:
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        level: "info"  # Not debug
```

---

# General Validation (4)

## Critical Severity (4)

### GEN_YAML_001: Valid YAML Syntax

**Severity**: Critical  
**Category**: General  
**Description**: Ensure docker-compose.yml has valid YAML syntax with proper indentation and quoting.

**Why It Matters**: Invalid YAML causes parsing errors and prevents service startup.

**Common Issues**:

- Incorrect indentation (must use spaces, not tabs)
- Missing colons
- Unclosed quotes
- Invalid escape sequences

**Validation**:

```bash
# Validate with docker-compose
docker-compose config

# Or use conftest
conftest test docker-compose.yml --policy policy/
```

---

### GEN_JSON_001: Valid JSON for daemon.json

**Severity**: Critical  
**Category**: General  
**Description**: Ensure daemon.json is valid JSON with proper syntax, comma placement, and quoting.

**Why It Matters**: Invalid JSON prevents daemon from starting.

**Bad daemon.json**:

```json
{
  "log-driver": "json-file",
  "storage-driver": "overlay2"  # No trailing comma!
  "insecure-registries": ["registry.local"]
}
```

**Good daemon.json**:

```json
{
  "log-driver": "json-file",
  "storage-driver": "overlay2",
  "insecure-registries": ["registry.local"]
}
```

---

### GEN_PERM_001: Correct File Permissions

**Severity**: Critical  
**Category**: General  
**Description**: Set docker-compose.yml to 644, .env files to 600, daemon.json to 644, all owned by root:root.

**Why It Matters**: World-readable .env files expose secrets; world-writable configs allow malicious changes.

**Check Script** (Linux/macOS):

```bash
#!/bin/bash
# Check docker-compose.yml
if [ -f docker-compose.yml ]; then
    perms=$(stat -c '%a' docker-compose.yml)
    if [ "$perms" != "644" ]; then
        echo "[GEN_PERM_001] docker-compose.yml should be 644"
    fi
fi

# Check .env files
if [ -f .env ]; then
    perms=$(stat -c '%a' .env)
    if [ "$perms" != "600" ]; then
        echo "[GEN_PERM_001] .env should be 600"
        chmod 600 .env
    fi
fi
```

**Fix**:

```bash
chmod 644 docker-compose.yml
chmod 600 .env
```

---

### GEN_OWNER_001: Correct File Ownership

**Severity**: Critical  
**Category**: General  
**Description**: Ensure docker-compose.yml and daemon.json are owned by root:root for security.

**Why It Matters**: Non-root owned configs allow modification by attackers.

**Check Script**:

```bash
#!/bin/bash
owner=$(stat -c '%U:%G' docker-compose.yml)
if [ "$owner" != "root:root" ]; then
    echo "[GEN_OWNER_001] docker-compose.yml should be owned by root:root"
    sudo chown root:root docker-compose.yml
fi
```

---

## Summary

**Total Checks**: 32

- **Dockerfile**: 13 checks (9 Critical + 4 High)
- **docker-compose**: 15 checks (11 Critical + 4 High)
- **General**: 4 checks (4 Critical)

All checks are implemented as OPA/Rego policies in the `policy/` directory (categorized by type) and can be validated using conftest.

For testing examples and usage, see [examples/README.md](../examples/README.md).
