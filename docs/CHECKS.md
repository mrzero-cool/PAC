# Docker Security Checks Reference

Comprehensive reference for all **54 security checks** covering Dockerfiles, docker-compose.yml files, and general validation.

---

## Check Summary Checklist

| ID | Check Name | File Type | Severity | Risk | Enforcement |
|----|------------|-----------|----------|------|-------------|
| **DF_BASE_001** | Use specific base image version tag | Dockerfile | **Critical** | Using 'latest' tag can introduce breaking changes and vulnerabilities | DENY |
| **DF_BASE_002** | Use minimal/hardened base images | Dockerfile | **High** | Bloated base images increase attack surface and vulnerability exposure | WARN |
| **DF_BASE_003** | Use trusted registry for base images | Dockerfile | **Critical** | Untrusted registries may contain compromised or malicious images | DENY |
| **DF_BASE_004** | Use base image digest instead of tag | Dockerfile | **High** | Tags can be modified; digests are immutable ensuring reproducibility | WARN |
| **DF_BASE_005** | Verify base image is maintained | Dockerfile | **High** | Unmaintained images accumulate unpatched vulnerabilities | WARN |
| **DF_USER_001** | Create and use non-root user | Dockerfile | **Critical** | Running as root allows full system access if compromised | DENY |
| **DF_USER_002** | Ensure final USER is not root | Dockerfile | **Critical** | Container execution as root enables privilege escalation | DENY |
| **DF_USER_003** | Remove SUID and SGID bits | Dockerfile | **High** | SUID/SGID binaries can be exploited to elevate privileges | WARN |
| **DF_FILE_002** | Explicitly COPY required files only | Dockerfile | **Critical** | Copying all files may include secrets or dev artifacts | DENY |
| **DF_FILE_003** | Set appropriate file permissions | Dockerfile | **High** | World-readable sensitive files can be accessed by any process | WARN |
| **DF_FILE_004** | Avoid curl piping to shell | Dockerfile | **Critical** | Pipe-to-shell bypasses verification and can execute malware | DENY |
| **DF_SEC_001** | Do not hardcode secrets | Dockerfile | **Critical** | Secrets persist in image layers and are accessible to anyone | DENY |
| **DF_SEC_002** | Do not pass secrets via build ARG | Dockerfile | **Critical** | ARG values are visible in image history | DENY |
| **DF_SEC_003** | Use Docker BuildKit secrets mount | Dockerfile | **High** | Secrets in ENV/ARG are visible; mounts are ephemeral | WARN |
| **DF_SEC_004** | Do not commit .env or secrets files | .dockerignore | **Critical** | Accidental inclusion of secrets exposes credentials | DENY |
| **DF_PKG_002** | Pin package versions explicitly | Dockerfile | **High** | Automatic versions can introduce breaking changes or vulnerabilities | WARN |
| **DF_PKG_006** | Remove unnecessary packages | Dockerfile | **High** | Unnecessary packages increase attack surface | WARN |
| **DF_CMD_002** | Use exec form not shell form | Dockerfile | **High** | Shell form enables injection attacks | DENY |
| **DF_CMD_003** | Do not use sudo in container | Dockerfile | **High** | Sudo adds complexity and attack surface | WARN |
| **DF_CMD_004** | Minimize running as root | Dockerfile | **High** | Root execution increases blast radius | WARN |
| **DF_FS_003** | Set appropriate WORKDIR ownership | Dockerfile | **High** | Root-owned WORKDIR breaks non-root application execution | WARN |
| **DF_MULTI_001** | Use multistage builds | Dockerfile | **Medium** | Single-stage builds include build tools in production | WARN |
| **DF_MULTI_003** | Copy only necessary artifacts | Dockerfile | **High** | Copying directories between stages may include secrets | WARN |
| **DF_BUILD_003** | Use .dockerignore to exclude files | .dockerignore | **Medium** | Large build contexts slow builds and may leak secrets | WARN |
| **DF_HEALTH_001** | Include HEALTHCHECK instruction | Dockerfile | **Medium** | No healthcheck prevents orchestrators from detecting failures | MEDIUM |
| **DC_IMG_001** | Use specific image version tags | Docker Compose | **Critical** | Mutable tags cause unpredictable behavior | DENY |
| **DC_IMG_002** | Use image pull policy Always | Docker Compose | **High** | Stale cached images may have vulnerabilities | WARN |
| **DC_USER_001** | Run services as non-root user | Docker Compose | **Critical** | Root services allow full system compromise | DENY |
| **DC_USER_002** | Do not use privileged mode | Docker Compose | **Critical** | Privileged mode grants full host access | DENY |
| **DC_SEC_001** | Disable privilege escalation | Docker Compose | **High** | Exploits can escalate privileges without no-new-privileges | DENY |
| **DC_SEC_002** | Drop all unnecessary capabilities | Docker Compose | **Critical** | Capabilities allow unauthorized system access | DENY |
| **DC_SEC_003** | Only add required capabilities | Docker Compose | **Critical** | Excess capabilities expand attack surface | WARN |
| **DC_SEC_004** | Set read-only root filesystem | Docker Compose | **High** | Writable root allows persistence of attacks | WARN |
| **DC_SEC_005** | Use tmpfs for temporary files | Docker Compose | **High** | Writable disk allows malware persistence | WARN |
| **DC_NET_001** | Define services on custom network | Docker Compose | **High** | Default bridge lacks isolation | WARN |
| **DC_NET_002** | Do not expose unnecessary ports | Docker Compose | **High** | Exposed ports increase attack surface | WARN |
| **DC_NET_004** | Do not expose port 22 (SSH) | Docker Compose | **High** | SSH exposure allows brute force attacks | DENY |
| **DC_NET_005** | Use network_mode carefully | Docker Compose | **Critical** | Host network disables isolation | DENY |
| **DC_VOL_001** | Mount volumes with flags | Docker Compose | **High** | Writable volumes allow data modification | WARN |
| **DC_VOL_002** | No writable host directories | Docker Compose | **Critical** | Host write access allows system modification | DENY |
| **DC_VOL_003** | Do not mount Docker socket | Docker Compose | **Critical** | Socket access grants full host control | DENY |
| **DC_VOL_004** | Do not mount host root | Docker Compose | **Critical** | Host root mount allows complete compromise | DENY |
| **DC_VOL_006** | Set volume ownership to non-root | Docker Compose | **High** | Root volumes break non-root apps | WARN |
| **DC_VOL_007** | Use tmpfs for temp storage | Docker Compose | **High** | Unrestricted tmpfs allows execution | WARN |
| **DC_ENV_001** | No environment secrets | Docker Compose | **Critical** | Env vars are visible in inspect and logs | DENY |
| **DC_ENV_002** | Use .env for config | .env | **High** | Hardcoded config is inflexible and insecure | WARN |
| **DC_ENV_003** | Do not commit .env files | .gitignore | **Critical** | Committed secrets are exposed to repo readers | DENY |
| **DC_SEC_MAN_001** | Use Docker Secrets | Docker Compose | **High** | Secrets management is more secure than env vars | WARN |
| **DC_HEALTH_001** | Define health checks | Docker Compose | **Medium** | Required for self-healing services | MEDIUM |
| **DC_LOG_001** | Configure logging driver | Docker Compose | **High** | Logs needed for audit/forensics | WARN |
| **DC_LOG_002** | Set log rotation limits | Docker Compose | **High** | Unlimited logs cause DOM | WARN |
| **DC_LOG_003** | Do not log sensitive info | Docker Compose | **Critical** | Logs are often stored insecurely | DENY |
| **GEN_YAML_001** | Valid YAML syntax | Docker Compose | **Critical** | Invalid YAML prevents startup | DENY |
| **GEN_JSON_001** | Valid JSON syntax | daemon.json | **Critical** | Invalid JSON prevents daemon start | DENY |

---

## Dockerfile Checks (25)

### DF_BASE_001: Use Specific Version Tag

- **Severity**: Critical
- **Enforcement**: DENY
- **Description**: Always specify an explicit version tag for base images instead of using 'latest' tag to ensure reproducible builds and predictable behavior.
- **Risk**: Using 'latest' tag can introduce breaking changes when base image is updated, potentially introducing vulnerabilities or breaking your application.
- **Remediation**: Use a specific valid tag such as `22.04` or `3.19`.

**Bad**:

```dockerfile
FROM ubuntu:latest
```

**Good**:

```dockerfile
FROM ubuntu:22.04
```

### DF_BASE_002: Use Minimal/Hardened Base Images

- **Severity**: High
- **Enforcement**: WARN
- **Description**: Prefer minimal base images (Alpine, Distroless, Chainguard) to reduce attack surface and image size.
- **Risk**: Bloated base images with unnecessary packages increase vulnerability exposure and deployment time.
- **Remediation**: Switch to `alpine`, `slim`, or `distroless` variants.

**Bad**:

```dockerfile
FROM python:3.9  # Full Debian image (~1GB)
```

**Good**:

```dockerfile
FROM python:3.9-alpine  # Minimal (~50MB)
# or
FROM gcr.io/distroless/python3
```

### DF_BASE_003: Use Trusted Registry for Base Images

- **Severity**: Critical
- **Enforcement**: DENY
- **Description**: Only pull base images from trusted official registries (Docker Hub Official, trusted vendors).
- **Risk**: Untrusted registries may contain compromised or malicious images leading to supply chain attacks.
- **Remediation**: Configure a list of allowed registries in policy and ensure all `FROM` instructions point to them.

**Bad**:

```dockerfile
FROM unknown-registry.com/my-app:v1
```

**Good**:

```dockerfile
FROM docker.io/library/node:18
# or
FROM my-company-registry.com/base/node:18
```

### DF_BASE_004: Use Base Image Digest Instead of Tag

- **Severity**: High
- **Enforcement**: WARN
- **Description**: Pin base images by SHA256 digest for maximum reproducibility and security.
- **Risk**: Tags can be modified or re-tagged, allowing tag substitution attacks; digest is immutable.
- **Remediation**: Obtain the SHA256 digest of the desired image and appendage it to the tag.

**Bad**:

```dockerfile
FROM alpine:3.19
```

**Good**:

```dockerfile
FROM alpine:3.19@sha256:c5b1261d6d3e43071626931fc004f70149baeba2c8ec672bd4f27761f8e1ad6b
```

### DF_BASE_005: Verify Base Image is Maintained

- **Severity**: High
- **Enforcement**: WARN
- **Description**: Choose base images that are actively maintained and regularly patched for security vulnerabilities.
- **Risk**: Unmaintained base images will accumulate unpatched vulnerabilities over time.
- **Remediation**: Upgrade to a supported version of the base OS or language runtime.

**Bad**:

```dockerfile
FROM python:2.7  # EOL since 2020
```

**Good**:

```dockerfile
FROM python:3.11
```

### DF_USER_001: Create and Use Non-Root User

- **Severity**: Critical
- **Enforcement**: DENY
- **Description**: Create a non-root user for the application and ensure the container runs with this user, not root.
- **Risk**: Running as root allows attackers to easily gain full system access if container is compromised.
- **Remediation**: Use `RUN useradd` or `adduser` to create a user and `USER` to switch to it.

**Bad**:

```dockerfile
# No USER instruction - runs as root by default
FROM node:18
CMD ["node", "app.js"]
```

**Good**:

```dockerfile
FROM node:18
RUN useradd -m appuser
USER appuser
CMD ["node", "app.js"]
```

### DF_USER_002: Ensure Final USER is Not Root

- **Severity**: Critical
- **Enforcement**: DENY
- **Description**: The last USER instruction in Dockerfile must specify a non-root user to prevent privilege escalation.
- **Risk**: Container will execute as root, enabling full host compromise if escape vulnerability is exploited.
- **Remediation**: Ensure the Dockerfile ends with a `USER` instruction switching to a non-privileged user.

**Bad**:

```dockerfile
USER appuser
# ...
USER root  # Switched back to root!
```

**Good**:

```dockerfile
USER root  # Install packages
RUN apt-get update && apt-get install -y curled
USER appuser  # Switch back for runtime
```

### DF_USER_003: Remove SUID and SGID Bits

- **Severity**: High
- **Enforcement**: WARN
- **Description**: Remove setuid and setgid bits from files in the image to prevent privilege escalation.
- **Risk**: SUID/SGID binaries can be exploited by attackers to elevate privileges within container.
- **Remediation**: Run a command to find and remove these bits during the build.

**Good**:

```dockerfile
RUN find / -perm /6000 -type f -exec chmod a-s {} \; || true
```

### DF_FILE_002: Explicitly COPY Required Files Only

- **Severity**: Critical
- **Enforcement**: DENY
- **Description**: Copy only necessary files to container instead of copying entire directory with COPY . .
- **Risk**: Copying all files may inadvertently include secrets, credentials, or development artifacts in production image.
- **Remediation**: Use explicit copy paths for required files.

**Bad**:

```dockerfile
COPY . /app
```

**Good**:

```dockerfile
COPY package.json package-lock.json /app/
COPY src/ /app/src/
```

### DF_FILE_003: Set Appropriate File Permissions

- **Severity**: High
- **Enforcement**: WARN
- **Description**: Set restrictive file permissions (chmod) on copied files, especially for sensitive config files.
- **Risk**: World-readable sensitive files can be accessed by any process in the container.
- **Remediation**: `chmod` sensitive files to `600` or `644` and directories to `755`.

**Bad**:

```dockerfile
RUN chmod 777 /app/config.json
```

**Good**:

```dockerfile
RUN chmod 644 /app/config.json
```

### DF_FILE_004: Avoid Curl Bashing (Pipe to Shell)

- **Severity**: Critical
- **Enforcement**: DENY
- **Description**: Do not use patterns like 'curl | bash' or 'wget | sh' as they bypass verification and can execute malicious code.
- **Risk**: Pipe-based execution skips verification steps and can be intercepted to inject malicious commands.
- **Remediation**: Download the script, verify checksum/signature, inspect it, and then execute.

**Bad**:

```dockerfile
RUN curl https://install.example.com/script.sh | bash
```

**Good**:

```dockerfile
RUN curl -O https://install.example.com/script.sh \
    && echo "abcdef...  script.sh" | sha256sum -c - \
    && bash script.sh
```

### DF_SEC_001: Do Not Hardcode Secrets

- **Severity**: Critical
- **Enforcement**: DENY
- **Description**: Never hardcode API keys, passwords, tokens, or certificates in Dockerfile or ENV instructions.
- **Risk**: Secrets persist in image layers forever and are accessible to anyone with image access.
- **Remediation**: Use external secrets management (Vault, AWS Secrets Manager, K8s Secrets).

**Bad**:

```dockerfile
ENV AWS_ACCESS_KEY_ID=AKIA...
```

**Good**:

```dockerfile
# Inject at runtime
```

### DF_SEC_002: Do Not Pass Secrets via Build ARG

- **Severity**: Critical
- **Enforcement**: DENY
- **Description**: Avoid using ARG for secrets as they persist in image layer metadata and build history.
- **Risk**: ARG values are visible in image history and can be extracted by attackers analyzing image layers.
- **Remediation**: Use BuildKit `--mount=type=secret` instead.

**Bad**:

```dockerfile
ARG SSH_KEY
RUN echo $SSH_KEY > /root/.ssh/id_rsa
```

**Good**:

```dockerfile
# Use with: docker build --secret id=ssh_key,src=id_rsa .
RUN --mount=type=secret,id=ssh_key cat /run/secrets/ssh_key > /root/.ssh/id_rsa
```

### DF_SEC_003: Use Docker BuildKit Secrets Mount

- **Severity**: High
- **Enforcement**: WARN
- **Description**: Use --secret flag with BuildKit to mount secrets during build without storing them in image.
- **Risk**: Secrets passed as ENV or ARG will be visible in final image and layer history.
- **Remediation**: Adopt BuildKit secret mounts for all build-time credentials.

### DF_SEC_004: Do Not Commit .env or Secrets Files

- **Severity**: Critical
- **Enforcement**: DENY
- **Description**: Ensure .env, .aws, .ssh, and other secret files are listed in .dockerignore to prevent inclusion in build.
- **Risk**: Secret files accidentally copied into image expose credentials to anyone with image access.
- **Remediation**: Verify `.dockerignore` exists and contains sensitive patterns.

**Good `.dockerignore`**:

```text
.env
.git
.aws
.ssh
```

### DF_PKG_002: Pin Package Versions Explicitly

- **Severity**: High
- **Enforcement**: WARN
- **Description**: Specify exact package versions (name=version) instead of allowing automatic version selection.
- **Risk**: Automatic version selection can introduce breaking changes or install known vulnerable versions.
- **Remediation**: Use `=` or specific syntax to pin versions.

**Bad**:

```dockerfile
RUN apk add python3
```

**Good**:

```dockerfile
RUN apk add python3=3.9.16-r0
```

### DF_PKG_006: Remove Unnecessary Packages

- **Severity**: High
- **Enforcement**: WARN
- **Description**: Only install packages required for application runtime; remove development tools from production images.
- **Risk**: Unnecessary packages increase attack surface and may contain exploitable vulnerabilities.
- **Remediation**: Use `--no-cache` and refrain from installing `vim`, `curl` (unless needed), `git` in final stage.

### DF_CMD_002: Use Exec Form Not Shell Form

- **Severity**: High
- **Enforcement**: DENY
- **Description**: Use exec form (JSON array syntax) for ENTRYPOINT and CMD to avoid shell processing.
- **Risk**: Shell form processes variables and enables shell injection attacks through environment variables.
- **Remediation**: Rewrite commands as JSON arrays.

**Bad**:

```dockerfile
CMD node app.js
```

**Good**:

```dockerfile
CMD ["node", "app.js"]
```

### DF_CMD_003: Do Not Use Sudo

- **Severity**: High
- **Enforcement**: WARN
- **Description**: Never use sudo in RUN instructions; run commands directly as the appropriate user.
- **Risk**: Sudo in containers is unnecessary complexity and creates unnecessary attack surface.
- **Remediation**: Switch `USER` explicitly instead of using `sudo`.

**Bad**:

```dockerfile
RUN sudo apt-get update
```

**Good**:

```dockerfile
USER root
RUN apt-get update
USER appuser
```

### DF_CMD_004: Minimize Running as Root

- **Severity**: High
- **Enforcement**: WARN
- **Description**: Only run commands that absolutely require root with root; switch to non-root user for application.
- **Risk**: Unnecessarily running as root increases blast radius if container is compromised.
- **Remediation**: Consolidate root commands at the top of the Dockerfile.

### DF_FS_003: Set Appropriate WORKDIR Ownership

- **Severity**: High
- **Enforcement**: WARN
- **Description**: Ensure WORKDIR is owned by non-root user running the application.
- **Risk**: If WORKDIR is owned by root, non-root user cannot write to it, breaking application.
- **Remediation**: `chown` the directory after creation.

**Good**:

```dockerfile
WORKDIR /app
RUN chown appuser:appuser /app
USER appuser
```

### DF_MULTI_001: Use Multistage Builds

- **Severity**: Medium
- **Enforcement**: WARN
- **Description**: Use multistage builds to separate build environment from runtime; copy only artifacts to final stage.
- **Risk**: Single-stage builds include unnecessary build tools and dependencies in production image.
- **Remediation**: Define a `builder` stage and a `final` stage.

**Good**:

```dockerfile
FROM golang AS builder
# ... build ...
FROM alpine
COPY --from=builder /app/bin /app/bin
```

### DF_MULTI_003: Copy Only Necessary Artifacts

- **Severity**: High
- **Enforcement**: WARN
- **Description**: In multistage builds, explicitly COPY only required artifacts, not entire directories.
- **Risk**: Copying entire directories may include build artifacts, development files, or secrets.
- **Remediation**: Be specific in `COPY --from` paths.

### DF_BUILD_003: Use .dockerignore

- **Severity**: Medium
- **Enforcement**: WARN
- **Description**: Create .dockerignore to exclude unnecessary files (.git, node_modules, .env) from build context.
- **Risk**: Including unnecessary files increases build context size and may expose secrets.
- **Remediation**: Create a robust `.dockerignore`.

### DF_HEALTH_001: Include HEALTHCHECK

- **Severity**: Medium
- **Enforcement**: MEDIUM
- **Description**: Define HEALTHCHECK with appropriate interval, timeout, and start period for application health monitoring.
- **Risk**: Without healthcheck, container orchestrators cannot detect unhealthy instances and may serve bad requests.
- **Remediation**: Add `HEALTHCHECK` instruction.

**Good**:

```dockerfile
HEALTHCHECK --interval=30s --timeout=3s \
  CMD curl -f http://localhost/ || exit 1
```

---

## Docker Compose Checks (24)

### DC_IMG_001: Use Specific Image Version Tags

- **Severity**: Critical
- **Enforcement**: DENY
- **Description**: Always specify explicit image version tags (e.g., myapp:1.0.0) instead of 'latest' or no tag.
- **Risk**: Without explicit tags, composition may use different image versions causing unpredictable behavior.

**Bad**:

```yaml
image: nginx:latest
```

**Good**:

```yaml
image: nginx:1.25.3
```

### DC_IMG_002: Use Image Pull Policy Always

- **Severity**: High
- **Enforcement**: WARN
- **Description**: Ensure images are pulled from registry each time (image_pull_policy: always) for latest updates.
- **Risk**: Stale cached images may have known vulnerabilities.

**Good**:

```yaml
pull_policy: always
```

### DC_USER_001: Run Services as Non-Root User

- **Severity**: Critical
- **Enforcement**: DENY
- **Description**: Set 'user: UID:GID' (e.g., user: 1000:1000) to run service as non-root user.
- **Risk**: Services running as root allow full system compromise if container is exploited.

**Bad**:

```yaml
image: myapp
# user: omitted
```

**Good**:

```yaml
image: myapp
user: "1000:1000"
```

### DC_USER_002: Do Not Use Privileged Mode

- **Severity**: Critical
- **Enforcement**: DENY
- **Description**: Never set 'privileged: true' as it grants full host access; use capabilities instead.
- **Risk**: Privileged containers disable all isolation features, allowing complete host compromise.

**Bad**:

```yaml
privileged: true
```

### DC_SEC_001: Disable Privilege Escalation

- **Severity**: High
- **Enforcement**: DENY
- **Description**: Set 'security_opt: [no-new-privileges:true]' to prevent processes gaining new privileges.
- **Risk**: Without no-new-privileges, exploits can escalate from current user to root or other users.

**Good**:

```yaml
security_opt:
  - no-new-privileges:true
```

### DC_SEC_002: Drop All Unnecessary Capabilities

- **Severity**: Critical
- **Enforcement**: DENY
- **Description**: Always drop all capabilities with 'cap_drop: [ALL]' and add back only required ones.
- **Risk**: Unnecessary Linux capabilities allow privilege escalation and unauthorized system access.

**Good**:

```yaml
cap_drop:
  - ALL
```

### DC_SEC_003: Only Add Required Capabilities

- **Severity**: Critical
- **Enforcement**: WARN
- **Description**: Use 'cap_add' to add back only specific capabilities needed (e.g., NET_BIND_SERVICE, CHOWN).
- **Risk**: Added capabilities expand attack surface; only essential capabilities should be granted.

**Bad**:

```yaml
cap_add:
  - SYS_ADMIN
```

**Good**:

```yaml
cap_add:
  - NET_BIND_SERVICE
```

### DC_SEC_004: Set Read-Only Root Filesystem

- **Severity**: High
- **Enforcement**: WARN
- **Description**: Set 'read_only: true' to prevent modifications to root filesystem; use 'tmpfs' for writable dirs.
- **Risk**: Writable filesystem allows attackers to modify system files and persist backdoors.

**Good**:

```yaml
read_only: true
```

### DC_SEC_005: Use Tmpfs for Temporary Files

- **Severity**: High
- **Enforcement**: WARN
- **Description**: Mount '/tmp' and '/run' as tmpfs with noexec,nosuid,nodev flags when read_only is true.
- **Risk**: Without tmpfs, application cannot write temporary files; with wrong flags, can execute malicious code.

**Good**:

```yaml
tmpfs:
  - /tmp
  - /run
```

### DC_NET_001: Define Services on Custom Network

- **Severity**: High
- **Enforcement**: WARN
- **Description**: Define all services on custom 'networks' instead of using default bridge network.
- **Risk**: Default network allows all containers to communicate; custom networks enforce service isolation.

**Bad**:

```yaml
# implicitly uses default bridge
```

**Good**:

```yaml
networks:
  backend:
    driver: bridge
```

### DC_NET_002: Do Not Expose Unnecessary Ports

- **Severity**: High
- **Enforcement**: WARN
- **Description**: Only expose ports that are required for external access; avoid exposing debug or management ports.
- **Risk**: Exposed ports increase attack surface and may allow unauthorized access to services.

**Bad**:

```yaml
ports:
  - "5432:5432"  # Database exposed
```

### DC_NET_004: Do Not Expose Port 22 (SSH)

- **Severity**: High
- **Enforcement**: DENY
- **Description**: Never expose port 22; use 'docker-compose exec' for container access.
- **Risk**: Exposed SSH port allows unauthorized remote access to containers.

**Bad**:

```yaml
ports:
  - "22:22"
```

### DC_NET_005: Use Network Mode Carefully

- **Severity**: Critical
- **Enforcement**: DENY
- **Description**: Avoid 'network_mode: host' which disables network isolation; only use bridge (default).
- **Risk**: Host network mode disables network isolation allowing direct access to host network.

**Bad**:

```yaml
network_mode: host
```

### DC_VOL_001: Mount Volumes with Appropriate Flags

- **Severity**: High
- **Enforcement**: WARN
- **Description**: Use volume mount flags (ro, rw, Z, z) appropriately; use ':ro' for read-only when possible.
- **Risk**: World-writable volumes allow unauthorized data modification and potential privilege escalation.

**Good**:

```yaml
volumes:
  - ./config:/app/config:ro
```

### DC_VOL_002: Avoid Mounting Host Directories with Write Access

- **Severity**: Critical
- **Enforcement**: DENY
- **Description**: Do not mount host directories with write access (rw flag); use read-only (:ro) when possible.
- **Risk**: Write access to host filesystem allows attackers to modify or delete host files.

**Bad**:

```yaml
volumes:
  - /var/lib:/app/data
```

**Good**:

```yaml
volumes:
  - /var/lib:/app/data:ro
```

### DC_VOL_003: Do Not Mount Docker Socket

- **Severity**: Critical
- **Enforcement**: DENY
- **Description**: Never mount '/var/run/docker.sock' in container as it grants full Docker daemon access.
- **Risk**: Docker socket access allows container to manage all containers and access host directly.

**Bad**:

```yaml
volumes:
  - /var/run/docker.sock:/var/run/docker.sock
```

### DC_VOL_004: Do Not Mount Host Filesystem Root

- **Severity**: Critical
- **Enforcement**: DENY
- **Description**: Never mount '/' (host root) into container as it allows complete host compromise.
- **Risk**: Root filesystem mount allows attackers to modify host system and persist attacks.

**Bad**:

```yaml
volumes:
  - /:/host
```

### DC_VOL_006: Set Volume Ownership to Non-Root

- **Severity**: High
- **Enforcement**: WARN
- **Description**: Ensure volumes are owned by non-root user running application to prevent permission issues.
- **Risk**: Root-owned volumes prevent non-root users from writing data, breaking application.

### DC_VOL_007: Use Tmpfs for Temporary Storage

- **Severity**: High
- **Enforcement**: WARN
- **Description**: Mount tmpfs volumes for temporary files with restrictions: tmpfs: options: [noexec, nosuid, nodev].
- **Risk**: Writable tmpfs without restrictions allows execution of malicious code in memory.

### DC_ENV_001: Do Not Use Environment Variables for Secrets

- **Severity**: Critical
- **Enforcement**: DENY
- **Description**: Never store passwords, tokens, API keys in 'environment' section; use external secret management.
- **Risk**: Environment variables are visible in process list, container inspect, and logs.

**Bad**:

```yaml
environment:
  - DB_PASS=secret
```

### DC_ENV_002: Use .env File for Non-Secret Configuration

- **Severity**: High
- **Enforcement**: WARN
- **Description**: Use .env file for non-secret configuration; add .env to .gitignore to prevent accidental commits.
- **Risk**: Hardcoded configuration makes composition inflexible and may expose sensitive defaults.
- **Remediation**: Create a `.env` file and use `${VAR}` syntax in compose.

### DC_ENV_003: Do Not Commit .env Files

- **Severity**: Critical
- **Enforcement**: DENY
- **Description**: Add .env, .env.local, .env.*.local to .gitignore to prevent committing configuration files.
- **Risk**: Committed .env files expose all configuration including secrets to repository access.

### DC_SEC_MAN_001: Use Docker Secrets

- **Severity**: High
- **Enforcement**: WARN
- **Description**: Use 'secrets' section with external secret file for sensitive data in Swarm mode.
- **Risk**: Without secrets, configuration exposes sensitive data to multiple exposure points.

**Good**:

```yaml
secrets:
  db_password:
    file: ./db_password.txt
```

### DC_HEALTH_001: Define Health Checks

- **Severity**: Medium
- **Enforcement**: MEDIUM
- **Description**: Include 'healthcheck' for each service with test, interval, timeout, and retries.
- **Risk**: Without healthchecks, failed services continue running and serving bad requests.

**Good**:

```yaml
healthcheck:
  test: ["CMD", "curl", "-f", "http://localhost"]
  interval: 30s
  timeout: 10s
  retries: 3
```

### DC_LOG_001: Configure Logging Driver

- **Severity**: High
- **Enforcement**: WARN
- **Description**: Set 'logging: driver' and 'logging: options' for centralized logging (json-file, syslog, splunk).
- **Risk**: Without logging configuration, logs are not collected for audit and forensics.

**Good**:

```yaml
logging:
  driver: "json-file"
```

### DC_LOG_002: Set Log Rotation and Size Limits

- **Severity**: High
- **Enforcement**: WARN
- **Description**: Configure 'max-size' and 'max-file' for log rotation to prevent disk space exhaustion.
- **Risk**: Unlimited log size can fill disk and cause service failure.

**Good**:

```yaml
logging:
  driver: "json-file"
  options:
    max-size: "10m"
    max-file: "3"
```

### DC_LOG_003: Do Not Log Sensitive Information

- **Severity**: Critical
- **Enforcement**: DENY
- **Description**: Ensure application does not log passwords, tokens, or sensitive data in logs.
- **Risk**: Logged secrets are visible in logs and centralized logging systems.
- **Remediation**: Check application logging configuration (e.g., log4j, morgan) to exclude headers and body containing secrets.

---

## General Validation Checks (2)

### GEN_YAML_001: Valid YAML Syntax

- **Severity**: Critical
- **Enforcement**: DENY
- **Description**: Ensure docker-compose.yml has valid YAML syntax with proper indentation and quoting.
- **Risk**: Invalid YAML causes parsing errors and prevents service startup.
- **Remediation**: Run `docker-compose config` to validate.

### GEN_JSON_001: Valid JSON Syntax

- **Severity**: Critical
- **Enforcement**: DENY
- **Description**: Ensure daemon.json is valid JSON with proper syntax, comma placement, and quoting.
- **Risk**: Invalid JSON prevents daemon from starting.
- **Remediation**: Use a JSON validator (jq).

***Bad***:

```json
{ "key": "value" "missing": "comma" }
```
