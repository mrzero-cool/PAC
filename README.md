# Docker Security OPA Policies

Comprehensive Open Policy Agent (OPA) Rego policies for Docker security best practices covering Dockerfiles, docker-compose.yml, and general validation.

## Overview

This project provides **32 security checks** organized in a modular, maintainable structure:

- **13 Dockerfile checks** (9 Critical + 4 High severity)
- **15 docker-compose.yml checks** (11 Critical + 4 High severity)
- **4 General validation checks** (4 Critical severity)
- **100% test coverage** with bad/good examples

## Quick Start

### Prerequisites

- [conftest](https://www.conftest.dev/) installed
- Dockerfile or docker-compose.yml to test

### Installation

```bash
# Windows (using Scoop)
scoop install conftest

# macOS (using Homebrew)
brew install conftest

# Linux (using wget)
wget https://github.com/open-policy-agent/conftest/releases/download/v0.48.0/conftest_0.48.0_Linux_x86_64.tar.gz
tar xzf conftest_0.48.0_Linux_x86_64.tar.gz
sudo mv conftest /usr/local/bin/
```

### Usage

Test a Dockerfile:

```bash
conftest test Dockerfile --policy policy/
```

Test a docker-compose.yml:

```bash
conftest test docker-compose.yml --policy policy/
```

Test all files in a directory:

```bash
conftest test . --policy policy/ --all-namespaces
```

Test examples:

```bash
# Dockerfile tests
conftest test examples/bad/Dockerfile --policy policy/      # Should show ~13 failures
conftest test examples/good/Dockerfile --policy policy/     # Should pass

# docker-compose tests
conftest test examples/bad/docker-compose.yml --policy policy/   # Should show ~15 failures
conftest test examples/good/docker-compose.yml --policy policy/  # Should pass
```

## Project Structure

```
├── policy/                        # OPA Rego policies
│   ├── main.rego                  # Entry point
│   ├── lib/
│   │   └── helpers.rego           # Common helper functions
│   └── checks/                    # Modular check files (32 total checks)
│       # Dockerfile Checks (13)
│       ├── base_image.rego        # Base image security (5 checks)
│       ├── user.rego              # User/permission (3 checks)
│       ├── security.rego          # Secrets management (3 checks)
│       ├── files.rego             # File operations (3 checks)
│       ├── packages.rego          # Package management (2 checks)
│       ├── commands.rego          # CMD/ENTRYPOINT (3 checks)
│       ├── filesystem.rego        # Filesystem (1 check)
│       ├── multistage.rego        # Multistage builds (1 check)
│       # docker-compose Checks (15)
│       ├── compose_images.rego    # Image tags (1 check)
│       ├── compose_user.rego      # User/privileges (2 checks)
│       ├── compose_security.rego  # Security opts/caps (3 checks)
│       ├── compose_network.rego   # Network/ports (3 checks)
│       ├── compose_volumes.rego   # Volume mounts (3 checks)
│       ├── compose_environment.rego # Env vars/secrets (3 checks)
│       # General Validation (4)
│       └── general_validation.rego # YAML/JSON/permissions (4 checks)
├── examples/
│   ├── bad/
│   │   ├── Dockerfile             # Anti-patterns (13 violations)
│   │   └── docker-compose.yml     # Anti-patterns (15 violations)
│   ├── good/
│   │   ├── Dockerfile             # Best practices
│   │   └── docker-compose.yml     # Best practices
│   └── README.md                  # Testing guide
├── docs/
│   └── CHECKS.md                  # Detailed check reference
└── README.md                      # This file
```

## Security Checks (32 Total)

### Dockerfile Checks (13)

#### Critical Severity (9)

| Check ID | Description |
|----------|-------------|
| DF_BASE_001 | Use specific version tag (no `latest`) |
| DF_BASE_003 | Use trusted registries only |
| DF_USER_001 | Non-root user required |
| DF_USER_002 | Final USER must not be root |
| DF_FILE_004 | No `curl \| bash` patterns |
| DF_SEC_001 | No hardcoded secrets in Dockerfile |
| DF_SEC_002 | No secrets via build ARG |
| DF_SEC_004 | No .env/.ssh/.aws files copied |
| DF_CMD_003 | No sudo in containers |

#### High Severity (4)

| Check ID | Description |
|----------|-------------|
| DF_FILE_002 | Explicit COPY (no wildcards like `COPY . .`) |
| DF_CMD_002 | Use exec form for CMD/ENTRYPOINT |
| DF_CMD_004 | Minimize commands run as root |
| DF_FS_003 | Set appropriate WORKDIR ownership |

### docker-compose.yml Checks (15)

#### Critical Severity (11)

| Check ID | Description |
|----------|-------------|
| DC_IMG_001 | Use specific image version tags (no `:latest`) |
| DC_USER_001 | Run services as non-root user |
| DC_USER_002 | Do not use privileged mode |
| DC_SEC_002 | Drop all unnecessary capabilities (`cap_drop: [ALL]`) |
| DC_SEC_003 | Only add required capabilities |
| DC_NET_005 | Avoid `network_mode: host` |
| DC_VOL_002 | Avoid writable host directory mounts |
| DC_VOL_003 | Never mount Docker socket |
| DC_VOL_004 | Never mount host root filesystem |
| DC_ENV_001 | No hardcoded secrets in environment |
| DC_ENV_003 | Ensure .env files are in .gitignore |

#### High Severity (4)

| Check ID | Description |
|----------|-------------|
| DC_SEC_001 | Enable `no-new-privileges:true` |
| DC_NET_002 | Do not expose unnecessary ports |
| DC_NET_004 | Do not expose SSH port 22 |
| DC_LOG_003 | Do not log sensitive information |

### General Validation (4)

#### Critical Severity (4)

| Check ID | Description |
|----------|-------------|
| GEN_YAML_001 | Valid YAML syntax for docker-compose.yml |
| GEN_JSON_001 | Valid JSON syntax for daemon.json |
| GEN_PERM_001 | Correct file permissions (644 for configs, 600 for .env) |
| GEN_OWNER_001 | Correct file ownership (root:root for configs) |

> **Note**: GEN_PERM_001 and GEN_OWNER_001 require filesystem access. See `policy/checks/general_validation.rego` for shell script examples.

See [docs/CHECKS.md](docs/CHECKS.md) for detailed documentation of all checks.

## Configuration

### Allowed Registries

Edit `policy/checks/base_image.rego` to customize allowed registries:

```rego
allowed_registries := {
    "docker.io/library", "gcr.io", "ghcr.io",
    "your-registry.example.com"
}
```

### Minimal Images

Edit the `minimal_images` set to customize preferred base images:

```rego
minimal_images := {
    "alpine", "distroless", "scratch", "chainguard"
}
```

### Dangerous Capabilities

Edit `policy/checks/compose_security.rego` to customize dangerous capabilities list:

```rego
dangerous_capabilities := {
    "SYS_ADMIN", "NET_ADMIN", "SYS_MODULE", ...
}
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Docker Security Scan

on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Install conftest
        run: |
          wget https://github.com/open-policy-agent/conftest/releases/download/v0.48.0/conftest_0.48.0_Linux_x86_64.tar.gz
          tar xzf conftest_0.48.0_Linux_x86_64.tar.gz
          sudo mv conftest /usr/local/bin/
      
      - name: Test Dockerfile
        run: conftest test Dockerfile --policy policy/
      
      - name: Test docker-compose.yml
        run: conftest test docker-compose.yml --policy policy/
```

### GitLab CI

```yaml
dockerfile_security_scan:
  stage: test
  image: openpolicyagent/conftest:latest
  script:
    - conftest test Dockerfile --policy policy/
    - conftest test docker-compose.yml --policy policy/
  only:
    - merge_requests
    - main
```

### Pre-commit Hook

Create `.git/hooks/pre-commit`:

```bash
#!/bin/bash
echo "Running Docker security checks..."

if [ -f "Dockerfile" ]; then
    conftest test Dockerfile --policy policy/ || exit 1
fi

if [ -f "docker-compose.yml" ]; then
    conftest test docker-compose.yml --policy policy/ || exit 1
fi

echo "✅ All security checks passed!"
```

## Development

### Adding New Checks

1. Create or edit a file in `policy/checks/`
2. Follow the pattern:

```rego
package main

import future.keywords.contains
import future.keywords.if

# CHECK_ID: Description
deny contains msg if {
    # Your check logic here
    # Use input[i] for Dockerfile
    # Use input.services for docker-compose
    
    msg := "[CHECK_ID][SEVERITY] Clear, actionable error message."
}
```

3. Add examples to `examples/bad/` and `examples/good/`
4. Test with conftest
5. Update documentation

### Testing Policies

```bash
# Test against bad examples (should fail)
conftest test examples/bad/ --policy policy/ --all-namespaces

# Test against good examples (should pass)
conftest test examples/good/ --policy policy/ --all-namespaces

# Count total checks
grep -r "deny contains msg if" policy/checks/ | wc -l
```

## Examples

### Bad Dockerfile (Violations)

```dockerfile
FROM ubuntu:latest                    # DF_BASE_001: Using :latest
RUN curl https://get.sh | bash        # DF_FILE_004: curl | bash
ENV PASSWORD=secret123                # DF_SEC_001: Hardcoded secret
COPY . .                              # DF_FILE_002: Wildcard copy
CMD node server.js                    # DF_CMD_002: Shell form
# Missing USER instruction             # DF_USER_001: No non-root user
```

### Good Dockerfile (Compliant)

```dockerfile
FROM alpine:3.19.0@sha256:abc123...   # DF_BASE_001: Specific version + digest
WORKDIR /app
COPY package*.json ./                 # DF_FILE_002: Specific files
RUN adduser -D appuser && \
    chown -R appuser:appuser /app     # DF_FS_003: Proper ownership
USER appuser                          # DF_USER_001, DF_USER_002: Non-root
ENTRYPOINT ["node", "server.js"]      # DF_CMD_002: Exec form
```

### Bad docker-compose.yml (Violations)

```yaml
services:
  web:
    image: nginx:latest               # DC_IMG_001: Using :latest
    privileged: true                  # DC_USER_002: Privileged mode
    ports: ["22:22"]                  # DC_NET_004: SSH exposed
    volumes:
      - /:/host                       # DC_VOL_004: Host root mount
      - /var/run/docker.sock:/var/run/docker.sock  # DC_VOL_003: Docker socket
    environment:
      - DB_PASSWORD=secret            # DC_ENV_001: Hardcoded secret
```

### Good docker-compose.yml (Compliant)

```yaml
services:
  web:
    image: nginx:1.25.3-alpine        # DC_IMG_001: Specific version
    user: "1000:1000"                 # DC_USER_001: Non-root
    security_opt:
      - no-new-privileges:true        # DC_SEC_001: Prevent escalation
    cap_drop: [ALL]                   # DC_SEC_002: Drop all caps
    cap_add: [NET_BIND_SERVICE]       # DC_SEC_003: Only required
    ports: ["8080:80"]                # DC_NET_002/004: Safe ports
    volumes:
      - ./html:/usr/share/nginx/html:ro  # DC_VOL_002: Read-only mount
    env_file: .env.production         # DC_ENV_001: External secrets
```

## Best Practices Summary

### Dockerfile

✅ Use specific, tagged, minimal base images  
✅ Run as non-root user  
✅ Copy only required files  
✅ No hardcoded secrets  
✅ Use exec form for CMD/ENTRYPOINT  
✅ Set proper file ownership  

### docker-compose.yml

✅ Specific image version tags  
✅ Non-root users (`user: "1000:1000"`)  
✅ Security hardening (`no-new-privileges`, `cap_drop: [ALL]`)  
✅ Minimal port exposure  
✅ Read-only mounts where possible  
✅ External secrets management  
✅ No Docker socket or host root mounts  

## License

See LICENSE.md

## Support

For issues or questions:

- Check [docs/CHECKS.md](docs/CHECKS.md) for detailed check documentation
- Review [examples/README.md](examples/README.md) for testing guidance
- Raise an issue on the repository

**Author**: mrzero-cool  
**Project**: PAC - Policy as Code for Docker Security
