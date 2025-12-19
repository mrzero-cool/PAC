# Docker Security Policy Examples

This directory contains example files demonstrating security policy compliance for both Dockerfiles and docker-compose.yml files.

## Structure

```
examples/
├── bad/
│   ├── Dockerfile           # Violates Dockerfile security checks
│   └── docker-compose.yml   # Violates docker-compose security checks
├── good/
│   ├── Dockerfile           # Compliant Dockerfile
│   └── docker-compose.yml   # Compliant docker-compose.yml
└── README.md                # This file
```

## Testing Examples

### Test All Files

```bash
# Test all bad examples (should show violations)
conftest test examples/bad/ --policy policy/ --all-namespaces

# Test all good examples (should pass)
conftest test examples/good/ --policy policy/ --all-namespaces
```

### Test Individual Files

```bash
# Test bad Dockerfile
conftest test examples/bad/Dockerfile --policy policy/

# Test bad docker-compose.yml
conftest test examples/bad/docker-compose.yml --policy policy/

# Test good Dockerfile
conftest test examples/good/Dockerfile --policy policy/

# Test good docker-compose.yml
conftest test examples/good/docker-compose.yml --policy policy/
```

## Dockerfile Examples

### Bad Dockerfile (`bad/Dockerfile`)

Intentionally violates 13 Dockerfile security checks:

- DF_BASE_001: Uses `ubuntu:latest` (no version tag)
- DF_BASE_003: Not from trusted minimal registry
- DF_USER_001: No USER instruction
- DF_USER_002: Runs as root
- DF_FILE_002: Copies entire directory (COPY . .)
- DF_FILE_004: Uses curl | bash pattern
- DF_SEC_001: Hardcodes secrets in ENV
- DF_SEC_002: Passes secrets via ARG
- DF_SEC_004: Copies .env files
- DF_CMD_002: Uses shell form for CMD
- DF_CMD_003: Uses sudo in RUN
- DF_CMD_004: Runs unnecessary commands as root
- DF_FS_003: No WORKDIR ownership set

**Expected**: ~13 Dockerfile violations

### Good Dockerfile (`good/Dockerfile`)

Demonstrates best practices and passes all 13 Dockerfile checks:

- Specific Alpine version with SHA256 digest
- Minimal base image from trusted registry
- Non-root user with proper ownership
- Specific file copies only
- No secrets or sensitive files
- Exec form for commands
- No sudo usage
- Proper WORKDIR ownership

**Expected**: 0 violations

## docker-compose.yml Examples

### Bad docker-compose.yml (`bad/docker-compose.yml`)

Intentionally violates 15 docker-compose security checks:

- DC_IMG_001: Uses :latest tags
- DC_USER_001: Runs as root
- DC_USER_002: Uses privileged mode
- DC_SEC_001: Missing no-new-privileges
- DC_SEC_002: Doesn't drop capabilities
- DC_SEC_003: Adds dangerous capabilities
- DC_NET_002: Exposes unnecessary ports
- DC_NET_004: Exposes SSH port 22
- DC_NET_005: Uses network_mode: host
- DC_VOL_002: Writable host mounts
- DC_VOL_003: Mounts Docker socket
- DC_VOL_004: Mounts host root filesystem
- DC_ENV_001: Hardcoded secrets in environment
- DC_ENV_003: References .env files
- DC_LOG_003: Logs sensitive information

**Expected**: ~15 docker-compose violations

### Good docker-compose.yml (`good/docker-compose.yml`)

Demonstrates best practices and passes all 15 docker-compose checks:

- Specific version tags for all images
- Non-root users (user: "1000:1000")
- Security options: no-new-privileges:true
- Drops all capabilities, adds only required ones
- Minimal port exposure (no SSH, DB ports)
- Named volumes instead of host mounts
- Read-only mounts where applicable
- External secrets management (.env.production)
- No Docker socket mounts
- No host filesystem mounts
- Proper logging configuration

**Expected**: 0 violations

## General Validation

The policy also includes general validation for:

- GEN_YAML_001: Valid YAML syntax (automatic via conftest)
- GEN_JSON_001: Valid JSON syntax for daemon.json
- GEN_PERM_001: File permissions (requires shell script)
- GEN_OWNER_001: File ownership (requires shell script)

**Note**: File permission and ownership checks (GEN_PERM_001, GEN_OWNER_001) require filesystem access and should be implemented as separate shell scripts. See `general_validation.rego` for implementation guidance.

## Summary

**Total Checks: 32**

- Dockerfile: 13 checks
- docker-compose: 15 checks
- General: 4 checks

All checks are implemented in modular Rego policy files under `policy/checks/`.
