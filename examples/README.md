# Dockerfile Examples

This directory contains example Dockerfiles demonstrating security policy compliance.

## Structure

```
examples/
├── bad/
│   └── Dockerfile      # Violates 20/21 security checks
├── good/
│   └── Dockerfile      # Compliant with all 21 checks
└── README.md           # This file
```

## Bad Dockerfile

Located in `bad/Dockerfile`, this file intentionally violates 20 of the 21 security checks to demonstrate what NOT to do:

- Uses `ubuntu:latest` (no version pinning, no digest, not minimal)
- Installs unpinned packages and dev tools
- Uses `curl | bash` pattern
- Hardcodes secrets in ARG/ENV
- Copies entire directory and sensitive files
- Sets insecure permissions (777, SUID)
- Uses sudo and shell form commands
- No USER instruction

**Usage:**

```bash
conftest test examples/bad/Dockerfile --policy policy/
```

**Expected**: ~20 failures

## Good Dockerfile

Located in `good/Dockerfile`, this file demonstrates best practices and passes all 21 security checks:

- Uses Alpine with specific version and SHA256 digest
- Pins all package versions
- Multistage build with specific file copies
- No secrets or sensitive files
- Restrictive permissions
- Non-root user with proper ownership
- Exec form for ENTRYPOINT/CMD

**Usage:**

```bash
conftest test examples/good/Dockerfile --policy policy/
```

**Expected**: 0 failures (all pass)
