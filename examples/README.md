# Docker Security Examples

This directory contains reference implementations of "Good" (Secure) and "Bad" (Insecure) configurations for Dockerfiles and Docker Compose files. These examples are designed to demonstrate the 56 security policies enforced by the OPA Rego rules in this project.

## Directory Structure

```text
examples/
├── bad/
│   ├── Dockerfile             # Violates all 25 Dockerfile security checks
│   └── docker-compose.yml     # Violates all 27 Compose security checks
├── good/
│   ├── Dockerfile             # Complies with all 25 Dockerfile security checks
│   └── docker-compose.yml     # Complies with all 27 Compose security checks
└── README.md                  # This file
```

## How to Test

You can use `conftest` to run policies against these examples.

### Testing "Bad" Examples (Expect Failures)

These files are intentionally insecure. Running strict policies against them should generate numerous failures.

```bash
# Test Bad Dockerfile
conftest test examples/bad/Dockerfile --policy policy/

# Test Bad Compose File
conftest test examples/bad/docker-compose.yml --policy policy/
```

### Testing "Good" Examples (Expect Success)

These files represent production-hardened configurations. Policies should pass or produce only minimal warnings (notes).

```bash
# Test Good Dockerfile
conftest test examples/good/Dockerfile --policy policy/

# Test Good Compose File
conftest test examples/good/docker-compose.yml --policy policy/
```

## Key Checks Demonstrated

- **Base Images**: `latest` tag vs specific tags, trusted registries.
- **User**: Root vs Non-root user implementation.
- **Files**: Dangerous permissions (777) vs restrictive (644/755).
- **Secrets**: Hardcoded env vars vs Secrets mounts.
- **Network**: Host networking vs Custom isolated networks.
- **Capabilities**: Full privileges vs Dropped capabilities.
- **Volumes**: Host root mounts vs Read-only named volumes.
