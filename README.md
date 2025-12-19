# Docker Security OPA Policies

Comprehensive Open Policy Agent (OPA) Rego policies for Docker security best practices.

## Overview

This project provides **21 Critical and High severity security checks** for Dockerfiles, organized in a modular, maintainable structure.

- **8 Critical** severity checks
- **13 High** severity checks
- **100% test coverage** with bad/good examples

## Quick Start

### Prerequisites

- [conftest](https://www.conftest.dev/) installed
- Dockerfile to test

### Usage

Test a Dockerfile:

```bash
conftest test path/to/Dockerfile --policy policy/
```

Test examples:

```bash
# Should show ~20 failures
conftest test examples/bad/Dockerfile --policy policy/

# Should pass all checks
conftest test examples/good/Dockerfile --policy policy/
```

## Project Structure

```
├── policy/                    # OPA Rego policies
│   ├── main.rego             # Entry point
│   ├── lib/
│   │   └── helpers.rego      # Common helper functions
│   └── checks/               # Modular check files
│       ├── base_image.rego   # Base image checks (5)
│       ├── user.rego         # User/permission checks (3)
│       ├── security.rego     # Secrets checks (3)
│       ├── files.rego        # File operation checks (3)
│       ├── packages.rego     # Package management (2)
│       ├── commands.rego     # CMD/ENTRYPOINT (3)
│       ├── filesystem.rego   # Filesystem checks (1)
│       └── multistage.rego   # Multistage builds (1)
├── examples/
│   ├── bad/Dockerfile        # Anti-patterns
│   ├── good/Dockerfile       # Best practices
│   └── README.md
├── docs/
│   └── CHECKS.md             # Detailed check reference
└── README.md                 # This file
```

## Security Checks

### Critical (8)

- DF_BASE_001: Specific version tag (no `latest`)
- DF_BASE_003: Trusted registries only
- DF_USER_001: Non-root user required
- DF_USER_002: Final USER not root
- DF_FILE_004: No `curl | bash` patterns
- DF_SEC_001: No hardcoded secrets
- DF_SEC_002: No secrets via ARG
- DF_SEC_004: No .env/.ssh/.aws files

### High (13)

- DF_BASE_002: Minimal base images
- DF_BASE_004: SHA256 digest pinning
- DF_BASE_005: Maintained images
- DF_USER_003: No SUID/SGID bits
- DF_FILE_002: Specific COPY (no wildcards)
- DF_FILE_003: Safe permissions
- DF_PKG_002: Pin package versions
- DF_PKG_006: Remove dev tools
- DF_CMD_002: Exec form
- DF_CMD_003: No sudo
- DF_CMD_004: Minimize root
- DF_FS_003: WORKDIR ownership
- DF_MULTI_003: Specific artifacts in multistage

See [docs/CHECKS.md](docs/CHECKS.md) for detailed documentation.

## Configuration

### Allowed Registries

Edit `policy/checks/base_image.rego` to customize allowed registries:

```rego
allowed_registries := {"your.registry.com", "gcr.io", ...}
```

### Minimal Images

Edit the `minimal_images` set to customize preferred base images.

## CI/CD Integration

### GitHub Actions

```yaml
- name: Dockerfile Security Scan
  run: conftest test Dockerfile --policy policy/
```

### GitLab CI

```yaml
dockerfile_scan:
  script:
    - conftest test Dockerfile --policy policy/
```

## Development

### Adding New Checks

1. Create or edit a file in `policy/checks/`
2. Follow the pattern:

```rego
package main
import future.keywords.contains
import future.keywords.if

deny contains msg if {
    # your check logic
    msg := "[CHECK_ID][SEVERITY] Description"
}
```

3. Test with examples
4. Update documentation

## License

See project license file.

## Support

For issues or questions, refer to the documentation or raise an issue.

Author: mrzero-cool

