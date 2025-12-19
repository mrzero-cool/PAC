# ==============================================================================
# Docker Security Policy - Main Entry Point
# ==============================================================================
# This file serves as the entry point for conftest.
# All policy checks are organized in modular files under checks/ directory.
#
# Structure:
#   policy/
#   ├── main.rego (this file)
#   ├── lib/helpers.rego
#   └── checks/
#       # Dockerfile Checks (21 checks)
#       ├── base_image.rego
#       ├── user.rego
#       ├── security.rego
#       ├── files.rego
#       ├── packages.rego
#       ├── commands.rego
#       ├── filesystem.rego
#       ├── multistage.rego
#       # docker-compose.yml Checks (15 checks)
#       ├── compose_images.rego
#       ├── compose_user.rego
#       ├── compose_security.rego
#       ├── compose_network.rego
#       ├── compose_volumes.rego
#       ├── compose_environment.rego
#       # General Validation (4 checks)
#       └── general_validation.rego
#
# Total Checks: 32
#   - Dockerfile: 13 checks (9 Critical + 4 High)
#   - docker-compose: 15 checks (11 Critical + 4 High)
#   - General: 4 checks (4 Critical)
# ==============================================================================

package main

import future.keywords.contains
import future.keywords.if

# This file intentionally left minimal.
# All deny rules are defined in modular check files under checks/
# All helper functions are in lib/helpers.rego
#
# Conftest will automatically load all .rego files in the policy directory
# and merge them into the main package namespace.
