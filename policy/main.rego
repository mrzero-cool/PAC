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
#   ├── base/
#   │   ├── base_image.rego
#   │   ├── multistage.rego
#   │   ├── packages.rego
#   │   └── compose_images.rego
#   ├── user/
#   │   ├── user.rego
#   │   └── compose_user.rego
#   ├── network/
#   │   └── compose_network.rego
#   ├── security/
#   │   ├── security.rego
#   │   ├── compose_security.rego
#   │   └── compose_environment.rego
#   ├── files/
#   │   ├── files.rego
#   │   ├── filesystem.rego
#   │   └── compose_volumes.rego
#   ├── commands/
#   │   └── commands.rego
#   └── general/
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
# All deny rules are defined in modular check files under separate categories (e.g., base/, user/, etc.)
# All helper functions are in lib/helpers.rego
#
# Conftest will automatically load all .rego files in the policy directory
# and merge them into the main package namespace.
