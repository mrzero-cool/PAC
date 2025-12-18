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
#       ├── base_image.rego
#       ├── user.rego
#       ├── security.rego
#       ├── files.rego
#       ├── packages.rego
#       ├── commands.rego
#       ├── filesystem.rego
#       └── multistage.rego
#
# Total Checks: 21 (8 Critical + 13 High Severity)
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
