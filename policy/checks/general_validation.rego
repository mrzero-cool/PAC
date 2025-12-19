package main

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# ==============================================================================
# GENERAL VALIDATION CHECKS
# ==============================================================================

# GEN_YAML_001: Valid YAML syntax
# Note: This is automatically validated by conftest's YAML parser
# If the YAML is invalid, conftest will fail before running policies
# This rule provides explicit guidance

# GEN_JSON_001: Valid JSON syntax for daemon.json
# Note: Similar to YAML, JSON validation happens at parse time
# These checks are here for completeness and documentation

# The following checks (GEN_PERM_001, GEN_OWNER_001) require filesystem-level
# access which OPA/Rego cannot directly provide when parsing YAML/JSON content.
# These should be implemented as separate validation scripts.

# ==============================================================================
# HELPER FUNCTIONS FOR VALIDATION
# ==============================================================================

# Helper: Check if input is valid YAML structure
is_valid_yaml_structure if {
    # Input was successfully parsed as YAML/JSON
    # If we reach this point, the structure is valid
    input
}

# Helper: Common YAML/JSON validation errors to document
# These are caught by conftest's parser before policies run:
# - Indentation errors in YAML
# - Missing colons or quotes
# - Unclosed brackets or braces
# - Invalid escape sequences
# - Duplicate keys at the same level

# ==============================================================================
# DOCKER COMPOSE STRUCTURE VALIDATION
# ==============================================================================

# Validate docker-compose.yml has required version
deny contains msg if {
    input.services  # This indicates it's a docker-compose file
    not input.version
    not input.services  # Double-check structure
    msg := "[GEN_YAML_001][CRITICAL] docker-compose.yml should specify a version. Add 'version: \"3.8\"' or later."
}

# Validate services section exists
deny contains msg if {
    # Check if this looks like a compose file but has no services
    input.version
    not input.services
    msg := "[GEN_YAML_001][CRITICAL] docker-compose.yml must have a 'services:' section defining at least one service."
}

# Validate each service has an image or build context
deny contains msg if {
    input.services
    some service_name, service_config in input.services
    not service_config.image
    not service_config.build
    msg := sprintf("[GEN_YAML_001][CRITICAL] Service '%s' must specify either 'image:' or 'build:' directive.", [service_name])
}

# ==============================================================================
# DAEMON.JSON VALIDATION
# ==============================================================================

# Validate daemon.json structure (when input is daemon.json)
deny contains msg if {
    # Check if this is daemon.json by looking for typical fields
    input["log-driver"]
    
    # Validate log-driver is a valid type
    log_driver := input["log-driver"]
    not is_valid_log_driver(log_driver)
    
    msg := sprintf("[GEN_JSON_001][CRITICAL] Invalid log-driver in daemon.json: '%s'. Use: json-file, syslog, journald, gelf, fluentd, or local.", [log_driver])
}

valid_log_drivers := {
    "json-file", "syslog", "journald", "gelf", 
    "fluentd", "awslogs", "splunk", "local", "none"
}

is_valid_log_driver(driver) if {
    driver in valid_log_drivers
}

# Validate storage-driver if present
deny contains msg if {
    input["storage-driver"]
    storage_driver := input["storage-driver"]
    not is_valid_storage_driver(storage_driver)
    
    msg := sprintf("[GEN_JSON_001][CRITICAL] Invalid storage-driver in daemon.json: '%s'. Use: overlay2, aufs, btrfs, devicemapper, or zfs.", [storage_driver])
}

valid_storage_drivers := {
    "overlay2", "aufs", "btrfs", "devicemapper", "zfs", "vfs"
}

is_valid_storage_driver(driver) if {
    driver in valid_storage_drivers
}

# ==============================================================================
# NOTES ON FILE PERMISSIONS AND OWNERSHIP
# ==============================================================================

# GEN_PERM_001: Correct file permissions
# GEN_OWNER_001: Correct file ownership
#
# These checks require filesystem-level access and cannot be implemented
# directly in OPA/Rego which operates on parsed content.
#
# Recommended implementation:
# Create a shell script: check_file_permissions.sh
#
# #!/bin/bash
# # Check docker-compose.yml permissions
# if [ -f docker-compose.yml ]; then
#     perms=$(stat -c '%a' docker-compose.yml)
#     if [ "$perms" != "644" ]; then
#         echo "[GEN_PERM_001][HIGH] docker-compose.yml should have 644 permissions"
#     fi
# fi
#
# # Check .env permissions
# if [ -f .env ]; then
#     perms=$(stat -c '%a' .env)
#     if [ "$perms" != "600" ]; then
#         echo "[GEN_PERM_001][HIGH] .env file should have 600 permissions"
#     fi
# fi
#
# # Check ownership
# owner=$(stat -c '%U:%G' docker-compose.yml)
# if [ "$owner" != "root:root" ]; then
#     echo "[GEN_OWNER_001][HIGH] docker-compose.yml should be owned by root:root"
# fi
#
# Note: On Windows, use PowerShell equivalent:
# Get-Acl docker-compose.yml | Format-List
