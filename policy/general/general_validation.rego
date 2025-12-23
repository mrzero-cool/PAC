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


# Validating file syntax and structure. OPA/Rego operates on parsed content.

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

    driver in valid_storage_drivers
}

# ==============================================================================
# ADDITIONAL GENERAL CHECKS
# ==============================================================================

# DF_MULTI_001: Use multistage builds
# Description: Use multistage builds to reduce final image size.
# Severity: Medium
warn contains msg if {
    # Check if there are multiple FROM instructions
    from_cmds := [i | input[i].Cmd == "from"]
    count(from_cmds) < 2
    
    msg := "[DF_MULTI_001][MEDIUM] Dockerfile appears to use a single stage build. Use multistage builds to separate build environment from runtime artifacts and reduce image size."
}

# DF_HEALTH_001: Include HEALTHCHECK instruction
# Description: Define HEALTHCHECK for application health monitoring.
# Severity: Medium
warn contains msg if {
    # Check for HEALTHCHECK instruction
    healthchecks := [i | input[i].Cmd == "healthcheck"]
    count(healthchecks) == 0
    
    # Exclude scratch or simple base images if needed, but generally good practice
    msg := "[DF_HEALTH_001][MEDIUM] Dockerfile missing HEALTHCHECK instruction. Define health check to allow orchestrators to monitor container health."
}

# DC_HEALTH_001: Define health checks for all services
# Description: Include 'healthcheck' for each service.
# Severity: Medium
warn contains msg if {
    input.services
    some service_name, service_config in input.services
    
    not service_config.healthcheck
    
    msg := sprintf("[DC_HEALTH_001][MEDIUM] Service '%s' modifies healthcheck. Ensure it defines test, interval, timeout, and retries.", [service_name])
}

# DC_LOG_001: Configure logging driver
# Description: Set 'logging: driver' for centralized logging.
# Severity: High
warn contains msg if {
    input.services
    some service_name, service_config in input.services
    
    not service_config.logging
    
    msg := sprintf("[DC_LOG_001][HIGH] Service '%s' does not configure logging. Configure a logging driver (e.g., json-file, syslog) for centralized logs.", [service_name])
}

# DC_LOG_002: Set log rotation and size limits
# Description: Configure 'max-size' and 'max-file' for log rotation.
# Severity: High
warn contains msg if {
    input.services
    some service_name, service_config in input.services
    service_config.logging
    service_config.logging.driver == "json-file"
    
    not has_log_rotation(service_config.logging)
    
    msg := sprintf("[DC_LOG_002][HIGH] Service '%s' uses json-file logging without rotation. Set 'max-size' and 'max-file' in logging options to prevent disk exhaustion.", [service_name])
}

# DF_MULTI_003: Copy only necessary artifacts between stages
# Enhanced: Better --from flag detection and wildcard handling
deny contains msg if {
    some i
    cmd := input[i]
    cmd.Cmd == "copy"
    count(cmd.Value) > 0
    
    has_from_flag(cmd.Value)
    
    # Get source (first non-flag argument after --from)
    source := get_copy_source(cmd.Value)
    is_wildcard_copy_multi(source)
    
    msg := sprintf("[DF_MULTI_003][HIGH] In multistage builds, copy specific artifacts not entire directories. Found: COPY --from=... %s. Specify exact files to reduce final image size.", [source])
}

has_from_flag(values) if {
    some val in values
    startswith(val, "--from=")
}

has_from_flag(values) if {
    some i
    values[i] == "--from"
}

get_copy_source(values) := source if {
    # Find first non-flag value (the source path)
    non_flags := [v | some v in values; not startswith(v, "--"); v != "--from"]
    count(non_flags) > 0
    source := non_flags[0]
}

is_wildcard_copy_multi(source) if {
    source in {".", "./", "*", "./*", "/*"}
}

# DF_BUILD_003: Use .dockerignore to exclude files
# Description: Create .dockerignore to exclude unnecessary files from build context.
# Severity: Medium
# Note: Rego cannot check for file existence, so this flags if no .dockerignore pattern is evident.
warn contains msg if {
    # If we see COPY . . it's highly recommended to use .dockerignore
    some i
    cmd := input[i]
    cmd.Cmd == "copy"
    some val in cmd.Value
    val in {".", "./"}
    
    msg := "[DF_BUILD_003][MEDIUM] Using wildcard COPY ('.'). Ensure a '.dockerignore' file exists to exclude sensitive files (.git, .env, etc.) from the build context."
}

has_log_rotation(logging) if {
    logging.options
    logging.options["max-size"]
}


