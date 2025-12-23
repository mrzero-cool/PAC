package main

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# ==============================================================================
# DOCKER COMPOSE - ENVIRONMENT & SECRETS CHECKS
# ==============================================================================

# Secret-like environment variable patterns
secret_env_patterns := {
    "password", "passwd", "pwd", "secret", "token", "api_key",
    "apikey", "access_key", "accesskey", "private_key", "privatekey",
    "credential", "auth", "bearer", "certificate", "cert"
}

# DC_ENV_001: Do not use environment variables for secrets
# Checks for hardcoded secrets in environment section
deny contains msg if {
    input.services
    some service_name, service_config in input.services
    service_config.environment
    
    # Handle both array and object formats
    msg := get_secret_env_error(service_name, service_config.environment)
}

# For object-style environment (key: value)
get_secret_env_error(service_name, env_obj) := msg if {
    is_object(env_obj)
    some key, value in env_obj
    lower_key := lower(key)
    is_secret_key_pattern(lower_key)
    
    # Check if value is actually set (not just referencing external)
    value_str := sprintf("%v", [value])
    not is_external_reference(value_str)
    
    msg := sprintf("[DC_ENV_001][CRITICAL] Service '%s' has hardcoded secret in environment. Key: '%s'. Use Docker secrets or external secret management instead.", [service_name, key])
}

# For array-style environment (["KEY=value"])
get_secret_env_error(service_name, env_array) := msg if {
    is_array(env_array)
    some env_entry in env_array
    entry_str := sprintf("%v", [env_entry])
    contains(entry_str, "=")
    parts := split(entry_str, "=")
    key := parts[0]
    lower_key := lower(key)
    is_secret_key_pattern(lower_key)
    
    # Has a value set
    count(parts) > 1
    value := parts[1]
    value != ""
    not is_external_reference(value)
    
    msg := sprintf("[DC_ENV_001][CRITICAL] Service '%s' has hardcoded secret in environment. Entry: '%s'. Use Docker secrets or external secret management instead.", [service_name, env_entry])
}

is_secret_key_pattern(lower_key) if {
    some pattern in secret_env_patterns
    contains(lower_key, pattern)
}

is_external_reference(value_str) if {
    # Checks if value references external source
    startswith(value_str, "$")
}

is_external_reference(value_str) if {
    startswith(value_str, "${")
}

# DC_ENV_003: Do not commit .env files to version control
# Checks if .env files are explicitly referenced in compose file
deny contains msg if {
    input.services
    some service_name, service_config in input.services
    service_config.env_file
    
    # Check env_file references (handles both string and array)
    env_files := cast_to_array(service_config.env_file)
    some env_file_entry in env_files
    
    env_file_str := sprintf("%v", [env_file_entry])
    contains(env_file_str, ".env")
    
    msg := sprintf("[DC_ENV_003][CRITICAL] Service '%s' references .env file: '%s'. Ensure .env files are in .gitignore and never committed to version control.", [service_name, env_file_str])
}

cast_to_array(x) := x if {
    is_array(x)
}
cast_to_array(x) := [x] if {
    is_string(x)
}

# DC_LOG_003: Do not log sensitive information
# This check is limited - can only detect obvious logging configuration issues
# Cannot detect application-level logging without runtime analysis
deny contains msg if {
    input.services
    some service_name, service_config in input.services
    service_config.logging
    service_config.logging.options
    
    # Check if logging options might expose sensitive data
    some key, value in service_config.logging.options
    lower_key := lower(key)
    value_str := sprintf("%v", [value])
    
    # Check for environment variable logging
    contains(lower_key, "env")
    contains(lower_key, "log")
    
    msg := sprintf("[DC_LOG_003][CRITICAL] Service '%s' may log environment variables. Logging config: '%s: %s'. Ensure sensitive data is not logged.", [service_name, key, value_str])
}

# Additional check: warn if service has both secrets and verbose logging
    msg := sprintf("[DC_LOG_003][CRITICAL] Service '%s' uses debug logging which may expose sensitive information. Review logging configuration.", [service_name])
}

# DC_ENV_002: Use .env file for non-secret configuration
# Description: Use .env file for non-secret configuration.
# Severity: High
warn contains msg if {
    input.services
    some service_name, service_config in input.services
    
    # If using environment variables in compose file directly (array or object)
    service_config.environment
    count(service_config.environment) > 5
    
    # And not using env_file
    not service_config.env_file
    
    msg := sprintf("[DC_ENV_002][HIGH] Service '%s' has many environment variables defined inline. Consider moving non-secret config to '.env' file for better management.", [service_name])
}

# DC_SEC_MAN_001: Use Docker Secrets for sensitive data
# Description: Use 'secrets' section for sensitive data instead of environment variables.
# Severity: High
warn contains msg if {
    input.services
    some service_name, service_config in input.services
    
    # Check if secrets are used
    not service_config.secrets
    
    # Only warn if there seem to be sensitive env vars (checked by DC_ENV_001 generally, but this is specific guidance)
    has_potential_secrets_in_env(service_config)
    
    msg := sprintf("[DC_SEC_MAN_001][HIGH] Service '%s' contains potential secrets in environment but does not use Docker Secrets. Use top-level 'secrets' for sensitive data.", [service_name])
}

has_potential_secrets_in_env(service_config) if {
    service_config.environment
    # Reuse previous logic or simplified check
    is_object(service_config.environment)
    some key, _ in service_config.environment
    is_secret_key_pattern(lower(key))
}

has_potential_secrets_in_env(service_config) if {
    service_config.environment
    is_array(service_config.environment)
    some entry in service_config.environment
    contains(lower(entry), "secret")
}
