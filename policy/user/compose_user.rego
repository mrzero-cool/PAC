package main

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# ==============================================================================
# DOCKER COMPOSE - USER & PRIVILEGE CHECKS
# ==============================================================================

# DC_USER_001: Run services as non-root user
# Ensures services specify a non-root user
deny contains msg if {
    input.services
    some service_name, service_config in input.services
    not service_config.user
    msg := sprintf("[DC_USER_001][CRITICAL] Service '%s' must run as non-root user. Add 'user: \"1000:1000\"' or similar non-root UID:GID.", [service_name])
}

deny contains msg if {
    input.services
    some service_name, service_config in input.services
    service_config.user
    user := service_config.user
    is_root_user(user)
    msg := sprintf("[DC_USER_001][CRITICAL] Service '%s' is running as root. User: '%s'. Use non-root user (e.g., user: \"1000:1000\").", [service_name, user])
}

is_root_user(user) if {
    # Handle both string and int types
    user_str := sprintf("%v", [user])
    lower(user_str) == "root"
}

is_root_user(user) if {
    user_str := sprintf("%v", [user])
    user_str == "0"
}

is_root_user(user) if {
    user_str := sprintf("%v", [user])
    startswith(user_str, "0:")
}

is_root_user(user) if {
    user_str := sprintf("%v", [user])
    lower_user := lower(user_str)
    startswith(lower_user, "root:")
}

# DC_USER_002: Do not use privileged mode
# Privileged mode disables all container isolation
deny contains msg if {
    input.services
    some service_name, service_config in input.services
    service_config.privileged == true
    msg := sprintf("[DC_USER_002][CRITICAL] Service '%s' must not use 'privileged: true'. This disables all isolation. Use specific capabilities instead.", [service_name])
}
