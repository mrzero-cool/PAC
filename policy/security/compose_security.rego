package main

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# ==============================================================================
# DOCKER COMPOSE - SECURITY OPTIONS & CAPABILITIES
# ==============================================================================

# DC_SEC_001: Disable privilege escalation
# Ensures security_opt includes no-new-privileges:true
deny contains msg if {
    input.services
    some service_name, service_config in input.services
    not has_no_new_privileges(service_config)
    msg := sprintf("[DC_SEC_001][HIGH] Service '%s' should set 'security_opt: [\"no-new-privileges:true\"]' to prevent privilege escalation.", [service_name])
}

has_no_new_privileges(service_config) if {
    service_config.security_opt
    some opt in service_config.security_opt
    opt == "no-new-privileges:true"
}

has_no_new_privileges(service_config) if {
    service_config.security_opt
    some opt in service_config.security_opt
    contains(opt, "no-new-privileges")
}

# DC_SEC_002: Drop all unnecessary capabilities
# Ensures cap_drop: [ALL] is set
deny contains msg if {
    input.services
    some service_name, service_config in input.services
    not has_cap_drop_all(service_config)
    msg := sprintf("[DC_SEC_002][CRITICAL] Service '%s' must drop all capabilities with 'cap_drop: [\"ALL\"]' and add back only required ones.", [service_name])
}

has_cap_drop_all(service_config) if {
    service_config.cap_drop
    some cap in service_config.cap_drop
    upper(cap) == "ALL"
}

# DC_SEC_003: Only add required capabilities
# Warns about potentially dangerous capabilities
dangerous_capabilities := {
    "SYS_ADMIN", "SYS_MODULE", "SYS_RAWIO", "SYS_PTRACE",
    "SYS_BOOT", "MAC_ADMIN", "MAC_OVERRIDE", "NET_ADMIN",
    "DAC_OVERRIDE", "DAC_READ_SEARCH", "SETUID", "SETGID",
    "SYS_TIME", "AUDIT_CONTROL", "AUDIT_WRITE"
}

deny contains msg if {
    input.services
    some service_name, service_config in input.services
    service_config.cap_add
    some cap in service_config.cap_add
    upper_cap := upper(cap)
    upper_cap in dangerous_capabilities
    msg := sprintf("[DC_SEC_003][CRITICAL] Service '%s' adds dangerous capability '%s'. Only add specific required capabilities (e.g., NET_BIND_SERVICE, CHOWN).", [service_name, cap])
}

# Additional check: too many capabilities added
deny contains msg if {
    input.services
    some service_name, service_config in input.services
    service_config.cap_add
    count(service_config.cap_add) > 3
    caps := concat(", ", service_config.cap_add)
    msg := sprintf("[DC_SEC_003][CRITICAL] Service '%s' adds too many capabilities (%d). Found: [%s]. Only add minimal required capabilities.", [service_name, count(service_config.cap_add), caps])
}
