package main

import future.keywords.contains
import future.keywords.if

# ==============================================================================
# USER & PERMISSION CHECKS - ENHANCED
# ==============================================================================

# DF_USER_001: Ensure that a user is switched to (at least one USER instruction)
# Enhanced: Handle multistage builds properly
deny contains msg if {
    not has_user_instruction
    not is_scratch_based
    msg := "[DF_USER_001][CRITICAL] Dockerfile must include at least one 'USER' instruction to run as non-root. Add: RUN adduser -D appuser && USER appuser"
}

has_user_instruction if {
    input[_].Cmd == "user"
}

is_scratch_based if {
    # Scratch images don't have users
    some i
    input[i].Cmd == "from"
    val := input[i].Value
    image := val[0]
    lower(image) == "scratch"
}

# DF_USER_002: Ensure that the final USER instruction is not root
# Enhanced: Better UID/GID handling and validation
deny contains msg if {
    user_cmds := [param | input[i]; input[i].Cmd == "user"; param := input[i].Value]
    count(user_cmds) > 0
    last_user_args := user_cmds[count(user_cmds) - 1]
    count(last_user_args) > 0
    user_spec := last_user_args[0]
    is_root(user_spec)
    msg := sprintf("[DF_USER_002][CRITICAL] The final USER instruction must not be 'root'. Found: '%s'. Use non-root user (e.g., USER appuser or USER 1000:1000).", [user_spec])
}

is_root(user) if {
    lower(user) == "root"
}

is_root(user) if {
    user == "0"
}

is_root(user) if {
    # UID:GID format where UID is 0
    startswith(user, "0:")
}

is_root(user) if {
    # root:GID format
    lower_user := lower(user)
    startswith(lower_user, "root:")
}

is_root(user) if {
    # :0 format (inherits UID, GID is 0)
    user == ":0"
}

is_root(user) if {
    # :root format
    lower_user := lower(user)
    user == ":root"
}

# DF_USER_003: Remove SUID and SGID bits from files
# Enhanced: Comprehensive SUID/SGID detection with numeric and symbolic modes
deny contains msg if {
    some i
    cmd := input[i]
    cmd.Cmd == "run"
    full_cmd := concat(" ", cmd.Value)
    has_suid_sgid(full_cmd)
    msg := sprintf("[DF_USER_003][HIGH] Remove SUID/SGID bits from binaries for security. Found in RUN: '%s'. SUID/SGID binaries can be exploited for privilege escalation.", [full_cmd])
}

has_suid_sgid(cmd_str) if {
    # Symbolic: chmod u+s (setuid)
    regex.match("chmod.*u\\+s", cmd_str)
}

has_suid_sgid(cmd_str) if {
    # Symbolic: chmod g+s (setgid)
    regex.match("chmod.*g\\+s", cmd_str)
}

has_suid_sgid(cmd_str) if {
    # Symbolic: chmod +s (both)
    regex.match("chmod.*\\+s", cmd_str)
}

has_suid_sgid(cmd_str) if {
    # Numeric: 4xxx (setuid)
    regex.match("chmod.*\\s+4[0-7]{3}", cmd_str)
}

has_suid_sgid(cmd_str) if {
    # Numeric: 2xxx (setgid)
    regex.match("chmod.*\\s+2[0-7]{3}", cmd_str)
}

has_suid_sgid(cmd_str) if {
    # Numeric: 6xxx (both setuid and setgid)
    regex.match("chmod.*\\s+6[0-7]{3}", cmd_str)
}

has_suid_sgid(cmd_str) if {
    # Numeric without space: chmod 4755
    regex.match("chmod\\s+[426][0-7]{3}\\s+", cmd_str)
}
