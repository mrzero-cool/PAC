package main

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# ==============================================================================
# COMMAND CHECKS (CMD/ENTRYPOINT) - ENHANCED
# ==============================================================================

# DF_CMD_002: Use exec form not shell form
# Enhanced: Better detection of shell vs exec form with fewer false positives
deny contains msg if {
    some i
    cmd := input[i]
    is_cmd_or_entrypoint(cmd.Cmd)
    count(cmd.Value) == 1
    value := cmd.Value[0]
    is_shell_form(value)
    msg := sprintf("[DF_CMD_002][HIGH] Use exec form [\"cmd\", \"arg\"] instead of shell form for %s. Found: %s. Shell form enables shell injection attacks.", [upper(cmd.Cmd), value])
}

is_shell_form(value) if {
    # Shell form typically contains spaces (e.g., "python app.py")
    # Exec form with single arg like ["python3"] won't have spaces
    contains(value, " ")
}

is_shell_form(value) if {
    # Shell form with shell constructs
    contains(value, "&&")
}

is_shell_form(value) if {
    contains(value, "||")
}

is_shell_form(value) if {
    contains(value, "|")
}

is_shell_form(value) if {
    # Variable expansion indicates shell form
    contains(value, "$")
}

is_shell_form(value) if {
    # Script invocation
    regex.match(".*/bin/(ba)?sh\\s+-c", value)
}

# DF_CMD_003: Do not use sudo in container
# Enhanced: Comprehensive sudo detection including su and doas
deny contains msg if {
    some i
    cmd := input[i]
    cmd.Cmd == "run"
    full_cmd := concat(" ", cmd.Value)
    uses_sudo(full_cmd)
    msg := sprintf("[DF_CMD_003][HIGH] Do not use sudo/su in containers. Found in RUN: '%s'. Run commands directly as the appropriate user with USER instruction.", [full_cmd])
}

uses_sudo(cmd_str) if {
    # sudo command
    regex.match("(^|\\s)sudo\\s+", cmd_str)
}

uses_sudo(cmd_str) if {
    # su command (except 'su -' in proper user switching context)
    regex.match("(^|\\s)su\\s+", cmd_str)
    not contains(cmd_str, "su -")
}

uses_sudo(cmd_str) if {
    # doas (OpenBSD sudo alternative)
    regex.match("(^|\\s)doas\\s+", cmd_str)
}

uses_sudo(cmd_str) if {
    # sudo with options
    regex.match("sudo\\s+-[a-zA-Z]+", cmd_str)
}

# DF_CMD_004: Minimize running as root
# Enhanced: Smarter detection of unnecessary root operations
deny contains msg if {
    some i
    cmd := input[i]
    cmd.Cmd == "run"
    full_cmd := concat(" ", cmd.Value)
    requires_root_unnecessarily(full_cmd)
    operation := get_root_operation(full_cmd)
    msg := sprintf("[DF_CMD_004][HIGH] Minimize commands run as root. Consider if this needs root: '%s'. Run as non-root user when possible.", [operation])
}

requires_root_unnecessarily(cmd_str) if {
    # World-writable chmod (doesn't need root)
    regex.match("chmod\\s+(777|666)", cmd_str)
}

requires_root_unnecessarily(cmd_str) if {
    # Changing ownership to root (usually unnecessary)
    regex.match("chown\\s+root:", cmd_str)
}

requires_root_unnecessarily(cmd_str) if {
    # chown to root:root
    contains(cmd_str, "chown root:root")
}

requires_root_unnecessarily(cmd_str) if {
    # chown to 0:0
    regex.match("chown\\s+0:0", cmd_str)
}

get_root_operation(cmd_str) := "chmod 777" if {
    contains(cmd_str, "chmod 777")
} else := "chown root" if {
    contains(cmd_str, "chown root")
} else := operation if {
    operation := substring(cmd_str, 0, min(50, count(cmd_str)))
}



