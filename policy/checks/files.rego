package main

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# ==============================================================================
# FILE OPERATION CHECKS - ENHANCED
# ==============================================================================

# DF_FILE_002: Explicitly COPY required files only
# Enhanced: Better wildcard detection and multistage awareness
deny contains msg if {
    some i
    cmd := input[i]
    cmd.Cmd == "copy"
    count(cmd.Value) > 0
    
    # Filter out flags
    non_flag_values := [v | some v in cmd.Value; not startswith(v, "--")]
    count(non_flag_values) > 0
    
    source := non_flag_values[0]
    is_wildcard_copy(source)
    
    msg := sprintf("[DF_FILE_002][HIGH] Copy only required files, not entire directories. Found: COPY %s. Use specific file patterns instead.", [source])
}

is_wildcard_copy(source) if {
    source == "."
}

is_wildcard_copy(source) if {
    source == "./"
}

is_wildcard_copy(source) if {
    source == "*"
}

is_wildcard_copy(source) if {
    source == "./*"
}

is_wildcard_copy(source) if {
    # Dot with any path separator
    regex.match("^\\.$", source)
}

# DF_FILE_003: Set appropriate file permissions
# Enhanced: Comprehensive insecure permission detection
deny contains msg if {
    some i
    cmd := input[i]
    cmd.Cmd == "run"
    full_cmd := concat(" ", cmd.Value)
    has_insecure_chmod(full_cmd)
    insecure_pattern := get_insecure_pattern(full_cmd)
    msg := sprintf("[DF_FILE_003][HIGH] Avoid insecure permissions. Found: '%s' in RUN. Use restrictive permissions (e.g., 755 for directories, 644 for files).", [insecure_pattern])
}

has_insecure_chmod(cmd_str) if {
    # World-writable: 777
    contains(cmd_str, "chmod")
    regex.match("chmod.*(777|0777)", cmd_str)
}

has_insecure_chmod(cmd_str) if {
    # World-writable files: 666
    contains(cmd_str, "chmod")
    regex.match("chmod.*(666|0666)", cmd_str)
}

has_insecure_chmod(cmd_str) if {
    # Symbolic: o+w (others write)
    contains(cmd_str, "chmod")
    regex.match("chmod.*o\\+w", cmd_str)
}

has_insecure_chmod(cmd_str) if {
    # Symbolic: a+w (all write)
    contains(cmd_str, "chmod")
    regex.match("chmod.*a\\+w", cmd_str)
}

has_insecure_chmod(cmd_str) if {
    # Too permissive: 7xx across the board
    contains(cmd_str, "chmod")
    regex.match("chmod.*\\s+7[0-7]{2}", cmd_str)
    # Exclude 755 and 750 which are common and acceptable
    not regex.match("chmod.*(755|750)", cmd_str)
}

get_insecure_pattern(cmd_str) := pattern if {
    regex.match("chmod.*(777|0777)", cmd_str)
    pattern := "chmod 777"
}

get_insecure_pattern(cmd_str) := pattern if {
    regex.match("chmod.*(666|0666)", cmd_str)
    pattern := "chmod 666"
}

get_insecure_pattern(cmd_str) := pattern if {
    regex.match("chmod.*o\\+w", cmd_str)
    pattern := "chmod o+w"
}

get_insecure_pattern(cmd_str) := "chmod with insecure permissions" if {
    true  # Fallback
}

# DF_FILE_004: Avoid curl | bash / wget | sh patterns
# Enhanced: Comprehensive pipe-to-shell detection with more variations
deny contains msg if {
    some i
    cmd := input[i]
    cmd.Cmd == "run"
    full_cmd := concat(" ", cmd.Value)
    is_pipe_to_shell(full_cmd)
    msg := sprintf("[DF_FILE_004][CRITICAL] Avoid piping downloads to shell interpreters. Found in RUN: '%s'. Download, verify, then execute separately.", [full_cmd])
}

is_pipe_to_shell(cmd_str) if {
    # curl/wget piped to bash/sh/zsh
    regex.match("(curl|wget).+\\|.*(bash|sh|zsh)", cmd_str)
}

is_pipe_to_shell(cmd_str) if {
    # curl/wget piped to any shell
    regex.match("(curl|wget).+\\|\\s*(sudo\\s+)?(bash|sh|zsh|fish|ksh)", cmd_str)
}

is_pipe_to_shell(cmd_str) if {
    # Variations with output redirection
    regex.match("(curl|wget).+\\|\\s*\\$\\(.*\\)", cmd_str)
}

is_pipe_to_shell(cmd_str) if {
    # Direct to interpreter: curl url | sh
    regex.match("(curl|wget).*\\|\\s*sh\\b", cmd_str)
}

is_pipe_to_shell(cmd_str) if {
    # With xargs
    regex.match("(curl|wget).+\\|\\s*xargs.*(bash|sh)", cmd_str)
}

