package main

import future.keywords.contains
import future.keywords.if

# ==============================================================================
# MULTISTAGE BUILD CHECKS - ENHANCED
# ==============================================================================

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
    is_wildcard_copy(source)
    
    msg := sprintf("[DF_MULTI_003][HIGH] In multistage builds, copy specific artifacts not entire directories. Found: COPY --from=... %s. Specify exact files to reduce final image size.", [source])
}

has_from_flag(values) if {
    some val in values
    startswith(val, "--from=")
}

has_from_flag(values) if {
    some i
    values[i] == "--from"
    # Next value should be the stage name
}

get_copy_source(values) := source if {
    # Find first non-flag value (the source path)
    non_flags := [v | some v in values; not startswith(v, "--"); v != "--from"]
    count(non_flags) > 0
    source := non_flags[0]
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
    source == "/*"
}
