package main

import future.keywords.contains
import future.keywords.if

# ==============================================================================
# FILESYSTEM CHECKS - ENHANCED
# ==============================================================================

# DF_FS_003: Set appropriate WORKDIR ownership
# Enhanced: Better detection with multistage awareness
deny contains msg if {
    has_workdir
    not has_workdir_chown
    not is_scratch_image
    msg := "[DF_FS_003][HIGH] Set WORKDIR ownership to non-root user with chown. Add: RUN chown -R appuser:appuser /app after WORKDIR."
}

has_workdir if {
    input[_].Cmd == "workdir"
}

has_workdir_chown if {
    some i
    cmd := input[i]
    cmd.Cmd == "run"
    full_cmd := concat(" ", cmd.Value)
    
    # Has chown command
    contains(full_cmd, "chown")
    
    # Not changing to root
    not contains(full_cmd, "chown root")
    not regex.match("chown\\s+0:", full_cmd)
}

has_workdir_chown if {
    # COPY --chown also satisfies this
    some i
    cmd := input[i]
    cmd.Cmd == "copy"
    some val in cmd.Value
    contains(val, "--chown")
    not contains(val, "root")
}

is_scratch_image if {
    some i
    input[i].Cmd == "from"
    val := input[i].Value
    image := val[0]
    lower(image) == "scratch"
}
