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

get_insecure_pattern(cmd_str) := result if {
    regex.match("chmod.*(777|0777)", cmd_str)
    result := "chmod 777"
}

get_insecure_pattern(cmd_str) := result if {
    not regex.match("chmod.*(777|0777)", cmd_str)
    regex.match("chmod.*(666|0666)", cmd_str)
    result := "chmod 666"
}

get_insecure_pattern(cmd_str) := result if {
    not regex.match("chmod.*(777|0777)", cmd_str)
    not regex.match("chmod.*(666|0666)", cmd_str)
    regex.match("chmod.*o\\+w", cmd_str)
    result := "chmod o+w"
}

get_insecure_pattern(cmd_str) := result if {
    not regex.match("chmod.*(777|0777)", cmd_str)
    not regex.match("chmod.*(666|0666)", cmd_str)
    not regex.match("chmod.*o\\+w", cmd_str)
    result := "chmod with insecure permissions"
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

# DF_PKG_002: Pin package versions explicitly
# Enhanced: Support for multiple package managers and better detection
deny contains msg if {
    some i
    cmd := input[i]
    cmd.Cmd == "run"
    full_cmd := concat(" ", cmd.Value)
    has_unpinned_packages(full_cmd)
    pkg_mgr := get_package_manager(full_cmd)
    msg := sprintf("[DF_PKG_002][HIGH] Pin package versions explicitly for %s. Found in RUN: '%s'. Example: apt-get install package=1.2.3 or apk add package=1.2.3-r0", [pkg_mgr, full_cmd])
}

has_unpinned_packages(cmd_str) if {
    # apt-get install without version pinning
    contains(cmd_str, "apt-get install")
    not contains(cmd_str, "=")
    # Exclude apt-get update, upgrade, etc.
    not contains(cmd_str, "update")
    not contains(cmd_str, "upgrade")
}

has_unpinned_packages(cmd_str) if {
    # apt install (without apt-get)
    regex.match("apt\\s+install", cmd_str)
    not contains(cmd_str, "=")
    not contains(cmd_str, "update")
    not contains(cmd_str, "upgrade")
}

has_unpinned_packages(cmd_str) if {
    # apk add without version pinning
    contains(cmd_str, "apk add")
    not contains(cmd_str, "=")
    # Exclude apk update
    not contains(cmd_str, "apk update")
}

has_unpinned_packages(cmd_str) if {
    # yum install without version pinning
    contains(cmd_str, "yum install")
    not contains(cmd_str, "-")  # yum uses package-version
    not contains(cmd_str, "yum update")
}

has_unpinned_packages(cmd_str) if {
    # dnf install without version pinning
    contains(cmd_str, "dnf install")
    not contains(cmd_str, "-")
    not contains(cmd_str, "dnf update")
}

has_unpinned_packages(cmd_str) if {
    # pip install without version pinning
    regex.match("pip3?\\s+install", cmd_str)
    not contains(cmd_str, "==")
    # Allow requirements.txt
    not contains(cmd_str, "requirements.txt")
    not contains(cmd_str, "-r ")
}

has_unpinned_packages(cmd_str) if {
    # npm install without version pinning
    contains(cmd_str, "npm install")
    not contains(cmd_str, "@")  # npm uses package@version
    # Allow package.json
    not contains(cmd_str, "package.json")
}

has_unpinned_packages(cmd_str) if {
    # gem install without version pinning
    contains(cmd_str, "gem install")
    not contains(cmd_str, "-v ")
    not contains(cmd_str, "--version")
}

get_package_manager(cmd_str) := result if {
    contains(cmd_str, "apt-get")
    result := "apt-get"
}

get_package_manager(cmd_str) := result if {
    not contains(cmd_str, "apt-get")
    regex.match("apt\\s+install", cmd_str)
    result := "apt"
}

get_package_manager(cmd_str) := result if {
    not contains(cmd_str, "apt-get")
    not regex.match("apt\\s+install", cmd_str)
    contains(cmd_str, "apk add")
    result := "apk"
}

get_package_manager(cmd_str) := result if {
    not contains(cmd_str, "apt-get")
    not regex.match("apt\\s+install", cmd_str)
    not contains(cmd_str, "apk add")
    contains(cmd_str, "yum install")
    result := "yum"
}

get_package_manager(cmd_str) := result if {
    not contains(cmd_str, "apt-get")
    not regex.match("apt\\s+install", cmd_str)
    not contains(cmd_str, "apk add")
    not contains(cmd_str, "yum install")
    contains(cmd_str, "dnf install")
    result := "dnf"
}

get_package_manager(cmd_str) := result if {
    not contains(cmd_str, "apt-get")
    not regex.match("apt\\s+install", cmd_str)
    not contains(cmd_str, "apk add")
    not contains(cmd_str, "yum install")
    not contains(cmd_str, "dnf install")
    regex.match("pip3?\\s+install", cmd_str)
    result := "pip"
}

get_package_manager(cmd_str) := result if {
    not contains(cmd_str, "apt-get")
    not regex.match("apt\\s+install", cmd_str)
    not contains(cmd_str, "apk add")
    not contains(cmd_str, "yum install")
    not contains(cmd_str, "dnf install")
    not regex.match("pip3?\\s+install", cmd_str)
    contains(cmd_str, "npm install")
    result := "npm"
}

get_package_manager(cmd_str) := result if {
    not contains(cmd_str, "apt-get")
    not regex.match("apt\\s+install", cmd_str)
    not contains(cmd_str, "apk add")
    not contains(cmd_str, "yum install")
    not contains(cmd_str, "dnf install")
    not regex.match("pip3?\\s+install", cmd_str)
    not contains(cmd_str, "npm install")
    contains(cmd_str, "gem install")
    result := "gem"
}

get_package_manager(cmd_str) := result if {
    not contains(cmd_str, "apt-get")
    not regex.match("apt\\s+install", cmd_str)
    not contains(cmd_str, "apk add")
    not contains(cmd_str, "yum install")
    not contains(cmd_str, "dnf install")
    not regex.match("pip3?\\s+install", cmd_str)
    not contains(cmd_str, "npm install")
    not contains(cmd_str, "gem install")
    result := "package manager"
}

# DF_PKG_006: Remove unnecessary packages
# Enhanced: Better dev tool detection with multistage build awareness
dev_tools := {
    "gcc", "g++", "make", "cmake", "automake", "autoconf",
    "git", "subversion", "mercurial",
    "vim", "nano", "emacs",
    "curl", "wget",
    "build-essential", "build-base",
    "python3-dev", "python-dev",
    "gcc-c++", "clang"
}

deny contains msg if {
    some i
    cmd := input[i]
    cmd.Cmd == "run"
    full_cmd := concat(" ", cmd.Value)
    
    some tool in dev_tools
    is_installing_dev_tool(full_cmd, tool)
    
    # Only flag if not properly cleaned up in same layer
    not is_properly_cleaned_up(full_cmd)
    
    msg := sprintf("[DF_PKG_006][HIGH] Remove development tools from production images or use multistage builds. Found: '%s' in RUN without cleanup.", [tool])
}

is_installing_dev_tool(cmd_str, tool) if {
    contains(cmd_str, "install")
    contains(cmd_str, tool)
}

is_properly_cleaned_up(cmd_str) if {
    # Command chains with && and removes packages
    contains(cmd_str, "&&")
    contains(cmd_str, "remove")
}

is_properly_cleaned_up(cmd_str) if {
    # Uses apk del
    contains(cmd_str, "&&")
    contains(cmd_str, "apk del")
}

is_properly_cleaned_up(cmd_str) if {
    # Uses apt-get remove/purge
    contains(cmd_str, "&&")
    regex.match(".*(apt-get|apt)\\s+(remove|purge)", cmd_str)
}

is_properly_cleaned_up(cmd_str) if {
    # Uses yum/dnf remove
    contains(cmd_str, "&&")
    regex.match(".*(yum|dnf)\\s+remove", cmd_str)
}

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

