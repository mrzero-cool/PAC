package main

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# ==============================================================================
# PACKAGE MANAGEMENT CHECKS - ENHANCED
# ==============================================================================

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

get_package_manager(cmd_str) := "apt-get" if {
    contains(cmd_str, "apt-get")
}

get_package_manager(cmd_str) := "apt" if {
    regex.match("apt\\s+install", cmd_str)
}

get_package_manager(cmd_str) := "apk" if {
    contains(cmd_str, "apk add")
}

get_package_manager(cmd_str) := "yum" if {
    contains(cmd_str, "yum install")
}

get_package_manager(cmd_str) := "dnf" if {
    contains(cmd_str, "dnf install")
}

get_package_manager(cmd_str) := "pip" if {
    regex.match("pip3?\\s+install", cmd_str)
}

get_package_manager(cmd_str) := "npm" if {
    contains(cmd_str, "npm install")
}

get_package_manager(cmd_str) := "gem" if {
    contains(cmd_str, "gem install")
}

get_package_manager(cmd_str) := "package manager" if {
    true  # Fallback
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

