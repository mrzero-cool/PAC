package main

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# ==============================================================================
# SECURITY & SECRETS CHECKS - ENHANCED
# ==============================================================================

# DF_SEC_001: Do not hardcode secrets in Dockerfile
# Enhanced: Expanded secret detection patterns and value inspection
deny contains msg if {
    some i
    cmd := input[i]
    is_env_or_arg(cmd.Cmd)
    count(cmd.Value) > 0
    key := cmd.Value[0] 
    is_secret_key(key)
    msg := sprintf("[DF_SEC_001][CRITICAL] Hardcoded secret detected in %s instruction. Key: '%s'. Use Docker secrets, build args without defaults, or environment injection at runtime.", [upper(cmd.Cmd), key])
}

is_secret_key(key) if {
    lower_key := lower(key)
    contains(lower_key, "password")
}

is_secret_key(key) if {
    lower_key := lower(key)
    contains(lower_key, "passwd")
}

is_secret_key(key) if {
    lower_key := lower(key)
    contains(lower_key, "secret")
}

is_secret_key(key) if {
    lower_key := lower(key)
    contains(lower_key, "token")
}

is_secret_key(key) if {
    lower_key := lower(key)
    contains(lower_key, "api_key")
}

is_secret_key(key) if {
    lower_key := lower(key)
    contains(lower_key, "apikey")
}

is_secret_key(key) if {
    lower_key := lower(key)
    contains(lower_key, "access_key")
}

is_secret_key(key) if {
    lower_key := lower(key)
    contains(lower_key, "accesskey")
}

is_secret_key(key) if {
    lower_key := lower(key)
    contains(lower_key, "private_key")
}

is_secret_key(key) if {
    lower_key := lower(key)
    contains(lower_key, "privatekey")
}

is_secret_key(key) if {
    lower_key := lower(key)
    contains(lower_key, "credential")
}

is_secret_key(key) if {
    lower_key := lower(key)
    contains(lower_key, "auth")
}

is_secret_key(key) if {
    lower_key := lower(key)
    regex.match(".*_pwd$", lower_key)
}

is_secret_key(key) if {
    lower_key := lower(key)
    regex.match(".*_pass$", lower_key)
}

# DF_SEC_002: Do not pass secrets via build ARG
# Enhanced: Better default value detection and secret pattern matching
deny contains msg if {
    some i
    cmd := input[i]
    cmd.Cmd == "arg"
    count(cmd.Value) > 0
    has_default_value(cmd.Value)
    key := get_key(cmd.Value)
    is_secret_key(key)
    msg := sprintf("[DF_SEC_002][CRITICAL] Do not pass secrets via build ARG with default values. Key: '%s'. ARG values are visible in image history. Use --secret mount or runtime injection.", [key])
}

has_default_value(val_arr) if {
    # Multiple values means there's a default: ARG NAME VALUE
    count(val_arr) > 1
}

has_default_value(val_arr) if {
    # Single value with = means default: ARG NAME=VALUE
    count(val_arr) == 1
    contains(val_arr[0], "=")
}

get_key(val_arr) := key if {
    count(val_arr) > 1
    # First element is the key
    key := val_arr[0]
}

get_key(val_arr) := key if {
    count(val_arr) == 1
    contains(val_arr[0], "=")
    parts := split(val_arr[0], "=")
    key := parts[0]
}

get_key(val_arr) := key if {
    count(val_arr) == 1
    not contains(val_arr[0], "=")
    # Just the key name
    key := val_arr[0]
}

# DF_SEC_004: Do not commit .env or secrets files (COPY/ADD)
# Enhanced: Comprehensive sensitive file pattern detection
deny contains msg if {
    some i
    cmd := input[i]
    is_copy_or_add(cmd.Cmd)
    count(cmd.Value) > 1
    
    # Get all source files (everything except last which is destination)
    sources := array.slice(cmd.Value, 0, count(cmd.Value) - 1)
    
    # Filter out flags like --from, --chown
    non_flag_sources := [s | some s in sources; not startswith(s, "--")]
    
    count(non_flag_sources) > 0
    some source in non_flag_sources
    is_sensitive_file(source)
    msg := sprintf("[DF_SEC_004][CRITICAL] Do not copy sensitive files into the image. Found: '%s'. Add to .dockerignore or use BuildKit secrets.", [source])
}

is_sensitive_file(filename) if {
    lower_name := lower(filename)
    endswith(lower_name, ".env")
}

is_sensitive_file(filename) if {
    lower_name := lower(filename)
    endswith(lower_name, ".env.local")
}

is_sensitive_file(filename) if {
    lower_name := lower(filename)
    endswith(lower_name, ".env.production")
}

is_sensitive_file(filename) if {
    lower_name := lower(filename)
    contains(lower_name, ".aws")
}

is_sensitive_file(filename) if {
    lower_name := lower(filename)
    contains(lower_name, ".ssh")
}

is_sensitive_file(filename) if {
    lower_name := lower(filename)
    contains(lower_name, "id_rsa")
}

is_sensitive_file(filename) if {
    lower_name := lower(filename)
    contains(lower_name, "id_dsa")
}

is_sensitive_file(filename) if {  
    lower_name := lower(filename)
    contains(lower_name, "id_ecdsa")
}

is_sensitive_file(filename) if {
    lower_name := lower(filename)
    endswith(lower_name, ".pem")
}

is_sensitive_file(filename) if {
    lower_name := lower(filename)
    endswith(lower_name, ".key")
}

is_sensitive_file(filename) if {
    lower_name := lower(filename)
    endswith(lower_name, ".p12")
}

is_sensitive_file(filename) if {
    lower_name := lower(filename)
    endswith(lower_name, ".pfx")
}

is_sensitive_file(filename) if {
    lower_name := lower(filename)
    contains(lower_name, "credentials")
}

is_sensitive_file(filename) if {
    lower_name := lower(filename)
    endswith(lower_name, ".gpg")
}

is_sensitive_file(filename) if {
    lower_name := lower(filename)
    contains(lower_name, "kubeconfig")
}


# DF_SEC_003: Use Docker BuildKit secrets mount
# Description: Use --secret flag with BuildKit to mount secrets during build without storing them in image.
# Severity: High
warn contains msg if {
    some i
    cmd := input[i]
    is_secret_consuming_cmd(cmd)
    
    # Check if a secret is potentially being passed as ARG or ENV (already covered by 001/002)
    # This check specifically encourages using --mount=type=secret
    not uses_secret_mount(cmd)
    
    # Heuristic: if we see pattern like "COPY secret /run/secrets/" or similar usage without mount
    uses_local_secret_copy(cmd)
    
    msg := sprintf("[DF_SEC_003][HIGH] Use BuildKit secrets mount instead of COPY for sensitive files. Found in %s: '%s'. Use run --mount=type=secret...", [upper(cmd.Cmd), cmd.Value[0]])
}

is_secret_consuming_cmd(cmd) if {
    cmd.Cmd == "run"
}

is_secret_consuming_cmd(cmd) if {
    cmd.Cmd == "copy"
}

uses_secret_mount(cmd) if {
    some val in cmd.Value
    contains(val, "--mount=type=secret")
}

uses_local_secret_copy(cmd) if {
    cmd.Cmd == "copy"
    count(cmd.Value) > 0
    source := cmd.Value[0]
    is_sensitive_file(source)
}

