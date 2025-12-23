package main

import future.keywords.contains
import future.keywords.if

# Common helper functions used across multiple checks

# Check if command is ENV or ARG
is_env_or_arg(cmd) if {
    cmd == "env"
}
is_env_or_arg(cmd) if {
    cmd == "arg"
}

# Check if command is COPY or ADD
is_copy_or_add(cmd) if {
    cmd == "copy"
}
is_copy_or_add(cmd) if {
    cmd == "add"
}

# Check if command is CMD or ENTRYPOINT
is_cmd_or_entrypoint(cmd) if {
    cmd == "cmd"
}
is_cmd_or_entrypoint(cmd) if {
    cmd == "entrypoint"
}

# Check if key name indicates a secret
is_secret_key(key) if {
    contains(lower(key), "password")
}
is_secret_key(key) if {
    contains(lower(key), "secret")
}
is_secret_key(key) if {
    contains(lower(key), "token")
}
is_secret_key(key) if {
    contains(lower(key), "api_key")
}
is_secret_key(key) if {
    contains(lower(key), "access_key")
}

# Check if user is root
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
    startswith(lower(user), "root:")
}

is_root(user) if {
    # :0 format (inherits UID, GID is 0)
    user == ":0"
}

is_root(user) if {
    # :root format
    lower(user) == ":root"
}

# Helper to get minimum
min(a, b) := a if {
    a < b
} else := b
