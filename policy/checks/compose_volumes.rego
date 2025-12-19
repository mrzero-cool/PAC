package main

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# ==============================================================================
# DOCKER COMPOSE - VOLUME MOUNT CHECKS
# ==============================================================================

# DC_VOL_003: Do not mount Docker socket
# Mounting Docker socket grants full Docker daemon access
deny contains msg if {
    input.services
    some service_name, service_config in input.services
    service_config.volumes
    some volume in service_config.volumes
    volume_str := sprintf("%v", [volume])
    is_docker_socket_mount(volume_str)
    msg := sprintf("[DC_VOL_003][CRITICAL] Service '%s' mounts Docker socket. Volume: '%s'. This grants full Docker daemon access - remove this mount.", [service_name, volume_str])
}

is_docker_socket_mount(volume_str) if {
    contains(volume_str, "/var/run/docker.sock")
}

is_docker_socket_mount(volume_str) if {
    contains(volume_str, "docker.sock")
}

# DC_VOL_004: Do not mount host filesystem root
# Mounting host root allows complete host compromise
deny contains msg if {
    input.services
    some service_name, service_config in input.services
    service_config.volumes
    some volume in service_config.volumes
    volume_str := sprintf("%v", [volume])
    is_root_filesystem_mount(volume_str)
    msg := sprintf("[DC_VOL_004][CRITICAL] Service '%s' mounts host root filesystem. Volume: '%s'. This allows complete host compromise - never mount host root.", [service_name, volume_str])
}

is_root_filesystem_mount(volume_str) if {
    # Mount like "/:/host" or "/:/mnt"
    regex.match("^/:", volume_str)
}

is_root_filesystem_mount(volume_str) if {
    # Variations with spaces
    regex.match("^/\\s*:", volume_str)
}

# DC_VOL_002: Avoid mounting host directories with write access
# Checks for host mounts without :ro flag
dangerous_host_paths := {
    "/etc", "/bin", "/sbin", "/usr", "/lib", "/lib64",
    "/boot", "/sys", "/proc", "/dev", "/root", "/home"
}

deny contains msg if {
    input.services
    some service_name, service_config in input.services
    service_config.volumes
    some volume in service_config.volumes
    volume_str := sprintf("%v", [volume])
    
    # Check if it's a host mount (contains :)
    contains(volume_str, ":")
    
    # Not read-only
    not is_readonly_mount(volume_str)
    
    # Check if mounting dangerous paths
    some dangerous_path in dangerous_host_paths
    startswith(volume_str, dangerous_path)
    
    msg := sprintf("[DC_VOL_002][CRITICAL] Service '%s' mounts sensitive host directory with write access. Volume: '%s'. Use ':ro' flag for read-only access.", [service_name, volume_str])
}

# Additional check: any writable host mount should be flagged
deny contains msg if {
    input.services
    some service_name, service_config in input.services
    service_config.volumes
    some volume in service_config.volumes
    volume_str := sprintf("%v", [volume])
    
    # Is a host path mount (starts with / or ./)
    is_host_path_mount(volume_str)
    
    # Not read-only
    not is_readonly_mount(volume_str)
    
    # Not Docker socket (already caught by DC_VOL_003)
    not is_docker_socket_mount(volume_str)
    
    # Not root mount (already caught by DC_VOL_004)
    not is_root_filesystem_mount(volume_str)
    
    msg := sprintf("[DC_VOL_002][CRITICAL] Service '%s' mounts host directory with write access. Volume: '%s'. Consider using ':ro' flag to prevent host filesystem modification.", [service_name, volume_str])
}

is_host_path_mount(volume_str) if {
    # Absolute path mount
    startswith(volume_str, "/")
}

is_host_path_mount(volume_str) if {
    # Relative path mount
    startswith(volume_str, "./")
}

is_host_path_mount(volume_str) if {
    # Windows path mount
    regex.match("^[A-Za-z]:", volume_str)
}

is_readonly_mount(volume_str) if {
    endswith(volume_str, ":ro")
}

is_readonly_mount(volume_str) if {
    contains(volume_str, ":ro,")
}

is_readonly_mount(volume_str) if {
    # Long form with read_only option
    contains(volume_str, "read_only")
}
