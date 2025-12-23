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

# DC_VOL_007: Use tmpfs for temporary storage
# Description: Mount tmpfs volumes for temporary files with restrictions.
# Severity: High
warn contains msg if {
    input.services
    some service_name, service_config in input.services
    
    # Check if tmpfs is used
    not service_config.tmpfs
    
    msg := sprintf("[DC_VOL_007][HIGH] Service '%s' does not use 'tmpfs'. Use tmpfs for temporary files (e.g., /tmp) to minimize disk I/O and improve security.", [service_name])
}

warn contains msg if {
    input.services
    some service_name, service_config in input.services
    service_config.tmpfs
    some tmpfs_path in service_config.tmpfs
    
    # Check for secure options if it's a list (some compose formats allow list or string)
    is_array(service_config.tmpfs)
    # This part is tricky as tmpfs in compose v2/v3 has different formats
    # Heuristic: just check existence for now as options parsing is complex
    
    msg := sprintf("[DC_VOL_007][INFO] Service '%s' uses tmpfs at '%s'. Ensure options 'noexec,nosuid,nodev' are set if possible.", [service_name, tmpfs_path])
}

# DC_VOL_001: Mount volumes with appropriate flags
# Description: Encourage using ':ro' flag for all volumes when write access is not required.
# Severity: High
warn contains msg if {
    input.services
    some service_name, service_config in input.services
    service_config.volumes
    some volume in service_config.volumes
    volume_str := sprintf("%v", [volume])
    
    # Not read-only
    not is_readonly_mount(volume_str)
    
    # Not already caught by more specific critical rules (002, 003, 004)
    not is_docker_socket_mount(volume_str)
    not is_root_filesystem_mount(volume_str)
    not is_sensitive_host_mount(volume_str)
    
    msg := sprintf("[DC_VOL_001][HIGH] Service '%s' mounts volume '%s' without ':ro' flag. Use read-only mounts where possible to follow least privilege.", [service_name, volume_str])
}

is_sensitive_host_mount(volume_str) if {
    some dangerous_path in dangerous_host_paths
    startswith(volume_str, dangerous_path)
}

# DC_VOL_006: Set volume ownership to non-root
# Description: Ensure volumes are owned by non-root user running application.
# Severity: High
warn contains msg if {
    input.services
    some service_name, service_config in input.services
    service_config.volumes
    some volume in service_config.volumes
    
    # If service runs as root (default), warn about volume ownership
    not service_config.user
    
    msg := sprintf("[DC_VOL_006][HIGH] Service '%s' mounts volumes but may be running as root (no 'user' specified). Root-owned volumes can cause permission issues for non-root processes.", [service_name])
}
