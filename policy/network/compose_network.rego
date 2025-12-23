package main

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# ==============================================================================
# DOCKER COMPOSE - NETWORK CHECKS
# ==============================================================================

# Dangerous ports that should not be exposed
dangerous_ports := {
    "22", "23", "3389",  # SSH, Telnet, RDP
    "21", "20",           # FTP
    "25", "587", "465",   # SMTP
    "445", "139",         # SMB
    "3306", "5432",       # MySQL, PostgreSQL (direct exposure)
    "27017", "6379",      # MongoDB, Redis (direct exposure)
    "9200", "9300"        # Elasticsearch
}

# DC_NET_004: Do not expose port 22 (SSH)
# Specifically checks for SSH port exposure
deny contains msg if {
    input.services
    some service_name, service_config in input.services
    service_config.ports
    some port_mapping in service_config.ports
    port_str := sprintf("%v", [port_mapping])
    exposes_ssh_port(port_str)
    msg := sprintf("[DC_NET_004][HIGH] Service '%s' exposes SSH port 22. Port mapping: '%s'. Use 'docker compose exec' for container access instead.", [service_name, port_str])
}

exposes_ssh_port(port_str) if {
    # Direct mapping: "22:22"
    contains(port_str, "22:")
}

exposes_ssh_port(port_str) if {
    # Host port only: "22"
    startswith(port_str, "22")
    not contains(port_str, ":")
}

exposes_ssh_port(port_str) if {
    # Mapping to 22: "2222:22"
    regex.match(":\\s*22$", port_str)
}

# DC_NET_002: Do not expose unnecessary ports
# Checks for exposure of dangerous/management ports
deny contains msg if {
    input.services
    some service_name, service_config in input.services
    service_config.ports
    some port_mapping in service_config.ports
    port_str := sprintf("%v", [port_mapping])
    
    # Extract port number
    port_num := extract_port_number(port_str)
    port_num in dangerous_ports
    port_num != "22"  # Already handled by DC_NET_004
    
    msg := sprintf("[DC_NET_002][HIGH] Service '%s' exposes potentially dangerous port %s. Port mapping: '%s'. Only expose ports required for external access.", [service_name, port_num, port_str])
}

extract_port_number(port_str) := port if {
    # Format: "8080:80" -> extract first port (host port)
    contains(port_str, ":")
    parts := split(port_str, ":")
    port := parts[0]
}

extract_port_number(port_str) := port if {
    # Format: "80" -> single port
    not contains(port_str, ":")
    port := port_str
}

# DC_NET_005: Use network_mode carefully
# Warns against network_mode: host which disables network isolation
deny contains msg if {
    input.services
    some service_name, service_config in input.services
    service_config.network_mode
    network_mode := service_config.network_mode
    is_host_network(network_mode)
    msg := sprintf("[DC_NET_005][CRITICAL] Service '%s' uses 'network_mode: host' which disables network isolation. Use default bridge networking instead.", [service_name])
}

is_host_network(mode) if {
    lower(mode) == "host"
}

    mode_str := sprintf("%v", [mode])
    lower(mode_str) == "host"
}

# DC_NET_001: Define services on custom network
# Description: Define all services on custom 'networks' instead of using default bridge network.
# Severity: High
warn contains msg if {
    input.services
    some service_name, service_config in input.services
    
    # Check if networks are defined for the service
    not service_config.networks
    
    # And check if network_mode is not host/none (which don't use networks)
    not is_host_or_none_network(service_config)
    
    msg := sprintf("[DC_NET_001][HIGH] Service '%s' uses default bridge network (no 'networks' defined). Use custom user-defined networks for better isolation and DNS resolution.", [service_name])
}

is_host_or_none_network(service_config) if {
    service_config.network_mode
    lower(service_config.network_mode) == "host"
}

is_host_or_none_network(service_config) if {
    service_config.network_mode
    lower(service_config.network_mode) == "none"
}
