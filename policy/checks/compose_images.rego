package main

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# ==============================================================================
# DOCKER COMPOSE - IMAGE CHECKS
# ==============================================================================

# DC_IMG_001: Use specific image version tags
# Ensures all services use specific version tags instead of 'latest'
deny contains msg if {
    input.services
    some service_name, service_config in input.services
    service_config.image
    image := service_config.image
    is_latest_or_no_tag_compose(image)
    msg := sprintf("[DC_IMG_001][CRITICAL] Service '%s' must use specific image version tag, not 'latest'. Found: '%s'. Use versioned tags for reproducible deployments.", [service_name, image])
}

is_latest_or_no_tag_compose(image) if {
    # No tag at all (e.g., "nginx" without ":version")
    not contains(image, ":")
}

is_latest_or_no_tag_compose(image) if {
    # Explicitly uses :latest (case-insensitive)
    lower_image := lower(image)
    endswith(lower_image, ":latest")
}

is_latest_or_no_tag_compose(image) if {
    # Edge case: registry/image:latest
    parts := split(image, ":")
    count(parts) >= 2
    tag := parts[count(parts) - 1]
    lower(tag) == "latest"
}
