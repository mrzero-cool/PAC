package main

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# ==============================================================================
# COMPOSE IMAGE CHECKS
# ==============================================================================

# DC_IMG_001: Use specific image version tags
# Description: Always specify explicit image version tags instead of 'latest' or no tag.
# Severity: Critical
deny contains msg if {
    some service_name, service_config in input.services
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

# DC_IMG_002: Use image pull policy Always for base images
# Description: Ensure images are pulled from registry each time for latest updates.
# Severity: High
warn contains msg if {
    some service_name, service_config in input.services
    # Check if pull_policy is missing or not set to 'always'
    not is_pull_policy_always(service_config)
    msg := sprintf("[DC_IMG_002][HIGH] Service '%s' does not specify 'pull_policy: always'. Recommended to ensure latest security patches are pulled.", [service_name])
}

is_pull_policy_always(service_config) if {
    lower(service_config.pull_policy) == "always"
}
