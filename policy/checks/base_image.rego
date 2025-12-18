package main

import future.keywords.contains
import future.keywords.if

# ==============================================================================
# BASE IMAGE CHECKS - ENHANCED
# ==============================================================================

# DF_BASE_001: Ensure base image does not use 'latest' tag
# Enhanced: Case-insensitive, handles edge cases like empty tags
deny contains msg if {
    some i
    input[i].Cmd == "from"
    val := input[i].Value
    image := val[0]
    
    # Skip AS aliases and platform specifiers
    not contains(image, "--")
    
    is_latest_or_no_tag(image)
    msg := sprintf("[DF_BASE_001][CRITICAL] Base image must not use 'latest' tag. Found: '%s'. Use specific version tags for reproducible builds.", [image])
}

is_latest_or_no_tag(image) if {
    # No tag at all (e.g., "ubuntu" without ":version")
    not contains(image, ":")
}
is_latest_or_no_tag(image) if {
    # Explicitly uses :latest (case-insensitive)
    lower_image := lower(image)
    endswith(lower_image, ":latest")
}
is_latest_or_no_tag(image) if {
    # Edge case: registry/image:latest
    parts := split(image, ":")
    count(parts) >= 2
    tag := parts[count(parts) - 1]
    lower(tag) == "latest"
}

# DF_BASE_002: Use minimal/hardened base images
# Enhanced: More comprehensive minimal image detection
minimal_images := {
    "alpine", "distroless", "scratch", "chainguard",
    "gcr.io/distroless", "cgr.dev/chainguard",
    "busybox", "static"
}

deny contains msg if {
    some i
    input[i].Cmd == "from"
    val := input[i].Value
    image := val[0]
    
    # Skip scratch (it's minimal but special case)
    not contains(lower(image), "scratch")
    
    # Only check non-AS names
    not contains(image, "--")
    
    not is_minimal_image(image)
    msg := sprintf("[DF_BASE_002][HIGH] Prefer minimal base images (alpine, distroless, scratch, chainguard). Found: '%s'. Reduces attack surface and image size.", [image])
}

is_minimal_image(image) if {
    lower_image := lower(image)
    some minimal in minimal_images
    contains(lower_image, minimal)
}

# DF_BASE_003: Ensure base image is from a trusted registry
# Enhanced: Comprehensive registry whitelist with organization support
allowed_registries := {
    # Docker Hub Official
    "docker.io/library", "library/",
    # Official base images (no prefix)
    "ubuntu", "alpine", "debian", "centos", "fedora", "archlinux",
    "node", "python", "golang", "java", "openjdk", "ruby", "php",
    "nginx", "httpd", "redis", "postgres", "mysql", "mongo",
    "elasticsearch", "rabbitmq", "memcached",
    # Cloud provider registries
    "gcr.io", "us.gcr.io", "eu.gcr.io", "asia.gcr.io",
    "mcr.microsoft.com", "k8s.gcr.io",
    "quay.io", "ghcr.io", "registry.gitlab.com",
    # Distroless and security-focused
    "gcr.io/distroless", "cgr.dev/chainguard",
    # Custom (configure this)
    "mycorp.registry.com", "registry.mycompany.com"
}

deny contains msg if {
    some i
    input[i].Cmd == "from"
    val := input[i].Value
    image := val[0]
    
    # Skip scratch (special case - no registry)
    lower_image := lower(image)
    not lower_image == "scratch"
    
    # Skip AS aliases and flags
    not contains(image, "--")
    
    not is_allowed_registry(image)
    msg := sprintf("[DF_BASE_003][CRITICAL] Base image must be from trusted registry. Found: '%s'. Use official or approved container registries only.", [image])
}

is_allowed_registry(image) if {
    lower_image := lower(image)
    some registry in allowed_registries
    lower_registry := lower(registry)
    startswith(lower_image, lower_registry)
}

is_allowed_registry(image) if {
    # Special case: Official Docker Hub images without prefix
    # e.g., "node:18" instead of "docker.io/library/node:18"
    not contains(image, "/")
    not contains(image, ".")
    
    # Check if it's a known official image
    image_name := split(image, ":")[0]
    lower_name := lower(image_name)
    
    official_images := {
        "ubuntu", "alpine", "debian", "centos", "fedora",
        "node", "python", "golang", "go", "java", "openjdk",
        "ruby", "php", "nginx", "httpd", "redis", "postgres",
        "mysql", "mongo", "busybox", "scratch"
    }
    
    lower_name in official_images
}

# DF_BASE_004: Use base image digest instead of tag
# Enhanced: Better digest detection and format validation
deny contains msg if {
    some i
    input[i].Cmd == "from"
    val := input[i].Value
    image := val[0]
    
    # Skip scratch
    lower_image := lower(image)
    not lower_image == "scratch"
    
    # Skip AS aliases
    not contains(image, "--")
    
    not has_digest(image)
    msg := sprintf("[DF_BASE_004][HIGH] Pin base image by SHA256 digest for immutability. Found: '%s'. Example: 'alpine:3.19@sha256:abc123...'", [image])
}

has_digest(image) if {
    contains(image, "@sha256:")
}

has_digest(image) if {
    # Support other digest algorithms if needed
    contains(image, "@sha384:")
}

has_digest(image) if {
    contains(image, "@sha512:")
}

# DF_BASE_005: Verify base image is maintained and updated
# Enhanced: Comprehensive deprecated/EOL image detection
deprecated_images := {
    # CentOS (EOL)
    "centos:6", "centos:7", "centos:8",
    # Ubuntu EOL
    "ubuntu:12.04", "ubuntu:14.04", "ubuntu:15", "ubuntu:16.04",
    "ubuntu:17", "ubuntu:18.10", "ubuntu:19",
    # Debian EOL
    "debian:squeeze", "debian:wheezy", "debian:jessie", "debian:stretch",
    # Node.js EOL
    "node:6", "node:7", "node:8", "node:9", "node:10", "node:11",
    "node:12", "node:13", "node:15", "node:17",
    # Python EOL
    "python:2.6", "python:2.7", "python:3.0", "python:3.1",
    "python:3.2", "python:3.3", "python:3.4", "python:3.5", "python:3.6",
    # Alpine very old
    "alpine:2", "alpine:3.0", "alpine:3.1", "alpine:3.2", "alpine:3.3",
    "alpine:3.4", "alpine:3.5", "alpine:3.6", "alpine:3.7", "alpine:3.8",
    # Others
    "amazonlinux:1", "oraclelinux:6", "busybox:1.28"
}

deny contains msg if {
    some i
    input[i].Cmd == "from"
    val := input[i].Value
    image := val[0]
    
    # Extract base without digest
    base_image := split(image, "@")[0]
    
    is_deprecated_image(base_image)
    msg := sprintf("[DF_BASE_005][HIGH] Base image is deprecated or unmaintained (EOL). Found: '%s'. Use actively maintained versions.", [base_image])
}

is_deprecated_image(image) if {
    lower_image := lower(image)
    some deprecated in deprecated_images
    lower_deprecated := lower(deprecated)
    
    # Exact match or starts with (for flexibility)
    startswith(lower_image, lower_deprecated)
}

is_deprecated_image(image) if {
    # Pattern matching for version ranges
    lower_image := lower(image)
    
    # CentOS 6.x or 7.x
    regex.match("centos:[67]", lower_image)
}

is_deprecated_image(image) if {
    lower_image := lower(image)
    
    # Python 2.x
    regex.match("python:2\\.", lower_image)
}
