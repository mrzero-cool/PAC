# ==========================================
# DOCKERFILE WITH PASS AND FAIL CASES
# ==========================================

# [FAIL] DF_BASE_001: Using 'latest' tag
# [FAIL] DF_BASE_002: Not using a minimal image
FROM ubuntu:latest

# [PASS] Setting workdir is good practice
WORKDIR /app

# [FAIL] DF_SEC_001: Hardcoded secret (API Key)
ENV API_KEY=12345-abcde-secret-key

# [FAIL] DF_SEC_002: ARG with default secret value
ARG DB_PASSWORD=mysecretpassword

# [PASS] Valid COPY instruction
COPY . /app

# [FAIL] DF_SEC_004: Copying sensitive files
COPY .env /app/.env
COPY id_rsa /root/.ssh/id_rsa

# [FAIL] Common security best practice: Running as root (User not switched)
# Missing USER instruction

# [FAIL] DF_PKG_002 (Unpinned Version) & DF_PKG_006 (Dev Tool without cleanup)
RUN apt-get update && apt-get install -y curl

# [FAIL] Exposing SSH port typically flagged
EXPOSE 22

CMD ["/bin/bash"]
