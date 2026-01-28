# ==========================================
# 1. Build AMD Verifier
# ==========================================
FROM rust:1.88-slim-bookworm AS amd-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    perl \
    make \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY verifiers/amd .

WORKDIR /build/amd-verifier
RUN cargo build --release

# ==========================================
# 2. Build Intel Attester
# ==========================================
FROM ubuntu:22.04 AS intel-builder

ARG SDK_VERSION=2.25
ARG SGX_VERSION=2.25.100.3
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl gpg ca-certificates build-essential make pkg-config

RUN curl -fsSL https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | gpg --dearmor -o /usr/share/keyrings/intel-sgx-deb.gpg \
    && echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/intel-sgx-deb.gpg] https://download.01.org/intel-sgx/sgx_repo/ubuntu jammy main' | tee /etc/apt/sources.list.d/intel-sgx.list \
    && apt-get update

RUN apt-get install -y --no-install-recommends libsgx-dcap-ql-dev libsgx-dcap-quote-verify-dev

RUN mkdir -p ./sgx && \
    curl --retry 5 --retry-all-errors --retry-delay 2 \
    -fsSL https://download.01.org/intel-sgx/sgx-linux/${SDK_VERSION}/distro/ubuntu22.04-server/sgx_linux_x64_sdk_${SGX_VERSION}.bin \
    -o ./sgx/sgx_linux_x64_sdk_${SGX_VERSION}.bin

RUN chmod +x ./sgx/sgx_linux_x64_sdk_${SGX_VERSION}.bin && \
    echo -e 'no\n/opt' | ./sgx/sgx_linux_x64_sdk_${SGX_VERSION}.bin

ENV LD_LIBRARY_PATH=/opt/sgxsdk/libsgx-enclave-common/

WORKDIR /app
COPY verifiers/intel .
RUN . /opt/sgxsdk/environment && make

# ==========================================
# 3. Build SSS Tool
# ==========================================
FROM rust:1.88-slim-bookworm AS sss-builder

WORKDIR /build
COPY sss-tool .

WORKDIR /build/sss-tool
RUN cargo build --release

# ==========================================
# 4. Trust Server
# ==========================================
FROM ubuntu:22.04 AS trust-server

ENV DEBIAN_FRONTEND=noninteractive
ENV NODE_ENV=production

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates gnupg \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

# Install Intel SGX Runtime Libraries
RUN curl -fsSL https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | gpg --dearmor -o /usr/share/keyrings/intel-sgx-deb.gpg \
    && echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/intel-sgx-deb.gpg] https://download.01.org/intel-sgx/sgx_repo/ubuntu jammy main' | tee /etc/apt/sources.list.d/intel-sgx.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
       libsgx-dcap-ql \
       libsgx-dcap-quote-verify \
       libsgx-uae-service \
       libsgx-dcap-default-qpl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# -- Intel --
COPY --from=intel-builder /app/app /usr/local/bin/attester
COPY verifiers/intel/sgx_default_qcnl.conf /etc/sgx_default_qcnl.conf

# -- AMD --
COPY --from=amd-builder /build/amd-verifier/target/release/amd-verifier /usr/local/bin/amd-verifier

# -- SSS Tool --
COPY --from=sss-builder /build/target/release/sss-tool /usr/local/bin/sss-tool

RUN chmod +x /usr/local/bin/attester /usr/local/bin/amd-verifier /usr/local/bin/sss-tool

COPY src/package*.json ./
RUN npm ci

COPY src/*.js ./
COPY src/whitelist.csv ./
COPY src/keys.json ./

EXPOSE 8080

CMD ["node", "server.js"]
