# Build Stage
FROM ubuntu:latest AS build

# Update and install necessary build tools
RUN apt update && apt install -y \
    curl unzip git wget python3 python3-pip build-essential \
    && wget https://go.dev/dl/go1.23.2.linux-amd64.tar.gz \
    && rm -rf /usr/local/go && tar -C /usr/local -xzf go1.23.2.linux-amd64.tar.gz \
    && rm -f go1.23.2.linux-amd64.tar.gz \
    && apt clean && rm -rf /var/lib/apt/lists/*

# Set environment variables for Go
ENV PATH="$PATH:/usr/local/go/bin:/root/go/bin:/usr/local/go/bin:$HOME/.local/bin"
ENV GOROOT="/usr/local/go"
ENV GOPATH="/root/go"

# Install Python dependencies without cache

# Install Go tools
RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest


# Runtime Stage (final smaller image using Python slim)
FROM python@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
RUN apt update && apt install -y git && apt clean && rm -rf /var/lib/apt/lists/*
# Copy Go binaries and tools from the build stage
COPY --from=build /usr/local/go /usr/local/go
COPY --from=build /root/go/bin /root/go/bin

WORKDIR /app/service/
# The shared class is built from this repository, not from the published
# release: a worker that calls auth_headers(task) against a release that
# does not have it fails inside the scan.  scripts/build_workers.sh passes
# the local wheel; the default is the published release.
ARG B_HUNTERS_WHEEL=b-hunters==1.4.1
RUN pip install --no-cache-dir ${B_HUNTERS_WHEEL} uro
RUN git clone https://github.com/projectdiscovery/nuclei-templates /app/templates
# Set environment variables for Go
ENV PATH="$PATH:/usr/local/go/bin:/root/go/bin:/usr/local/go/bin:$HOME/.local/bin"
ENV GOROOT="/usr/local/go"
ENV GOPATH="/root/go"

# Copy necessary files
COPY nucleim nucleim

# Default command
CMD ["python3", "-m", "nucleim"]
