FROM node:20-alpine3.19
WORKDIR /workspace
ENV CGO_ENABLED=0
RUN apk add --no-cache git python3 curl && \
    curl -L https://go.dev/dl/go1.24.5.linux-amd64.tar.gz | tar -C /usr/local -xz && \
    git config --global --add safe.directory /workspace && \
    npm install -g npm@8.19.2
ENV PATH=$PATH:/usr/local/go/bin
ENTRYPOINT ["tail", "-f"]
