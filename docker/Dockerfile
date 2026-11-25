# The release workflow stages the static musl binaries by Docker architecture.
FROM scratch
ARG TARGETARCH
COPY --chmod=755 linux/${TARGETARCH}/secretspec /secretspec
ENTRYPOINT ["/secretspec"]
