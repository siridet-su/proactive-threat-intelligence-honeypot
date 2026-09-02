FROM scratch

ARG IMPLEMENTATION_SHA256
LABEL org.opencontainers.image.title="cowrie-hardware-fusion-poc-workload" \
      org.opencontainers.image.description="Fixed bounded non-malware workload for isolated Pi PoC" \
      org.opencontainers.image.revision="${IMPLEMENTATION_SHA256}"

COPY --chmod=0555 poc-workload-linux-arm64 /poc-workload

USER 65532:65532
ENTRYPOINT ["/poc-workload"]
