FROM scratch
COPY idp-mcp-bridge /idp-mcp-bridge
# no shell, no Docker socket, no files to write: the service runs as an unprivileged user. `docker run IMAGE check-config`
# validates a connections file (mounted) without starting anything.
USER 65532:65532
ENTRYPOINT ["/idp-mcp-bridge"]
