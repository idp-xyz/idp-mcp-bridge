# idp-mcp-bridge

The bridge between the IDP TELOS MCP gateway and third-party MCP servers: each member authorizes a third-party service once with OAuth, and the bridge calls it with that member's own token. Plan: the platform repository, docs/adr/idp-mcp-bridge-oauth-plan.md. This repository's own decisions: [`docs/adr/ADR-0001-bridge-design.md`](docs/adr/ADR-0001-bridge-design.md) (Chinese, D1 to D20). Operations: [`docs/RUNBOOK.md`](docs/RUNBOOK.md) (Chinese).

Status: **B1 (skeleton) and B2 (OAuth per member) are in place.** Connections, one MCP 2026-07-28 endpoint per connection for the gateway, the client toward the third party under the address rules, the rate limits, the circuit breaker, audit and metrics; and OAuth: discovery with a pinned issuer, client identity by client metadata document or preregistration (dynamic registration only if opted in), authorization code with PKCE, `state`, `iss` and the `resource` of RFC 8707, grants sealed in PostgreSQL, refresh that one replica at a time performs, step-up on `insufficient_scope`, revocation, and the internal API of the Workspace verified against Keycloak. A connection that needs no token works without any of it. **B3** adds the reviewer account (an operator-authorized account per connection, used for `tools/list` only) and computes the `Mcp-Param-*` headers a tool declares. **Still open:** offboarding a member automatically (the operator runs `revoke`).

## How it sits in the platform

```
HOST -> gateway --(signed caller assertion, audience = the connection's endpoint)--> bridge /mcp/<id> --(arguments only)--> third party
Workspace --(member's token exchanged for the bridge's audience)--> bridge :8681 /internal/v1/...
bridge --(PKCE, state, resource; the member's own token)--> third party's authorization server and MCP server
```

**One endpoint per connection, by path:** `http://idp-mcp-bridge.idp-mcp-bridge.svc.cluster.local:8680/mcp/<id>` (the base is `IDP_BRIDGE_BASE_URL`). The gateway registers each connection as its own server of class `external`, named `<id>`, with that URL as its endpoint, and the audience of the caller assertion is that URL character for character, so an assertion made for one connection is refused at another. A host per connection was rejected: it needs wildcard DNS and a name per connection in the Service, the Ingress and the certificate, and the gateway's `IDP_BRIDGE_ENDPOINTS` accepts a URL prefix (`http://idp-mcp-bridge.idp-mcp-bridge.svc.cluster.local:8680/mcp/`) that covers every connection at once (ADR-0001 D5).

## Configuration

Settings are environment variables (`cmd/idp-mcp-bridge/main.go` documents each); the connections are a YAML file, read once at start and validated strictly (an unknown key, a missing required one, an address that breaks the rules, a value out of its bounds stops the bridge with status 2). `idp-mcp-bridge check-config` validates the file and prints the connections and their audiences.

```yaml
connections:
  - id: github                       # lower case, digits, hyphens; the path /mcp/github and the server name at the gateway
    title: GitHub                    # what a member is told
    endpoint: https://api.githubcopilot.example/mcp      # public https only (internal/addr), no query, port 443
    authorization:
      mode: oauth                    # none: the third party needs no token; oauth: each member authorizes
      issuer: https://github.example/login/oauth          # the authorization server, pinned; required for oauth (discovery refuses any other)
      client:
        mode: cimd                   # cimd: the client_id is this address, a metadata document the operator hosts
        document: https://workspace.example.com/.well-known/mcp-client/github.json
        # mode: preregistered with  id: <client id>  and  secretFile: /etc/idp/secrets/github   (a mounted Secret)
        # dynamicRegistration: true  is an explicit opt-in for cimd clients only (the fallback when the server does not accept
        #                            a CIMD address); off unless written
      scopes: [repo, read:org]       # requested as written
    rateLimit: {windowSeconds: 60, connectionCalls: 300, memberCalls: 60}   # the defaults; a sliding window, in memory, per pod
    breaker: {failures: 5, openSeconds: 30}                                  # the defaults
  - id: docs
    title: Public docs
    endpoint: https://mcp.docs.example.com/mcp
    authorization: {mode: none}      # no issuer, client or scopes: they would be ignored, so they are refused
```

For acceptance only, `IDP_BRIDGE_TEST_ORIGINS` (exact `host:port` pairs) lets a connection's addresses be plain http on a private address, as idp-web's `IDP_WEB_TEST_ORIGINS` does; nothing else is exempted, and `tests/deploy` fails if a manifest sets it.

## What goes to the third party, exactly

Built from an allow-list, never cleaned from the caller's request (`internal/upstream/client.go`):

- Body of a `tools/call`: `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":<tool>,"arguments":<arguments as sent>,"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"progressToken":<the caller's, only if it is a string of up to 128 bytes or an integer>}}}`. No other top-level param (`task`, `inputResponses`, `requestState`, anything invented), no other `_meta` key (no `clientInfo`, no trace keys, no `io.idp.telos/` key).
- Headers: `Content-Type`, `Accept`, `MCP-Protocol-Version`, `Mcp-Method`, `Mcp-Name` (the tool; Base64 form if not plain ASCII), `User-Agent: idp-mcp-bridge`, `Authorization: Bearer <the member's token for this connection>` when the connection has one, and the `Mcp-Param-*` headers the tool's definition declares (`x-mcp-header`), computed from the arguments and the definition the bridge last listed (Base64 form for a value that is not plain printable ASCII, at most 16 headers of 1024 bytes; a tool whose definition is unknown or invalid gets none). No `traceparent`, `tracestate`, `baggage`, and not one header copied from the gateway's request.
- Nothing of the caller: no assertion, tenant, member or client. The connection is made to an address that passed the address rules at the dial (every answer of a name must be public, the checked IP is the one dialed), through the operator's proxy if `IDP_BRIDGE_EGRESS_PROXY` is set (then the proxy is the only address dialed and it must enforce the rules itself). No redirect is followed.

## What comes back, exactly

- A plain answer is read up to `IDP_BRIDGE_MAX_RESULT_BYTES` (1 MiB); a stream one event at a time up to the same, and nothing past `IDP_BRIDGE_MAX_STREAM_BYTES` (4 MiB, comments and keep-alives included) is read. Over either: the call ends with a tool error that says so.
- A request from the third party to the client (`sampling/createMessage`, `elicitation/create`, `roots/list`, `ping`), a result of type `input_required` or `task`: the call ends with a tool error, nothing of it is relayed (idp-mcp ADR-0001 D51 c). Notifications, progress included, are dropped: this endpoint answers with plain JSON.
- Every key beginning `io.idp.telos/`, at any depth of a result or a tool definition, is removed (only the bridge, the gateway and the platform set them). The rest of the result is passed on unchanged, and is as untrusted as any tool result: the HOST marks it so.
- "Authorization required": a tool error whose `structuredContent` is exactly `{"io.idp.telos/authorizationRequired":{"connection":"<id>"}}`, with a sentence telling the model the member must connect the service in the Workspace. Never an address: the Workspace builds its own link. The third party hears nothing of such a call.

## OAuth

Settings (all required once a connection has `mode: oauth`; `cmd/idp-mcp-bridge/main.go` lists them): `IDP_BRIDGE_DATABASE_URL_FILE`, `IDP_BRIDGE_ENCRYPTION_KEYS_FILE` (`<id>:<base64 of 32 bytes>` a line, the first seals, all open), `IDP_BRIDGE_REDIRECT_URI` (the Workspace's callback page, the same for every connection), `IDP_BRIDGE_OIDC_ISSUER`, `IDP_BRIDGE_API_AUDIENCE`, `IDP_BRIDGE_WORKSPACE_CLIENT`.

The internal API (port 8681, `Authorization: Bearer <the member's token exchanged for the bridge's audience>`, verified against Keycloak's keys: issuer, audience, expiry, `azp` = the Workspace's client, tenant and subject; the member comes from the token and from nothing else):

| Route | Request | Answer |
|---|---|---|
| `GET /internal/v1/connections` | | `{"connections":[{"id","title","status","reason","scope","reviewer"}]}` (`reviewer` only for a caller with the reviewer role), status one of `not_required`, `not_connected`, `connected`, `reauthorization_required` (reason `insufficient_scope`, `issuer_changed`, `expired`) |
| `POST /internal/v1/connections/{id}/authorization` | none | `{"url": ...}` the authorization address (state, S256 challenge, scope, `resource`) |
| `POST /internal/v1/connections/{id}/callback` | `{"code","state","iss","error"}` | 200 `{"connection","status":"connected"}`, or a fixed error code (`invalid_state`, `state_expired`, `authorization_failed`, `authorization_denied`, ...) |
| `DELETE /internal/v1/connections/{id}/grant` | | 204: tokens revoked at the server if it has a revocation endpoint, grant deleted either way |
| `POST /internal/v1/connections/{id}/reviewer/authorization` | none | `{"url": ...}` for the connection's reviewer account; 403 `forbidden` without the reviewer role (`IDP_BRIDGE_REVIEWER_ROLE`, no default); finished by the same callback |
| `DELETE /internal/v1/connections/{id}/reviewer/grant` | | 204; 403 `forbidden` without the role |
| `GET /internal/v1/connections/{id}/client-metadata` | | the client metadata document of a `cimd` connection (public; the Workspace serves it at `client.document`) |

Operator commands: `idp-mcp-bridge migrate`, `ensure-login USER`, `reseal` (move every sealed value to the current key), `revoke --tenant T --member M [--connection C]` or `revoke --connection C`. The server runs no DDL and does not migrate: `migrate` (owner URL, `IDP_BRIDGE_MIGRATION_DATABASE_URL`, held only by the migration Job) creates the tables and the role `idp_bridge_app` (DML on three tables, nothing else), `ensure-login USER` makes the login role the server runs as, and the server refuses to start on another schema version or as a role that could change the schema (RUNBOOK 5.2). Never a token, code, verifier, state or client secret is in a log line, metric, error or answer, but the authorization address (which carries the state and the challenge by design).

## Use

```bash
make test               # gofmt, vet, tests with -race (includes tests/deploy: the manifests against the code)
make test-integration   # the same over a throwaway PostgreSQL (own container, removed again): the OAuth flows and the store run over it too
make build              # bin/idp-mcp-bridge
bash deploy/build.sh    # the image (scratch, user 65532): static binary on the host, then docker build --network none
```
