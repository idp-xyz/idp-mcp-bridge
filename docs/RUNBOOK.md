# idp-mcp-bridge 运维手册

适用：idp-mcp-bridge（外联桥：放在 idp-mcp 网关后面，替成员调用第三方 MCP 服务）。设计与取舍见 [`adr/ADR-0001-bridge-design.md`](adr/ADR-0001-bridge-design.md)，为什么要有它见平台的 `docs/adr/idp-mcp-bridge-oauth-plan.md` 与对外互通 ADR 草案（D-X1、D-X2、D-X4）。本手册讲 Kubernetes 部署、连接文件、OAuth（成员各自授权：数据库、加密密钥、Keycloak、撤销，第 5 节）、轮换、日志、故障排查。

## 1. 它是什么，怎么接

- 一个 MCP 2026-07-28 服务器，**每条连接一个端点**：`http://idp-mcp-bridge.idp-mcp-bridge.svc.cluster.local:8680/mcp/<连接 id>`（端口 8680）；Workspace 用的内部 API 在 8681（有 oauth 连接时按第 5 节运行；没有时对所有请求答 501）；运维端口 9680（`/healthz`、`/readyz`、`/metrics`）。工具就是第三方服务的工具，经网关时带目标名前缀（目标名就是连接 id，如 `github__create_issue`）。
- **只能放在网关后面**：网络策略只放网关和注册服务进 8680，只放 Workspace 进 8681；每个 `tools/call` 还必须带网关签的调用者断言（D2），受众是**这条连接的端点**，所以绕过网关直连的请求、或把 A 连接的断言拿到 B 连接用，都是 403。没有关闭这项检查的设置。
- **它是唯一被允许出站到公网的组件之一**：命名空间 `idp-mcp-bridge` 里只有它。出口策略只放公网地址的 443，减去 `internal/addr` 拒绝的全部 IPv4 段；服务自己也拒绝同一批地址，策略是集群对它的再做一遍。只有 IPv4。
- **副本数**：可以多于一个。成员的授权在 PostgreSQL 里，一个副本开始的授权可以由另一个完成，一个授权的刷新不论哪个副本都只有一个在做（行锁，ADR D26）；限流窗口与熔断器仍是各副本的（N 个副本时一个成员在窗口内最多可做 N 倍的调用，各副本各有自己的熔断）。

## 2. 部署

```bash
# 1. 命名空间（带 restricted 与 idp-mcp/mcp-upstream 标签）
kubectl apply -f deploy/kubernetes/namespace.yaml
# 2. 网关的公钥，不在仓库里
kubectl -n idp-mcp-bridge create configmap idp-mcp-bridge-gateway-caller-keys --from-file=caller.pub=<网关的公钥 PEM>
# 3. 预注册客户端的密钥（只有用了 preregistered 的连接才需要；每个一个键，连接文件里的 secretFile 指向它）
kubectl -n idp-mcp-bridge create secret generic idp-mcp-bridge-client-secrets --from-file=crm=<文件>
# 3b. 有 oauth 连接时（第 5 节）：授权库的角色与 Secret 见 5.2（所有者的 URL 只给迁移 Job），加密密钥：
kubectl -n idp-mcp-bridge create secret generic idp-mcp-bridge-encryption-keys --from-literal=keys="k1:$(openssl rand -base64 32)"
# 4. 写连接（第 4 节），把镜像换成构建出的、按摘要固定的镜像，再应用
kubectl apply -k deploy/kubernetes
kubectl -n idp-mcp-bridge rollout status deploy/idp-mcp-bridge
```

发布的 `connections.yaml` **没有连接**，服务在文件里一条连接都没有时启动即退出（状态码 2，写明原因），Pod 不就绪：哪些第三方会收到成员的 Agent 发出的内容，是运维的决定，不是缺省。`kubectl -n idp-mcp-bridge logs deploy/idp-mcp-bridge` 里出现 `idp-mcp-bridge listening` 之后 `/readyz` 才是 200。

**镜像**：`bash deploy/build.sh` 在宿主上静态编译，再 `docker build --network none`（scratch，用户 65532），推到自己的 registry，把 `kustomization.yaml` 里的 `registry.example.com/idp/idp-mcp-bridge` 和 `sha256:000…` 换成真实值（按摘要，不用标签）。镜像里没有 shell；`docker run -v $PWD/c.yaml:/c.yaml -v ... -e IDP_BRIDGE_CONFIG_FILE=/c.yaml ... IMAGE check-config` 可以在应用之前检查连接文件（要同样设置 `IDP_BRIDGE_CALLER_KEYS_FILE` 与 `IDP_BRIDGE_BASE_URL`），它列出每条连接和它的受众。

## 3. 在网关登记

每条连接在网关登记为一个**外部上游**，**逐字使用 `check-config` 列出的受众作为端点**：`http://idp-mcp-bridge.idp-mcp-bridge.svc.cluster.local:8680/mcp/<id>`。

```bash
# 注册服务与网关都设：指向桥的端点必须登记为 external（idp-mcp ADR-0001 D50），漏标是登记失败，不是悄悄的缺省
IDP_BRIDGE_ENDPOINTS=http://idp-mcp-bridge.idp-mcp-bridge.svc.cluster.local:8680/mcp/
# 登记（以 operator 的令牌）；class 之后不能改
POST /api/v1/servers  {"displayName":"github","targetName":"github","endpoint":"http://idp-mcp-bridge.idp-mcp-bridge.svc.cluster.local:8680/mcp/github","class":"external"}
POST /api/v1/servers/{id}/discover        # 经桥列出第三方的工具：不需要令牌的连接直接成功；要令牌的连接要先有评审账号（第 5.6 节），否则 502
GET  /api/v1/servers/{id}/catalog         # 评审人读完整目录
POST /api/v1/servers/{id}/approve         {"digest":"<看过的目录摘要>"}
```

`identity` **不写（缺省 `none`），不要写 `forward`**：idp-mcp ADR-0001 15.1（G1）让网关对指向桥地址（`IDP_BRIDGE_ENDPOINTS` 匹配）的外部上游发**签名的调用者断言**（受众是这个目标的端点，有效期 60 秒），external 目标的 `identity` 仍必须是 `none`，因为 `forward` 会发明文的调用者，登记时被拒绝。**网关没有 `IDP_GATEWAY_CALLER_KEY_FILE`（签名密钥）时，对桥的调用不发出**（`NOT_DELIVERED`）。端点必须与桥的受众逐字相同：多一个斜杠、`http` 写成 `https`、连接 id 不同，每个调用都是 403。**登记要求 idp-mcp 含 15.2**：此前注册服务要求端点以 `/mcp` 结尾，桥的 `/mcp/<连接 id>` 登记不了（平台验收 PATH O 发现）。

**网关的签名**：网关设 `IDP_GATEWAY_CALLER_KEY_FILE`（P-256 私钥），公钥放进 ConfigMap `idp-mcp-bridge-gateway-caller-keys`。两边的时钟差不要超过 30 秒。

## 4. 连接文件

格式与每个键的含义见 README；校验规则在 `internal/config/config.go`。要点：

- `id`：小写字母、数字、连字符，至多 40 个字符；它是路径、网关里的服务名、成员授权的键，**登记之后不要改**（改了等于另一条连接）。
- `endpoint`：公网 https 地址、443 端口、没有用户名密码、没有查询串、没有片段。内网地址、`http`、非 443 端口、数字写法古怪的 IP（`0x7f.1`）都被拒绝。
- `authorization.mode`：`none`（第三方不要令牌；不许写 issuer、client、scopes）或 `oauth`（`issuer` 必填并钉死，`client` 是 `cimd`（带文档地址）或 `preregistered`（带 `id` 和 `secretFile`）；`dynamicRegistration: true` 只允许 cimd，是明确的选择，缺省关）。
- `rateLimit`、`breaker`：缺省 60 秒窗口、每连接 300 次、每成员 60 次；连续 5 次失败后断开 30 秒。
- 文件只在启动时读一次；kustomize 按内容给 ConfigMap 命名，改了会换 Pod。
- **`IDP_BRIDGE_TEST_ORIGINS` 永远不要设**：它让桥连非公网、非 https 的地址（D6），`tests/deploy` 保证发布的清单里没有它。

## 5. OAuth：成员各自授权

**什么时候需要**：连接文件里有一条 `authorization.mode: oauth`。这时下面的设置都是必需的，缺任何一个服务启动即退出（状态码 2，写明缺哪个）；没有 oauth 连接则一个都不读，桥也不连数据库。

| 设置 | 含义 |
|---|---|
| `IDP_BRIDGE_DATABASE_URL_FILE`（或 `IDP_BRIDGE_DATABASE_URL`） | 授权库的 PostgreSQL URL，来自挂载的 Secret `idp-mcp-bridge-database` 的 `service-url`（含密码，所以是文件）。**这是应用角色（`idp_bridge_app` 的成员）：三张表的 DML，没有 DDL**；服务不迁移，只在启动时检查库的版本正是它要的，并拒绝以能改库的角色（超级用户、BYPASSRLS、对 schema 有 CREATE、拥有表）运行。TLS 是 URL 的：`sslmode=verify-full&sslrootcert=...` |
| `IDP_BRIDGE_ENCRYPTION_KEYS_FILE` | 加密密钥文件（Secret `idp-mcp-bridge-encryption-keys` 的 `keys`） |
| `IDP_BRIDGE_REDIRECT_URI` | **Workspace 的回调页**，所有连接共用，公网 https、无片段。它是配置，不是请求的字段：能指定它的调用者能把授权码送到自己的地址。授权服务器上登记（预注册客户端）或客户端元数据文档里写的 `redirect_uris` 就是它 |
| `IDP_BRIDGE_OIDC_ISSUER`、`IDP_BRIDGE_API_AUDIENCE`、`IDP_BRIDGE_WORKSPACE_CLIENT` | 验证 Workspace 对内部 API 的调用（ADR D28）：Keycloak 的 realm、令牌的受众（Workspace 换令牌时的 `audience`）、唯一被接受的 `azp`（Workspace 的令牌交换客户端）。`IDP_BRIDGE_OIDC_JWKS_URL`（缺省 `<issuer>/protocol/openid-connect/certs`）必须是 https；集群内只有 http 时要显式设 `IDP_BRIDGE_OIDC_ALLOW_HTTP=true`（启动日志警告：决定谁能调用的密钥经 http 取）。`IDP_BRIDGE_OIDC_CA_FILE` 给它加一个 CA。`IDP_BRIDGE_TENANT_CLAIM`（缺省 `tenant_id`）是租户声明 |

| `IDP_BRIDGE_REVIEWER_ROLE`、`IDP_BRIDGE_REVIEWER_TENANT`、`IDP_BRIDGE_ROLES_CLAIM` | 谁可以授权评审账号（第 5.6 节）：令牌里 `roles` 声明（可改）含这个 realm 角色，设了租户则还要是这个租户。**没有缺省，不设就没有人能**；只设租户不设角色是配置错误 |

**Keycloak 要做的**：一个客户端代表桥（它的 client id 就是 `IDP_BRIDGE_API_AUDIENCE`），允许 Workspace 的令牌交换客户端把成员的令牌换成以它为受众的令牌（idp-workspace 的 `auth: exchange` 配置里 `audience` 填它）；令牌要带租户声明；**要用评审账号的话，换来的令牌还要带 `roles` 声明**（桥的客户端要有 realm 角色的映射，平台的 realm 在用户的映射里有 `roles`，换出的令牌是否带上要在你的 Keycloak 里确认）。桥的出口策略要放到 Keycloak 的 JWKS（`networkpolicy.yaml` 的 `bridge-keycloak`，按你的 Keycloak 调整命名空间、标签与端口）。

**Workspace 要做的**（W1）：托管每条 `cimd` 连接的客户端元数据文档，内容取自桥：`GET /internal/v1/connections/{id}/client-metadata`（不需要令牌，没有秘密），原样公开在连接文件里 `client.document` 的地址上，**逐字相同**（它就是 client_id）；回调页用成员的会话核对登录成员，再把 `code`、`state`、`iss`（或 `error`）连同成员的换来的令牌交给 `POST /internal/v1/connections/{id}/callback`。

### 5.1 内部 API（Workspace 调用，端口 8681）

都要 `Authorization: Bearer <成员的令牌，换成受众为桥>`，成员只取自令牌；没有令牌或令牌不好都是 401，不说是哪一项。错误答案是 `{"error": "<固定的码>", "reason": "<固定的码，可无>"}`，里面没有第三方说的话。

| 路由 | 请求 | 答案 |
|---|---|---|
| `GET /internal/v1/connections` | 无 | `{"connections":[{"id","title","status","reason","scope","reviewer"}]}`；`reviewer`（`{"status","reason","scope"}`，状态同成员的）**只有带评审角色的调用者才有**，别人的答案里没有这个键；`status` 是 `not_required`、`not_connected`、`connected`、`reauthorization_required`；`reason`（只有重新授权时）是 `insufficient_scope`、`issuer_changed`、`expired`；`scope` 是成员授予的。没有令牌、没有授权服务器的地址 |
| `POST /internal/v1/connections/{id}/authorization` | 无正文（有也不看） | `{"url": "<授权地址>"}`：授权服务器的 `authorization_endpoint` 加上 `response_type=code`、`client_id`、`redirect_uri`、`state`、`code_challenge`（S256）、`scope`、`resource`（RFC 8707）；404 `not_found`（没有这条连接、或它不要令牌）；409 `authorization_server_refused` 加 `reason`（`issuer_mismatch`、`issuer_not_listed`、`resource_mismatch`、`resource_metadata_origin`、`pkce_unsupported`、`client_identity_unsupported`、`address_refused`、`redirect_refused`、`metadata_invalid`）：对方的元数据与配置对不上，不重试也无用；502 `authorization_server_unavailable`：对方没有应答 |
| `POST /internal/v1/connections/{id}/callback` | `{"code","state","iss","error"}` | 200 `{"connection","status":"connected"}`；400 `invalid_state`（没有、用过、不是这个成员的、不是这条连接的）、`state_expired`（10 分钟）、`invalid_request`、`authorization_failed` 加 `reason`（`iss_mismatch`、`iss_missing`、`invalid_grant`、`token_response_invalid`、`token_endpoint_error`）、`authorization_denied` 加 `reason`（`access_denied`、`invalid_scope`、`server_error`、`temporarily_unavailable`、`invalid_request`、`unauthorized_client`、`unsupported_response_type`，其他一律 `authorization_failed`）；409 `configuration_changed`；502 `authorization_server_unavailable` |
| `DELETE /internal/v1/connections/{id}/grant` | 无 | 204（没有授权也是 204）；对方有撤销端点时先撤销刷新令牌再撤销访问令牌，不论撤销成不成功都删除 |
| `POST /internal/v1/connections/{id}/reviewer/authorization` | 无 | 同上，是评审账号的授权地址；没有评审角色 403 `forbidden`；不要令牌的连接 404。授权在回调里完成（同一个回调路由），结果存为这条连接的评审授权，不是调用者自己的 |
| `DELETE /internal/v1/connections/{id}/reviewer/grant` | 无 | 204；没有评审角色 403 `forbidden`；撤销与删除同成员的断开 |
| `GET /internal/v1/connections/{id}/client-metadata` | 无（公开） | 客户端元数据文档：`client_id`（文档自己的地址）、`client_name`、`redirect_uris`（`IDP_BRIDGE_REDIRECT_URI`）、`grant_types`、`response_types`、`token_endpoint_auth_method: none`；404 对不是 `cimd` 的连接 |

### 5.2 数据库、建库与角色

**建库与角色**（一次；与 idp-mcp、idp-host、idp-web 同一套做法）。数据库 `idp_bridge` 由 DBA 建，所有者角色（建表的）的 URL 放进 Secret `idp-mcp-bridge-database-owner` 的 `owner-url`，**只有迁移 Job 挂它**，Deployment 没有。然后：

```bash
kubectl -n idp-mcp-bridge create secret generic idp-mcp-bridge-database-owner --from-literal=owner-url='postgres://idp_bridge_owner:<密码>@postgresql.databases.svc.cluster.local:5432/idp_bridge?sslmode=verify-full'
kubectl apply -k deploy/kubernetes          # Job idp-mcp-bridge-migrate 建表与角色 idp_bridge_app（只有三张表的 DML）；这时 Deployment 还起不来（没有服务角色的 Secret），这是预期
# 建服务用的登录角色（idp_bridge_app 的成员，不是超级用户）：用同一个镜像，一次性运行
kubectl -n idp-mcp-bridge run idp-mcp-bridge-ensure-login --rm -it --restart=Never --image=<镜像> \
  --env=IDP_BRIDGE_MIGRATION_DATABASE_URL=<所有者的 URL> --env=IDP_BRIDGE_APP_DB_PASSWORD=<服务角色的密码> \
  --command -- /idp-mcp-bridge ensure-login idp_bridge_svc
kubectl -n idp-mcp-bridge create secret generic idp-mcp-bridge-database \
  --from-literal=service-url='postgres://idp_bridge_svc:<密码>@postgresql.databases.svc.cluster.local:5432/idp_bridge?sslmode=verify-full&sslrootcert=/etc/idp/database/ca.crt' \
  --from-file=ca.crt=<签发数据库服务器证书的 CA>
```

（那条一次性命令把密码放在命令行里，只在受控的终端上做，或改用一个临时的、挂 Secret 的 Pod。）**TLS**：选项都在 URL 里；镜像没有系统 CA，所以私有 CA 必须用 `sslrootcert`。**升级**：先跑迁移的 Job（只往前走；Job 的模板建好后不能改，要先删旧的 Job），再滚动 Deployment：服务在库的版本与它要的不一致（更旧、更新都算）时拒绝启动，所以有迁移的版本，先迁移、再滚动，期间不要重启旧 Pod。PostgreSQL 14 及更早的 `public` schema 缺省允许所有角色建对象：服务会因为"对 schema 有 CREATE"拒绝启动，要先 `REVOKE CREATE ON SCHEMA public FROM PUBLIC`（15 起缺省已经如此）。


迁移 `0001_grants.sql`：`grants`（每行一个（租户、成员、连接）：密封的访问令牌与刷新令牌、到期时间、签发它的 issuer、授予的范围、升级后需要的范围与重新授权的原因、时间）、`pending_states`（进行中的授权：`state` 的 SHA-256、成员、连接、密封的 PKCE 验证码、issuer、重定向地址、范围、client_id、resource、到期时间；10 分钟，每分钟清一次过期的）、`client_registrations`（动态注册得到的客户端，密钥密封）。令牌、验证码、客户端密钥在库里都是密文；`state` 只存摘要。**备份**拿到的是密文，密钥在另一个 Secret 里：两者要分开保管，丢了密钥则所有授权作废（成员要重新授权）。

### 5.3 加密密钥与轮换

密钥文件每行 `<id>:<32 字节的 base64>`（`openssl rand -base64 32`），**第一行加密，所有行都能解**，`#` 开头的行与空行忽略。每个密文里写着它的密钥 id；附加数据是（租户、成员、连接、密钥 id），所以拷到别的成员或别的连接的行里解不开。

```bash
# 1. 在文件最前面加一行新密钥（旧的留着），更新 Secret，滚动重启：新授权和每次刷新用新密钥，旧行仍然解得开
# 2. 把旧行都改封到新密钥下（可在任何一个副本上跑，行一个一个加锁）：
#    镜像是 scratch，没有 shell，不能 exec：用一次性的 Job 跑同一个镜像（同样的 Secret 挂载与环境变量），参数 `reseal`；
#    `revoke` 与 `migrate` 同理
# 3. 输出 "re-sealed N values under key <新 id>" 之后，旧密钥才可以从文件里删掉，再滚动重启
```

`reseal` 处理授权与动态注册的密钥；进行中的授权 10 分钟就过期，不处理。某一行用的密钥不在文件里，`reseal` 报错并停下，行不动。

### 5.4 撤销与成员离开

- 成员自己断开：Workspace 的 `DELETE .../grant`。**再授权**（重新连接、`reauthorization_required` 或 `insufficient_scope` 之后重新授权，评审账号同）会替换授权，被取代的刷新令牌与访问令牌在新授权存入之后向授权服务器撤销（尽力而为，失败只记日志里的码，不影响新授权；服务器没有撤销端点则不做；ADR D35）。
- 运维：`idp-mcp-bridge revoke --tenant T --member M [--connection C]`：成员的授权（或这一条连接上的）逐条向授权服务器撤销（连接还在配置里、对方有撤销端点时，尽力而为），再删除；`idp-mcp-bridge revoke --connection C`：一条被撤下的连接的所有授权，直接删除（不向对方撤销：它们不按连接列出，连接多半已经不在文件里了）。命令需要与服务相同的数据库、密钥文件与（撤销要用的）连接文件设置。
- **未做（记为开放）**：成员离开租户时自动清理。身份提供方不会通知桥，桥也不扫描；离职流程要调用 `revoke`。管理员撤销某个成员的授权也只有这条命令。

### 5.5 常见的授权问题

| 现象（API 的码） | 原因 |
|---|---|
| 409 `authorization_server_refused` / `issuer_mismatch` | 授权服务器的元数据里的 `issuer` 与连接文件里钉死的不是同一个字符串（多一个斜杠也算）。以对方的元数据为准去改配置；这是防"被引到别的授权服务器"的检查，不要放宽 |
| `issuer_not_listed` / `resource_mismatch` | 受保护资源的元数据（RFC 9728）没有列出钉死的 issuer，或它写的 `resource` 与连接的端点（规范化之后，路径也要一致，带不带结尾斜杠也算）不是同一个 |
| `resource_metadata_origin` | 对方 401 的 `WWW-Authenticate` 把元数据指向了别的源；桥只在端点自己的源上取 |
| `client_identity_unsupported` | 对方不支持客户端元数据文档（`client_id_metadata_document_supported`），而连接没有开 `dynamicRegistration`；或预注册客户端的认证方式桥做不了（只做 `client_secret_basic`、`client_secret_post`） |
| `pkce_unsupported` | 对方的元数据没有在 `code_challenge_methods_supported` 里列 `S256`（MCP 要求客户端拒绝这样的服务器；官方 SDK 不查） |
| 回调 `iss_mismatch` / `iss_missing` | 回调里的 `iss` 不是钉死的 issuer（授权服务器混淆），或对方声明发 `iss`（`authorization_response_iss_parameter_supported`）却没发 |

### 5.6 评审账号（目录、评审与漂移探测用）

很多第三方连 `tools/list` 都要令牌，而网关的登记、评审、漂移探测没有成员。每条 `oauth` 连接可以有**一个评审账号**，是**运维**授权的，**只用于 `tools/list`，从不用于 `tools/call`**（成员的调用只带成员自己的令牌；评审账号存在也不会让没有授权的成员的调用发出去）。

**评审账号应当是什么**：第三方那里**专门为此建立的账号**，不是任何人的个人账号（成员离职不应让目录坏掉，个人账号的权限也不该借给目录），**权限是能列出工具的最小**（只读；不能访问成员的数据；有"仅元数据"之类的范围就用它），名下没有数据。在连接文件里写 `authorization.reviewerScopes`（缺省用 `scopes`）。

```bash
# 1. 配置谁可以授权：一个 realm 角色（可再限定一个租户）；不设就没有人
IDP_BRIDGE_REVIEWER_ROLE=idp-reviewer          # 给负责目录的运维的 realm 角色；令牌的 roles 声明里要有它
IDP_BRIDGE_REVIEWER_TENANT=<运维的租户>        # 可选
# 2. Workspace 的页面（W1）里，有这个角色的运维对每条连接看到"评审账号"的状态，点"授权"：
#    POST /internal/v1/connections/{id}/reviewer/authorization  →  跳到第三方，**用那个专门的账号**登录并同意
#    回到回调页 → POST /internal/v1/connections/{id}/callback（与成员的相同）
# 3. 在网关里 discover / 重新评审：现在列表带评审账号的令牌
# 4. 换账号、撤销：DELETE /internal/v1/connections/{id}/reviewer/grant（向第三方撤销再删除），再授权新的
```

- 授权存在授权库里，密封，与任何成员的授权分开；同一个运维自己连接这个服务（成员授权）与授权评审账号互不影响。
- 评审令牌的刷新、轮换与成员的一样（行锁，一次只有一个副本刷新）；刷新令牌被对方拒绝时评审授权被删除，目录退回"不带令牌"，`discover` 会得到 502 "没有授权好的评审账号"：重新授权即可。
- 状态在列表里（只给有评审角色的调用者）：`connected`、`not_connected`、`reauthorization_required`（原因 `issuer_changed`、`expired`）。
- 撤下连接（`revoke --connection C`）两种授权都删；成员离职（`revoke --tenant --member`）不动评审账号。

### 5.7 `Mcp-Param-*` 头

工具可以在输入 schema 里用 `x-mcp-header` 声明某些参数要镜像进 `Mcp-Param-<名>` 头（MCP 2026-07-28，SEP-2243）。桥按**最后一次列出的工具定义**和调用的参数算出这些头发给第三方（规则与上限见 ADR D34），**不复制网关请求里的任何头**。定义来自每次 `tools/list`；一个调用遇到目录里没有的工具（或目录超过 5 分钟）会先刷新一次（用评审账号；每条连接至多每 30 秒由调用引起一次，熔断器开着或超出连接限流时不刷新），仍然未知则**不带这些头照样发出**。工具有无效的 `x-mcp-header` 注解（类型是 number、名字不是 token、重名、不在 `properties` 一路可达的位置）则这个工具没有头。参数太长放不进头（值编码后超过 1024 字节、超过 16 个头、名字超过 128 字节）：调用被拒绝，模型读到哪里太长，第三方没有收到请求。

## 6. 轮换

- 网关的签名密钥：ConfigMap 的 `caller.pub` 里可以放多把公钥（PEM 一块一块写）；先加新的，网关切换之后再删旧的。
- 预注册客户端的密钥：换 Secret 里的文件，再重启 Pod。

## 7. 日志与指标

每次调用一行审计（`msg: "audit"`）：`tool`、`connection`、`tenant`、`member`（租户加主体的 SHA-256 前 4 字节，不是主体）、`outcome`、`bytes`、`ms`。**没有参数、结果、令牌**。`outcome` 取值：`ok`、`tool_error`（第三方的工具自己报错）、`rpc_error`、`authorization_required`、`token_error`、`rate_limited`、`circuit_open`、`unreachable`、`bad_response`、`result_too_large`、`reverse_refused`、`refused`（第三方答 4xx）、`failed`（第三方答 5xx）、`not_configured`、`bad_request`、`canceled`。被拒绝的断言写 `caller assertion refused` 一行（原因写日志，不给调用者）。

指标（`/metrics`）：`idp_bridge_calls_total{connection,outcome}`、`idp_bridge_call_seconds_total{connection}`、`idp_bridge_result_bytes_total{connection}`、`idp_bridge_breaker_state{connection}`（0 关、1 开、2 半开）。标签里没有任何来自调用者的值，表不会被调用者撑大。

## 8. 企业出口代理

设 `IDP_BRIDGE_EGRESS_PROXY=http://proxy:3128`（无凭据）后，桥只连这个代理（按精确的主机与端口，不做地址检查），**代理必须自己拒绝非公网目的地**：桥看不到代理最后连了哪个地址，所以 DNS 重绑定那一类检查要由代理做。同时要把 `networkpolicy.yaml` 的 `bridge-egress` 换成只放代理的规则。配置文件里的地址仍然检查（公网 https）。环境变量里的 `HTTP_PROXY` 从不被读。代理的凭据不能写在地址里（进程列表和崩溃报告看得见）；需要认证的代理，留作以后。

## 9. 故障排查

| 现象 | 原因 |
|---|---|
| 每个 `tools/call` 都是 403，日志里 `caller assertion refused` | 看 `reason`：`made for ..., not for ...` 是端点与受众不是同一个字符串；`signed with a key this server does not hold` 是公钥没配或没轮换；`expired`/`issued in the future` 是时钟差；`no assertion` 是网关没发断言（网关没有签名密钥，或这个端点不在 `IDP_BRIDGE_ENDPOINTS` 里） |
| 启动退出，状态码 2 | 配置错误，stderr 写明（连接文件的哪一条哪一项、哪个环境变量） |
| 工具调用答"连接 X 之前先在 Workspace 授权" | 这个成员没有授权；授权过期且不能刷新；刷新令牌被对方拒绝（授权已删除）；对方答 `insufficient_scope`（授权保留，要求更大的范围，列表里的原因是 `insufficient_scope`） |
| 答"... is not answering at the moment" | 这条连接的熔断器开了（连续失败）；`idp_bridge_breaker_state` 为 1；等 `openSeconds`，第三方恢复后第一次调用就关上它 |
| 答"... too often" | 限流；文字里有多少秒后可以再试 |
| 答"the answer is longer than the limit" | 第三方的结果超过 `IDP_BRIDGE_MAX_RESULT_BYTES`；让模型少要一点；上限不要调到超过网关的外部目标上限（1 MiB），否则网关会再截一次 |
| `discover` 失败，"wants a credential to list its tools" | 第三方连列出工具都要令牌：需要评审账号（B3） |
| 日志里 `is not a public address` 一类 | 连接的地址（或它的名字解析到的某个地址）不是公网地址；这是规则，不是故障 |

## 10. 安全边界（运维要知道的）

- 第三方永远收不到 TELOS 的身份：没有调用者断言、没有租户与成员、没有追踪头、没有 `clientInfo`；只有参数、协议信封和这个成员自己的第三方令牌。这条在桥这一跳执行，因为网关对指向桥的外部上游要发断言（G1）。
- 第三方的结果一律不可信：桥不解释它、不按它行事；删去平台命名空间 `io.idp.telos/` 的键，限制大小，拒绝它向客户端发出的请求；HOST 再按外部标记处理（敏感级别上限、不可信包装、成员确认）。
- 桥被攻破：它不持有网关的私钥、没有 Kubernetes API 的凭据、出口只到公网地址的 443；它持有的是加密的令牌（AES-256-GCM，密钥在数据库没有的 Secret 里）和一把加密密钥；拿到数据库的备份得不到令牌。
