# ADR-0001　idp-mcp-bridge 的设计（骨架：连接、对网关的端点、对第三方的客户端、出口、限流与熔断）

| 项 | 内容 |
|---|---|
| 状态 | 已接受（2026-11-22，随任务 B1；外联桥计划第 5 节）。D25 在 B2 评审后改为所有者与应用角色分开。D33、D34 随任务 B3（评审账号、`Mcp-Param-*` 头）；D38 到 D42 随成员离开的撤销（F1、F2，计划 `idp-mcp-bridge-offboarding-plan.md`）；D36、D37 随 GitHub 的验证（令牌端点用 200 回错误；最小权限的范围）；D35 在平台验收之后（再授权时撤销被取代的令牌）。D21 到 D32 随任务 B2（OAuth、授权库、Workspace 的内部 API）；B3（评审账号）在 D33 实现，D13 的 `ReviewerSource` 是它的接入点。D15（存储接口）与 D16（内部 API）在 B2 里实现，细节以 D24 到 D30 为准 |
| 范围 | `idp-mcp-bridge` 的技术栈、连接配置、对网关的 MCP 端点与调用者校验、对第三方的 MCP 客户端（发什么、收什么）、地址规则与出口、限流与熔断、"需要授权"的答复、为 B2 留的接口、审计与指标、部署 |
| 依据 | B2：RFC 6749、6750、7009、7591、7636、8414、8707、9207、9728，OpenID Connect Discovery 1.0，OAuth Client ID Metadata Document（草案），MCP 2026-07-28 授权部分（规范页本机取不到，以官方 Python SDK 2026-10-13 的客户端为参照读过，不抄：`idp-mcp/build/conformance-deps/python-sdk/src/mcp/client/auth/`）；平台的 `docs/adr/idp-mcp-bridge-oauth-plan.md`（第 2、3、5、7 节）；对外互通 ADR 草案 D-X1、D-X2、D-X4；idp-mcp ADR-0001 D12、D44、D50 到 D53；idp-web ADR-0001 D1、D2、D6 到 D8、D14、D22、D24；idp-workspace ADR-0001 D16；MCP 2026-07-28 |

## 1. 背景与边界

计划（已确认）决定新增外联桥：放在 idp-mcp 网关后面，替成员调用第三方 MCP 服务；成员各自用 OAuth 授权，桥持有令牌；第三方永远收不到 TELOS 的身份。本 ADR 只记仓库自己的决策。为什么要有这个组件、令牌怎么存、授权怎么走，在计划里，这里不重复。

本任务（B1）只建骨架：服务能启动、读连接、对网关说 2026-07-28、校验网关签名的调用者、对第三方说 2026-07-28、检查地址、限流、熔断、审计。**不需要令牌的连接已经端到端可用**；需要令牌的连接（`mode: oauth`）一律答"需要授权"，不调用第三方，因为令牌来源是 B2 的。

计划第 7 节的选择点按建议采用：回调落在 Workspace；客户端身份 CIMD 为主、预注册为辅、动态注册缺省关；不做运行的暂停与恢复；每条连接一个评审账号用于发现；新仓库；每个部署一把加密密钥，来自 Secret。

## 2. 决策

| # | 决策 | 理由 |
|---|---|---|
| D1 | **照 idp-web 的方式搭：Go，MCP 服务层手写并复制，不共享代码；骨架阶段只用标准库加三个依赖** | idp-web ADR-0001 D1 已做过这个选择：协议准入规则是 idp-mcp 网关的规则，每个上游各复制一份，比引入共享模块（要版本、要发布、要几个仓库同时升级）简单；复制会漂移，所以把漂移变成测试失败。复制的内容：`internal/mcp/assertion.go`（调用者断言的校验，与 idp-web 逐字相同，只加了三个导出的小函数给测试用的签名器：`RequestDigest`、`KeyID`、`AssertionType`）、`internal/mcp/testdata/caller-assertion-v1.json`（平台发布的一致性向量，与 `idp-contracts/vectors/caller-assertion/v1.json` 逐字节相同，由 `caller_vectors_test.go` 让每个用例经过校验器与服务器的 `tools/call`）、`internal/addr`（地址规则，连同测试与模糊测试语料）。**与 idp-web 的复制不同之处只有一处**：服务器不拥有固定的工具表，`tools/list` 与 `tools/call` 交给一个 `Backend` 接口，由它转发给第三方（`internal/mcp/server.go`）；`Mcp-Method` 必需、`MCP-Protocol-Version`、`_meta` 信封的检查与 idp-web 一致，测试同样复制。**依赖**（版本、许可）：`golang.org/x/net v0.63.0`（BSD-3-Clause；`idna`，地址规则要用）、`golang.org/x/text v0.44.0`（BSD-3-Clause，`idna` 的间接依赖）、`gopkg.in/yaml.v3 v3.0.1`（MIT 与 Apache-2.0；连接文件，`KnownFields(true)` 做严格校验）、`golang.org/x/crypto/x509roots/fallback v0.0.0-20261115193255-739070949446`（BSD-3-Clause，数据是 Mozilla 的根证书，MPL-2.0；镜像是 scratch，没有 CA 证书，Go 在系统没有时用它：与 idp-web D13 相同）。四个都已在 idp-web 里使用，版本相同。**B2 增加两个**：`github.com/jackc/pgx/v5 v5.12.0`（MIT；PostgreSQL 驱动，idp-web、idp-mcp、idp-host 已用，版本相同；间接依赖 `pgpassfile`、`pgservicefile`、`puddle/v2`、`golang.org/x/sync` 同样来自 pgx）与 `github.com/golang-jwt/jwt/v5 v5.3.1`（MIT；验证 Keycloak 签的令牌，idp-mcp 网关用同一个库与同一个版本做同一件事） |
| D2 | **调用者只取自网关签名的断言，没有关掉的开关** | 与 idp-web D2 相同的规则（ES256、`typ` 为 `idp-caller+jwt`、`kid` 是持有的公钥、有效期、`req` 等于这次请求的摘要、`jti` 只收一次），受众是**这条连接的端点**（D5）。与 idp-web 不同：idp-web 在没有设公钥时可以走"网络信任"的模式，桥**没有**这个模式：调用者决定用谁的令牌，一个没人签名的调用者就是借用别的成员令牌的办法，所以 `IDP_BRIDGE_CALLER_KEYS_FILE` 与 `IDP_BRIDGE_BASE_URL` 必须设（缺了启动退出，状态码 2），`mcp.New` 对空的校验器直接 panic。检查在读工具名之外的任何东西之前、在 `Backend` 之前：没有断言的 `tools/call` 得到 HTTP 403，令牌查询与第三方连接都不会发生。`tools/list` 与 `server/discover` 不需要调用者（网关的注册与漂移探测没有）。租户和成员只来自校验过的调用者，不是参数、不是 `_meta` 的任何键（包括旧式的未签名的 `io.idp.telos/caller`，被忽略） |
| D3 | **连接配置：一个 YAML 文件，启动时读一次，严格校验** | 每条连接：`id`（也是网关里的服务名，小写字母、数字、连字符，至多 40 个字符）、`title`、`endpoint`、`authorization`（`mode`、`issuer`、`client`、`scopes`）、`rateLimit`、`breaker`。未知键、缺必填项、越界的值、重复的 id、一个文件里多个 YAML 文档，都是启动错误，不猜缺省。限流与熔断有缺省与上下限（D12、D13）。预注册客户端的密钥是文件引用（`secretFile`，绝对路径，Secret 挂载），不是值；`Load` 检查它可读且非空。文件在 ConfigMap 里，所以也不接受含查询串的端点（密钥会被放在那里）。理由：配置错误应当让桥起不来，而不是让它带着一个以为生效的设置运行；B2 读同一个文件，所以 B2 要的项现在就必填，文件的形状不会在 OAuth 到来时变 |
| D4 | **授权模式：`none` 或 `oauth`；`issuer` 对 `oauth` 必填并钉死，对 `none` 不允许** | 计划写"钉死的授权服务器 issuer（B2 用，现在就必填，让配置稳定）"，也写"不需要令牌的连接已经端到端可用"，两句话放在一起，issuer 不能对每条连接都必填：一个不要令牌的第三方没有授权服务器。所以用 `authorization.mode` 表达"要不要令牌"：`oauth` 的 issuer、client（`cimd` 带文档地址，`preregistered` 带 `id` 与 `secretFile`）、scopes 必填并校验（issuer 与 CIMD 文档同样走地址规则，CIMD 文档必须有路径），`none` 写了其中任何一个都是错误（写了又被忽略的一行，是一个错误的信念）。动态注册是 `client.dynamicRegistration: true` 的明确选择，缺省关，只允许用于 `cimd`（它是服务器不接受 CIMD 地址时 B2 的退路），对 `preregistered` 无意义，也是错误 |
| D5 | **对网关：每条连接一个端点，按路径：`/mcp/<连接 id>`** | 端点 URL 是 `IDP_BRIDGE_BASE_URL` 加 `/mcp/<id>`，网关把每条连接登记为一个 external 服务器，服务名与端点都是它。**受众就是这个 URL**，所以给 A 连接签的断言在 B 连接是 403（有测试）。**为什么不是每连接一个主机**：主机一条连接一个，要通配的 DNS 或每条连接一个 Service 名、证书与 Ingress 条目，增加一条连接就是一次基础设施变更；而网关的 `IDP_BRIDGE_ENDPOINTS` 本来就接受地址前缀（idp-mcp D50），一个前缀 `http://idp-mcp-bridge.idp-mcp-bridge.svc.cluster.local:8680/mcp/` 就覆盖全部连接，"指向桥的必须是 external"这条检查对新增的连接自动生效。路径方案的代价：所有连接共享一个端口与一个网络策略，由断言的受众来区分；这正是断言要承担的区分。其他路径、`/mcp`、`/mcp/<id>/x` 都是 404 |
| D6 | **地址规则与测试例外：idp-web 的规则，只多一条"只许 https"** | `internal/addr` 是 idp-web 的复制（IANA 特殊用途地址注册表的全部"非全球可达"段，数字写法古怪的 IP、用户名密码、非 80/443 端口都拒绝）。配置里的地址（端点、issuer、CIMD 文档）经 `addr.TargetWith` 解析，再要求 https（第三方的凭据要走这条线）、没有片段、端点与 issuer 没有查询串；于是第三方只能在 443 端口。`IDP_BRIDGE_TEST_ORIGINS`（精确的 `host:port`，通配符、缺端口、空主机都是错误）只用于验收：只豁免端口规则、公网规则与"只许 https"，同一主机的另一个端口、同一端口的另一个主机、重定向到别处都不豁免；启动时日志警告；`tests/deploy` 保证发布的清单里没有它 |
| D7 | **出口：只连检查过的地址，不跟随重定向，不读环境代理，可选企业代理** | `internal/egress` 是桥唯一的外联方式。拨号时解析一次，**任何一个**答案不是公网地址就拒绝（一个名字有一个私网答案，就是一个属于对方的名字），再对检查过的那个 IP 拨号，TLS 按请求的主机名验证证书；端口在拨号处再检查一次。**不跟随任何重定向**：跟随会把成员的令牌带到应答指向的地方，而地址规则只判断了第一个地址；第三方搬了端点是运维改配置的事。`DisableCompression`（读取有上限，压缩的体会是炸弹）、不读 `HTTP(S)_PROXY`。**企业代理**（`IDP_BRIDGE_EGRESS_PROXY`，http(s)://主机:端口，不带凭据）：设了之后桥只连这个代理（精确的主机与端口，不做地址检查），它之后连到哪个地址桥看不到，所以**代理必须自己拒绝非公网目的地**，网络策略要换成只放代理的规则（RUNBOOK 第 7 节）；配置文件里的地址仍然检查。代理的凭据不放进地址（进程列表看得见），需要认证的代理留给 B2 之后 |
| D8 | **对第三方的客户端：只转发 `tools/list` 与 `tools/call`** | `server/discover` 由桥自己回答（网关登记与探测问的是"这个服务器说不说 2026-07-28、有没有工具"，这是桥的事实；第三方不说 2026-07-28 会在 `tools/list` 暴露）。`tools/list` 翻页（至多 20 页、500 个工具）合成一个结果；每页都过 D11。`tools/call` 的工具名至多 256 字节、没有控制字符（它进正文与 `Mcp-Name` 头；非 ASCII 的名字用规范的 Base64 形式）。一个请求一个连接上的一个 id，无需唯一性 |
| D9 | **发给第三方的东西：从白名单构造，不是从调用者的请求里清理** | 与网关对 external 目标的 `externalParams` 同一条规则（idp-mcp D51 b），在桥这一跳再执行一次，因为网关对指向桥的目标要发断言（任务 G1），"不外传身份"改由桥执行。正文：`name`、`arguments`（原样）、`_meta`；`_meta` 只有三个键：协议版本、客户端能力（固定 `{}`）、调用者的进度令牌（字符串且不超过 128 字节、或整数，否则丢弃）。**顶层不放任何别的 param**（`task`、`inputResponses`、`requestState` 和调用者编的都不放；比网关的"去掉这三个"更严，因为桥构造的是新对象，不是过滤旧的）。请求头：`Content-Type`、`Accept`、`MCP-Protocol-Version`、`Mcp-Method`、`Mcp-Name`、固定的 `User-Agent: idp-mcp-bridge`（说明是哪个产品，不说是谁在用，也没有版本）、有令牌时的 `Authorization: Bearer`；**没有** `traceparent`、`tracestate`、`baggage`、`Mcp-Param-*`、`Cookie`，网关请求上的任何头都不带。`Mcp-Param-*`（SEP-2243）是客户端提供的、桥不知道哪些是工具声明的，所以 B1 不转发；代价是依赖这些头的第三方工具会拒绝调用，遇到具体服务再按工具的 schema 构造。测试：`TestTheThirdPartyReceivesNoIdentityNoAssertionNoCustomMetaNoTraceHeaders` 对请求头做白名单断言，对正文做"没有租户、成员、断言、追踪值"的子串断言 |
| D10 | **第三方回来的东西：有上限，逐条判断，请求一律拒绝** | 一次普通应答至多 `IDP_BRIDGE_MAX_RESULT_BYTES`（缺省 1 MiB），流里的一个事件同样；一条流读到的全部字节至多 `IDP_BRIDGE_MAX_STREAM_BYTES`（缺省 4 MiB，注释行与保活行也算，读到上限就不再读：一个没有尽头的流只占一块缓冲，直到上限或调用时限）；上限在 1 到 16 MiB，事件上限不得大于流上限。数字就是网关对 external 目标的（idp-mcp D51 d），因为桥交出去的结果要被网关在同样的上限下读。逐条判断（`classify`，网关同名函数的改写）：流里的 JSON-RPC 请求（`sampling/createMessage`、`elicitation/create`、`roots/list`、`ping`）、`resultType: "input_required"`、`resultType: "task"`，都使这次调用以工具错误结束（桥自己的措辞，方法名只在固定的几个里取），第三方的任何内容不转发；通知（进度也在内）丢弃，因为桥的端点只回答普通 JSON（进度令牌仍然转发给第三方，进度本身 B1 不转给网关）；`resultType` 只收 `complete` 或缺省。第三方的 JSON-RPC 错误：保留错误码、消息截到 512 字节、不要 `data`，作为工具错误告诉模型（工具错误会被 HOST 当作不可信的工具结果包装，协议错误不一定）。状态码：401 保留 `WWW-Authenticate`（B2 的发现要用）；3xx 是重定向，不跟随；其他非 200 且没有可用错误体的，是状态错误 |
| D11 | **平台命名空间 `io.idp.telos/` 的键在第三方的结果与工具元数据里被删除** | 只有桥、网关与平台可以设这样的键（`io.idp.telos/external` 是网关写的类别标记，HOST 信它；`io.idp.telos/authorizationRequired` 是桥的）。删除在**任意深度**、**不论值**：结果与每个工具的元数据、注解、schema、`structuredContent` 都过一遍，解码再编码，所以重复的键（一个解析器看见、另一个看不见）折叠成一个，数字保持原样（`UseNumber`）。桥自己写的 `authorizationRequired` 不经过这个函数（它不是第三方的结果）。网关对 `io.idp.telos/external` 另有覆盖（idp-mcp D51 h），这一条是桥这一跳的第二道 |
| D12 | **限流：每连接、每成员的滑动窗口，在内存里，按副本** | 与 idp-web D22 同一个形状：窗口、每连接次数（所有成员合计）、每成员次数，缺省 60 秒、300、60，上限 1 小时、10 万。两个范围一起判断，**被拒绝的调用两边都不记**（一个被自己的上限拒绝的成员不占连接的额度）。超限时调用以工具错误结束，文字写明多少秒后可再试、并让模型用已有的内容回答。没有成员的请求（`tools/list` 的探测）只数连接。每次运行的上限做不到（断言里没有运行号），HOST 的步数限制兜底。N 个副本时一个成员最多可做 N 倍的调用；第三方自己的限额才是精确的上限。成员表有大小上限 |
| D13 | **熔断器：每连接一个，连续失败后断开，暂停后半开；令牌来源是接口** | 连续 `failures` 次（缺省 5）失败后断开，暂停 `openSeconds`（缺省 30 秒）后放一个试探调用过去（半开时其余调用被拒），试探成功就关上，失败就再断开一个暂停；调用方走了（上下文取消）不算失败，试探要还回去。**什么算失败**（`upstream.Counts`）：第三方没有应答（连不上、地址被拒、超时）、应了 5xx、应的不是应答（不是 JSON 或事件流、不是这个请求的应答、重定向）；第三方答"不"（401、403、4xx、JSON-RPC 错误、工具自己的错误）、结果太大、请求第三方对客户端发起，都是应答，不算失败。`tools/list` 也在同一个熔断器后面（网关每分钟探测一次，对一个已经倒下的第三方不该再压）。断开时调用以工具错误结束，写明多少秒后重试。指标里有 `idp_bridge_breaker_state{connection}` |
| D14 | **"需要授权"：工具错误，只带连接 id，从不带地址；先查令牌，再限流，再熔断，再调用** | `auth.TokenSource.Token(ctx, subject, connection)` 返回 `ErrNoToken` 时，调用以 `isError: true` 的工具结果结束，文字告诉模型成员要先在 Workspace 连接这个服务、再问一次、在那之前不要重复调用，`structuredContent` 是**恰好** `{"io.idp.telos/authorizationRequired":{"connection":"<id>"}}`。**不带地址**：Workspace 自己构造指向自己页面的链接；从结果里来的地址可能是钓鱼链接，模型可能被引导着把它展示给成员（有测试：整个应答里没有 `://`）。**第三方一次请求也收不到**（有测试：`Requests()` 为 0）。检查次序：先令牌——没有授权的成员不占连接的额度、不动熔断器；之后限流（保护桥与第三方），再熔断，再调用。第三方答 401 且有令牌时：向来源要一次新令牌（`Refresh`，传入被拒的令牌），有就重试一次，没有（`ErrNoToken`）或重试仍是 401，就是"需要授权"；至多一次，每次调用。对 `mode: none` 的连接，第三方答 401 不是"需要授权"（成员授权不了一个没配置授权的连接），答"这条连接没有配置成给出它要的凭据，请告诉运维"。`TokenSource` 要的 `Subject` 只来自校验过的断言：跨成员、跨租户（同主体、另一租户是另一个成员）各有测试，调用的参数与 `_meta` 都不能指定成员 |
| D15 | **令牌存储的接口：`grants.Store` 与 `grants.Sealer`，B1 只声明** | 一行一个（租户、成员、连接）：密封后的访问令牌与刷新令牌（`Sealer` 的产物，AES-GCM，每个部署一把密钥、来自 Secret、轮换时第一把加密全部可解；附加数据绑定（租户、成员、连接），拷到别人的行里解不开）、访问令牌到期时间、发行它的 issuer 与授予的 scopes（与配置不同就不再使用，成员重新授权）、时间戳。方法：`Get`、`Put`、`Delete`（成员断开）、`DeleteMember`（成员离开租户）、`DeleteConnection`（运维撤下连接）、`ForMember`（Workspace 的页面）。**存储不接触明文**：它保管的是 `Sealer` 做出来的东西，所以数据库泄露或备份泄露得到的是密文，密钥在数据库没有的 Secret 里。B1 的实现 `grants.Unimplemented` 每个方法都返回 `ErrNotImplemented` |
| D16 | **Workspace 调用的内部 API：声明路由与类型，B1 一律答 501；认证规则写在这里** | 路由（在自己的端口 8681 上，所以网络策略能让网关只到一个、Workspace 只到另一个）：`GET /internal/v1/connections`（列出这个成员可用的连接与状态：`not_required`、`not_connected`、`connected`、`reauthorization_required`）、`POST /internal/v1/connections/{id}/authorization`（开始授权，返回授权地址，给 Workspace 重定向成员的浏览器）、`POST /internal/v1/connections/{id}/callback`（Workspace 核对登录成员就是发起的人之后，交来 `code`、`state`、`iss`）、`DELETE /internal/v1/connections/{id}/grant`（断开）。**认证规则**：Workspace 带**成员自己的令牌换成的、受众是桥的令牌**调用，与它调 idp-host 的方式相同（idp-workspace D16：RFC 8693，Workspace 是请求方客户端，按令牌摘要与受众缓存）；桥**自己**对 Keycloak 的密钥验证它：签名、issuer、有效期、受众包含桥自己的、`azp` 是 Workspace 的客户端而不是别的客户端、租户与主体声明；成员只来自令牌，路径、查询、头、正文里没有任何东西指名成员；没有令牌或令牌不好都是 401 且不说是哪一项。不接受网关的断言（它是另一个受众、为工具调用签的），也不接受 Workspace 自己的服务凭据（授权的是成员）。**OAuth 的重定向地址是桥的配置，不是请求的字段**：能指定它的调用者能把授权码送到自己的地址。B1：没有令牌是 401，有令牌（`api.Unimplemented` 的 `Authenticate` 与 `Service` 都返回未实现）是 501 与 `{"error":"not_implemented"}` |
| D17 | **审计与指标：一次调用一行，没有参数、结果、令牌** | 审计行（`msg: "audit"`）：`tool`（截到 64 字节）、`connection`、`tenant`、`member`（租户加主体的 SHA-256 前 4 字节，idp-web D4 的写法，不是主体）、`outcome`、`bytes`（读自第三方的字节数）、`ms`。`outcome` 是固定的一组（RUNBOOK 第 6 节）。指标：`idp_bridge_calls_total{connection,outcome}`、`idp_bridge_call_seconds_total{connection}`、`idp_bridge_result_bytes_total{connection}`、`idp_bridge_breaker_state{connection}`；标签只有配置里的连接与固定的 `outcome`，调用者不能撑大表。令牌只出现在桥到第三方那一跳的 `Authorization` 头里：不在日志、不在错误（客户端的错误去掉了 `*url.Error` 里重复的地址，错误文字里没有地址与令牌）、不在指标、不在给模型的任何文字里（有测试） |
| D18 | **设置、监听与镜像** | 全部是环境变量（`cmd/idp-mcp-bridge/main.go` 的注释逐项列出），密钥来自文件。三个监听：`IDP_BRIDGE_LISTEN`（`/mcp/<id>`，缺省 127.0.0.1:8680）、`IDP_BRIDGE_API_LISTEN`（缺省 8681）、`IDP_BRIDGE_METRICS`（缺省 9680），非回环地址需要 `IDP_BRIDGE_PRIVATE_NETWORK=true`（运维声明只有网关与 Workspace 到得了），三个地址必须不同。配置错误（缺设置、文件无效、连接无效）写到 stderr，退出码 2；`/readyz` 在配置载入后就绪。`idp-mcp-bridge check-config` 校验后列出每条连接与它的受众。镜像：`FROM scratch`，用户 65532，宿主上静态编译再 `docker build --network none`（`deploy/build.sh`），与 idp-web 相同 |
| D19 | **Kubernetes 清单与网络策略** | 命名空间 `idp-mcp-bridge`（restricted，带 `idp-mcp/mcp-upstream` 标签），只有它在里面。默认全拒；DNS；**入口**：8680 只放网关与注册服务，8681 只放 `idp-workspace` 命名空间里的 `workspace`，9680 只放 `observability`；**出口**：公网 IPv4 的 443，减去 `internal/addr` 拒绝的全部 IPv4 段（与 idp-web 的清单相同的 excepts，`tests/deploy` 对整个 IPv4 空间每个 /24 比较代码与策略）；别的什么都出不去（不是 Kubernetes API、不是别的命名空间）。发布的 `connections.yaml` 没有连接，服务在没有连接时不启动：哪些第三方会收到成员的 Agent 发出的内容是运维的决定。镜像是占位的、按摘要固定。清单里没有密钥、没有 `IDP_BRIDGE_TEST_ORIGINS`、没有设代理。`tests/deploy` 检查：对象的命名与命名空间、加固（非 root、只读根文件系统、去掉全部能力、无服务账号令牌）、端口与探针、挂载与设置一致、没有测试专用的东西、没有密钥材料、README 里的示例是服务接受的文件 |
| D20 | **B1 不做的**（B2 已做：令牌、数据库、加密、Keycloak 验证，D21 到 D32） | 令牌（B2）；评审账号（B3，`ReviewerSource` 已声明，`NoReviewer` 不带令牌，`oauth` 连接的 `tools/list` 因此通常是 401，桥答"需要评审账号"）；进度通知转给网关（端点只回答普通 JSON）；`Mcp-Param-*` 转发；旧版本协议（计划第 6 节）；需要认证的出口代理；数据库、加密、Keycloak 验证 |
| D21 | **发现：钉死的 issuer 是锚，资源与元数据都要与它对上，对不上就拒绝、说是哪一项、不跟随** | 每条连接、缓存 1 小时（失败不缓存；令牌端点没有应答时丢弃，下次重新发现）。**(1) 受保护资源元数据**（RFC 9728）：先取一次不带令牌的 `tools/list` 的 401 里 `WWW-Authenticate` 的 `resource_metadata`（探测请求走 B1 的客户端：不带身份、不带令牌），否则按路径插入的 well-known（`/.well-known/oauth-protected-resource/<端点路径>`），再否则根下的；`resource_metadata` **必须在端点自己的源上**（`resource_metadata_origin`，否则拒绝，不去取）：授权服务器是谁由资源的源和钉死的 issuer 决定，不由一个头决定。元数据的 `resource` 经规范化（小写的协议与主机、去掉默认端口与片段）后**必须等于**连接端点的规范形式（`resource_mismatch`；带不带结尾斜杠也算不同，父路径也不行），`authorization_servers` 必须**含有**钉死的 issuer（`issuer_not_listed`，逐字比较）。**(2) 授权服务器元数据**（RFC 8414，然后 OpenID 发现）：候选地址按 issuer 的路径构造（根：`/.well-known/oauth-authorization-server`、`/.well-known/openid-configuration`；有路径：把 well-known 插在路径前（OAuth 与 OpenID 各一）、再是路径后附加 `/.well-known/openid-configuration`）；某个地址 200 且是元数据就用它，4xx 与不是元数据的换下一个，5xx 与网络错误停止（可重试）。其中 `issuer` **必须逐字等于钉死的**（`issuer_mismatch`；结尾斜杠也算不同），不一致就拒绝，**不去找别的地址、不跟随**。授权、令牌、撤销、注册端点都要过 B1 的地址规则（https、公网，测试例外）；元数据必须在 `code_challenge_methods_supported` 里列 `S256`（`pkce_unsupported`），`grant_types_supported` 若有要含 `authorization_code`。**(3) 请求**：`oauth.Fetcher` 走 D7 的检查过的拨号，只许 https（测试例外），响应体不超过 256 KiB，只跟随**同源且不改方法**的重定向（GET 跟 301、302、303、307、308，POST 只跟 307、308，至多 3 次；其他是 `redirect_refused`）。错误只有固定的码，对方说的话与地址不进给成员的答案 |
| D22 | **客户端身份：CIMD 为主，预注册为辅，动态注册只在明确开启时** | `cimd`：授权服务器元数据有 `client_id_metadata_document_supported: true` 时，`client_id` 就是连接文件里 `client.document` 的地址，公共客户端，`token_endpoint_auth_method: none`（请求里带 `client_id`，没有密钥）。**文档的内容是桥的**：`GET /internal/v1/connections/{id}/client-metadata` 由配置生成（`client_id`、`client_name`、`redirect_uris`＝`IDP_BRIDGE_REDIRECT_URI`、`grant_types`、`response_types`、`token_endpoint_auth_method`），Workspace（W1）把它公开在 `client.document` 的地址上，所以文档不可能与桥发出的请求不一致。服务器不支持 CIMD：连接开了 `dynamicRegistration: true` 且有注册端点才动态注册（RFC 7591：公共客户端，一次，每（连接、issuer、重定向地址）一行，密钥密封），否则 `client_identity_unsupported`。`preregistered`：密钥每次从 `secretFile` 读（不缓存、不进日志）；认证方式按授权服务器的 `token_endpoint_auth_methods_supported`：缺省或含 `client_secret_basic` 用 Basic（id 与密钥先按 `application/x-www-form-urlencoded` 编码，RFC 6749 2.3.1），否则含 `client_secret_post` 用表单，否则 `client_identity_unsupported`。令牌与刷新请求都用同一个身份 |
| D23 | **开始授权与回调：PKCE、`state`、`resource`、`iss`；重定向地址是配置；回调落在 Workspace** | **重定向地址**：`IDP_BRIDGE_REDIRECT_URI`，所有连接共用，公网 https（测试例外），不是任何请求的字段；回调按 `state` 找到连接，路径里的 id 与 `state` 记的不同则拒绝（`invalid_state`，该 `state` 已用掉）。**开始**（`POST .../authorization`）：成员取自已认证的令牌，**从不取自正文**；PKCE S256，验证码 32 随机字节（43 字符）；`state` 32 随机字节；写入 `pending_states`：`state` 的 SHA-256（库里没有 `state` 本身）、租户、成员、连接、**密封的**验证码、issuer、重定向地址、范围、client_id、resource、到期（10 分钟）。范围：**恰好是**连接文件的 `scopes`（**没有配置就不带 `scope` 参数**；资源元数据的 `scopes_supported` 只在连接明确写 `scopesFromResource: true` 时才用，D37），升级后再并上授权库记的需要的范围；范围非空且授权服务器的 `scopes_supported` 含 `offline_access` 时追加它并带 `prompt=consent`（SEP-2207，与 SDK 一致）。返回**只有授权地址**：授权端点加 `response_type=code`、`client_id`、`redirect_uri`、`state`、`code_challenge`、`code_challenge_method=S256`、`scope`、`resource`（RFC 8707，取连接端点的规范形式）。**回调**（`POST .../callback`）：(1) `state` 在**一条语句里**取出并删除，条件是它属于调用的租户与成员（别人拿来的不消耗，也与"从来没有过"不可区分：不能被用来使别人的授权失效，也不是探测的口子）；(2) 连接、到期（`state_expired`）、issuer 与重定向地址与现在的配置一致（`configuration_changed`）；(3) `iss`（RFC 9207）：有则必须**逐字**等于钉死的 issuer，授权服务器元数据声明 `authorization_response_iss_parameter_supported` 时必须有，在用 `code` 之前检查，也对 `error` 的回调检查；(4) `error` 映射到固定的一组（`access_denied`、`invalid_scope`、`server_error`、`temporarily_unavailable`、`invalid_request`、`unauthorized_client`、`unsupported_response_type`，其他 `authorization_failed`），`error_description` 从不读；(5) 令牌请求：`grant_type=authorization_code`、`code`、`redirect_uri`、`code_verifier`、`resource` 与客户端认证；(6) 应答校验：`token_type` 不区分大小写是 Bearer、有 `access_token`、`expires_in`（缺则不知道到期）、`refresh_token`、`scope`（缺则按 RFC 6749 5.1 就是请求的）。成功写入授权库 |
| D24 | **令牌的密封：AES-256-GCM，一个密钥文件，当前密钥加密，所有密钥解密，附加数据绑定拥有者** | `internal/sealer`。密钥文件每行 `<id>:<32 字节 base64>`，第一行是当前的。密文：版本、密钥 id、随机数、密文；**附加数据**是（租户、成员、连接、密钥 id），每段带长度（`"ab"+"c"`与`"a"+"bc"`不同）：拷到别的成员、别的租户、别的连接的行里解不开，改了密文里的密钥 id 也解不开。新行与每次刷新用当前密钥；旧密钥仍能解；`idp-mcp-bridge reseal` 把不在当前密钥下的授权与动态注册密钥重新封一遍，之后旧密钥才能从文件里删（RUNBOOK 5.3）。解不开的令牌是系统故障（"凭据暂时读不出来"的工具错误），**不是"需要授权"**：不要因为一个密钥配错了让全体成员重新授权。进行中授权的验证码同样密封 |
| D25 | **授权库：PostgreSQL（pgx v5）；建表的角色与服务运行的角色分开，服务从不执行 DDL，也不在启动时迁移** | 桥是平台里最敏感的存储（每个成员的第三方令牌），进程若被攻破，能拿到的库权限必须最小。做法与 idp-web、idp-mcp、idp-host 相同。**所有者角色**（DBA 建库时给）只用于一次性的迁移 Job：它的 URL 在 Secret `idp-mcp-bridge-database-owner` 里（`IDP_BRIDGE_MIGRATION_DATABASE_URL[_FILE]`），只有 Job 挂载，Deployment 没有。`idp-mcp-bridge migrate`：用所有者的 URL，咨询锁串行、一个事务一个文件、`schema_migrations`；迁移文件建三张表（`grants`、`pending_states`、`client_registrations`），建角色 `idp_bridge_app`（NOLOGIN、NOBYPASSRLS），**只给它这三张表的 SELECT、INSERT、UPDATE、DELETE，以及 `schema_migrations` 的 SELECT，别的什么都不给**。`idp-mcp-bridge ensure-login USER`（所有者 URL，密码在 `IDP_BRIDGE_APP_DB_PASSWORD[_FILE]`）建或更新登录角色，它是 `idp_bridge_app` 的成员（LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE），服务用它（`IDP_BRIDGE_DATABASE_URL`）。**服务只检查，不迁移**：`grants.Open` 拒绝启动，如果库的版本不等于这个二进制要的（更旧或更新都拒绝，信息写明先跑 migrate），或者连接的角色能改库（超级用户、BYPASSRLS、对当前 schema 有 CREATE、拥有 schema 里的表，每一项都拒绝）；只有 `migrate` 命令调用 `grants.Migrate`（`tests/deploy` 数源码里的调用点）。升级的顺序：先跑 Job、再滚动 Deployment；库的版本与二进制要求的必须相等。连接带 TCP 保活与用户超时（idp-web 的 `guardDial`），失联的对端几十秒内被发现。一条语句或事务受 5 秒限制，刷新除外（持锁等对方的令牌端点，受 20 秒限制）。`/readyz` 在库不应答时是 503。没有 oauth 连接就不连库。**测试**：集成测试以应用角色运行服务（`pgtest.Scratch` 返回所有者 URL 与服务 URL）；一个测试用服务角色的连接执行 `CREATE TABLE`、`CREATE SCHEMA`、`DROP TABLE`、`ALTER TABLE`、`TRUNCATE`、`CREATE INDEX`、改 `schema_migrations`、`CREATE ROLE`、`CREATE FUNCTION`，全部被拒，而它该做的操作成功；另有测试证明用所有者 URL 打开会被拒，库的版本比期望的旧或新都拒绝启动 |
| D26 | **令牌来源：提前 60 秒刷新，跨副本每个授权同一时刻只有一个刷新，轮换要认，`invalid_grant` 删除授权** | `Token`：授权的 issuer 不是连接现在钉死的、或有重新授权的原因，是 `ErrNoToken`；到期前超过 60 秒直接用；否则（或第三方答 401 之后 `Refresh(rejected)`）进入 `renew`。**`renew` 在 `SELECT … FOR UPDATE` 的行锁下进行，锁住之后按行里现在的内容决定**：被拒绝的令牌已经不是行里的（别人刷新过了）、或提前刷新时已经不临近到期了（别人在等锁的时候刷新了），就用行里的，不再刷新：**第二个等锁的人用第一个人的结果**，所以对方在轮换时作废旧刷新令牌的情况下，刷新令牌只用一次（测试：两个副本、六个并发调用、授权服务器作废被轮换的令牌，授权服务器只收到一次刷新）。刷新请求：`grant_type=refresh_token`、`refresh_token`、`resource`、客户端认证；应答没有 `refresh_token`＝没有轮换，保留旧的，没有 `scope`＝没变（RFC 6749 6）；**新令牌在同一个事务里写入**。`invalid_grant`：删除授权，`ErrNoToken`，成员被告知重新授权。对方没有应答（网络、5xx、429）：令牌还没过期就继续用（刷新是提前做的），已经过期或刚被拒绝则是"请稍后再试"的工具错误，授权保留。没有刷新令牌且已过期：`ErrNoToken`，授权保留，列表里原因是 `expired` |
| D27 | **升级范围：第三方答 403 加 `error="insufficient_scope"`，就是"需要授权"，授权记下需要的范围** | 桥解析 `WWW-Authenticate` 的 Bearer 质询（RFC 9110、6750：引号串、转义、逗号），`error` 是 `insufficient_scope` 且这次调用带着令牌时，调用 `StepUpper.InsufficientScope`：授权行**保留**，`needed_scope`＝已授予的范围、已记的需要的范围与质询的 `scope` 的并集（SEP-2350），`reauth_reason`＝`insufficient_scope`；此后这个授权不再被使用（`Token` 给 `ErrNoToken`），直到成员再授权；**再授权请求的范围是配置的范围与 `needed_scope` 的并集**，成功后新授权替换旧的。答复是 B1 的同一个标记（只有连接 id）。**没有这个 `error` 的 403 仍是"被拒绝"的工具错误**，不动授权，也不计入熔断。列表里这个连接显示"需要重新授权"，原因 `insufficient_scope` |
| D28 | **Workspace 内部 API 的认证：桥自己用 Keycloak 的密钥验证换来的令牌** | `internal/idauth`（D16 的规则，实现）：JWKS（缓存 10 分钟，未知 `kid` 最多每 30 秒重取一次，已取到的密钥在 Keycloak 暂时不可达时继续有效）、只收非对称算法（RS/PS/ES）、`iss` 逐字等于 `IDP_BRIDGE_OIDC_ISSUER`、`aud` 含 `IDP_BRIDGE_API_AUDIENCE`、`exp` 必需（容差 30 秒）、**`azp` 等于 `IDP_BRIDGE_WORKSPACE_CLIENT`**（没有这一条，realm 里任何别的客户端为桥的受众换来的令牌都会被接受）、`sub` 与租户声明（缺省 `tenant_id`）非空。任何一项不过都是 401，不说是哪一项。JWKS 的地址必须是 https（集群内只有 http 的要显式设 `IDP_BRIDGE_OIDC_ALLOW_HTTP=true`，启动日志警告），取 JWKS 用一个独立的客户端（Keycloak 在集群里，不是公网地址，所以不能用 B1 的出口客户端）：不跟随重定向、不读环境代理、10 秒超时、可加 CA。成员取自令牌，`api` 的路径、查询、头、正文都不指名成员（测试：正文里写别人的名字没有用） |
| D29 | **断开、撤销、成员离开** | 断开（`DELETE .../grant`）：授权服务器有 `revocation_endpoint` 时先撤销刷新令牌、再撤销访问令牌（RFC 7009，带客户端认证与 `token_type_hint`），**不论撤销成不成功都删除授权**（成员要求断开，对方的撤销端点挂了不应让他仍然连着），只记失败的码；没有授权也是 204。运维子命令 `revoke --tenant T --member M [--connection C]`：该成员的授权逐条同样处理；`revoke --connection C`：整条连接的授权直接删除（不撤销：不按连接列出，连接多半已不在文件里）。**自动清理离开租户的成员的授权不在这一期，记为开放**：身份提供方不通知桥，桥不扫描 Keycloak；离职流程必须调用 `revoke`。管理员撤销某成员的授权同样只有这个命令 |
| D30 | **列表：每条连接对调用成员的状态，不含令牌、不含授权服务器的地址** | `GET .../connections`：`id`、`title`、`status`（`not_required`、`not_connected`、`connected`、`reauthorization_required`）、`reason`（`insufficient_scope`、`issuer_changed`、`expired`）、`scope`（成员授予的）。测试里整个答案不含任何令牌、授权服务器的地址或端点路径 |
| D31 | **日志、指标、错误、审计、API 答案里没有令牌、授权码、验证码、`state`、客户端密钥（授权地址除外）** | 授权地址带 `state` 与挑战是设计如此，只给 Workspace，不进日志（API 日志与审计不记答案）。OAuth 的日志只写（连接、租户、固定的码）；`oauth.Error` 的 `Detail` 是桥自己的话（可含元数据里的地址，从不含秘密），不进给成员的答案；API 的错误是固定的码。令牌端点与撤销端点的响应体从不读进日志或错误（只读 `error` 的固定集合）。测试 `noSecretsAnywhere`：把测试里捕获到的一切（日志、指标、每个 API 答案与 MCP 答案）对授权服务器替身签发过的每个令牌、刷新令牌、授权码、客户端密钥做子串搜索，在成功与每种失败（错的 iss、授权被拒、令牌端点 500、`invalid_grant`、撤销失败）之后；并有一个"日志里确实有内容"的检查，防止搜索空转 |
| D32 | **设置、清单与命令** | 新设置见 RUNBOOK 第 5 节与 `main.go`：`IDP_BRIDGE_DATABASE_URL[_FILE]`、`IDP_BRIDGE_ENCRYPTION_KEYS_FILE`、`IDP_BRIDGE_REDIRECT_URI`、`IDP_BRIDGE_OIDC_ISSUER`、`IDP_BRIDGE_OIDC_JWKS_URL`、`IDP_BRIDGE_OIDC_ALLOW_HTTP`、`IDP_BRIDGE_OIDC_CA_FILE`、`IDP_BRIDGE_API_AUDIENCE`、`IDP_BRIDGE_WORKSPACE_CLIENT`、`IDP_BRIDGE_TENANT_CLAIM`；有 oauth 连接时必需，没有时一个不读。子命令 `migrate`、`ensure-login`、`revoke`、`reseal`（用同一个镜像，`FROM scratch`，所以一次性 Job 而不是 exec）。清单：迁移 Job `idp-mcp-bridge-migrate`（只挂 Secret `idp-mcp-bridge-database-owner`）；Deployment 多挂 Secret `idp-mcp-bridge-database`（只有应用角色的 URL）与 `idp-mcp-bridge-encryption-keys`（都 `optional`：没有 oauth 连接时不必有），出口策略多两条：`bridge-database`（Deployment 与 Job，`databases` 命名空间的 PostgreSQL，5432）与 `bridge-keycloak`（`keycloak` 命名空间的 Keycloak 的 JWKS，8443，按你的集群调整）；入口不变（8681 只放 Workspace）。`tests/deploy` 比对这些。`make test-integration` 起一个自己的 PostgreSQL 容器，让授权流程与存储也在 PostgreSQL 上跑一遍（内存与 PostgreSQL 两个存储跑同一组测试），用完删掉 |
| D33 | **评审账号：连接的、不是成员的；运维授权，只用于 `tools/list`，从不用于 `tools/call`** | 计划第 2 节第 8 点：很多第三方连列出工具都要令牌，网关的注册、评审与漂移探测又没有成员。连接是整个部署共用的，所以评审账号是**运维的**：**每条 `oauth` 连接至多一个**。**谁可以授权**：令牌带配置的 realm 角色（`IDP_BRIDGE_REVIEWER_ROLE`，**没有缺省**，不设就没有人；平台的 realm 把 realm 角色放在 `roles` 声明里，`IDP_BRIDGE_ROLES_CLAIM` 可改）、设了 `IDP_BRIDGE_REVIEWER_TENANT` 时还要是这个租户。由 `idauth` 在验证令牌时判定，`auth.Subject.Reviewer`；网关的断言不会设它。**路由**（B2 的认证，同一个 Workspace 令牌）：`POST /internal/v1/connections/{id}/reviewer/authorization` → `{"url"}`（没有角色是 403 `forbidden`；不要令牌的连接 404）；回调仍是 `POST .../callback`：待办的 `state` 记着这是评审账号的授权和发起的运维（租户加成员，绑定同 B2），回调时**再查一次角色**（授权中途角色被收回则 403，`state` 已用掉）；`DELETE .../reviewer/grant` → 204（撤销同成员的断开：先刷新令牌、再访问令牌，不论成败都删除）；`GET .../connections` 只对有角色的调用者在每条连接上多一个 `"reviewer": {"status","reason","scope"}`（状态同成员的，不要令牌的连接是 `not_required`），别人的答案里没有这个键。**存储**：授权库的同一张表，一行，`reviewer = true`，租户与成员为空（库的 CHECK 约束保证"评审账号的行没有租户与成员，成员的行两者都有"），主键含 `reviewer`；`authorized_by` 记发起的运维（租户/成员）；**密封的附加数据含 `reviewer`**：评审账号的令牌解不出成员的，反之亦然。同一个人的成员授权与评审账号**互相独立**：各自刷新、断开、显示；成员离职（`RevokeMember`）不动评审账号，撤下连接（`RevokeConnection`）两种都删。迁移 `0002_reviewer_grants.sql`（`pending_states` 多一列 `reviewer`）。**使用**：`ReviewerSource.Token` 只被 `tools/list`（网关的列表、目录刷新）读，`CallTool` **从不**看这里（测试：评审账号存在时，没有授权的成员仍得到"需要授权"、第三方一次请求也没有收到；有授权的成员的调用带的是自己的令牌）。刷新走 B2 的同一个行锁与轮换（`renew` 对任何一种授权）；列表遇 401 时向来源要一次新令牌再试一次；刷新令牌被拒（`invalid_grant`）则删除评审授权，列表退回不带令牌（第三方答 401 时的错误写明"这条连接没有授权好的评审账号"）。评审账号的授权范围：连接文件的 `authorization.reviewerScopes`（可选，缺省用 `scopes`），**应当是能列出工具的最小范围**。**评审账号应当是什么**：第三方那里**专门为此建立的账号**（不是任何人的个人账号，不属于会离职的成员），只有列出工具所需的最小权限（只读，不能访问成员的数据；有的服务有"仅元数据"的范围），名下没有数据；用它走一遍授权就是上面的流程。它的令牌能做的事就是列出工具，桥也只拿它做这件事，但令牌本身在第三方那里仍是一个账号的令牌，所以按最小权限建立是第一道防线，桥的限制（只用于 `tools/list`）是第二道。运维步骤见 RUNBOOK 5.6 |
| D34 | **`Mcp-Param-*` 头：由桥按工具定义与调用的参数计算，从不复制网关请求里的** | 2026-07-28（SEP-2243）：工具可在输入 schema 的属性上写 `x-mcp-header`，客户端把这些参数镜像进 `Mcp-Param-<名>` 头，声明了的服务器可以因为缺这些头而拒绝调用。idp-mcp 的网关不知道哪些头是工具声明的，只转发并限制数量与长度（idp-mcp D51 g，D12）；桥是对第三方的客户端，**知道**工具的定义，所以计算。**规则**（按规范、官方 SDK 的 `mcp/shared/inbound.py` 与 idp-mcp 的 `internal/server/protocol.go`）：注解只在**经由 `properties` 一路可达的属性**上有效（根上、`anyOf`、`items`、`patternProperties`、`$defs` 里都无效，`default`/`enum` 等实例数据不是 schema）；名字是 RFC 9110 的 token（所以不可能含冒号、空格、换行）；属性类型是 `string`、`integer` 或 `boolean`（**不是 `number`**：它的文本形式各实现不一致）；名字不区分大小写地唯一。**有任何一个注解无效的工具没有任何头**（2026-07-28 的客户端必须丢弃这样的工具）。**值**：缺失或 `null` 没有头；布尔是 `true`/`false`；整数按原样写（不经浮点，大整数不会被舍入；带小数、指数、前导零的不渲染）；字符串原样；对象与数组没有渲染；**不是可打印 ASCII、或有首尾空白、或本身像 `=?base64?...?=` 的值用 Base64 形式**（idp-mcp 的 `EncodeHeaderValue`）：所以含回车换行的值不可能结束一行头去注入另一行（测试：`eu\r\nX-Evil: 1\r\nAuthorization: ...` 到第三方是 Base64，第三方没有收到 `X-Evil`，也没有收到被换掉的 `Authorization`）。**大小**：至多 16 个头、名字（前缀之后）至多 128 字节、值（编码之后）至多 1024 字节，同 idp-mcp 转发时的上限；超出则**拒绝这次调用**（工具错误，写明哪里太长，没有请求发出，不算第三方的失败），不截断、不少发几个头（idp-mcp 同样：少几个头会让第三方因看不见的原因拒绝）。**定义从哪里来**：桥最后一次列出的目录，每条连接一份：每次 `tools/list`（网关的，或桥自己为此做的）更新；一个调用遇到**未知的工具**（目录里没有，或目录比 5 分钟 TTL 旧）时先刷新一次（用评审账号的令牌，D33），**且**连接的熔断器是关的、没有超过连接的限流、距上一次由调用引起的刷新不到 30 秒则不刷新——所以一个编造工具名的模型不能让桥去列表；刷新失败或仍然未知：**这个调用不带 `Mcp-Param-*` 头照样发出**。**从不复制**：给第三方的头仍是 D9 的白名单，`Mcp-Param-*` 只能经 `CallToolWithHeaders` 的额外头进去，且只放行这一族、每个名字一个值（测试：网关请求上的 `Mcp-Param-Region` 与别的头不被复制）。这修订 D9 与第 3 节第 3 条：`Mcp-Param-*` 不再整体不转发 |
| D35 | **再次授权时，被取代的令牌向授权服务器撤销** | D29 只说了断开与运维的撤销；再授权（`reauthorization_required` 之后、`insufficient_scope` 之后、或成员已连接时再点"连接"，评审账号同样）也会替换授权，旧授权的刷新令牌若不处理就一直有效，平台验收在授权服务器替身的记录里看到了这一点。`Finish` 在**新授权已存入之后**，对**旧授权**走与断开同一条撤销路径（`revoke`：RFC 7009，先刷新令牌、再访问令牌，授权服务器没有撤销端点则什么也不做），**不持有任何行锁**，撤销的失败**只记码**，绝不撤销已存的新授权，`Finish` 照常成功。不撤销：与新授权里相同的令牌（`keep`）、以及签发者不是连接现在钉死的 issuer 的旧授权的令牌（令牌只出示给签发它的服务器：issuer 变了，旧令牌不能发给新的服务器）。成员的授权与同一个人的评审授权各自只撤销自己的旧令牌。限制：读旧授权与写新授权之间没有锁，这个窗口里别的副本刚刷新出的令牌不会被撤销（它在这次替换之后本来也不再被使用，到期即失效） |
| D36 | **令牌端点的错误：有 `error` 的应答就是错误，不论状态码；GitHub 的两个码按 `invalid_grant` 处理（已知的偏离，只列这两个）** | RFC 6749 5.2 规定错误是 400 加 `error`；GitHub 的令牌端点（`/login/oauth/access_token`）对错误答 **200** 加 `{"error": ...}`（`bad_verification_code`：码错或已用；`bad_refresh_token`：刷新令牌过期或被撤销；`incorrect_client_credentials`、`redirect_uri_mismatch`、`unverified_user_email`）。此前桥把这样的 200 当成"令牌应答不合格"（缺 `token_type`），于是一个已死的刷新令牌永远是"暂时无法更新"，授权不会被删除、成员不会被要求重新授权。现在：`TokenRequest` 先看 5xx 与 429（可重试，同前），然后**应答体里有非空 `error` 就是错误应答，不论状态**（状态不是 200 的同前）；映射同前（固定的一组 RFC 码，其余是 `unknown`），**只读 `error`，从不读 `error_description`**。**已知偏离的映射**，明确列出、保持很小：`bad_verification_code` 与 `bad_refresh_token` 视为 `invalid_grant`（刷新时删除授权、成员被告知重新授权；换码时授权失败的原因是 `invalid_grant`）；GitHub 其余三个码（以及任何别的未知码）是令牌端点的错误，授权不删除、详情写日志里的码，**不是**死授权（测试：`incorrect_client_credentials` 的 200 不删除授权）。这个映射表对所有授权服务器生效（码只在对方真的发这些词时才出现），要加新码是一次有意的修改。**授权地址的内容**见 D37（本条原先写的"没有配置范围就取资源元数据的整串"已被 D37 取代）。|
| D37 | **最小权限：授权请求只要连接文件里配置的 `scopes`；没有配置就不带 `scope`；资源元数据的范围表只在明确选择时才用** | MCP 规范的范围选择策略（以及官方 SDK）：`WWW-Authenticate` 的 `scope`，否则资源元数据的 `scopes_supported`，否则授权服务器的。B2 按这个次序实现，连接文件的 `scopes` 为空时就去要资源列出的**全部**范围。对企业平台，这个缺省不对：运维没有列范围，却会向成员要第三方提供的一切，可能包括写权限（用 OAuth App 而不是 GitHub App 连 GitHub，会要 `repo`、`write:packages`、`gist`……）。**这是有意偏离规范的 SHOULD。**新规则：授权请求要**恰好是**连接配置的 `scopes`（评审账号：`reviewerScopes`，没有则 `scopes`，同一条规则，没有回退）；没有配置就**没有 `scope` 参数**，也就没有 `offline_access` 与 `prompt`（`offline_access` 只在范围非空、且授权服务器的 `scopes_supported` 含它时追加，同前）。资源元数据的 `scopes_supported` 只在连接写了 `authorization.scopesFromResource: true`（缺省 false；`mode: none` 的连接写它是错误）时才作为 `scopes` 为空时的回退——这是运维对"要第三方列出的全部"的明确同意。**升级范围（D27）仍然并入第三方质询里的 `scope`**：那是第三方在 403 之后点名要的某一个范围，成员会在同意页上看到；但它**可能扩大授权**（一个行为不端的第三方可以一再要求更大的范围），所以桥把**新增的范围名**写进日志（只有范围名，且只有合法的 RFC 6749 范围记号，`scope asked for by the third party's challenge`，带连接与租户），运维可以据此发现。GitHub App 忽略 `scope`（权限在 App 的设置里），所以 `scopes: []` 是 GitHub 的正确写法。测试：七种组合（没有配置：有无资源列表、有无 `offline_access` 都没有 `scope`；选择加入：用资源的列表；配置的优先；评审账号同样），升级仍然并入、日志里有新增的名字 |
| D38 | **"成员离开"接口：只许平台的服务，用 OIDC 客户端凭据令牌；处理与 `revoke` 命令相同；幂等** | 计划 `idp-mcp-bridge-offboarding-plan.md` 第 1、2 节。`POST /internal/v1/members/offboard`，正文 `{"tenant","member","reason"}`，`reason` 是固定的一组：`user_deleted`、`user_disabled`、`tenant_changed`、`operator`、`other`（别的值与多余的字段都是 400）。**认证**：调用方用 OIDC 客户端凭据模式取得服务令牌；桥用现有的发行方与公钥验签（同 D28：签名、issuer、受众、`exp`），要求 `azp` 在 `IDP_BRIDGE_OFFBOARD_CLIENTS`（逗号分隔）里；**这个名单为空则接口不存在（404）**。令牌无效是 401；有效但不是服务的（`azp` 不在名单里，或令牌属于一个成员：有会话 `sid` 或是委托 `act`，或是 Workspace 换来的成员令牌，其 `azp` 是 Workspace 的客户端）是 403。限制要写明：桥靠 `azp` 名单与"没有会话、不是委托"区分服务与成员，所以名单里应当只放专用的服务客户端，不要放会签发成员令牌的客户端。**处理**（`oauth.Service.Offboard`，`revoke` 命令也走它）：对成员的每个授权，向授权服务器撤销（刷新令牌在先、访问令牌在后，D29，GitHub 连接见 D42），不论撤销成败都删除授权；删除成员未完成的授权状态；标记他授权的评审账号（D40）；一个连接的 `revoke --connection` 限定到那一条连接时不算离开，不动未完成的授权与评审账号。**幂等**：重复调用、成员本来就没有授权，都是 200 加零。**答案只有计数**：`{"grants_removed","revocations_failed","reviewer_grants_marked"}`，没有令牌、没有授权服务器的地址。**审计与计数**：一行 `audit`（`event: offboard`，租户、成员的哈希前缀、`reason`、`source`（route、reconcile、command）、`caller`（服务的 `azp`）、连接、授权数、撤销失败数、状态数），计数器 `idp_bridge_offboard_total{reason,source}`、`_grants_removed_total`、`_revocation_failed_total`。**不由安全闸限制**（一次一个成员），但每次都写审计 |
| D39 | **兜底对账：目录适配器是接口；Keycloak 适配器只用于开发测试；只认明确结果；安全闸；一次一个副本** | 身份系统还没选定，**核心里没有任何东西依赖 Keycloak 的管理接口**：`directory.Directory.Lookup(ctx, tenant, member)` 返回 `present`、`disabled`、`deleted`、`moved`（换了租户）、`unknown`（任何错误都是它）。`reconcile.Reconciler` 每 `IDP_BRIDGE_RECONCILE_INTERVAL`（缺省 15 分钟，`0` 关闭，至少 1 秒）一轮：把库里每个不同的（租户、成员）（只算成员自己的授权，评审账号不算）交给目录；**`unknown` 一律不动**（超时、出错、没权限、应答不像用户，记一条不带错误正文的日志，下一轮再查）；`deleted`、`disabled`、`moved` 按接口同一条路径离开，原因分别是 `user_deleted`、`user_disabled`、`tenant_changed`。**安全闸**：一轮里判定离开的成员**不少于 5 人且多于已知成员的 20%** 时，这一轮什么都不做，日志里一条 ERROR 级的告警（`reconciliation brake`）加计数器 `reconcile_brake_total`；运维核对之后用 `idp-mcp-bridge reconcile --now --force` 越过（`reconcile --now` 不带 `--force` 仍受闸约束；目录整个不可达时全是 `unknown`，不触发闸也不撤任何东西）。**一次一个副本**：一轮开始时取 PostgreSQL 咨询锁（`TryLock`，保持到一轮结束，副本死了连接断开就释放），取不到的副本这一轮是 `busy`，什么也不做。`IDP_BRIDGE_DIRECTORY=none`（缺省）没有对账；`keycloak-dev` 是 `internal/directory/keycloakdev`，**明确标为开发测试用**，启动时日志有一行说明：一个带服务账号的保密客户端（`IDP_BRIDGE_KEYCLOAK_URL`、`_REALM`、`_CLIENT_ID`、`_CLIENT_SECRET_FILE`，租户属性名 `_TENANT_ATTRIBUTE` 缺省 `tenant_id`），用客户端凭据取令牌（缓存到到期前 30 秒，401 时换一次再试），`GET /admin/realms/{realm}/users/{sub}`：404 且正文是 Keycloak 的 `User not found` 才是 `deleted`（realm 不存在的 404 不是）；`enabled: false` 是 `disabled`；租户属性不是授权的租户是 `moved`；同租户且启用是 `present`；没有租户属性、没有 `enabled`、`id` 不是这个成员、不像用户的正文、5xx、403、429、不可达，都是 `unknown`；可能是路径的成员 id（含 `/`、空）不去查。以后换成最终身份系统的 SCIM 查询（`GET /Users/{id}`）或它自己的目录接口，只是再写一个适配器。**重新启用不会自动恢复**：授权已经删除，成员要重新连接 |
| D40 | **评审账号的授权人离开：保留、标记、告警，不撤销** | 授权人（`authorized_by`）离开（接口或对账）时，撤掉评审账号会让这个服务对所有成员不可用，所以保留；迁移 `0003_offboarding.sql` 给 `grants` 加 `authorizer_left`，`MarkAuthorizerLeft` 标记他授权的评审授权；日志 `the operator who authorized a reviewer account left: re-authorize it`（WARN）与计数器 `idp_bridge_reviewer_authorizer_left_total`；运维看到的列表里这条连接的 `reviewer` 是 `{"status":"connected","reason":"authorizer_left"}`（还能用，所以仍是 `connected`）；成员的列表没有这个键。由别的运维重新授权评审账号时新授权替换旧授权，标记随之清除。评审账号的令牌**从不**因此撤销。**对账也要找到他**：授权评审账号的运维可能自己没有任何成员授权，所以一轮对账除了有成员授权的人，还查评审授权里不同的 `authorized_by`（按存下来的样子解析：第一个 `/` 前是租户、后是成员；解析不了的跳过并记一条不带内容的日志；已经标记的不再查，告警只发一次）。这样的人：仍在或查不清 → 不动；已删除、已停用、换了租户 → **只**标记评审账号（`AuthorizerLeft`，审计 `event: authorizer_left`、告警、计数器）；同时有成员授权的人照旧整个离开（接口那条路径，里面已经标记），不重复计数。他们**与成员一样计入安全闸的分母与分子**（否则一次错误的"都离开了"会标记所有评审账号） |
| D41 | **撤销没能确认：断开之后列表里如实说** | 成员断开时授权总是删除（D29），但如果向第三方的撤销失败，成员在 Workspace 里应当知道要去第三方那里自己撤销：表 `unconfirmed_revocations`（租户、成员、连接，时间），列表里这条连接是 `not_connected` 加 `reason: revocation_unconfirmed`；成员重新连接（`Finish`）时清除。只记成员自己的断开，不记离开的成员（没有人会看到）。适用于任何撤销机制，GitHub 的两个接口都失败时（D42）是它最常见的来源 |
| D42 | **GitHub 的撤销：`revocation: github`，用 GitHub 自己的接口** | GitHub 的授权服务器没有 RFC 7009 的撤销端点，成员断开、再授权、离开之后，桥里的令牌删了，GitHub 那边的刷新令牌还能用约半年。连接配置加可选的 `authorization.revocation: github`（只对**预注册的客户端**有效：GitHub 的接口用应用的客户端 id 与密钥做 Basic 认证；写在 CIMD 客户端或不要令牌的连接上是配置错误）。断开、离开（接口与对账）、`revoke` 命令、评审账号的断开：`DELETE https://api.github.com/applications/{client_id}/grant`，Basic `client_id:client_secret`，JSON 正文 `{"access_token": "<这个授权当前的访问令牌>"}`，头 `Accept: application/vnd.github+json`、`X-GitHub-Api-Version: 2022-11-28`、`Content-Type: application/json`；走检查过地址的出口客户端，应答体有界，30 秒的时限。**204 是已撤销；404 与 422 当作已经没有了**（记一条日志，带状态码，不算失败）；**别的都是失败**，失败时再试 `DELETE /applications/{client_id}/token`（只撤这一个访问令牌）；两个都失败才算撤销失败（只记状态码，授权照样删除，D29；断开时记 D41）。**访问令牌已过期怎么办（本期的选择）**：如果存着的访问令牌已经过了到期时间，而授权有刷新令牌，就**先刷新一次**再出示新的令牌，理由是这个接口靠一个它认得的访问令牌指出是哪个授权，刷新是出示一个能被接受的令牌的唯一办法，代价是多一次刷新（结果马上被撤销）；没有刷新令牌，或刷新失败，就出示存着的旧令牌（GitHub 答 404 就是已经没有了）；没过期的不刷新。**再授权（D35）不用整个授权的接口**：同一个用户对同一个应用的授权 GitHub 那边只有一个，删了它新颁发的令牌也一起没了，所以被取代的访问令牌只走 `/token` 接口。**待核实**：GitHub 现行文档说 OAuth App 与 GitHub App 的所有者都能用 `/grant`，旧版文档说它不适用于 GitHub App 的用户令牌；本期按现行文档写，用替身测，**在下一次真实 GitHub 验证之前一直记为未核实**，实测要看：`/grant` 对 GitHub App 的过期用户令牌是否答 204，答 404/422 时刷新令牌是否确实也失效，`/token` 是否同时让刷新令牌失效。如果两个接口都不行，桥会如实在列表里写"撤销未确认"（D41），日志与计数器里是失败，运维提示成员到 GitHub 的 Settings → Applications 自己撤销 |

## 3. 对计划与相邻决策的反馈（B1、B2 中发现的）

1. **计划第 5 节 B1 与第 3 节的"issuer 现在就必填"与"不需要令牌的连接已可用"互相冲突**，D4 用 `authorization.mode` 解决：issuer 对 `oauth` 必填、对 `none` 不允许。
2. **G1 要改的不止 D51 a**：（a）D50 要求 external 目标的 `identity` 是 `none`，登记时拒绝 `forward`，指向桥的要允许 `forward`；（b）`externalParams` 从白名单重建 `_meta`，只有三个键，G1 必须把断言（`io.idp.telos/caller-assertion`）作为第四个键放进去，而且只对桥的目标；（c）**断言的 `req` 摘要是对"params 去掉 `_meta`"算的**：网关在 `externalParams` 之后又把 `task`、`inputResponses`、`requestState` 去掉，摘要必须算在**发给桥的那一份**上，不是客户端发来的那一份，否则合法的调用也因摘要不符被桥拒绝；（d）受众是桥的端点（带路径）。在 G1 之前，桥的每个 `tools/call` 都是 403。
3. **`Mcp-Param-*`**：网关对 external 目标转发客户端给的那些（D51 g），桥不复制它们；B1 完全不发，依赖这些头的第三方工具会失败。**B3（D34）按工具的 schema 与参数计算。**
4. **进度**：网关把进度通知从 external 上游转给客户端（D51 c），桥的端点只回答 JSON，没有进度；进度令牌仍转给第三方。要有进度，桥要改成可以流式回答。
5. **OAuth 重定向地址**要在桥的配置里（B2 的设置），不是请求字段（D16）。
6. **评审账号**（计划第 2 节第 8 点）的探测也要过限流与熔断（D12、D13）：B3 的目录刷新同样（D34）。

**B2：官方 SDK 的客户端与本实现不同的地方**（规范页本机仍取不到，下面是 SDK 的实现与 RFC 的规则对照；与规范原文的核对仍未做）：

7. **受保护资源元数据的 `resource`**：SDK 接受"是端点的父路径"（`check_resource_allowed`：同源、路径前缀）并用 PRM 的 `resource` 作 RFC 8707 的 `resource`；本实现按任务要求要求**规范化后相等**，并总是用连接端点的规范形式作 `resource`。更严：一个把 `resource` 写成站点根的第三方会被拒绝（`resource_mismatch`）。
8. **授权服务器的选择**：SDK 取 PRM 列表里的第一个，没有 PRM 时退到资源的源（2025-03-26 的做法）；本实现只接受**钉死的** issuer，它必须在列表里，没有 PRM 就拒绝。
9. **`issuer` 的比较**：SDK 的 `issuers_match` 把根 issuer 带与不带结尾斜杠视为相同；本实现逐字比较（任务要求），所以配置里要写与对方元数据完全一样的字符串。
10. **PKCE**：SDK 不查元数据是否列了 `S256`；本实现拒绝没有列的服务器（MCP 对客户端的要求，按我的记忆，规范页没能核对）。要放宽这一条需要一个明确的决定。
11. **`resource_metadata` 的源**：SDK 直接取头里给的地址；本实现只取端点自己的源上的。真实服务把元数据放在另一个主机上的话会被拒绝（`resource_metadata_origin`），出现时再讨论。
12. **客户端密钥的编码**：SDK 的 Basic 认证对 id 与密钥做百分号编码（`quote(safe="")`，空格是 `%20`）；RFC 6749 2.3.1 写的是 `application/x-www-form-urlencoded` 编码（空格是 `+`），本实现按 RFC。只有 id 或密钥里含空格时两者才不同。
13. **刷新请求里的 `client_id`**：SDK 总是在表单里带；本实现按认证方式（Basic 不带，`client_secret_post` 与公共客户端带）。
14. **升级范围**：SDK 在调用时处理 403 `insufficient_scope`（再授权后重试）；本实现没有运行的暂停与恢复（计划选择点 3），所以是"需要授权"加授权保留，成员授权后重新提问。
15. **`offline_access` 与 `prompt=consent`**：与 SDK（SEP-2207）一致：授权服务器的 `scopes_supported` 含 `offline_access` 时追加并带 `prompt=consent`。
16. **没有刷新令牌的授权**：到期后是 `ErrNoToken`，授权行保留以便列表显示 `expired`；SDK 的做法是清除令牌。

**B2：计划里不清楚或需要决定的地方**

17. 计划第 2 节第 5 点写"回调里换令牌"，第 7 节选 Workspace 接回调：于是桥的"回调"是 Workspace 调用的 API，`state` 的所属人检查在桥里做（调用的租户与成员必须是开始授权的），Workspace 另核对登录成员；两层都要有，任何一层缺了都不够。
18. 计划没有说**授权的撤销**在第三方不支持 RFC 7009 时怎么办：只删除。没有"提示成员去第三方那里手动撤销"的机制。
19. 计划没有说**成员离开租户时谁触发清理**（第 2 节第 6 点写了"成员离开租户时删掉令牌"）：没有来源。D29 记为开放；需要身份提供方的事件或 HOST/Workspace 的钩子。
20. **评审账号的授权**用什么流程取得令牌：B3 取了同一个授权码流程，由有 realm 角色的运维在第三方那里以专门的账号登录（D33）；服务级凭据（客户端凭据模式）仍是计划第 6 节的以后的选项。
21. 第三方元数据里的 `scopes_supported` 与连接文件的 `scopes`：连接文件为准，空时才用资源元数据的（SDK 的次序里 `WWW-Authenticate` 的 `scope` 更前，本实现只在 403 `insufficient_scope` 时用质询的 `scope`，401 质询里的 `scope` 不用：它来自第三方，不应改变运维配置的范围）。
22. **动态注册的客户端是公共客户端**（`token_endpoint_auth_method: none` 请求）；服务器若指派了带密钥的方式，按它指派的用（D22）。

## 4. 反向验证

每条控制各去掉一次，看对应的测试失败，再恢复。`go test` 不带 `-race`，只跑相关的包。

| # | 去掉的控制（改动） | 失败的测试 |
|---|---|---|
| M1 | 验签的结果不看（`err = nil`） | `TestACallWithoutAnAssertionIsRefusedAndTheBackendNeverSeesIt`, `TestAForgedOrMissingAssertionIsRefusedBeforeAnythingLeaves`, `TestEveryCaseOfTheCallerAssertionVectorsComesOutAsTheFileSays` 等 |
| M2 | 不比对受众 | `TestAForgedOrMissingAssertionIsRefusedBeforeAnythingLeaves`, `TestEveryCaseOfTheCallerAssertionVectorsComesOutAsTheFileSays` |
| M3 | 不比对请求摘要 `req` | `TestAForgedOrMissingAssertionIsRefusedBeforeAnythingLeaves`, `TestEveryCaseOfTheCallerAssertionVectorsComesOutAsTheFileSays`, `TestForgedAndMalformedAssertionsAreRefused` |
| M4 | 同一个 `jti` 可以再用 | `TestAForgedOrMissingAssertionIsRefusedBeforeAnythingLeaves`, `TestEveryCaseOfTheCallerAssertionVectorsComesOutAsTheFileSays`, `TestTheGatewaysAssertionIsAccepted` |
| M5 | 不要求 `Mcp-Method` 头 | `TestTheMethodHeaderIsRequiredAndMustMatchTheBody` |
| M6 | 给第三方的请求加 `traceparent` 头 | `TestTheThirdPartyReceivesNoIdentityNoAssertionNoCustomMetaNoTraceHeaders` |
| M7 | `_meta` 里加 `clientInfo` | `TestTheThirdPartyReceivesNoIdentityNoAssertionNoCustomMetaNoTraceHeaders` |
| M8 | 客户端能力不是 `{}` | `TestTheThirdPartyReceivesNoIdentityNoAssertionNoCustomMetaNoTraceHeaders` |
| M9 | 进度令牌不检查有效性直接转发 | `TestAProgressTokenThatIsNotValidIsNotSentEvenIfAskedFor` |
| M10 | 顶层多放一个 `task` | `TestTheThirdPartyReceivesNoIdentityNoAssertionNoCustomMetaNoTraceHeaders` |
| M11 | 不删 `io.idp.telos/` 键 | `TestKeysOfThePlatformsNamespaceAreRemovedFromResultsAndToolMetadata`, `TestListToolsPagesAndBoundsThePages`, `TestSanitizeRemovesTheNamespaceAtEveryDepthAndKeepsTheRest` |
| M12 | 普通应答不设上限 | `TestOversizedAndEndlessResultsAreCut` |
| M13 | 流不设总上限 | `TestOneEventOverTheLimitAndAStreamOverTheLimitAreCut`, `TestOversizedAndEndlessResultsAreCut` |
| M14 | 一行的长度不设上限（事件上限的另一半） | `TestOneEventOverTheLimitAndAStreamOverTheLimitAreCut` |
| M15 | 流里的 JSON-RPC 请求当通知丢掉 | `TestRequestsTheThirdPartyMakesOfTheClientAreRefused` |
| M16 | `input_required` 不拒绝 | `TestRequestsTheThirdPartyMakesOfTheClientAreRefused` |
| M17 | 没有令牌时不答「需要授权」，用空令牌照样调用 | `TestAMemberArgumentCannotNameAnotherMember`, `TestAMemberWithoutATokenGetsAuthorizationRequiredAndTheThirdPartyReceivesNothing` |
| M18 | `structuredContent` 里多放一个 `url` | `TestA401IsAnsweredByARefreshOnceAndATokenThatCannotBeRefreshedMeansAuthorizationRequired`, `TestAMemberWithoutATokenGetsAuthorizationRequiredAndTheThirdPartyReceivesNothing` |
| M19 | 取令牌时丢掉租户 | `TestA401IsAnsweredByARefreshOnceAndATokenThatCannotBeRefreshedMeansAuthorizationRequired`, `TestAMemberWithoutATokenGetsAuthorizationRequiredAndTheThirdPartyReceivesNothing`, `TestAuditLinesAndMetricsHoldNoArgumentsResultsOrTokens` |
| M20 | 重试后仍是 401 时返回成功 | `TestA401IsAnsweredByARefreshOnceAndATokenThatCannotBeRefreshedMeansAuthorizationRequired` |
| M21 | 不要求名字的每个答案都是公网地址 | `TestAddressRulesRefuseANameThatResolvesToAPrivateAddressAndConnectToNothing`, `TestEveryAnswerOfANameMustBePublicAndTheConnectionIsToTheCheckedAddress` |
| M22 | 拨号处不查端口 | `TestOnlyPort80And443AreDialedUnlessTheOriginIsATestOrigin` |
| M23 | 跟随重定向 | `TestARedirectIsNotFollowedAndNothingIsSentToItsTarget`, `TestARedirectToAPrivateAddressIsNotFollowed` |
| M24 | 测试例外按主机而不是 `主机:端口` | `TestARedirectIsNotFollowedAndNothingIsSentToItsTarget`, `TestATestOriginIsExemptExactlyAndNothingElseIs` |
| M25 | 出口客户端读环境变量里的代理 | `TestEveryAnswerOfANameMustBePublicAndTheConnectionIsToTheCheckedAddress` |
| M26 | 不判每成员上限 | `TestTheLimiterSlidesAndDoesNotCountARefusal`, `TestTheRateLimitsArePerMemberAndPerConnectionAndSlide` |
| M27 | 不判每连接上限 | `TestTheConnectionLimitIsSharedAndAMemberRefusedForItDoesNotUseTheirOwn`, `TestTheLimiterIsSafeForConcurrentUse`, `TestTheRateLimitsArePerMemberAndPerConnectionAndSlide` |
| M28 | 窗口里的旧调用不过期 | `TestTheConnectionLimitIsSharedAndAMemberRefusedForItDoesNotUseTheirOwn`, `TestTheLimiterSlidesAndDoesNotCountARefusal`, `TestTheRateLimitsArePerMemberAndPerConnectionAndSlide` |
| M29 | 连续失败达到次数也不断开 | `TestTheBreakerLetsOneTrialThroughAfterThePauseAndDecidesByIt`, `TestTheBreakerOpensAfterConsecutiveFailuresOnly`, `TestTheCircuitBreakerOpensAfterConsecutiveFailuresAndClosesAfterATrial` |
| M30 | 断开后仍放调用通过 | `TestTheBreakerLetsOneTrialThroughAfterThePauseAndDecidesByIt`, `TestTheBreakerOpensAfterConsecutiveFailuresOnly`, `TestTheCircuitBreakerOpensAfterConsecutiveFailuresAndClosesAfterATrial` |
| M31 | 半开时放第二个调用 | `TestTheBreakerLetsOneTrialThroughAfterThePauseAndDecidesByIt` |
| M32 | 审计行写主体而不是哈希 | `TestAuditLinesAndMetricsHoldNoArgumentsResultsOrTokens` |
| M33 | 配置文件允许未知键 | `TestEachInvalidSettingIsRefusedForItsOwnReason` |
| M34 | 端点可以是 http | `TestEachInvalidSettingIsRefusedForItsOwnReason` |
| M35 | 配置里的地址不适用地址规则（私网、回环、元数据地址放行） | `TestATestOriginIsExemptFromHTTPSAndTheAddressRulesAndNothingElseIs`, `TestEachInvalidSettingIsRefusedForItsOwnReason` |
| M36 | `oauth` 连接不要求 `issuer` | `TestEachInvalidSettingIsRefusedForItsOwnReason` |
| M37 | 预注册客户端也允许动态注册 | `TestSettingsThatDoNotFitTheirModeAreRefused` |
| M38 | API 不要求令牌 | `TestWithoutATokenEveryRouteIsUnauthenticatedAndTheServiceIsNotCalled` |
| M39 | API 接受没有租户的令牌 | `TestTheServiceIsCalledWithTheMemberTheTokenNamesAndOnlyThat` |
| M40 | 出口策略不排除 10.0.0.0/8 | `TestEgressPolicyIsTheOnlyWayOutAndIsIPv4OnlyOnPort443` |
| M41 | MCP 端口的入口放进 Workspace、去掉注册服务 | `TestIngressAdmitsTheGatewayAndTheRegistryOnTheMCPPortTheWorkspaceOnTheAPIPortAndNobodyElse` |
| M42 | 清单里设 `IDP_BRIDGE_TEST_ORIGINS` | `TestNothingTestOnlyIsShipped` |
| M43 | 没有网关公钥也启动 | `TestEachMissingOrInvalidSettingIsAConfigurationError` |
| M44 | 非回环地址不需要私网声明 | `TestEachMissingOrInvalidSettingIsAConfigurationError` |
| M45 | `tools/list` 不过滤命名空间的键 | `TestKeysOfThePlatformsNamespaceAreRemovedFromResultsAndToolMetadata`, `TestListToolsPagesAndBoundsThePages` |
| M46 | 被拒绝的调用也记入窗口 | `TestTheLimiterSlidesAndDoesNotCountARefusal` |
| M47 | 超限的调用仍然发出 | `TestTheRateLimitsArePerMemberAndPerConnectionAndSlide` |
| M48 | 熔断器开着也发出调用 | `TestTheCircuitBreakerOpensAfterConsecutiveFailuresAndClosesAfterATrial` |
| M49 | 不要令牌的连接答 401 时答「需要授权」 | `TestAConnectionThatNeedsNoTokenAndIsAskedForOneSaysSo` |
| M50 | `mcp.New` 接受空的校验器 | `TestAServerCannotBeBuiltWithoutACallerVerifier` |
| M51 | 任何工具名都可以发送 | `TestAToolNameThatCannotBeSentIsAToolErrorAndNothingIsSent`, `TestAToolNameThatCannotBeSentIsRefusedBeforeAnythingIsSent` |
| M52 | 允许重复的连接 id | `TestEachInvalidSettingIsRefusedForItsOwnReason` |
| M53 | 4xx 也算失败（熔断） | `TestStatusesAndAnswersThatAreNotAnswers`, `TestTheCircuitBreakerOpensAfterConsecutiveFailuresAndClosesAfterATrial` |
| M54 | 列出工具不计入连接的限流 | `TestTheListingCountsForTheConnectionsLimitAndForNoMember` |
| M55 | 列出工具不经熔断器 | `TestTheCircuitBreakerOpensAfterConsecutiveFailuresAndClosesAfterATrial` |
| M56 | 流里的通知被当作错误 | `TestAStreamIsReadMessageByMessageAndNotificationsAreNotAnAnswer` |
| M57 | 拨号处一律当作测试例外 | `TestARedirectIsNotFollowedAndNothingIsSentToItsTarget`, `TestATestOriginIsExemptExactlyAndNothingElseIs`, `TestAddressRulesRefuseANameThatResolvesToAPrivateAddressAndConnectToNothing` 等 |

57 项全部失败（没有一项仍然通过）。头一轮里有三项仍然通过，是测试的缺口，补了测试再做：M9（调用方已经检查进度令牌，客户端里的检查是第二道，补了客户端层面的测试）、M14（行长度与事件长度两处检查互相掩盖，补了一个"超长的注释行、总量未超"的用例）、M41（测试用了 `mcp[...] != ""`，对缺失的键也成立，改成存在性检查）；M25 第一次写的改动不能编译，改写后失败。M43 原先也通过（错误信息仍点名这个环境变量），测试改成要求"is not set"。

## 5. 反向验证（B2：D21 到 D31）

做法同第 4 节：每个新控制各去掉一次，看测试失败，再恢复；这一轮在 PostgreSQL 上跑（`IDP_TEST_PG_OWNER_URL` 设了，存储与授权流程的测试在内存与 PostgreSQL 上各跑一遍）。第 4 节 B1 的 57 项在 B2 完成后整体重跑过，仍然全部失败。

| # | 去掉的控制（改动） | 失败的测试 |
|---|---|---|
| B2-1 | 不要求资源元数据的 `resource` 等于端点 | `TestDiscoveryRefusesWhatDoesNotMatchThePinnedIssuerAndTheEndpoint` |
| B2-2 | 不要求钉死的 issuer 在资源列出的授权服务器里 | `TestDiscoveryRefusesWhatDoesNotMatchThePinnedIssuerAndTheEndpoint` |
| B2-3 | 不要求授权服务器元数据的 `issuer` 等于钉死的 | `TestDiscoveryRefusesWhatDoesNotMatchThePinnedIssuerAndTheEndpoint` |
| B2-4 | `resource_metadata` 可以在别的源上 | `TestDiscoveryRefusesWhatDoesNotMatchThePinnedIssuerAndTheEndpoint` |
| B2-5 | 不要求 `S256` | `TestDiscoveryRefusesWhatDoesNotMatchThePinnedIssuerAndTheEndpoint` |
| B2-6 | 授权服务器元数据里的端点不过地址规则 | `TestDiscoveryRefusesWhatDoesNotMatchThePinnedIssuerAndTheEndpoint` |
| B2-7 | OAuth 请求跟随别的源的重定向 | `TestDiscoveryRefusesWhatDoesNotMatchThePinnedIssuerAndTheEndpoint`, `TestTheFetcherFollowsOnlySameOriginRedirectsThatKeepTheMethodAndBoundsTheBody` |
| B2-8 | POST 也跟随会改方法的重定向 | `TestTheFetcherFollowsOnlySameOriginRedirectsThatKeepTheMethodAndBoundsTheBody` |
| B2-9 | OAuth 响应体不设上限 | `TestTheFetcherFollowsOnlySameOriginRedirectsThatKeepTheMethodAndBoundsTheBody` |
| B2-10 | OAuth 地址可以是 http | `TestDiscoveryRefusesWhatDoesNotMatchThePinnedIssuerAndTheEndpoint` |
| B2-11 | 服务器不支持 CIMD 也用 CIMD | `TestWithoutCIMDSupportAConnectionNeedsDynamicRegistrationOptedInOrItIsRefused` |
| B2-12 | 没有选择动态注册也注册 | `TestWithoutCIMDSupportAConnectionNeedsDynamicRegistrationOptedInOrItIsRefused` |
| B2-13 | 预注册客户端不按服务器宣告的认证方式 | `TestAPreregisteredClientAuthenticatesWithTheMethodTheServerAdvertises` |
| B2-14 | 客户端元数据文档写别的重定向地址 | `TestACallbackIsOneUseShortLivedAndForTheConnectionThatWasStarted`, `TestAMemberLosesNothingWhenSomeoneElseTriesTheirState`, `TestARefreshTokenTheServerRefusesDeletesTheGrantAndTheMemberIsToldToConnect` 等 |
| B2-15 | PKCE 用 plain | `TestACallbackIsOneUseShortLivedAndForTheConnectionThatWasStarted`, `TestAMemberLosesNothingWhenSomeoneElseTriesTheirState`, `TestAPreregisteredClientAuthenticatesWithTheMethodTheServerAdvertises` 等 |
| B2-16 | 令牌请求不带真正的验证码 | `TestACallbackIsOneUseShortLivedAndForTheConnectionThatWasStarted`, `TestAMemberLosesNothingWhenSomeoneElseTriesTheirState`, `TestAPreregisteredClientAuthenticatesWithTheMethodTheServerAdvertises` 等 |
| B2-17 | 授权请求不带 `resource` | `TestACallbackIsOneUseShortLivedAndForTheConnectionThatWasStarted`, `TestAMemberLosesNothingWhenSomeoneElseTriesTheirState`, `TestAPreregisteredClientAuthenticatesWithTheMethodTheServerAdvertises` 等 |
| B2-18 | 授权码换令牌不带 `resource` | `TestACallbackIsOneUseShortLivedAndForTheConnectionThatWasStarted`, `TestAMemberLosesNothingWhenSomeoneElseTriesTheirState`, `TestAPreregisteredClientAuthenticatesWithTheMethodTheServerAdvertises` 等 |
| B2-19 | 刷新不带 `resource` | `TestARefreshTokenTheServerRefusesDeletesTheGrantAndTheMemberIsToldToConnect`, `TestATokenIsBoundToItsConnectionByTheResourceAndByTheGrantsKey`, `TestKeyRotationNewRowsUseTheCurrentKeyOldRowsStillOpenAndResealMovesTheRest` 等 |
| B2-20 | `state` 可被别的成员取出（存储） | `TestACallbackIsOneUseShortLivedAndForTheConnectionThatWasStarted`, `TestAMemberLosesNothingWhenSomeoneElseTriesTheirState`, `TestPendingStatesAreTakenOnceOnlyByTheirOwnerAndSweptWhenTheyExpire` 等 |
| B2-21 | `state` 可以用两次（存储） | `TestACallbackIsOneUseShortLivedAndForTheConnectionThatWasStarted`, `TestPendingStatesAreTakenOnceOnlyByTheirOwnerAndSweptWhenTheyExpire` |
| B2-22 | `state` 不过期 | `TestACallbackIsOneUseShortLivedAndForTheConnectionThatWasStarted` |
| B2-23 | 回调页的连接与开始时的不同也接受 | `TestACallbackIsOneUseShortLivedAndForTheConnectionThatWasStarted` |
| B2-24 | 不检查回调的 `iss` | `TestAWrongOrMissingIssInTheCallbackFailsTheAuthorizationBeforeAnyCodeIsSpent` |
| B2-25 | 服务器声明发 `iss` 而没发也接受 | `TestAWrongOrMissingIssInTheCallbackFailsTheAuthorizationBeforeAnyCodeIsSpent` |
| B2-26 | 把授权服务器的 `error` 原样告诉成员 | `TestAnErrorFromTheAuthorizationServerIsAFixedCodeAndItsDescriptionNeverReachesTheMember` |
| B2-27 | 配置在授权中途变了也完成 | `TestAnAuthorizationStartedUnderAnotherConfigurationIsNotFinished` |
| B2-28 | 不提前刷新（窗口缩到 1 纳秒） | `TestARefreshTokenTheServerRefusesDeletesTheGrantAndTheMemberIsToldToConnect`, `TestATokenIsBoundToItsConnectionByTheResourceAndByTheGrantsKey`, `TestKeyRotationNewRowsUseTheCurrentKeyOldRowsStillOpenAndResealMovesTheRest` 等 |
| B2-29 | 刷新不加行锁（PostgreSQL） | `TestLockedSerializesCallersAcrossReplicasAndAnErrorLeavesTheRowAsItWas`, `TestTwoCallersOnTwoReplicasSpendTheRefreshTokenOnce` |
| B2-30 | 刷新不加锁（内存） | `TestLockedSerializesCallersAcrossReplicasAndAnErrorLeavesTheRowAsItWas`, `TestTwoCallersOnTwoReplicasSpendTheRefreshTokenOnce` |
| B2-31 | 等锁的第二个人不用第一个人的结果，自己再刷新 | `TestTwoCallersOnTwoReplicasSpendTheRefreshTokenOnce` |
| B2-32 | 轮换后仍存旧刷新令牌 | `TestRefreshTokenRotationIsHonouredAndAnOmittedScopeAndRefreshTokenAreKept` |
| B2-33 | `invalid_grant` 不删除授权 | `TestARefreshTokenTheServerRefusesDeletesTheGrantAndTheMemberIsToldToConnect` |
| B2-34 | 任何 403 都当作 `insufficient_scope` | `TestInsufficientScopeAsksTheMemberToAuthorizeAgainForTheUnionAndAPlain403IsJustRefused` |
| B2-35 | 升级范围只记质询的，不与已授予的合并 | `TestInsufficientScopeAsksTheMemberToAuthorizeAgainForTheUnionAndAPlain403IsJustRefused` |
| B2-36 | 需要重新授权的授权仍被使用 | `TestInsufficientScopeAsksTheMemberToAuthorizeAgainForTheUnionAndAPlain403IsJustRefused` |
| B2-37 | 再授权不并上需要的范围 | `TestInsufficientScopeAsksTheMemberToAuthorizeAgainForTheUnionAndAPlain403IsJustRefused` |
| B2-38 | 先撤销访问令牌再撤销刷新令牌 | `TestDisconnectingRevokesAtTheServerDeletesTheGrantAndTheNextCallAsksToConnectAndAFailedRevocationDoesNotKeepTheMemberConnected` |
| B2-39 | 断开时不删除授权 | `TestDisconnectingRevokesAtTheServerDeletesTheGrantAndTheNextCallAsksToConnectAndAFailedRevocationDoesNotKeepTheMemberConnected` |
| B2-40 | 断开时不向授权服务器撤销 | `TestDisconnectingRevokesAtTheServerDeletesTheGrantAndTheNextCallAsksToConnectAndAFailedRevocationDoesNotKeepTheMemberConnected` |
| B2-41 | 授权不按租户区分 | `TestACallbackIsOneUseShortLivedAndForTheConnectionThatWasStarted`, `TestAMemberLosesNothingWhenSomeoneElseTriesTheirState`, `TestAPreregisteredClientAuthenticatesWithTheMethodTheServerAdvertises` 等 |
| B2-42 | 授权不按连接区分 | `TestATokenIsBoundToItsConnectionByTheResourceAndByTheGrantsKey` |
| B2-43 | 密文不绑定拥有者 | `TestASealedValueDoesNotOpenForAnotherMemberTenantConnectionOrAnEditedKeyID`, `TestOneMembersCallNeverUsesAnotherMembersToken` |
| B2-44 | 密文不绑定密钥 id | `TestASealedValueDoesNotOpenForAnotherMemberTenantConnectionOrAnEditedKeyID` |
| B2-45 | 最后一行的密钥加密（而不是第一行） | `TestASealedValueDoesNotOpenForAnotherMemberTenantConnectionOrAnEditedKeyID`, `TestASealedValueOpensForItsOwnerAndNamesItsKeyAndDoesNotRepeat`, `TestKeyRotationNewRowsUseTheCurrentKeyOldRowsStillOpenAndResealMovesTheRest` |
| B2-46 | `reseal` 什么都不重封 | `TestKeyRotationNewRowsUseTheCurrentKeyOldRowsStillOpenAndResealMovesTheRest` |
| B2-47 | API 接受任何客户端的令牌（不查 `azp`） | `TestEverythingElseIsUnauthenticatedWithoutSayingWhy`, `TestTheVerifierIsTheAPIsAuthenticatorAndAnUnauthenticatedCallIs401` |
| B2-48 | API 不查受众 | `TestEverythingElseIsUnauthenticatedWithoutSayingWhy` |
| B2-49 | API 不查 issuer | `TestEverythingElseIsUnauthenticatedWithoutSayingWhy` |
| B2-50 | API 不要求 `exp` | `TestEverythingElseIsUnauthenticatedWithoutSayingWhy` |
| B2-51 | API 不要求租户声明 | `TestEverythingElseIsUnauthenticatedWithoutSayingWhy` |
| B2-52 | JWKS 里的加密密钥也被信任 | `TestEverythingElseIsUnauthenticatedWithoutSayingWhy` |
| B2-53 | 日志里写授权码 | `TestNothingSecretIsAnywhereAfterEveryKindOfFailure` |
| B2-54 | API 不要求令牌 | `TestWithoutATokenEveryRouteIsUnauthenticatedAndTheServiceIsNotCalled` |
| B2-55 | 迁移不加咨询锁 | `TestMigrationsAreAppliedOnceAndOpenRefusesASchemaThatIsNotThere` |
| B2-56 | 旧密钥不能解密（轮换后） | `TestKeyRotationNewRowsUseTheCurrentKeyOldRowsStillOpenAndResealMovesTheRest` |
| B2-57 | 对方暂时不应答时，仍在有效期内的令牌不继续用 | `TestAnAuthorizationServerThatDoesNotAnswerLeavesAValidTokenInUseAndTheGrantInPlace` |

57 项全部失败。头一轮里有几项是改动写得不能编译（未使用的变量），改写后重跑；有两项原先仍然通过，是测试的缺口，补了测试："授权按连接区分"（B2-41）（原先刷新令牌属于另一个客户端，授权服务器替身的 `invalid_grant` 碰巧挡住了错用，测试改成不经刷新直接取令牌）、迁移的咨询锁（B2-55，原先并发迁移发生在已迁移的库上，什么也没测到，改成在新库上并发，且总共只应用一次）。

## 6. 反向验证（D25 的改动：所有者与应用角色分开）

同第 5 节，在 PostgreSQL 上做。头一轮有两项仍然通过：B2R-6（测试用的"不合法的名字"在集群里已经有了，被"角色已存在"挡住，不是检查挡住的；改成每次都是新名字）、B2R-8（检查"只有一处调用"的测试按文件数，改成按调用点数）。B2R-7 的第一种改动（把读权限给 PUBLIC）与原来等价，改成去掉读权限。

| # | 去掉的控制（改动） | 失败的测试 |
|---|---|---|
| B2R-1 | 应用角色得到三张表的全部权限（含 TRUNCATE） | `TestTheServiceRoleCanOnlyReadAndWriteTheThreeTablesAndCannotChangeTheSchema` |
| B2R-2 | 应用角色可以在 schema 里建对象 | `TestEveryStoreKeepsGrantsPerTenantMemberAndConnection`, `TestLockedSerializesCallersAcrossReplicasAndAnErrorLeavesTheRowAsItWas`, `TestPendingStatesAreTakenOnceOnlyByTheirOwnerAndSweptWhenTheyExpire` 等 |
| B2R-3 | 服务不拒绝能改库的角色 | `TestTheServiceRoleCanOnlyReadAndWriteTheThreeTablesAndCannotChangeTheSchema` |
| B2R-4 | 服务不拒绝版本不符的库 | `TestTheServerNeverMigratesAndRefusesASchemaThatIsNotTheOneItExpects` |
| B2R-5 | 登录角色是超级用户 | `TestEveryStoreKeepsGrantsPerTenantMemberAndConnection`, `TestLockedSerializesCallersAcrossReplicasAndAnErrorLeavesTheRowAsItWas`, `TestPendingStatesAreTakenOnceOnlyByTheirOwnerAndSweptWhenTheyExpire` 等 |
| B2R-6 | 角色名不检查，可夹带 SQL | `TestEnsureLoginMakesARoleThatIsNotAnOwnerAndRefusesBadNames` |
| B2R-7 | 应用角色读不了 `schema_migrations` | `TestEveryStoreKeepsGrantsPerTenantMemberAndConnection`, `TestLockedSerializesCallersAcrossReplicasAndAnErrorLeavesTheRowAsItWas`, `TestPendingStatesAreTakenOnceOnlyByTheirOwnerAndSweptWhenTheyExpire` 等 |
| B2R-8 | 服务启动时迁移 | `TestOnlyTheMigrateCommandAppliesMigrations` |
| B2R-9 | Deployment 挂所有者的 Secret | `TestServiceIsHardenedAndItsSettingsAgreeWithItsMountsAndPorts`, `TestTheMigrationJobHoldsTheOwnersURLAndTheServiceNeverDoes` |
| B2R-10 | Job 不是所有者 URL 的唯一持有者 | `TestTheMigrationJobHoldsTheOwnersURLAndTheServiceNeverDoes` |
| B2R-11 | 迁移 Job 到不了数据库 | `TestTheDatabaseAndKeycloakAreTheOnlyPlacesInTheClusterTheBridgeMayReach` |
| B2R-12 | `migrate` 不要求所有者的 URL | `TestTheDatabaseCommandsNeedTheOwnersURLAndNothingElse` |

12 项全部失败。第 5 节的 57 项与第 4 节的 57 项在这次改动之后又整体重跑过，仍然全部失败。

## 7. 反向验证（B3：D33、D34）

做法同第 5 节，在 PostgreSQL 上做。

| # | 去掉的控制（改动） | 失败的测试 |
|---|---|---|
| B3R-1 | 没有评审角色也能开始评审账号的授权 | `TestOnlyACallerWithTheReviewerRoleMayAuthorizeOrDisconnectAReviewerAccount` |
| B3R-2 | 没有评审角色也能断开评审账号 | `TestOnlyACallerWithTheReviewerRoleMayAuthorizeOrDisconnectAReviewerAccount` |
| B3R-3 | 回调时不再查评审角色 | `TestOnlyACallerWithTheReviewerRoleMayAuthorizeOrDisconnectAReviewerAccount` |
| B3R-4 | 评审授权存成发起运维自己的成员授权 | `TestAnOperatorAuthorizesTheConnectionsReviewerAccountAndTheListingUsesItsToken`, `TestDisconnectingTheReviewerAccountRevokesItsTokensAtTheServer`, `TestTheListShowsTheReviewerAccountToACallerWithTheRoleOnly` 等 |
| B3R-5 | 评审账号的密文也能按成员的打开（附加数据不含 `reviewer`） | `TestAReviewerSealedValueDoesNotOpenAsAMembersAndNeitherTheOtherWayRound`, `TestAnOperatorAuthorizesTheConnectionsReviewerAccountAndTheListingUsesItsToken` |
| B3R-6 | 评审授权用连接的 `scopes`，不用 `reviewerScopes` | `TestAnOperatorAuthorizesTheConnectionsReviewerAccountAndTheListingUsesItsToken`, `TestTheListShowsTheReviewerAccountToACallerWithTheRoleOnly` |
| B3R-7 | 目录列表不用评审账号的令牌 | `TestAnOperatorAuthorizesTheConnectionsReviewerAccountAndTheListingUsesItsToken`, `TestTheReviewerTokenIsRenewedLikeAMembersUnderTheSameLockAndRotation` |
| B3R-8 | 成员没有授权时，调用退而用评审账号的令牌 | `TestTheReviewerTokenIsNeverUsedForACallAndTheMembersGrantIsIndependentOfIt` |
| B3R-9 | 所有人的列表里都有 `reviewer` | `TestTheListShowsTheReviewerAccountToACallerWithTheRoleOnly` |
| B3R-10 | 成员离职连评审授权一起删（存储） | `TestAReviewerGrantIsOfTheConnectionAndNeverOfAMember` |
| B3R-11 | 库不拒绝既是评审又有租户成员、或两者都没有的行 | `TestTheDatabaseRefusesARowThatIsNeitherAMembersNorTheConnectionsReviewer` |
| B3R-12 | 任何角色都算评审 | `TestTheReviewerRoleAndTenantMakeAReviewerAndNothingElseDoes` |
| B3R-13 | 评审租户不起限定作用 | `TestTheReviewerRoleAndTenantMakeAReviewerAndNothingElseDoes` |
| B3R-14 | 只设评审租户不设角色不是错误 | `TestTheReviewerRoleHasNoDefaultAndATenantNeedsARole` |
| B3R-15 | 列表遇 401 不向来源要新令牌 | `TestTheReviewerTokenIsRenewedLikeAMembersUnderTheSameLockAndRotation` |
| B3R-16 | 网关的列表不更新工具目录 | `TestTheCatalogIsRefreshedOnAMissAndAfterTheTTLAndNotMoreOftenThanTheMinimum`, `TestTheCircuitBreakerOpensAfterConsecutiveFailuresAndClosesAfterATrial` |
| B3R-17 | `number` 类型的属性也能有 `x-mcp-header` | `TestAToolWhoseDefinitionIsUnknownOrInvalidGetsNoHeadersAndTheCallStillGoes`, `TestAToolWithAnInvalidAnnotationHasNoHeaders` |
| B3R-18 | 头的名字不必是 token | `TestAToolWithAnInvalidAnnotationHasNoHeaders` |
| B3R-19 | 头的名字可以大小写不同地重复 | `TestAToolWithAnInvalidAnnotationHasNoHeaders` |
| B3R-20 | 注解可以在不经 `properties` 可达的位置 | `TestAToolWithAnInvalidAnnotationHasNoHeaders` |
| B3R-21 | 不是可打印 ASCII 的值（含回车换行）原样发送 | `TestAValueThatWouldInjectAHeaderLineIsSentInTheBase64Form`, `TestAValueThatWouldInjectAHeaderLineReachesTheThirdPartyAsBase64AndAsNothingElse`, `TestHeadersThatDoNotFitTheBoundsRefuseTheCallAndNothingIsTruncated` |
| B3R-22 | 像 `=?base64?...?=` 的值原样发送 | `TestAValueThatWouldInjectAHeaderLineIsSentInTheBase64Form` |
| B3R-23 | 超过 1024 字节的值照发 | `TestAnArgumentThatIsTooLongForItsHeaderRefusesTheCallAndNothingIsSent`, `TestHeadersThatDoNotFitTheBoundsRefuseTheCallAndNothingIsTruncated` |
| B3R-24 | 超过 16 个头照发 | `TestHeadersThatDoNotFitTheBoundsRefuseTheCallAndNothingIsTruncated` |
| B3R-25 | 超过 128 字节的名字照发 | `TestHeadersThatDoNotFitTheBoundsRefuseTheCallAndNothingIsTruncated` |
| B3R-26 | 额外头里任何头都发出去 | `TestOnlyMcpParamHeadersGoOutThroughTheExtraHeaders` |
| B3R-27 | 带小数的整数也渲染成头 | `TestTheHeadersAreComputedFromTheArgumentsAsTheSpecificationSays` |
| B3R-28 | 太长的参数不拒绝调用 | `TestAnArgumentThatIsTooLongForItsHeaderRefusesTheCallAndNothingIsSent` |
| B3R-29 | 目录永不过期 | `TestTheCatalogIsRefreshedOnAMissAndAfterTheTTLAndNotMoreOftenThanTheMinimum` |
| B3R-30 | 每个未知工具的调用都去刷新目录 | `TestTheCatalogIsRefreshedOnAMissAndAfterTheTTLAndNotMoreOftenThanTheMinimum` |
| B3R-31 | 熔断器不是关的也为调用刷新目录 | `TestTheRefreshOfTheCatalogUsesTheConnectionsLimitsAndTheBreaker` |
| B3R-32 | 为调用刷新目录不受连接限流约束 | `TestTheRefreshOfTheCatalogUsesTheConnectionsLimitsAndTheBreaker` |
| B3R-33 | 不校验 `reviewerScopes` | `TestReviewerScopesAreOptionalCheckedLikeScopesAndForbiddenWithoutOAuth` |
| B3R-34 | 不要令牌的连接可以写 `reviewerScopes` | `TestReviewerScopesAreOptionalCheckedLikeScopesAndForbiddenWithoutOAuth` |
| B3R-35 | 评审授权的状态不记它是评审的 | `TestAnOperatorAuthorizesTheConnectionsReviewerAccountAndTheListingUsesItsToken`, `TestDisconnectingTheReviewerAccountRevokesItsTokensAtTheServer`, `TestOnlyACallerWithTheReviewerRoleMayAuthorizeOrDisconnectAReviewerAccount` 等 |
| B3R-36 | 迁移 2 没有被要求（版本检查少一） | `TestAReviewerGrantIsOfTheConnectionAndNeverOfAMember`, `TestEveryStoreKeepsGrantsPerTenantMemberAndConnection`, `TestLockedSerializesCallersAcrossReplicasAndAnErrorLeavesTheRowAsItWas` 等 |

36 项全部失败。B3 完成之后 B1、B2 与 D25 的反向验证表又整体重跑过，仍然全部失败（有几个测试因为为调用刷新目录而多了一次 `tools/list` 请求，调整了期望的请求数：熔断器与地址规则的测试先让网关列一次，目录就不需要刷新）。

## 8. 反向验证（D35）

| # | 去掉的控制（改动） | 失败的测试 |
|---|---|---|
| B4R-1 | 再授权时不撤销被取代的令牌 | `TestAFailingRevocationNeverUndoesTheNewGrantAndOnlyItsCodeIsLogged`, `TestAuthorizingAgainAfterAStepUpRevokesTheSupersededTokens`, `TestAuthorizingAgainRevokesTheSupersededTokensAndTheNewGrantWorks` 等 |
| B4R-2 | 别的签发者的旧令牌也发给现在的服务器 | `TestTokensOfAnotherIssuerAreNotSentToTheCurrentServerForRevocation` |
| B4R-3 | 先撤销访问令牌、再撤销刷新令牌 | `TestAuthorizingAgainRevokesTheSupersededTokensAndTheNewGrantWorks`, `TestDisconnectingRevokes...`（断开用同一条路径） |
| B4R-4 | 新授权自己的令牌也被撤销 | `TestAuthorizingAgainAfterAStepUpRevokesTheSupersededTokens`, `TestAuthorizingAgainRevokesTheSupersededTokensAndTheNewGrantWorks`, `TestAuthorizingTheReviewerAccountAgainRevokesTheSupersededReviewerTokens` |

4 项全部失败。没有撤销端点、撤销失败（503）、评审账号、成员与评审互不影响各有测试；"同样的令牌不撤销"（`keep`）没有测试能让授权服务器替身给出相同的令牌，不声称已验证。

## 9. 反向验证（D36）

| # | 去掉的控制（改动） | 失败的测试 |
|---|---|---|
| B5R-1 | 200 应答里的 `error` 不当作错误 | `TestAGitHubBadCodeIsInvalidGrantAndTheOtherGitHubErrorsAreErrorsOfTheTokenEndpoint`, `TestAnErrorAnsweredWithHTTP200IsAnErrorAndAGitHubDeadRefreshTokenDeletesTheGrant` |
| B5R-2 | `bad_refresh_token` 不按 `invalid_grant` 处理 | `TestAnErrorAnsweredWithHTTP200IsAnErrorAndAGitHubDeadRefreshTokenDeletesTheGrant` |
| B5R-3 | `bad_verification_code` 不按 `invalid_grant` 处理 | `TestAGitHubBadCodeIsInvalidGrantAndTheOtherGitHubErrorsAreErrorsOfTheTokenEndpoint` |
| B5R-4 | 再多一个码（`incorrect_client_credentials`）按 `invalid_grant` 处理 | `TestAGitHubBadCodeIsInvalidGrantAndTheOtherGitHubErrorsAreErrorsOfTheTokenEndpoint`, `TestOnlyTheTwoListedCodesDeleteAGrantWhenARefreshIsRefusedWith200` |

4 项全部失败。

## 10. 反向验证（D37）

| # | 去掉的控制（改动） | 失败的测试 |
|---|---|---|
| B6R-1 | 没有配置范围就去要资源列出的全部 | `TestAStepUpStillUnionsTheChallengedScopeWithNoScopesConfiguredAndLogsTheNamesAdded`, `TestTheAuthorizationAskedForIsTheConfiguredScopesAndTheResourcesListOnlyOnTheOptIn` |
| B6R-2 | `scopesFromResource` 不起作用 | `TestTheAuthorizationAskedForIsTheConfiguredScopesAndTheResourcesListOnlyOnTheOptIn` |
| B6R-3 | 没有范围也要 `offline_access` | `TestTheAuthorizationAskedForIsTheConfiguredScopesAndTheResourcesListOnlyOnTheOptIn` |
| B6R-4 | 质询新增的范围名不写日志 | `TestAStepUpStillUnionsTheChallengedScopeWithNoScopesConfiguredAndLogsTheNamesAdded` |
| B6R-5 | `mode: none` 的连接可以写 `scopesFromResource` | `TestScopesFromResourceIsAnOptInForOAuthConnectionsOnly` |

5 项全部失败。D27 的并集（升级后再授权要配置的范围与质询的范围的并集）由原有的 `TestInsufficientScopeAsksTheMemberToAuthorizeAgainForTheUnionAndAPlain403IsJustRefused` 与上面的升级测试覆盖（B2R-35、B2R-37 仍然有效）。

## 11. 反向验证（D38 到 D42）

同第 5 节，在 PostgreSQL 上做。

| # | 去掉的控制（改动） | 失败的测试 |
|---|---|---|
| B7R-1 | 任何客户端的服务令牌都能调用接口（不查 `azp` 允许名单） | `TestAServiceTokenIsAClientCredentialsTokenOfAClientOnTheAllowListAndNothingElseIs` |
| B7R-2 | 成员的令牌（有会话 `sid`、或是委托 `act`）也被接受为服务令牌 | `TestAServiceTokenIsAClientCredentialsTokenOfAClientOnTheAllowListAndNothingElseIs` |
| B7R-3 | 接口的正文不严格（多余字段也收） | `TestTheRouteIsForServicesOnTheAllowListOnlyAndDisabledWithoutOne` |
| B7R-4 | 原因不限于固定的一组 | `TestTheRouteIsForServicesOnTheAllowListOnlyAndDisabledWithoutOne` |
| B7R-5 | 审计行里的原因不是实际的原因 | `TestOffboardingIsAuditedWithTheReasonAndTheCallerAndCountedAndAFailedRevocationDoesNotKeepTheGrant` |
| B7R-6 | 成员离开时不删他未完成的授权 | `TestAServiceTellsTheBridgeAMemberLeftAndEverythingOfTheMembersGoes` |
| B7R-7 | 不标记授权人离开的评审账号 | `TestWhenTheAuthorizerOfAReviewerAccountLeavesTheAccountIsKeptMarkedAndNotRevoked` |
| B7R-8 | 授权人离开时评审账号被删除而不是标记（存储） | `TestDisconnectingTheReviewerAccountRevokesItsTokensAtTheServer`, `TestTheStoreKnowsWhoTheMembersAreAndForgetsAMembersPendingAuthorizationsAndMarksTheAuthorizersReviewerAccounts`, `TestWhenTheAuthorizerOfAReviewerAccountLeavesTheAccountIsKeptMarkedAndNotRevoked` |
| B7R-9 | 列表不显示 `authorizer_left` | `TestWhenTheAuthorizerOfAReviewerAccountLeavesTheAccountIsKeptMarkedAndNotRevoked` |
| B7R-10 | 运维只撤一条连接时也当作离开（清未完成的授权、标记评审账号） | `TestTheOperatorsRevokeCommandIsTheSamePathWithReasonOperator` |
| B7R-11 | 撤销失败不计数 | `TestGitHubSaying404Or422MeansAlreadyGoneAndAnythingElseFallsBackToTheTokenEndpointAndThenFails`, `TestOffboardingIsAuditedWithTheReasonAndTheCallerAndCountedAndAFailedRevocationDoesNotKeepTheGrant` |
| B7R-12 | 令牌撤销失败不算失败 | `TestOffboardingIsAuditedWithTheReasonAndTheCallerAndCountedAndAFailedRevocationDoesNotKeepTheGrant` |
| B7R-13 | 安全闸不要求至少 5 人 | `TestTheSafetyBrakeHoldsARoundInWhichMoreThanAFifthAndAtLeastFiveWouldGoUnlessForced` |
| B7R-14 | 安全闸是不少于 20% 而不是多于 20% | `TestTheSafetyBrakeHoldsARoundInWhichMoreThanAFifthAndAtLeastFiveWouldGoUnlessForced` |
| B7R-15 | `--force` 不能越过安全闸 | `TestTheReconcileCommandRunsOneRoundAndForceGoesPastTheBrake`, `TestTheSafetyBrakeHoldsARoundInWhichMoreThanAFifthAndAtLeastFiveWouldGoUnlessForced` |
| B7R-16 | 目录出错也当作已删除 | `TestAnythingThatIsNotAClearAnswerDoesNothing` |
| B7R-17 | 对账的原因不取自查询结果 | `TestAMemberWhoIsDeletedDisabledOrMovedIsOffboardedWithTheReasonOfTheLookupAndNobodyElseIs` |
| B7R-18 | 对账不加锁，两个副本可以同时跑 | `TestOnlyOneReplicaReconcilesAtATime` |
| B7R-19 | 评审账号也算成员 | `TestAMemberWhoIsDeletedDisabledOrMovedIsOffboardedWithTheReasonOfTheLookupAndNobodyElseIs`, `TestAnythingThatIsNotAClearAnswerDoesNothing`, `TestTheSafetyBrakeHoldsARoundInWhichMoreThanAFifthAndAtLeastFiveWouldGoUnlessForced` |
| B7R-20 | Keycloak 的任何 404 都是已删除（包括 realm 不存在） | `TestTheAdapterGivesOnlyClearAnswers` |
| B7R-21 | 没有 `enabled` 的应答也当作用户 | `TestTheAdapterGivesOnlyClearAnswers` |
| B7R-22 | 别的用户的应答也当作这个用户的 | `TestTheAdapterGivesOnlyClearAnswers` |
| B7R-23 | 没有租户属性也当作仍在 | `TestTheAdapterGivesOnlyClearAnswers` |
| B7R-24 | 可能是路径的成员 id 也去查 | `TestWhenKeycloakCannotBeAskedTheAnswerIsUnknownAndNothingIsAsked` |
| B7R-25 | 断开时只撤销单个令牌、不删 GitHub 上的整个授权 | `TestDisconnectingFromGitHubDeletesTheMembersGrantAtGitHubWithTheApplicationsCredentials`, `TestGitHubSaying404Or422MeansAlreadyGoneAndAnythingElseFallsBackToTheTokenEndpointAndThenFails`, `TestTheReviewerAccountAndTheOperatorsRevokeUseGitHubsAPIToo` |
| B7R-26 | 再授权时也删整个 GitHub 授权（会同时撤销新令牌） | `TestAuthorizingAgainAtGitHubRevokesOnlyTheOldTokenAndNeverTheGrant` |
| B7R-27 | 整个授权的接口失败时不试令牌接口 | `TestGitHubSaying404Or422MeansAlreadyGoneAndAnythingElseFallsBackToTheTokenEndpointAndThenFails` |
| B7R-28 | 404 不算已经没有了 | `TestGitHubSaying404Or422MeansAlreadyGoneAndAnythingElseFallsBackToTheTokenEndpointAndThenFails` |
| B7R-29 | 访问令牌已过期也不先刷新 | `TestAnExpiredAccessTokenIsRefreshedFirstIfThereIsARefreshTokenAndOtherwiseThePresentedOneIsTheStaleOne` |
| B7R-30 | 撤销没能确认时不记录 | `TestAMemberWhoseRevocationCouldNotBeConfirmedIsToldSoInTheListUntilTheyConnectAgain` |
| B7R-31 | 重新连接不清除撤销未确认 | `TestAMemberWhoseRevocationCouldNotBeConfirmedIsToldSoInTheListUntilTheyConnectAgain` |
| B7R-32 | GitHub 的 Basic 认证不用应用的密钥 | `TestAMemberWhoseRevocationCouldNotBeConfirmedIsToldSoInTheListUntilTheyConnectAgain`, `TestAnExpiredAccessTokenIsRefreshedFirstIfThereIsARefreshTokenAndOtherwiseThePresentedOneIsTheStaleOne`, `TestDisconnectingFromGitHubDeletesTheMembersGrantAtGitHubWithTheApplicationsCredentials` |
| B7R-33 | `revocation: github` 也允许用于非预注册的客户端 | `TestRevocationGitHubIsForPreregisteredClientsOnly` |
| B7R-34 | 对账间隔没有下限 | `TestTheOffboardingAndDirectorySettingsAreCheckedAndTheRouteAndTheDirectoryAreOffByDefault` |

34 项全部失败。

| B8R-1 | 对账不查评审授权的授权人 | `TestAnAuthorizerThatIsNotTenantSlashMemberIsSkippedAndLogged`, `TestAnAuthorizerWithNoMemberGrantsIsLookedUpAndWhenHeLeavesOnlyTheAccountIsMarked`, `TestTheBrakeCountsAuthorizersWithNoMemberGrantsToo` |
| B8R-2 | 没有成员授权的授权人离开时也整个"离开"，而不是只标记账号 | 同上三项 |
| B8R-3 | 解析不了的授权人也去查 | `TestAnAuthorizerThatIsNotTenantSlashMemberIsSkippedAndLogged` |
| B8R-4 | 既有成员授权又授权评审账号的人算两次 | `TestAMemberWhoIsDeletedDisabledOrMovedIsOffboardedWithTheReasonOfTheLookupAndNobodyElseIs`, `TestAnAuthorizerWhoAlsoHoldsMemberGrantsIsOffboardedOnceAndNotCountedTwice` 等 |
| B8R-5 | 已经标记的账号的授权人每轮都再查（存储） | `TestAnAuthorizerWhoAlsoHoldsMemberGrantsIsOffboardedOnceAndNotCountedTwice`, `TestTheStoreListsTheAuthorizersOfReviewerAccountsThatAreNotYetMarked` |

（B8R 是 D40 的补充：对账找到没有成员授权的授权人；5 项全部失败。）
