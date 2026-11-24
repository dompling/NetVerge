# NetVerge 双引擎架构复审 V0.2

> 仅静态审查，不修改功能代码。本文是 V0.1 的补充与修正；存在冲突时以本次更严格的验证门槛为准。
> 结论：允许继续小范围实验，不批准全局代理切换或发布。

## 1. 审查依据

- NetVerge：[2d032ee](https://github.com/dompling/NetVerge/tree/2d032eec3932993943ce64536f220038b79947b7)，包括架构 V0.1 及原型。
- Whistle：[e039fd8](https://github.com/avwo/whistle/tree/e039fd86bc70928b0de7abc2f71a1612d530b370)。
- Mihomo：[0455d0d](https://github.com/MetaCubeX/mihomo/tree/0455d0d28c4526937380505153e65a843d8612e8)，Meta 源码快照。该快照尚未与 CVR 实际打包的内核版本核对，不能视为实际运行版本。
- 范围：入口、路由、进程元数据、DNS、规则优先级、控制面、进程管理及测试覆盖。未运行 Windows/Mihomo/Whistle 测试，所有运行结果均待验证。

## 2. 复审发现

### R01 / P0：全局串联会改变 Mihomo 进程规则语义

证据：
- Mihomo [adapter/inbound/http.go](https://github.com/MetaCubeX/mihomo/blob/0455d0d28c4526937380505153e65a843d8612e8/adapter/inbound/http.go) 与 [https.go](https://github.com/MetaCubeX/mihomo/blob/0455d0d28c4526937380505153e65a843d8612e8/adapter/inbound/https.go)：从入站连接 RemoteAddr 获取源地址。
- [tunnel/tunnel.go](https://github.com/MetaCubeX/mihomo/blob/0455d0d28c4526937380505153e65a843d8612e8/tunnel/tunnel.go)：resolveMetadata 的 FindProcess 通过网络类型、SrcIP、SrcPort 查找进程。
- [rules/common/process.go](https://github.com/MetaCubeX/mihomo/blob/0455d0d28c4526937380505153e65a843d8612e8/rules/common/process.go)：PROCESS-NAME / PROCESS-PATH 基于所得元数据匹配。

推论：应用 -> Whistle -> Mihomo 时，Mihomo 入站套接字的直接对端是 Whistle，不再是浏览器等原始应用。按原进程名称、路径、源端口选择策略的行为不能保证一致。若 Whistle 复用连接，多个请求也未必对应独立网络连接。

修正：默认入口继续使用 Mihomo，HTTP 调试先通过显式端口或指定应用/域名接入。不得宣称全局替换可无损保留进程分流。若用户依赖进程规则，应保持原路径或明确提示不支持。不能通过伪造 HTTP Header 作为可信进程身份；专用入口只能标识 HTTP 调试流量类别，不能恢复原始 PID。

### R02 / P0：默认上游规则不构成强制出口

证据：
- NetVerge [engine.cjs](https://github.com/dompling/NetVerge/blob/2d032eec3932993943ce64536f220038b79947b7/engines/whistle/engine.cjs) 将用户规则与 /.*/ proxy://127.0.0.1:PORT 拼接。
- Whistle [rules/util.js:55-105](https://github.com/avwo/whistle/blob/e039fd86bc70928b0de7abc2f71a1612d530b370/lib/rules/util.js#L55-L105)：普通文件、默认规则、Mock、服务规则、shadowRules 共同组成规则集合；shadowRulesMode 会排除部分普通规则，但并非天然的出口隔离。
- [proxy 文档](https://github.com/avwo/whistle/blob/e039fd86bc70928b0de7abc2f71a1612d530b370/docs/en/docs/rules/proxy.md)：host 与 proxy 冲突时默认 host 生效。
- [inspectors/res.js](https://github.com/avwo/whistle/blob/e039fd86bc70928b0de7abc2f71a1612d530b370/lib/inspectors/res.js) 与 [tunnel.js](https://github.com/avwo/whistle/blob/e039fd86bc70928b0de7abc2f71a1612d530b370/lib/tunnel.js)：分别执行 HTTP 和 CONNECT 的代理/地址解析。

风险：用户规则可能改变出口；上游失败不能静默改走直连。这里不是说当前原型必然泄漏，而是源码不能支持“所有请求必经 Mihomo”的保证。

修正：区分实验模式与正式受控模式。正式模式只接受明确允许的 HTTP 操作，由单一配置来源生成规则，限制额外路由、远程规则、插件、系统 hosts。验证规则解析后的实际行为；如产品承诺强制出口，应额外验证网络级约束，而非只依赖文本匹配。未经验证不支持任意 Whistle 规则导入。

### R03 / P0：管理接口和数据面未分离

证据：
- 原型只绑定 127.0.0.1，但没有设置 WebUI 认证。
- Whistle [config.js:516-532](https://github.com/avwo/whistle/blob/e039fd86bc70928b0de7abc2f71a1612d530b370/lib/config.js#L516-L532) 默认 uiport=port。
- [biz/webui/lib/index.js:154-191](https://github.com/avwo/whistle/blob/e039fd86bc70928b0de7abc2f71a1612d530b370/biz/webui/lib/index.js#L154-L191)：用户名与密码均空时 verifyLogin 返回 true。其他路由可能还有自己的保护，需要逐项验证。

风险：本机进程及在特定条件下的浏览器页面可能访问控制面，接触请求数据、修改规则等。loopback 不等于身份认证。本次未做可利用性验证，不应把风险表述成已证实漏洞。

修正：数据端口与管理端口分离、独立随机认证凭据、Rust 后端调用管理 API；测试未认证请求与跨源访问被拒。若模式允许关闭 WebUI，需确认仍能满足所需控制接口。不得向带 Tauri 权限的 WebView 直接加载未经审查的 Whistle 页面。

### R04 / P0：配置隔离并不完整

证据：Whistle [config.js:516-532](https://github.com/avwo/whistle/blob/e039fd86bc70928b0de7abc2f71a1612d530b370/lib/config.js#L516-L532) 先读取 rc 配置并合并，随后还拼接 WHISTLE_MODE 环境变量。原型只设置 baseDir、safe 和插件关闭，未证明 rc、继承环境、持久化规则和 HTTPS capture 设置都隔离。

修正：明确独立的 rc 路径、环境变量允许列表、规则及属性存储归属，验证已有 Whistle 安装不会影响 NetVerge。safe 模式的上游证书校验不等于禁止 MITM；HTTPS 解密必须由 NetVerge 显式控制。Windows mkdir mode 不是 ACL 保证，正式私钥和会话数据目录需验证 ACL。

### R05 / P0：ready 仅表示 Whistle 启动，不表示双引擎链路可用

原型回调输出 ready、port、upstream，未检查上游身份、端口监听、认证、真实代理请求。Mihomo 的 mixed-port 也可能存在代理认证或监听范围配置。

CVR [config/mixed_port.rs](https://github.com/dompling/NetVerge/blob/2d032eec3932993943ce64536f220038b79947b7/src-tauri/src/config/mixed_port.rs) 的 effective() 在查询失败时会返回 desired()。这是端口解析逻辑，不能作为健康证明。

修正：区分 Started、UpstreamReady、Ready、Degraded。只有实际内核 API 和受控代理探测成功才允许切换入口。上游凭据须在控制面管理，不能出现在普通日志或 CLI 参数。Mihomo 重载、端口迁移、Whistle 退出时须重验证。

### R06 / P0：系统代理端口不止一个使用位置

CVR [core/sysopt.rs:418-461](https://github.com/dompling/NetVerge/blob/2d032eec3932993943ce64536f220038b79947b7/src-tauri/src/core/sysopt.rs#L418-L461) 使用 MixedPort::desired() 构造全局系统代理/守护；[utils/server.rs:197-212](https://github.com/dompling/NetVerge/blob/2d032eec3932993943ce64536f220038b79947b7/src-tauri/src/utils/server.rs#L197-L212) PAC 端点又使用 desired() 替换模板。proxy_control.rs 还有服务与本地操作分支。

修正：不可修改 MixedPort::desired/effective 的语义来返回 Whistle 端口，否则会影响 Mihomo 自身配置、探测等调用者。若未来允许全局切换，应新增单独的 OS proxy target 概念，并覆盖守护、PAC、代理关闭、异常回退。Windows 首版不改其他平台路径，不复制 CVR 的整个状态机。

### R07 / P1：现有 smoke test 不足以证明真实集成

[smoke.test.cjs](https://github.com/dompling/NetVerge/blob/2d032eec3932993943ce64536f220038b79947b7/engines/whistle/smoke.test.cjs) 使用本地 HTTP server 作为上游，不是 Mihomo，只断言方法、Host 和 URL。测试尚未运行；没有 CONNECT、证书错误、上游断开、进程规则、真实出口与 DNS 验证。临时端口释放再绑定存在竞争窗口，清理回调先注册目录删除再注册子进程退出，在 Windows 上也需要验证资源释放顺序。

修正：先运行现有最小测试，修复确定失败，再增加真实 Mihomo 和可控目的服务。不要用公网站点是否打开作为唯一判据。

### R08 / P1：依赖和发布身份重复

原型 package.json 固定 Whistle 顶层版本，但没有独立 lockfile；npm install 仍可能解析不同传递依赖。CVR 原有 updater、产品标识和发布配置仍指向上游。

修正：生产前锁定 Node 版本、Whistle 传递依赖、平台架构与校验值；独立进程、数据目录、应用身份和更新渠道。先保留 Whistle 上游包，不为减小体积过早删除内部文件。对比带 WebUI 与精简模式实际占用，再决定优化。

## 3. 数据面方案重新比较

| 方案 | 数据路径 | 优点 | 局限 | 决策 |
|---|---|---|---|---|
| A 全局 Whistle 前置 | App -> Whistle -> Mihomo | 简单、覆盖广 | 所有 HTTP 增加一跳；进程规则变化；系统代理风险 | 不作为默认首版 |
| B 显式选择性调试 | 普通 App -> Mihomo；测试 App -> Whistle -> Mihomo | 不动既有系统代理；隔离容易；低迁移风险 | 需要应用支持显式代理，调试流量的进程语义仍变化 | 首选第一阶段 |
| C PAC 选择性分流 | 指定域名 -> Whistle；其他 -> Mihomo/原有 PAC 结果 | 可保留大部分原链路 | PAC 客户端兼容、URL 可见性、规则合并、守护状态 | 第二阶段候选 |
| D Mihomo 前置 + 命名回流入口 | App -> Mihomo -> Whistle -> 专用 Mihomo 入口 | 第一跳可保留原进程元数据；减少全局影响 | 第二跳仍丢失原进程和已选出口；CONNECT 语义、回环、二次分流、双计量 | 单独研究，不进入首版 |
| E 单内核重写 | Mihomo 内直接实现 HTTP/MITM | 理论上链路更短 | 大量协议、安全和上游维护负担 | 不采用 |

D 的源码可行性线索：Mihomo [listener/inbound/http.go](https://github.com/MetaCubeX/mihomo/blob/0455d0d28c4526937380505153e65a843d8612e8/listener/inbound/http.go) 提供具名 HTTP 监听器，[rules/common/in_name.go](https://github.com/MetaCubeX/mihomo/blob/0455d0d28c4526937380505153e65a843d8612e8/rules/common/in_name.go) 可按入口名匹配，[adapter/outbound/http.go](https://github.com/MetaCubeX/mihomo/blob/0455d0d28c4526937380505153e65a843d8612e8/adapter/outbound/http.go) 使用 CONNECT 建立出站 HTTP 代理隧道。具名入口可用于识别回流类别，但不能自动传递第一跳决策，也不能保证明文 HTTP 或 TLS 都能按预期进入 Whistle；不是已完成方案。

## 4. 推荐复用边界（收敛版）

### 原样保留
- CVR 的系统代理、PAC、代理守护、订阅、节点选择、DNS、TUN、连接和流量 UI。
- Mihomo 的网络代理与路由内核。
- Whistle HTTP 解析、请求响应修改、证书生成、会话缓存和必要插件接口。

### 复用接口，不复制实现
- 进程启动和状态事件：参考 CVR 状态机，不把 HTTP sidecar 塞进 Mihomo 提权服务。
- UI：复用 MUI、导航、编辑器、通用筛选、日志格式。暂不将连接页面强行改成 HTTP 请求页面。
- 配置：统一用户入口，不共享同一个物理 YAML 或 JS 执行环境。HTTP 规则由一个明确所有者持有。
- 统计：Mihomo 总流量，Whistle HTTP 诊断；对于本地 Mock 不应将本地流量当外网总流量；方案 D 更需独立验证二次统计。

### 暂不开发
- Surge 配置全面转换、自定义 TLS 引擎、双系统代理、双 DNS 配置、全量代理/捕获、TUN 联动。
- 不为追求单进程而将 Node/Whistle 移植到 Rust/Go。
- 不提前进行品牌重构和大规模 UI 修改。

## 5. 阶段 1 验证矩阵

保持原 CVR 系统代理配置不变；只启动明确指定的 Whistle 测试入口。在可控 Windows 测试机运行真实 Mihomo 与本地测试服务。

| 用例 | 对照与判定 |
|---|---|
| 基准 HTTP/HTTPS | 直连 Mihomo 与经 Whistle 比较目标响应、出口策略、目标域名 |
| 纯 HTTP Rewrite | 修改方法、头、请求体、响应体，观察目标实际收到和客户端实际得到的值 |
| HTTPS CONNECT | 未开启解密时隧道透明，不安装 CA、不修改 TLS 内容 |
| TLS 错误 | 后续仅在隔离测试 CA 环境验证上游证书错误不会被静默忽略 |
| 规则优先级 | 域名、IP、REJECT、Host/URL 改写、Mock、非法规则、上游不可用，禁止未授权直连 |
| 原进程规则 | 同一应用通过两个入口，对比 Mihomo 的 Process/ProcessPath/规则命中；记录不兼容 |
| DNS | 域名/IP 目标、代理端解析、DNS 缓存、Fake-IP（如适用），观察真实解析路径 |
| 生命周期 | Mihomo 关闭/改端口、Whistle 关闭、端口冲突、启动失败；不得修改系统代理或证书 |
| 本地安全 | 未认证管理请求、跨源访问、已有 Whistle 配置污染、数据目录权限 |
| 性能 | 同负载的 p50/p95、CPU/RSS、吞吐、冷启动、安装包体积及缓存增长 |

不要求首轮完成 MITM 正式安装或 PAC 集成。测试失败先归因，不将不同系统或内核版本的结果混为一个基准。

## 6. 复审结论与下一步边界

- V0.1 的 CVR 主壳 + Whistle sidecar 总方向保留，但默认流量接入策略改为 B（选择性显式调试）。
- 先解决原型隔离与测试，不更换系统代理端口，不写 UI，不合并 dev，不发布。
- P0 是正式接入的阻塞项，不代表原型不能在隔离环境下用于实验。
- 下一步仅允许在独立环境验证原型与实际 Mihomo 的基础串联，再根据结果决定是否值得继续集成。本文没有宣称任何运行测试已通过。
