# NetVerge 第一步：最小 MITM 集成（V0.3 范围决策）

本文件收敛 V0.1 / V0.2 的研发范围。目标不是完整移植 Whistle，而是在保留 CVR / Mihomo 的网络接管能力前提下，验证指定 HTTPS 流量能够被 Whistle 解密，并继续按预期代理访问。本文仅为实施范围，不代表功能已实现。

## 1. 职责

- CVR：现有 TUN 开关、系统代理、配置、节点、DNS、进程及连接管理均保持不变。
- Mihomo：网络入口、原始流量识别、普通流量转发，以及选择性导入 MITM 的候选路由。
- Whistle：复用现成的 CONNECT、TLS 拦截、CA/叶证书生成、HTTP 解析和最小请求观测；作为 sidecar，不移植内部 TLS 源码、不启动独立桌面壳、不修改系统代理。
- NetVerge 新增最少的控制逻辑：启停、健康检查、授权的证书安装/撤销、MITM 域名列表及受控回流配置。默认关闭。

## 2. 候选链路（需实测）

普通流量：App -> Mihomo TUN -> 原有策略 -> 目标。
命中授权域名的 HTTPS TCP 流量：App -> Mihomo TUN -> Whistle HTTP outbound (CONNECT) -> TLS 解密/HTTP 解析 -> Mihomo 专用回流入站 -> 预期策略 -> 目标。

源码依据：
- [Mihomo HTTP outbound](https://github.com/MetaCubeX/mihomo/blob/0455d0d28c4526937380505153e65a843d8612e8/adapter/outbound/http.go#L91-L145) 会建立 CONNECT 隧道。
- [Whistle tunnel](https://github.com/avwo/whistle/blob/e039fd86bc70928b0de7abc2f71a1612d530b370/lib/tunnel.js#L150-L225) 存在按规则控制 HTTPS 拦截的逻辑。
- [Mihomo named inbound](https://github.com/MetaCubeX/mihomo/blob/0455d0d28c4526937380505153e65a843d8612e8/listener/inbound/http.go) 和 [IN-NAME rule](https://github.com/MetaCubeX/mihomo/blob/0455d0d28c4526937380505153e65a843d8612e8/rules/common/in_name.go) 提供区分回流入口的依据。

以上不等于已证明组合可行。实际打包的 Mihomo 版本、CONNECT 内 TLS 数据、域名识别、回流规则及出口均需核对。回流入口应明确不再匹配 MITM 规则；第二跳不会天然保留第一跳进程信息或已选策略，先限定可明确验证的域名和出口，不承诺全量透明兼容。

## 3. 最小功能

| 能力 | 首步 |
| --- | --- |
| 原有 TUN、DNS、订阅、代理节点 | 原样保留 |
| Whistle 模块启动/停止与真实上游探测 | 必需 |
| MITM 主开关及指定域名 | 必需 |
| 独立 CA、显式安装/撤销 | 必需（先隔离测试证书） |
| 最小 HTTPS 请求观测 | 必需，验证 URL/方法/状态；正文仅按需显示 |
| Rewrite、Mock、Script、Surge Module | 暂不开发 |
| Whistle 独立 WebUI / 插件 / 更新 | 不作为产品功能，控制面隔离与认证 |
| 全局解密、QUIC/HTTP3、证书锁定绕过 | 不支持；不得静默降级 |

## 4. 实施顺序与停止条件

1. 隔离验证：保持系统代理、TUN 配置不变，通过显式 Whistle 入口验证 HTTP/CONNECT、选择性 TLS 解密、真实 Mihomo 上游、有效与无效证书。测试使用受控服务器与专用测试客户端，CA 仅在明确授权的测试环境信任。先消除原型的环境配置污染、未认证管理端口、上游健康检查问题。
2. TUN 集成可行性实验：固定一个受控 HTTPS 域名，使用现有 Mihomo 的具名入口/规则能力接入 Whistle；确认实际数据走向、无代理循环、普通流量路径不变、上游不可用时不静默直连。若域名或出口语义不能保持，停止扩展并保留显式代理模式。
3. 最小桌面功能：仅增加 MITM 开关、域名管理、证书信任管理、引擎状态、最小请求查看。复用 CVR UI 和生命周期框架；不改既有系统代理主责。
4. 在 Windows 验收关闭/异常退出/重启/端口变化与原有代理功能回归后，再决定第二阶段（Rewrite）。

首步完成标准：开启既有 TUN 后，授权测试域名的 HTTPS 请求可被正确解密并显示完整 URL，客户端正常获得响应；普通流量不经过 Whistle；关闭 MITM 或引擎失效后，受控恢复且没有未授权的直连；未选择域名不解密。QUIC、证书锁定及原进程策略不兼容须明确告知，不绕过安全校验。

## 5. 当前状态

仅更新范围决策。已有 engines/whistle 原型仍未实测，不能作为 MITM 已完成的证据。不合并 dev、不发布、不提前开发其他功能。


> Superseding product decision: [review 12](mitm-desktop-review-12.md). Fixed-return topology is historical lab only; original routing inheritance is mandatory before desktop activation.
