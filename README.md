# v2naive

一个独立的 naive 节点服务端，按 `wyx2685/v2board` 的接口习惯对接：

- 配置拉取：`/api/v2/server/config`
- 用户拉取：`/api/v1/server/UniProxy/user`
- 流量上报：`/api/v1/server/UniProxy/push`
- 在线上报：`/api/v1/server/UniProxy/alive`

当前实现重点：

- `v2node` 节点类型下的 `protocol=naive`
- `Runtime.Engine=caddy` 时使用官方 `klzgrad/forwardproxy@naive` 运行真 naive 协议
- `Runtime.Engine=legacy` 时保留旧的 TLS + HTTP/2 / HTTP/1.1 forward proxy，方便回滚
- 用户热更新
- 基础证书模式：`file` / `self` / `http` / `dns`
- Basic Auth 用户名/密码都使用用户 `uuid`

当前重构状态：

- `caddy` 引擎优先解决“真 naive 协议兼容”
- `legacy` 引擎仍然保留完整的旧计费链路
- `caddy` 引擎已经能回传每条 naive 隧道的用户/IP/上下行字节，并通过本地鉴权口做设备数限制
- `caddy` 引擎的下一段重点还剩速率限制的实战压测和更细的异常恢复

面板侧约定：

- 在 `v2node` 节点里选择 `protocol=naive`
- `host` 填写客户端实际连接的域名
- `tls_settings.server_name` 建议与证书域名一致
- `listen_ip` 一般填 `0.0.0.0`

示例配置：

```yaml
Log:
  Level: info
  Output: /var/log/v2naive/v2naive.log

Runtime:
  Engine: caddy
  CaddyPath: /opt/v2naive/caddy
  WorkingDir: /var/lib/v2naive
  AdminPortBase: 22019

Nodes:
  - ApiHost: "https://your-panel.example.com"
    NodeID: 1
    ApiKey: "your-server-token"
    Timeout: 15
    RetryCount: 2
```

也可以直接复制 [config.yml.example](config.yml.example)。

构建：

```bash
go build -o v2naive .
```

运行：

```bash
go run . -config config.yml
```

一键安装：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/ssw-cloud/v2naive/main/script/install.sh) \
  --api-host "https://your-panel.example.com" \
  --node-id 1 \
  --api-key "your-server-token"
```

同一台 VPS 部署多个节点 ID：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/ssw-cloud/v2naive/main/script/install.sh) \
  --api-host "https://your-panel.example.com" \
  --node-id 1,2,3 \
  --api-key "your-server-token"
```

也可以重复传入 `--node-id`，例如 `--node-id 1 --node-id 2 --node-id 3`。脚本会在 `/etc/v2naive/config.yml` 里生成多条 `Nodes`，但这些节点在面板下发的服务端口不能互相冲突。

默认会优先下载 GitHub Release 里的 Linux 二进制包，只有在找不到对应 release 时才会回退到源码编译。
不指定 `--version` 时会自动使用 latest release。

统一升级已有节点：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/ssw-cloud/v2naive/main/script/install.sh) --upgrade
```

`--upgrade` 会复用现有 `/etc/v2naive/config.yml`，只更新二进制、Caddy runtime、systemd 服务和 logrotate，不会重写节点 ID、面板地址或 API key。

私有仓库安装/升级：

```bash
read -rsp "GitHub token: " V2NAIVE_GITHUB_TOKEN; echo
export V2NAIVE_GITHUB_TOKEN
bash <(curl -fsSL \
  -H "Authorization: Bearer ${V2NAIVE_GITHUB_TOKEN}" \
  -H "Accept: application/vnd.github.raw" \
  "https://api.github.com/repos/ssw-cloud/v2naive/contents/script/install.sh?ref=main") --upgrade
unset V2NAIVE_GITHUB_TOKEN
```

token 只需要对该私有仓库有只读权限。脚本会用同一个 `V2NAIVE_GITHUB_TOKEN` 下载私有 release 资产；只有 release 资产不可用或强制源码构建时才会拉取源码。

当 `Engine=caddy` 时，安装脚本还会额外构建一个带本地统计补丁的 `forwardproxy@naive` 运行时：

- 会优先下载 release 里的 `v2naive_caddy_linux_<arch>.tar.gz`
- 没有对应 release 时，再自动同步本仓库源码
- 然后用 `xcaddy` 从 [runtime/forwardproxy](/Users/raoziyang/CodexProjects/v2naive/runtime/forwardproxy/go.mod:1) 构建自定义 Caddy
- 这样 `v2naive` 才能拿到每条 naive 隧道的用户/IP/上下行事件，继续对接 v2board 的流量与在线上报

如果要指定版本：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/ssw-cloud/v2naive/main/script/install.sh) \
  --version "v0.1.0" \
  --api-host "https://your-panel.example.com" \
  --node-id 1 \
  --api-key "your-server-token"
```

如果你明确要强制源码编译：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/ssw-cloud/v2naive/main/script/install.sh) \
  --build-from-source \
  --api-host "https://your-panel.example.com" \
  --node-id 1 \
  --api-key "your-server-token"
```

systemd 模板见 [deploy/v2naive.service](deploy/v2naive.service)。
