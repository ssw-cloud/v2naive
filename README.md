# v2naive

一个独立的 naive 节点服务端，按 `wyx2685/v2board` 的接口习惯对接：

- 配置拉取：`/api/v2/server/config`
- 用户拉取：`/api/v1/server/UniProxy/user`
- 流量上报：`/api/v1/server/UniProxy/push`
- 在线上报：`/api/v1/server/UniProxy/alive`

当前实现重点：

- `v2node` 节点类型下的 `protocol=naive`
- TLS + HTTP/2 / HTTP/1.1 forward proxy
- 用户热更新
- 用户流量统计
- 在线 IP 上报
- 基础证书模式：`file` / `self` / `http` / `dns`
- Basic Auth 用户名/密码都使用用户 `uuid`

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

默认会优先下载 GitHub Release 里的 Linux 二进制包，只有在找不到对应 release 时才会回退到源码编译。

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
