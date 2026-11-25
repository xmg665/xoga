# `xoga` 流媒体 DNS 解锁与路由分流解锁完整教程

`xoga` 原生内置了**零内存膨胀**（无需加载几十 MB 的 `geoip.dat` / `geosite.dat`）的 **DNS 解锁引擎 (`/etc/xoga/dns.yml`)** 与 **多协议出站路由分流引擎 (`/etc/xoga/routes.toml`)**，完全兼容原版 `soga` 的配置文件语法，并且支持**修改保存后 5 秒内自动热重载**（无需重启服务、不断流）。

---

## 一、工作原理与防客户端本地解析污染（`domain_sniff`）

很多时候节点明明配好了 DNS 解锁或 WARP 分流，客户端还是提示未解锁，最常见的原因是：**用户的客户端（Clash / v2rayN / Shadowrocket）在本地提前把域名解析成了普通 IP**，把目标 IP 发给了节点，导致节点的域名规则失效。

`xoga` 在 `/etc/xoga/xoga.conf` 中默认开启了首包嗅探覆写：
```ini
domain_sniff=true
```
当客户端发来的是目标 IP 时，`xoga` 会在 0 分配嗅探层自动提取 **TLS ClientHello SNI** 或 **HTTP Host** 域名：
- 一旦该域名命中 `dns.yml` 或 `routes.toml` 中的解锁规则，`xoga` 会自动把目标重写回真实域名，再交给解锁 DNS 或远端 SOCKS5/SS/Trojan/VLESS 落地机处理，彻底杜绝客户端预解析导致的解锁失效。
- 普通未命中的直连流量不做多余 DNS 查询，保持零额外延迟。

---

## 二、方案 A：DNS 解锁配置教程 (`/etc/xoga/dns.yml`)

适用场景：你拥有自建 DNS 解锁机（`dnsmasq` + `sniproxy`）或购买了第三方流媒体 DNS 解锁服务（如 1Stream 等提供的解锁 IP 或 DoH 链接）。

编辑 `/etc/xoga/dns.yml`（保存后 **5 秒内自动生效**，无需 `xoga restart`）：

### 1. 使用解锁机 IP（UDP / TCP 53 端口）
```yaml
# 将 Netflix、Disney+、动画疯指向解锁 DNS IP，并强制只解析 IPv4（防止 VPS IPv6 抢占导致漏解锁）
"154.12.xx.xx":
  strategy: ipv4_only
  rules:
    - geosite:netflix
    - geosite:disney
    - geosite:bahamut
    - geosite:dazn
    - domain:hbomax.com

# 若需要指定 TCP 53 查询可写 tcp://8.8.8.8:53
"1.1.1.1":
  strategy: ipv4_first
  rules:
    - else
```

### 2. 使用 DoH（DNS over HTTPS）链接解锁（如 1Stream 等）
```yaml
"https://xxx.core.access.example.com/dns-query":
  strategy: ipv4_only
  rules:
    - geosite:netflix
    - geosite:disney
    - geosite:hbo
    - geosite:hulu
    - geosite:primevideo
    - geosite:openai
```

### 3. 远程托管统一 `dns.yml`（批量管理几十台节点）
如果多台节点共用同一份解锁规则，只需在 `/etc/xoga/xoga.conf` 中配置：
```ini
dns_config_url=https://your-oss-or-gist.example.com/dns.yml
dns_strategy=ipv4_first
```

---

## 三、方案 B：路由分流解锁教程 (`/etc/xoga/routes.toml`)

适用场景：本机挂载了 **Cloudflare WARP (`127.0.0.1:40000`)** 解锁 ChatGPT / Claude / Gemini，或将流媒体流量转发到另一台干净的**解锁落地机**（支持 `socks` / `socks5`、`http`、`ss`、`trojan`、`vless`、或双栈机指定 `ipv6_only` / 指定源网卡 IP 直连）。

编辑 `/etc/xoga/routes.toml`（保存后 **5 秒内自动热重载**，完全兼容原版 `soga` 的 `[[routes]]` + `[[routes.Outs]]` 写法）：

### 场景 1：OpenAI / Claude / Gemini / Grok 走本机 WARP (`127.0.0.1:40000`)

#### 第 1 步：在节点一键启动轻量 `wireproxy`（或 `warp-svc`）监听本地 `40000` 端口
如果机器已经跑着 `127.0.0.1:40000` 的 SOCKS5（例如 `warp-cli set-mode proxy` + `warp-cli set-proxy-port 40000`），可直接跳到第 2 步。

#### 第 2 步：配置 `/etc/xoga/routes.toml`
你可以直接使用原版 `soga` 的 `domain:` 列表，也可以使用更简洁的内置 `geosite:` 集合：

```toml
enable=true

# ---------- AI 平台全部走本地 WARP SOCKS5 (127.0.0.1:40000) ----------
[[routes]]
name = "ai-warp"
rules = [
  "geosite:openai",
  "geosite:claude",
  "geosite:gemini",
  "geosite:perplexity",
  "geosite:grok",
  "geosite:metaai",
  "geosite:copilot",
  "domain:whatismyipaddress.com"
]

[[routes.Outs]]
type = "socks"
server = "127.0.0.1"
port = 40000

# ---------- 兜底直连，放最后 ----------
[[routes]]
rules = ["*"]
[[routes.Outs]]
type = "direct"
```

---

### 场景 2：流媒体分流到远端 Shadowsocks / Trojan / VLESS 解锁落地机（支持负载均衡与主备容灾）

当同一个 `[[routes]]` 下配置多个 `[[routes.Outs]]` 时，`xoga` 支持：
- `balance = "first"`：**主备容灾**（优先走第 1 台落地机，若第 1 台连接超时自动毫秒级无缝切换到第 2 台）
- `balance = "round_robin"`：**轮询负载均衡**（多台落地机平摊带宽，某台故障自动回退到其余可用节点）
- `balance = "random"`：**随机负载均衡**

```toml
enable=true

[[routes]]
name = "media-unlock-landing"
balance = "first"
rules = [
  "geosite:netflix",
  "geosite:disney",
  "geosite:tiktok",
  "geosite:bahamut",
  "geosite:dmm",
  "geosite:abema"
]

# 主落地：Shadowsocks AEAD 节点
[[routes.Outs]]
type = "ss"
server = "tw-unlock-1.example.com"
port = 28388
cipher = "aes-256-gcm"
password = "your_ss_password"

# 备用落地：Trojan 节点（当主落地不可达时自动接管）
[[routes.Outs]]
type = "trojan"
server = "tw-unlock-2.example.com"
port = 443
password = "your_trojan_password"
sni = "tw-unlock-2.example.com"
skip_cert_verify = false

# 也可使用 VLESS + WS + TLS 落地：
# [[routes.Outs]]
# type = "vless"
# server = "hk-unlock.example.com"
# port = 443
# uuid = "b831381d-6324-4d53-ad4f-8cda48b30811"
# tls = true
# sni = "hk-unlock.example.com"
# network = "ws"
# ws_path = "/vless"

[[routes]]
rules = ["*"]
[[routes.Outs]]
type = "direct"
```

---

### 场景 3：多 IP 站群机 / 双栈机指定干净源 IP 或纯 IPv6 解锁

部分 VPS 的主 IPv4 被 Google 送中或被 Netflix 标记，但**副 IPv4** 或赠送的原生 **IPv6** 是干净解锁的：

```toml
enable=true

# 让 Netflix / Google / YouTube 强制走本机原生 IPv6 出站
[[routes]]
name = "clean-ipv6-direct"
rules = [
  "geosite:netflix",
  "geosite:youtube",
  "geosite:google"
]
[[routes.Outs]]
type = "direct"
listen_strategy = "ipv6_only"
# 如有多块网卡/多个 IP，还可显式绑定出口源 IP：
# listen_ipv4 = "198.51.100.12"
# listen_ipv6 = "2001:db8::8888"

[[routes]]
rules = ["*"]
[[routes.Outs]]
type = "direct"
```

---

### 场景 4：单进程多节点聚合 + 按 `node_id` 绑定多隧道 / 站群源 IP 出口

当一台入口/中转落地机挂载了多条 OpenVPN / WireGuard 隧道（如 `tun0` ~ `tun35`）或多块弹性网卡 IP 时，可在 `xoga.conf` 配置 `node_id=781,782,784`，并在 `/etc/xoga/routes.toml` 中按节点 ID 指定独立出口源 IP（100% 兼容原版 `soga` 的 `listen = "..."` 语法，TCP 与 UDP 均自动绑定）：

```toml
[[routes]]
rules = ["node_id:781"]
[[routes.Outs]]
listen = "10.163.0.100"  # 节点 781 绑定澳门隧道出口 IP
type = "direct"

[[routes]]
rules = ["node_id:782"]
[[routes.Outs]]
listen = "10.163.0.108"  # 节点 782 绑定台北隧道出口 IP
type = "direct"

# 也可将指定节点的特定域名（如 AI）单独分流至本地 WARP：
[[routes]]
rules = ["node_id:851", "geosite:openai"]
[[routes.Outs]]
type = "socks"
server = "127.0.0.1"
port = 40000
```

---

## 四、内置零内存 `geosite:` 规则速查表

无需下载维护任何 `.dat` 文件，以下标签在 `dns.yml` 与 `routes.toml` 中开箱即用：

| 类别 | 内置标签 |
| :--- | :--- |
| **AI 大模型** | `geosite:openai` (`chatgpt`)、`geosite:claude` (`anthropic`)、`geosite:gemini`、`geosite:perplexity`、`geosite:grok` (`xai`)、`geosite:metaai`、`geosite:copilot` |
| **国际流媒体** | `geosite:netflix`、`geosite:disney`、`geosite:youtube`、`geosite:hbo`、`geosite:hulu`、`geosite:primevideo`、`geosite:dazn`、`geosite:spotify` |
| **港台日区域流媒体** | `geosite:bahamut`（动画疯）、`geosite:bilibili`、`geosite:tvb`、`geosite:viu`、`geosite:abema`、`geosite:dmm`、`geosite:tiktok` |
| **常用平台** | `geosite:google`、`geosite:apple`、`geosite:telegram`、`geosite:twitter` |
| **自定义匹配前缀** | `domain:xxx.com`（域名及子域名）、`full:a.xxx.com`（精确匹配）、`keyword:openai`（关键字）、`regexp:.*\.nflx.*`（正则）、`1.2.3.0/24`（IP/CIDR） |

---

## 五、从原版 `soga` 无缝迁移清单

如果你已有现成的 `/etc/soga/` 目录（包含 `soga.conf`、`routes.toml`、`dns.yml`、`blockList`、`whiteList`），`xoga` 已完整兼容以下配置键：
- `type=sspanel-uim` / `v2board` / `xboard` / `newv2board`
- `server_type=v2ray`（自动识别 `vless=true/false`、`v2ray_reduce_memory=true`）、`vless`、`trojan`、`ss`
- `proxy_protocol=true`、`forbidden_ports=25,26,...,6881-6999`、`forbidden_bit_torrent=true`
- `redis_enable` / `redis_addr` / `redis_password` / `redis_db` / `conn_limit_expiry`

只需一行命令即可把原版配置平滑迁移到 `xoga`：
```bash
cp -f /etc/soga/soga.conf /etc/xoga/xoga.conf
cp -f /etc/soga/routes.toml /etc/xoga/routes.toml
cp -f /etc/soga/dns.yml /etc/xoga/dns.yml
xoga restart
xoga log -f
```

---

## 六、如何验证解锁已生效

1. 在 `routes.toml` 的解锁规则中临时加入 `"domain:whatismyipaddress.com"` 或 `"full:ip.sb"`（无需重启，等 5 秒自动热加载）。
2. 客户端连接该节点，在浏览器或终端访问 `https://ip.sb` 或打开 ChatGPT / Netflix。
3. 查看 `xoga log -f` 无报错，且 `ip.sb` 显示为你的 WARP IP / 落地机 IP，即代表分流解锁生效。
