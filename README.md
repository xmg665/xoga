# xoga — 高性能极低内存代理节点后端

`xoga` 是参考 `soga` 部署与运维操作习惯、使用纯 **Go** 从零重构的开源轻量级多协议节点后端，原生对接 **V2Board / NewV2Board / Xboard (`UniProxy`)** 与 **SSPanel-UIM / SSPanel-Metron (`mod_mu`)** 面板，针对 **CPU 与常驻内存** 进行了深度工程级优化。

---

## 核心特性与性能优化对比

| 维度 | 原版 `soga` + `soga-cmd` | `xoga` 重构版 |
| :--- | :--- | :--- |
| **构建体积** | `soga` (~85.8 MB) + `soga-cmd` (~7.5 MB) = **~93.3 MB** | **单二进制集成守护进程 + CLI (~7 MB)**，体积缩减 **>92%** |
| **外部依赖** | 捆绑数十个云厂商 SDK、`gopsutil`、重量级 GeoIP/GeoSite | 仅依赖官方扩展库 `golang.org/x/crypto`，纯标准库零臃肿 |
| **转发零拷贝** | 用户态缓冲区拷贝为主 | Linux 内核态 **`splice(2)` 4MiB 窗口零拷贝直通（含 `proxy_protocol=true` 穿透解包）** + `TCP_FASTOPEN` + 64-bit WebSocket 掩码加速 |
| **鉴权与抗重放** | 多用户线性遍历 / 磁盘落盘缓存文件 | **无锁 `O(1)` IP→User Hint 内存缓存（零磁盘 I/O，5000+ 用户 VMess/SS 毫秒级降载）** + 零分配栈上 `vmessKDF` + 双代原子布隆防重放过滤器 |
| **多节点与路由** | 多开或重量级规则扫描 | **单进程多节点聚合 (`node_id=781,782,...`)** 共享内存池/连接池 + **`O(labels)` 零分配域名后缀哈希树** + `node_id:xxx` 独立源 IP 出口绑定 |
| **面板与 DNS** | 周期性重复拉取 / 并发重复解析 | **HTTP/2 Keep-Alive + `ETag` (`304`) 短路** + 跨节点共享审计规则缓存 + **DNS `singleflight` 合并与 RFC 8767 过期兜底 (`Serve-Stale`)** |
| **限速流控** | 互斥锁令牌桶 | **无锁 CAS 虚拟到达时间 (GCRA) 限速器** + 动态触发限速 (`dy_limit_*`) + 长连接复用 RESP Redis 全局设备数限制 |
| **常驻内存** | 常见 80 ~ 500+ MiB | 空载 **~8 ~ 14 MiB**，内置 `GOMEMLIMIT` + `GOGC` 软上限与周期性 `MADV_DONTNEED` 内存归还 |

---

## 支持的面板与协议

- **对接面板 (`type=`)**：`v2board`、`newv2board`、`xboard`、`sspanel`（兼容 UIM `custom_config` 与 Metron 分号节点串）
- **节点协议 (`server_type=`)**：
  - `vless`：VLESS v0 TCP / UDP（`[16]byte` UUID O(1) 无锁检索，Scatter-Gather 零拷贝响应头）
  - `trojan`：Trojan TCP / Trojan-UDP Associate（SHA-224 `[56]byte` O(1) 无锁检索）
  - `shadowsocks` / `ss`：经典 AEAD（`aes-128-gcm`、`aes-256-gcm`、`chacha20-ietf-poly1305`）及 **Shadowsocks-2022**（`2022-blake3-aes-128-gcm`、`2022-blake3-aes-256-gcm`，支持单密钥与 V2Board/Xboard `server_key` 多用户 **EIH** 身份头）
  - `vmess` / `v2ray`：现代 VMess AEAD（AES-128-GCM / ChaCha20-Poly1305 / Shake128 长度掩码与 `GlobalPadding` 混淆 / VMess UDP-over-TCP，内置无锁 IP→User `O(1)` 缓存与零分配栈上 KDF）
- **单进程多节点聚合与 Docker 环境变量模式**：
  - 支持 `node_id=781,782,783-790` 单进程同时承载数十个节点（共享同一个 Go 运行时、HTTP/2 面板连接池、DNS 缓存与 `routes.toml` 路由快照，错峰同步防面板拥塞）
  - 支持 `routes.toml` 按 `rules=["node_id:781"]` + `listen = "10.163.0.100"` 将不同节点精准绑定至不同 TUN 隧道 / 多 IP 站群源地址出口（TCP 与 UDP 均生效）
  - 兼容原版 `vaxilu/soga` Docker 环境变量无配置文件启动（`IS_DOCKER=true` + 环境变量注入 + 自动兼容 `/etc/soga/routes.toml` 挂载路径）
- **传输与中转特性**：
  - 原生 TCP / TLS 1.2 & 1.3（支持手动证书热重载、内置 Let's Encrypt `cert_mode=http` 自动签发、内存自签 ECDSA P-256 证书、`force_close_ssl=true` 反代落盘）
  - WebSocket（RFC 6455 零依赖升级、支持 `?ed=2048` `Sec-WebSocket-Protocol` Early Data、自动透传 `CF-Connecting-IP` / `X-Real-IP` / `X-Forwarded-For` 真实客户端 IP）
  - HAProxy **PROXY Protocol v1 & v2**（`proxy_protocol=true` 中转真实 IP 识别）
  - 零分配首包协议嗅探（TLS ClientHello SNI、HTTP Host、BitTorrent / DHT / uTP / Tracker 协议自动封禁）与审计/分流路由（`blockList`、`whiteList`、`routes.toml`、面板下发动态路由）
  - **流媒体 DNS 解锁与多协议路由分流解锁（支持 5 秒自动热重载，无需重启）**：
    - `dns.yml`：支持 UDP / TCP / **DoH (`https://.../dns-query`)** 分流解析、支持 `ipv4_only` / `ipv6_only` / `ipv4_first` 策略与远程 `dns_config_url`
    - `routes.toml`：100% 兼容 `soga` 原生 `[[routes]]` + `[[routes.Outs]]`（支持本机 **WARP `socks` `:40000`**、`socks5`、`http`、`ss`、`trojan`、`vless` 落地机轮询/主备容灾及双栈 `ipv6_only` / 指定网卡源 IP 直连）
    - 内置零内存流媒体/AI `geosite:` 规则集（`netflix`、`disney`、`openai`、`claude`、`gemini`、`perplexity`、`grok`、`tiktok`、`bahamut` 等开箱即用，无需几十 MB 的 `.dat` 文件）
    - 默认开启 `domain_sniff=true` 自动识别客户端预解析 IP 并还原真实 SNI/Host 域名，杜绝客户端本地 DNS 污染导致漏解锁
    - 完整实战配置见 👉 **[《流媒体 DNS 解锁与路由分流解锁完整教程 (docs/UNLOCK_GUIDE.md)》](docs/UNLOCK_GUIDE.md)**
    - 脚本与容器完整手册见 👉 **[《一键脚本、多实例与 Docker 部署完整教程 (docs/DOCKER_AND_SCRIPT_GUIDE.md)》](docs/DOCKER_AND_SCRIPT_GUIDE.md)**

---

## 一键安装与快速对接（完全参考 `soga` 操作）

### 1. 标准一键安装
```bash
bash <(curl -Ls https://raw.githubusercontent.com/xmg665/xoga/main/install.sh)
```

### 2. 安装同时直接写入节点配置并启动（支持单进程多节点聚合）
```bash
# 对接 V2Board / Xboard
bash <(curl -Ls https://raw.githubusercontent.com/xmg665/xoga/main/install.sh) \
  type=v2board \
  server_type=vless \
  node_id=1 \
  webapi_url=https://your-panel.example.com \
  webapi_key=your_communication_token

# 对接 SSPanel-UIM（单进程同时聚合承载多个节点）
bash <(curl -Ls https://raw.githubusercontent.com/xmg665/xoga/main/install.sh) \
  type=sspanel-uim \
  server_type=v2ray \
  node_id=781,782,783,784 \
  proxy_protocol=true \
  webapi_url=https://your-panel.example.com/ \
  webapi_key=your_mu_key
```

### 3. Docker 一键启动（100% 兼容 `vaxilu/soga` 环境变量与 `/etc/soga/routes.toml` 挂载）
```bash
docker run -d \
  --name xoga \
  --restart always \
  --net host \
  --ulimit nofile=1048576:1048576 \
  -e TZ=Asia/Shanghai \
  -e type=sspanel-uim \
  -e server_type=v2ray \
  -e node_id=851 \
  -e webapi_url=https://your-panel.example.com/ \
  -e webapi_key=your_mu_key \
  -e proxy_protocol=true \
  -v /etc/sg/aomen.toml:/etc/soga/routes.toml \
  ghcr.io/xmg665/xoga:latest
```
更多 `docker-compose.yml`、多开实例（`xoga new`）与迁移示例请阅读 👉 **[docs/DOCKER_AND_SCRIPT_GUIDE.md](docs/DOCKER_AND_SCRIPT_GUIDE.md)**。

---

## 命令行与多实例管理

安装完成后直接输入 `xoga` 即可呼出交互式彩色管理菜单，或使用与 `soga` 完全一致的子命令：

```bash
xoga                              # 显示交互式管理菜单
xoga list                         # 列出所有实例、运行状态与实时 systemd 内存占用
xoga new hk2 type=xboard server_type=trojan node_id=2 webapi_url=https://... webapi_key=...
xoga remove hk2                   # 停止并移除指定多开实例
xoga rename hk2 jp1               # 重命名多开实例
xoga start [name]                 # 启动默认实例或指定实例
xoga stop [name]                  # 停止实例
xoga restart [name]               # 重启实例
xoga status [name]                # 查看实例运行状态与实时内存
xoga enable [name]                # 设置开机自启
xoga disable [name]               # 取消开机自启
xoga log [name]                   # 查看最近 1000 行日志
xoga log [name] -f                # 实时跟踪日志输出
xoga config [name]                # 查看实例配置文件
xoga config [name] node_id=3 user_conn_limit=3   # 快速修改单个或多个配置项
xoga update [version]             # 在线更新到最新版或指定版本
xoga uninstall                    # 完全卸载 xoga 及所有实例
xoga version                      # 查看版本号
```

---

## 配置文件说明 (`/etc/xoga/xoga.conf`)

完全兼容 `soga.conf` 常用字段，并新增底层 CPU/内存调优开关：

```ini
# 基础对接配置
type=v2board                 # 可选: v2board, newv2board, xboard, sspanel
server_type=vless            # 可选: vless, trojan, shadowsocks (ss), vmess (v2ray)
node_id=1
api=webapi

webapi_url=https://panel.example.com
webapi_key=your_panel_token

# 证书与反代
cert_file=
key_file=
cert_mode=                   # http (自动申请 Let's Encrypt) / self (内存自签) / 留空
cert_domain=
force_close_ssl=false        # 设为 true 强制关闭本地 TLS，便于前置 Nginx/Caddy 反代

# 中转与全局设备限制
proxy_protocol=false         # 开启后自动解析 PROXY Protocol v1/v2 获取真实客户端 IP
user_conn_limit=0            # 单用户在线 IP 数限制 (0 跟随面板 device_limit)
user_speed_limit=0           # 单用户限速 Mbps (0 跟随面板 speed_limit)
user_tcp_limit=0             # 单用户最大并发 TCP 连接数
node_speed_limit=0           # 节点总带宽上限 Mbps

# 动态限速 (与 soga 一致)
dy_limit_enable=false
dy_limit_trigger_time=60
dy_limit_trigger_speed=100
dy_limit_speed=30
dy_limit_time=600
dy_limit_white_user_id=

# CPU & 内存深度调优参数
enable_zero_copy=true        # 无速率限制时启用 Linux splice(2) 内核态零拷贝转发
mem_limit_mb=128             # Go 运行时 GOMEMLIMIT 软内存上限 (MiB)
gc_percent=50                # GOGC 回收百分比，降低常驻堆体积
conn_idle_sec=300            # 空闲 TCP 连接回收秒数
udp_idle_sec=60              # 空闲 UDP 会话回收秒数
```

---

## 本地源码编译

```bash
git clone https://github.com/xmg665/xoga.git
cd xoga
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o xoga ./cmd/xoga
```
