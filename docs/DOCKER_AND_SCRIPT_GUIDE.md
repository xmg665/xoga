# `xoga` 一键脚本与 Docker 部署完整教程

`xoga` 同时支持 **宿主机一键脚本（Systemd 单实例 / 多实例 / 单进程多节点聚合）** 与 **Docker / Docker Compose 容器化部署**，100% 兼容原版 `soga` 的配置文件键名、Docker 环境变量以及 `/etc/soga/routes.toml` 挂载路径。

---

## 第一部分：一键脚本安装与管理教程（推荐生产环境）

### 1. 标准一键安装
```bash
bash <(curl -Ls https://raw.githubusercontent.com/xmg665/xoga/main/install.sh)
```
安装完成后会自动生成默认配置文件 `/etc/xoga/xoga.conf`、`routes.toml`、`dns.yml`、`blockList`、`whiteList`，并注册开机自启服务 `xoga.service`。

### 2. 一键安装并直接写入面板配置启动

#### 对接 V2Board / Xboard / NewV2Board
```bash
bash <(curl -Ls https://raw.githubusercontent.com/xmg665/xoga/main/install.sh) \
  type=xboard \
  server_type=vless \
  node_id=1 \
  webapi_url=https://panel.example.com \
  webapi_key=your_communication_token
```

#### 对接 SSPanel-UIM / Metron（支持单进程同时跑几十个节点！）
```bash
bash <(curl -Ls https://raw.githubusercontent.com/xmg665/xoga/main/install.sh) \
  type=sspanel-uim \
  server_type=v2ray \
  node_id=781,782,783,784,785 \
  proxy_protocol=true \
  webapi_url=https://api.example.com/ \
  webapi_key=your_mu_key
```

---

### 3. `xoga` 常用管理命令速查

直接输入 `xoga` 可呼出彩色交互式管理菜单，也可直接使用命令行操作：

| 命令 | 功能说明 |
| :--- | :--- |
| `xoga` | 打开交互式可视化管理菜单 |
| `xoga list` | 查看本机所有实例的运行状态、节点 ID、开机自启与**实时内存占用** |
| `xoga status [实例名]` | 查看默认实例或指定多开实例的详细状态 |
| `xoga start / stop / restart [实例名]` | 启动 / 停止 / 重启默认实例或指定多开实例 |
| `xoga enable / disable [实例名]` | 开启 / 关闭开机自启 |
| `xoga log [实例名] -f` | 实时滚动查看节点运行日志（不加 `-f` 查看最近 1000 行） |
| `xoga config [实例名]` | 打印当前实例配置文件内容 |
| `xoga config [实例名] k1=v1 k2=v2` | 快速修改一个或多个配置项（保留原注释格式） |
| `xoga new <实例名> [k1=v1 ...]` | 新建独立 Systemd 多开实例（对应 `/etc/xoga/<实例名>.conf`） |
| `xoga remove <实例名>` | 停止并删除指定多开实例 |
| `xoga rename <旧名> <新名>` | 重命名多开实例 |
| `xoga update [版本号]` | 在线升级到最新版或指定版本（如 `xoga update 1.2.2`） |
| `xoga uninstall` | 彻底卸载 `xoga` 及所有实例服务 |

---

### 4. 单机多实例（`xoga new`）实战示例

如果一台服务器除了主多节点服务外，还需要跑一个使用独立路由表（例如独立挂载 `/etc/sg/aomen.toml` 走本机 WARP `:40000`）的专属节点：

```bash
xoga new aomen \
  type=sspanel-uim \
  server_type=v2ray \
  node_id=851 \
  webapi_url=https://api.example.com/ \
  webapi_key=your_mu_key \
  proxy_protocol=true \
  routes_file=/etc/sg/aomen.toml

# 查看所有实例状态与内存
xoga list

# 单独重启或查看 aomen 实例日志
xoga restart aomen
xoga log aomen -f
```

---

### 5. 从原版 `/etc/soga` 一键平滑迁移到 `xoga`

```bash
# 1. 安装 xoga
bash <(curl -Ls https://raw.githubusercontent.com/xmg665/xoga/main/install.sh)

# 2. 直接复用现有 soga 配置与分流规则
cp -f /etc/soga/soga.conf /etc/xoga/xoga.conf
cp -f /etc/soga/routes.toml /etc/xoga/routes.toml
cp -f /etc/soga/dns.yml /etc/xoga/dns.yml

# 3. 停用原 soga 并启动 xoga 接管端口
systemctl stop soga && systemctl disable soga
xoga restart
xoga list
```

---

## 第二部分：Docker 与 Docker Compose 部署教程

`xoga` 官方镜像体积极小（Alpine 基础镜像 + 纯静态二进制仅 **~14 MB**），且原生内置 `IS_DOCKER=true` 模式，**可直接无缝替换 `vaxilu/soga` 容器启动命令**。

### 方式 1：`docker run` 纯环境变量启动（100% 兼容 `vaxilu/soga` 命令与挂载路径）

无需编写 `xoga.conf`，直接通过 `-e` 传入面板参数，并且原 `/etc/soga/routes.toml` 挂载路径无需修改即可自动识别与 5 秒热加载：

```bash
docker run -d \
  --name xoga-aomen \
  --restart always \
  --net host \
  --ulimit nofile=1048576:1048576 \
  -e TZ=Asia/Shanghai \
  -e type=sspanel-uim \
  -e server_type=v2ray \
  -e node_id=851 \
  -e webapi_url=https://api.example.com/ \
  -e webapi_key=your_mu_key \
  -e proxy_protocol=true \
  -e v2ray_reduce_memory=true \
  -v /etc/sg/aomen.toml:/etc/soga/routes.toml \
  ghcr.io/xmg665/xoga:latest
```

> **多节点容器提示**：环境变量 `-e node_id=781,782,783,784` 同样支持单容器同时聚合运行数十个节点！

---

### 方式 2：`docker run` 挂载配置文件目录启动

如果你习惯使用配置文件目录统一管理 `xoga.conf`、`routes.toml`、`dns.yml` 与证书：

```bash
mkdir -p /etc/xoga
# 编辑好 /etc/xoga/xoga.conf 与 /etc/xoga/routes.toml 后启动：

docker run -d \
  --name xoga \
  --restart always \
  --net host \
  --ulimit nofile=1048576:1048576 \
  -v /etc/xoga:/etc/xoga \
  ghcr.io/xmg665/xoga:latest run -c /etc/xoga/xoga.conf
```

---

### 方式 3：使用 `docker-compose.yml` 部署（含本机 WARP 分流联动）

创建 `docker-compose.yml`：

```yaml
services:
  xoga:
    image: ghcr.io/xmg665/xoga:latest
    container_name: xoga-node
    restart: always
    network_mode: host
    ulimits:
      nofile:
        soft: 1048576
        hard: 1048576
    environment:
      - IS_DOCKER=true
      - TZ=Asia/Shanghai
      - type=xboard
      - server_type=vless
      - node_id=1,2,3
      - webapi_url=https://panel.example.com
      - webapi_key=your_token
      - proxy_protocol=true
      - mem_limit_mb=512
    volumes:
      - /etc/xoga/routes.toml:/etc/xoga/routes.toml:ro
      - /etc/xoga/dns.yml:/etc/xoga/dns.yml:ro
```

启动与日常运维命令：
```bash
docker compose up -d          # 后台启动
docker compose logs -f        # 查看实时日志
docker compose pull && docker compose up -d   # 一键拉取最新镜像并平滑升级
```

---

### 方式 4：从源码本地构建 Docker 镜像

如果服务器不方便拉取 `ghcr.io`，可直接在本地 10 秒构建镜像：

```bash
git clone https://github.com/xmg665/xoga.git
cd xoga
docker build -t xoga:latest .

# 使用本地构建的 xoga:latest 启动
docker run -d --name xoga --restart always --net host \
  -e type=sspanel-uim -e server_type=v2ray -e node_id=851 \
  -e webapi_url=https://api.example.com/ -e webapi_key=your_key \
  -v /etc/sg/aomen.toml:/etc/soga/routes.toml \
  xoga:latest
```
