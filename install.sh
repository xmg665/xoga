#!/bin/bash

red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'

REPO="xmg665/xoga"

# check root
[[ $EUID -ne 0 ]] && echo -e "${red}错误：${plain} 必须使用 root 用户运行此脚本！\n" && exit 1

# check os
if [[ -f /etc/redhat-release ]]; then
    release="centos"
elif grep -Eqi "debian" /etc/issue 2>/dev/null || grep -Eqi "debian" /proc/version 2>/dev/null; then
    release="debian"
elif grep -Eqi "ubuntu" /etc/issue 2>/dev/null || grep -Eqi "ubuntu" /proc/version 2>/dev/null; then
    release="ubuntu"
elif grep -Eqi "centos|red hat|redhat|rocky|alma" /etc/issue 2>/dev/null || grep -Eqi "centos|red hat|redhat" /proc/version 2>/dev/null; then
    release="centos"
else
    release="debian"
fi

arch=$(uname -m)
if [[ $arch == "x86_64" || $arch == "x64" || $arch == "amd64" ]]; then
    arch="amd64"
elif [[ $arch == "aarch64" || $arch == "arm64" ]]; then
    arch="arm64"
else
    arch="amd64"
    echo -e "${yellow}未识别架构 $(uname -m)，默认使用: ${arch}${plain}"
fi

echo "系统架构: ${arch}"

if ! command -v systemctl >/dev/null 2>&1; then
    echo -e "${red}未检测到 systemctl，请使用带有 systemd 的现代 Linux 发行版 (Ubuntu 18+ / Debian 10+ / Rocky / Alma / CentOS 7+)${plain}"
    exit 1
fi

install_base() {
    if ! command -v curl >/dev/null 2>&1 || ! command -v tar >/dev/null 2>&1; then
        if [[ "${release}" == "centos" ]]; then
            yum install -y wget curl tar ca-certificates tzdata >/dev/null 2>&1
        else
            apt-get update -y >/dev/null 2>&1
            apt-get install -y wget curl tar ca-certificates tzdata >/dev/null 2>&1
        fi
    fi
}

check_status() {
    if [[ ! -f /etc/systemd/system/xoga.service ]]; then
        return 2
    fi
    if systemctl is-active --quiet xoga; then
        return 0
    fi
    return 1
}

install_xoga() {
    local target_ver="$1"
    local url=""

    if [[ -z "${target_ver}" ]]; then
        echo -e "${green}开始下载并安装 xoga 最新版...${plain}"
        url="https://github.com/${REPO}/releases/latest/download/xoga-linux-${arch}.tar.gz"
    else
        target_ver="${target_ver#v}"
        echo -e "${green}开始下载并安装 xoga v${target_ver}...${plain}"
        url="https://github.com/${REPO}/releases/download/v${target_ver}/xoga-linux-${arch}.tar.gz"
    fi

    curl -fL --retry 3 -o /tmp/xoga.tar.gz "${url}"
    if [[ $? -ne 0 ]]; then
        echo -e "${red}下载失败: ${url}${plain}"
        echo -e "${yellow}请检查服务器是否可访问 GitHub Releases 或指定版本号是否存在${plain}"
        exit 1
    fi

    systemctl stop xoga >/dev/null 2>&1 || true

    rm -rf /usr/local/xoga
    mkdir -p /usr/local/xoga /etc/xoga
    tar -xzf /tmp/xoga.tar.gz -C /usr/local/xoga
    rm -f /tmp/xoga.tar.gz

    # Support archives packed either flat or with top-level xoga/ directory
    if [[ -d /usr/local/xoga/xoga && -f /usr/local/xoga/xoga/xoga ]]; then
        mv /usr/local/xoga/xoga/* /usr/local/xoga/
        rmdir /usr/local/xoga/xoga 2>/dev/null || true
    fi

    chmod +x /usr/local/xoga/xoga
    ln -sf /usr/local/xoga/xoga /usr/bin/xoga

    cp -f /usr/local/xoga/xoga.service /etc/systemd/system/xoga.service
    cp -f /usr/local/xoga/xoga@.service /etc/systemd/system/xoga@.service
    systemctl daemon-reload
    systemctl enable xoga >/dev/null 2>&1

    for f in blockList whiteList dns.yml routes.toml; do
        if [[ ! -f "/etc/xoga/${f}" && -f "/usr/local/xoga/${f}" ]]; then
            cp "/usr/local/xoga/${f}" "/etc/xoga/${f}"
        fi
    done

    local installed_ver
    installed_ver="$(/usr/local/xoga/xoga version 2>/dev/null || echo "latest")"
    echo -e "${green}xoga v${installed_ver}${plain} 安装完成，已设置开机自启！"

    if [[ ! -f /etc/xoga/xoga.conf ]]; then
        cp /usr/local/xoga/xoga.conf /etc/xoga/xoga.conf
        echo -e "${yellow}首次全新安装，已生成默认配置 /etc/xoga/xoga.conf${plain}"
    else
        systemctl restart xoga
        sleep 1
        if check_status; then
            echo -e "${green}xoga 服务已自动重启成功${plain}"
        else
            echo -e "${yellow}xoga 暂未就绪，请检查配置或运行 xoga log 查看详情${plain}"
        fi
    fi

    echo ""
    echo "xoga 管理命令使用方法 (单二进制集成 CLI & 守护进程):"
    echo "---------------------------------------------------------------"
    echo "xoga                              - 显示交互式管理菜单"
    echo "xoga list                         - 列出所有实例、状态与内存占用"
    echo "xoga new <name> [k1=v1 ...]       - 新建多开实例"
    echo "xoga remove <name> [name...]      - 移除多开实例"
    echo "xoga rename <old_name> <new_name> - 重命名实例"
    echo "xoga start [name]                 - 启动实例"
    echo "xoga stop [name]                  - 停止实例"
    echo "xoga restart [name]               - 重启实例"
    echo "xoga status [name]                - 查看实例状态与实时内存"
    echo "xoga enable [name]                - 设置实例开机自启"
    echo "xoga disable [name]               - 取消实例开机自启"
    echo "xoga log [name]                   - 查看实例日志(默认 1000 行)"
    echo "xoga log [name] -f                - 持续输出实例实时日志"
    echo "xoga config [name]                - 查看实例配置文件"
    echo "xoga config [name] k1=v1 k2=v2    - 修改或新增配置项"
    echo "xoga update [version]             - 在线更新 xoga"
    echo "xoga uninstall                    - 完全卸载 xoga"
    echo "xoga version                      - 查看版本"
    echo "---------------------------------------------------------------"
}

version_arg=""
configs=()
for arg in "$@"; do
    if [[ "${arg}" == *"="* ]]; then
        configs+=("${arg}")
    elif [[ -z "${version_arg}" ]]; then
        version_arg="${arg}"
    fi
done

install_base
install_xoga "${version_arg}"

if [[ ${#configs[@]} -gt 0 ]]; then
    echo -e "${green}正在写入命令行配置参数...${plain}"
    /usr/bin/xoga config "${configs[@]}"
    systemctl restart xoga
    sleep 1
    if check_status; then
        echo -e "${green}xoga 启动成功！${plain}"
    else
        echo -e "${red}xoga 启动异常，请执行 xoga log 查看详细日志${plain}"
    fi
fi
