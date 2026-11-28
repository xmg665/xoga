package cli

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/xmg665/xoga/internal/config"
	"github.com/xmg665/xoga/internal/version"
)

const (
	ansiRed    = "\033[0;31m"
	ansiGreen  = "\033[0;32m"
	ansiYellow = "\033[0;33m"
	ansiCyan   = "\033[0;36m"
	ansiPlain  = "\033[0m"

	InstallRepoURL = "https://raw.githubusercontent.com/xmg665/xoga/main/install.sh"
)

var (
	validInstanceRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,48}$`)
	validVersionRe  = regexp.MustCompile(`^v?[0-9]+\.[0-9]+\.[0-9]+([0-9A-Za-z.-]*)$`)
)

type InstanceInfo struct {
	Name          string // "xoga" for default instance, otherwise template instance name
	UnitName      string // "xoga.service" or "xoga@<name>.service"
	ConfigPath    string // "/etc/xoga/<name>.conf"
	Active        bool
	Enabled       bool
	MemoryCurrent string
	PanelType     string
	ServerType    string
	NodeID        int
	NodeDisplay   string
}

func ResolveUnitAndConfig(instance string) (name, unit, confPath string) {
	instance = strings.TrimSpace(instance)
	if instance == "" || instance == "xoga" || instance == "default" {
		return "xoga", "xoga.service", config.DefaultConfigPath
	}
	return instance, fmt.Sprintf("xoga@%s.service", instance), filepath.Join(config.DefaultConfigDir, instance+".conf")
}

func DiscoverInstances() []InstanceInfo {
	entries, err := os.ReadDir(config.DefaultConfigDir)
	var names []string
	seenDefault := false
	if err == nil {
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".conf") {
				continue
			}
			base := strings.TrimSuffix(e.Name(), ".conf")
			if base == "xoga" {
				seenDefault = true
			} else {
				names = append(names, base)
			}
		}
	}
	sort.Strings(names)
	ordered := make([]string, 0, len(names)+1)
	if seenDefault || len(names) == 0 {
		ordered = append(ordered, "xoga")
	}
	ordered = append(ordered, names...)

	out := make([]InstanceInfo, 0, len(ordered))
	for _, n := range ordered {
		out = append(out, InspectInstance(n))
	}
	return out
}

func InspectInstance(instance string) InstanceInfo {
	name, unit, confPath := ResolveUnitAndConfig(instance)
	info := InstanceInfo{
		Name:       name,
		UnitName:   unit,
		ConfigPath: confPath,
	}
	if cfg, err := config.Load(confPath); err == nil {
		info.PanelType = cfg.Type
		info.ServerType = cfg.ServerType
		info.NodeID = cfg.NodeID
		info.NodeDisplay = cfg.FormatNodeIDs()
	}
	if out, err := exec.Command("systemctl", "show", unit, "-p", "ActiveState,UnitFileState,MainPID,MemoryCurrent").Output(); err == nil {
		var mainPID string
		var cgroupMem string
		for _, line := range strings.Split(string(out), "\n") {
			k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
			if !ok {
				continue
			}
			switch k {
			case "ActiveState":
				info.Active = v == "active"
			case "UnitFileState":
				info.Enabled = v == "enabled"
			case "MainPID":
				mainPID = v
			case "MemoryCurrent":
				cgroupMem = v
			}
		}
		if info.Active {
			// Prefer actual process RSS (`/proc/<pid>/status` VmRSS) so kernel TCP socket sk_buffs
			// from 10k+ connections don't artificially inflate reported xoga process memory.
			if rss := readProcRSS(mainPID); rss != "" {
				info.MemoryCurrent = rss
			} else {
				info.MemoryCurrent = formatSystemdBytes(cgroupMem)
			}
		}
	}
	return info
}

func readProcRSS(pid string) string {
	if pid == "" || pid == "0" {
		return ""
	}
	data, err := os.ReadFile("/proc/" + pid + "/status")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "VmRSS:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				var kb uint64
				if _, err := fmt.Sscanf(fields[1], "%d", &kb); err == nil && kb > 0 {
					return fmt.Sprintf("%.1f MiB", float64(kb)/1024.0)
				}
			}
		}
	}
	return ""
}

func formatSystemdBytes(s string) string {
	if s == "" || s == "[not set]" || s == "18446744073709551615" {
		return "-"
	}
	var b uint64
	if _, err := fmt.Sscanf(s, "%d", &b); err != nil || b == 0 {
		return "-"
	}
	return fmt.Sprintf("%.1f MiB", float64(b)/(1024*1024))
}

func RunCommand(args []string) int {
	if len(args) == 0 {
		RunInteractiveMenu()
		return 0
	}

	sub := args[0]
	rest := args[1:]

	switch sub {
	case "version", "-v", "--version":
		fmt.Println(version.Version)
		return 0
	case "help", "-h", "--help":
		PrintUsage()
		return 0
	case "list", "ls":
		PrintInstanceList()
		return 0
	case "status":
		inst := firstArg(rest)
		printDetailedStatus(inst)
		return 0
	case "start", "stop", "restart", "enable", "disable":
		inst := firstArg(rest)
		if err := LifecycleAction(sub, inst); err != nil {
			fmt.Fprintf(os.Stderr, "%s错误: %v%s\n", ansiRed, err, ansiPlain)
			return 1
		}
		return 0
	case "new":
		if err := CreateInstance(rest); err != nil {
			fmt.Fprintf(os.Stderr, "%s新建实例失败: %v%s\n", ansiRed, err, ansiPlain)
			return 1
		}
		return 0
	case "remove", "rm":
		if err := RemoveInstances(rest); err != nil {
			fmt.Fprintf(os.Stderr, "%s移除实例失败: %v%s\n", ansiRed, err, ansiPlain)
			return 1
		}
		return 0
	case "rename", "mv":
		if len(rest) != 2 {
			fmt.Fprintf(os.Stderr, "%s用法: xoga rename <old_name> <new_name>%s\n", ansiRed, ansiPlain)
			return 1
		}
		if err := RenameInstance(rest[0], rest[1]); err != nil {
			fmt.Fprintf(os.Stderr, "%s重命名失败: %v%s\n", ansiRed, err, ansiPlain)
			return 1
		}
		return 0
	case "log", "logs":
		return ShowLogs(rest)
	case "config":
		if err := HandleConfigCmd(rest); err != nil {
			fmt.Fprintf(os.Stderr, "%s配置操作失败: %v%s\n", ansiRed, err, ansiPlain)
			return 1
		}
		return 0
	case "update", "install", "self-update":
		ver := firstArg(rest)
		return RunOnlineUpdate(ver)
	case "uninstall":
		return RunUninstall(false)
	default:
		PrintUsage()
		return 1
	}
}

func PrintUsage() {
	fmt.Println("xoga 高性能轻量节点后端管理工具 (兼容 soga 操作):")
	fmt.Println("---------------------------------------------------------------")
	fmt.Println("xoga                              - 显示交互式管理菜单")
	fmt.Println("xoga list                         - 列出所有实例、状态与内存占用")
	fmt.Println("xoga new <name> [k1=v1 ...]       - 新建多开实例并写入配置")
	fmt.Println("xoga remove <name> [name...]      - 停止并移除指定多开实例")
	fmt.Println("xoga rename <old_name> <new_name> - 重命名实例")
	fmt.Println("xoga start [name]                 - 启动实例")
	fmt.Println("xoga stop [name]                  - 停止实例")
	fmt.Println("xoga restart [name]               - 重启实例")
	fmt.Println("xoga status [name]                - 查看实例状态与资源占用")
	fmt.Println("xoga enable [name]                - 设置实例开机自启")
	fmt.Println("xoga disable [name]               - 取消实例开机自启")
	fmt.Println("xoga log [name]                   - 查看实例最近 1000 行日志")
	fmt.Println("xoga log [name] -f                - 持续实时输出实例日志")
	fmt.Println("xoga config [name]                - 查看实例配置文件内容")
	fmt.Println("xoga config [name] k1=v1 k2=v2    - 快速修改或新增配置项")
	fmt.Println("xoga update [version]             - 在线安装/更新 xoga")
	fmt.Println("xoga uninstall                    - 完全卸载 xoga 及所有实例")
	fmt.Println("xoga version                      - 查看版本号")
	fmt.Println("xoga run -c /etc/xoga/xoga.conf   - 前台运行节点后端守护进程")
	fmt.Println("---------------------------------------------------------------")
}

func PrintInstanceList() {
	list := DiscoverInstances()
	fmt.Printf("%-14s %-12s %-10s %-12s %-12s %-8s %-10s %s\n",
		"实例名", "运行状态", "开机自启", "面板类型", "协议", "节点ID", "当前内存", "配置文件")
	fmt.Println(strings.Repeat("-", 96))
	for _, item := range list {
		st := ansiYellow + "未运行" + ansiPlain
		if item.Active {
			st = ansiGreen + "运行中" + ansiPlain
		}
		en := "否"
		if item.Enabled {
			en = "是"
		}
		mem := item.MemoryCurrent
		if mem == "" {
			mem = "-"
		}
		nd := item.NodeDisplay
		if nd == "" {
			nd = fmt.Sprintf("%d", item.NodeID)
		}
		fmt.Printf("%-14s %-21s %-10s %-12s %-12s %-14s %-10s %s\n",
			item.Name, st, en, emptyDash(item.PanelType), emptyDash(item.ServerType), nd, mem, item.ConfigPath)
	}
}

func printDetailedStatus(instance string) {
	info := InspectInstance(instance)
	st := ansiYellow + "未运行" + ansiPlain
	if info.Active {
		st = ansiGreen + "已运行" + ansiPlain
	}
	en := ansiRed + "否" + ansiPlain
	if info.Enabled {
		en = ansiGreen + "是" + ansiPlain
	}
	fmt.Printf("实例名称:   %s%s%s (%s)\n", ansiCyan, info.Name, ansiPlain, info.UnitName)
	fmt.Printf("运行状态:   %s\n", st)
	fmt.Printf("开机自启:   %s\n", en)
	if info.MemoryCurrent != "" && info.MemoryCurrent != "-" {
		fmt.Printf("实时内存:   %s%s%s\n", ansiGreen, info.MemoryCurrent, ansiPlain)
	}
	nd := info.NodeDisplay
	if nd == "" {
		nd = fmt.Sprintf("%d", info.NodeID)
	}
	fmt.Printf("节点信息:   type=%s server_type=%s node_id=%s\n",
		emptyDash(info.PanelType), emptyDash(info.ServerType), nd)
	fmt.Printf("配置文件:   %s\n", info.ConfigPath)
}

func ValidateInstanceName(instance string) error {
	instance = strings.TrimSpace(instance)
	if instance == "" || instance == "xoga" || instance == "default" {
		return nil
	}
	if !validInstanceRe.MatchString(instance) {
		return fmt.Errorf("无效实例名 %q (仅支持字母/数字/下划线/短横线)", instance)
	}
	return nil
}

func LifecycleAction(action, instance string) error {
	if err := ValidateInstanceName(instance); err != nil {
		return err
	}
	name, unit, confPath := ResolveUnitAndConfig(instance)
	if (action == "start" || action == "restart") && !fileExists(confPath) {
		return fmt.Errorf("配置文件 %s 不存在", confPath)
	}
	if action == "start" || action == "restart" {
		_ = exec.Command("systemctl", "reset-failed", unit).Run()
	}
	cmd := exec.Command("systemctl", action, unit)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return err
	}
	switch action {
	case "start":
		fmt.Printf("%sxoga [%s] 启动成功，可使用 `xoga log %s` 查看日志%s\n", ansiGreen, name, optArg(name), ansiPlain)
	case "stop":
		fmt.Printf("%sxoga [%s] 已停止%s\n", ansiGreen, name, ansiPlain)
	case "restart":
		fmt.Printf("%sxoga [%s] 重启成功%s\n", ansiGreen, name, ansiPlain)
	case "enable":
		fmt.Printf("%sxoga [%s] 已设置开机自启%s\n", ansiGreen, name, ansiPlain)
	case "disable":
		fmt.Printf("%sxoga [%s] 已取消开机自启%s\n", ansiGreen, name, ansiPlain)
	}
	return nil
}

func CreateInstance(args []string) error {
	if len(args) == 0 {
		return errors.New("用法: xoga new <name> [k1=v1 k2=v2 ...]")
	}
	instName := strings.TrimSpace(args[0])
	if !validInstanceRe.MatchString(instName) || instName == "xoga" {
		return fmt.Errorf("无效实例名 %q (仅支持字母/数字/下划线/短横线，且不能为 xoga)", instName)
	}
	_, unit, confPath := ResolveUnitAndConfig(instName)
	if fileExists(confPath) {
		return fmt.Errorf("实例 %q 已存在 (%s)", instName, confPath)
	}

	applied, err := config.UpdateFile(confPath, args[1:])
	if err != nil {
		return err
	}
	fmt.Printf("%s已创建实例配置: %s%s\n", ansiGreen, confPath, ansiPlain)
	for _, kv := range applied {
		fmt.Printf("  + %s\n", kv)
	}

	_ = exec.Command("systemctl", "daemon-reload").Run()
	if err := exec.Command("systemctl", "enable", unit).Run(); err != nil {
		return fmt.Errorf("设置开机自启失败 (%s): %w", unit, err)
	}
	if len(args[1:]) > 0 {
		if err := exec.Command("systemctl", "restart", unit).Run(); err != nil {
			return fmt.Errorf("启动实例 [%s] 失败 (%s): %w", instName, unit, err)
		}
		fmt.Printf("%s实例 [%s] 已启动并设置开机自启%s\n", ansiGreen, instName, ansiPlain)
	} else {
		fmt.Printf("%s请编辑 %s 或运行 `xoga config %s k=v` 后执行 `xoga start %s`%s\n",
			ansiYellow, confPath, instName, instName, ansiPlain)
	}
	return nil
}

func RemoveInstances(names []string) error {
	if len(names) == 0 {
		return errors.New("用法: xoga remove <name> [name...]")
	}
	for _, n := range names {
		if n == "xoga" || n == "default" {
			return errors.New("默认实例不可通过 remove 删除，若需完全卸载请使用 `xoga uninstall`")
		}
		if !validInstanceRe.MatchString(strings.TrimSpace(n)) {
			return fmt.Errorf("无效实例名 %q", n)
		}
		_, unit, confPath := ResolveUnitAndConfig(n)
		_ = exec.Command("systemctl", "stop", unit).Run()
		_ = exec.Command("systemctl", "disable", unit).Run()
		if err := os.Remove(confPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		fmt.Printf("%s已移除实例 [%s]%s\n", ansiGreen, n, ansiPlain)
	}
	return nil
}

func RenameInstance(oldName, newName string) error {
	oldName = strings.TrimSpace(oldName)
	newName = strings.TrimSpace(newName)
	if oldName == "xoga" || oldName == "default" || newName == "xoga" || newName == "default" ||
		!validInstanceRe.MatchString(oldName) || !validInstanceRe.MatchString(newName) {
		return errors.New("不支持重命名默认实例 xoga，或实例名称不合法")
	}
	_, oldUnit, oldConf := ResolveUnitAndConfig(oldName)
	_, newUnit, newConf := ResolveUnitAndConfig(newName)
	if !fileExists(oldConf) {
		return fmt.Errorf("实例 [%s] 不存在", oldName)
	}
	if fileExists(newConf) {
		return fmt.Errorf("目标实例 [%s] 已存在", newName)
	}

	wasActive := InspectInstance(oldName).Active
	_ = exec.Command("systemctl", "stop", oldUnit).Run()
	_ = exec.Command("systemctl", "disable", oldUnit).Run()

	if err := os.Rename(oldConf, newConf); err != nil {
		return err
	}
	_ = exec.Command("systemctl", "enable", newUnit).Run()
	if wasActive {
		_ = exec.Command("systemctl", "start", newUnit).Run()
	}
	fmt.Printf("%s实例 [%s] 已重命名为 [%s]%s\n", ansiGreen, oldName, newName, ansiPlain)
	return nil
}

func HandleConfigCmd(args []string) error {
	instance := "xoga"
	var pairs []string
	for i, a := range args {
		if strings.Contains(a, "=") {
			pairs = append(pairs, a)
		} else if i == 0 {
			instance = a
		}
	}
	if err := ValidateInstanceName(instance); err != nil {
		return err
	}
	name, _, confPath := ResolveUnitAndConfig(instance)
	if len(pairs) == 0 {
		data, err := os.ReadFile(confPath)
		if err != nil {
			return err
		}
		fmt.Printf("%s# === %s (%s) ===%s\n%s", ansiCyan, name, confPath, ansiPlain, string(data))
		return nil
	}
	if name != "xoga" && !fileExists(confPath) {
		return fmt.Errorf("实例 %q 不存在 (%s)，如需新建请使用 `xoga new %s ...`", name, confPath, name)
	}

	applied, err := config.UpdateFile(confPath, pairs)
	if err != nil {
		return err
	}
	for _, kv := range applied {
		fmt.Printf("%s已写入配置 [%s]: %s%s\n", ansiGreen, name, kv, ansiPlain)
	}
	fmt.Printf("%s提示: 执行 `xoga restart %s` 使新配置立即生效%s\n", ansiYellow, optArg(name), ansiPlain)
	return nil
}

func parseShowLogsArgs(args []string, instanceExists func(string) bool) (instance, lines string, follow bool, err error) {
	instance = "xoga"
	lines = "1000"
	hasInstance := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-f" || a == "--follow":
			follow = true
		case a == "-n" || a == "--lines":
			if i+1 < len(args) && isDigits(args[i+1]) {
				lines = args[i+1]
				i++
			}
		case strings.HasPrefix(a, "--lines="):
			if val := strings.TrimPrefix(a, "--lines="); isDigits(val) {
				lines = val
			}
		case strings.HasPrefix(a, "-n") && len(a) > 2 && isDigits(a[2:]):
			lines = a[2:]
		case !strings.HasPrefix(a, "-"):
			if isDigits(a) {
				// Numeric instance names (e.g. "101") take precedence when their config file exists
				// and no instance name was already provided.
				if !hasInstance && instanceExists != nil && instanceExists(a) {
					instance = a
					hasInstance = true
				} else {
					lines = a
				}
			} else {
				instance = a
				hasInstance = true
			}
		}
	}
	if err = ValidateInstanceName(instance); err != nil {
		return "", "", false, err
	}
	return instance, lines, follow, nil
}

func ShowLogs(args []string) int {
	instance, lines, follow, err := parseShowLogsArgs(args, func(name string) bool {
		if ValidateInstanceName(name) != nil {
			return false
		}
		_, _, confPath := ResolveUnitAndConfig(name)
		return fileExists(confPath)
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s%v%s\n", ansiRed, err, ansiPlain)
		return 1
	}
	_, unit, _ := ResolveUnitAndConfig(instance)
	jArgs := []string{"-u", unit, "-e", "--no-pager", "-n", lines}
	if follow {
		jArgs = append(jArgs, "-f")
	}
	cmd := exec.Command("journalctl", jArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return 1
	}
	return 0
}

func RunOnlineUpdate(targetVer string) int {
	targetVer = strings.TrimSpace(targetVer)
	if targetVer != "" && !validVersionRe.MatchString(targetVer) {
		fmt.Fprintf(os.Stderr, "%s无效版本号 %q (示例: v1.3.2 或 1.3.2)%s\n", ansiRed, targetVer, ansiPlain)
		return 1
	}
	// Download installer safely to mktemp with curl -fsSL (failing on HTTP/DNS errors instead of running empty/HTML body)
	// and pass targetVer as positional `$1` (never interpolated into bash source!).
	const safeRunner = `set -eo pipefail; tmp="$(mktemp /tmp/xoga-install.XXXXXX.sh)"; trap 'rm -f "$tmp"' EXIT; curl -fsSL --retry 3 "$1" -o "$tmp"; shift; bash "$tmp" "$@"`
	cmdArgs := []string{"-c", safeRunner, "xoga-update", InstallRepoURL}
	if targetVer != "" {
		cmdArgs = append(cmdArgs, targetVer)
	}
	cmd := exec.Command("bash", cmdArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "%s更新失败: %v%s\n", ansiRed, err, ansiPlain)
		return 1
	}
	return 0
}

func RunUninstall(skipConfirm bool) int {
	if !skipConfirm {
		fmt.Print("确定要完全卸载 xoga 及所有实例配置吗? [y/N]: ")
		sc := bufio.NewScanner(os.Stdin)
		if !sc.Scan() {
			return 0
		}
		ans := strings.ToLower(strings.TrimSpace(sc.Text()))
		if ans != "y" && ans != "yes" {
			fmt.Println("已取消卸载")
			return 0
		}
	}

	for _, inst := range DiscoverInstances() {
		_ = exec.Command("systemctl", "stop", inst.UnitName).Run()
		_ = exec.Command("systemctl", "disable", inst.UnitName).Run()
	}
	_ = os.Remove("/etc/systemd/system/xoga.service")
	_ = os.Remove("/etc/systemd/system/xoga@.service")
	_ = exec.Command("systemctl", "daemon-reload").Run()
	_ = exec.Command("systemctl", "reset-failed").Run()
	_ = os.RemoveAll(config.DefaultConfigDir)
	_ = os.RemoveAll(config.DefaultBinDir)

	fmt.Printf("\n%sxoga 已卸载完成。如需移除管理命令可执行: rm -f /usr/bin/xoga%s\n", ansiGreen, ansiPlain)
	return 0
}

func firstArg(s []string) string {
	if len(s) > 0 {
		return s[0]
	}
	return ""
}

func optArg(name string) string {
	if name == "xoga" {
		return ""
	}
	return name
}

func emptyDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
