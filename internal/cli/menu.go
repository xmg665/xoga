package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/xmg665/xoga/internal/version"
)

// RunInteractiveMenu provides an interactive terminal management menu matching soga / soga-cmd.
func RunInteractiveMenu() {
	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Printf("\n  %sxoga 高性能低内存节点后端管理面板%s (%s)\n", ansiGreen, ansiPlain, version.Summary())
		fmt.Println("  ──────────────────────────────────────────────")
		fmt.Printf("  %s0.%s  退出管理菜单\n", ansiGreen, ansiPlain)
		fmt.Println("  ──────────────────────────────────────────────")
		fmt.Printf("  %s1.%s  在线安装 / 更新 xoga\n", ansiGreen, ansiPlain)
		fmt.Printf("  %s2.%s  卸载 xoga\n", ansiGreen, ansiPlain)
		fmt.Println("  ──────────────────────────────────────────────")
		fmt.Printf("  %s3.%s  查看所有实例状态与实时内存占用 (list)\n", ansiGreen, ansiPlain)
		fmt.Printf("  %s4.%s  新建多开实例 (new)\n", ansiGreen, ansiPlain)
		fmt.Printf("  %s5.%s  快捷修改实例配置 (config)\n", ansiGreen, ansiPlain)
		fmt.Println("  ──────────────────────────────────────────────")
		fmt.Printf("  %s6.%s  启动实例 (start)\n", ansiGreen, ansiPlain)
		fmt.Printf("  %s7.%s  停止实例 (stop)\n", ansiGreen, ansiPlain)
		fmt.Printf("  %s8.%s  重启实例 (restart)\n", ansiGreen, ansiPlain)
		fmt.Printf("  %s9.%s  查看实例日志 (log)\n", ansiGreen, ansiPlain)
		fmt.Println("  ──────────────────────────────────────────────")
		fmt.Printf("  %s10.%s 设置开机自启 (enable)\n", ansiGreen, ansiPlain)
		fmt.Printf("  %s11.%s 取消开机自启 (disable)\n", ansiGreen, ansiPlain)
		fmt.Printf("  %s12.%s 查看版本信息 (version)\n\n", ansiGreen, ansiPlain)

		printDetailedStatus("xoga")

		fmt.Print("\n请输入操作编号 [0-12]: ")
		choice, ok := readTrimmed(reader)
		if !ok {
			return
		}

		switch choice {
		case "0", "q", "quit", "exit":
			return
		case "1":
			fmt.Print("输入指定版本号 (直接回车安装最新版): ")
			ver, ok := readTrimmed(reader)
			if !ok {
				return
			}
			RunOnlineUpdate(ver)
		case "2":
			if RunUninstall(false) == 0 {
				return
			}
		case "3":
			fmt.Println()
			PrintInstanceList()
		case "4":
			fmt.Print("请输入新实例名称 (例如 hk2): ")
			name, ok := readTrimmed(reader)
			if !ok {
				return
			}
			fmt.Print("请输入初始配置键值 (空格分隔，如 type=v2board server_type=vless node_id=2): ")
			kvLine, ok := readTrimmed(reader)
			if !ok {
				return
			}
			kvs := strings.Fields(kvLine)
			args := append([]string{name}, kvs...)
			if err := CreateInstance(args); err != nil {
				fmt.Printf("%s%v%s\n", ansiRed, err, ansiPlain)
			}
		case "5":
			inst, ok := promptInstance(reader)
			if !ok {
				return
			}
			fmt.Print("输入 k1=v1 k2=v2 修改配置 (直接回车查看当前配置): ")
			kvLine, ok := readTrimmed(reader)
			if !ok {
				return
			}
			kvs := strings.Fields(kvLine)
			args := append([]string{inst}, kvs...)
			if err := HandleConfigCmd(args); err != nil {
				fmt.Printf("%s%v%s\n", ansiRed, err, ansiPlain)
			}
		case "6":
			inst, ok := promptInstance(reader)
			if !ok {
				return
			}
			if err := LifecycleAction("start", inst); err != nil {
				fmt.Printf("%s%v%s\n", ansiRed, err, ansiPlain)
			}
		case "7":
			inst, ok := promptInstance(reader)
			if !ok {
				return
			}
			if err := LifecycleAction("stop", inst); err != nil {
				fmt.Printf("%s%v%s\n", ansiRed, err, ansiPlain)
			}
		case "8":
			inst, ok := promptInstance(reader)
			if !ok {
				return
			}
			if err := LifecycleAction("restart", inst); err != nil {
				fmt.Printf("%s%v%s\n", ansiRed, err, ansiPlain)
			}
		case "9":
			inst, ok := promptInstance(reader)
			if !ok {
				return
			}
			_ = ShowLogs([]string{inst})
		case "10":
			inst, ok := promptInstance(reader)
			if !ok {
				return
			}
			_ = LifecycleAction("enable", inst)
		case "11":
			inst, ok := promptInstance(reader)
			if !ok {
				return
			}
			_ = LifecycleAction("disable", inst)
		case "12":
			fmt.Println(version.Summary())
		default:
			fmt.Printf("%s请输入有效数字 [0-12]%s\n", ansiRed, ansiPlain)
		}

		fmt.Printf("\n%s按回车键返回主菜单...%s", ansiYellow, ansiPlain)
		if _, err := reader.ReadString('\n'); err != nil {
			return
		}
	}
}

func promptInstance(r *bufio.Reader) (string, bool) {
	fmt.Print("实例名称 [默认 xoga]: ")
	s, ok := readTrimmed(r)
	if !ok {
		return "", false
	}
	if s == "" {
		return "xoga", true
	}
	return s, true
}

func readTrimmed(r *bufio.Reader) (string, bool) {
	s, err := r.ReadString('\n')
	if err != nil && len(s) == 0 {
		return "", false
	}
	return strings.TrimSpace(s), true
}
