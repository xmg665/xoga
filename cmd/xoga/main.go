package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/xmg665/xoga/internal/cli"
	"github.com/xmg665/xoga/internal/config"
	"github.com/xmg665/xoga/internal/daemon"
	"github.com/xmg665/xoga/internal/logger"
)

func main() {
	args := os.Args[1:]

	// Daemon mode is triggered by:
	// 1. `xoga run [-c /etc/xoga/xoga.conf]`
	// 2. `xoga -c /etc/xoga/xoga.conf` (soga@.service flag compatibility)
	// 3. Zero-arg container startup when `IS_DOCKER=true` or `XOGA_DAEMON=true` (vaxilu/soga Docker compatibility)
	if len(args) > 0 && (args[0] == "run" || args[0] == "-c" || strings.HasPrefix(args[0], "-c=")) {
		runArgs := args
		if args[0] == "run" {
			runArgs = args[1:]
		}
		os.Exit(runDaemon(runArgs))
	}
	if len(args) == 0 && isEnvDaemonMode() {
		os.Exit(runDaemon(nil))
	}

	// Management CLI / Interactive TUI mode (compatible with soga & soga-cmd)
	os.Exit(cli.RunCommand(args))
}

func isEnvDaemonMode() bool {
	for _, k := range []string{"IS_DOCKER", "XOGA_DAEMON"} {
		v := strings.ToLower(strings.TrimSpace(os.Getenv(k)))
		if v == "1" || v == "true" || v == "yes" {
			return true
		}
	}
	return false
}

func runDaemon(args []string) int {
	fs := flag.NewFlagSet("xoga run", flag.ContinueOnError)
	confPath := fs.String("c", config.DefaultConfigPath, "Path to configuration file")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	cfg, err := config.LoadWithEnv(*confPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config %s: %v\n", *confPath, err)
		return 1
	}
	logger.SetLevel(logger.ParseLevel(cfg.LogLevel))

	agent, err := daemon.NewAgent(cfg)
	if err != nil {
		logger.Errorf("Configuration invalid: %v", err)
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := agent.Run(ctx); err != nil {
		logger.Errorf("Agent exited with error: %v", err)
		return 1
	}
	return 0
}
