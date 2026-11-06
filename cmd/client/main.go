// Command secret-gate is one binary with three faces: the agent-native
// noun-verb CLI (internal/cli), the MCP stdio adapter (internal/mcpserver),
// and the cache daemon (internal/daemon). All three share internal/core.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/nerveband/secret-gate/internal/cli"
	"github.com/nerveband/secret-gate/internal/clientconfig"
	"github.com/nerveband/secret-gate/internal/core"
	"github.com/nerveband/secret-gate/internal/daemon"
	"github.com/nerveband/secret-gate/internal/mcpserver"
	"github.com/nerveband/secret-gate/internal/version"
)

func main() {
	args := os.Args[1:]

	// "daemon run" is the re-exec entry point used by daemon.EnsureDaemon.
	// It must bypass the CLI envelope entirely.
	if len(args) >= 2 && args[0] == "daemon" && args[1] == "run" {
		runDaemonProcess(args[2:])
		return
	}
	if len(args) >= 1 && args[0] == "mcp" {
		runMCP()
		return
	}
	// Pre-0.4.0 flag-style invocation printed secret values to stdout.
	// It is refused outright with a structured migration hint.
	if isLegacyInvocation(args) {
		_ = cli.WriteError(os.Stderr, "cli", "usage",
			"flag-style invocation was removed in 0.4.0 because it printed secret values to stdout",
			"use: secret-gate item search --query <q> · secret-gate item read --item <name> --reveal · secret-gate exec --item <name> --field <f> --env VAR -- <cmd>")
		os.Exit(cli.ExitUsage)
	}

	os.Exit(newApp().Run(args))
}

// isLegacyInvocation reports whether argv starts with a flag instead of
// a subcommand (the pre-0.4.0 calling convention), excluding the global
// flags the new CLI accepts in front position.
func isLegacyInvocation(args []string) bool {
	if len(args) == 0 || !strings.HasPrefix(args[0], "-") {
		return false
	}
	switch args[0] {
	case "--help", "-h", "--json", "--quiet", "-q":
		return false
	}
	return true
}

func newApp() *cli.App {
	cfg := clientconfig.Load()
	cacheTTLSec := int(cfg.CacheTTL.Seconds())
	if cacheTTLSec <= 0 {
		cacheTTLSec = 3600
	}
	stateDir := requestStateDir()
	dc := core.NewRealDaemonClientWithConfig(cacheTTLSec)
	pc := core.NewHTTPProxyClient(cfg.ServerURL, dc, cacheTTLSec, stateDir)
	svc := core.NewService(core.Config{
		ServerURL:   cfg.ServerURL,
		CacheTTLSec: cacheTTLSec,
		SSHAgent:    cfg.SSHAgentIntegration,
	}, dc, pc)
	async, _ := pc.(core.AsyncProxyClient)

	return &cli.App{
		Version:   version.Version,
		ServerURL: cfg.ServerURL,
		Service:   svc,
		Async:     async,
		Admin:     dc,
		StateDir:  stateDir,
		Stdout:    os.Stdout,
		Stderr:    os.Stderr,
		Stdin:     os.Stdin,
	}
}

func runDaemonProcess(args []string) {
	runFlags := flag.NewFlagSet("daemon run", flag.ExitOnError)
	socket := runFlags.String("socket", daemon.SocketPath(), "Unix socket path")
	cacheTTL := runFlags.Int("cache-ttl", 3600, "Cache TTL in seconds")
	idleTimeout := runFlags.Int("idle-timeout", 300, "Idle timeout in seconds")
	_ = runFlags.Parse(args)

	if err := daemon.RunDaemon(*socket, *cacheTTL, *idleTimeout); err != nil {
		fmt.Fprintf(os.Stderr, "Daemon error: %v\n", err)
		os.Exit(1)
	}
}

func runMCP() {
	cfg := clientconfig.Load()
	if cfg.ServerURL == "" {
		fmt.Fprintln(os.Stderr, "Error: server URL is required for MCP mode")
		fmt.Fprintln(os.Stderr, "Set SECRET_GATE_URL env var or configure server_url in ~/.config/secret-gate/config.json")
		os.Exit(1)
	}
	cacheTTLSec := int(cfg.CacheTTL.Seconds())
	if cacheTTLSec <= 0 {
		cacheTTLSec = 3600
	}
	stateDir := requestStateDir()
	dc := mcpserver.NewRealDaemonClientWithConfig(cacheTTLSec)
	_ = dc.EnsureRunning()
	pc := core.NewHTTPProxyClient(cfg.ServerURL, dc, cacheTTLSec, stateDir)
	mcpCfg := mcpserver.Config{
		ServerURL:   cfg.ServerURL,
		CacheTTLSec: cacheTTLSec,
		SSHAgent:    cfg.SSHAgentIntegration,
	}
	server := mcpserver.New(mcpCfg, dc, pc)

	fmt.Fprintln(os.Stderr, "secret-gate MCP server starting (stdio transport)...")
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		fmt.Fprintf(os.Stderr, "MCP server error: %v\n", err)
		os.Exit(1)
	}
}

func requestStateDir() string {
	if dir := os.Getenv("SECRET_GATE_STATE_DIR"); dir != "" {
		return dir
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "state", "secret-gate")
}
