package cli

import "fmt"

func init() {
	usageText["daemon status"] = `Usage: secret-gate daemon status

Show cache daemon status (PID, uptime, cached entry count, socket path).`
	usageText["daemon start"] = `Usage: secret-gate daemon start

Ensure the cache daemon is running, starting it if needed.`
	usageText["daemon flush"] = `Usage: secret-gate daemon flush [--commit]

Flush all cached secrets. Without --commit this is a dry run that
reports what would be flushed.

Examples:
  secret-gate daemon flush            # preview
  secret-gate daemon flush --commit   # actually flush`
	usageText["daemon stop"] = `Usage: secret-gate daemon stop

Stop the cache daemon. Succeeds (no-op) when it is not running.`
}

func (a *App) runDaemon(args []string) int {
	if len(args) == 0 {
		return a.fail("daemon", "usage", "daemon requires a subcommand: status, start, flush, stop",
			"run: secret-gate daemon status --help")
	}
	switch args[0] {
	case "status":
		return a.daemonStatus(args[1:])
	case "start":
		return a.daemonStart(args[1:])
	case "flush":
		return a.daemonFlush(args[1:])
	case "stop":
		return a.daemonStop(args[1:])
	default:
		return a.fail("daemon", "usage", fmt.Sprintf("unknown daemon subcommand %q", args[0]),
			"valid subcommands: status, start, flush, stop (daemon run is internal)")
	}
}

func (a *App) daemonStatus(args []string) int {
	const command = "daemon status"
	fs := a.newFlagSet(command)
	if code, done := a.parse(fs, command, args); done {
		return code
	}
	status, err := a.Service.DaemonStatus()
	if err != nil {
		return a.failErr(command, err)
	}
	return a.ok(command, status, &Meta{Visibility: VisibilityMetadataOnly})
}

func (a *App) daemonStart(args []string) int {
	const command = "daemon start"
	fs := a.newFlagSet(command)
	if code, done := a.parse(fs, command, args); done {
		return code
	}
	if err := a.Admin.EnsureRunning(); err != nil {
		return a.fail(command, "internal", "failed to start daemon: "+err.Error(), "")
	}
	status, err := a.Service.DaemonStatus()
	if err != nil {
		return a.failErr(command, err)
	}
	return a.ok(command, status, &Meta{Visibility: VisibilityMetadataOnly})
}

func (a *App) daemonFlush(args []string) int {
	const command = "daemon flush"
	fs := a.newFlagSet(command)
	commit := fs.Bool("commit", false, "actually flush (default is a dry-run preview)")
	if code, done := a.parse(fs, command, args); done {
		return code
	}
	if !a.Admin.IsRunning() {
		return a.ok(command, map[string]interface{}{
			"running": false, "flushed": 0,
			"message": "daemon is not running; nothing to flush",
		}, &Meta{Visibility: VisibilityMetadataOnly})
	}
	entries, err := a.Admin.List()
	if err != nil {
		return a.fail(command, "internal", "failed to list cache entries: "+err.Error(), "")
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.SecretName)
	}
	if !*commit {
		return a.ok(command, map[string]interface{}{
			"dry_run":     true,
			"would_flush": len(entries),
			"entries":     names,
		}, &Meta{Visibility: VisibilityMetadataOnly})
	}
	if err := a.Admin.Flush(); err != nil {
		return a.fail(command, "internal", "flush failed: "+err.Error(), "")
	}
	return a.ok(command, map[string]interface{}{
		"flushed": len(entries),
		"entries": names,
	}, &Meta{Visibility: VisibilityMetadataOnly})
}

func (a *App) daemonStop(args []string) int {
	const command = "daemon stop"
	fs := a.newFlagSet(command)
	if code, done := a.parse(fs, command, args); done {
		return code
	}
	if !a.Admin.IsRunning() {
		return a.ok(command, map[string]interface{}{
			"running": false, "message": "daemon is not running",
		}, &Meta{Visibility: VisibilityMetadataOnly})
	}
	if err := a.Admin.StopDaemon(); err != nil {
		return a.fail(command, "internal", "failed to stop daemon: "+err.Error(), "")
	}
	return a.ok(command, map[string]interface{}{"stopped": true}, &Meta{Visibility: VisibilityMetadataOnly})
}
