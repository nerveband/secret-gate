package cli

import "testing"

func TestDaemonStatusEnvelope(t *testing.T) {
	ta := newTestApp(t)
	if code := ta.app.Run([]string{"daemon", "status"}); code != ExitOK {
		t.Fatalf("exit = %d", code)
	}
	data := ta.okEnvelope(t)["data"].(map[string]interface{})
	if data["running"] != true || data["pid"].(float64) != 4242 {
		t.Fatalf("data = %v", data)
	}
}

func TestDaemonFlushIsDryRunByDefault(t *testing.T) {
	ta := newTestApp(t)
	ta.daemon.data["a"] = map[string]string{"x": "fake-value-1234"}
	if code := ta.app.Run([]string{"daemon", "flush"}); code != ExitOK {
		t.Fatalf("exit = %d", code)
	}
	if ta.daemon.flushed {
		t.Fatal("flush executed without --commit")
	}
	data := ta.okEnvelope(t)["data"].(map[string]interface{})
	if data["dry_run"] != true || data["would_flush"].(float64) != 1 {
		t.Fatalf("data = %v", data)
	}
}

func TestDaemonFlushCommit(t *testing.T) {
	ta := newTestApp(t)
	ta.daemon.data["a"] = map[string]string{"x": "fake-value-1234"}
	if code := ta.app.Run([]string{"daemon", "flush", "--commit"}); code != ExitOK {
		t.Fatalf("exit = %d", code)
	}
	if !ta.daemon.flushed {
		t.Fatal("flush not executed with --commit")
	}
}

func TestDaemonFlushNotRunningIsIdempotent(t *testing.T) {
	ta := newTestApp(t)
	ta.daemon.running = false
	if code := ta.app.Run([]string{"daemon", "flush", "--commit"}); code != ExitOK {
		t.Fatalf("exit = %d — flush on a stopped daemon must be a no-op success", code)
	}
}

func TestDaemonStopIdempotent(t *testing.T) {
	ta := newTestApp(t)
	if code := ta.app.Run([]string{"daemon", "stop"}); code != ExitOK {
		t.Fatalf("exit = %d", code)
	}
	if !ta.daemon.stopped {
		t.Fatal("stop not delegated")
	}
	ta2 := newTestApp(t)
	ta2.daemon.running = false
	if code := ta2.app.Run([]string{"daemon", "stop"}); code != ExitOK {
		t.Fatalf("second stop exit = %d, want 0 (idempotent)", code)
	}
}

func TestDaemonStart(t *testing.T) {
	ta := newTestApp(t)
	ta.daemon.running = false
	if code := ta.app.Run([]string{"daemon", "start"}); code != ExitOK {
		t.Fatalf("exit = %d", code)
	}
	if !ta.daemon.running {
		t.Fatal("start did not ensure the daemon")
	}
}
