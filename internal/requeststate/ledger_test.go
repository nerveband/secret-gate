package requeststate

import (
	"fmt"
	"sync"
	"testing"
)

func TestConcurrentPutPreservesEveryToken(t *testing.T) {
	dir := t.TempDir()
	var wg sync.WaitGroup
	errs := make(chan error, 100)
	for i := range 100 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ledger, err := Open(dir)
			if err == nil {
				err = ledger.Put(Entry{Token: fmt.Sprintf("tok-%03d", i), SecretName: "item", State: "pending"})
			}
			if err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	ledger, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := ledger.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 100 {
		t.Fatalf("entries = %d, want 100", len(entries))
	}
}

func TestTerminalStateIsMonotonic(t *testing.T) {
	ledger, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.Put(Entry{Token: "tok", State: "pending"}); err != nil {
		t.Fatal(err)
	}
	if err := ledger.SetState("tok", "completed"); err != nil {
		t.Fatal(err)
	}
	if err := ledger.SetState("tok", "expired"); err != nil {
		t.Fatal(err)
	}
	entry, ok, err := ledger.Get("tok")
	if err != nil || !ok {
		t.Fatalf("get: ok=%v err=%v", ok, err)
	}
	if entry.State != "completed" {
		t.Fatalf("state = %q, want completed", entry.State)
	}
}
