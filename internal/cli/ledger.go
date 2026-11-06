package cli

import "github.com/nerveband/secret-gate/internal/requeststate"

type LedgerEntry = requeststate.Entry
type Ledger = requeststate.Ledger

func OpenLedger(dir string) (*Ledger, error) { return requeststate.Open(dir) }
