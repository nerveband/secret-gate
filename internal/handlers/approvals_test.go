package handlers

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/johnuopini/secret-gate/internal/models"
)

func TestApproverAPIRequiresBearerToken(t *testing.T) {
	wh := newWriteHarness(t, "SecretA")
	wh.h.config.ApproverToken = "sg_approver_secret"

	req := httptest.NewRequest(http.MethodGet, "/approvals", nil)
	rec := httptest.NewRecorder()
	wh.h.HandleApprovals(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d, want 401", rec.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/approvals", nil)
	req.Header.Set("Authorization", "Bearer wrong")
	rec = httptest.NewRecorder()
	wh.h.HandleApprovals(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token status = %d, want 401", rec.Code)
	}
}

func TestApproverAPIStreamListDecideAndRevokeWindow(t *testing.T) {
	wh := newWriteHarness(t)
	pw := &fakePushWard{}
	wh.h.SetPushWardClient(pw)
	wh.h.config.ApproverToken = "sg_approver_secret"

	mux := http.NewServeMux()
	mux.HandleFunc("/request", wh.h.HandleRequest)
	mux.HandleFunc("/approvals", wh.h.HandleApprovals)
	mux.HandleFunc("/approvals/", wh.h.HandleApprovals)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	streamReq, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/approvals/events", nil)
	if err != nil {
		t.Fatal(err)
	}
	streamReq.Header.Set("Authorization", "Bearer sg_approver_secret")
	streamResp, err := http.DefaultClient.Do(streamReq)
	if err != nil {
		t.Fatal(err)
	}
	defer streamResp.Body.Close()

	events := make(chan ApprovalEvent, 16)
	go func() {
		scanner := bufio.NewScanner(streamResp.Body)
		for scanner.Scan() {
			line := scanner.Text()
			if rest, ok := strings.CutPrefix(line, "data: "); ok {
				var ev ApprovalEvent
				if err := json.Unmarshal([]byte(rest), &ev); err == nil {
					events <- ev
				}
			}
		}
	}()

	// 1. Initial snapshot event.
	select {
	case ev := <-events:
		if ev.Type != "snapshot" || len(ev.Pending) != 0 {
			t.Fatalf("initial event = %#v", ev)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for SSE snapshot")
	}

	// 2. Submit a write request and verify approval.created contains metadata only, never values.
	code, sub, raw := wh.submit(writeBody("mac-server", "agent-42", "NAS admin", "create", `{"password":"SUPER-SECRET-PASSWORD","username":"admin"}`), agentAddr)
	if code != http.StatusAccepted {
		t.Fatalf("submit code=%d raw=%s", code, raw)
	}

	var created ApprovalEvent
	select {
	case created = <-events:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for approval.created event")
	}
	if created.Type != "approval.created" || created.Approval == nil {
		t.Fatalf("created event = %#v", created)
	}
	if created.Approval.Context.PaseoAgentID != "agent-42" || created.Approval.RequesterMachine != "mac-server" {
		t.Fatalf("context/machine = %#v", created.Approval)
	}
	if data, _ := json.Marshal(created); strings.Contains(string(data), "SUPER-SECRET-PASSWORD") {
		t.Fatalf("secret value leaked in SSE event: %s", string(data))
	}

	// 3. Decide with approve_writes via POST /approvals/{id}/decide.
	decideReq := httptest.NewRequest(http.MethodPost, "/approvals/"+created.Approval.ID+"/decide",
		strings.NewReader(`{"action":"approve_writes","approver":"voice-workspace"}`))
	decideReq.Header.Set("Authorization", "Bearer sg_approver_secret")
	decideRec := httptest.NewRecorder()
	wh.h.HandleApprovals(decideRec, decideReq)
	if decideRec.Code != http.StatusOK {
		t.Fatalf("decide code=%d body=%s", decideRec.Code, decideRec.Body.String())
	}
	var decideResp DecideResponse
	if err := json.Unmarshal(decideRec.Body.Bytes(), &decideResp); err != nil {
		t.Fatal(err)
	}
	if decideResp.Approval.Status != models.StatusApproved || decideResp.Approval.WriteWindowID == "" {
		t.Fatalf("decideResp = %#v", decideResp)
	}
	if wh.status(sub.Token) != models.StatusApproved {
		t.Fatalf("store status = %s, want approved", wh.status(sub.Token))
	}
	if len(pw.resolved) != 1 || pw.resolved[0] != "sg-"+created.Approval.ID {
		t.Fatalf("PushWard activity not resolved on Approver API decision: %v", pw.resolved)
	}

	select {
	case ev := <-events:
		if ev.Type != "approval.approved" || ev.Approval == nil || ev.Approval.Approver != "voice-workspace" {
			t.Fatalf("approved event = %#v", ev)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for approval.approved event")
	}

	// 4. Revoke the write window via POST /approvals/windows/{id}/revoke.
	revokeReq := httptest.NewRequest(http.MethodPost, "/approvals/windows/"+decideResp.Approval.WriteWindowID+"/revoke",
		strings.NewReader(`{"approver":"voice-workspace"}`))
	revokeReq.Header.Set("Authorization", "Bearer sg_approver_secret")
	revokeRec := httptest.NewRecorder()
	wh.h.HandleApprovals(revokeRec, revokeReq)
	if revokeRec.Code != http.StatusOK {
		t.Fatalf("revoke code=%d body=%s", revokeRec.Code, revokeRec.Body.String())
	}

	select {
	case ev := <-events:
		if ev.Type != "window.revoked" || ev.WindowID != decideResp.Approval.WriteWindowID {
			t.Fatalf("revoked event = %#v", ev)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for window.revoked event")
	}
}
