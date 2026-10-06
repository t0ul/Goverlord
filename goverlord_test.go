package goverlord_test

import (
	"errors"
	"sync"
	"testing"

	"github.com/t0ul/goverlord"
)

type capturedAuditor struct {
	mu     sync.Mutex
	events []string
}

func (c *capturedAuditor) Emit(traceID, span, event string, fields map[string]any) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, event+":"+fields["status"].(string))
	return ""
}

func (c *capturedAuditor) saw(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, e := range c.events {
		if e == key {
			return true
		}
	}
	return false
}

func base(opts ...goverlord.Option) *goverlord.ControlPlane {
	std := []goverlord.Option{
		goverlord.WithRole(goverlord.Role{Name: "op", Permissions: []goverlord.Permission{
			goverlord.PermConfigWrite, goverlord.PermRollback, goverlord.PermKillSwitch,
		}}),
		goverlord.WithRole(goverlord.Role{Name: "reader", Permissions: nil}),
		goverlord.WithOperator(goverlord.Operator{ID: "alice", Roles: []string{"op"}}),
		goverlord.WithOperator(goverlord.Operator{ID: "bob", Roles: []string{"op"}}),
		goverlord.WithOperator(goverlord.Operator{ID: "carol", Roles: []string{"reader"}}),
		goverlord.WithConfig(map[string]any{"model": "planner"}),
	}
	return goverlord.New(append(std, opts...)...)
}

func TestRBAC(t *testing.T) {
	cp := base()
	if !cp.Can("alice", goverlord.PermConfigWrite) {
		t.Error("alice should hold config.write")
	}
	if cp.Can("carol", goverlord.PermConfigWrite) {
		t.Error("carol (reader) must not hold config.write")
	}
	if cp.Can("nobody", goverlord.PermConfigWrite) {
		t.Error("unknown operator must hold nothing")
	}
}

func TestImmediateApplyWithoutDualControl(t *testing.T) {
	cp := base() // no WithDualControl
	id, applied, err := cp.Propose("alice", goverlord.PermConfigWrite,
		goverlord.Change{Set: map[string]any{"model": "coder"}})
	if err != nil || !applied || id != "" {
		t.Fatalf("expected immediate apply, got id=%q applied=%v err=%v", id, applied, err)
	}
	if cp.Config()["model"] != "coder" || cp.Version() != 1 {
		t.Fatalf("config/version not updated: %v v%d", cp.Config(), cp.Version())
	}
}

func TestFourEyes(t *testing.T) {
	cp := base(goverlord.WithDualControl(goverlord.PermConfigWrite))

	id, applied, err := cp.Propose("alice", goverlord.PermConfigWrite,
		goverlord.Change{Set: map[string]any{"model": "coder"}})
	if err != nil || applied || id == "" {
		t.Fatalf("expected a pending proposal, got id=%q applied=%v err=%v", id, applied, err)
	}
	if cp.Config()["model"] != "planner" {
		t.Fatal("config changed before approval")
	}

	if _, err := cp.Approve("alice", id); !errors.Is(err, goverlord.ErrSameOperator) {
		t.Fatalf("self-approval should fail with ErrSameOperator, got %v", err)
	}
	if _, err := cp.Approve("carol", id); !errors.Is(err, goverlord.ErrForbidden) {
		t.Fatalf("reader approval should be forbidden, got %v", err)
	}

	applied, err = cp.Approve("bob", id)
	if err != nil || !applied {
		t.Fatalf("bob's approval should commit: applied=%v err=%v", applied, err)
	}
	if cp.Config()["model"] != "coder" {
		t.Fatalf("approved change not applied: %v", cp.Config())
	}
	if len(cp.Pending()) != 0 {
		t.Error("proposal should be cleared after approval")
	}
}

func TestRollbackRecordsNewVersion(t *testing.T) {
	cp := base()
	cp.Propose("alice", goverlord.PermConfigWrite, goverlord.Change{Set: map[string]any{"model": "a"}})
	cp.Propose("alice", goverlord.PermConfigWrite, goverlord.Change{Set: map[string]any{"model": "b"}})
	if cp.Config()["model"] != "b" {
		t.Fatalf("precondition failed: %v", cp.Config())
	}
	if err := cp.Rollback("alice", 0); err != nil {
		t.Fatal(err)
	}
	// v0 genesis had model=planner.
	if cp.Config()["model"] != "planner" {
		t.Fatalf("rollback did not restore genesis: %v", cp.Config())
	}
	if cp.Version() != 3 { // v1=a, v2=b, v3=rollback
		t.Fatalf("rollback should append a version, got v%d", cp.Version())
	}
	if err := cp.Rollback("carol", 0); !errors.Is(err, goverlord.ErrForbidden) {
		t.Fatalf("reader rollback should be forbidden, got %v", err)
	}
}

func TestKillSwitchFailsClosed(t *testing.T) {
	aud := &capturedAuditor{}
	cp := base(goverlord.WithAuditor(aud))

	if err := cp.KillSwitch("carol", true); !errors.Is(err, goverlord.ErrForbidden) {
		t.Fatalf("reader must not toggle the kill switch, got %v", err)
	}
	if err := cp.KillSwitch("alice", true); err != nil {
		t.Fatal(err)
	}
	if !cp.Killed() {
		t.Fatal("kill switch should be engaged")
	}

	if _, _, err := cp.Propose("alice", goverlord.PermConfigWrite,
		goverlord.Change{Set: map[string]any{"model": "x"}}); !errors.Is(err, goverlord.ErrKilled) {
		t.Fatalf("propose under kill switch should fail closed, got %v", err)
	}
	if err := cp.Guard("alice", goverlord.PermConfigWrite); !errors.Is(err, goverlord.ErrKilled) {
		t.Fatalf("Guard should fail closed, got %v", err)
	}

	// Disengage is allowed even while killed.
	if err := cp.KillSwitch("alice", false); err != nil {
		t.Fatal(err)
	}
	if err := cp.Guard("alice", goverlord.PermConfigWrite); err != nil {
		t.Fatalf("Guard should pass after disengage, got %v", err)
	}
	if !aud.saw("killswitch:engaged") || !aud.saw("killswitch:disengaged") {
		t.Error("expected kill-switch engage/disengage audit events")
	}
}

func TestGuardAndUnknownOperator(t *testing.T) {
	cp := base()
	if err := cp.Guard("nobody", goverlord.PermConfigWrite); !errors.Is(err, goverlord.ErrUnknownOperator) {
		t.Fatalf("unknown operator should be rejected, got %v", err)
	}
	if err := cp.Guard("carol", goverlord.PermConfigWrite); !errors.Is(err, goverlord.ErrForbidden) {
		t.Fatalf("reader should be forbidden, got %v", err)
	}
	if err := cp.Guard("alice", goverlord.PermConfigWrite); err != nil {
		t.Fatalf("operator should pass guard, got %v", err)
	}
}
