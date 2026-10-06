// Command goverlord runs a scripted governance scenario end to end and prints
// the audit trail plus final state — a living example and a smoke test.
//
//	goverlord demo
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/t0ul/goverlord"
)

// printAuditor writes each governance event as one JSON line to stdout.
type printAuditor struct{}

func (printAuditor) Emit(traceID, span, event string, fields map[string]any) string {
	b, _ := json.Marshal(map[string]any{"span": span, "event": event, "fields": fields})
	fmt.Println(string(b))
	return ""
}

func main() {
	if len(os.Args) < 2 || os.Args[1] != "demo" {
		fmt.Fprintln(os.Stderr, "usage: goverlord demo")
		os.Exit(1)
	}

	cp := goverlord.New(
		goverlord.WithRole(goverlord.Role{Name: "admin", Permissions: []goverlord.Permission{goverlord.PermWildcard}}),
		goverlord.WithRole(goverlord.Role{Name: "operator", Permissions: []goverlord.Permission{
			goverlord.PermConfigWrite, goverlord.PermRollback,
		}}),
		goverlord.WithOperator(goverlord.Operator{ID: "alice", Roles: []string{"operator"}}),
		goverlord.WithOperator(goverlord.Operator{ID: "bob", Roles: []string{"operator"}}),
		goverlord.WithOperator(goverlord.Operator{ID: "root", Roles: []string{"admin"}}),
		goverlord.WithDualControl(goverlord.PermConfigWrite),
		goverlord.WithConfig(map[string]any{"model": "planner", "rate_per_minute": 120}),
		goverlord.WithAuditor(printAuditor{}),
	)

	fmt.Println("# alice proposes raising the rate limit (dual control → pending)")
	id, applied, err := cp.Propose("alice", goverlord.PermConfigWrite, goverlord.Change{
		Note: "raise rate limit for launch", Set: map[string]any{"rate_per_minute": 600},
	})
	fmt.Printf("  applied=%v err=%v proposal=%s\n\n", applied, err, id)

	fmt.Println("# alice tries to approve her own proposal (four-eyes → denied)")
	_, err = cp.Approve("alice", id)
	fmt.Printf("  err=%v\n\n", err)

	fmt.Println("# bob approves (committed)")
	applied, err = cp.Approve("bob", id)
	fmt.Printf("  applied=%v err=%v  config=%v  version=%d\n\n", applied, err, cp.Config(), cp.Version())

	fmt.Println("# root rolls back to v0")
	_ = cp.Rollback("root", 0)
	fmt.Printf("  config=%v  version=%d\n\n", cp.Config(), cp.Version())

	fmt.Println("# root hits the kill switch; alice's next change fails closed")
	_ = cp.KillSwitch("root", true)
	_, _, err = cp.Propose("alice", goverlord.PermConfigWrite, goverlord.Change{Set: map[string]any{"model": "x"}})
	fmt.Printf("  killed=%v  propose err=%v\n", cp.Killed(), err)
}
