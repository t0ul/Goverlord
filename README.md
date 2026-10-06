# goverlord

A zero-dependency **governed control plane** for AI systems — the overlord that
decides who may change what, and under what ceremony. Pure Go standard library,
concurrency-safe, no database required.

Part of *the fleet* — build-your-own Go security tools. goverlord is the Track II
governance backbone; it pairs with
[`gledger`](https://github.com/t0ul/gledger) (audit),
[`gouncer`](https://github.com/t0ul/gouncer) (gateway),
[`gumpers`](https://github.com/t0ul/gumpers) (guardrails),
[`gorauder`](https://github.com/t0ul/gorauder) (red-team), and
[`goflage`](https://github.com/t0ul/goflage) (redaction).

## What it governs

- **Operator RBAC.** Operators bear roles; roles grant permissions. `Can` and
  `Guard` resolve access; `*` is a wildcard.
- **Four-eyes dual control.** Mark sensitive permissions (e.g. `config.write`)
  as dual-control: a change is *proposed*, parked, and takes effect only when a
  **different** operator with the same permission *approves* it. Self-approval is
  refused.
- **Versioned config with rollback.** Every commit appends an immutable snapshot
  to an append-only history. `Rollback(to)` restores an earlier snapshot as a
  *new* version — history is never rewritten, so the rollback itself is audited.
- **Fail-closed kill switch.** `KillSwitch(engage)` blocks every mutation and
  makes `Guard` deny the data plane. Disengaging is allowed while engaged so you
  can always recover.
- **Tamper-evident governance trail.** Every action emits through an `Auditor`
  interface identical to `gledger.AuditLog.Emit`, so the control plane's own
  history is as tamper-evident as the data plane's.

## Usage

```go
cp := goverlord.New(
    goverlord.WithRole(goverlord.Role{Name: "operator", Permissions: []goverlord.Permission{
        goverlord.PermConfigWrite, goverlord.PermRollback,
    }}),
    goverlord.WithOperator(goverlord.Operator{ID: "alice", Roles: []string{"operator"}}),
    goverlord.WithOperator(goverlord.Operator{ID: "bob", Roles: []string{"operator"}}),
    goverlord.WithDualControl(goverlord.PermConfigWrite),
    goverlord.WithConfig(map[string]any{"rate_per_minute": 120}),
    goverlord.WithAuditor(auditLog), // e.g. *gledger.AuditLog
)

// Four-eyes: propose, then a different operator approves.
id, applied, _ := cp.Propose("alice", goverlord.PermConfigWrite,
    goverlord.Change{Note: "launch", Set: map[string]any{"rate_per_minute": 600}})
// applied == false; id is pending
cp.Approve("bob", id) // committed → version advances

// Data-plane gate (fails closed under the kill switch):
if err := cp.Guard("alice", goverlord.PermConfigWrite); err == nil {
    // ... perform the governed action ...
}
```

## Demo / CLI

```sh
go build ./cmd/goverlord
./goverlord demo   # runs propose → self-approve-denied → approve → rollback → kill switch, printing the audit trail
```

## Test

```sh
go test ./...
```

## Status

v0. In-memory RBAC, four-eyes, versioned config, rollback, kill switch, audit.
Not yet: persistence/snapshotting the plane itself, time-boxed or N-of-M
approvals, per-key config schemas, and governed operator/role management (roles
and operators are bootstrapped at construction for now).
