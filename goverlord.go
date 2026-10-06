// Package goverlord is a zero-dependency governed control plane for AI systems:
// the overlord that decides who may change what, and under what ceremony. It
// gives you operator RBAC, four-eyes dual control on sensitive changes, an
// append-only versioned config with one-call rollback, and a fail-closed kill
// switch. Every governance action is emitted through an Auditor interface
// identical to gledger.AuditLog.Emit, so the control plane's own history is as
// tamper-evident as the data plane's. Part of the fleet.
package goverlord

import (
	"fmt"
	"sync"
	"time"
)

// ControlPlane holds roles, operators, the versioned config, pending four-eyes
// proposals, and the kill-switch state. It is safe for concurrent use.
type ControlPlane struct {
	mu          sync.RWMutex
	roles       map[string]Role
	operators   map[string]Operator
	versions    []Version
	proposals   map[string]*Proposal
	dualControl map[Permission]bool
	killed      bool
	auditor     Auditor
}

// New builds a ControlPlane with a genesis (empty) config at version 0.
func New(opts ...Option) *ControlPlane {
	cp := &ControlPlane{
		roles:       map[string]Role{},
		operators:   map[string]Operator{},
		proposals:   map[string]*Proposal{},
		dualControl: map[Permission]bool{},
		versions: []Version{{
			N: 0, Config: map[string]any{}, By: "system",
			At: time.Now(), Note: "genesis", Parent: -1,
		}},
	}
	for _, o := range opts {
		o(cp)
	}
	return cp
}

// can resolves RBAC for an operator (caller holds at least a read lock).
func (cp *ControlPlane) can(op Operator, perm Permission) bool {
	for _, rn := range op.Roles {
		r, ok := cp.roles[rn]
		if !ok {
			continue
		}
		for _, p := range r.Permissions {
			if p == perm || p == PermWildcard {
				return true
			}
		}
	}
	return false
}

// Can reports whether an operator holds a permission.
func (cp *ControlPlane) Can(opID string, perm Permission) bool {
	cp.mu.RLock()
	defer cp.mu.RUnlock()
	op, ok := cp.operators[opID]
	return ok && cp.can(op, perm)
}

// Guard is the data-plane gate: it fails closed under the kill switch and then
// checks RBAC. Callers invoke it before performing a governed runtime action.
func (cp *ControlPlane) Guard(opID string, perm Permission) error {
	cp.mu.RLock()
	defer cp.mu.RUnlock()
	if cp.killed {
		return ErrKilled
	}
	op, ok := cp.operators[opID]
	if !ok {
		return ErrUnknownOperator
	}
	if !cp.can(op, perm) {
		return ErrForbidden
	}
	return nil
}

// Propose requests a config change under perm. If perm is under dual control the
// change is parked as a pending proposal (returns applied=false and an id for a
// second operator to Approve); otherwise it is committed immediately.
func (cp *ControlPlane) Propose(opID string, perm Permission, ch Change) (proposalID string, applied bool, err error) {
	cp.mu.Lock()
	defer cp.mu.Unlock()

	op, ok := cp.operators[opID]
	if !ok {
		return "", false, ErrUnknownOperator
	}
	if !cp.can(op, perm) {
		cp.audit(opID, "propose", "forbidden", map[string]any{"perm": string(perm)})
		return "", false, ErrForbidden
	}
	if cp.killed {
		return "", false, ErrKilled
	}

	if cp.dualControl[perm] {
		id := NewID()
		cp.proposals[id] = &Proposal{ID: id, By: opID, Perm: perm, Change: ch, At: time.Now()}
		cp.audit(opID, "propose", "pending", map[string]any{
			"proposal": id, "perm": string(perm), "note": ch.Note,
		})
		return id, false, nil
	}

	v := cp.apply(opID, ch)
	cp.audit(opID, "apply", "committed", map[string]any{
		"version": v.N, "perm": string(perm), "note": ch.Note,
	})
	return "", true, nil
}

// Approve commits a pending proposal. The approver must differ from the proposer
// (four-eyes) and must hold the proposal's permission.
func (cp *ControlPlane) Approve(approverID, proposalID string) (bool, error) {
	cp.mu.Lock()
	defer cp.mu.Unlock()

	if cp.killed {
		return false, ErrKilled
	}
	ap, ok := cp.operators[approverID]
	if !ok {
		return false, ErrUnknownOperator
	}
	p, ok := cp.proposals[proposalID]
	if !ok {
		return false, ErrNoProposal
	}
	if p.By == approverID {
		cp.audit(approverID, "approve", "denied-same-operator", map[string]any{"proposal": proposalID})
		return false, ErrSameOperator
	}
	if !cp.can(ap, p.Perm) {
		cp.audit(approverID, "approve", "forbidden", map[string]any{"proposal": proposalID})
		return false, ErrForbidden
	}

	v := cp.apply(approverID, p.Change)
	delete(cp.proposals, proposalID)
	cp.audit(approverID, "approve", "committed", map[string]any{
		"proposal": proposalID, "proposer": p.By, "version": v.N, "perm": string(p.Perm),
	})
	return true, nil
}

// Reject discards a pending proposal.
func (cp *ControlPlane) Reject(approverID, proposalID string) error {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	if _, ok := cp.operators[approverID]; !ok {
		return ErrUnknownOperator
	}
	p, ok := cp.proposals[proposalID]
	if !ok {
		return ErrNoProposal
	}
	delete(cp.proposals, proposalID)
	cp.audit(approverID, "reject", "discarded", map[string]any{"proposal": proposalID, "proposer": p.By})
	return nil
}

// Rollback reverts config to the snapshot at version `to`, recorded as a new
// version (history is never rewritten). Requires PermRollback.
func (cp *ControlPlane) Rollback(opID string, to int) error {
	cp.mu.Lock()
	defer cp.mu.Unlock()

	op, ok := cp.operators[opID]
	if !ok {
		return ErrUnknownOperator
	}
	if !cp.can(op, PermRollback) {
		cp.audit(opID, "rollback", "forbidden", map[string]any{"to": to})
		return ErrForbidden
	}
	if cp.killed {
		return ErrKilled
	}
	if to < 0 || to >= len(cp.versions) {
		return ErrBadVersion
	}
	target := cp.versions[to]
	v := cp.commit(opID, cloneConfig(target.Config), fmt.Sprintf("rollback to v%d", to), target.N)
	cp.audit(opID, "rollback", "committed", map[string]any{"to": to, "version": v.N})
	return nil
}

// KillSwitch engages or disengages the fail-closed switch. Requires PermKillSwitch.
// Disengaging is permitted even while engaged.
func (cp *ControlPlane) KillSwitch(opID string, engage bool) error {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	op, ok := cp.operators[opID]
	if !ok {
		return ErrUnknownOperator
	}
	if !cp.can(op, PermKillSwitch) {
		cp.audit(opID, "killswitch", "forbidden", map[string]any{"engage": engage})
		return ErrForbidden
	}
	cp.killed = engage
	status := "disengaged"
	if engage {
		status = "engaged"
	}
	cp.audit(opID, "killswitch", status, nil)
	return nil
}

// apply commits a Change against the latest config (caller holds the write lock).
func (cp *ControlPlane) apply(by string, ch Change) Version {
	cur := cp.versions[len(cp.versions)-1]
	nc := cloneConfig(cur.Config)
	for k, val := range ch.Set {
		if val == nil {
			delete(nc, k)
		} else {
			nc[k] = val
		}
	}
	return cp.commit(by, nc, ch.Note, cur.N)
}

func (cp *ControlPlane) commit(by string, cfg map[string]any, note string, parent int) Version {
	v := Version{N: len(cp.versions), Config: cfg, By: by, At: time.Now(), Note: note, Parent: parent}
	cp.versions = append(cp.versions, v)
	return v
}

func (cp *ControlPlane) audit(actor, event, status string, fields map[string]any) {
	if cp.auditor == nil {
		return
	}
	if fields == nil {
		fields = map[string]any{}
	}
	fields["actor"] = actor
	fields["status"] = status
	cp.auditor.Emit(NewID(), "goverlord", event, fields)
}

// --- Read-only accessors ---

// Config returns a clone of the current configuration.
func (cp *ControlPlane) Config() map[string]any {
	cp.mu.RLock()
	defer cp.mu.RUnlock()
	return cloneConfig(cp.versions[len(cp.versions)-1].Config)
}

// Version returns the current version number.
func (cp *ControlPlane) Version() int {
	cp.mu.RLock()
	defer cp.mu.RUnlock()
	return cp.versions[len(cp.versions)-1].N
}

// History returns a copy of the full version lineage, oldest first.
func (cp *ControlPlane) History() []Version {
	cp.mu.RLock()
	defer cp.mu.RUnlock()
	out := make([]Version, len(cp.versions))
	for i, v := range cp.versions {
		v.Config = cloneConfig(v.Config)
		out[i] = v
	}
	return out
}

// Pending returns a snapshot of the open proposals.
func (cp *ControlPlane) Pending() []Proposal {
	cp.mu.RLock()
	defer cp.mu.RUnlock()
	out := make([]Proposal, 0, len(cp.proposals))
	for _, p := range cp.proposals {
		out = append(out, *p)
	}
	return out
}

// Killed reports whether the kill switch is engaged.
func (cp *ControlPlane) Killed() bool {
	cp.mu.RLock()
	defer cp.mu.RUnlock()
	return cp.killed
}
