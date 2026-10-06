package goverlord

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"
)

// Permission is a capability string checked by RBAC, e.g. "config.write".
type Permission string

// Built-in permissions used by the control plane's own operations. Config
// changes via Propose use whatever permission the caller names.
const (
	PermConfigWrite Permission = "config.write"
	PermRollback    Permission = "config.rollback"
	PermKillSwitch  Permission = "killswitch.toggle"
	PermWildcard    Permission = "*" // grants everything
)

// Role groups permissions under a name.
type Role struct {
	Name        string
	Permissions []Permission
}

// Operator is an authenticated actor, identified by ID and bearing roles.
type Operator struct {
	ID    string
	Roles []string
}

// Change is a config mutation: keys in Set are merged into the current config;
// a nil value deletes that key. Note is recorded on the resulting version.
type Change struct {
	Note string
	Set  map[string]any
}

// Version is an immutable config snapshot in the append-only history.
type Version struct {
	N      int            // 0 is genesis
	Config map[string]any // full snapshot, not a delta
	By     string         // operator who committed it
	At     time.Time
	Note   string
	Parent int // the version this was derived from (rollback lineage)
}

// Proposal is a pending, four-eyes change awaiting a second operator's approval.
type Proposal struct {
	ID     string
	By     string
	Perm   Permission
	Change Change
	At     time.Time
}

// Auditor receives structured audit events. *gledger.AuditLog satisfies it as-is.
type Auditor interface {
	Emit(traceID, span, event string, fields map[string]any) string
}

// Governance errors.
var (
	ErrUnknownOperator = errors.New("goverlord: unknown operator")
	ErrForbidden       = errors.New("goverlord: operator lacks the required permission")
	ErrKilled          = errors.New("goverlord: kill switch engaged; mutations refused")
	ErrNoProposal      = errors.New("goverlord: no such proposal")
	ErrSameOperator    = errors.New("goverlord: four-eyes requires a different approver")
	ErrBadVersion      = errors.New("goverlord: version out of range")
)

// Option configures a ControlPlane at construction.
type Option func(*ControlPlane)

// WithRole registers a role.
func WithRole(r Role) Option {
	return func(cp *ControlPlane) { cp.roles[r.Name] = r }
}

// WithOperator registers an operator.
func WithOperator(o Operator) Option {
	return func(cp *ControlPlane) { cp.operators[o.ID] = o }
}

// WithDualControl marks permissions that require four-eyes (propose + approve).
func WithDualControl(perms ...Permission) Option {
	return func(cp *ControlPlane) {
		for _, p := range perms {
			cp.dualControl[p] = true
		}
	}
}

// WithConfig sets the genesis (v0) configuration.
func WithConfig(initial map[string]any) Option {
	return func(cp *ControlPlane) { cp.versions[0].Config = cloneConfig(initial) }
}

// WithAuditor attaches an audit sink (e.g. a *gledger.AuditLog).
func WithAuditor(a Auditor) Option {
	return func(cp *ControlPlane) { cp.auditor = a }
}

func cloneConfig(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return cloneVal(m).(map[string]any)
}

func cloneVal(v any) any {
	switch t := v.(type) {
	case map[string]any:
		o := make(map[string]any, len(t))
		for k, vv := range t {
			o[k] = cloneVal(vv)
		}
		return o
	case []any:
		o := make([]any, len(t))
		for i, vv := range t {
			o[i] = cloneVal(vv)
		}
		return o
	default:
		return v
	}
}

// NewID returns a random 128-bit hex id (proposal ids, audit trace ids).
func NewID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
