package gateway

import core "onshore/data-plane/internal/gateway"

// The AI gateway and the plumbing every gateway service shares (the vault client,
// Serve, RunLoop) are core code in internal/gateway, under AGPL. The HTTP proxy
// here builds on them; these names keep its code as it was.

const MaxBody = core.MaxBody

type (
	VaultClient = core.VaultClient
	Deps        = core.Deps
	TwinItem    = core.TwinItem
	Cloaked     = core.Cloaked
)

var (
	Serve             = core.Serve
	CloakText         = core.CloakText
	Uncloak           = core.Uncloak
	TwinEntities      = core.TwinEntities
	RunLoop           = core.RunLoop
	ErrVaultDown      = core.ErrVaultDown
	ErrDenied         = core.ErrDenied
	ErrCallerRejected = core.ErrCallerRejected

	fail               = core.Fail
	readLimited        = core.ReadLimited
	clientIP           = core.ClientIP
	safeUpstream       = core.SafeUpstream
	copyRequestHeaders = core.CopyRequestHeaders
	hopHeaders         = core.HopHeaders
	keyOK              = core.KeyOK
	hashKey            = core.HashKey
)
