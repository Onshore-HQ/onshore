package logproc

import "onshore/data-plane/internal/payload"

// The payload readers and counters are core code (internal/payload, AGPL), shared
// with the AI gateway. These names keep the log pipeline code as it was.

const MaxLeafBytes = payload.MaxLeafBytes

type (
	Item     = payload.Item
	Leaf     = payload.Leaf
	Counts   = payload.Counts
	Counters = payload.Counters
	Payload  = payload.Payload
)

var (
	ParseBody       = payload.ParseBody
	ParseOTLP       = payload.ParseOTLP
	ParseOTLPSignal = payload.ParseOTLPSignal
	HostOf          = payload.HostOf
	HintFromPath    = payload.HintFromPath
)
