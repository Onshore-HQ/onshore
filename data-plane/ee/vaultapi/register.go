// Package vaultapi adds the paid routes to the vault API. It is under the Onshore
// Commercial Licence (see ee/LICENSE at the repository root): free for development
// and testing, and on test vaults; production use needs Onshore Business or above.
package vaultapi

import (
	"net/http"

	"onshore/data-plane/internal/httpapi"
	"onshore/data-plane/internal/license"
)

type api struct{ *httpapi.Server }

func init() { httpapi.Register(register) }

func register(srv *httpapi.Server, r httpapi.Routes) {
	s := &api{srv}
	b := license.Business

	// Data subject requests beyond erasure: find, show, export, restrict.
	r.Authed("POST /v1/vaults/{vault}/subjects/search", b, s.listSubjects)
	r.Authed("GET /v1/vaults/{vault}/subjects/{id}", b, s.getSubject)
	r.Authed("GET /v1/vaults/{vault}/subjects/{id}/export", b, s.exportSubject)
	r.Authed("POST /v1/vaults/{vault}/subjects/{id}/restrict", b, s.restrictSubject)

	// Flow checks (residency map).
	r.Authed("POST /v1/vaults/{vault}/flows/{flow}/check", b, s.flowCheck)

	// Cloaking for AI.
	r.Authed("POST /v1/vaults/{vault}/cloak", b, s.cloak)
	r.Authed("POST /v1/vaults/{vault}/uncloak", b, s.uncloak)
	r.Authed("DELETE /v1/vaults/{vault}/twins/{id}", b, s.deleteTwin)

	// Secure components. Minting a client token is the gate; the frame endpoints
	// authenticate by that token.
	r.Authed("POST /v1/vaults/{vault}/client-tokens", b, s.clientTokenMint)
	r.Public("GET /embed/rv.js", s.embedStatic("rv.js", "text/javascript; charset=utf-8", true))
	r.Public("GET /embed/rv-watch.js", s.embedStatic("rv-watch.js", "text/javascript; charset=utf-8", true))
	r.Public("GET /embed/frame.js", s.embedStatic("frame.js", "text/javascript; charset=utf-8", false))
	r.Public("GET /embed/frame.css", s.embedStatic("frame.css", "text/css; charset=utf-8", false))
	r.Public("GET /embed/frame/{vault}", s.embedFrame)
	r.Public("POST /embed/v1/describe", s.embedDescribe)
	r.Public("POST /embed/v1/collect", s.embedCollect)
	r.Public("POST /embed/v1/reveal", s.embedReveal)

	// Log pipelines, the AI gateway, the HTTP proxy and files.
	in := func(p string, h http.HandlerFunc) { r.Internal(p, b, h) }
	in("POST /internal/logs/tokenize", s.logsTokenize)
	in("POST /internal/logs/preview", s.logsPreview)
	in("POST /internal/gateway/reveal", s.gatewayReveal)
	in("POST /internal/gateway/decide", s.gatewayDecide)
	in("POST /internal/gateway/proxy-preview", s.proxyPreview)
	in("POST /internal/gateway/ai-preview", s.aiPreview)
	in("POST /internal/gateway/file", s.gatewayFile)
	in("POST /internal/cloak/twin", s.cloakTwinSave)
	in("POST /internal/cloak/options", s.cloakOptions)

	// Your own data types.
	in("POST /internal/rulesets/versions", s.rulesetVersions)
	in("POST /internal/rulesets/snapshot", s.rulesetSnapshot)
	in("POST /internal/custom/check", s.customCheck)
	in("POST /internal/custom/bench", s.customBench)
	in("POST /internal/custom/samples/add", s.customSamplesAdd)
	in("POST /internal/custom/samples/delete", s.customSamplesDelete)
	in("POST /internal/custom/samples/run", s.customSamplesRun)
	in("POST /internal/custom/try", s.customTry)
	in("POST /internal/custom/values", s.customValues)
	in("POST /internal/custom/benchmark", s.customBenchmark)
	in("POST /internal/custom/quick-bench", s.customQuickBench)
}
