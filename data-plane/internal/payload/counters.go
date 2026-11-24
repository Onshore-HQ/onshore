package payload

import (
	"context"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"onshore/data-plane/internal/detect"
)

type countKey struct {
	minute                                                time.Time
	vault, module, source, dest, destHost, entity, action string
	entityVersion                                         int
	ruleset                                               int64
}

// Counters batches detection counts per minute. They hold types and counts, never
// values, and feed the "caught before leaving" chart and the residency report.
type Counters struct {
	mu     sync.Mutex
	counts map[countKey]int64
	// Rules stamps each count with the versions that produced it.
	Rules detect.RuleSets
}

// Record adds counts for one source.
func (c *Counters) Record(vault, module, source, dest string, counts Counts, scale int64) {
	c.RecordTo(vault, module, source, dest, "", counts, scale)
}

// HostOf returns the lower-case host of an upstream address, for the residency map.
func HostOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// RecordTo adds counts for one source, stamped with the host they were headed to.
func (c *Counters) RecordTo(vault, module, source, dest, destHost string, counts Counts, scale int64) {
	minute := time.Now().UTC().Truncate(time.Minute)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.counts == nil {
		c.counts = map[countKey]int64{}
	}
	var rs *detect.RuleSet
	if c.Rules != nil {
		rs = c.Rules.For(vault)
	}
	for k, n := range counts {
		key := countKey{minute: minute, vault: vault, module: module, source: source, dest: dest, destHost: destHost, entity: k[0], action: k[1]}
		if rs != nil {
			key.ruleset = rs.Version
			if d := rs.Custom(k[0]); d != nil {
				key.entityVersion = d.Version
			}
		}
		c.counts[key] += n * scale
	}
}

// Flush upserts counts. On failure the remainder is kept for the next attempt.
func (c *Counters) Flush(ctx context.Context, pool *pgxpool.Pool) error {
	c.mu.Lock()
	batch := c.counts
	c.counts = nil
	c.mu.Unlock()
	for k, n := range batch {
		_, err := pool.Exec(ctx, `INSERT INTO events.detection_events(occurred_at,vault_id,module,source_id,destination,entity_type,action,count,entity_version,ruleset_version,dest_host) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,nullif($9::int,0),nullif($10::bigint,0),nullif($11,''))
			ON CONFLICT (occurred_at,vault_id,module,source_id,destination,coalesce(dest_host,''),entity_type,action,coalesce(entity_version,0),coalesce(ruleset_version,0)) DO UPDATE SET count=events.detection_events.count+EXCLUDED.count`,
			k.minute, k.vault, k.module, k.source, k.dest, k.entity, k.action, n, k.entityVersion, k.ruleset, k.destHost)
		if err != nil {
			c.mu.Lock()
			if c.counts == nil {
				c.counts = map[countKey]int64{}
			}
			for k, n := range batch {
				c.counts[k] += n
			}
			c.mu.Unlock()
			return err
		}
		delete(batch, k)
	}
	return nil
}
