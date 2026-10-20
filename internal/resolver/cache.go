package resolver

import (
	"time"

	"github.com/swayam5342/dnsr/internal/wire"
)

type cacheEntry struct {
	rrs     []wire.RR
	sigs    []wire.RR
	expires time.Time
}

type zoneEntry struct {
	ns      []Nameserver
	expires time.Time
}

// clampTTLs caps every TTL at MaxTTL so no record can stay cached for longer.
func (r *Resolver) clampTTLs(rrs []wire.RR) []wire.RR {
	out := make([]wire.RR, len(rrs))
	for i, rr := range rrs {
		if rr.TTL > r.MaxTTL {
			rr.TTL = r.MaxTTL
		}
		out[i] = rr
	}
	return out
}

func minTTL(rrs []wire.RR) uint32 {
	m := rrs[0].TTL
	for _, rr := range rrs {
		if rr.TTL < m {
			m = rr.TTL
		}
	}
	return m
}

// evict makes room in a bounded cache: expired entries go first, then arbitrary ones.
func evict[V any](m map[string]V, max int, expired func(V) bool) {
	if len(m) < max {
		return
	}
	for k, v := range m {
		if expired(v) {
			delete(m, k)
		}
	}
	for k := range m {
		if len(m) < max {
			break
		}
		delete(m, k)
	}
}

func (r *Resolver) cacheGet(name string, t wire.RRType) ([]wire.RR, []wire.RR, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.cache[name+"|"+t.String()]
	if !ok || time.Now().After(e.expires) {
		return nil, nil, false
	}
	left := uint32(time.Until(e.expires).Seconds())
	out := make([]wire.RR, len(e.rrs))
	for i, rr := range e.rrs {
		rr.TTL = left
		out[i] = rr
	}
	return out, e.sigs, true
}

func (r *Resolver) cachePut(name string, t wire.RRType, rrs, sigs []wire.RR) {
	if len(rrs) == 0 {
		return
	}
	ttl := min(minTTL(rrs), r.MaxTTL)
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	evict(r.cache, r.MaxCacheEntries, func(e cacheEntry) bool { return now.After(e.expires) })
	r.cache[name+"|"+t.String()] = cacheEntry{rrs, sigs, now.Add(time.Duration(ttl) * time.Second)}
}

func (r *Resolver) putZone(zone string, ns []Nameserver, ttl uint32) {
	ttl = min(ttl, r.MaxTTL)
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	evict(r.zoneNS, r.MaxCacheEntries, func(e zoneEntry) bool { return now.After(e.expires) })
	r.zoneNS[zone] = zoneEntry{ns, now.Add(time.Duration(ttl) * time.Second)}
}

func (r *Resolver) closestKnownZone(name string) (string, []Nameserver) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	for z := name; ; {
		if e, ok := r.zoneNS[z]; ok && len(e.ns) > 0 && now.Before(e.expires) {
			return z, e.ns
		}
		if z == "." {
			return ".", r.Roots
		}
		z = wire.ParentName(z)
	}
}
