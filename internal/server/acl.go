package server

import (
	"log"
	"net/netip"
	"strings"
	"time"
)

var loopbackOnly = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")}

// ParseAllow reads a comma-separated list of CIDR ranges or single addresses.
func ParseAllow(list string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for item := range strings.SplitSeq(list, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if strings.Contains(item, "/") {
			p, err := netip.ParsePrefix(item)
			if err != nil {
				return nil, err
			}
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(item)
		if err != nil {
			return nil, err
		}
		out = append(out, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
	}
	return out, nil
}

// permitted reports whether a client address falls inside the access list.
func (s *Server) permitted(ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	a = a.Unmap().WithZone("")
	allow := s.Allow
	if len(allow) == 0 {
		allow = loopbackOnly
	}
	for _, p := range allow {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// noteRefused logs a refused client at most once per minute.
func (s *Server) noteRefused(ip string) {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if now.Sub(s.refused[ip]) < time.Minute {
		return
	}
	if len(s.refused) > 10000 {
		clear(s.refused)
	}
	s.refused[ip] = now
	log.Printf("access list: refusing queries from %s", ip)
}
