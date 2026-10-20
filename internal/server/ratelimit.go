package server

import (
	"log"
	"time"
)

type bucket struct {
	tokens  float64
	last    time.Time
	logged  time.Time
	dropped int
}

// allow is a per-client token bucket: Rate queries per second, bursts up to Burst.
func (s *Server) allow(ip string) bool {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.buckets) > 10000 {
		for k, b := range s.buckets {
			if now.Sub(b.last) > time.Minute {
				delete(s.buckets, k)
			}
		}
	}
	b, ok := s.buckets[ip]
	if !ok {
		b = &bucket{tokens: s.Burst, last: now}
		s.buckets[ip] = b
	}
	b.tokens = min(s.Burst, b.tokens+now.Sub(b.last).Seconds()*s.Rate)
	b.last = now
	if b.tokens < 1 {
		if b.dropped++; now.Sub(b.logged) > time.Minute {
			log.Printf("rate limit: dropping queries from %s (%d dropped)", ip, b.dropped)
			b.logged = now
		}
		return false
	}
	b.tokens--
	return true
}
