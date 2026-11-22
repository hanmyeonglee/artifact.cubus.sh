package auth

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

var trustedProxyPrefixes = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
}

// ExtractClientIP resolves the caller IP safely behind nginx-proxy + cloudflared.
// X-Real-IP is trusted ONLY when TCP RemoteAddr is on a trusted private/loopback proxy;
// X-Forwarded-For is never trusted because TRUST_DOWNSTREAM_PROXY preserves client-supplied values.
func ExtractClientIP(r *http.Request) netip.Addr {
	remote := parseRemoteAddr(r.RemoteAddr)
	if !remote.IsValid() {
		return netip.Addr{}
	}
	if isTrustedProxy(remote) {
		if raw := strings.TrimSpace(r.Header.Get("X-Real-IP")); raw != "" {
			if addr, err := netip.ParseAddr(raw); err == nil {
				return addr.Unmap()
			}
		}
	}
	return remote
}

// RateLimitIPKey buckets IPv4 by /32 and IPv6 by /64 to prevent IPv6 rotation bypasses.
func RateLimitIPKey(addr netip.Addr) string {
	if !addr.IsValid() {
		return "unknown"
	}
	addr = addr.Unmap()
	if addr.Is4() {
		return addr.String()
	}
	return netip.PrefixFrom(addr, 64).Masked().String()
}

func parseRemoteAddr(raw string) netip.Addr {
	host, _, err := net.SplitHostPort(raw)
	if err != nil {
		host = raw
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(host))
	if err != nil {
		return netip.Addr{}
	}
	return addr.Unmap()
}

func isTrustedProxy(addr netip.Addr) bool {
	for _, pfx := range trustedProxyPrefixes {
		if pfx.Contains(addr) {
			return true
		}
	}
	return false
}

type bucket struct {
	tokens   float64
	lastSeen time.Time
}

// Limiter is a bounded, concurrency-safe token-bucket rate limiter.
type Limiter struct {
	mu         sync.Mutex
	ratePerSec float64
	burst      float64
	maxEntries int
	buckets    map[string]*bucket
	nowFn      func() time.Time
}

func NewLimiter(perMinute int, burst int) *Limiter {
	if perMinute < 1 {
		perMinute = 1
	}
	if burst < 1 {
		burst = perMinute
	}
	return &Limiter{
		ratePerSec: float64(perMinute) / 60.0,
		burst:      float64(burst),
		maxEntries: 4096,
		buckets:    make(map[string]*bucket),
		nowFn:      time.Now,
	}
}

func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.nowFn()
	if len(l.buckets) >= l.maxEntries {
		cutoff := now.Add(-10 * time.Minute)
		for k, b := range l.buckets {
			if b.lastSeen.Before(cutoff) {
				delete(l.buckets, k)
			}
		}
		if len(l.buckets) >= l.maxEntries {
			// Evict oldest arbitrary entry if still saturated.
			for k := range l.buckets {
				delete(l.buckets, k)
				break
			}
		}
	}

	b, ok := l.buckets[key]
	if !ok {
		l.buckets[key] = &bucket{
			tokens:   l.burst - 1,
			lastSeen: now,
		}
		return true
	}

	elapsed := now.Sub(b.lastSeen).Seconds()
	if elapsed > 0 {
		b.tokens = min(l.burst, b.tokens+elapsed*l.ratePerSec)
		b.lastSeen = now
	}
	if b.tokens < 1.0 {
		return false
	}
	b.tokens -= 1.0
	return true
}
