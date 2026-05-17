package blocklist

import (
	"net"
	"strings"
)

// List holds IPs and CIDR networks that are permanently denied access.
type List struct {
	networks []*net.IPNet
	addrs    map[string]struct{}
}

// New parses a slice of IPs and CIDR strings into a List.
// Invalid entries are silently ignored.
func New(entries []string) *List {
	l := &List{addrs: make(map[string]struct{})}
	for _, raw := range entries {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "/") {
			if _, network, err := net.ParseCIDR(entry); err == nil {
				l.networks = append(l.networks, network)
			}
			continue
		}
		if ip := net.ParseIP(entry); ip != nil {
			l.addrs[ip.String()] = struct{}{}
		}
	}
	return l
}

// Contains reports whether ipStr matches any entry in the list.
func (l *List) Contains(ipStr string) bool {
	if len(l.networks) == 0 && len(l.addrs) == 0 {
		return false
	}
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return false
	}
	if _, ok := l.addrs[ip.String()]; ok {
		return true
	}
	for _, n := range l.networks {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
