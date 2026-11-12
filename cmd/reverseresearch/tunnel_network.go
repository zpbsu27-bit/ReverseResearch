package main

import (
	"crypto/sha256"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	sdkproxy "github.com/openai/tunnel-client/pkg/proxy"
)

type systemTunnelProxy struct {
	address string
	bypass  string
}

type tunnelProxySelection struct {
	proxy     *url.URL
	automatic bool
}

// tunnelNetwork selects a transport path, with no polling or request retry.
// Each SDK attempt reads current settings. A failed automatic proxy is avoided
// briefly on the next SDK attempt. Direct connections use the OS routes,
// including virtual adapters; no VPN vendor, adapter name or port is assumed.
type tunnelNetwork struct {
	lookup func(string) (string, bool)
	read   func() (systemTunnelProxy, error)
	now    func() time.Time
	report func(string)

	mu          sync.Mutex
	failedProxy [sha256.Size]byte
	failedUntil time.Time
	lastRoute   string
}

const tunnelProxyFailureWindow = 15 * time.Second

func newTunnelNetwork(report func(string)) *tunnelNetwork {
	return &tunnelNetwork{lookup: os.LookupEnv, read: readSystemTunnelProxy, now: time.Now, report: report}
}

func (n *tunnelNetwork) selectProxy(req *http.Request) (tunnelProxySelection, error) {
	// Do not use http.ProxyFromEnvironment's process-wide cached configuration.
	// Explicit empty values also suppress OS fallback.
	values := make(map[string]string)
	explicit := false
	for _, name := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy"} {
		if value, present := n.lookup(name); present {
			values[name] = strings.TrimSpace(value)
			if name != "NO_PROXY" && name != "no_proxy" {
				explicit = true
			}
		}
	}
	first := func(names ...string) string {
		for _, name := range names {
			if value := values[name]; value != "" {
				return value
			}
		}
		return ""
	}
	noProxy := first("NO_PROXY", "no_proxy")
	var address string
	if explicit {
		if strings.EqualFold(req.URL.Scheme, "https") {
			address = first("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy")
		} else {
			address = first("HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy")
		}
	} else {
		settings, err := n.read()
		if err != nil {
			return tunnelProxySelection{}, err
		}
		if systemProxyBypass(settings.bypass, req.URL) {
			return tunnelProxySelection{}, nil
		}
		address = settings.address
	}
	if address == "" {
		return tunnelProxySelection{}, nil
	}
	address, err := validateSystemProxyURL(address)
	if err != nil {
		return tunnelProxySelection{}, err
	}
	if ip := net.ParseIP(req.URL.Hostname()); strings.EqualFold(req.URL.Hostname(), "localhost") || (ip != nil && ip.IsLoopback()) || tunnelNoProxyIP(noProxy, req.URL) {
		return tunnelProxySelection{}, nil
	}
	// Reuse the SDK's environment/bypass owner. Normalize the default target
	// port and leading wildcard to retain the standard NO_PROXY conventions.
	target := *req.URL
	if target.Port() == "" {
		port := "80"
		if strings.EqualFold(target.Scheme, "https") {
			port = "443"
		}
		target.Host = net.JoinHostPort(target.Hostname(), port)
	}
	entries := strings.Split(noProxy, ",")
	for i, entry := range entries {
		if strings.TrimSpace(entry) == "*" {
			return tunnelProxySelection{}, nil
		}
		entries[i] = strings.TrimPrefix(strings.TrimSpace(entry), "*")
	}
	route := sdkproxy.ResolveRoute(sdkproxy.RouteKindControlPlane, "control-plane", &target, nil, "", func(key string) (string, bool) {
		switch key {
		case "HTTPS_PROXY", "HTTP_PROXY":
			return address, true
		case "NO_PROXY":
			return strings.Join(entries, ","), true
		default:
			return "", false
		}
	})
	proxy := route.ProxyURL
	selection := tunnelProxySelection{proxy: proxy, automatic: !explicit}
	if selection.automatic && proxy != nil {
		identity := sha256.Sum256([]byte(proxy.String()))
		n.mu.Lock()
		if identity == n.failedProxy && n.now().Before(n.failedUntil) {
			selection.proxy = nil
		}
		n.mu.Unlock()
	}
	return selection, nil
}

type adaptiveTunnelTransport struct {
	prototype *http.Transport
	direct    *http.Transport
	network   *tunnelNetwork

	mu       sync.Mutex
	proxied  *http.Transport
	proxyKey [sha256.Size]byte
}

func (n *tunnelNetwork) adapt(base http.RoundTripper) (http.RoundTripper, error) {
	transport, ok := base.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("tunnel network adapter requires an HTTP transport")
	}
	prototype := transport.Clone() // Keep the SDK's TLS and timeout policy.
	prototype.Proxy = nil
	return &adaptiveTunnelTransport{prototype: prototype, direct: prototype.Clone(), network: n}, nil
}

func (t *adaptiveTunnelTransport) routeTransport(proxy *url.URL) *http.Transport {
	if proxy == nil {
		return t.direct
	}
	identity := sha256.Sum256([]byte(proxy.String()))
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.proxied == nil || identity != t.proxyKey {
		if t.proxied != nil {
			t.proxied.CloseIdleConnections()
		}
		t.proxied = t.prototype.Clone()
		t.proxied.Proxy = func(*http.Request) (*url.URL, error) { return proxy, nil }
		t.proxyKey = identity
	}
	return t.proxied
}

func (t *adaptiveTunnelTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	selection, err := t.network.selectProxy(req)
	if err != nil {
		if req.Body != nil {
			_ = req.Body.Close()
		}
		return nil, err
	}
	n := t.network
	route := "系统路由（直连或虚拟网卡）"
	if selection.proxy != nil {
		source := "系统代理"
		if !selection.automatic {
			source = "显式环境代理"
		}
		route = source + " " + selection.proxy.Scheme + "://" + selection.proxy.Host
	}
	n.mu.Lock()
	changed := route != n.lastRoute
	n.lastRoute = route
	n.mu.Unlock()
	if changed && n.report != nil {
		n.report(route) // Host/scheme only; never expose proxy credentials.
	}
	// Separate pools prevent HTTP/2 from reusing an old path before consulting
	// a changed Proxy function. At most the direct and current proxy pools stay
	// cached; an address change closes the previous pool's idle connections.
	response, err := t.routeTransport(selection.proxy).RoundTrip(req) // One submission.
	if selection.automatic && selection.proxy != nil {
		identity := sha256.Sum256([]byte(selection.proxy.String()))
		n.mu.Lock()
		if err != nil && req.Context().Err() == nil {
			n.failedProxy = identity
			n.failedUntil = n.now().Add(tunnelProxyFailureWindow)
		} else if err == nil && identity == n.failedProxy {
			n.failedUntil = time.Time{}
		}
		n.mu.Unlock()
	}
	return response, err // HTTP/auth errors and cancellation stay with the SDK.
}

func (t *adaptiveTunnelTransport) CloseIdleConnections() {
	t.direct.CloseIdleConnections()
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.proxied != nil {
		t.proxied.CloseIdleConnections()
	}
}

// Supplement only the IP/CIDR forms not handled by the pinned SDK's bypass
// helper; hostname and suffix matching stay with that existing owner.
func tunnelNoProxyIP(value string, target *url.URL) bool {
	ip := net.ParseIP(target.Hostname())
	if ip == nil {
		return false
	}
	port := target.Port()
	if port == "" {
		if target.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	for _, entry := range strings.Split(value, ",") {
		entry = strings.TrimSpace(entry)
		if _, subnet, err := net.ParseCIDR(entry); err == nil && subnet.Contains(ip) {
			return true
		}
		if host, explicitPort, err := net.SplitHostPort(entry); err == nil {
			if other := net.ParseIP(host); other != nil && other.Equal(ip) && explicitPort == port {
				return true
			}
		} else if other := net.ParseIP(strings.Trim(entry, "[]")); other != nil && other.Equal(ip) {
			return true
		}
	}
	return false
}

func systemProxyBypass(value string, target *url.URL) bool {
	host := strings.ToLower(target.Hostname())
	for _, entry := range strings.Split(value, ";") {
		entry = strings.ToLower(strings.TrimSpace(entry))
		if entry == "<local>" && !strings.Contains(host, ".") && net.ParseIP(host) == nil {
			return true
		}
		candidate := host
		if strings.Contains(entry, ":") {
			candidate = strings.ToLower(target.Host)
		}
		if matches, err := path.Match(entry, candidate); err == nil && matches {
			return true
		}
	}
	return false
}
