package main

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestWindowsManualProxySelection(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{"127.0.0.1:7897", "http://127.0.0.1:7897"},
		{"http=127.0.0.1:8080;https=127.0.0.1:7897", "http://127.0.0.1:7897"},
		{" HTTPS = https://proxy.example:8443 ;http=127.0.0.1:80", "https://proxy.example:8443"},
		{" HTTPS = http://127.0.0.1:7897", "http://127.0.0.1:7897"},
		{"http=127.0.0.1:7897", ""},
		{"", ""},
		{"https=", ""},
		{"socks5://127.0.0.1:1080", "socks5://127.0.0.1:1080"},
		{"http://user:pass=word@proxy.example:8080", "http://user:pass=word@proxy.example:8080"},
		{"[::1]:7897", "http://[::1]:7897"},
	} {
		got, err := selectSystemHTTPSProxy(tc.input)
		if err != nil || got != tc.want {
			t.Fatalf("%q: %q %v, want %q", tc.input, got, err, tc.want)
		}
	}
	for _, input := range []string{"file:///private", "https=://bad", "http://proxy.example/path", "http://proxy.example/?key=private", "http://proxy.example:70000", "http://proxy.example:0"} {
		if _, err := selectSystemHTTPSProxy(input); err == nil || strings.Contains(err.Error(), "private") {
			t.Fatalf("invalid proxy exposed or accepted: %q %v", input, err)
		}
	}
}

func TestTunnelProxyExplicitEnvironmentPrecedence(t *testing.T) {
	for _, name := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"} {
		for _, value := range []string{"", "http://explicit.example:8080"} {
			readCalled := false
			network := &tunnelNetwork{
				lookup: func(key string) (string, bool) { return value, key == name },
				read: func() (systemTunnelProxy, error) {
					readCalled = true
					return systemTunnelProxy{address: "http://system.example:8080"}, nil
				},
				now: time.Now,
			}
			req, _ := http.NewRequest(http.MethodGet, "https://service.example/api", nil)
			got, err := network.selectProxy(req)
			if err != nil || readCalled || got.automatic || (value == "" && got.proxy != nil) || (value != "" && (got.proxy == nil || got.proxy.String() != value)) {
				t.Fatalf("explicit %s=%q overridden", name, value)
			}
		}
	}
	network := &tunnelNetwork{lookup: func(string) (string, bool) { return "", false }, read: func() (systemTunnelProxy, error) {
		return systemTunnelProxy{address: "http://system.example:8080"}, nil
	}, now: time.Now}
	req, _ := http.NewRequest(http.MethodGet, "https://service.example/api", nil)
	got, err := network.selectProxy(req)
	if err != nil || got.proxy == nil || got.proxy.String() != "http://system.example:8080" || !got.automatic {
		t.Fatalf("system fallback %+v %v", got, err)
	}
}

func TestTunnelProxyBypassRules(t *testing.T) {
	for _, tc := range []struct {
		target, bypass string
		want           bool
	}{
		{"https://host/path", "<local>", true},
		{"https://service.example/path", "<local>", false},
		{"https://api.example/path", "*.example", true},
		{"https://outside.example.net/path", "*.example", false},
		{"https://api.example:443/path", "api.example:443", true},
		{"https://api.example:8443/path", "api.example:443", false},
	} {
		req, _ := http.NewRequest(http.MethodGet, tc.target, nil)
		if got := systemProxyBypass(tc.bypass, req.URL); got != tc.want {
			t.Fatalf("bypass %q %q = %v", tc.bypass, tc.target, got)
		}
	}
	for _, env := range []map[string]string{{"NO_PROXY": "service.example"}, {"HTTPS_PROXY": "http://explicit.example:8080", "NO_PROXY": "*"}} {
		network := &tunnelNetwork{lookup: func(key string) (string, bool) { value, ok := env[key]; return value, ok }, read: func() (systemTunnelProxy, error) {
			return systemTunnelProxy{address: "http://system.example:8080"}, nil
		}, now: time.Now}
		req, _ := http.NewRequest(http.MethodGet, "https://service.example/api", nil)
		selection, err := network.selectProxy(req)
		if err != nil || selection.proxy != nil {
			t.Fatalf("NO_PROXY not honored: %+v %v", selection, err)
		}
	}
	for _, tc := range []struct{ target, noProxy string }{
		{"https://10.2.3.4/api", "10.0.0.0/8"},
		{"https://[2001:db8::1]/api", "2001:db8::/32"},
		{"https://[2001:db8::1]/api", "[2001:db8::1]:443"},
		{"https://service.example/api", "service.example:443"},
		{"https://service.example/api", "*.example"},
		{"https://service.example/api", "unrelated.example,*"},
	} {
		network := &tunnelNetwork{lookup: func(key string) (string, bool) { return tc.noProxy, key == "NO_PROXY" }, read: func() (systemTunnelProxy, error) {
			return systemTunnelProxy{address: "http://system.example:8080"}, nil
		}, now: time.Now}
		req, _ := http.NewRequest(http.MethodGet, tc.target, nil)
		if selection, err := network.selectProxy(req); err != nil || selection.proxy != nil {
			t.Fatalf("NO_PROXY IP/port/wildcard %q failed: %+v %v", tc.noProxy, selection, err)
		}
	}
}
