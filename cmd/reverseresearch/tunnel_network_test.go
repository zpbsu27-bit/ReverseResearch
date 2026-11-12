package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// This proxy forwards real CONNECT/TLS bytes, without receiving the control
// plane's Authorization header. Only synthetic test credentials are used.
func newTunnelTestProxy(t *testing.T, origin string, listener ...net.Listener) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	count := new(atomic.Int64)
	var mu sync.Mutex
	var connections []net.Conn
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || r.Header.Get("Authorization") != "" {
			t.Error("proxy received unexpected method or origin credential")
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		upstream, err := net.DialTimeout("tcp", origin, time.Second)
		if err != nil {
			http.Error(w, "origin unavailable", http.StatusBadGateway)
			return
		}
		client, buffer, err := w.(http.Hijacker).Hijack()
		if err != nil {
			_ = upstream.Close()
			return
		}
		mu.Lock()
		connections = append(connections, client, upstream)
		mu.Unlock()
		count.Add(1)
		_, _ = buffer.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
		_ = buffer.Flush()
		go func() { _, _ = io.Copy(upstream, buffer); _ = upstream.Close(); _ = client.Close() }()
		go func() { _, _ = io.Copy(client, upstream); _ = upstream.Close(); _ = client.Close() }()
	})
	proxy := httptest.NewUnstartedServer(handler)
	if len(listener) != 0 {
		_ = proxy.Listener.Close()
		proxy.Listener = listener[0]
	}
	proxy.Start()
	t.Cleanup(func() {
		proxy.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, connection := range connections {
			_ = connection.Close()
		}
	})
	return proxy, count
}

func TestTunnelNetworkLiveTLSRouteSwitchAndProxyFailure(t *testing.T) {
	var calls, directDials atomic.Int64
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer synthetic-origin-key" {
			t.Error("origin auth lost")
		}
		if r.URL.Path == "/auth-error" {
			w.WriteHeader(http.StatusUnauthorized)
		}
		if r.URL.Path == "/server-error" {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		_, _ = io.WriteString(w, "origin")
	}))
	origin.EnableHTTP2 = true
	origin.StartTLS()
	t.Cleanup(origin.Close)
	proxy1, count1 := newTunnelTestProxy(t, origin.Listener.Addr().String())
	proxy2, count2 := newTunnelTestProxy(t, origin.Listener.Addr().String())
	_, port, _ := net.SplitHostPort(origin.Listener.Addr().String())
	endpoint := "https://example.com:" + port
	settings := systemTunnelProxy{address: proxy1.URL}
	now := time.Now()
	var reports []string
	network := &tunnelNetwork{lookup: func(string) (string, bool) { return "", false }, read: func() (systemTunnelProxy, error) { return settings, nil }, now: func() time.Time { return now }, report: func(route string) { reports = append(reports, route) }}
	base := http.DefaultTransport.(*http.Transport).Clone()
	base.TLSClientConfig = origin.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	base.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address == "example.com:"+port {
			directDials.Add(1)
			address = origin.Listener.Addr().String()
		}
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, address)
	}
	adapted, err := network.adapt(base)
	if err != nil {
		t.Fatal(err)
	}
	transport := adapted.(*adaptiveTunnelTransport)
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	get := func(path string, want int) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, endpoint+path, nil)
		req.Header.Set("Authorization", "Bearer synthetic-origin-key")
		response, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if err != nil || response.StatusCode != want || string(body) != "origin" || response.ProtoMajor != 2 {
			t.Fatalf("TLS/H2 reply: %+v %q %v", response, body, err)
		}
	}
	get("/", http.StatusOK)
	if count1.Load() != 1 || directDials.Load() != 0 {
		t.Fatal("initial proxy route not used")
	}
	settings.address = "" // OS direct/TUN routing, while the process stays alive.
	get("/", http.StatusOK)
	if directDials.Load() != 1 {
		t.Fatalf("live switch to OS route failed: direct dials=%d, proxy connects=%d, route reports=%v", directDials.Load(), count1.Load(), reports)
	}
	settings.address = proxy2.URL
	get("/", http.StatusOK)
	if count2.Load() != 1 {
		t.Fatal("live switch to a new proxy failed")
	}
	get("/auth-error", http.StatusUnauthorized)
	get("/server-error", http.StatusServiceUnavailable)
	get("/", http.StatusOK)
	if directDials.Load() != 1 {
		t.Fatal("HTTP auth error incorrectly changed route")
	}

	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	settings.address = "http://" + closed.Addr().String()
	failedAddress := closed.Addr().String()
	_ = closed.Close()
	before := calls.Load()
	req, _ := http.NewRequest(http.MethodPost, endpoint+"/", strings.NewReader("one-submission"))
	if response, err := client.Do(req); err == nil {
		_ = response.Body.Close()
		t.Fatal("closed proxy unexpectedly succeeded")
	}
	if calls.Load() != before {
		t.Fatal("adapter replayed failed request to origin")
	}
	get("/", http.StatusOK) // The next caller/SDK attempt can use OS routing.
	if calls.Load() != before+1 {
		t.Fatal("OS fallback did not submit exactly once")
	}
	now = now.Add(tunnelProxyFailureWindow + time.Second)
	selection, err := network.selectProxy(req)
	if err != nil || selection.proxy == nil {
		t.Fatal("failed proxy remained permanently disabled")
	}
	recoveredListener, err := net.Listen("tcp", failedAddress)
	if err != nil {
		t.Fatal(err)
	}
	_, recoveredCount := newTunnelTestProxy(t, origin.Listener.Addr().String(), recoveredListener)
	get("/", http.StatusOK)
	if recoveredCount.Load() != 1 {
		t.Fatal("same proxy address did not recover after cooldown")
	}
	settings.address = proxy1.URL
	get("/", http.StatusOK)
	if len(reports) < 5 {
		t.Fatalf("route changes were not observable: %v", reports)
	}

	for _, expired := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		want := context.Canceled
		if expired {
			cancel()
			ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
			want = context.DeadlineExceeded
		} else {
			cancel()
		}
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"/", nil)
		if _, err := client.Do(request); !errors.Is(err, want) {
			t.Fatalf("cancel/deadline cause lost: %v", err)
		}
		cancel()
		selection, err = network.selectProxy(req)
		if err != nil || selection.proxy == nil || selection.proxy.String() != proxy1.URL {
			t.Fatal("caller cancellation/deadline penalized the current proxy")
		}
	}
}

func TestTunnelNetworkDoesNotBypassExplicitFailedProxyOrExposeCredentials(t *testing.T) {
	var dials atomic.Int64
	var reports []string
	network := &tunnelNetwork{
		lookup: func(key string) (string, bool) {
			return "http://private-user:private-password@proxy.example:3128", key == "HTTPS_PROXY"
		},
		read: func() (systemTunnelProxy, error) {
			t.Fatal("explicit route read system setting")
			return systemTunnelProxy{}, nil
		},
		now:    time.Now,
		report: func(route string) { reports = append(reports, route) },
	}
	base := http.DefaultTransport.(*http.Transport).Clone()
	base.DialContext = func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		return nil, fmt.Errorf("synthetic connection refused")
	}
	adapted, err := network.adapt(base)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: adapted}
	for i := 0; i < 2; i++ {
		req, _ := http.NewRequest(http.MethodPost, "https://origin.example/", strings.NewReader("synthetic"))
		if _, err := client.Do(req); err == nil {
			t.Fatal("failed explicit route accepted")
		}
		selection, err := network.selectProxy(req)
		if err != nil || selection.proxy == nil || selection.automatic {
			t.Fatal("explicit route silently bypassed")
		}
	}
	if dials.Load() != 2 {
		t.Fatalf("unexpected retry/replay count: %d", dials.Load())
	}
	if strings.Contains(strings.Join(reports, " "), "private-") {
		t.Fatal("proxy credential exposed in route log")
	}
}
