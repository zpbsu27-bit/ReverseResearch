package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	tunnelclient "github.com/openai/tunnel-client"
	"github.com/openai/tunnel-client/pkg/controlplane/wiretypes"
	"github.com/openai/tunnel-client/testsupport/mocktunnelservice"
)

func TestTunnelNetworkActualSDKKeepsMCPAcrossRouteChanges(t *testing.T) {
	const tunnelID = "tunnel_sdktestaaaaaaaaaaaaaaaaaaaaaaaaa"
	controlPlane := mocktunnelservice.NewMockTunnelService(
		mocktunnelservice.WithAPIKey("sdk-test-api-key"),
		mocktunnelservice.WithTunnelID(tunnelID),
		mocktunnelservice.WithPollWaitLimit(20*time.Millisecond),
		mocktunnelservice.WithInitializationPhaseCommandsWithoutSessionHeaders(),
	)
	controlPlane.Start(t)
	origin := httptest.NewUnstartedServer(httputil.NewSingleHostReverseProxy(controlPlane.BaseURL()))
	origin.EnableHTTP2 = true
	origin.StartTLS()
	t.Cleanup(origin.Close)
	proxy1, count1 := newTunnelTestProxy(t, origin.Listener.Addr().String())
	proxy2, count2 := newTunnelTestProxy(t, origin.Listener.Addr().String())
	_, port, _ := net.SplitHostPort(origin.Listener.Addr().String())
	var settings atomic.Value
	settings.Store(systemTunnelProxy{address: proxy1.URL})
	network := &tunnelNetwork{lookup: func(string) (string, bool) { return "", false }, read: func() (systemTunnelProxy, error) { return settings.Load().(systemTunnelProxy), nil }, now: time.Now}

	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	server := mcp.NewServer(&mcp.Implementation{Name: "network-contract-fixture", Version: "1"}, &mcp.ServerOptions{Capabilities: &mcp.ServerCapabilities{Tools: &mcp.ToolCapabilities{ListChanged: false}}})
	var toolCalls, adapters, directDials atomic.Int64
	mcp.AddTool(server, &mcp.Tool{Name: "route_probe", Description: "synthetic route contract"}, func(_ context.Context, _ *mcp.CallToolRequest, args struct {
		Value string `json:"value"`
	}) (*mcp.CallToolResult, map[string]string, error) {
		toolCalls.Add(1)
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: args.Value}}}, map[string]string{"value": args.Value}, nil
	})
	serverCtx, cancelServer := context.WithCancel(context.Background())
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Run(serverCtx, serverTransport) }()
	t.Cleanup(func() {
		cancelServer()
		select {
		case <-serverDone:
		case <-time.After(3 * time.Second):
			t.Error("fixture MCP server did not stop")
		}
	})
	client, err := tunnelclient.New(tunnelclient.Config{
		TunnelID: tunnelID, APIKey: "sdk-test-api-key", ControlPlaneBaseURL: "https://example.com:" + port,
		PollTimeout: 100 * time.Millisecond, PollDeadlineGuardrail: time.Second, LogWriter: io.Discard,
		ControlPlaneHTTPTransportAdapter: func(base http.RoundTripper) (http.RoundTripper, error) {
			adapters.Add(1)
			transport := base.(*http.Transport).Clone()
			transport.TLSClientConfig = origin.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
			transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
				if address == "example.com:"+port {
					directDials.Add(1)
					address = origin.Listener.Addr().String()
				}
				return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, address)
			}
			adapted, err := network.adapt(transport)
			if closer, ok := adapted.(interface{ CloseIdleConnections() }); ok {
				t.Cleanup(closer.CloseIdleConnections)
			}
			return adapted, err
		},
	}, clientTransport)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := client.Stop(ctx); err != nil {
			t.Errorf("SDK stop: %v", err)
		}
		if err := controlPlane.WaitForNoActivePollRequests(ctx, nil); err != nil {
			t.Errorf("SDK poll cleanup: %v", err)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if err := client.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := client.WaitUntilReady(ctx); err != nil {
		t.Fatal(err)
	}
	for i, route := range []systemTunnelProxy{{address: proxy1.URL}, {}, {address: proxy2.URL}} {
		settings.Store(route)
		value := fmt.Sprintf("route-%d", i)
		command := mocktunnelservice.CommandResponse{
			Command: mocktunnelservice.NewCommand(value, json.RawMessage(fmt.Sprintf(`{"jsonrpc":"2.0","id":"%s","method":"tools/call","params":{"name":"route_probe","arguments":{"value":"%s"}}}`, value, value)), nil),
			ExpectedResponses: []mocktunnelservice.ExpectedResponse{{RequestID: value, Assert: func(tb testing.TB, response mocktunnelservice.ReceivedResponse) {
				var payload struct {
					Result struct {
						StructuredContent map[string]string `json:"structuredContent"`
					} `json:"result"`
				}
				if err := json.Unmarshal(response.JSONResponse, &payload); err != nil || response.ResponseCode != http.StatusOK || response.ResponseType != string(wiretypes.ResponsePayloadJSONRPC) || payload.Result.StructuredContent["value"] != value {
					tb.Errorf("MCP response lost or misattributed: %s %v", response.JSONResponse, err)
				}
			}}},
		}
		mocktunnelservice.WithCommandResponses(command)(controlPlane)
		if err := controlPlane.WaitForResponses(ctx, i+3); err != nil {
			t.Fatal(err)
		}
	}
	if toolCalls.Load() != 3 || adapters.Load() != 2 || count1.Load() == 0 || count2.Load() == 0 || directDials.Load() == 0 {
		t.Fatalf("SDK route/ownership evidence: calls=%d adapters=%d proxy1=%d proxy2=%d direct=%d", toolCalls.Load(), adapters.Load(), count1.Load(), count2.Load(), directDials.Load())
	}
	for _, request := range controlPlane.ReceivedHTTPRequests() {
		if strings.HasPrefix(request.Path, "/v1/tunnel") && request.Headers.Get("Authorization") != "Bearer sdk-test-api-key" {
			t.Error("SDK origin authentication was not preserved")
		}
	}
}

func TestTunnelNetworkSDKRejectsInvalidAdapter(t *testing.T) {
	_, clientTransport := mcp.NewInMemoryTransports()
	for _, adapter := range []func(http.RoundTripper) (http.RoundTripper, error){
		func(http.RoundTripper) (http.RoundTripper, error) {
			return nil, fmt.Errorf("synthetic adapter failure")
		},
		func(http.RoundTripper) (http.RoundTripper, error) { return nil, nil },
	} {
		client, err := tunnelclient.New(tunnelclient.Config{TunnelID: "tunnel_sdktestaaaaaaaaaaaaaaaaaaaaaaaaa", APIKey: "sdk-test-api-key", LogWriter: io.Discard, ControlPlaneHTTPTransportAdapter: adapter}, clientTransport)
		if err == nil || client != nil {
			t.Fatal("invalid adapter constructed a runnable SDK client")
		}
	}
}

func TestTunnelNetworkSDKPreservesExplicitUnixSocket(t *testing.T) {
	t.Setenv("TUNNEL_INTEGRATION_TUNNEL_SERVICE_SOCKET_PATH", "synthetic-explicit-socket")
	_, clientTransport := mcp.NewInMemoryTransports()
	var called bool
	client, err := tunnelclient.New(tunnelclient.Config{
		TunnelID: "tunnel_sdktestaaaaaaaaaaaaaaaaaaaaaaaaa", APIKey: "sdk-test-api-key", LogWriter: io.Discard,
		ControlPlaneHTTPTransportAdapter: func(http.RoundTripper) (http.RoundTripper, error) {
			called = true
			return nil, fmt.Errorf("TCP adapter should not replace explicit Unix socket")
		},
	}, clientTransport)
	if err != nil || called {
		t.Fatalf("explicit socket authority changed: called=%v err=%v", called, err)
	}
	if err := client.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestTunnelNetworkSDKAdapterDoesNotChangeSerializableConfig(t *testing.T) {
	encoded, err := json.Marshal(tunnelclient.Config{ControlPlaneHTTPTransportAdapter: func(base http.RoundTripper) (http.RoundTripper, error) { return base, nil }})
	if err != nil || strings.Contains(string(encoded), "HTTPTransportAdapter") {
		t.Fatalf("adapter changed serializable config contract: %s %v", encoded, err)
	}
}
