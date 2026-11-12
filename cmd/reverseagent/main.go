package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"

	"reverseresearch/internal/remoteagent"
	"reverseresearch/internal/targetidentity"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	flags := flag.NewFlagSet("ReverseResearch-Agent", flag.ContinueOnError)
	var manifestPath, privateKeyPath, tlsCert, tlsKey, clientCA, listen, stateRoot string
	flags.StringVar(&manifestPath, "manifest", "", "signed agent manifest JSON")
	flags.StringVar(&privateKeyPath, "private-key", "", "base64 Ed25519 private key file")
	flags.StringVar(&tlsCert, "tls-cert", "", "TLS server certificate")
	flags.StringVar(&tlsKey, "tls-key", "", "TLS server private key")
	flags.StringVar(&clientCA, "client-ca", "", "trusted client CA PEM")
	flags.StringVar(&listen, "listen", "127.0.0.1:9443", "listen address")
	flags.StringVar(&stateRoot, "state", "", "task-owned persistent agent state directory")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if manifestPath == "" || privateKeyPath == "" || tlsCert == "" || tlsKey == "" || clientCA == "" || stateRoot == "" {
		return errors.New("--manifest, --private-key, --tls-cert, --tls-key, --client-ca, and --state are required")
	}
	manifest, err := loadManifest(manifestPath)
	if err != nil {
		return err
	}
	privateKey, err := loadPrivateKey(privateKeyPath)
	if err != nil {
		return err
	}
	ledger, err := remoteagent.NewOperationLedger(filepath.Join(stateRoot, "operations"))
	if err != nil {
		return err
	}
	runtime, err := remoteagent.NewAgentRuntime(manifest, privateKey, ledger)
	if err != nil {
		return err
	}
	for name, handler := range remoteagent.BuiltinReadOnlyCapabilities() {
		if !contains(manifest.Capabilities, name) {
			continue
		}
		if err := runtime.RegisterCapability(name, handler); err != nil {
			return err
		}
	}
	tlsConfig, err := remoteagent.LoadServerTLSConfig(tlsCert, tlsKey, clientCA)
	if err != nil {
		return err
	}
	if err := runtime.BindTLSConfig(tlsConfig); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	fmt.Fprintf(os.Stderr, "ReverseResearch-Agent %s listening on %s with %d declared capability(ies); arbitrary remote shell is disabled.\n", manifest.AgentID, listen, len(manifest.Capabilities))
	return remoteagent.ServeMTLS(ctx, listen, runtime.Handler(), tlsConfig)
}

func loadManifest(path string) (remoteagent.Manifest, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return remoteagent.Manifest{}, err
	}
	var manifest remoteagent.Manifest
	if err := json.Unmarshal(body, &manifest); err != nil {
		return remoteagent.Manifest{}, err
	}
	if err := remoteagent.VerifyManifest(manifest); err != nil {
		return remoteagent.Manifest{}, err
	}
	return manifest, nil
}
func loadPrivateKey(path string) (ed25519.PrivateKey, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(body)))
	if err != nil {
		return nil, err
	}
	if len(decoded) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("Ed25519 private key length=%d want=%d", len(decoded), ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(decoded), nil
}
func artifactInspectCapability(_ context.Context, job remoteagent.JobRequest) (remoteagent.CapabilityResult, error) {
	identity, err := targetidentity.Inspect(job.Target)
	if err != nil {
		return remoteagent.CapabilityResult{}, err
	}
	body, err := json.Marshal(identity)
	if err != nil {
		return remoteagent.CapabilityResult{}, err
	}
	return remoteagent.CapabilityResult{State: "applied", Body: body}, nil
}

func artifactHashCapability(_ context.Context, job remoteagent.JobRequest) (remoteagent.CapabilityResult, error) {
	identity, err := targetidentity.Inspect(job.Target)
	if err != nil {
		return remoteagent.CapabilityResult{}, err
	}
	body, err := json.Marshal(map[string]any{
		"sha256": identity.SHA256,
		"size":   identity.Size,
	})
	if err != nil {
		return remoteagent.CapabilityResult{}, err
	}
	return remoteagent.CapabilityResult{State: "applied", Body: body}, nil
}
func contains(values []string, want string) bool {
	for _, v := range values {
		if strings.TrimSpace(v) == want {
			return true
		}
	}
	return false
}
