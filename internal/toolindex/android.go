package toolindex

import (
	"os"
	"path/filepath"
	"runtime"
)

const JADXVersion = "0.7.1"
const JADXEngineSHA256 = "6e5eacf500b64292bfb73c49797c1958f6ee44646e43e868039ae7feb573ff75"

type RuntimeArtifact struct {
	Role   string `json:"role"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

func JADXPaths(root string) (string, string) {
	return filepath.Join(root, "runtime", "android", "jadx-headless", JADXVersion, "jadx-headless-mcp-"+JADXVersion+"-all.jar"), filepath.Join(root, "patches", "jadx", "ReverseResearchJadxBridge.java")
}

// This is a composite interpreted profile, not an executable JAR. Discovery
// observes files/pins; only the original backend owner can start its worker.
func discoverJADX(root string, tools []Tool) Tool {
	jar, bridge := JADXPaths(root)
	t := Tool{Name: "jadx-headless", Path: bridge, Source: "project-interpreted", Version: JADXVersion, Architecture: "jvm-bytecode", Provider: "1013503897/jadx-headless-mcp", CanonicalSource: "https://github.com/1013503897/jadx-headless-mcp/tree/v0.7.1", License: "Apache-2.0 engine; MIT bridge", InstallScope: "project", TrustStatus: "engine-hash-pinned; bridge-identity-observed", RuntimeKind: "java-source-bridge", HealthStatus: "unavailable", Capabilities: []string{"android-static", "dex-decompile", "static-reference"}, Redistributable: true}
	if runtime.GOOS != "windows" && runtime.GOOS != "linux" {
		t.IdentityError = "native process-tree profile unsupported"
		return t
	}
	var java Tool
	for _, tool := range tools {
		if tool.Name == "java21" {
			java = tool
			break
		}
	}
	if !java.Available || java.HealthStatus != "identity-verified" {
		t.IdentityError = "existing Java21 profile unavailable"
		return t
	}
	t.InterpreterPath = java.Path
	compiler := "javac"
	if runtime.GOOS == "windows" {
		compiler += ".exe"
	}
	for _, entry := range []struct{ role, path string }{
		{"engine", jar}, {"bridge", bridge}, {"java", java.Path}, {"source-compiler", filepath.Join(filepath.Dir(java.Path), compiler)},
	} {
		info, err := os.Stat(entry.path)
		if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 128<<20 {
			t.IdentityError = "runtime component missing or outside profile: " + entry.role
			return t
		}
		id, err := executableIdentity(entry.path)
		if err != nil {
			t.IdentityError = "runtime identity unavailable: " + entry.role
			return t
		}
		if entry.role == "engine" && id.SHA256 != JADXEngineSHA256 {
			t.IdentityError = "engine differs from pinned profile"
			return t
		}
		t.RuntimeArtifacts = append(t.RuntimeArtifacts, RuntimeArtifact{entry.role, entry.path, id.SHA256, id.Size})
	}
	t.Available, t.HealthStatus = true, "runtime-profile-present"
	return t
}
