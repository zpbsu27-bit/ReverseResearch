package backend

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// The starter has no session generation to retire when startup cleanup fails.
// Preserve this failure for the caller instead of reporting a later empty Close
// as proof that its private engine workspace can be removed.
var ErrJADXCleanupUnverified = errors.New("JADX startup process cleanup unverified")

// NewJADX uses the existing Lazy/session-generation and prepared process-tree
// owner. The caller supplies immutable private engine/bridge copies and owns
// the target-selection workflow; startup never loads an APK.
func NewJADX(java, jar, bridge, work string) *Lazy {
	return NewLazy("jadx", func(ctx context.Context) (*mcp.ClientSession, func() error, error) {
		for _, path := range []string{java, jar, bridge} {
			if !filepath.IsAbs(path) {
				return nil, nil, errors.New("JADX requires exact absolute runtime paths")
			}
			if info, err := os.Stat(path); err != nil || !info.Mode().IsRegular() {
				return nil, nil, fmt.Errorf("JADX runtime missing: %s", path)
			}
		}
		for _, name := range []string{"home", "tmp", "evidence"} {
			if err := os.MkdirAll(filepath.Join(work, name), 0700); err != nil {
				return nil, nil, err
			}
		}
		cmd := exec.Command(java, "-Xmx1024m", "-Duser.home="+filepath.Join(work, "home"), "-Djava.io.tmpdir="+filepath.Join(work, "tmp"), "-cp", jar, bridge)
		cmd.Dir = work
		log, err := openLogAt(filepath.Join(work, "evidence"), "jadx.log")
		if err != nil {
			return nil, nil, err
		}
		cmd.Stderr = log
		scope, err := prepareBackendProcess(cmd)
		if err != nil {
			return nil, nil, errors.Join(err, log.Close())
		}
		client := mcp.NewClient(&mcp.Implementation{Name: "reverseresearch-jadx-client", Version: "1"}, nil)
		session, err := client.Connect(ctx, &mcp.CommandTransport{Command: cmd, TerminateDuration: 5 * time.Second}, nil)
		if err != nil {
			cleanupErr := scope.abort(log, cmd.Process != nil)
			if cleanupErr != nil && cmd.Process != nil {
				cleanupErr = errors.Join(ErrJADXCleanupUnverified, cleanupErr)
			}
			return nil, nil, errors.Join(fmt.Errorf("connect JADX metadata worker: %w", err), cleanupErr)
		}
		cleanup, err := scope.claim(log, false)
		if err != nil {
			return nil, nil, errors.Join(ErrJADXCleanupUnverified, err, session.Close())
		}
		return session, cleanup, nil
	})
}
