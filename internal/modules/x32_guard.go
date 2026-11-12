package modules

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"reverseresearch/internal/processcontrol"
	"reverseresearch/internal/recordio"
)

const (
	X32GuardArgument           = "_rr_guard"
	maxX32MutationReceiptBytes = 1 << 20
	maxX32CachedResultBytes    = 512 << 10
	maxX32ReceiptShardFiles    = 256
	maxX32ReceiptShardBytes    = int64(32 << 20)
	maxX32SessionBindingBytes  = int64(64 << 10)
)

var (
	ErrX32GuardRequired    = errors.New("x32dbg mutation guard is required")
	ErrX32OutcomeUncertain = errors.New("x32dbg mutation outcome is uncertain and will not be replayed")
	ErrX32ToolBlocked      = errors.New("x32dbg tool is blocked by the guarded mutation boundary")
	ErrX32SessionUnbound   = errors.New("x32dbg mutation requires a bound AttachProcess session")
	ErrX32SessionConflict  = errors.New("x32dbg session is bound to a different controlled process")
)

type X32Policy string

const (
	X32ReadOnly X32Policy = "read_only"
	X32Guarded  X32Policy = "guarded"
	X32Blocked  X32Policy = "blocked"
)

var x32ReadOnlyTools = map[string]struct{}{
	"Disassemble": {}, "DisassembleFunction": {}, "Echo": {}, "EvalExpression": {},
	"FindPattern": {}, "FollowPointer": {}, "GetAllRegisters": {}, "GetArguments": {},
	"GetCallStack": {}, "GetCurrentAddress": {}, "GetDebugState": {}, "GetDumpableRegions": {},
	"GetEventLog": {}, "GetExports": {}, "GetFunctions": {}, "GetImports": {}, "GetMemoryMap": {},
	"GetPEB": {}, "GetPatches": {}, "GetReferences": {}, "GetSEHChain": {}, "GetStrings": {},
	"GetThreads": {}, "ListBookmarks": {}, "ListBreakpoints": {}, "ListCommandsByCategory": {},
	"ListModules": {}, "ListSymbols": {}, "ReadMemory": {}, "SearchForStrings": {},
	"SearchSymbols": {}, "WaitForEvent": {}, "WaitForPause": {}, "WatchExpressions": {},
}

var x32BlockedTools = map[string]struct{}{
	"ExecuteDebuggerCommand": {},
	"LoadBinary":             {},
	"RestartDebug":           {},
}

func X32ToolPolicy(tool string) X32Policy {
	if _, ok := x32BlockedTools[tool]; ok {
		return X32Blocked
	}
	if _, ok := x32ReadOnlyTools[tool]; ok {
		return X32ReadOnly
	}
	return X32Guarded
}

func X32GuardJSONSchema() map[string]any {
	return map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"properties": map[string]any{
			"pid":          map[string]any{"type": "integer", "minimum": 1},
			"process_key":  map[string]any{"type": "string", "minLength": 64, "maxLength": 64},
			"owner":        map[string]any{"type": "string", "minLength": 1, "maxLength": 160},
			"lease_id":     map[string]any{"type": "string", "minLength": 1, "maxLength": 128},
			"operation_id": map[string]any{"type": "string", "minLength": 1, "maxLength": 160},
		},
		"required": []string{"pid", "process_key", "owner", "lease_id", "operation_id"},
	}
}

type x32GuardMetadata struct {
	PID         uint32 `json:"pid"`
	ProcessKey  string `json:"process_key"`
	Owner       string `json:"owner"`
	LeaseID     string `json:"lease_id"`
	OperationID string `json:"operation_id"`
}

type x32SessionBinding struct {
	RuntimeID   string `json:"runtime_id"`
	PID         uint32 `json:"pid"`
	ProcessKey  string `json:"process_key"`
	Owner       string `json:"owner"`
	LeaseID     string `json:"lease_id"`
	AttachOpID  string `json:"attach_operation_id"`
	AttachedUTC string `json:"attached_utc"`
}

type x32CachedResult struct {
	Structured any      `json:"structured,omitempty"`
	Text       []string `json:"text,omitempty"`
}

type x32MutationReceipt struct {
	OperationID   string          `json:"operation_id"`
	RequestDigest string          `json:"request_digest"`
	Tool          string          `json:"tool"`
	PID           uint32          `json:"pid"`
	ProcessKey    string          `json:"process_key"`
	Owner         string          `json:"owner"`
	LeaseID       string          `json:"lease_id"`
	Status        string          `json:"status"`
	Result        x32CachedResult `json:"result,omitempty"`
	CreatedUTC    string          `json:"created_utc"`
	CompletedUTC  string          `json:"completed_utc,omitempty"`
}

type x32LeaseReader interface {
	Get(uint32) (processcontrol.Lease, error)
}

type x32MutationGuard struct {
	root      string
	leases    x32LeaseReader
	runtimeID string
}

var x32OperationIDPattern = regexp.MustCompile("^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")

func newX32MutationGuard(root string) (*x32MutationGuard, error) {
	absolute, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	leases, err := processcontrol.NewLeaseStore(filepath.Join(absolute, "state", "process-control"))
	if err != nil {
		return nil, err
	}
	return newX32MutationGuardWithLeases(absolute, leases)
}

func newX32MutationGuardWithLeases(root string, leases x32LeaseReader) (*x32MutationGuard, error) {
	if leases == nil {
		return nil, errors.New("x32dbg mutation guard requires a process lease reader")
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(absolute, "state", "x32dbg-guard", "operations")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	runtimeID, err := newX32RuntimeID()
	if err != nil {
		return nil, err
	}
	return &x32MutationGuard{root: absolute, leases: leases, runtimeID: runtimeID}, nil
}

func (g *x32MutationGuard) Call(
	ctx context.Context,
	tool string,
	arguments any,
	execute func(context.Context, any) (*mcp.CallToolResult, error),
) (result *mcp.CallToolResult, err error) {
	if execute == nil {
		return nil, errors.New("x32dbg executor is required")
	}
	switch X32ToolPolicy(tool) {
	case X32ReadOnly:
		return execute(ctx, arguments)
	case X32Blocked:
		return nil, fmt.Errorf("%w: %s; use typed guarded AttachProcess/session tools instead", ErrX32ToolBlocked, tool)
	}

	cleanArguments, meta, err := extractX32Guard(arguments)
	if err != nil {
		return nil, err
	}
	if err := validateX32Guard(meta); err != nil {
		return nil, err
	}
	digest, err := x32RequestDigest(tool, cleanArguments, meta)
	if err != nil {
		return nil, err
	}

	lockPath := g.operationLockPath(meta.OperationID)
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o700); err != nil {
		return nil, fmt.Errorf("create x32dbg operation lock shard: %w", err)
	}
	opRelease, err := recordio.AcquireContext(ctx, lockPath, 10*time.Second)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, opRelease()) }()

	if receipt, err := g.loadReceipt(meta.OperationID); err == nil {
		if receipt.RequestDigest != digest || receipt.Tool != tool ||
			receipt.PID != meta.PID || receipt.ProcessKey != meta.ProcessKey ||
			receipt.Owner != meta.Owner || receipt.LeaseID != meta.LeaseID {
			return nil, errors.New("x32dbg operation_id was already used for a different guarded request")
		}
		switch receipt.Status {
		case "completed":
			if tool == "AttachProcess" {
				if err := g.validateBoundSession(meta); err != nil {
					return nil, fmt.Errorf("completed AttachProcess belongs to a different or closed runtime; use a new operation_id to re-establish the session: %w", err)
				}
			}
			return restoreX32Result(receipt.Result), nil
		case "prepared":
			return nil, fmt.Errorf("%w: operation_id=%s", ErrX32OutcomeUncertain, meta.OperationID)
		default:
			return nil, fmt.Errorf("invalid x32dbg mutation receipt status %q", receipt.Status)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	sessionRelease, err := recordio.AcquireContext(ctx, g.sessionLockPath(), 10*time.Second)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, sessionRelease()) }()

	if err := g.validateLease(meta); err != nil {
		return nil, err
	}
	if tool == "AttachProcess" {
		if err := validateAttachPID(cleanArguments, meta.PID); err != nil {
			return nil, err
		}
		if err := g.allowAttach(meta); err != nil {
			return nil, err
		}
	} else {
		if err := g.validateBoundSession(meta); err != nil {
			return nil, err
		}
	}

	// Reserve enough cold-receipt capacity before the debugger effect executes.
	// The session lock held above serializes guarded effects across processes, so
	// this reservation cannot be consumed by another x32 mutation before commit.
	if err := recordio.CheckShardQuotaContext(
		ctx,
		g.operationArchivePath(meta.OperationID),
		maxX32MutationReceiptBytes,
		maxX32ReceiptShardFiles,
		maxX32ReceiptShardBytes,
	); err != nil {
		return nil, fmt.Errorf("reserve x32dbg durable receipt capacity: %w", err)
	}

	receipt := x32MutationReceipt{
		OperationID: meta.OperationID, RequestDigest: digest, Tool: tool,
		PID: meta.PID, ProcessKey: meta.ProcessKey, Owner: meta.Owner, LeaseID: meta.LeaseID,
		Status: "prepared", CreatedUTC: time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := g.saveReceiptContext(ctx, receipt); err != nil {
		return nil, err
	}

	result, callErr := execute(ctx, cleanArguments)
	if callErr != nil {
		return nil, callErr
	}
	if result == nil {
		return nil, errors.New("x32dbg mutation returned no result; outcome remains uncertain")
	}
	if result.IsError {
		return result, nil
	}

	if tool == "AttachProcess" {
		if err := g.saveBinding(x32SessionBinding{
			RuntimeID: g.runtimeID,
			PID:       meta.PID, ProcessKey: meta.ProcessKey, Owner: meta.Owner, LeaseID: meta.LeaseID,
			AttachOpID: meta.OperationID, AttachedUTC: time.Now().UTC().Format(time.RFC3339Nano),
		}); err != nil {
			return nil, err
		}
	}
	if tool == "StopDebug" {
		if err := g.clearBinding(meta); err != nil {
			return nil, err
		}
	}

	cached, err := cacheX32Result(result)
	if err != nil {
		return nil, err
	}
	receipt.Status = "completed"
	receipt.Result = cached
	receipt.CompletedUTC = time.Now().UTC().Format(time.RFC3339Nano)
	if err := g.saveReceipt(receipt); err != nil {
		return nil, err
	}
	return result, nil
}

func extractX32Guard(arguments any) (map[string]any, x32GuardMetadata, error) {
	input, ok := arguments.(map[string]any)
	if !ok {
		return nil, x32GuardMetadata{}, fmt.Errorf("%w: arguments must be a JSON object", ErrX32GuardRequired)
	}
	clean := make(map[string]any, len(input))
	for key, value := range input {
		clean[key] = value
	}
	raw, ok := clean[X32GuardArgument]
	if !ok {
		return nil, x32GuardMetadata{}, fmt.Errorf("%w: missing %s", ErrX32GuardRequired, X32GuardArgument)
	}
	delete(clean, X32GuardArgument)
	body, err := json.Marshal(raw)
	if err != nil {
		return nil, x32GuardMetadata{}, fmt.Errorf("encode x32dbg guard: %w", err)
	}
	var meta x32GuardMetadata
	if err := json.Unmarshal(body, &meta); err != nil {
		return nil, x32GuardMetadata{}, fmt.Errorf("decode x32dbg guard: %w", err)
	}
	meta.ProcessKey = strings.TrimSpace(meta.ProcessKey)
	meta.Owner = strings.TrimSpace(meta.Owner)
	meta.LeaseID = strings.TrimSpace(meta.LeaseID)
	meta.OperationID = strings.TrimSpace(meta.OperationID)
	return clean, meta, nil
}

func validateX32Guard(meta x32GuardMetadata) error {
	if meta.PID == 0 || len(meta.ProcessKey) != 64 || meta.Owner == "" || meta.LeaseID == "" {
		return fmt.Errorf("%w: pid, 64-char process_key, owner, and lease_id are required", ErrX32GuardRequired)
	}
	if !x32OperationIDPattern.MatchString(meta.OperationID) {
		return fmt.Errorf("%w: operation_id must match [A-Za-z0-9][A-Za-z0-9._:-]{0,159}", ErrX32GuardRequired)
	}
	return nil
}

func (g *x32MutationGuard) validateLease(meta x32GuardMetadata) error {
	_, err := g.currentLease(meta)
	return err
}

func (g *x32MutationGuard) currentLease(meta x32GuardMetadata) (processcontrol.Lease, error) {
	lease, err := g.leases.Get(meta.PID)
	if err != nil {
		return processcontrol.Lease{}, fmt.Errorf("validate x32dbg process lease: %w", err)
	}
	if lease.ProcessKey != meta.ProcessKey || lease.Owner != meta.Owner || lease.LeaseID != meta.LeaseID {
		return processcontrol.Lease{}, fmt.Errorf(
			"validate x32dbg process lease: expected key=%s owner=%q lease=%s; current key=%s owner=%q lease=%s",
			meta.ProcessKey, meta.Owner, meta.LeaseID, lease.ProcessKey, lease.Owner, lease.LeaseID,
		)
	}
	return lease, nil
}

func (g *x32MutationGuard) targetBits(meta x32GuardMetadata) (int, error) {
	lease, err := g.currentLease(meta)
	if err != nil {
		return 0, err
	}
	return xdbgBitsFromLease(lease)
}

func validateAttachPID(arguments map[string]any, guardedPID uint32) error {
	body, err := json.Marshal(arguments)
	if err != nil {
		return err
	}
	var request struct {
		PID uint32 `json:"pid"`
	}
	if err := json.Unmarshal(body, &request); err != nil {
		return fmt.Errorf("decode AttachProcess arguments: %w", err)
	}
	if request.PID == 0 || request.PID != guardedPID {
		return fmt.Errorf("AttachProcess pid=%d does not match guarded pid=%d", request.PID, guardedPID)
	}
	return nil
}

func (g *x32MutationGuard) allowAttach(meta x32GuardMetadata) error {
	binding, err := g.loadBinding()
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if binding.RuntimeID == g.runtimeID && binding.PID == meta.PID && binding.ProcessKey == meta.ProcessKey &&
		binding.Owner == meta.Owner && binding.LeaseID == meta.LeaseID {
		return nil
	}
	current, leaseErr := g.leases.Get(binding.PID)
	if leaseErr != nil || current.ProcessKey != binding.ProcessKey ||
		current.Owner != binding.Owner || current.LeaseID != binding.LeaseID {
		if removeErr := os.Remove(g.bindingPath()); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return removeErr
		}
		return nil
	}
	return fmt.Errorf(
		"%w: pid=%d key=%s owner=%q lease=%s",
		ErrX32SessionConflict, binding.PID, binding.ProcessKey, binding.Owner, binding.LeaseID,
	)
}

func (g *x32MutationGuard) validateBoundSession(meta x32GuardMetadata) error {
	binding, err := g.loadBinding()
	if errors.Is(err, os.ErrNotExist) {
		return ErrX32SessionUnbound
	}
	if err != nil {
		return err
	}
	if binding.RuntimeID != g.runtimeID || binding.PID != meta.PID || binding.ProcessKey != meta.ProcessKey ||
		binding.Owner != meta.Owner || binding.LeaseID != meta.LeaseID {
		return fmt.Errorf(
			"%w: runtime=%s bound pid=%d key=%s owner=%q lease=%s",
			ErrX32SessionConflict, binding.RuntimeID, binding.PID, binding.ProcessKey, binding.Owner, binding.LeaseID,
		)
	}
	return nil
}

func x32RequestDigest(tool string, arguments map[string]any, meta x32GuardMetadata) (string, error) {
	payload := struct {
		Tool       string         `json:"tool"`
		Arguments  map[string]any `json:"arguments"`
		PID        uint32         `json:"pid"`
		ProcessKey string         `json:"process_key"`
		Owner      string         `json:"owner"`
		LeaseID    string         `json:"lease_id"`
	}{
		Tool: tool, Arguments: arguments, PID: meta.PID,
		ProcessKey: meta.ProcessKey, Owner: meta.Owner, LeaseID: meta.LeaseID,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:]), nil
}

func cacheX32Result(result *mcp.CallToolResult) (x32CachedResult, error) {
	cached := x32CachedResult{Structured: result.StructuredContent}
	for _, item := range result.Content {
		if text, ok := item.(*mcp.TextContent); ok {
			cached.Text = append(cached.Text, text.Text)
		}
	}
	body, err := json.Marshal(cached)
	if err != nil {
		return x32CachedResult{}, fmt.Errorf("cache x32dbg mutation result: %w", err)
	}
	if len(body) > maxX32CachedResultBytes {
		sum := sha256.Sum256(body)
		return x32CachedResult{Text: []string{fmt.Sprintf(
			"durable replay result omitted: sha256=%s bytes=%d",
			hex.EncodeToString(sum[:]), len(body),
		)}}, nil
	}
	return cached, nil
}

func restoreX32Result(cached x32CachedResult) *mcp.CallToolResult {
	result := &mcp.CallToolResult{StructuredContent: cached.Structured}
	for _, value := range cached.Text {
		result.Content = append(result.Content, &mcp.TextContent{Text: value})
	}
	return result
}

func x32OperationKey(operationID string) string {
	sum := sha256.Sum256([]byte(operationID))
	return hex.EncodeToString(sum[:])
}

func (g *x32MutationGuard) operationPath(operationID string) string {
	key := x32OperationKey(operationID)
	return filepath.Join(g.root, "state", "x32dbg-guard", "operations", "prepared", key[:2], key+".json")
}

func (g *x32MutationGuard) legacyOperationPath(operationID string) string {
	key := x32OperationKey(operationID)
	return filepath.Join(g.root, "state", "x32dbg-guard", "operations", key+".json")
}

func (g *x32MutationGuard) operationArchivePath(operationID string) string {
	key := x32OperationKey(operationID)
	return filepath.Join(g.root, "state", "x32dbg-guard", "operations", "archive", key[:2], key+".json")
}

func (g *x32MutationGuard) operationLockPath(operationID string) string {
	key := x32OperationKey(operationID)
	return filepath.Join(g.root, "state", "x32dbg-guard", "operations", "locks", key[:2], key+".lock")
}

func (g *x32MutationGuard) sessionLockPath() string {
	return filepath.Join(g.root, "state", "x32dbg-guard", ".session.lock")
}

func (g *x32MutationGuard) bindingPath() string {
	return filepath.Join(g.root, "state", "x32dbg-guard", "session.json")
}

func (g *x32MutationGuard) loadReceipt(operationID string) (x32MutationReceipt, error) {
	if receipt, err := g.readReceiptPath(g.operationArchivePath(operationID), operationID); err == nil {
		return receipt, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return x32MutationReceipt{}, err
	}
	receipt, err := g.readReceiptPath(g.operationPath(operationID), operationID)
	if err == nil {
		return receipt, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return x32MutationReceipt{}, err
	}

	receipt, err = g.readReceiptPath(g.legacyOperationPath(operationID), operationID)
	if err != nil {
		return x32MutationReceipt{}, err
	}
	if receipt.Status == "completed" {
		// Best-effort one-way migration for pre-sharding completed receipts. The
		// legacy receipt remains authoritative if the bounded archive is full.
		if archiveErr := g.writeCompletedReceiptArchive(receipt); archiveErr == nil {
			_ = os.Remove(g.legacyOperationPath(operationID))
		}
	}
	return receipt, nil
}

func (g *x32MutationGuard) readReceiptPath(path, operationID string) (x32MutationReceipt, error) {
	body, err := recordio.ReadFileLimit(path, maxX32MutationReceiptBytes)
	if err != nil {
		return x32MutationReceipt{}, err
	}
	var receipt x32MutationReceipt
	if err := json.Unmarshal(body, &receipt); err != nil {
		return x32MutationReceipt{}, fmt.Errorf("decode x32dbg mutation receipt: %w", err)
	}
	if receipt.OperationID != operationID {
		return x32MutationReceipt{}, errors.New("x32dbg mutation receipt identity mismatch")
	}
	return receipt, nil
}

func (g *x32MutationGuard) saveReceipt(receipt x32MutationReceipt) error {
	return g.saveReceiptContext(context.Background(), receipt)
}

func (g *x32MutationGuard) saveReceiptContext(ctx context.Context, receipt x32MutationReceipt) error {
	body, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	if len(body) > maxX32MutationReceiptBytes {
		return fmt.Errorf("x32dbg mutation receipt exceeds durable size limit: %d > %d", len(body), maxX32MutationReceiptBytes)
	}
	if receipt.Status != "completed" {
		return recordio.WriteFileShardQuotaContext(
			ctx, g.operationPath(receipt.OperationID), body, 0o600,
			maxX32ReceiptShardFiles, maxX32ReceiptShardBytes,
		)
	}
	if err := g.writeCompletedReceiptArchiveBytes(receipt.OperationID, body); err != nil {
		return err
	}
	// The archive is authoritative once published. Failure to delete the old
	// prepared/hot receipt must not turn a completed debugger mutation into an
	// uncertain result; loadReceipt always checks the archive first.
	_ = os.Remove(g.operationPath(receipt.OperationID))
	_ = os.Remove(g.legacyOperationPath(receipt.OperationID))
	return nil
}

func (g *x32MutationGuard) writeCompletedReceiptArchive(receipt x32MutationReceipt) error {
	body, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	return g.writeCompletedReceiptArchiveBytes(receipt.OperationID, body)
}

func (g *x32MutationGuard) writeCompletedReceiptArchiveBytes(operationID string, body []byte) error {
	path := g.operationArchivePath(operationID)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create x32dbg receipt archive shard: %w", err)
	}
	if existing, err := recordio.ReadFileLimit(path, maxX32MutationReceiptBytes); err == nil {
		if bytes.Equal(existing, body) {
			return nil
		}
		return errors.New("completed x32dbg mutation receipt archive changed")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if len(body) > maxX32MutationReceiptBytes {
		return fmt.Errorf("x32dbg completed receipt exceeds durable size limit: %d > %d", len(body), maxX32MutationReceiptBytes)
	}
	return recordio.WriteFileShardQuota(path, body, 0o600, maxX32ReceiptShardFiles, maxX32ReceiptShardBytes)
}

func (g *x32MutationGuard) loadBinding() (x32SessionBinding, error) {
	body, err := recordio.ReadFileLimit(g.bindingPath(), maxX32SessionBindingBytes)
	if err != nil {
		return x32SessionBinding{}, err
	}
	var binding x32SessionBinding
	if err := json.Unmarshal(body, &binding); err != nil {
		return x32SessionBinding{}, fmt.Errorf("decode x32dbg session binding: %w", err)
	}
	if binding.RuntimeID == "" || binding.PID == 0 || binding.ProcessKey == "" || binding.Owner == "" || binding.LeaseID == "" {
		return x32SessionBinding{}, errors.New("invalid x32dbg session binding")
	}
	return binding, nil
}

func (g *x32MutationGuard) saveBinding(binding x32SessionBinding) error {
	body, err := json.MarshalIndent(binding, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	if int64(len(body)) > maxX32SessionBindingBytes {
		return fmt.Errorf("x32dbg session binding exceeds durable size limit: %d > %d", len(body), maxX32SessionBindingBytes)
	}
	return recordio.WriteFile(g.bindingPath(), body, 0o600)
}

func (g *x32MutationGuard) Close() (err error) {
	release, err := recordio.Acquire(g.sessionLockPath(), 10*time.Second)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, release()) }()

	binding, err := g.loadBinding()
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if binding.RuntimeID != g.runtimeID {
		return nil
	}
	if err := os.Remove(g.bindingPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func newX32RuntimeID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate x32dbg runtime id: %w", err)
	}
	return "runtime_" + hex.EncodeToString(raw[:]), nil
}

func (g *x32MutationGuard) clearBinding(meta x32GuardMetadata) error {
	binding, err := g.loadBinding()
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if binding.RuntimeID != g.runtimeID || binding.PID != meta.PID || binding.ProcessKey != meta.ProcessKey ||
		binding.Owner != meta.Owner || binding.LeaseID != meta.LeaseID {
		return fmt.Errorf("%w while clearing session", ErrX32SessionConflict)
	}
	if err := os.Remove(g.bindingPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
