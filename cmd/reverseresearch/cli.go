package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"reverseresearch/internal/buildversion"
	"reverseresearch/internal/casebook"
	"reverseresearch/internal/compatibility"
	"reverseresearch/internal/contractaudit"
	researchcore "reverseresearch/internal/core"
	"reverseresearch/internal/die"
	"reverseresearch/internal/hookplan"
	"reverseresearch/internal/knowledge"
	"reverseresearch/internal/memscan"
	"reverseresearch/internal/modules"
	"reverseresearch/internal/patchplan"
	"reverseresearch/internal/pointermap"
	"reverseresearch/internal/sandbox"
	"reverseresearch/internal/statecompat"
)

func runCLI(ctx context.Context, root string, args []string, stdout, stderr io.Writer) (err error) {
	if len(args) == 0 {
		printUsage(stdout)
		return nil
	}
	if args[0] == "version" || args[0] == "--version" {
		if len(args) != 1 {
			return errors.New("version does not accept additional arguments")
		}
		return writeJSON(stdout, map[string]any{
			"version": buildversion.Version, "go_version": runtime.Version(),
			"goos": runtime.GOOS, "goarch": runtime.GOARCH,
		})
	}
	if args[0] == "state-layout" {
		return runStateLayoutCLI(root, args[1:], stdout)
	}
	if args[0] != "help" && args[0] != "-h" && args[0] != "--help" {
		if _, layoutErr := statecompat.Ensure(root); layoutErr != nil {
			return fmt.Errorf("state layout compatibility: %w", layoutErr)
		}
	}

	switch args[0] {
	case "help", "-h", "--help":
		printUsage(stdout)
		return nil
	case "serve":
		return runServe(ctx, root, args[1:])
	case "target":
		service, err := researchcore.New(root)
		if err != nil {
			return err
		}
		return runTargetCLI(service, args[1:], stdout)
	case "app":
		service, err := researchcore.New(root)
		if err != nil {
			return err
		}
		return runApplicationCLI(ctx, service, args[1:], stdout, stderr)
	case "die":
		service, err := researchcore.New(root)
		if err != nil {
			return err
		}
		return runDIECLI(ctx, service, args[1:], stdout, stderr)
	case "malware":
		service, err := researchcore.New(root)
		if err != nil {
			return err
		}
		return runMalwareCLI(ctx, service, args[1:], stdout, stderr)
	case "detection":
		service, err := researchcore.New(root)
		if err != nil {
			return err
		}
		return runDetectionCLI(service, args[1:], stdout, stderr)
	case "dfir":
		service, err := researchcore.New(root)
		if err != nil {
			return err
		}
		return runDFIRCLI(service, args[1:], stdout, stderr)
	case "fuzz":
		service, err := researchcore.New(root)
		if err != nil {
			return err
		}
		return runFuzzCLI(service, args[1:], stdout, stderr)
	case "crash":
		service, err := researchcore.New(root)
		if err != nil {
			return err
		}
		return runCrashCLI(service, args[1:], stdout, stderr)
	case "protocol":
		service, err := researchcore.New(root)
		if err != nil {
			return err
		}
		return runProtocolCLI(service, args[1:], stdout, stderr)
	case "source":
		service, err := researchcore.New(root)
		if err != nil {
			return err
		}
		return runSourceCLI(service, args[1:], stdout, stderr)
	case "purple":
		service, err := researchcore.New(root)
		if err != nil {
			return err
		}
		return runPurpleCLI(service, args[1:], stdout, stderr)
	case "attackgraph":
		service, err := researchcore.New(root)
		if err != nil {
			return err
		}
		return runAttackGraphCLI(service, args[1:], stdout, stderr)
	case "cloud":
		service, err := researchcore.New(root)
		if err != nil {
			return err
		}
		return runCloudCLI(service, args[1:], stdout, stderr)
	case "cti":
		service, err := researchcore.New(root)
		if err != nil {
			return err
		}
		return runCTICLI(service, args[1:], stdout, stderr)
	case "hunt":
		service, err := researchcore.New(root)
		if err != nil {
			return err
		}
		return runHuntCLI(service, args[1:], stdout, stderr)
	case "ios":
		service, err := researchcore.New(root)
		if err != nil {
			return err
		}
		return runIOSCLI(service, args[1:], stdout, stderr)
	case "firmware":
		service, err := researchcore.New(root)
		if err != nil {
			return err
		}
		return runFirmwareCLI(service, args[1:], stdout, stderr)
	case "report":
		service, err := researchcore.New(root)
		if err != nil {
			return err
		}
		return runReportCLI(service, args[1:], stdout, stderr)
	case "dashboard":
		service, err := researchcore.New(root)
		if err != nil {
			return err
		}
		return runDashboardCLI(service, args[1:], stdout, stderr)
	case "collab":
		service, err := researchcore.New(root)
		if err != nil {
			return err
		}
		return runCollaborationCLI(service, args[1:], stdout, stderr)
	case "rbac":
		return runRBACCLI(args[1:], stdout, stderr)
	case "agent":
		service, err := researchcore.New(root)
		if err != nil {
			return err
		}
		return runAgentCLI(service, args[1:], stdout, stderr)
	case "pack":
		service, err := researchcore.New(root)
		if err != nil {
			return err
		}
		return runPackCLI(service, args[1:], stdout, stderr)
	case "process":
		service, err := researchcore.New(root)
		if err != nil {
			return err
		}
		return runProcessCLI(service, args[1:], stdout, stderr)
	case "memory":
		service, err := researchcore.New(root)
		if err != nil {
			return err
		}
		return runMemoryCLI(ctx, service, args[1:], stdout, stderr)
	case "pointer":
		service, err := researchcore.New(root)
		if err != nil {
			return err
		}
		return runPointerCLI(ctx, service, args[1:], stdout, stderr)
	case "watch":
		runtime := modules.New(root)
		defer func() { err = errors.Join(err, runtime.Close()) }()
		return runWatchCLI(ctx, runtime, args[1:], stdout, stderr)
	case "hook":
		service, err := researchcore.New(root)
		if err != nil {
			return err
		}
		return runHookCLI(ctx, service, args[1:], stdout, stderr)
	case "compat":
		service, err := researchcore.New(root)
		if err != nil {
			return err
		}
		return runCompatibilityCLI(service, args[1:], stdout, stderr)
	case "patch":
		service, err := researchcore.New(root)
		if err != nil {
			return err
		}
		return runPatchCLI(service, args[1:], stdout, stderr)
	case "diff":
		service, err := researchcore.New(root)
		if err != nil {
			return err
		}
		return runDiffCLI(ctx, service, args[1:], stdout, stderr)
	case "sync":
		service, err := researchcore.New(root)
		if err != nil {
			return err
		}
		return runSyncCLI(service, args[1:], stdout, stderr)
	case "route":
		service, err := researchcore.New(root)
		if err != nil {
			return err
		}
		return runRouteCLI(service, args[1:], stdout)
	case "prepare":
		service, err := researchcore.New(root)
		if err != nil {
			return err
		}
		return runPrepareCLI(service, args[1:], stdout)
	case "playbook":
		service, err := researchcore.New(root)
		if err != nil {
			return err
		}
		return runPlaybookCLI(service, args[1:], stdout)
	case "domain-pack":
		service, err := researchcore.New(root)
		if err != nil {
			return err
		}
		return runDomainPackCLI(service, args[1:], stdout)
	case "knowledge-pack":
		service, err := researchcore.New(root)
		if err != nil {
			return err
		}
		return runKnowledgePackCLI(service, args[1:], stdout)
	case "web":
		service, err := researchcore.New(root)
		if err != nil {
			return err
		}
		return runWebCLI(ctx, service, args[1:], stdout, stderr)
	case "android":
		service, err := researchcore.New(root)
		if err != nil {
			return err
		}
		return runAndroidCLI(ctx, service, args[1:], stdout, stderr)
	case "tools":
		service, err := researchcore.New(root)
		if err != nil {
			return err
		}
		return runToolsCLI(service, args[1:], stdout)
	case "contract":
		return runContractCLI(root, args[1:], stdout, stderr)
	case "capability":
		service, err := researchcore.New(root)
		if err != nil {
			return err
		}
		return runCapabilityCLI(service, args[1:], stdout)
	case "engagement":
		service, err := researchcore.New(root)
		if err != nil {
			return err
		}
		return runEngagementCLI(service, args[1:], stdout, stderr)
	case "job":
		service, err := researchcore.New(root)
		if err != nil {
			return err
		}
		return runJobCLI(service, args[1:], stdout, stderr)
	case "case":
		service, err := researchcore.New(root)
		if err != nil {
			return err
		}
		return runCaseCLI(service, args[1:], stdout, stderr)
	case "journal":
		service, err := researchcore.New(root)
		if err != nil {
			return err
		}
		return runJournalCLI(service, args[1:], stdout, stderr)
	case "sandbox":
		service, err := researchcore.New(root)
		if err != nil {
			return err
		}
		return runSandboxCLI(service, args[1:], stdout, stderr)
	case "module":
		runtime := modules.New(root)
		defer func() { err = errors.Join(err, runtime.Close()) }()
		return runModuleCLI(ctx, runtime, args[1:], stdout, stderr)
	case "x32dbg", "ghidra", "r2":
		runtime := modules.New(root)
		defer func() { err = errors.Join(err, runtime.Close()) }()
		return runModuleCallCLI(ctx, runtime, args[0], args[1:], stdout, stderr)
	default:
		return fmt.Errorf("unknown command %q; run ReverseResearch help", args[0])
	}
}

func runTargetCLI(service *researchcore.Service, args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return errors.New("target subcommand is required: identify or compare")
	}
	switch args[0] {
	case "identify":
		if len(args) != 2 {
			return errors.New("usage: ReverseResearch target identify <path>")
		}
		result, err := service.Identify(args[1])
		if err != nil {
			return err
		}
		return writeJSON(stdout, result)
	case "compare":
		if len(args) != 3 {
			return errors.New("usage: ReverseResearch target compare <left-path> <right-path>")
		}
		result, err := service.Compare(args[1], args[2])
		if err != nil {
			return err
		}
		return writeJSON(stdout, result)
	default:
		return fmt.Errorf("unknown target subcommand %q", args[0])
	}
}

func runDIECLI(ctx context.Context, service *researchcore.Service, args []string, stdout, stderr io.Writer) error {
	if len(args) < 2 || args[0] != "scan" {
		return errors.New("usage: ReverseResearch die scan <path> [--timeout 15s] [--verbose] [--deep] [--heuristic] [--all-types] [--entropy] [--info]")
	}
	path := args[1]
	flags := flag.NewFlagSet("die scan", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var timeoutText string
	var options die.ScanOptions
	flags.StringVar(&timeoutText, "timeout", die.DefaultTimeout.String(), "bounded DiE scan timeout")
	flags.BoolVar(&options.Verbose, "verbose", false, "request detailed DiE output")
	flags.BoolVar(&options.Deep, "deep", false, "enable deep scan")
	flags.BoolVar(&options.Heuristic, "heuristic", false, "enable heuristic scan")
	flags.BoolVar(&options.AllTypes, "all-types", false, "scan all file types")
	flags.BoolVar(&options.Entropy, "entropy", false, "include entropy information")
	flags.BoolVar(&options.Info, "info", false, "include file information")
	if err := flags.Parse(args[2:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments after die scan")
	}
	timeout, err := time.ParseDuration(timeoutText)
	if err != nil || timeout <= 0 {
		return fmt.Errorf("invalid DiE timeout %q", timeoutText)
	}
	options.Timeout = timeout
	report, err := service.ScanDIE(ctx, path, options)
	if err != nil {
		return err
	}
	return writeJSON(stdout, report)
}

func runProcessCLI(service *researchcore.Service, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("process subcommand is required: inspect, debug-route, acquire, get, or release")
	}
	if len(args) < 2 {
		return fmt.Errorf("usage: ReverseResearch process %s <pid>", args[0])
	}
	parsed, err := strconv.ParseUint(args[1], 10, 32)
	if err != nil || parsed == 0 {
		return fmt.Errorf("invalid process pid %q", args[1])
	}
	pid := uint32(parsed)

	switch args[0] {
	case "inspect":
		if len(args) != 2 {
			return errors.New("usage: ReverseResearch process inspect <pid>")
		}
		result, err := service.InspectProcess(pid)
		if err != nil {
			return err
		}
		return writeJSON(stdout, result)
	case "debug-route":
		if len(args) != 2 {
			return errors.New("usage: ReverseResearch process debug-route <pid>")
		}
		result, err := service.DebugRouteProcess(pid)
		if err != nil {
			return err
		}
		return writeJSON(stdout, result)
	case "get":
		if len(args) != 2 {
			return errors.New("usage: ReverseResearch process get <pid>")
		}
		result, err := service.GetProcessControl(pid)
		if err != nil {
			return err
		}
		return writeJSON(stdout, result)
	case "acquire", "release":
		flags := flag.NewFlagSet("process "+args[0], flag.ContinueOnError)
		flags.SetOutput(stderr)
		var processKey, owner, leaseID string
		flags.StringVar(&processKey, "key", "", "process identity key returned by process inspect")
		flags.StringVar(&owner, "owner", "", "logical control owner")
		if args[0] == "release" {
			flags.StringVar(&leaseID, "lease-id", "", "lease identity returned by process acquire")
		}
		if err := flags.Parse(args[2:]); err != nil {
			return err
		}
		if flags.NArg() != 0 || strings.TrimSpace(processKey) == "" || strings.TrimSpace(owner) == "" || (args[0] == "release" && strings.TrimSpace(leaseID) == "") {
			if args[0] == "release" {
				return errors.New("usage: ReverseResearch process release <pid> --key <process-key> --owner <owner> --lease-id <lease-id>")
			}
			return errors.New("usage: ReverseResearch process acquire <pid> --key <process-key> --owner <owner>")
		}
		if args[0] == "acquire" {
			result, err := service.AcquireProcessControl(pid, processKey, owner)
			if err != nil {
				return err
			}
			return writeJSON(stdout, result)
		}
		if err := service.ReleaseProcessControl(pid, processKey, owner, leaseID); err != nil {
			return err
		}
		return writeJSON(stdout, map[string]any{"released": true, "pid": pid, "process_key": strings.TrimSpace(processKey), "owner": strings.TrimSpace(owner)})
	default:
		return fmt.Errorf("unknown process subcommand %q", args[0])
	}
}

func runMemoryCLI(ctx context.Context, service *researchcore.Service, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("memory subcommand is required: scan, refine, or get")
	}
	switch args[0] {
	case "scan":
		if len(args) < 2 {
			return errors.New("usage: ReverseResearch memory scan <pid> --key <process-key> --type <u32> (--value <n> | --unknown) [--start <addr>] [--end <addr>] [--alignment N] [--max-bytes N] [--max-candidates N] [--timeout 5s]")
		}
		parsedPID, err := strconv.ParseUint(args[1], 10, 32)
		if err != nil || parsedPID == 0 {
			return fmt.Errorf("invalid process pid %q", args[1])
		}
		flags := flag.NewFlagSet("memory scan", flag.ContinueOnError)
		flags.SetOutput(stderr)
		var processKey, valueType, value, startRaw, endRaw, timeoutRaw string
		var unknown bool
		var alignment, maxCandidates int
		var maxBytes uint64
		flags.StringVar(&processKey, "key", "", "fresh process identity key")
		flags.StringVar(&valueType, "type", "u32", "value type: u8/i8/u16/i16/u32/i32/u64/i64/f32/f64")
		flags.StringVar(&value, "value", "", "exact initial value")
		flags.BoolVar(&unknown, "unknown", false, "capture all aligned values in the bounded range")
		flags.StringVar(&startRaw, "start", "0", "inclusive start address, decimal or 0x-prefixed")
		flags.StringVar(&endRaw, "end", "0", "exclusive end address; 0 uses the architecture user-space ceiling")
		flags.IntVar(&alignment, "alignment", 0, "candidate alignment; 0 defaults to value size")
		flags.Uint64Var(&maxBytes, "max-bytes", memscan.DefaultMaxBytes, "maximum process bytes read")
		flags.IntVar(&maxCandidates, "max-candidates", memscan.DefaultMaxCandidates, "maximum persisted candidates")
		flags.StringVar(&timeoutRaw, "timeout", memscan.DefaultTimeout.String(), "bounded scan timeout")
		if err := flags.Parse(args[2:]); err != nil {
			return err
		}
		if flags.NArg() != 0 || strings.TrimSpace(processKey) == "" {
			return errors.New("memory scan requires --key and no positional arguments after flags")
		}
		if unknown && strings.TrimSpace(value) != "" {
			return errors.New("--unknown and --value are mutually exclusive")
		}
		if !unknown && strings.TrimSpace(value) == "" {
			return errors.New("memory scan requires --value unless --unknown is used")
		}
		start, err := strconv.ParseUint(strings.TrimSpace(startRaw), 0, 64)
		if err != nil {
			return fmt.Errorf("invalid memory scan start address %q", startRaw)
		}
		end, err := strconv.ParseUint(strings.TrimSpace(endRaw), 0, 64)
		if err != nil {
			return fmt.Errorf("invalid memory scan end address %q", endRaw)
		}
		timeout, err := time.ParseDuration(timeoutRaw)
		if err != nil {
			return fmt.Errorf("invalid memory scan timeout %q", timeoutRaw)
		}
		mode := memscan.ModeExact
		if unknown {
			mode = memscan.ModeUnknown
		}
		result, err := service.StartMemoryScan(ctx, memscan.StartRequest{
			PID: uint32(parsedPID), ProcessKey: processKey, ValueType: valueType, Mode: mode, Value: value,
			StartAddress: start, EndAddress: end, Alignment: alignment,
			MaxBytes: maxBytes, MaxCandidates: maxCandidates, Timeout: timeout,
		})
		if err != nil {
			return err
		}
		return writeJSON(stdout, result)

	case "refine":
		if len(args) < 2 {
			return errors.New("usage: ReverseResearch memory refine <scan-id> --expected-version <n> --mode <exact|changed|unchanged|increased|decreased> [--value <n>] [--timeout 5s]")
		}
		flags := flag.NewFlagSet("memory refine", flag.ContinueOnError)
		flags.SetOutput(stderr)
		var expectedVersion int
		var modeRaw, value, timeoutRaw string
		flags.IntVar(&expectedVersion, "expected-version", 0, "required candidate-set version fence")
		flags.StringVar(&modeRaw, "mode", "", "exact, changed, unchanged, increased, or decreased")
		flags.StringVar(&value, "value", "", "required for exact refinement")
		flags.StringVar(&timeoutRaw, "timeout", memscan.DefaultTimeout.String(), "bounded refinement timeout")
		if err := flags.Parse(args[2:]); err != nil {
			return err
		}
		if flags.NArg() != 0 || expectedVersion < 1 || strings.TrimSpace(modeRaw) == "" {
			return errors.New("memory refine requires --expected-version and --mode")
		}
		mode := memscan.Mode(strings.ToLower(strings.TrimSpace(modeRaw)))
		if mode == memscan.ModeExact && strings.TrimSpace(value) == "" {
			return errors.New("exact memory refinement requires --value")
		}
		timeout, err := time.ParseDuration(timeoutRaw)
		if err != nil {
			return fmt.Errorf("invalid memory refinement timeout %q", timeoutRaw)
		}
		result, err := service.RefineMemoryScan(ctx, memscan.RefineRequest{
			ScanID: args[1], ExpectedVersion: expectedVersion, Mode: mode, Value: value, Timeout: timeout,
		})
		if err != nil {
			return err
		}
		return writeJSON(stdout, result)

	case "get":
		if len(args) < 2 {
			return errors.New("usage: ReverseResearch memory get <scan-id> [--sample N]")
		}
		flags := flag.NewFlagSet("memory get", flag.ContinueOnError)
		flags.SetOutput(stderr)
		var sample int
		flags.IntVar(&sample, "sample", memscan.DefaultSampleLimit, "candidate sample size")
		if err := flags.Parse(args[2:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return errors.New("usage: ReverseResearch memory get <scan-id> [--sample N]")
		}
		result, err := service.GetMemoryScan(args[1], sample)
		if err != nil {
			return err
		}
		return writeJSON(stdout, result)
	default:
		return fmt.Errorf("unknown memory subcommand %q", args[0])
	}
}

func runPointerCLI(ctx context.Context, service *researchcore.Service, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("pointer subcommand is required: scan, get, or verify")
	}
	switch args[0] {
	case "scan":
		if len(args) < 2 {
			return errors.New("usage: ReverseResearch pointer scan <pid> --key <process-key> --target <addr> [--start <addr>] [--end <addr>] [--max-offset <n>] [--max-depth N]")
		}
		parsedPID, err := strconv.ParseUint(args[1], 10, 32)
		if err != nil || parsedPID == 0 {
			return fmt.Errorf("invalid process pid %q", args[1])
		}
		flags := flag.NewFlagSet("pointer scan", flag.ContinueOnError)
		flags.SetOutput(stderr)
		var processKey, targetRaw, startRaw, endRaw, maxOffsetRaw, timeoutRaw string
		var maxDepth, alignment, maxNodes, maxChains int
		var maxBytes uint64
		flags.StringVar(&processKey, "key", "", "fresh process identity key")
		flags.StringVar(&targetRaw, "target", "", "target address, decimal or 0x-prefixed")
		flags.StringVar(&startRaw, "start", "0", "inclusive scan start address")
		flags.StringVar(&endRaw, "end", "0", "exclusive scan end address; 0 uses the architecture ceiling")
		flags.StringVar(&maxOffsetRaw, "max-offset", strconv.FormatUint(pointermap.DefaultMaxOffset, 10), "maximum positive pointer offset")
		flags.IntVar(&maxDepth, "max-depth", pointermap.DefaultMaxDepth, "maximum pointer chain depth")
		flags.IntVar(&alignment, "alignment", 0, "pointer-slot alignment; 0 uses pointer width")
		flags.Uint64Var(&maxBytes, "max-bytes", pointermap.DefaultMaxBytes, "maximum bytes read per depth")
		flags.IntVar(&maxNodes, "max-nodes", pointermap.DefaultMaxNodes, "maximum search nodes")
		flags.IntVar(&maxChains, "max-chains", pointermap.DefaultMaxChains, "maximum persisted module-anchored chains")
		flags.StringVar(&timeoutRaw, "timeout", pointermap.DefaultTimeout.String(), "bounded pointer scan timeout")
		if err := flags.Parse(args[2:]); err != nil {
			return err
		}
		if flags.NArg() != 0 || strings.TrimSpace(processKey) == "" || strings.TrimSpace(targetRaw) == "" {
			return errors.New("pointer scan requires --key and --target")
		}
		target, err := strconv.ParseUint(strings.TrimSpace(targetRaw), 0, 64)
		if err != nil || target == 0 {
			return fmt.Errorf("invalid pointer target address %q", targetRaw)
		}
		start, err := strconv.ParseUint(strings.TrimSpace(startRaw), 0, 64)
		if err != nil {
			return fmt.Errorf("invalid pointer scan start address %q", startRaw)
		}
		end, err := strconv.ParseUint(strings.TrimSpace(endRaw), 0, 64)
		if err != nil {
			return fmt.Errorf("invalid pointer scan end address %q", endRaw)
		}
		maxOffset, err := strconv.ParseUint(strings.TrimSpace(maxOffsetRaw), 0, 64)
		if err != nil {
			return fmt.Errorf("invalid pointer max offset %q", maxOffsetRaw)
		}
		timeout, err := time.ParseDuration(timeoutRaw)
		if err != nil {
			return fmt.Errorf("invalid pointer scan timeout %q", timeoutRaw)
		}
		result, err := service.BuildPointerMap(ctx, pointermap.BuildRequest{
			PID: uint32(parsedPID), ProcessKey: processKey, TargetAddress: target,
			StartAddress: start, EndAddress: end, MaxOffset: maxOffset, MaxDepth: maxDepth,
			Alignment: alignment, MaxBytes: maxBytes, MaxNodes: maxNodes, MaxChains: maxChains,
			Timeout: timeout,
		})
		if err != nil {
			return err
		}
		return writeJSON(stdout, result)

	case "get":
		if len(args) < 2 {
			return errors.New("usage: ReverseResearch pointer get <map-id> [--sample N]")
		}
		flags := flag.NewFlagSet("pointer get", flag.ContinueOnError)
		flags.SetOutput(stderr)
		var sample int
		flags.IntVar(&sample, "sample", pointermap.DefaultSample, "pointer chain sample size")
		if err := flags.Parse(args[2:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return errors.New("usage: ReverseResearch pointer get <map-id> [--sample N]")
		}
		result, err := service.GetPointerMap(args[1], sample)
		if err != nil {
			return err
		}
		return writeJSON(stdout, result)

	case "verify":
		if len(args) < 2 {
			return errors.New("usage: ReverseResearch pointer verify <map-id> --pid <pid> --key <process-key> [--target <addr>] [--timeout 10s] [--sample N]")
		}
		flags := flag.NewFlagSet("pointer verify", flag.ContinueOnError)
		flags.SetOutput(stderr)
		var pid uint
		var processKey, targetRaw, timeoutRaw string
		var sample int
		flags.UintVar(&pid, "pid", 0, "current process pid")
		flags.StringVar(&processKey, "key", "", "fresh current process identity key")
		flags.StringVar(&targetRaw, "target", "0", "current expected final target address; 0 checks structural resolution only")
		flags.StringVar(&timeoutRaw, "timeout", pointermap.DefaultTimeout.String(), "bounded verification timeout")
		flags.IntVar(&sample, "sample", pointermap.DefaultSample, "verification sample size")
		if err := flags.Parse(args[2:]); err != nil {
			return err
		}
		if flags.NArg() != 0 || pid == 0 || strings.TrimSpace(processKey) == "" {
			return errors.New("pointer verify requires --pid and --key")
		}
		target, err := strconv.ParseUint(strings.TrimSpace(targetRaw), 0, 64)
		if err != nil {
			return fmt.Errorf("invalid pointer verification target %q", targetRaw)
		}
		timeout, err := time.ParseDuration(timeoutRaw)
		if err != nil {
			return fmt.Errorf("invalid pointer verification timeout %q", timeoutRaw)
		}
		result, err := service.VerifyPointerMap(ctx, pointermap.VerifyRequest{
			MapID: args[1], PID: uint32(pid), ProcessKey: processKey,
			TargetAddress: target, Timeout: timeout, SampleLimit: sample,
		})
		if err != nil {
			return err
		}
		return writeJSON(stdout, result)
	default:
		return fmt.Errorf("unknown pointer subcommand %q", args[0])
	}
}

func runWatchCLI(ctx context.Context, runtime *modules.Runtime, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 || args[0] != "write" {
		return errors.New("usage: ReverseResearch watch write <pid> --key <process-key> --owner <owner> --lease-id <lease-id> --operation-id <id> --address <addr> [--size 1|2|4|8] [--timeout 30s] [--max-events N]")
	}
	if len(args) < 2 {
		return errors.New("write watch pid is required")
	}
	parsedPID, err := strconv.ParseUint(args[1], 10, 32)
	if err != nil || parsedPID == 0 {
		return fmt.Errorf("invalid process pid %q", args[1])
	}
	flags := flag.NewFlagSet("watch write", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var processKey, owner, leaseID, operationID, addressRaw, timeoutRaw string
	var size, maxEvents int
	flags.StringVar(&processKey, "key", "", "fresh process identity key")
	flags.StringVar(&owner, "owner", "", "current process-control lease owner")
	flags.StringVar(&leaseID, "lease-id", "", "current process-control lease id")
	flags.StringVar(&operationID, "operation-id", "", "one-shot watch workflow operation id")
	flags.StringVar(&addressRaw, "address", "", "watched address, decimal or 0x-prefixed")
	flags.IntVar(&size, "size", 1, "hardware watch size: 1, 2, 4, or 8")
	flags.StringVar(&timeoutRaw, "timeout", modules.DefaultWriteWatchTimeout.String(), "overall watch deadline")
	flags.IntVar(&maxEvents, "max-events", modules.DefaultWriteWatchMaxEvents, "maximum pause events to collect")
	if err := flags.Parse(args[2:]); err != nil {
		return err
	}
	if flags.NArg() != 0 || strings.TrimSpace(processKey) == "" || strings.TrimSpace(owner) == "" ||
		strings.TrimSpace(leaseID) == "" || strings.TrimSpace(operationID) == "" || strings.TrimSpace(addressRaw) == "" {
		return errors.New("write watch requires --key, --owner, --lease-id, --operation-id, and --address")
	}
	address, err := strconv.ParseUint(strings.TrimSpace(addressRaw), 0, 64)
	if err != nil || address == 0 {
		return fmt.Errorf("invalid write watch address %q", addressRaw)
	}
	timeout, err := time.ParseDuration(timeoutRaw)
	if err != nil {
		return fmt.Errorf("invalid write watch timeout %q", timeoutRaw)
	}
	report, err := runtime.ObserveWrite(ctx, modules.X32WriteWatchRequest{
		PID: uint32(parsedPID), ProcessKey: processKey, Owner: owner, LeaseID: leaseID,
		OperationID: operationID, Address: address, Size: size, Timeout: timeout,
		MaxEvents: maxEvents, StopOnWrite: true,
	})
	if err != nil {
		return err
	}
	return writeJSON(stdout, report)
}

func runHookCLI(ctx context.Context, service *researchcore.Service, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("hook subcommand is required: plan, get, list, apply, verify, rollback, or cancel")
	}
	switch args[0] {
	case "plan":
		flags := flag.NewFlagSet("hook plan", flag.ContinueOnError)
		flags.SetOutput(stderr)
		var path, sourceRaw, destinationRaw, expected, description string
		flags.StringVar(&path, "path", "", "target PE file")
		flags.StringVar(&sourceRaw, "source-rva", "", "detour source RVA; decimal or 0x-prefixed")
		flags.StringVar(&destinationRaw, "destination-rva", "", "detour destination RVA; decimal or 0x-prefixed")
		flags.StringVar(&expected, "expected", "", "optional exact original bytes expected at the whole-instruction overwrite span")
		flags.StringVar(&description, "description", "", "optional description")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 || strings.TrimSpace(path) == "" || strings.TrimSpace(sourceRaw) == "" || strings.TrimSpace(destinationRaw) == "" {
			return errors.New("usage: ReverseResearch hook plan --path <pe> --source-rva <rva> --destination-rva <rva> [--expected <hex>] [--description <text>]")
		}
		source, err := strconv.ParseUint(strings.TrimSpace(sourceRaw), 0, 64)
		if err != nil {
			return fmt.Errorf("invalid source RVA %q", sourceRaw)
		}
		destination, err := strconv.ParseUint(strings.TrimSpace(destinationRaw), 0, 64)
		if err != nil {
			return fmt.Errorf("invalid destination RVA %q", destinationRaw)
		}
		result, err := service.PlanHook(ctx, hookplan.PlanRequest{
			Path: path, SourceRVA: source, DestinationRVA: destination,
			ExpectedHex: expected, Description: description,
		})
		if err != nil {
			return err
		}
		return writeJSON(stdout, result)

	case "get", "verify":
		if len(args) != 2 {
			return fmt.Errorf("usage: ReverseResearch hook %s <hook-id>", args[0])
		}
		var value any
		var err error
		if args[0] == "get" {
			value, err = service.GetHook(args[1])
		} else {
			value, err = service.VerifyHook(args[1])
		}
		if err != nil {
			return err
		}
		return writeJSON(stdout, value)

	case "list":
		flags := flag.NewFlagSet("hook list", flag.ContinueOnError)
		flags.SetOutput(stderr)
		var path string
		flags.StringVar(&path, "path", "", "optional target file filter")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return errors.New("unexpected positional arguments after hook list")
		}
		result, err := service.ListHooks(path)
		if err != nil {
			return err
		}
		return writeJSON(stdout, result)

	case "apply":
		if len(args) < 2 {
			return errors.New("usage: ReverseResearch hook apply <hook-id> --expected-version N --operation-id <id> --confirm-in-place")
		}
		hookID := args[1]
		flags := flag.NewFlagSet("hook apply", flag.ContinueOnError)
		flags.SetOutput(stderr)
		var expectedVersion int
		var operationID string
		var confirm bool
		flags.IntVar(&expectedVersion, "expected-version", 0, "required current hook version")
		flags.StringVar(&operationID, "operation-id", "", "required crash-recovery identity")
		flags.BoolVar(&confirm, "confirm-in-place", false, "explicitly confirm in-place target mutation")
		if err := flags.Parse(args[2:]); err != nil {
			return err
		}
		if flags.NArg() != 0 || expectedVersion < 1 || strings.TrimSpace(operationID) == "" {
			return errors.New("hook apply requires --expected-version N and --operation-id <id>")
		}
		result, err := service.ApplyHook(hookplan.ApplyRequest{
			HookID: hookID, ExpectedVersion: expectedVersion, OperationID: operationID, ConfirmInPlace: confirm,
		})
		if err != nil {
			return err
		}
		return writeJSON(stdout, result)

	case "rollback":
		if len(args) < 2 {
			return errors.New("usage: ReverseResearch hook rollback <hook-id> --expected-version N --operation-id <id>")
		}
		hookID := args[1]
		flags := flag.NewFlagSet("hook rollback", flag.ContinueOnError)
		flags.SetOutput(stderr)
		var expectedVersion int
		var operationID string
		flags.IntVar(&expectedVersion, "expected-version", 0, "required current hook version")
		flags.StringVar(&operationID, "operation-id", "", "required crash-recovery identity")
		if err := flags.Parse(args[2:]); err != nil {
			return err
		}
		if flags.NArg() != 0 || expectedVersion < 1 || strings.TrimSpace(operationID) == "" {
			return errors.New("hook rollback requires --expected-version N and --operation-id <id>")
		}
		result, err := service.RollbackHook(hookplan.RollbackRequest{
			HookID: hookID, ExpectedVersion: expectedVersion, OperationID: operationID,
		})
		if err != nil {
			return err
		}
		return writeJSON(stdout, result)

	case "cancel":
		if len(args) < 2 {
			return errors.New("usage: ReverseResearch hook cancel <hook-id> --expected-version N")
		}
		hookID := args[1]
		flags := flag.NewFlagSet("hook cancel", flag.ContinueOnError)
		flags.SetOutput(stderr)
		var expectedVersion int
		flags.IntVar(&expectedVersion, "expected-version", 0, "required current hook version")
		if err := flags.Parse(args[2:]); err != nil {
			return err
		}
		if flags.NArg() != 0 || expectedVersion < 1 {
			return errors.New("hook cancel requires --expected-version N")
		}
		result, err := service.CancelHook(hookplan.CancelRequest{HookID: hookID, ExpectedVersion: expectedVersion})
		if err != nil {
			return err
		}
		return writeJSON(stdout, result)
	default:
		return fmt.Errorf("unknown hook subcommand %q", args[0])
	}
}

func runPatchCLI(service *researchcore.Service, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("patch subcommand is required: plan, get, dry-run, apply, verify, or rollback")
	}
	switch args[0] {
	case "plan":
		flags := flag.NewFlagSet("patch plan", flag.ContinueOnError)
		flags.SetOutput(stderr)
		var path, offsetRaw, expected, replacement, description, editsJSON, editsFile string
		flags.StringVar(&path, "path", "", "target file")
		flags.StringVar(&offsetRaw, "offset", "", "zero-based offset; decimal or 0x-prefixed hex")
		flags.StringVar(&expected, "expected", "", "expected original bytes")
		flags.StringVar(&replacement, "replacement", "", "replacement bytes")
		flags.StringVar(&editsJSON, "edits-json", "", "composite edits as a JSON array")
		flags.StringVar(&editsFile, "edits-file", "", "read composite edits JSON array from a file")
		flags.StringVar(&description, "description", "", "optional description")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 || strings.TrimSpace(path) == "" {
			return errors.New("usage: ReverseResearch patch plan --path <file> (--offset <n|0xHEX> --expected <hex> --replacement <hex> | --edits-json <array> | --edits-file <path>) [--description <text>]")
		}
		if editsJSON != "" && editsFile != "" {
			return errors.New("--edits-json and --edits-file are mutually exclusive")
		}
		request := patchplan.PlanRequest{Path: path, Description: description}
		if editsJSON != "" || editsFile != "" {
			if offsetRaw != "" || expected != "" || replacement != "" {
				return errors.New("composite edits cannot be combined with --offset, --expected, or --replacement")
			}
			if editsFile != "" {
				body, err := os.ReadFile(editsFile)
				if err != nil {
					return fmt.Errorf("read composite edits file: %w", err)
				}
				editsJSON = string(body)
			}
			if err := json.Unmarshal([]byte(editsJSON), &request.Edits); err != nil {
				return fmt.Errorf("decode composite edits JSON: %w", err)
			}
			if len(request.Edits) == 0 {
				return errors.New("composite edits array must not be empty")
			}
		} else {
			if offsetRaw == "" || expected == "" || replacement == "" {
				return errors.New("single patch plan requires --offset, --expected, and --replacement")
			}
			offset, err := strconv.ParseInt(offsetRaw, 0, 64)
			if err != nil || offset < 0 {
				return fmt.Errorf("invalid patch offset %q", offsetRaw)
			}
			request.Offset = offset
			request.ExpectedHex = expected
			request.ReplacementHex = replacement
		}
		result, err := service.PlanPatch(request)
		if err != nil {
			return err
		}
		return writeJSON(stdout, result)

	case "get", "dry-run", "verify":
		if len(args) != 2 {
			return fmt.Errorf("usage: ReverseResearch patch %s <plan-id>", args[0])
		}
		var value any
		var err error
		switch args[0] {
		case "get":
			value, err = service.GetPatch(args[1])
		case "dry-run":
			value, err = service.DryRunPatch(args[1])
		case "verify":
			value, err = service.VerifyPatch(args[1])
		}
		if err != nil {
			return err
		}
		return writeJSON(stdout, value)

	case "rollback":
		if len(args) < 2 {
			return errors.New("usage: ReverseResearch patch rollback <plan-id> [--operation-id <id>]")
		}
		planID := args[1]
		flags := flag.NewFlagSet("patch rollback", flag.ContinueOnError)
		flags.SetOutput(stderr)
		var operationID string
		flags.StringVar(&operationID, "operation-id", "", "optional replay identity for crash-safe retry")
		if err := flags.Parse(args[2:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return errors.New("unexpected positional arguments after patch rollback")
		}
		result, err := service.RollbackPatchOperation(patchplan.RollbackRequest{PlanID: planID, OperationID: operationID})
		if err != nil {
			return err
		}
		return writeJSON(stdout, result)

	case "apply":
		if len(args) < 2 {
			return errors.New("usage: ReverseResearch patch apply <plan-id> [--in-place | --output <path>] [--operation-id <id>]")
		}
		planID := args[1]
		flags := flag.NewFlagSet("patch apply", flag.ContinueOnError)
		flags.SetOutput(stderr)
		var inPlace bool
		var output, operationID string
		flags.BoolVar(&inPlace, "in-place", false, "modify the source file")
		flags.StringVar(&output, "output", "", "write a patched copy to this path")
		flags.StringVar(&operationID, "operation-id", "", "optional replay identity for crash-safe retry")
		if err := flags.Parse(args[2:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return errors.New("unexpected positional arguments after patch apply")
		}
		result, err := service.ApplyPatch(patchplan.ApplyRequest{
			PlanID:      planID,
			InPlace:     inPlace,
			OutputPath:  output,
			OperationID: operationID,
		})
		if err != nil {
			return err
		}
		return writeJSON(stdout, result)
	default:
		return fmt.Errorf("unknown patch subcommand %q", args[0])
	}
}

func runDiffCLI(ctx context.Context, service *researchcore.Service, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("diff subcommand is required: quick, functions, or migrate")
	}
	switch args[0] {
	case "migrate":
		return runMigrationCLI(ctx, service, args[1:], stdout, stderr)
	case "quick":
		if len(args) != 3 {
			return errors.New("usage: ReverseResearch diff quick <old-file> <new-file>")
		}
		result, err := service.QuickDiff(ctx, args[1], args[2])
		if err != nil {
			return err
		}
		return writeJSON(stdout, result)
	case "functions":
		if len(args) < 3 {
			return errors.New("usage: ReverseResearch diff functions <old-file> <new-file> [--threshold 70]")
		}
		leftPath, rightPath := args[1], args[2]
		flags := flag.NewFlagSet("diff functions", flag.ContinueOnError)
		flags.SetOutput(stderr)
		var threshold int
		flags.IntVar(&threshold, "threshold", 70, "function match threshold from 1 to 100")
		if err := flags.Parse(args[3:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return errors.New("unexpected positional arguments after diff functions")
		}
		result, err := service.FunctionDiff(ctx, leftPath, rightPath, threshold)
		if err != nil {
			return err
		}
		return writeJSON(stdout, result)
	default:
		return fmt.Errorf("unknown diff subcommand %q", args[0])
	}
}

func runRouteCLI(service *researchcore.Service, args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: ReverseResearch route <task text>")
	}
	result, err := service.Route(strings.Join(args, " "))
	if err != nil {
		return err
	}
	return writeJSON(stdout, result)
}

func runPrepareCLI(service *researchcore.Service, args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: ReverseResearch prepare <task text>")
	}
	result, err := service.Prepare(strings.Join(args, " "))
	if err != nil {
		return err
	}
	return writeJSON(stdout, result)
}

func runPlaybookCLI(service *researchcore.Service, args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return errors.New("playbook subcommand is required: list, show, or route")
	}
	switch args[0] {
	case "list":
		if len(args) != 1 {
			return errors.New("usage: ReverseResearch playbook list")
		}
		values, err := service.ListPlaybooks()
		if err != nil {
			return err
		}
		return writeJSON(stdout, values)
	case "show":
		if len(args) != 2 {
			return errors.New("usage: ReverseResearch playbook show <playbook-id>")
		}
		value, err := service.GetPlaybook(args[1])
		if err != nil {
			return err
		}
		return writeJSON(stdout, value)
	case "route":
		if len(args) != 2 {
			return errors.New("usage: ReverseResearch playbook route <route-id>")
		}
		value, ok, err := service.PlaybookForRoute(args[1])
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("route %q has no playbook; do not force-fit it", args[1])
		}
		return writeJSON(stdout, value)
	default:
		return fmt.Errorf("unknown playbook subcommand %q", args[0])
	}
}

func runToolsCLI(service *researchcore.Service, args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return errors.New("tools subcommand is required: scan or show")
	}
	switch args[0] {
	case "scan":
		if len(args) != 1 {
			return errors.New("usage: ReverseResearch tools scan")
		}
		index, err := service.ScanTools()
		if err != nil {
			return err
		}
		return writeJSON(stdout, index)
	case "show":
		if len(args) != 1 {
			return errors.New("usage: ReverseResearch tools show")
		}
		index, err := service.LoadToolIndex()
		if err != nil {
			return err
		}
		return writeJSON(stdout, index)
	case "ensure":
		if len(args) < 2 {
			return errors.New("usage: ReverseResearch tools ensure <tool> [tool...]")
		}
		plan, err := service.PlanTools(args[1:])
		if err != nil {
			return err
		}
		return writeJSON(stdout, plan)
	default:
		return fmt.Errorf("unknown tools subcommand %q", args[0])
	}
}

func runContractCLI(root string, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("contract subcommand is required: audit")
	}
	switch args[0] {
	case "audit":
		flags := flag.NewFlagSet("contract audit", flag.ContinueOnError)
		flags.SetOutput(stderr)
		snapshot, _ := contractaudit.FindDefaultSnapshot(root)
		flags.StringVar(&snapshot, "snapshot", snapshot, "online RR/RT contract snapshot")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return errors.New("unexpected positional arguments after contract audit")
		}
		if strings.TrimSpace(snapshot) == "" {
			return errors.New("contract audit snapshot is required; default snapshot could not be discovered")
		}
		report, err := contractaudit.Audit(snapshot)
		if err != nil {
			return err
		}
		if err := writeJSON(stdout, report); err != nil {
			return err
		}
		if !report.Match {
			return errors.New("backend tool contract drift detected")
		}
		return nil
	default:
		return fmt.Errorf("unknown contract subcommand %q", args[0])
	}
}

func runCapabilityCLI(service *researchcore.Service, args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return errors.New("capability subcommand is required: status or list")
	}
	switch args[0] {
	case "status":
		if len(args) != 2 {
			return errors.New("usage: ReverseResearch capability status <route-id>")
		}
		status, err := service.CapabilityStatus(args[1])
		if err != nil {
			return err
		}
		return writeJSON(stdout, status)
	case "list":
		if len(args) != 1 {
			return errors.New("usage: ReverseResearch capability list")
		}
		statuses, err := service.CapabilityStatuses()
		if err != nil {
			return err
		}
		return writeJSON(stdout, statuses)
	default:
		return fmt.Errorf("unknown capability subcommand %q", args[0])
	}
}

func runSandboxCLI(service *researchcore.Service, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("sandbox subcommand is required: plan or create")
	}
	switch args[0] {
	case "plan", "create":
		flags := flag.NewFlagSet("sandbox "+args[0], flag.ContinueOnError)
		flags.SetOutput(stderr)
		var name, route, kindRaw string
		flags.StringVar(&name, "name", "", "sandbox name")
		flags.StringVar(&route, "route", "", "optional research route")
		flags.StringVar(&kindRaw, "kind", string(sandbox.KindFilesystem), "filesystem, wsl, or docker")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 || strings.TrimSpace(name) == "" {
			return fmt.Errorf("usage: ReverseResearch sandbox %s --name <text> [--kind filesystem|wsl|docker] [--route <route>]", args[0])
		}
		kind := sandbox.Kind(strings.ToLower(strings.TrimSpace(kindRaw)))
		plan, err := service.PlanSandbox(sandbox.PlanRequest{Name: name, Route: route, Kind: kind})
		if err != nil {
			return err
		}
		if args[0] == "plan" {
			return writeJSON(stdout, plan)
		}
		if !plan.Ready {
			return fmt.Errorf("sandbox is not ready; missing tools: %s", strings.Join(plan.MissingTools, ", "))
		}
		created, err := service.CreateSandbox(plan)
		if err != nil {
			return err
		}
		return writeJSON(stdout, created)
	default:
		return fmt.Errorf("unknown sandbox subcommand %q", args[0])
	}
}

func runCompatibilityCLI(service *researchcore.Service, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("compat subcommand is required: add, import, get, list, or verify")
	}
	switch args[0] {
	case "add":
		flags := flag.NewFlagSet("compat add", flag.ContinueOnError)
		flags.SetOutput(stderr)
		var game, build, modulePath, moduleRole, hookID, hookName, outcome, validation, caseID, evidenceRaw, notes string
		flags.StringVar(&game, "game", "", "game/product name")
		flags.StringVar(&build, "build", "", "game build/version label")
		flags.StringVar(&modulePath, "module", "", "DLL/EXE path to fingerprint")
		flags.StringVar(&moduleRole, "role", "", "optional module role")
		flags.StringVar(&hookID, "hook-id", "", "optional guarded hook record id")
		flags.StringVar(&hookName, "hook-name", "", "optional human hook label")
		flags.StringVar(&outcome, "outcome", string(compatibility.OutcomeUnknown), "unknown|candidate|compatible|incompatible")
		flags.StringVar(&validation, "validation", string(compatibility.ValidationRecordOnly), "record-only|static-verified|runtime-verified")
		flags.StringVar(&caseID, "case-id", "", "optional linked research case")
		flags.StringVar(&evidenceRaw, "evidence", "", "comma-separated case evidence ids")
		flags.StringVar(&notes, "notes", "", "optional notes")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 || strings.TrimSpace(game) == "" || strings.TrimSpace(build) == "" || strings.TrimSpace(modulePath) == "" {
			return errors.New("usage: ReverseResearch compat add --game <name> --build <version> --module <path> [--role <role>] [--hook-id <id>] [--hook-name <name>] [--outcome unknown|candidate|compatible|incompatible] [--validation record-only|static-verified|runtime-verified] [--case-id <id> --evidence <id,id>] [--notes <text>]")
		}
		record, err := service.AddCompatibility(compatibility.AddRequest{
			Game: game, Build: build, ModulePath: modulePath, ModuleRole: moduleRole,
			HookID: hookID, HookName: hookName,
			Outcome: compatibility.Outcome(outcome), Validation: compatibility.Validation(validation),
			CaseID: caseID, EvidenceIDs: splitCSV(evidenceRaw), Notes: notes,
		})
		if err != nil {
			return err
		}
		return writeJSON(stdout, record)

	case "import":
		flags := flag.NewFlagSet("compat import", flag.ContinueOnError)
		flags.SetOutput(stderr)
		var manifest string
		flags.StringVar(&manifest, "manifest", "", "compatibility manifest JSON path")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 || strings.TrimSpace(manifest) == "" {
			return errors.New("usage: ReverseResearch compat import --manifest <path.json>")
		}
		result, err := service.ImportCompatibilityManifest(manifest)
		if err != nil {
			return err
		}
		return writeJSON(stdout, result)

	case "get":
		if len(args) != 2 {
			return errors.New("usage: ReverseResearch compat get <compat-id>")
		}
		record, err := service.GetCompatibility(args[1])
		if err != nil {
			return err
		}
		return writeJSON(stdout, record)

	case "list":
		flags := flag.NewFlagSet("compat list", flag.ContinueOnError)
		flags.SetOutput(stderr)
		var game, build, moduleSHA, hookID, outcome, validation string
		var limit int
		flags.StringVar(&game, "game", "", "optional game filter")
		flags.StringVar(&build, "build", "", "optional build filter")
		flags.StringVar(&moduleSHA, "module-sha", "", "optional module SHA-256 filter")
		flags.StringVar(&hookID, "hook-id", "", "optional hook id filter")
		flags.StringVar(&outcome, "outcome", "", "optional outcome filter")
		flags.StringVar(&validation, "validation", "", "optional validation filter")
		flags.IntVar(&limit, "limit", 100, "maximum records from 1 to 1000")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 || limit < 1 || limit > 1000 {
			return errors.New("usage: ReverseResearch compat list [--game <name>] [--build <version>] [--module-sha <sha256>] [--hook-id <id>] [--outcome <value>] [--validation <value>] [--limit 1..1000]")
		}
		records, err := service.ListCompatibility(compatibility.Filter{
			Game: game, Build: build, ModuleSHA: moduleSHA, HookID: hookID,
			Outcome: compatibility.Outcome(outcome), Validation: compatibility.Validation(validation), Limit: limit,
		})
		if err != nil {
			return err
		}
		return writeJSON(stdout, records)

	case "verify":
		if len(args) != 2 {
			return errors.New("usage: ReverseResearch compat verify <compat-id>")
		}
		result, err := service.VerifyCompatibility(args[1])
		if err != nil {
			return err
		}
		if err := writeJSON(stdout, result); err != nil {
			return err
		}
		if !result.RecordValid {
			return fmt.Errorf("compatibility record verification failed with %d issue(s); see JSON output", len(result.Issues))
		}
		return nil

	default:
		return fmt.Errorf("unknown compat subcommand %q", args[0])
	}
}

func runCaseCLI(service *researchcore.Service, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("case subcommand is required: create, list, show, verify, evidence, finding, path, hypothesis, hypothesis-update, detection, or retest")
	}
	if args[0] == "view" {
		return runCaseResearchViewCLI(service, args[1:], stdout, stderr)
	}
	if handled, err := runCaseV2CLI(service, args, stdout, stderr); handled {
		return err
	}
	switch args[0] {
	case "create":
		flags := flag.NewFlagSet("case create", flag.ContinueOnError)
		flags.SetOutput(stderr)
		var title, route, engagementID, targetsRaw string
		flags.StringVar(&title, "title", "", "case title")
		flags.StringVar(&route, "route", "", "optional research route")
		flags.StringVar(&engagementID, "engagement", "", "optional engagement id")
		flags.StringVar(&targetsRaw, "targets", "", "comma-separated target identities")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 || strings.TrimSpace(title) == "" {
			return errors.New("usage: ReverseResearch case create --title <text> [--route <route>] [--engagement <id>] [--targets <identity,identity>]")
		}
		targets := make([]casebook.Target, 0)
		for index, identity := range splitCSV(targetsRaw) {
			targets = append(targets, casebook.Target{ID: fmt.Sprintf("target_%d", index+1), Identity: identity})
		}
		result, err := service.CreateCase(casebook.CreateRequest{Title: title, Route: route, EngagementID: engagementID, Targets: targets})
		if err != nil {
			return err
		}
		return writeJSON(stdout, result)

	case "show":
		if len(args) != 2 {
			return errors.New("usage: ReverseResearch case show <case-id>")
		}
		result, err := service.GetCase(args[1])
		if err != nil {
			return err
		}
		return writeJSON(stdout, result)

	case "list":
		flags := flag.NewFlagSet("case list", flag.ContinueOnError)
		flags.SetOutput(stderr)
		limit := flags.Int("limit", 20, "maximum results from 1 to 100")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 || *limit < 1 || *limit > 100 {
			return errors.New("usage: ReverseResearch case list [--limit 1..100]")
		}
		result, err := service.ListCases(*limit)
		if err != nil {
			return err
		}
		return writeJSON(stdout, result)

	case "verify":
		if len(args) != 2 {
			return errors.New("usage: ReverseResearch case verify <case-id>")
		}
		result, err := service.VerifyCase(args[1])
		if err != nil {
			return err
		}
		if err := writeJSON(stdout, result); err != nil {
			return err
		}
		if !result.Valid {
			return fmt.Errorf("case verification failed with %d issue(s); see JSON output", len(result.Issues))
		}
		return nil

	case "evidence":
		if len(args) < 2 {
			return errors.New("usage: ReverseResearch case evidence <case-id> --summary <text> [--kind <kind>] [--source <path>] [--notes <text>]")
		}
		caseID := args[1]
		flags := flag.NewFlagSet("case evidence", flag.ContinueOnError)
		flags.SetOutput(stderr)
		var summary, kind, source, notes, observedAt, reproCommand, rawExcerpt, workItemID, supersedesID string
		flags.StringVar(&summary, "summary", "", "evidence summary")
		flags.StringVar(&kind, "kind", "", "evidence kind")
		flags.StringVar(&source, "source", "", "optional source file to hash and bind")
		flags.StringVar(&notes, "notes", "", "optional notes")
		flags.StringVar(&observedAt, "observed-at", "", "optional observation time/reference")
		flags.StringVar(&reproCommand, "repro-command", "", "optional reproduction command or procedure")
		flags.StringVar(&rawExcerpt, "raw-excerpt", "", "optional short raw excerpt")
		flags.StringVar(&workItemID, "workitem", "", "optional linked workitem id")
		flags.StringVar(&supersedesID, "supersedes", "", "optional superseded evidence id")
		if err := flags.Parse(args[2:]); err != nil {
			return err
		}
		if flags.NArg() != 0 || strings.TrimSpace(summary) == "" {
			return errors.New("usage: ReverseResearch case evidence <case-id> --summary <text> [--kind <kind>] [--source <path>] [--notes <text>]")
		}
		result, err := service.AddCaseEvidence(caseID, casebook.EvidenceRequest{
			Summary: summary, Kind: kind, SourcePath: source, Notes: notes,
			ObservedAt: observedAt, ReproCommand: reproCommand, RawExcerpt: rawExcerpt,
			LinkedWorkItemID: workItemID, SupersedesEvidenceID: supersedesID,
		})
		if err != nil {
			return err
		}
		return writeJSON(stdout, result)

	case "finding":
		if len(args) < 2 {
			return errors.New("usage: ReverseResearch case finding <case-id> --title <text> --conclusion <text> [--strength observed|inferred|unverified] [--confidence <level>] [--evidence <id,id>]")
		}
		caseID := args[1]
		flags := flag.NewFlagSet("case finding", flag.ContinueOnError)
		flags.SetOutput(stderr)
		var title, conclusion, strength, confidence, severity, evidenceRaw string
		var cweRaw, capecRaw, cveRaw, attackRaw, affectedAsset, reproducibility, detectionStatus, remediationStatus, retestStatus string
		var category, findingStatus, location, impact, reproStepsRaw, remediation string
		flags.StringVar(&title, "title", "", "finding title")
		flags.StringVar(&conclusion, "conclusion", "", "finding conclusion")
		flags.StringVar(&strength, "strength", "unverified", "claim strength: observed, inferred, or unverified")
		flags.StringVar(&confidence, "confidence", "", "optional confidence label")
		flags.StringVar(&severity, "severity", "", "optional severity")
		flags.StringVar(&cweRaw, "cwe", "", "comma-separated CWE ids")
		flags.StringVar(&capecRaw, "capec", "", "comma-separated CAPEC ids")
		flags.StringVar(&cveRaw, "cve", "", "comma-separated CVE ids")
		flags.StringVar(&attackRaw, "attack", "", "comma-separated ATT&CK technique ids")
		flags.StringVar(&affectedAsset, "affected-asset", "", "affected asset")
		flags.StringVar(&reproducibility, "reproducibility", "", "reproducibility status")
		flags.StringVar(&detectionStatus, "detection-status", "", "detection status")
		flags.StringVar(&remediationStatus, "remediation-status", "", "remediation status")
		flags.StringVar(&retestStatus, "retest-status", "", "retest status")
		flags.StringVar(&category, "category", "", "finding category")
		flags.StringVar(&findingStatus, "status", "", "finding lifecycle status, e.g. candidate|validated|closed")
		flags.StringVar(&location, "location", "", "file/address/url/class/location")
		flags.StringVar(&impact, "impact", "", "impact statement")
		flags.StringVar(&reproStepsRaw, "repro-steps", "", "comma-separated compact reproduction steps")
		flags.StringVar(&remediation, "remediation", "", "remediation guidance")
		flags.StringVar(&evidenceRaw, "evidence", "", "comma-separated evidence IDs")
		if err := flags.Parse(args[2:]); err != nil {
			return err
		}
		if flags.NArg() != 0 || strings.TrimSpace(title) == "" || strings.TrimSpace(conclusion) == "" {
			return errors.New("usage: ReverseResearch case finding <case-id> --title <text> --conclusion <text> [--strength observed|inferred|unverified] [--confidence <level>] [--evidence <id,id>]")
		}
		result, err := service.AddCaseFinding(caseID, casebook.FindingRequest{
			Title: title, Conclusion: conclusion, Strength: strength, Confidence: confidence, Severity: severity,
			CWE: splitCSV(cweRaw), CAPEC: splitCSV(capecRaw), CVE: splitCSV(cveRaw), ATTACK: splitCSV(attackRaw),
			AffectedAsset: affectedAsset, Reproducibility: reproducibility, DetectionStatus: detectionStatus,
			RemediationStatus: remediationStatus, RetestStatus: retestStatus,
			Category: category, Status: findingStatus, Location: location, Impact: impact,
			ReproSteps: splitCSV(reproStepsRaw), Remediation: remediation, EvidenceIDs: splitCSV(evidenceRaw),
		})
		if err != nil {
			return err
		}
		return writeJSON(stdout, result)

	case "path":
		if len(args) < 2 {
			return errors.New("usage: ReverseResearch case path <case-id> --title <text> --details <text> [--findings <id,id>]")
		}
		caseID := args[1]
		flags := flag.NewFlagSet("case path", flag.ContinueOnError)
		flags.SetOutput(stderr)
		var title, details, pathType, start, goal, residualRaw, findingsRaw string
		flags.StringVar(&title, "title", "", "research path title")
		flags.StringVar(&details, "details", "", "research/validation chain")
		flags.StringVar(&pathType, "type", "", "path type, e.g. attack|callflow|solve")
		flags.StringVar(&start, "start", "", "path start state")
		flags.StringVar(&goal, "goal", "", "path goal state")
		flags.StringVar(&residualRaw, "residual-risks", "", "comma-separated residual risks")
		flags.StringVar(&findingsRaw, "findings", "", "comma-separated finding IDs")
		if err := flags.Parse(args[2:]); err != nil {
			return err
		}
		if flags.NArg() != 0 || strings.TrimSpace(title) == "" || strings.TrimSpace(details) == "" {
			return errors.New("usage: ReverseResearch case path <case-id> --title <text> --details <text> [--findings <id,id>]")
		}
		result, err := service.AddCasePath(caseID, casebook.PathRequest{
			Title: title, Details: details, PathType: pathType, Start: start, Goal: goal,
			ResidualRisks: splitCSV(residualRaw), FindingIDs: splitCSV(findingsRaw),
		})
		if err != nil {
			return err
		}
		return writeJSON(stdout, result)

	default:
		return fmt.Errorf("unknown case subcommand %q", args[0])
	}
}

func runJournalCLI(service *researchcore.Service, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("journal subcommand is required: add, show, read, or search")
	}
	switch args[0] {
	case "add":
		flags := flag.NewFlagSet("journal add", flag.ContinueOnError)
		flags.SetOutput(stderr)
		var title, body, route, tagsRaw, domain, architecturesRaw, toolsRaw, operationID string
		var source knowledge.Source
		flags.StringVar(&title, "title", "", "knowledge title")
		flags.StringVar(&body, "body", "", "knowledge body")
		flags.StringVar(&operationID, "operation-id", "", "optional idempotent note creation identity; reuse after an uncertain result")
		flags.StringVar(&route, "route", "", "optional research route")
		flags.StringVar(&tagsRaw, "tags", "", "comma-separated tags")
		flags.StringVar(&domain, "domain", "", "applicability domain, for example native-static")
		flags.StringVar(&architecturesRaw, "arch", "", "comma-separated applicable architectures")
		flags.StringVar(&toolsRaw, "tools", "", "comma-separated applicable tools")
		flags.StringVar(&source.Reference, "source", "", "source reference; requires license and source-revision")
		flags.StringVar(&source.License, "license", "", "source license or explicit unspecified value")
		flags.StringVar(&source.UpstreamRevision, "source-revision", "", "source revision or date")
		flags.StringVar(&source.Engine, "engine", "", "applicable analysis engine")
		flags.StringVar(&source.Version, "target-version", "", "applicable target/engine version")
		flags.StringVar(&source.EvidenceStatus, "evidence-status", "", "author-supplied evidence status; defaults to unverified")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 || strings.TrimSpace(title) == "" || strings.TrimSpace(body) == "" {
			return errors.New("usage: ReverseResearch journal add --title <text> --body <text> [--route <route>] [--tags <tag,tag>] [--domain D] [--arch A] [--tools T]")
		}
		var provenance *knowledge.Source
		if source != (knowledge.Source{}) {
			provenance = &source
		}
		result, err := service.AddKnowledge(knowledge.AddRequest{
			OperationID: operationID,
			Title:       title, Body: body, Route: route, Tags: splitCSV(tagsRaw),
			Domain: domain, Architectures: splitCSV(architecturesRaw), Tools: splitCSV(toolsRaw),
			Source: provenance,
		})
		if err != nil {
			return err
		}
		return writeJSON(stdout, result)

	case "show":
		if len(args) != 2 {
			return errors.New("usage: ReverseResearch journal show <note-id>")
		}
		result, err := service.GetKnowledge(args[1])
		if err != nil {
			return err
		}
		return writeJSON(stdout, result)

	case "read":
		if len(args) < 2 {
			return errors.New("usage: ReverseResearch journal read <note-id> --revision <sha256> [--start-line N] [--max-lines 1..200]")
		}
		request := knowledge.ReadRequest{ID: args[1]}
		flags := flag.NewFlagSet("journal read", flag.ContinueOnError)
		flags.SetOutput(stderr)
		flags.StringVar(&request.Revision, "revision", "", "required revision from search or show")
		flags.IntVar(&request.StartLine, "start-line", 1, "one-based body line")
		flags.IntVar(&request.MaxLines, "max-lines", 80, "maximum lines from 1 to 200")
		if err := flags.Parse(args[2:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return errors.New("unexpected positional arguments after journal read")
		}
		result, err := service.ReadKnowledge(request)
		if err != nil {
			return err
		}
		return writeJSON(stdout, result)

	case "search":
		flags := flag.NewFlagSet("journal search", flag.ContinueOnError)
		flags.SetOutput(stderr)
		request := knowledge.SearchRequest{}
		var architecturesRaw, toolsRaw string
		flags.IntVar(&request.Limit, "limit", 20, "maximum results")
		flags.StringVar(&request.Domain, "domain", "", "exact applicability domain")
		flags.StringVar(&architecturesRaw, "arch", "", "comma-separated architecture filter")
		flags.StringVar(&toolsRaw, "tools", "", "comma-separated tool filter")
		flags.StringVar(&request.Route, "route", "", "exact research route")
		flags.StringVar(&request.Origin, "origin", "all", "all, journal, or builtin")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		request.Query = strings.Join(flags.Args(), " ")
		request.Architectures = splitCSV(architecturesRaw)
		request.Tools = splitCSV(toolsRaw)
		results, err := service.SearchKnowledgeFiltered(request)
		if err != nil {
			return err
		}
		return writeJSON(stdout, results)

	default:
		return fmt.Errorf("unknown journal subcommand %q", args[0])
	}
}

func splitCSV(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}

func runModuleCLI(ctx context.Context, runtime *modules.Runtime, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("module subcommand is required: status or call")
	}
	switch args[0] {
	case "status":
		if len(args) != 1 {
			return errors.New("usage: ReverseResearch module status")
		}
		return writeJSON(stdout, map[string]any{"backends": runtime.Statuses()})
	case "call":
		if len(args) < 3 {
			return errors.New("usage: ReverseResearch module call <x32dbg|ghidra|r2> <tool> [--json <object> | --json-file <path>] [x32dbg guard: --pid N --process-key K --owner O --lease-id L --operation-id ID]")
		}
		return runModuleCallCLI(ctx, runtime, args[1], args[2:], stdout, stderr)
	case "batch":
		return runModuleBatchCLI(ctx, runtime, args[1:], stdout, stderr)
	default:
		return fmt.Errorf("unknown module subcommand %q", args[0])
	}
}

type moduleCaller interface {
	Call(context.Context, string, string, any) (*mcp.CallToolResult, error)
}

func runModuleCallCLI(ctx context.Context, runtime moduleCaller, module string, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("tool name is required for module %s", module)
	}
	tool := args[0]
	flags := flag.NewFlagSet(module+" "+tool, flag.ContinueOnError)
	flags.SetOutput(stderr)
	var rawJSON, jsonFile string
	var guardPID uint64
	var processKey, owner, leaseID, operationID string
	flags.StringVar(&rawJSON, "json", "", "tool arguments as a JSON object")
	flags.StringVar(&jsonFile, "json-file", "", "read tool arguments from a JSON file")
	flags.Uint64Var(&guardPID, "pid", 0, "guarded x32dbg target process ID")
	flags.StringVar(&processKey, "process-key", "", "guarded x32dbg process identity key")
	flags.StringVar(&owner, "owner", "", "guarded x32dbg lease owner")
	flags.StringVar(&leaseID, "lease-id", "", "guarded x32dbg lease identity")
	flags.StringVar(&operationID, "operation-id", "", "guarded x32dbg mutation replay identity")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments after module tool")
	}
	if rawJSON != "" && jsonFile != "" {
		return errors.New("--json and --json-file are mutually exclusive")
	}
	if jsonFile != "" {
		body, err := os.ReadFile(jsonFile)
		if err != nil {
			return fmt.Errorf("read module JSON arguments: %w", err)
		}
		rawJSON = string(body)
	}
	var arguments any = map[string]any{}
	if strings.TrimSpace(rawJSON) != "" {
		if err := json.Unmarshal([]byte(rawJSON), &arguments); err != nil {
			return fmt.Errorf("decode module JSON arguments: %w", err)
		}
		if _, ok := arguments.(map[string]any); !ok {
			return errors.New("module JSON arguments must be an object")
		}
	}

	guardFlagsUsed := guardPID != 0 ||
		strings.TrimSpace(processKey) != "" ||
		strings.TrimSpace(owner) != "" ||
		strings.TrimSpace(leaseID) != "" ||
		strings.TrimSpace(operationID) != ""
	if guardFlagsUsed {
		if module != "x32dbg" {
			return errors.New("x32dbg guard flags are valid only for the x32dbg module")
		}
		switch modules.X32ToolPolicy(tool) {
		case modules.X32ReadOnly:
			return fmt.Errorf("x32dbg tool %s is read-only; guard flags are not accepted", tool)
		case modules.X32Blocked:
			return fmt.Errorf("x32dbg tool %s is blocked and cannot be enabled with guard flags", tool)
		}
		if guardPID == 0 || guardPID > 4294967295 ||
			strings.TrimSpace(processKey) == "" ||
			strings.TrimSpace(owner) == "" ||
			strings.TrimSpace(leaseID) == "" ||
			strings.TrimSpace(operationID) == "" {
			return errors.New("guarded x32dbg mutations require --pid, --process-key, --owner, --lease-id, and --operation-id")
		}
		object := arguments.(map[string]any)
		if tool == "AttachProcess" {
			if _, exists := object["pid"]; !exists {
				object["pid"] = guardPID
			}
		}
		object[modules.X32GuardArgument] = map[string]any{
			"pid":          guardPID,
			"process_key":  strings.TrimSpace(processKey),
			"owner":        strings.TrimSpace(owner),
			"lease_id":     strings.TrimSpace(leaseID),
			"operation_id": strings.TrimSpace(operationID),
		}
	}

	result, err := runtime.Call(ctx, module, tool, arguments)
	if err != nil {
		return err
	}
	value, err := moduleResultValue(result)
	if err != nil {
		return err
	}
	if err := modules.R2ToolResultIssue(module, tool, result); err != nil {
		return err
	}
	return writeJSON(stdout, value)
}

type moduleBatchStep struct {
	Module    string         `json:"module"`
	Tool      string         `json:"tool"`
	Arguments map[string]any `json:"arguments,omitempty"`
}

type moduleBatchResult struct {
	Index  int    `json:"index"`
	Module string `json:"module"`
	Tool   string `json:"tool"`
	Result any    `json:"result"`
}

type moduleBatchFailure struct {
	Index  int                 `json:"index"`
	Module string              `json:"module"`
	Tool   string              `json:"tool"`
	Error  string              `json:"error"`
	Result *mcp.CallToolResult `json:"result,omitempty"`
}

type moduleBatchPartial struct {
	Status     string              `json:"status"`
	Results    []moduleBatchResult `json:"results"`
	Failure    moduleBatchFailure  `json:"failure"`
	Total      int                 `json:"total"`
	Unexecuted int                 `json:"unexecuted"`
}

func runModuleBatchCLI(ctx context.Context, runtime moduleCaller, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("module batch", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var rawJSON, jsonFile string
	flags.StringVar(&rawJSON, "json", "", "batch steps as a JSON array")
	flags.StringVar(&jsonFile, "json-file", "", "read batch steps from a JSON file")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments after module batch")
	}
	if rawJSON != "" && jsonFile != "" {
		return errors.New("--json and --json-file are mutually exclusive")
	}
	if jsonFile != "" {
		body, err := os.ReadFile(jsonFile)
		if err != nil {
			return fmt.Errorf("read module batch JSON: %w", err)
		}
		rawJSON = string(body)
	}
	if strings.TrimSpace(rawJSON) == "" {
		return errors.New("usage: ReverseResearch module batch --json <array> | --json-file <path>")
	}
	steps, err := decodeModuleBatch([]byte(rawJSON))
	if err != nil {
		return err
	}
	results := make([]moduleBatchResult, 0, len(steps))
	for index, step := range steps {
		arguments := step.Arguments
		if arguments == nil {
			arguments = map[string]any{}
		}
		result, err := runtime.Call(ctx, step.Module, step.Tool, arguments)
		var value any
		if err == nil {
			value, err = moduleResultValue(result)
		}
		if err == nil {
			err = modules.R2ToolResultIssue(step.Module, step.Tool, result)
		}
		if err != nil {
			stepErr := fmt.Errorf("batch step %d %s.%s: %w", index, step.Module, step.Tool, err)
			partial := moduleBatchPartial{
				Status: "partial", Results: results,
				Failure: moduleBatchFailure{
					Index: index, Module: step.Module, Tool: step.Tool,
					Error: err.Error(), Result: result,
				},
				Total: len(steps), Unexecuted: len(steps) - index - 1,
			}
			if writeErr := writeJSON(stdout, partial); writeErr != nil {
				return errors.Join(stepErr, writeErr)
			}
			return stepErr
		}
		results = append(results, moduleBatchResult{
			Index: index, Module: step.Module, Tool: step.Tool, Result: value,
		})
	}
	return writeJSON(stdout, results)
}

func decodeModuleBatch(body []byte) ([]moduleBatchStep, error) {
	var steps []moduleBatchStep
	if err := json.Unmarshal(body, &steps); err != nil {
		return nil, fmt.Errorf("decode module batch: %w", err)
	}
	if len(steps) == 0 {
		return nil, errors.New("module batch must contain at least one step")
	}
	for index, step := range steps {
		if step.Module != "x32dbg" && step.Module != "ghidra" && step.Module != "r2" {
			return nil, fmt.Errorf("module batch step %d has invalid module %q", index, step.Module)
		}
		if strings.TrimSpace(step.Tool) == "" {
			return nil, fmt.Errorf("module batch step %d has empty tool", index)
		}
	}
	return steps, nil
}

func moduleResultValue(result *mcp.CallToolResult) (any, error) {
	if result == nil {
		return nil, errors.New("module returned no result")
	}
	var texts []string
	for _, content := range result.Content {
		if item, ok := content.(*mcp.TextContent); ok {
			texts = append(texts, item.Text)
		}
	}
	if result.IsError {
		return nil, fmt.Errorf("module tool error: %s", strings.Join(texts, "\n"))
	}
	if len(result.Meta) > 0 {
		return result, nil
	}
	if result.StructuredContent != nil {
		return result.StructuredContent, nil
	}
	return map[string]any{"text": strings.Join(texts, "\n")}, nil
}

func writeModuleResult(w io.Writer, result *mcp.CallToolResult) error {
	value, err := moduleResultValue(result)
	if err != nil {
		return err
	}
	return writeJSON(w, value)
}

func writeJSON(w io.Writer, value any) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	return encoder.Encode(value)
}

func runStateLayoutCLI(root string, args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return writeJSON(stdout, statecompat.BinaryCapabilities())
	}
	if len(args) != 1 {
		return errors.New("usage: ReverseResearch state-layout [capabilities|status]")
	}
	switch args[0] {
	case "capabilities":
		return writeJSON(stdout, statecompat.BinaryCapabilities())
	case "status":
		status, err := statecompat.Inspect(root)
		if err != nil {
			return err
		}
		return writeJSON(stdout, status)
	default:
		return errors.New("usage: ReverseResearch state-layout [capabilities|status]")
	}
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "ReverseResearch - local-first reverse-engineering toolkit")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  ReverseResearch version")
	fmt.Fprintln(w, "  ReverseResearch state-layout [capabilities|status]")
	fmt.Fprintln(w, "  ReverseResearch target identify <path>")
	fmt.Fprintln(w, "  ReverseResearch target compare <left-path> <right-path>")
	fmt.Fprintln(w, "  ReverseResearch die scan <path> [--timeout 15s] [--verbose] [--deep] [--heuristic] [--all-types] [--entropy] [--info]")
	p1SecurityHelp(w)
	p1ResearchHelp(w)
	p1PurpleHelp(w)
	p2SecurityHelp(w)
	p3ProductHelp(w)
	fmt.Fprintln(w, "  ReverseResearch process inspect <pid>")
	fmt.Fprintln(w, "  ReverseResearch process debug-route <pid>")
	fmt.Fprintln(w, "  ReverseResearch memory scan <pid> --key <process-key> --type u32 (--value N | --unknown) [--start A] [--end B]")
	fmt.Fprintln(w, "  ReverseResearch memory refine <scan-id> --expected-version N --mode <exact|changed|unchanged|increased|decreased> [--value N]")
	fmt.Fprintln(w, "  ReverseResearch memory get <scan-id> [--sample N]")
	fmt.Fprintln(w, "  ReverseResearch pointer scan <pid> --key <process-key> --target <addr> [--start A] [--end B] [--max-offset N] [--max-depth N]")
	fmt.Fprintln(w, "  ReverseResearch pointer get <map-id> [--sample N]")
	fmt.Fprintln(w, "  ReverseResearch pointer verify <map-id> --pid <pid> --key <process-key> [--target <addr>]")
	fmt.Fprintln(w, "  ReverseResearch watch write <pid> --key <process-key> --owner <owner> --lease-id <lease-id> --operation-id <id> --address <addr> [--size N] [--timeout 30s] [--max-events N]")
	fmt.Fprintln(w, "  ReverseResearch process acquire <pid> --key <process-key> --owner <owner>")
	fmt.Fprintln(w, "  ReverseResearch process get <pid>")
	fmt.Fprintln(w, "  ReverseResearch process release <pid> --key <process-key> --owner <owner> --lease-id <lease-id>")
	fmt.Fprintln(w, "  ReverseResearch hook plan --path <pe> --source-rva <rva> --destination-rva <rva> [--expected <hex>]")
	fmt.Fprintln(w, "  ReverseResearch hook get <hook-id> | hook list [--path <pe>] | hook verify <hook-id>")
	fmt.Fprintln(w, "  ReverseResearch hook apply <hook-id> --expected-version N --operation-id <id> --confirm-in-place")
	fmt.Fprintln(w, "  ReverseResearch hook rollback <hook-id> --expected-version N --operation-id <id> | hook cancel <hook-id> --expected-version N")
	fmt.Fprintln(w, "  ReverseResearch compat add --game <name> --build <version> --module <path> [--outcome candidate] [--validation record-only]")
	fmt.Fprintln(w, "  ReverseResearch compat import --manifest <path.json> | compat get <compat-id> | compat list [filters] | compat verify <compat-id>")
	fmt.Fprintln(w, "  ReverseResearch patch plan --path <file> (--offset <n|0xHEX> --expected <hex> --replacement <hex> | --edits-json <array> | --edits-file <path>)")
	fmt.Fprintln(w, "  ReverseResearch patch get <plan-id>")
	fmt.Fprintln(w, "  ReverseResearch patch dry-run <plan-id>")
	fmt.Fprintln(w, "  ReverseResearch patch apply <plan-id> [--in-place | --output <path>] [--operation-id <id>]")
	fmt.Fprintln(w, "  ReverseResearch patch verify <plan-id>")
	fmt.Fprintln(w, "  ReverseResearch patch rollback <plan-id> [--operation-id <id>]")
	fmt.Fprintln(w, "  ReverseResearch diff quick <old-file> <new-file>")
	fmt.Fprintln(w, "  ReverseResearch diff functions <old-file> <new-file> [--threshold 70]")
	fmt.Fprintln(w, "  ReverseResearch diff migrate <old-file> <new-file> --anchors <json-file> [--threshold 70]")
	fmt.Fprintln(w, "  ReverseResearch sync preview --json-file <request.json>")
	fmt.Fprintln(w, "  ReverseResearch route <task text>")
	fmt.Fprintln(w, "  ReverseResearch web backends | web profile --id <id> [--browser chrome|msedge]")
	fmt.Fprintln(w, "  ReverseResearch web cdp --endpoint <http://127.0.0.1:port> | web source <file> | web wasm <file>")
	fmt.Fprintln(w, "  ReverseResearch web sourcemap <map> [--source-index 0] [--offset 0] [--limit 8192] [--expected-sha256 <sha256>]")
	fmt.Fprintln(w, "  ReverseResearch web locate <map> --line 0 --column 0 [--expected-sha256 <sha256>]")
	fmt.Fprintln(w, "  ReverseResearch web har <capture.har> [--offset 0] [--limit 50] [--expected-sha256 <sha256>]")
	fmt.Fprintln(w, "  ReverseResearch web har-api <capture.har> | web har-body <capture.har> --entry-ordinal 0 --side response")
	fmt.Fprintln(w, "  ReverseResearch web har-compare <before.har> --right <after.har> [--expected-sha256 <comparison-sha256>]")
	fmt.Fprintln(w, "  ReverseResearch app analyze <asar-or-directory> | app javascript <js-or-asar> [--entry <packed-js>]")
	fmt.Fprintln(w, "  ReverseResearch app asar <archive> | app read <archive> --entry <name> | app zip <archive> | app zip-read <archive> --entry <name>")
	fmt.Fprintln(w, "  ReverseResearch app tar <tar-or-gzip> | app tar-read <archive> --entry <name>")
	fmt.Fprintln(w, "  ReverseResearch app package <zip/ipa/hap/hsp/app> --family apple|harmony [--view components|bundles]")
	fmt.Fprintln(w, "  ReverseResearch app go-read <executable> [--part header|version|module|module-body] [--limit 8192]")
	fmt.Fprintln(w, "  ReverseResearch ios plist <plist> | ios plist-data <plist> --object-index <id> | ios keyed <plist> | ios nib <nib> [--view values]")
	fmt.Fprintln(w, "  ReverseResearch crash inspect <core> [--view notes|segments|threads|signals] | crash note <core> --note-index <id>")
	fmt.Fprintln(w, "  ReverseResearch app managed <assembly> | app method <assembly> --token 0x06000001 | app go <binary> | app evm <carrier> --encoding hex|raw")
	fmt.Fprintln(w, "  ReverseResearch app compare-managed <before> --right <after> | app compare-javascript <before> --right <after>")
	fmt.Fprintln(w, "  ReverseResearch case view <case-id> [--finding <exact-finding-id>] [--expected-sha256 <case-revision>]")
	fmt.Fprintln(w, "  ReverseResearch web sse <capture.sse> [--offset 0] [--limit 50] [--data-preview-bytes 0] [--expected-sha256 <sha256>]")
	fmt.Fprintln(w, "  ReverseResearch android status | android devices | android probe <serial> | android workspace <serial> | android snapshot <serial>")
	fmt.Fprintln(w, "  ReverseResearch android tap <serial> --snapshot <id> --ui-sha <sha256> --operation-id <id> (--resource-id <id> | --text <text> | --content-desc <text>)")
	fmt.Fprintln(w, "  ReverseResearch prepare <task text>")
	fmt.Fprintln(w, "  ReverseResearch playbook list | playbook show <playbook-id> | playbook route <route-id>")
	fmt.Fprintln(w, "  ReverseResearch domain-pack list | domain-pack show <pack-id> | domain-pack route <route-id> | domain-pack audit <pack-id>")
	fmt.Fprintln(w, "  ReverseResearch knowledge-pack list | knowledge-pack show <pack-id> | knowledge-pack route <route-id>")
	fmt.Fprintln(w, "  ReverseResearch engagement create --organization <name> --operator <id> --targets <t,t> --actions <a,a> --auth-status <status> --network-profile <mode>")
	fmt.Fprintln(w, "  ReverseResearch engagement show <engagement-id> | engagement authorize <engagement-id> --target <target> --action <action>")
	fmt.Fprintln(w, "  ReverseResearch job plan --operation-id <id> --engagement <id> --target <target> --action <action> --effect-class <class>")
	fmt.Fprintln(w, "  ReverseResearch job show <job-id> | job prepare <job-id> --operation-id <id> | job transition <job-id> --operation-id <id> --to <state>")
	fmt.Fprintln(w, "  ReverseResearch tools scan")
	fmt.Fprintln(w, "  ReverseResearch tools show")
	fmt.Fprintln(w, "  ReverseResearch tools ensure <tool> [tool...]   # plan only; does not install")
	fmt.Fprintln(w, "  ReverseResearch contract audit [--snapshot <path>]")
	fmt.Fprintln(w, "  ReverseResearch capability status <route-id>")
	fmt.Fprintln(w, "  ReverseResearch capability list")
	fmt.Fprintln(w, "  ReverseResearch sandbox plan --name <text> [--kind filesystem|wsl|docker] [--route <route>]")
	fmt.Fprintln(w, "  ReverseResearch sandbox create --name <text> [--kind filesystem|wsl|docker] [--route <route>]")
	fmt.Fprintln(w, "  ReverseResearch case create --title <text> [--route <route>] [--engagement <id>] [--targets <identity,identity>]")
	fmt.Fprintln(w, "  ReverseResearch case list [--limit 1..100]")
	fmt.Fprintln(w, "  ReverseResearch case show <case-id>")
	fmt.Fprintln(w, "  ReverseResearch case verify <case-id> | case review <case-id>")
	fmt.Fprintln(w, "  ReverseResearch case evidence <case-id> --summary <text> [--source <path>]")
	fmt.Fprintln(w, "  ReverseResearch case finding <case-id> --title <text> --conclusion <text> [--strength observed|inferred|unverified] [--evidence <id,id>]")
	fmt.Fprintln(w, "  ReverseResearch case path <case-id> --title <text> --details <text> [--findings <id,id>]")
	fmt.Fprintln(w, "  ReverseResearch case hypothesis <case-id> --text <hypothesis> [--support <e,e>] [--conflict <e,e>] [--experiment <text>]")
	fmt.Fprintln(w, "  ReverseResearch case hypothesis-update <case-id> <hypothesis-id> --status <status> [--reason <text>] [--replacement <id>]")
	fmt.Fprintln(w, "  ReverseResearch case detection <case-id> --name <name> --kind <kind> --rule <text> --revision <rev> [--validated ...]")
	fmt.Fprintln(w, "  ReverseResearch case retest <case-id> --subject-type <type> --subject-id <id> --status <status> --summary <text> --evidence <e,e>")
	fmt.Fprintln(w, "  ReverseResearch case role <case-id> --role <role> [--skill <specialist>] [--handoff <condition>]")
	fmt.Fprintln(w, "  ReverseResearch case workitem <case-id> --title <text> [--owner-role <role>] | case workitem-update <case-id> <id> --status <status>")
	fmt.Fprintln(w, "  ReverseResearch case timeline <case-id> --kind <kind> --summary <text> [--workitem <id>] [--job <id>] [--evidence <e,e>]")
	fmt.Fprintln(w, "  ReverseResearch case artifact|observation|vulnerability|ioc|ttp|mitigation|report ...")
	fmt.Fprintln(w, "  ReverseResearch journal add --title <text> --body <text> [--tags <tag,tag>] [--domain D] [--arch A] [--tools T]")
	fmt.Fprintln(w, "  ReverseResearch journal search [--limit N] [--domain D] [--arch A] [--tools T] [--route R] [--origin all|journal|builtin] [query]")
	fmt.Fprintln(w, "  ReverseResearch journal show <note-id>")
	fmt.Fprintln(w, "  ReverseResearch journal read <note-id> --revision <sha256> [--start-line N] [--max-lines 1..200]")
	fmt.Fprintln(w, "  ReverseResearch module status")
	fmt.Fprintln(w, "  ReverseResearch module call <x32dbg|ghidra|r2> <tool> [--json <object> | --json-file <path>] [x32dbg guard flags]")
	fmt.Fprintln(w, "  ReverseResearch module batch --json <array> | --json-file <path>")
	fmt.Fprintln(w, "  ReverseResearch <x32dbg|ghidra|r2> <tool> [--json <object> | --json-file <path>]")
	fmt.Fprintln(w, "  ReverseResearch serve [--listen 127.0.0.1:19100] [--tunnel] [--tunnel-id tunnel_...]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "MCP is optional. Local Core and module commands do not start the ReverseResearch MCP server.")
}
