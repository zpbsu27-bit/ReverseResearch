package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"reverseresearch/internal/appinspect"
	"reverseresearch/internal/targetidentity"
	"reverseresearch/internal/toolprocess"
)

func buildAndroidCodeFixture(ctx context.Context, root, work string, a androidProducers) (string, string, error) {
	java, javac := filepath.Join(a.jdk, "bin", "java.exe"), filepath.Join(a.jdk, "bin", "javac.exe")
	source := filepath.Join(root, "tools", "fixtures", "android", "OfflineCodeProbe.java")
	paths := []string{java, javac, a.r8, source}
	before := []targetidentity.Identity{}
	for _, path := range paths {
		v, err := targetidentity.Inspect(path)
		if err != nil {
			return "", "", err
		}
		before = append(before, v)
	}
	dir := filepath.Join(work, "inputs", "android-code")
	classes, dex := filepath.Join(dir, "classes"), filepath.Join(dir, "dex")
	for _, path := range []string{classes, dex} {
		if err := os.MkdirAll(path, 0700); err != nil {
			return "", "", err
		}
	}
	observations := []map[string]any{}
	for _, command := range []struct {
		program string
		args    []string
	}{
		{javac, []string{"--release", "8", "-d", classes, source}},
		{java, []string{"-cp", a.r8, "com.android.tools.r8.D8", "--release", "--min-api", "28", "--output", dex, filepath.Join(classes, "demo", "OfflineCodeProbe.class")}},
	} {
		r := toolprocess.Run(ctx, command.program, command.args, 64<<10, 64<<10, dir)
		observations = append(observations, map[string]any{"program": command.program, "args": command.args, "stdout": string(r.Stdout), "stderr": string(r.Stderr), "truncated": r.Truncated, "succeeded": r.Err == nil})
		if r.Err != nil || r.Truncated {
			return "", "", fmt.Errorf("owned Android code producer failed: %v: %s", r.Err, r.Stderr)
		}
	}
	for i, path := range paths {
		v, err := targetidentity.Inspect(path)
		if err != nil || v.SHA256 != before[i].SHA256 {
			return "", "", errors.New("Android code producer/source drift")
		}
	}
	target := filepath.Join(dex, "classes.dex")
	id, err := targetidentity.Inspect(target)
	if err != nil {
		return "", "", err
	}
	receipt := filepath.Join(dir, "producer-receipt.json")
	err = writeJSON(receipt, map[string]any{"status": "PASS", "source_and_producer_inputs": before, "source_and_producer_currentness_verified": true, "commands": observations, "dex": id, "target_execution_performed": false})
	return target, receipt, err
}

// Supply immutable analysis inputs to the same isolated installation. Lifecycle
// remains in the original server/SDK backend owner; this does not start workers.
func installAndroidRecovery(root, work, jdk string) error {
	inputs := []map[string]any{}
	for _, name := range []string{
		filepath.Join("runtime", "android", "jadx-headless", "0.7.1", "jadx-headless-mcp-0.7.1-all.jar"),
		filepath.Join("patches", "jadx", "ReverseResearchJadxBridge.java"),
	} {
		source, destination := filepath.Join(root, name), filepath.Join(work, name)
		before, err := targetidentity.Inspect(source)
		if err != nil {
			return err
		}
		body, err := os.ReadFile(source)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(destination), 0700); err != nil {
			return err
		}
		if err := os.WriteFile(destination, body, 0600); err != nil {
			return err
		}
		copy, err := targetidentity.Inspect(destination)
		if err != nil || copy.SHA256 != before.SHA256 {
			return errors.New("JADX profile copy changed identity")
		}
		after, err := targetidentity.Inspect(source)
		if err != nil || after.SHA256 != before.SHA256 {
			return errors.New("JADX profile source changed during supply")
		}
		inputs = append(inputs, map[string]any{"source": before, "copy": copy, "source_currentness_verified": true})
	}
	if jdk != "" {
		if err := os.CopyFS(filepath.Join(work, "runtime", "ghidra", "java", "acceptance-jdk"), os.DirFS(jdk)); err != nil {
			return fmt.Errorf("supply existing full JDK: %w", err)
		}
	}
	return writeJSON(filepath.Join(work, "headless-profile-supply.json"), map[string]any{"status": "PASS", "inputs": inputs, "existing_full_jdk": jdk, "worker_started": false})
}

func (h *harness) assertJADXWorkClosed() error {
	deadline := time.Now().Add(40 * time.Second)
	for {
		paths, err := filepath.Glob(filepath.Join(h.work, "state", "tmp", "rr-jadx-*"))
		if err != nil {
			return err
		}
		if len(paths) == 0 {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("owned JADX workspace cleanup unverified: %v", paths)
		}
		select {
		case <-h.ctx.Done():
			return h.ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func (h *harness) androidCodeCase(dexPath, producerReceipt string) error {
	before, err := targetidentity.Inspect(dexPath)
	if err != nil {
		return err
	}
	evidence := []string{}
	if producerReceipt != "" {
		evidence = append(evidence, producerReceipt)
	}
	var methods appinspect.DEXReport
	path, err := h.call("app_dex_inspect", map[string]any{"path": dexPath, "view": "methods", "expected_sha256": before.SHA256, "limit": 200}, &methods)
	if err != nil {
		return err
	}
	evidence = append(evidence, path)
	counts := map[string]int{}
	for _, method := range methods.Methods {
		if !method.Defined {
			continue
		}
		for _, view := range []string{"instructions", "cfg", "edges"} {
			for offset := 0; ; {
				var code appinspect.DEXReport
				path, err := h.call("app_dex_inspect", map[string]any{"path": dexPath, "view": view, "method_index": method.Index, "offset": offset, "limit": 200, "expected_sha256": before.SHA256}, &code)
				if err != nil {
					return err
				}
				if code.Method == nil || code.Method.Descriptor != method.Descriptor || code.SHA256 != before.SHA256 || code.ExecutionPerformed {
					return errors.New("DEX selected code identity drift")
				}
				evidence = append(evidence, path)
				for _, row := range code.Instructions {
					counts[row.Mnemonic]++
				}
				if code.NextOffset == nil {
					break
				}
				offset = *code.NextOffset
			}
		}
	}
	for _, name := range []string{"packed-switch", "sparse-switch", "fill-array-data", "move-exception", "invoke-virtual", "const-wide", "invoke-static"} {
		if counts[name] == 0 {
			return fmt.Errorf("actual D8 did not exercise %s", name)
		}
	}
	className := "demo.OfflineCodeProbe"
	recover := func(args map[string]any) (appinspect.AndroidRecoveryReport, map[string]any, error) {
		args["path"], args["expected_sha256"] = dexPath, before.SHA256
		var report appinspect.AndroidRecoveryReport
		path, err := h.call("app_android_recover", args, &report)
		if err != nil {
			return report, nil, err
		}
		evidence = append(evidence, path)
		if !report.CleanupVerified || report.ExecutionPerformed || report.SHA256 != before.SHA256 || report.EngineSHA256 == "" || report.JavaVersion == "" {
			return report, nil, errors.New("JADX recovery/lifecycle/producer evidence missing")
		}
		if err := h.assertJADXWorkClosed(); err != nil {
			return report, nil, err
		}
		body, err := base64.StdEncoding.DecodeString(report.DataBase64)
		if err != nil {
			return report, nil, err
		}
		var value map[string]any
		if err := json.Unmarshal(body, &value); err != nil {
			return report, nil, err
		}
		return report, value, nil
	}
	_, classes, err := recover(map[string]any{"view": "classes", "query": "OfflineCode"})
	if err != nil {
		return err
	}
	rows, ok := classes["matching_rows"].([]any)
	if !ok || len(rows) != 1 || rows[0] != className {
		return errors.New("JADX discovery differs from owned class")
	}
	_, summary, err := recover(map[string]any{"view": "class", "class_name": className})
	if err != nil {
		return err
	}
	if summary["method_count"] != float64(11) {
		return errors.New("JADX parsed methods lost native/initializer/overloads")
	}
	for _, name := range []string{"dense", "nativeProbe", "<clinit>"} {
		_, method, err := recover(map[string]any{"view": "method", "class_name": className, "method_name": name})
		if err != nil {
			return err
		}
		body, _ := method["body"].(string)
		if name == "dense" && (method["mode"] != "java" || method["code_available"] != true || !strings.Contains(body, "switch") || !strings.Contains(body, "37")) {
			return errors.New("JADX actual Java body missing")
		}
		if name == "nativeProbe" && method["code_available"] != false {
			return errors.New("JADX invented native method code")
		}
		if name == "<clinit>" && (method["mode"] != "smali" || method["fell_back"] != true || !strings.Contains(body, "<clinit>")) {
			return errors.New("folded initializer not retained as exact smali")
		}
	}
	ids := map[string]bool{}
	for ordinal := 0; ordinal < 2; ordinal++ {
		_, method, err := recover(map[string]any{"view": "method", "class_name": className, "method_name": "overload", "overload_index": ordinal})
		if err != nil {
			return err
		}
		id, _ := method["producer_short_id"].(string)
		if id == "" || ids[id] || method["overload_count"] != float64(2) {
			return errors.New("JADX overload identities collapsed")
		}
		ids[id] = true
	}
	_, refs, err := recover(map[string]any{"view": "references", "class_name": className, "method_name": "dense"})
	if err != nil {
		return err
	}
	if refs["total"] != float64(1) {
		return errors.New("actual static caller reference missing")
	}
	_, _, err = recover(map[string]any{"view": "references", "class_name": className})
	if err != nil {
		return err
	}
	var page appinspect.AndroidRecoveryReport
	path, err = h.call("app_android_recover", map[string]any{"path": dexPath, "view": "method", "class_name": className, "method_name": "dense", "limit": 16, "expected_sha256": before.SHA256}, &page)
	if err != nil {
		return err
	}
	evidence = append(evidence, path)
	if page.ReadBytes != 16 || page.NextOffset == nil || !page.CleanupVerified {
		return errors.New("JADX first byte page incomplete")
	}
	var second appinspect.AndroidRecoveryReport
	path, err = h.call("app_android_recover", map[string]any{"path": dexPath, "view": "method", "class_name": className, "method_name": "dense", "offset": *page.NextOffset, "limit": 16, "expected_sha256": before.SHA256, "expected_result_sha256": page.ResultSHA256}, &second)
	if err != nil {
		return err
	}
	evidence = append(evidence, path)
	if second.ReadBytes != 16 || second.ResultSHA256 != page.ResultSHA256 || !second.CleanupVerified {
		return errors.New("JADX derived byte pages changed identity")
	}
	for _, args := range []map[string]any{
		{"view": "method", "class_name": className, "method_name": "overload"},
		{"view": "references", "class_name": className, "method_name": "overload"},
		{"view": "class", "class_name": "demo.Missing"},
		{"view": "method", "class_name": className, "method_name": "dense", "expected_result_sha256": strings.Repeat("0", 64)},
	} {
		args["path"], args["expected_sha256"] = dexPath, before.SHA256
		if err := h.rejectAndroidRecovery(h.ctx, args, &evidence); err != nil {
			return err
		}
	}
	cancelCtx, cancel := context.WithTimeout(h.ctx, time.Second)
	err = h.rejectAndroidRecovery(cancelCtx, map[string]any{"path": dexPath, "view": "classes", "expected_sha256": before.SHA256}, &evidence)
	cancel()
	if err != nil {
		return err
	}
	if err := h.assertJADXWorkClosed(); err != nil {
		return err
	}
	after, err := targetidentity.Inspect(dexPath)
	if err != nil || after.SHA256 != before.SHA256 {
		return errors.New("DEX changed during actual code recovery")
	}
	return h.closeCase("Android DEX 指令与代码恢复", "android code recovery dex code recovery jadx recovery 安卓代码恢复，恢复方法及静态引用", "android-code", []string{dexPath}, evidence, "Observed original D8 instruction bytes, structural CFG and possible exception edges, plus pinned JADX parsed identities, two distinct overloads, native code absence, static initializer smali and one static incoming caller. Byte pages bind artifact and derived digests. Rejected ambiguous/stale requests and cancelled worker startup cleanly. No target execution, ART type verification, runtime calls, JNI binding, installation or signer verification was performed.")
}

func (h *harness) rejectAndroidRecovery(ctx context.Context, args map[string]any, evidence *[]string) error {
	r, err := h.session.CallTool(ctx, &mcp.CallToolParams{Name: "app_android_recover", Arguments: args})
	if err == nil && (r == nil || !r.IsError) {
		return errors.New("JADX invalid/cancelled request returned success")
	}
	h.sequence++
	path := filepath.Join(h.work, "calls", fmt.Sprintf("%03d-android-rejected.json", h.sequence))
	message := ""
	if err != nil {
		message = err.Error()
	}
	if err := writeJSON(path, map[string]any{"arguments": args, "result": r, "transport_error": message, "expected_rejection": true}); err != nil {
		return err
	}
	*evidence = append(*evidence, path)
	return h.assertJADXWorkClosed()
}
