package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"reverseresearch/internal/appinspect"
	"reverseresearch/internal/targetidentity"
	"reverseresearch/internal/toolprocess"
)

type androidProducers struct {
	aapt2, r8, jdk string
	code           bool
}

func (a androidProducers) enabled() bool { return a.aapt2 != "" || a.r8 != "" || a.jdk != "" }

// This is an owned fixture producer, not a second application ZIP inspector.
// Only pinned local compilers run; the generated APK is unsigned and inert.
func buildAndroidFixture(ctx context.Context, root, work string, a androidProducers) (string, string, error) {
	if a.aapt2 == "" || a.r8 == "" || a.jdk == "" {
		return "", "", errors.New("all three Android producer paths are required")
	}
	for _, path := range []*string{&a.aapt2, &a.r8, &a.jdk} {
		absolute, err := filepath.Abs(*path)
		if err != nil {
			return "", "", err
		}
		*path = absolute
	}
	fixture := filepath.Join(root, "tools", "fixtures", "android")
	java, javac := filepath.Join(a.jdk, "bin", "java.exe"), filepath.Join(a.jdk, "bin", "javac.exe")
	paths := []string{a.aapt2, a.r8, java, javac, filepath.Join(fixture, "OfflineProbe.java"), filepath.Join(fixture, "AndroidManifest.xml"), filepath.Join(fixture, "res", "values", "values.xml"), filepath.Join(fixture, "res", "values-zh", "values.xml")}
	before := make([]targetidentity.Identity, 0, len(paths))
	for _, path := range paths {
		identity, err := targetidentity.Inspect(path)
		if err != nil {
			return "", "", err
		}
		before = append(before, identity)
	}
	dir := filepath.Join(work, "inputs", "android")
	classes, dex := filepath.Join(dir, "classes"), filepath.Join(dir, "dex")
	for _, path := range []string{dir, classes, dex} {
		if err := os.Mkdir(path, 0700); err != nil {
			return "", "", err
		}
	}
	compiled, resourceAPK := filepath.Join(dir, "compiled.zip"), filepath.Join(dir, "resources.apk")
	commands := []struct {
		program string
		args    []string
	}{
		{javac, []string{"--release", "8", "-d", classes, filepath.Join(fixture, "OfflineProbe.java")}},
		{java, []string{"-cp", a.r8, "com.android.tools.r8.D8", "--release", "--min-api", "28", "--output", dex, filepath.Join(classes, "rrfixture", "OfflineProbe.class")}},
		{a.aapt2, []string{"compile", "--dir", filepath.Join(fixture, "res"), "-o", compiled}},
		{a.aapt2, []string{"link", compiled, "--manifest", filepath.Join(fixture, "AndroidManifest.xml"), "-o", resourceAPK}},
		{a.aapt2, []string{"dump", "resources", resourceAPK}},
	}
	observations := []map[string]any{}
	for _, command := range commands {
		r := toolprocess.Run(ctx, command.program, command.args, 64<<10, 64<<10, dir)
		observations = append(observations, map[string]any{"program": command.program, "args": command.args, "stdout": string(r.Stdout), "stderr": string(r.Stderr), "truncated": r.Truncated, "succeeded": r.Err == nil})
		if r.Err != nil || r.Truncated {
			return "", "", fmt.Errorf("Android owned producer failed: %s: %v: %s", command.program, r.Err, r.Stderr)
		}
	}
	apkIdentity, err := targetidentity.Inspect(resourceAPK)
	if err != nil {
		return "", "", err
	}
	if apkIdentity.Size > 32<<20 {
		return "", "", errors.New("owned resource fixture exceeds size bound")
	}
	body, err := os.ReadFile(resourceAPK)
	if err != nil {
		return "", "", err
	}
	if fmt.Sprintf("%x", sha256.Sum256(body)) != apkIdentity.SHA256 {
		return "", "", errors.New("owned resource fixture changed while reading")
	}
	z, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return "", "", err
	}
	var output bytes.Buffer
	w := zip.NewWriter(&output)
	for _, entry := range z.File {
		if entry.Name == "classes.dex" || entry.UncompressedSize64 > 16<<20 {
			return "", "", errors.New("unexpected owned resource fixture member")
		}
		if err := w.Copy(entry); err != nil {
			return "", "", err
		}
	}
	dexBytes, err := os.ReadFile(filepath.Join(dex, "classes.dex"))
	if err != nil {
		return "", "", err
	}
	if len(dexBytes) > 16<<20 {
		return "", "", errors.New("owned DEX fixture exceeds size bound")
	}
	member, err := w.Create("classes.dex")
	if err != nil {
		return "", "", err
	}
	if _, err := member.Write(dexBytes); err != nil {
		return "", "", err
	}
	if err := w.Close(); err != nil {
		return "", "", err
	}
	path := filepath.Join(dir, "offline.apk")
	if err := os.WriteFile(path, output.Bytes(), 0600); err != nil {
		return "", "", err
	}
	for i, path := range paths {
		after, err := targetidentity.Inspect(path)
		if err != nil {
			return "", "", err
		}
		if after.SHA256 != before[i].SHA256 || after.Size != before[i].Size {
			return "", "", fmt.Errorf("Android source/producer changed: %s", path)
		}
	}
	identity, err := targetidentity.Inspect(path)
	if err != nil {
		return "", "", err
	}
	receipt := filepath.Join(dir, "producer-receipt.json")
	err = writeJSON(receipt, map[string]any{"status": "PASS", "source_and_producer_inputs": before, "source_and_producer_currentness_verified": true, "commands": observations, "resource_apk": apkIdentity, "apk": identity, "target_execution_performed": false, "signer_or_install_verified": false})
	return path, receipt, err
}

func (h *harness) androidCase(apk, producerReceipt string) error {
	before, err := targetidentity.Inspect(apk)
	if err != nil {
		return err
	}
	evidence := []string{producerReceipt}
	for _, view := range []string{"components", "manifest", "resources"} {
		var report appinspect.PackageReport
		path, err := h.call("app_package_inspect", map[string]any{"path": apk, "family": "android", "view": view, "expected_sha256": before.SHA256}, &report)
		if err != nil {
			return err
		}
		if report.ExecutionPerformed || report.SHA256 != before.SHA256 {
			return errors.New("Android package identity/effect drift")
		}
		if view == "manifest" && (report.Manifest == nil || report.Manifest.PackageName == nil || *report.Manifest.PackageName != "rrfixture.offline" || !report.ContentVerified) {
			return errors.New("actual AAPT2 manifest not observed")
		}
		if view == "resources" {
			if report.Resources == nil || report.Resources.TotalResourceConfigurations != 8 || !report.ContentVerified {
				return errors.New("actual AAPT2 configuration inventory differs")
			}
			unicode := false
			for _, row := range report.Resources.Resources {
				if row.KeyName != nil && *row.KeyName == "unicode" && row.Value != nil && row.Value.String != nil && row.Value.String.Text != nil && *row.Value.String.Text == "你好😀" {
					unicode = true
				}
			}
			if !unicode {
				return errors.New("actual AAPT2 supplementary string lost")
			}
		}
		evidence = append(evidence, path)
	}
	for offset := 0; offset < 2; offset++ {
		var report appinspect.PackageReport
		path, err := h.call("app_package_inspect", map[string]any{"path": apk, "family": "android", "view": "resource-values", "resource_index": 0, "offset": offset, "limit": 1, "expected_sha256": before.SHA256}, &report)
		if err != nil {
			return err
		}
		if report.Resources == nil || len(report.Resources.Mappings) != 1 || report.Resources.Mappings[0].Index != offset {
			return errors.New("actual AAPT2 bag page differs")
		}
		evidence = append(evidence, path)
	}
	var dex appinspect.DEXReport
	path, err := h.call("app_dex_inspect", map[string]any{"path": apk, "entry": "classes.dex", "view": "methods", "expected_sha256": before.SHA256}, &dex)
	if err != nil {
		return err
	}
	if dex.TotalClasses != 1 || dex.TotalMethods != 8 || dex.DefinedMethods != 4 || dex.ExecutionPerformed || dex.SHA256 != before.SHA256 {
		return errors.New("actual D8 definition/reference inventory differs")
	}
	native := false
	for _, method := range dex.Methods {
		if method.Name == "nativeProbe" && method.Defined && method.NativeDeclared {
			native = true
		}
	}
	if !native {
		return errors.New("D8 native declaration missing")
	}
	evidence = append(evidence, path)
	after, err := targetidentity.Inspect(apk)
	if err != nil {
		return err
	}
	if after.SHA256 != before.SHA256 {
		return errors.New("owned APK changed during static workflow")
	}
	return h.closeCase("Android APK/Manifest/ARSC/DEX 离线研究", "安卓离线 APK Manifest 和 resources.arsc 声明研究，查看 DEX 方法元数据并保留静态证据", "android-static", []string{apk}, evidence, "Observed an unsigned owned APK from actual AAPT2 and D8 producers: eight resource configurations including Chinese/supplementary text and an array, plus four DEX definitions among eight references with a native declaration. Original/member/configuration hashes bind static evidence. No APK installation, device access, signature validity, effective resource selection, native binding, target execution or full decompilation was verified.")
}
