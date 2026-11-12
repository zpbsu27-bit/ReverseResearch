package main

import (
	"bytes"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime/debug"
	"strings"
	"unicode/utf8"

	"reverseresearch/internal/appinspect"
	"reverseresearch/internal/targetidentity"
)

// The standard-library reader is an independent acceptance oracle here only.
// Product summary/records/field views retain their one canonical locator owner.
func (h *harness) goMetadataCase(target string) error {
	target, err := filepath.Abs(target)
	if err != nil {
		return err
	}
	before, err := targetidentity.InspectBounded(target, appinspect.MaxArtifactBytes)
	if err != nil {
		return err
	}
	body, err := os.ReadFile(target)
	if err != nil || goBytesSHA(body) != before.SHA256 {
		return errors.Join(errors.New("owned Go input changed while reading"), err)
	}
	oracle, err := buildinfo.Read(bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("independent Go build-info oracle: %w", err)
	}
	oraclePath := filepath.Join(h.work, "calls", "go-stdlib-oracle.json")
	if err := writeJSON(oraclePath, map[string]any{"target": before, "build_info": oracle, "target_execution_performed": false}); err != nil {
		return err
	}
	if oracle.Path != "example.invalid/rr/go-records-probe" || len(oracle.Deps) != 1 || oracle.Deps[0].Path != "example.invalid/rr/local" || oracle.Deps[0].Replace == nil || oracle.Deps[0].Replace.Path != "./local" {
		return errors.New("Go input does not match the owned local-replacement producer profile")
	}
	quotedSetting := false
	for _, s := range oracle.Settings {
		if s.Key == "-ldflags" && strings.Contains(s.Value, `"main.BuildLabel=quoted label for metadata"`) {
			quotedSetting = true
		}
	}
	if !quotedSetting {
		return errors.New("producer did not embed the quoted linker setting")
	}
	paths := []string{oraclePath}
	var summary appinspect.GoBinaryReport
	p, err := h.call("app_go_inspect", map[string]any{"path": target, "expected_sha256": before.SHA256, "limit": 200}, &summary)
	if err != nil {
		return err
	}
	paths = append(paths, p)
	if summary.SHA256 != before.SHA256 || !summary.BuildInfoAvailable || !summary.ModuleSemanticsAvailable || !summary.GrammarComplete || !summary.TextSummaryComplete || !summary.CoverageComplete || summary.ExecutionPerformed || summary.GoVersion != oracle.GoVersion || summary.PackagePath != oracle.Path || !reflect.DeepEqual(summary.Main, oracle.Main) || !reflect.DeepEqual(summary.Dependencies, oracle.Deps) || !reflect.DeepEqual(summary.Settings, oracle.Settings) {
		return errors.New("actual MCP Go summary differs from the independent compiler-output oracle")
	}
	var records []appinspect.GoModuleRecord
	var bodyRange *appinspect.GoMetadataRange
	for offset := 0; ; {
		var page appinspect.GoMetadataReport
		p, err := h.call("app_go_metadata_read", map[string]any{"path": target, "expected_sha256": before.SHA256, "part": "records", "offset": offset, "limit": 3}, &page)
		if err != nil {
			return err
		}
		paths = append(paths, p)
		if page.SHA256 != before.SHA256 || !page.GrammarComplete || !page.TextSummaryComplete || page.UnparsedRecords != 0 || page.TotalRecords != summary.TotalRecords || len(page.Records) == 0 || page.ExecutionPerformed {
			return errors.New("actual Go record page lost grammar/currentness evidence")
		}
		if bodyRange == nil {
			bodyRange = page.ModuleBodyRange
		}
		for _, record := range page.Records {
			if record.Index != len(records) || record.Range.Offset > uint64(len(body)) || record.Range.Size > uint64(len(body))-record.Range.Offset || record.Range.Basis != "original-file-bytes" || !record.Terminated || (record.Status != "parsed" && !(record.Kind == "blank" && record.Status == "ignored")) {
				return errors.New("Go original record range/order/status differs")
			}
			raw := body[record.Range.Offset : record.Range.Offset+record.Range.Size]
			prefix, err := base64.StdEncoding.DecodeString(record.RawPrefixBase64)
			if err != nil || !bytes.Equal(prefix, raw[:min(len(raw), 256)]) || goBytesSHA(raw) != record.RawSHA256 || utf8.Valid(raw) != record.RawUTF8 {
				return errors.New("Go record raw hash/preview differs from actual file bytes")
			}
			records = append(records, record)
		}
		if page.NextOffset == nil {
			break
		}
		if *page.NextOffset != len(records) || *page.NextOffset <= offset {
			return errors.New("Go records made no paging progress")
		}
		offset = *page.NextOffset
	}
	if len(records) != summary.TotalRecords || bodyRange == nil || bodyRange.Offset > uint64(len(body)) || bodyRange.Size > uint64(len(body))-bodyRange.Offset {
		return errors.New("Go complete record inventory/body range differs")
	}
	var reconstructed []byte
	for _, r := range records {
		if r.BodyOffset != len(reconstructed) || r.Range.Offset != bodyRange.Offset+uint64(len(reconstructed)) {
			return errors.New("Go records do not partition the original module body")
		}
		reconstructed = append(reconstructed, body[r.Range.Offset:r.Range.Offset+r.Range.Size]...)
	}
	if !bytes.Equal(reconstructed, body[bodyRange.Offset:bodyRange.Offset+bodyRange.Size]) {
		return errors.New("Go record inventory failed lossless original-body reconstruction")
	}
	var decodedSettings []debug.BuildSetting
	replacements := 0
	for _, record := range records {
		fields := map[string]string{}
		for _, field := range record.Fields {
			var decoded []byte
			for offset := 0; ; {
				var page appinspect.GoMetadataReport
				p, err := h.call("app_go_metadata_read", map[string]any{"path": target, "expected_sha256": before.SHA256, "part": "record-field", "record_index": record.Index, "field": field.Name, "offset": offset, "limit": 64}, &page)
				if err != nil {
					return err
				}
				paths = append(paths, p)
				chunk, err := base64.StdEncoding.DecodeString(page.DataBase64)
				if err != nil || page.SHA256 != before.SHA256 || page.Record == nil || page.Record.Index != record.Index || page.DecodedField == nil || page.DecodedField.SHA256 != field.SHA256 || len(chunk) != page.ReadBytes {
					return errors.New("Go decoded field page identity/bytes differ")
				}
				decoded = append(decoded, chunk...)
				if page.NextOffset == nil {
					break
				}
				if *page.NextOffset != len(decoded) || *page.NextOffset <= offset {
					return errors.New("Go decoded field made no paging progress")
				}
				offset = *page.NextOffset
			}
			if len(decoded) != field.Bytes || goBytesSHA(decoded) != field.SHA256 || utf8.Valid(decoded) != field.UTF8 {
				return errors.New("Go decoded field total/hash/encoding differs")
			}
			fields[field.Name] = string(decoded)
		}
		if record.Kind == "setting" {
			decodedSettings = append(decodedSettings, debug.BuildSetting{Key: fields["key"], Value: fields["value"]})
		}
		if record.Kind == "replacement" {
			replacements++
			if record.ReplacementOf == nil || *record.ReplacementOf < 0 || *record.ReplacementOf >= record.Index || records[*record.ReplacementOf].Kind != "dependency" || fields["path"] != oracle.Deps[0].Replace.Path || fields["version"] != oracle.Deps[0].Replace.Version || fields["sum"] != oracle.Deps[0].Replace.Sum {
				return errors.New("Go replacement antecedent/decoded fields differ")
			}
		}
	}
	if replacements != 1 || !reflect.DeepEqual(decodedSettings, oracle.Settings) {
		return errors.New("Go decoded settings/replacement coverage differs from the independent oracle")
	}
	for offset := 0; ; {
		var page appinspect.GoMetadataReport
		p, err := h.call("app_go_metadata_read", map[string]any{"path": target, "expected_sha256": before.SHA256, "part": "module-body", "offset": offset, "limit": 128}, &page)
		if err != nil {
			return err
		}
		paths = append(paths, p)
		chunk, err := base64.StdEncoding.DecodeString(page.DataBase64)
		if err != nil || page.Offset != offset || offset+len(chunk) > len(reconstructed) || !bytes.Equal(chunk, reconstructed[offset:offset+len(chunk)]) {
			return errors.New("Go raw byte pages differ from reconstructed record body")
		}
		if page.NextOffset == nil {
			if offset+len(chunk) != len(reconstructed) {
				return errors.New("Go raw byte page total differs")
			}
			break
		}
		if *page.NextOffset != offset+len(chunk) || len(chunk) == 0 {
			return errors.New("Go raw body made no paging progress")
		}
		offset = *page.NextOffset
	}
	after, err := targetidentity.InspectBounded(target, appinspect.MaxArtifactBytes)
	if err != nil || after.SHA256 != before.SHA256 || after.Size != before.Size {
		return errors.Join(errors.New("owned Go input currentness differs"), err)
	}
	return h.closeCase("Go 构建元数据无损研究", "分析 native binary 的结构，保留静态证据并生成研究报告，复核 Go 构建元数据", "native-static", []string{target}, paths, "Actual compiler-produced metadata matches the independent Go standard-library reader. Original module-body records and decoded settings were fully paged and hashed, including a local dependency replacement and quoted linker setting. Embedded declarations remain unauthenticated static evidence; the target was never executed.")
}

func goBytesSHA(body []byte) string {
	h := sha256.Sum256(body)
	return hex.EncodeToString(h[:])
}
