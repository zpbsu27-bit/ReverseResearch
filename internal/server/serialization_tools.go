package server

import (
	"context"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"reverseresearch/internal/appinspect"
	"reverseresearch/internal/dfir"
	"reverseresearch/internal/iosinspect"
)

func (r *Runtime) addSerializationTools() {
	for _, spec := range []struct {
		name, description string
		run               func(string, iosinspect.InspectOptions) (any, error)
	}{
		{"apple_plist_inspect", "Page one inert XML/bplist00 object table bound to the original file SHA-256. Retains exact typed integers, IEEE bits, data hashes and shared object references; bounded previews never instantiate Foundation classes.", func(p string, o iosinspect.InspectOptions) (any, error) { return r.core.InspectApplePlist(p, o) }},
		{"app_tar_inspect", "Page a local TAR/gzip TAR inventory after complete path/header/member range and gzip CRC checks. Links/special/sparse remain unavailable; no extraction or target execution.", func(p string, o iosinspect.InspectOptions) (any, error) {
			return r.core.InspectTAR(p, appinspect.PageOptions{Offset: o.Offset, Limit: o.Limit, ExpectedSHA256: o.ExpectedSHA256})
		}},
	} {
		r.addTool(&mcp.Tool{Name: spec.name, Description: spec.description, InputSchema: applicationSchema(nil)}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			var a struct {
				Path string `json:"path"`
				iosinspect.InspectOptions
			}
			if err := decodeArguments(request, &a); err != nil {
				return nil, err
			}
			v, err := spec.run(a.Path, a.InspectOptions)
			if err != nil {
				return nil, err
			}
			return structuredResult(v)
		})
	}
	r.addTool(&mcp.Tool{Name: "app_tar_read", Description: "Read at most 16384 selected regular TAR member bytes as base64 with original carrier/content digests. Decoding is bounded; links/special/sparse remain unavailable. Does not extract or execute.", InputSchema: applicationSchema(map[string]any{"entry": map[string]any{"type": "string", "minLength": 1}, "limit": map[string]any{"type": "integer", "minimum": 1, "maximum": 16384}}, "entry")}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var a struct {
			Path string `json:"path"`
			appinspect.EntryReadOptions
		}
		if err := decodeArguments(request, &a); err != nil {
			return nil, err
		}
		v, err := r.core.ReadTAR(a.Path, a.EntryReadOptions)
		if err != nil {
			return nil, err
		}
		return structuredResult(v)
	})
	r.addTool(&mcp.Tool{Name: "apple_plist_data_read", Description: "Read explicit selected plist data object bytes, including empty data, with snapshot/content digests and byte paging. XML/bplist00 only; no external entities or class instantiation.", InputSchema: applicationSchema(map[string]any{"object_index": map[string]any{"type": "integer", "minimum": 0}, "limit": map[string]any{"type": "integer", "minimum": 1, "maximum": 16384}}, "object_index")}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var a struct {
			Path string `json:"path"`
			iosinspect.PlistDataOptions
		}
		if err := decodeArguments(request, &a); err != nil {
			return nil, err
		}
		v, err := r.core.ReadApplePlistData(a.Path, a.PlistDataOptions)
		if err != nil {
			return nil, err
		}
		return structuredResult(v)
	})
	r.addTool(&mcp.Tool{Name: "apple_keyed_archive_inspect", Description: "Inspect inert NSKeyedArchiver serialized roots/classes/UID references and page original $objects indices. Cycles, nil and unresolved links remain explicit; root filters roots only. No Foundation decoding or target execution.", InputSchema: applicationSchema(map[string]any{"root": map[string]any{"type": "string"}})}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var a struct {
			Path string `json:"path"`
			iosinspect.KeyedArchiveOptions
		}
		if err := decodeArguments(request, &a); err != nil {
			return nil, err
		}
		v, err := r.core.InspectAppleKeyedArchive(a.Path, a.KeyedArchiveOptions)
		if err != nil {
			return nil, err
		}
		return structuredResult(v)
	})
	r.addTool(&mcp.Tool{Name: "apple_nib_inspect", Description: "Page compiled NIBArchive v1 object/value table declarations, exact integer/float representations and serialized object references. Preserves opaque class extensions; no UIKit construction or rendered UI claims.", InputSchema: applicationSchema(map[string]any{"view": map[string]any{"type": "string", "enum": []string{"objects", "values"}}})}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var a struct {
			Path string `json:"path"`
			iosinspect.NIBOptions
		}
		if err := decodeArguments(request, &a); err != nil {
			return nil, err
		}
		v, err := r.core.InspectAppleNIB(a.Path, a.NIBOptions)
		if err != nil {
			return nil, err
		}
		return structuredResult(v)
	})
	r.addTool(&mcp.Tool{Name: "crash_core_inspect", Description: "Read an ELF64 amd64 LE System V/Linux ABI-v0 recorded core snapshot; page segments/notes/threads/signals. Exact CORE PRSTATUS/SIGINFO semantics and all 27 registers retain source ranges. Historical PID never selects or authorizes a live process.", InputSchema: applicationSchema(map[string]any{"view": map[string]any{"type": "string", "enum": []string{"segments", "notes", "threads", "signals"}}})}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var a struct {
			Path string `json:"path"`
			dfir.CoreOptions
		}
		if err := decodeArguments(request, &a); err != nil {
			return nil, err
		}
		v, err := r.core.InspectRecordedCore(a.Path, a.CoreOptions)
		if err != nil {
			return nil, err
		}
		return structuredResult(v)
	})
	r.addTool(&mcp.Tool{Name: "crash_core_note_read", Description: "Read at most 16384 raw bytes from an exact recorded core note owner/descriptor with snapshot/content digests. Opaque note bytes retain their original meaning as unknown; never attaches to a historical PID.", InputSchema: applicationSchema(map[string]any{"note_index": map[string]any{"type": "integer", "minimum": 0}, "part": map[string]any{"type": "string", "enum": []string{"owner", "descriptor"}}, "limit": map[string]any{"type": "integer", "minimum": 1, "maximum": 16384}}, "note_index")}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var a struct {
			Path string `json:"path"`
			dfir.CoreNoteReadOptions
		}
		if err := decodeArguments(request, &a); err != nil {
			return nil, err
		}
		v, err := r.core.ReadRecordedCoreNote(a.Path, a.CoreNoteReadOptions)
		if err != nil {
			return nil, err
		}
		return structuredResult(v)
	})
}
