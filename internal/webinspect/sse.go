package webinspect

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

const (
	MaxSSEBytes        = 32 << 20
	DefaultSSEPageSize = 50
	MaxSSEPageSize     = 200
	MaxSSEPreviewBytes = 4096
	maxSSELineBytes    = 1 << 20
	maxSSEDataBytes    = 4 << 20
	maxSSEEvents       = 100000
	maxSSEPageBytes    = 48 << 10
)

type SSEOptions struct {
	Offset           int    `json:"offset"`
	Limit            int    `json:"limit"`
	DataPreviewBytes int    `json:"data_preview_bytes"`
	ExpectedSHA256   string `json:"expected_sha256,omitempty"`
}

type SSEEvent struct {
	Ordinal           int     `json:"ordinal"`
	StartByte         int     `json:"start_byte"`
	EndByte           int     `json:"end_byte"`
	StartLine         int     `json:"start_line"`
	EndLine           int     `json:"end_line"`
	EventType         string  `json:"event_type"`
	LastEventIDBytes  int     `json:"last_event_id_bytes"`
	LastEventIDSHA256 string  `json:"last_event_id_sha256"`
	DataBytes         int     `json:"data_bytes"`
	DataLines         int     `json:"data_lines"`
	DataSHA256        string  `json:"data_sha256"`
	DoneMarker        bool    `json:"done_marker"`
	DataPreview       *string `json:"data_preview,omitempty"`
	PreviewTruncated  bool    `json:"preview_truncated"`
}

type SSEReport struct {
	Path                  string     `json:"path"`
	SHA256                string     `json:"sha256"`
	Bytes                 int        `json:"bytes"`
	ValidationProfile     string     `json:"validation_profile"`
	EvidenceAuthority     string     `json:"evidence_authority"`
	TotalEvents           int        `json:"total_events"`
	Offset                int        `json:"offset"`
	ReturnedEvents        int        `json:"returned_events"`
	OmittedEvents         int        `json:"omitted_events"`
	NextOffset            *int       `json:"next_offset,omitempty"`
	Events                []SSEEvent `json:"events"`
	CommentLines          int        `json:"comment_lines"`
	IgnoredFields         int        `json:"ignored_fields"`
	RetryFields           int        `json:"retry_fields"`
	IgnoredIDFields       int        `json:"ignored_id_fields"`
	DoneMarkerCount       int        `json:"done_marker_count"`
	PendingDataAtEOF      bool       `json:"pending_data_at_eof"`
	UndispatchedTailBytes int        `json:"undispatched_tail_bytes"`
	EndedOnBlockBoundary  bool       `json:"ended_on_block_boundary"`
	CoverageComplete      bool       `json:"coverage_complete"`
	Truncated             bool       `json:"truncated"`
	PageBytesLimit        int        `json:"page_bytes_limit"`
	DataPreviewBytes      int        `json:"data_preview_bytes"`
	ApplicationCompletion string     `json:"application_completion"`
	Limitations           []string   `json:"limitations"`
	ExecutionPerformed    bool       `json:"execution_performed"`
	NetworkInteraction    bool       `json:"network_interaction"`
}

// InspectSSE projects a retained UTF-8 event-stream body. Parsing follows SSE
// field/block rules; it does not interpret provider JSON or reconnect/replay.
func InspectSSE(path string, options SSEOptions) (SSEReport, error) {
	if options.Limit == 0 {
		options.Limit = DefaultSSEPageSize
	}
	if options.Offset < 0 || options.Offset > maxSSEEvents || options.Limit < 1 || options.Limit > MaxSSEPageSize {
		return SSEReport{}, errors.New("SSE offset must be 0..100000; limit must be 1..200 events")
	}
	if options.DataPreviewBytes < 0 || options.DataPreviewBytes > MaxSSEPreviewBytes {
		return SSEReport{}, errors.New("SSE data_preview_bytes must be 0..4096; zero omits payload previews")
	}
	body, absolute, digest, err := readBoundedFile(path, MaxSSEBytes)
	if err != nil {
		return SSEReport{}, err
	}
	if err := checkExpectedSHA256(digest, options.ExpectedSHA256); err != nil {
		return SSEReport{}, err
	}
	if !utf8.Valid(body) {
		return SSEReport{}, errors.New("SSE summary profile requires valid UTF-8")
	}
	report := SSEReport{
		Path: absolute, SHA256: digest, Bytes: len(body),
		ValidationProfile: "rr.sse-summary.v1", EvidenceAuthority: "historical-artifact-bytes",
		Offset: options.Offset, Events: make([]SSEEvent, 0, options.Limit),
		PageBytesLimit: maxSSEPageBytes, DataPreviewBytes: options.DataPreviewBytes,
		ApplicationCompletion: "unverified",
		Limitations: []string{
			"Only emitted data events are paged; comments/control fields are counted. Pending EOF data is not dispatched.",
			"Valid UTF-8 is required, unlike browser replacement decoding. Input/line/data/event/page limits are enforced.",
			"Hashes describe joined SSE data; byte spans describe original blocks and include their blank-line delimiter.",
			"IDs and data are omitted by default; event labels and requested data prefixes may contain sensitive content.",
			"EOF and [DONE] do not prove application completion, server identity or tool execution; no JSON translation, replay or reconnect occurs.",
		},
	}
	cursor := 0
	if bytes.HasPrefix(body, []byte{0xef, 0xbb, 0xbf}) {
		cursor = 3
	}
	blockStart, blockLine, lineNumber := cursor, 1, 0
	lastID, eventType := "", ""
	var data strings.Builder
	dataLines, pageBytes, pageFull := 0, 0, false
	for cursor < len(body) {
		lineNumber++
		start := cursor
		for cursor < len(body) && body[cursor] != '\r' && body[cursor] != '\n' {
			cursor++
		}
		if cursor-start > maxSSELineBytes {
			return SSEReport{}, fmt.Errorf("SSE line %d exceeds 1 MiB", lineNumber)
		}
		line := string(body[start:cursor])
		if cursor < len(body) {
			separator := body[cursor]
			cursor++
			if separator == '\r' && cursor < len(body) && body[cursor] == '\n' {
				cursor++
			}
		}
		if line == "" {
			if dataLines > 0 {
				if report.TotalEvents >= maxSSEEvents {
					return SSEReport{}, errors.New("SSE exceeds 100000 emitted events")
				}
				text := data.String()
				text = text[:len(text)-1] // remove only the final data-field LF
				typeName := eventType
				if typeName == "" {
					typeName = "message"
				}
				event := SSEEvent{
					Ordinal: report.TotalEvents, StartByte: blockStart, EndByte: cursor,
					StartLine: blockLine, EndLine: lineNumber, EventType: typeName,
					LastEventIDBytes: len(lastID), LastEventIDSHA256: sseTextDigest(lastID),
					DataBytes: len(text), DataLines: dataLines, DataSHA256: sseTextDigest(text),
					DoneMarker: text == "[DONE]",
				}
				if event.DoneMarker {
					report.DoneMarkerCount++
				}
				if event.Ordinal >= options.Offset && event.Ordinal < options.Offset+options.Limit && !pageFull {
					if options.DataPreviewBytes > 0 {
						end := min(len(text), options.DataPreviewBytes)
						for end > 0 && end < len(text) && !utf8.RuneStart(text[end]) {
							end--
						}
						preview := text[:end]
						event.DataPreview, event.PreviewTruncated = &preview, end < len(text)
					}
					encoded, err := json.Marshal(event)
					if err != nil {
						return SSEReport{}, err
					}
					if len(encoded)+1 > maxSSEPageBytes {
						return SSEReport{}, fmt.Errorf("SSE event %d exceeds page byte budget", event.Ordinal)
					}
					if pageBytes+len(encoded)+1 > maxSSEPageBytes {
						pageFull = true
					} else {
						pageBytes += len(encoded) + 1
						report.Events = append(report.Events, event)
					}
				}
				report.TotalEvents++
			}
			data.Reset()
			dataLines, eventType = 0, ""
			blockStart, blockLine = cursor, lineNumber+1
			continue
		}
		if strings.HasPrefix(line, ":") {
			report.CommentLines++
			continue
		}
		field, value, found := strings.Cut(line, ":")
		if !found {
			value = ""
		} else {
			value = strings.TrimPrefix(value, " ") // one optional ASCII space
		}
		switch field {
		case "data":
			if data.Len()+len(value)+1 > maxSSEDataBytes {
				return SSEReport{}, fmt.Errorf("SSE block at byte %d exceeds 4 MiB joined data", blockStart)
			}
			data.WriteString(value)
			data.WriteByte('\n')
			dataLines++
		case "event":
			if len(value) > 1024 {
				return SSEReport{}, fmt.Errorf("SSE event label at line %d exceeds 1024 bytes", lineNumber)
			}
			eventType = value
		case "id":
			if len(value) > 4096 {
				return SSEReport{}, fmt.Errorf("SSE id at line %d exceeds 4096 bytes", lineNumber)
			}
			if strings.ContainsRune(value, '\x00') {
				report.IgnoredIDFields++
			} else {
				lastID = value
			}
		case "retry":
			report.RetryFields++ // retained control occurrence; no reconnect owner here
		default:
			report.IgnoredFields++
		}
	}
	if options.Offset > report.TotalEvents {
		return SSEReport{}, errors.New("SSE offset is outside emitted events")
	}
	report.PendingDataAtEOF = dataLines > 0
	report.UndispatchedTailBytes = len(body) - blockStart
	report.EndedOnBlockBoundary = blockStart == len(body)
	report.ReturnedEvents = len(report.Events)
	report.OmittedEvents = report.TotalEvents - report.ReturnedEvents
	report.CoverageComplete = report.OmittedEvents == 0 && !report.PendingDataAtEOF
	report.Truncated = !report.CoverageComplete
	next := options.Offset + report.ReturnedEvents
	if next < report.TotalEvents {
		report.NextOffset = &next
	}
	return report, nil
}

func sseTextDigest(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}
