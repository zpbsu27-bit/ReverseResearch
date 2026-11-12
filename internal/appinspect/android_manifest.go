package appinspect

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

const androidNamespace = "http://schemas.android.com/apk/res/android"

type AndroidAttribute struct {
	Namespace  string              `json:"namespace"`
	Name       string              `json:"name"`
	ResourceID *uint32             `json:"resource_id,omitempty"`
	Raw        *AndroidStringValue `json:"raw,omitempty"`
	Typed      *AndroidValue       `json:"typed,omitempty"`
}
type AndroidElement struct {
	Index        int                `json:"element_index"`
	Parent       *int               `json:"parent_index"`
	Depth        int                `json:"depth"`
	Namespace    string             `json:"namespace"`
	Name         string             `json:"name"`
	Role         string             `json:"role"`
	SourceOffset int                `json:"source_offset"`
	SourceBytes  int                `json:"source_bytes"`
	Line         *uint32            `json:"line,omitempty"`
	Attributes   []AndroidAttribute `json:"attributes"`
}
type AndroidManifestReport struct {
	Encoding                     string           `json:"encoding"`
	PackageName                  *string          `json:"package_name"`
	TotalElements                int              `json:"total_elements"`
	PermissionDeclarations       int              `json:"permission_declarations"`
	ComponentDeclarations        int              `json:"component_declarations"`
	Offset                       int              `json:"offset"`
	NextOffset                   *int             `json:"next_offset,omitempty"`
	Elements                     []AndroidElement `json:"elements"`
	CoverageComplete             bool             `json:"coverage_complete"`
	EffectivePermissionsVerified bool             `json:"effective_permissions_verified"`
	Limitations                  []string         `json:"limitations"`
}

func androidElementRole(namespace, name string) string {
	if namespace != "" {
		return "xml-element"
	}
	switch name {
	case "uses-permission", "uses-permission-sdk-23":
		return "permission-declaration"
	case "activity", "activity-alias", "service", "receiver", "provider":
		return "component-declaration"
	case "uses-sdk":
		return "sdk-declaration"
	case "uses-feature":
		return "feature-declaration"
	case "application":
		return "application-declaration"
	case "manifest":
		return "manifest-declaration"
	}
	return "xml-element"
}

func inspectAndroidManifest(body []byte, o PageOptions) (AndroidManifestReport, error) {
	r := AndroidManifestReport{Limitations: []string{"manifest elements/attributes are declarations, not granted permissions, component reachability or observed execution", "typed and raw values are preserved separately; resource references/defaults/SDK-conditional values are not resolved", "element parent indexes and byte ranges refer to this exact captured member; no app installation, XML entity fetching or target execution"}}
	if len(body) > 16<<20 {
		return r, errors.New("Android manifest exceeds 16 MiB")
	}
	var elements []AndroidElement
	var err error
	trimmed := bytes.TrimSpace(bytes.TrimPrefix(body, []byte{0xef, 0xbb, 0xbf}))
	if len(trimmed) > 0 && trimmed[0] == '<' {
		r.Encoding = "xml-utf8"
		elements, err = parseAndroidTextXML(body)
	} else {
		r.Encoding = "android-binary-xml"
		elements, err = parseAndroidBinaryXML(body)
	}
	if err != nil {
		return r, err
	}
	if len(elements) == 0 || elements[0].Name != "manifest" || elements[0].Namespace != "" {
		return r, errors.New("Android manifest requires one unqualified manifest root")
	}
	for _, a := range elements[0].Attributes {
		if a.Name == "package" && a.Namespace == "" {
			v := a.Raw
			if a.Typed != nil && a.Typed.Type == 3 {
				v = a.Typed.String
			}
			if v != nil && v.UTF8Available && v.TextComplete && v.Text != nil {
				r.PackageName = v.Text
			}
		}
	}
	for _, e := range elements {
		if e.Role == "permission-declaration" {
			r.PermissionDeclarations++
		}
		if e.Role == "component-declaration" {
			r.ComponentDeclarations++
		}
	}
	r.TotalElements = len(elements)
	start, end, err := page(o, len(elements))
	if err != nil {
		return r, err
	}
	r.Offset = start
	r.Elements = elements[start:end]
	r.CoverageComplete = start == 0 && end == len(elements)
	if end < len(elements) {
		r.NextOffset = &end
	}
	return r, nil
}

func parseAndroidTextXML(body []byte) ([]AndroidElement, error) {
	if !utf8.Valid(body) {
		return nil, errors.New("plain Android XML requires UTF-8")
	}
	decoder := xml.NewDecoder(bytes.NewReader(body))
	elements := []AndroidElement{}
	stack := []int{}
	closedRoot := false
	attributes := 0
	for {
		start := decoder.InputOffset()
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		switch v := token.(type) {
		case xml.Directive:
			return nil, errors.New("XML directives/DOCTYPE are not admitted")
		case xml.ProcInst:
			if v.Target != "xml" {
				return nil, errors.New("XML processing instruction is not admitted")
			}
		case xml.StartElement:
			if closedRoot || len(elements) >= 100000 || len(stack) >= 128 || len(v.Attr) > 256 || len(v.Name.Local) > 4096 || len(v.Name.Space) > 4096 {
				return nil, errors.New("Android XML root/count/depth/name/attribute budget exceeded")
			}
			e := AndroidElement{Index: len(elements), Depth: len(stack), Namespace: v.Name.Space, Name: v.Name.Local, Role: androidElementRole(v.Name.Space, v.Name.Local), SourceOffset: int(start), SourceBytes: int(decoder.InputOffset() - start), Attributes: []AndroidAttribute{}}
			if len(stack) > 0 {
				parent := stack[len(stack)-1]
				e.Parent = &parent
			}
			seen := map[xml.Name]bool{}
			for _, a := range v.Attr {
				if a.Name.Space == "xmlns" || a.Name.Space == "" && a.Name.Local == "xmlns" {
					continue
				}
				if seen[a.Name] || len(a.Name.Local) > 4096 || len(a.Name.Space) > 4096 {
					return nil, errors.New("duplicate/oversized Android XML attribute")
				}
				seen[a.Name] = true
				attributes++
				if attributes > 1<<20 {
					return nil, errors.New("Android XML attributes exceed 1M")
				}
				text := a.Value
				complete := true
				runes := []rune(text)
				if len(runes) > 1024 {
					text = string(runes[:1024])
					complete = false
				}
				raw := &AndroidStringValue{Text: &text, TextComplete: complete, UTF8Available: true, UTF16Units: len(utf16.Encode([]rune(a.Value))), Offset: e.SourceOffset, Bytes: e.SourceBytes, SHA256: digest(body[e.SourceOffset : e.SourceOffset+e.SourceBytes]), RangeBasis: "xml-start-tag; value normalized by XML decoder"}
				e.Attributes = append(e.Attributes, AndroidAttribute{Namespace: a.Name.Space, Name: a.Name.Local, Raw: raw})
			}
			elements = append(elements, e)
			stack = append(stack, e.Index)
		case xml.EndElement:
			if len(stack) == 0 {
				return nil, errors.New("unbalanced Android XML end")
			}
			stack = stack[:len(stack)-1]
			if len(stack) == 0 {
				closedRoot = true
			}
		case xml.CharData:
			if len(stack) == 0 && strings.TrimSpace(string(v)) != "" {
				return nil, errors.New("Android XML text outside root")
			}
		}
	}
	if len(stack) != 0 || !closedRoot {
		return nil, errors.New("incomplete Android XML root")
	}
	return elements, nil
}

func parseAndroidBinaryXML(body []byte) ([]AndroidElement, error) {
	root, err := androidChunkAt(body, 0)
	if err != nil {
		return nil, err
	}
	if root.kind != 3 || root.header != 8 || root.size != len(body) {
		return nil, errors.New("Android binary XML root/header/size invalid")
	}
	var pool *androidPool
	budget := &androidBudget{}
	resourceMap := []uint32{}
	mapSeen := false
	elements := []AndroidElement{}
	stack := []int{}
	closedRoot := false
	attrs := 0
	chunks := 0
	type namespaceFrame struct {
		prefix, uri string
		depth       int
	}
	namespaces := []namespaceFrame{}
	for at := root.header; at < root.size; {
		c, err := androidChunkAt(body, at)
		if err != nil {
			return nil, err
		}
		at += c.size
		chunks++
		if chunks > 300000 {
			return nil, errors.New("Android XML chunk count exceeds budget")
		}
		if c.kind == 1 {
			if pool != nil || len(elements) > 0 {
				return nil, errors.New("Android XML duplicate/late string pool")
			}
			pool, err = parseAndroidPool(c, body, budget)
			if err != nil {
				return nil, err
			}
			continue
		}
		if pool == nil {
			return nil, errors.New("Android XML node precedes string pool")
		}
		if c.kind == 0x180 {
			if mapSeen || len(elements) > 0 || c.header != 8 || (c.size-c.header)/4 > len(pool.strings) {
				return nil, errors.New("Android XML resource map invalid/duplicate/late")
			}
			mapSeen = true
			for pos := c.header; pos < c.size; pos += 4 {
				resourceMap = append(resourceMap, u32(c.body[pos:]))
			}
			continue
		}
		if c.header < 16 {
			return nil, errors.New("Android XML node header truncated")
		}
		line := u32(c.body[8:])
		if _, err := pool.name(u32(c.body[12:]), true); err != nil {
			return nil, err
		}
		ext := c.body[c.header:]
		switch c.kind {
		case 0x100, 0x101:
			if len(ext) < 8 {
				return nil, errors.New("Android namespace extension truncated")
			}
			prefix, err := pool.name(u32(ext), true)
			if err != nil {
				return nil, err
			}
			uri, err := pool.name(u32(ext[4:]), false)
			if err != nil {
				return nil, err
			}
			f := namespaceFrame{prefix, uri, len(stack)}
			if c.kind == 0x100 {
				if closedRoot || len(namespaces) >= 256 {
					return nil, errors.New("Android namespace scope/count invalid")
				}
				namespaces = append(namespaces, f)
			} else {
				if len(namespaces) == 0 || namespaces[len(namespaces)-1] != f {
					return nil, errors.New("Android namespace end does not match start")
				}
				namespaces = namespaces[:len(namespaces)-1]
			}
		case 0x102:
			if closedRoot || len(ext) < 20 || len(elements) >= 100000 || len(stack) >= 128 {
				return nil, errors.New("Android start element/count/depth invalid")
			}
			ns, err := pool.name(u32(ext), true)
			if err != nil {
				return nil, err
			}
			name, err := pool.name(u32(ext[4:]), false)
			if err != nil || name == "" {
				return nil, errors.New("Android element name invalid")
			}
			first, width, count := int(u16(ext[8:])), int(u16(ext[10:])), int(u16(ext[12:]))
			if first < 20 || width < 20 || count > 256 || uint64(first)+uint64(width)*uint64(count) > uint64(len(ext)) {
				return nil, errors.New("Android attribute table outside start node")
			}
			for _, pos := range []int{14, 16, 18} {
				if int(u16(ext[pos:])) > count {
					return nil, errors.New("Android id/class/style attribute index invalid")
				}
			}
			attrs += count
			if attrs > 1<<20 {
				return nil, errors.New("Android XML attributes exceed 1M")
			}
			e := AndroidElement{Index: len(elements), Depth: len(stack), Namespace: ns, Name: name, Role: androidElementRole(ns, name), SourceOffset: c.start, SourceBytes: c.size, Line: &line, Attributes: []AndroidAttribute{}}
			if len(stack) > 0 {
				parent := stack[len(stack)-1]
				e.Parent = &parent
			}
			seen := map[[2]string]bool{}
			for j := 0; j < count; j++ {
				a := ext[first+j*width:]
				ans, err := pool.name(u32(a), true)
				if err != nil {
					return nil, err
				}
				idx := u32(a[4:])
				aname, err := pool.name(idx, false)
				if err != nil || aname == "" {
					return nil, errors.New("Android attribute name invalid")
				}
				key := [2]string{ans, aname}
				if seen[key] {
					return nil, errors.New("duplicate Android attribute")
				}
				seen[key] = true
				v := AndroidAttribute{Namespace: ans, Name: aname}
				if int(idx) < len(resourceMap) {
					id := resourceMap[idx]
					v.ResourceID = &id
				}
				raw := u32(a[8:])
				if raw != 0xffffffff {
					v.Raw, err = pool.value(raw)
					if err != nil {
						return nil, err
					}
				}
				typed, err := androidTypedValue(a[12:], pool)
				if err != nil {
					return nil, err
				}
				v.Typed = &typed
				e.Attributes = append(e.Attributes, v)
			}
			elements = append(elements, e)
			stack = append(stack, e.Index)
		case 0x103:
			if len(ext) < 8 || len(stack) == 0 {
				return nil, errors.New("Android end element truncated/unbalanced")
			}
			ns, err := pool.name(u32(ext), true)
			if err != nil {
				return nil, err
			}
			name, err := pool.name(u32(ext[4:]), false)
			if err != nil {
				return nil, err
			}
			last := elements[stack[len(stack)-1]]
			if ns != last.Namespace || name != last.Name {
				return nil, errors.New("Android end element does not match start")
			}
			stack = stack[:len(stack)-1]
			if len(stack) == 0 {
				closedRoot = true
			}
		case 0x104:
			if len(ext) < 12 || len(stack) == 0 {
				return nil, errors.New("Android CDATA outside element")
			}
			if _, err := pool.value(u32(ext)); err != nil {
				return nil, err
			}
			if _, err := androidTypedValue(ext[4:], pool); err != nil {
				return nil, err
			}
		default:
			return nil, androidUnknownChunk(c.kind)
		}
	}
	if pool == nil || len(stack) != 0 || len(namespaces) != 0 || !closedRoot {
		return nil, errors.New("Android XML has incomplete root/namespace scopes")
	}
	return elements, nil
}
