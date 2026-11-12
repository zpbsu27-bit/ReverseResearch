// Package testfixture constructs inert format vectors without calling an
// inspected target, CLR, Electron, an ASAR writer or the production parsers.
package testfixture

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"strconv"
)

func ASAR(header string, content []byte) []byte {
	n := (len(header) + 3) &^ 3
	out := make([]byte, 16+n+len(content))
	binary.LittleEndian.PutUint32(out[0:4], 4)
	binary.LittleEndian.PutUint32(out[4:8], uint32(n+8))
	binary.LittleEndian.PutUint32(out[8:12], uint32(n+4))
	binary.LittleEndian.PutUint32(out[12:16], uint32(len(header)))
	copy(out[16:], header)
	copy(out[16+n:], content)
	return out
}
func JavaScriptASAR() []byte {
	a := []byte(`import {send} from './bridge.js'; function feature(){return fetch('/search');} ipcRenderer.invoke('search', 'fixture');`)
	b := []byte(`export function send(value){return value;}`)
	header, _ := json.Marshal(map[string]any{"files": map[string]any{"main.js": map[string]any{"size": len(a), "offset": "0"}, "bridge.js": map[string]any{"size": len(b), "offset": strconv.Itoa(len(a))}, "external.js": map[string]any{"size": 5, "unpacked": true}, "link.js": map[string]any{"link": "outside.js"}}})
	return ASAR(string(header), append(a, b...))
}

func JavaScriptPackageASAR() []byte {
	main := []byte(`import '#entry'; require('pkg');`)
	root := []byte(`{"imports":{"#entry":"./esm.mjs"}}`)
	dependency := []byte(`{"exports":{"require":"./index.cjs","import":"./index.mjs"}}`)
	payload := append(append(append([]byte{}, main...), root...), dependency...)
	empty := map[string]any{"size": 0, "offset": strconv.Itoa(len(payload))}
	header, _ := json.Marshal(map[string]any{"files": map[string]any{
		"main.js":      map[string]any{"size": len(main), "offset": "0"},
		"package.json": map[string]any{"size": len(root), "offset": strconv.Itoa(len(main))},
		"esm.mjs":      empty,
		"node_modules": map[string]any{"files": map[string]any{"pkg": map[string]any{"files": map[string]any{
			"package.json": map[string]any{"size": len(dependency), "offset": strconv.Itoa(len(main) + len(root))}, "index.cjs": empty, "index.mjs": empty,
		}}}},
	}})
	return ASAR(string(header), payload)
}

// Managed emits one inert PE32/CLI image with exact expected declarations:
// Example.Program::Value -> declared call MethodDef 2 (Native), one P/Invoke.
// ECMA-335 row bytes and PE offsets are fixed independently of appinspect.
func Managed(value byte) []byte {
	var stringsHeap bytes.Buffer
	stringsHeap.WriteByte(0)
	index := map[string]uint16{}
	for _, s := range []string{"Demo.dll", "Program", "Example", "Value", "Native", "Demo", "kernel32.dll", "GetTickCount"} {
		index[s] = uint16(stringsHeap.Len())
		stringsHeap.WriteString(s)
		stringsHeap.WriteByte(0)
	}
	var tables bytes.Buffer
	w16 := func(n uint16) { binary.Write(&tables, binary.LittleEndian, n) }
	w32 := func(n uint32) { binary.Write(&tables, binary.LittleEndian, n) }
	w32(0)
	tables.Write([]byte{2, 0, 0, 1})
	binary.Write(&tables, binary.LittleEndian, uint64(1<<0|1<<2|1<<6|1<<26|1<<28|1<<32))
	binary.Write(&tables, binary.LittleEndian, uint64(0))
	for _, n := range []uint32{1, 1, 2, 1, 1, 1} {
		w32(n)
	}
	// Module row; TypeDef with FieldList=1, MethodList=1.
	w16(0)
	w16(index["Demo.dll"])
	w16(1)
	w16(0)
	w16(0)
	w32(1)
	w16(index["Program"])
	w16(index["Example"])
	w16(0)
	w16(1)
	w16(1)
	w32(0x2800)
	w16(0)
	w16(0x16)
	w16(index["Value"])
	w16(1)
	w16(1)
	w32(0)
	w16(1)
	w16(0x2016)
	w16(index["Native"])
	w16(1)
	w16(1)
	w16(index["kernel32.dll"])
	w16(0)
	w16(5)
	w16(index["GetTickCount"])
	w16(1)
	// Assembly row: hash algorithm, version, flags, key, name, culture.
	w32(0)
	w16(1)
	w16(0)
	w16(0)
	w16(0)
	w32(0)
	w16(0)
	w16(index["Demo"])
	w16(0)
	streams := []struct {
		name string
		body []byte
	}{{"#~", tables.Bytes()}, {"#Strings", stringsHeap.Bytes()}, {"#Blob", []byte{0, 3, 0, 0, 8}}, {"#GUID", []byte{0x78, 0x56, 0x34, 0x12, 0xbc, 0x9a, 0xf0, 0xde, 1, 2, 3, 4, 5, 6, 7, 8}}}
	var root bytes.Buffer
	root.WriteString("BSJB")
	binary.Write(&root, binary.LittleEndian, uint16(1))
	binary.Write(&root, binary.LittleEndian, uint16(1))
	binary.Write(&root, binary.LittleEndian, uint32(0))
	binary.Write(&root, binary.LittleEndian, uint32(12))
	root.Write([]byte("v4.0.30319\x00\x00"))
	binary.Write(&root, binary.LittleEndian, uint16(0))
	binary.Write(&root, binary.LittleEndian, uint16(len(streams)))
	headerBytes := root.Len()
	for _, s := range streams {
		headerBytes += 8 + (len(s.name)+1+3)&^3
	}
	cursor := headerBytes
	for _, s := range streams {
		binary.Write(&root, binary.LittleEndian, uint32(cursor))
		binary.Write(&root, binary.LittleEndian, uint32(len(s.body)))
		root.WriteString(s.name)
		root.WriteByte(0)
		for root.Len()%4 != 0 {
			root.WriteByte(0)
		}
		cursor += len(s.body)
	}
	for _, s := range streams {
		root.Write(s.body)
	}
	out := make([]byte, 4096)
	put16 := func(p int, n uint16) { binary.LittleEndian.PutUint16(out[p:p+2], n) }
	put32 := func(p int, n uint32) { binary.LittleEndian.PutUint32(out[p:p+4], n) }
	copy(out, "MZ")
	put32(0x3c, 0x80)
	copy(out[0x80:], "PE\x00\x00")
	put16(0x84, 0x14c)
	put16(0x86, 1)
	put16(0x94, 224)
	put16(0x96, 0x2102)
	p := 0x98
	put16(p, 0x10b)
	put32(p+28, 0x400000)
	put32(p+32, 0x2000)
	put32(p+36, 0x200)
	put32(p+56, 0x4000)
	put32(p+60, 0x200)
	put32(p+92, 16)
	put32(p+96+14*8, 0x2000)
	put32(p+100+14*8, 72)
	s := p + 224
	copy(out[s:], ".text")
	put32(s+8, 0xe00)
	put32(s+12, 0x2000)
	put32(s+16, 0xe00)
	put32(s+20, 0x200)
	put32(s+36, 0x60000020)
	put32(0x200, 72)
	put16(0x204, 2)
	put16(0x206, 5)
	put32(0x208, 0x2100)
	put32(0x20c, uint32(root.Len()))
	put32(0x210, 1)
	put32(0x214, 0x06000001)
	copy(out[0x300:], root.Bytes())
	copy(out[0xa00:], []byte{8<<2 | 2, 0x1f, value, 0x28, 2, 0, 0, 6, 0x2a})
	return out
}
