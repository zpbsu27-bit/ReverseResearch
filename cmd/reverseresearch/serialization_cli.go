package main

import (
	"errors"
	"flag"
	"io"
	researchcore "reverseresearch/internal/core"
	"reverseresearch/internal/dfir"
	"reverseresearch/internal/iosinspect"
)

func runAppleSerializationCLI(s *researchcore.Service, args []string, stdout, stderr io.Writer) error {
	if len(args) < 2 {
		return errors.New("usage: ReverseResearch ios <plist|plist-data|keyed|nib> <path> [options]")
	}
	f := flag.NewFlagSet("ios "+args[0], flag.ContinueOnError)
	f.SetOutput(stderr)
	var o iosinspect.InspectOptions
	f.IntVar(&o.Offset, "offset", 0, "zero-based item/byte offset")
	f.IntVar(&o.Limit, "limit", 50, "maximum items, or bytes for plist-data")
	f.StringVar(&o.ExpectedSHA256, "expected-sha256", "", "original artifact digest")
	var root, view string
	var index int
	switch args[0] {
	case "plist":
	case "plist-data":
		f.Set("limit", "8192")
		f.IntVar(&index, "object-index", -1, "exact plist data object index")
	case "keyed":
		f.StringVar(&root, "root", "", "exact named root; filters roots, not the object table")
	case "nib":
		f.StringVar(&view, "view", "objects", "objects or values")
	default:
		return errors.New("unknown Apple serialization command")
	}
	if err := f.Parse(args[2:]); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return errors.New("unexpected Apple serialization arguments")
	}
	var v any
	var err error
	switch args[0] {
	case "plist":
		v, err = s.InspectApplePlist(args[1], o)
	case "plist-data":
		v, err = s.ReadApplePlistData(args[1], iosinspect.PlistDataOptions{InspectOptions: o, ObjectIndex: index})
	case "keyed":
		v, err = s.InspectAppleKeyedArchive(args[1], iosinspect.KeyedArchiveOptions{InspectOptions: o, Root: root})
	case "nib":
		v, err = s.InspectAppleNIB(args[1], iosinspect.NIBOptions{InspectOptions: o, View: view})
	}
	if err != nil {
		return err
	}
	return writeJSON(stdout, v)
}
func runRecordedCoreCLI(s *researchcore.Service, args []string, stdout, stderr io.Writer) error {
	if len(args) < 2 {
		return errors.New("usage: ReverseResearch crash <inspect|note> <core> [options]")
	}
	f := flag.NewFlagSet("crash "+args[0], flag.ContinueOnError)
	f.SetOutput(stderr)
	var o dfir.CoreOptions
	f.IntVar(&o.Offset, "offset", 0, "zero-based item/byte offset")
	f.IntVar(&o.Limit, "limit", 20, "maximum items, or bytes for note")
	f.StringVar(&o.ExpectedSHA256, "expected-sha256", "", "original core digest")
	var part string
	var index int
	if args[0] == "inspect" {
		f.StringVar(&o.View, "view", "notes", "segments, notes, threads or signals")
	} else if args[0] == "note" {
		f.Set("limit", "8192")
		f.IntVar(&index, "note-index", -1, "exact original note index")
		f.StringVar(&part, "part", "descriptor", "owner or descriptor")
	} else {
		return errors.New("unknown recorded core command")
	}
	if err := f.Parse(args[2:]); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return errors.New("unexpected recorded core arguments")
	}
	var v any
	var err error
	if args[0] == "inspect" {
		v, err = s.InspectRecordedCore(args[1], o)
	} else {
		v, err = s.ReadRecordedCoreNote(args[1], dfir.CoreNoteReadOptions{CoreOptions: o, NoteIndex: index, Part: part})
	}
	if err != nil {
		return err
	}
	return writeJSON(stdout, v)
}
