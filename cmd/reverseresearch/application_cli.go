package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"reverseresearch/internal/appinspect"
	"reverseresearch/internal/casebook"
	researchcore "reverseresearch/internal/core"
)

func applicationPageFlags(flags *flag.FlagSet, o *appinspect.PageOptions) {
	flags.IntVar(&o.Offset, "offset", 0, "zero-based inventory offset")
	flags.IntVar(&o.Limit, "limit", 50, "maximum items, 1..200")
	flags.StringVar(&o.ExpectedSHA256, "expected-sha256", "", "artifact digest from previous page")
}

func runCaseResearchViewCLI(service *researchcore.Service, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: ReverseResearch case view <case-id> [--finding <id>] [--offset 0] [--limit 50] [--expected-sha256 <case-revision>]")
	}
	flags := flag.NewFlagSet("case view", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var o casebook.ResearchViewOptions
	flags.StringVar(&o.FindingID, "finding", "", "exact finding ID for a dossier")
	flags.IntVar(&o.Offset, "offset", 0, "zero-based record offset")
	flags.IntVar(&o.Limit, "limit", 50, "maximum records, 1..200")
	flags.StringVar(&o.ExpectedSHA256, "expected-sha256", "", "Case snapshot revision")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected case view arguments")
	}
	v, err := service.CaseResearchView(args[0], o)
	if err != nil {
		return err
	}
	return writeJSON(stdout, v)
}

func runApplicationCLI(ctx context.Context, service *researchcore.Service, args []string, stdout, stderr io.Writer) error {
	if len(args) < 2 {
		return errors.New("usage: ReverseResearch app <analyze|asar|read|javascript|managed|method|go|go-read|evm|zip|zip-read|tar|tar-read|package|dex|android-recover|compare-javascript|compare-managed> <path> [options]")
	}
	flags := flag.NewFlagSet("app "+args[0], flag.ContinueOnError)
	flags.SetOutput(stderr)
	var page appinspect.PageOptions
	var entry, token, encoding, right, leftSHA, rightSHA, family, view, part string
	stringIndex := -1
	resourceIndex := -1
	methodIndex := -1
	recordIndex := -1
	var decodedField, evmResultSHA string
	var recovery appinspect.AndroidRecoveryOptions
	overloadIndex := -1
	applicationPageFlags(flags, &page)
	if args[0] == "read" || args[0] == "zip-read" || args[0] == "tar-read" || args[0] == "go-read" || args[0] == "android-recover" {
		// A default is not an explicitly supplied flag: records needs its own
		// item limit while byte views retain the existing 8192-byte default.
		flags.Lookup("limit").Value.Set("8192")
	}
	switch args[0] {
	case "android-recover":
		flags.StringVar(&recovery.View, "view", "classes", "classes, class, method or references")
		flags.StringVar(&recovery.Query, "query", "", "case-sensitive top-level class name substring")
		flags.StringVar(&recovery.ClassName, "class-name", "", "exact producer class name")
		flags.StringVar(&recovery.MethodName, "method-name", "", "exact parsed method name")
		flags.IntVar(&overloadIndex, "overload-index", -1, "artifact-local same-name overload ordinal")
		flags.StringVar(&recovery.ExpectedResultSHA256, "expected-result-sha256", "", "derived canonical JSON digest for subsequent byte pages")
	case "dex":
		flags.StringVar(&entry, "entry", "", "exact ZIP member, or omit for standalone DEX")
		flags.StringVar(&view, "view", "classes", "classes, methods, strings, string-bytes, instructions, cfg or edges")
		flags.IntVar(&stringIndex, "string-index", -1, "exact string index for string-bytes")
		flags.IntVar(&methodIndex, "method-index", -1, "build-local method index for instructions/cfg/edges")
	case "go-read":
		flags.StringVar(&part, "part", "module", "header/version/module/module-body bytes, records inventory or decoded record-field bytes")
		flags.IntVar(&recordIndex, "record-index", -1, "artifact-local semantic record index for record-field")
		flags.StringVar(&decodedField, "field", "", "path, version, sum, key or value decoded field")
	case "package":
		flags.StringVar(&family, "family", "", "apple, harmony or android")
		flags.StringVar(&view, "view", "components", "components/bundles; Android manifest/resources/resource-values")
		flags.IntVar(&resourceIndex, "resource-index", -1, "exact Android configuration inventory index for resource-values")
	case "read", "zip-read", "tar-read", "javascript":
		flags.StringVar(&entry, "entry", "", "exact archive entry")
	case "method":
		flags.StringVar(&token, "token", "", "build-local MethodDef token, for example 0x06000001")
	case "evm":
		flags.StringVar(&encoding, "encoding", "hex", "EVM carrier encoding: hex or raw")
		flags.StringVar(&view, "view", "instructions", "instructions, interface or interface-bytes")
		flags.StringVar(&evmResultSHA, "expected-result-sha256", "", "exact engine JSON digest for subsequent interface pages")
	case "compare-javascript", "compare-managed":
		flags.StringVar(&right, "right", "", "second artifact")
		flags.StringVar(&leftSHA, "expected-left-sha256", "", "left artifact digest")
		flags.StringVar(&rightSHA, "expected-right-sha256", "", "right artifact digest")
	}
	if err := flags.Parse(args[2:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected app arguments")
	}
	var result any
	var err error
	switch args[0] {
	case "android-recover":
		recovery.PageOptions = page
		flags.Visit(func(f *flag.Flag) {
			if f.Name == "overload-index" {
				recovery.OverloadIndex = &overloadIndex
			}
		})
		result, err = service.RecoverAndroid(ctx, args[1], recovery)
	case "dex":
		var selected *int
		var selectedMethod *int
		limitSet := false
		flags.Visit(func(f *flag.Flag) {
			if f.Name == "string-index" {
				selected = &stringIndex
			}
			if f.Name == "method-index" {
				selectedMethod = &methodIndex
			}
			if f.Name == "limit" {
				limitSet = true
			}
		})
		if view == "string-bytes" && !limitSet {
			page.Limit = 8192
		}
		result, err = service.InspectDEX(args[1], appinspect.DEXOptions{PageOptions: page, Entry: entry, View: view, StringIndex: selected, MethodIndex: selectedMethod})
	case "go-read":
		var selectedRecord *int
		limitSet := false
		flags.Visit(func(f *flag.Flag) {
			if f.Name == "record-index" {
				selectedRecord = &recordIndex
			}
			if f.Name == "limit" {
				limitSet = true
			}
		})
		if part == "records" && !limitSet {
			page.Limit = 50
		}
		result, err = service.ReadGoMetadata(args[1], appinspect.GoMetadataOptions{PageOptions: page, Part: part, RecordIndex: selectedRecord, Field: decodedField})
	case "package":
		var selected *int
		flags.Visit(func(f *flag.Flag) {
			if f.Name == "resource-index" {
				selected = &resourceIndex
			}
		})
		result, err = service.InspectApplicationPackage(args[1], appinspect.PackageOptions{PageOptions: page, Family: family, View: view, ResourceIndex: selected})
	case "analyze":
		result, err = service.InspectApplication(args[1], page)
	case "asar":
		result, err = service.InspectASAR(args[1], page)
	case "read":
		result, err = service.ReadASAR(args[1], appinspect.EntryReadOptions{Entry: entry, Offset: page.Offset, Limit: page.Limit, ExpectedSHA256: page.ExpectedSHA256})
	case "javascript":
		result, err = service.InspectJavaScript(args[1], appinspect.JavaScriptOptions{PageOptions: page, Entry: entry})
	case "managed":
		result, err = service.InspectManaged(args[1], page)
	case "method":
		result, err = service.InspectManagedMethod(args[1], appinspect.ManagedMethodOptions{PageOptions: page, Token: token})
	case "go":
		result, err = service.InspectGoBinary(args[1], page)
	case "evm":
		limitSet := false
		flags.Visit(func(f *flag.Flag) {
			if f.Name == "limit" {
				limitSet = true
			}
		})
		if view == "interface-bytes" && !limitSet {
			page.Limit = 8192
		}
		result, err = service.InspectEVM(ctx, args[1], appinspect.EVMOptions{PageOptions: page, Encoding: encoding, View: view, ExpectedResultSHA256: evmResultSHA})
	case "zip":
		result, err = service.InspectZIP(args[1], page)
	case "zip-read":
		result, err = service.ReadZIP(args[1], appinspect.EntryReadOptions{Entry: entry, Offset: page.Offset, Limit: page.Limit, ExpectedSHA256: page.ExpectedSHA256})
	case "tar":
		result, err = service.InspectTAR(args[1], page)
	case "tar-read":
		result, err = service.ReadTAR(args[1], appinspect.EntryReadOptions{Entry: entry, Offset: page.Offset, Limit: page.Limit, ExpectedSHA256: page.ExpectedSHA256})
	case "compare-javascript":
		result, err = service.CompareJavaScript(args[1], right, appinspect.CompareOptions{PageOptions: page, ExpectedLeftSHA256: leftSHA, ExpectedRightSHA256: rightSHA})
	case "compare-managed":
		result, err = service.CompareManaged(args[1], right, appinspect.CompareOptions{PageOptions: page, ExpectedLeftSHA256: leftSHA, ExpectedRightSHA256: rightSHA})
	default:
		return errors.New("unknown app command")
	}
	if err != nil {
		return err
	}
	return writeJSON(stdout, result)
}
