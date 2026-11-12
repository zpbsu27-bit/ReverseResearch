package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"strings"
	"time"

	researchcore "reverseresearch/internal/core"
	"reverseresearch/internal/webinspect"
)

func runWebCLI(ctx context.Context, service *researchcore.Service, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("web subcommand is required: backends, profile, cdp, source, sourcemap, har, sse, or wasm")
	}
	switch args[0] {
	case "har-api", "har-body", "har-compare":
		return runHARViewCLI(service, args, stdout, stderr)
	case "locate":
		if len(args) < 2 {
			return errors.New("usage: ReverseResearch web locate <map> --line 0 --column 0 [--expected-sha256 <sha256>]")
		}
		flags := flag.NewFlagSet("web locate", flag.ContinueOnError)
		flags.SetOutput(stderr)
		var o webinspect.SourceMapLocateOptions
		flags.IntVar(&o.Line, "line", 0, "zero-based generated line")
		flags.IntVar(&o.Column, "column", 0, "zero-based UTF-16 generated column")
		flags.StringVar(&o.ExpectedSHA256, "expected-sha256", "", "map digest")
		if err := flags.Parse(args[2:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return errors.New("unexpected web locate arguments")
		}
		r, err := service.LocateWebSourceMap(args[1], o)
		if err != nil {
			return err
		}
		return writeJSON(stdout, r)
	case "backends":
		if len(args) != 1 {
			return errors.New("usage: ReverseResearch web backends")
		}
		result, err := service.WebBackends()
		if err != nil {
			return err
		}
		return writeJSON(stdout, result)
	case "profile":
		flags := flag.NewFlagSet("web profile", flag.ContinueOnError)
		flags.SetOutput(stderr)
		var id, browser string
		flags.StringVar(&id, "id", "", "isolated profile id")
		flags.StringVar(&browser, "browser", "chrome", "chrome or msedge")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 || strings.TrimSpace(id) == "" {
			return errors.New("usage: ReverseResearch web profile --id <profile-id> [--browser chrome|msedge]")
		}
		result, err := service.PrepareWebProfile(id, browser)
		if err != nil {
			return err
		}
		return writeJSON(stdout, result)
	case "cdp":
		flags := flag.NewFlagSet("web cdp", flag.ContinueOnError)
		flags.SetOutput(stderr)
		var endpoint, timeoutRaw string
		flags.StringVar(&endpoint, "endpoint", "", "loopback CDP endpoint, for example http://127.0.0.1:9222")
		flags.StringVar(&timeoutRaw, "timeout", webinspect.DefaultCDPTimeout.String(), "bounded CDP timeout")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 || strings.TrimSpace(endpoint) == "" {
			return errors.New("usage: ReverseResearch web cdp --endpoint <http://127.0.0.1:port> [--timeout 3s]")
		}
		timeout, err := time.ParseDuration(timeoutRaw)
		if err != nil {
			return err
		}
		result, err := service.InspectWebCDP(ctx, endpoint, timeout)
		if err != nil {
			return err
		}
		return writeJSON(stdout, result)
	case "source":
		if len(args) != 2 {
			return errors.New("usage: ReverseResearch web source <local-js-or-css>")
		}
		result, err := service.AnalyzeWebSource(args[1])
		if err != nil {
			return err
		}
		return writeJSON(stdout, result)
	case "wasm":
		if len(args) < 2 {
			return errors.New("usage: ReverseResearch web wasm <local-wasm> [--wabt --view validation|wat|details --offset 0 --limit 8192 --expected-sha256 <sha> --expected-output-sha256 <sha>]")
		}
		flags := flag.NewFlagSet("web wasm", flag.ContinueOnError)
		flags.SetOutput(stderr)
		var options webinspect.WASMOptions
		flags.BoolVar(&options.UseWABT, "wabt", false, "use installed WABT 1.0.42 for full static validation")
		flags.StringVar(&options.View, "view", "", "validation, wat or details; requires --wabt")
		flags.IntVar(&options.Offset, "offset", 0, "decoded output byte offset")
		flags.IntVar(&options.Limit, "limit", 0, "returned UTF-8 byte budget; requires --wabt")
		flags.StringVar(&options.ExpectedSHA256, "expected-sha256", "", "WASM byte SHA-256")
		flags.StringVar(&options.ExpectedOutputSHA256, "expected-output-sha256", "", "decoded output SHA-256")
		if err := flags.Parse(args[2:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return errors.New("unexpected web wasm arguments")
		}
		result, err := service.InspectWebWASMWithOptions(ctx, args[1], options)
		if err != nil {
			return err
		}
		if err := writeJSON(stdout, result); err != nil {
			return err
		}
		if result.WABT != nil && !result.WABT.Validated {
			return errors.New("WABT rejected the module; see structured diagnostics")
		}
		return nil
	case "sourcemap":
		if len(args) < 2 {
			return errors.New("usage: ReverseResearch web sourcemap <local-map> [--source-index 0] [--offset 0] [--limit 8192] [--expected-sha256 <sha256>]")
		}
		flags := flag.NewFlagSet("web sourcemap", flag.ContinueOnError)
		flags.SetOutput(stderr)
		var options webinspect.SourceMapReadOptions
		flags.IntVar(&options.SourceIndex, "source-index", 0, "zero-based embedded source index")
		flags.IntVar(&options.Offset, "offset", 0, "decoded UTF-8 byte offset")
		flags.IntVar(&options.Limit, "limit", webinspect.DefaultSourceReadBytes, "maximum returned UTF-8 bytes")
		flags.StringVar(&options.ExpectedSHA256, "expected-sha256", "", "map digest from a previous page")
		if err := flags.Parse(args[2:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return errors.New("unexpected web sourcemap arguments")
		}
		result, err := service.ReadWebSourceMap(args[1], options)
		if err != nil {
			return err
		}
		return writeJSON(stdout, result)
	case "har":
		if len(args) < 2 {
			return errors.New("usage: ReverseResearch web har <local-har> [--offset 0] [--limit 50] [--expected-sha256 <sha256>]")
		}
		flags := flag.NewFlagSet("web har", flag.ContinueOnError)
		flags.SetOutput(stderr)
		var options webinspect.HAROptions
		flags.IntVar(&options.Offset, "offset", 0, "zero-based original entry ordinal")
		flags.IntVar(&options.Limit, "limit", webinspect.DefaultHARPageSize, "maximum returned entries")
		flags.StringVar(&options.ExpectedSHA256, "expected-sha256", "", "capture digest from a previous page")
		if err := flags.Parse(args[2:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return errors.New("unexpected web har arguments")
		}
		result, err := service.InspectWebHAR(args[1], options)
		if err != nil {
			return err
		}
		return writeJSON(stdout, result)
	case "sse":
		if len(args) < 2 {
			return errors.New("usage: ReverseResearch web sse <local-event-stream> [--offset 0] [--limit 50] [--data-preview-bytes 0] [--expected-sha256 <sha256>]")
		}
		flags := flag.NewFlagSet("web sse", flag.ContinueOnError)
		flags.SetOutput(stderr)
		var options webinspect.SSEOptions
		flags.IntVar(&options.Offset, "offset", 0, "zero-based emitted event ordinal")
		flags.IntVar(&options.Limit, "limit", webinspect.DefaultSSEPageSize, "maximum returned events")
		flags.IntVar(&options.DataPreviewBytes, "data-preview-bytes", 0, "optional UTF-8 data prefix per event; 0 omits, maximum 4096 bytes")
		flags.StringVar(&options.ExpectedSHA256, "expected-sha256", "", "capture digest from a previous page")
		if err := flags.Parse(args[2:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return errors.New("unexpected web sse arguments")
		}
		result, err := service.InspectWebSSE(args[1], options)
		if err != nil {
			return err
		}
		return writeJSON(stdout, result)
	default:
		return errors.New("unknown web subcommand; expected backends, profile, cdp, source, sourcemap, har, sse, or wasm")
	}
}
