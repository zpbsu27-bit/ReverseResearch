package main

import (
	"errors"
	"flag"
	"io"
	researchcore "reverseresearch/internal/core"
	"reverseresearch/internal/webinspect"
)

func runHARViewCLI(service *researchcore.Service, args []string, stdout, stderr io.Writer) error {
	if len(args) < 2 {
		return errors.New("usage: ReverseResearch web <har-api|har-body|har-compare> <capture> [options]")
	}
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	f.SetOutput(stderr)
	var o webinspect.HAROptions
	var right, leftSHA, rightSHA, side string
	ordinal := 0
	f.IntVar(&o.Offset, "offset", 0, "zero-based page or byte offset")
	f.IntVar(&o.Limit, "limit", 50, "maximum items or body bytes")
	if args[0] == "har-body" {
		f.Set("limit", "8192")
	}
	f.StringVar(&o.ExpectedSHA256, "expected-sha256", "", "capture/comparison digest")
	f.StringVar(&right, "right", "", "second capture")
	f.StringVar(&leftSHA, "expected-left-sha256", "", "left capture digest")
	f.StringVar(&rightSHA, "expected-right-sha256", "", "right capture digest")
	f.StringVar(&side, "side", "response", "request or response")
	f.IntVar(&ordinal, "entry-ordinal", 0, "original producer entry ordinal")
	if err := f.Parse(args[2:]); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return errors.New("unexpected HAR view arguments")
	}
	var v any
	var err error
	switch args[0] {
	case "har-api":
		v, err = service.InspectWebHARAPI(args[1], o)
	case "har-body":
		v, err = service.ReadWebHARBody(args[1], webinspect.HARBodyOptions{EntryOrdinal: ordinal, Side: side, Offset: o.Offset, Limit: o.Limit, ExpectedSHA256: o.ExpectedSHA256})
	case "har-compare":
		v, err = service.CompareWebHAR(args[1], right, webinspect.HARCompareOptions{HAROptions: o, ExpectedLeftSHA256: leftSHA, ExpectedRightSHA256: rightSHA})
	}
	if err != nil {
		return err
	}
	return writeJSON(stdout, v)
}
