package protocolinfer

import (
	"errors"
	"fmt"
)

type CandidateCheck struct {
	Kind      string `json:"kind"`
	Candidate any    `json:"candidate"`
	Passed    bool   `json:"passed"`
	Failures  int    `json:"failures"`
}

type Validation struct {
	ModelCorpusSHA256   string           `json:"model_corpus_sha256"`
	FixtureCorpusSHA256 string           `json:"fixture_corpus_sha256"`
	FixtureCount        int              `json:"fixture_count"`
	Checks              []CandidateCheck `json:"checks"`
	Validated           bool             `json:"validated"`
}

func ValidateModel(model Result, fixtures []Sample) (Validation, error) {
	decoded, err := Decode(fixtures)
	if err != nil {
		return Validation{}, err
	}
	if len(decoded) < 2 {
		return Validation{}, errors.New("at least two independent validation fixtures are required")
	}
	fixtureSHA := corpusSHA256(decoded)
	if model.CorpusSHA256 == "" {
		return Validation{}, errors.New("model corpus_sha256 is required")
	}
	if fixtureSHA == model.CorpusSHA256 {
		return Validation{}, errors.New("validation fixtures must be independent from the model corpus")
	}
	result := Validation{
		ModelCorpusSHA256: model.CorpusSHA256, FixtureCorpusSHA256: fixtureSHA,
		FixtureCount: len(decoded), Checks: []CandidateCheck{},
	}
	for _, candidate := range model.LengthCandidates {
		failures := 0
		for _, sample := range decoded {
			if !ValidateLength(sample, candidate) {
				failures++
			}
		}
		result.Checks = append(result.Checks, CandidateCheck{
			Kind: "length", Candidate: candidate, Passed: failures == 0, Failures: failures,
		})
	}
	for _, candidate := range model.ChecksumCandidates {
		failures := 0
		for _, sample := range decoded {
			if !ValidateChecksum(sample, candidate) {
				failures++
			}
		}
		result.Checks = append(result.Checks, CandidateCheck{
			Kind: "checksum", Candidate: candidate, Passed: failures == 0, Failures: failures,
		})
	}
	if len(result.Checks) == 0 {
		return Validation{}, fmt.Errorf("model has no length or checksum candidates to validate")
	}
	result.Validated = true
	for _, check := range result.Checks {
		if !check.Passed {
			result.Validated = false
			break
		}
	}
	return result, nil
}
