package detection

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"reverseresearch/internal/targetidentity"
)

const (
	SigmaEngine      = "rr-sigma-fixture-v1"
	maxRuleBytes     = 2 << 20
	maxFixtureBytes  = 8 << 20
	maxFixtureEvents = 10000
)

type SigmaRequest struct {
	RulePath         string   `json:"rule_path"`
	PositiveFixtures []string `json:"positive_fixtures"`
	NegativeFixtures []string `json:"negative_fixtures"`
}

type FixtureResult struct {
	Path    string `json:"path"`
	SHA256  string `json:"sha256"`
	Events  int    `json:"events"`
	Matches int    `json:"matches"`
	Passed  bool   `json:"passed"`
}

type SigmaValidation struct {
	Engine           string          `json:"engine"`
	RulePath         string          `json:"rule_path"`
	RuleSHA256       string          `json:"rule_sha256"`
	RuleRevision     string          `json:"rule_revision"`
	RuleText         string          `json:"rule_text"`
	Title            string          `json:"title"`
	SyntaxValid      bool            `json:"syntax_valid"`
	SchemaValid      bool            `json:"schema_valid"`
	PositiveFixtures []FixtureResult `json:"positive_fixtures"`
	NegativeFixtures []FixtureResult `json:"negative_fixtures"`
	PositivePassed   bool            `json:"positive_passed"`
	NegativePassed   bool            `json:"negative_passed"`
	ExpectedHit      string          `json:"expected_hit"`
	Validated        bool            `json:"validated"`
	Semantics        string          `json:"semantics"`
}

type compiledSigma struct {
	title      string
	selections map[string]any
	condition  conditionNode
}

type conditionNode interface {
	eval(map[string]bool) bool
}

type nameNode string

func (n nameNode) eval(values map[string]bool) bool { return values[string(n)] }

type notNode struct{ child conditionNode }

func (n notNode) eval(values map[string]bool) bool { return !n.child.eval(values) }

type binaryNode struct {
	op          string
	left, right conditionNode
}

func (n binaryNode) eval(values map[string]bool) bool {
	if n.op == "and" {
		return n.left.eval(values) && n.right.eval(values)
	}
	return n.left.eval(values) || n.right.eval(values)
}

type groupNode struct {
	all   bool
	names []string
}

func (n groupNode) eval(values map[string]bool) bool {
	if len(n.names) == 0 {
		return false
	}
	if n.all {
		for _, name := range n.names {
			if !values[name] {
				return false
			}
		}
		return true
	}
	for _, name := range n.names {
		if values[name] {
			return true
		}
	}
	return false
}

func ValidateSigmaFiles(request SigmaRequest) (SigmaValidation, error) {
	rulePath, ruleBody, ruleSHA, err := readFrozen(request.RulePath, maxRuleBytes)
	if err != nil {
		return SigmaValidation{}, err
	}
	compiled, err := compileSigma(ruleBody)
	if err != nil {
		return SigmaValidation{}, err
	}
	result := SigmaValidation{
		Engine: SigmaEngine, RulePath: rulePath, RuleSHA256: ruleSHA, RuleRevision: "sha256:" + ruleSHA,
		RuleText: string(ruleBody), Title: compiled.title, SyntaxValid: true, SchemaValid: true,
		ExpectedHit: "at least one match in every positive fixture and zero matches in every negative fixture",
		Semantics:   "bounded local Sigma subset: exact/glob/contains/startswith/endswith field predicates; and/or/not; 1|all of selection patterns; case-insensitive strings",
	}
	for _, path := range cleanPaths(request.PositiveFixtures) {
		fixture, evalErr := evaluateFixture(path, compiled, true)
		if evalErr != nil {
			return SigmaValidation{}, evalErr
		}
		result.PositiveFixtures = append(result.PositiveFixtures, fixture)
	}
	for _, path := range cleanPaths(request.NegativeFixtures) {
		fixture, evalErr := evaluateFixture(path, compiled, false)
		if evalErr != nil {
			return SigmaValidation{}, evalErr
		}
		result.NegativeFixtures = append(result.NegativeFixtures, fixture)
	}
	result.PositivePassed = len(result.PositiveFixtures) > 0
	for _, fixture := range result.PositiveFixtures {
		result.PositivePassed = result.PositivePassed && fixture.Passed
	}
	result.NegativePassed = len(result.NegativeFixtures) > 0
	for _, fixture := range result.NegativeFixtures {
		result.NegativePassed = result.NegativePassed && fixture.Passed
	}
	result.Validated = result.SyntaxValid && result.SchemaValid && result.PositivePassed && result.NegativePassed
	return result, nil
}

func compileSigma(body []byte) (compiledSigma, error) {
	var root map[string]any
	if err := yaml.Unmarshal(body, &root); err != nil {
		return compiledSigma{}, fmt.Errorf("sigma YAML syntax: %w", err)
	}
	title := strings.TrimSpace(asString(root["title"]))
	if title == "" {
		return compiledSigma{}, errors.New("sigma schema: title is required")
	}
	if _, ok := root["logsource"].(map[string]any); !ok {
		return compiledSigma{}, errors.New("sigma schema: logsource mapping is required")
	}
	detectionMap, ok := root["detection"].(map[string]any)
	if !ok {
		return compiledSigma{}, errors.New("sigma schema: detection mapping is required")
	}
	condition := strings.TrimSpace(asString(detectionMap["condition"]))
	if condition == "" {
		return compiledSigma{}, errors.New("sigma schema: detection.condition is required")
	}
	selections := map[string]any{}
	for key, value := range detectionMap {
		key = strings.TrimSpace(key)
		if key == "" || key == "condition" || key == "timeframe" {
			continue
		}
		if err := validateSelection(value); err != nil {
			return compiledSigma{}, fmt.Errorf("sigma selection %s: %w", key, err)
		}
		selections[key] = value
	}
	if len(selections) == 0 {
		return compiledSigma{}, errors.New("sigma schema: at least one selection is required")
	}
	node, err := parseCondition(condition, selections)
	if err != nil {
		return compiledSigma{}, fmt.Errorf("sigma condition: %w", err)
	}
	return compiledSigma{title: title, selections: selections, condition: node}, nil
}

func validateSelection(value any) error {
	switch typed := value.(type) {
	case map[string]any:
		if len(typed) == 0 {
			return errors.New("empty selection map")
		}
		for field := range typed {
			if err := validateFieldExpression(field); err != nil {
				return err
			}
		}
		return nil
	case []any:
		if len(typed) == 0 {
			return errors.New("empty selection list")
		}
		for _, item := range typed {
			if _, ok := item.(map[string]any); !ok {
				return errors.New("selection lists must contain mapping alternatives")
			}
			if err := validateSelection(item); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("unsupported selection type %T", value)
	}
}

func validateFieldExpression(field string) error {
	parts := strings.Split(field, "|")
	if strings.TrimSpace(parts[0]) == "" {
		return errors.New("empty field name")
	}
	for _, modifier := range parts[1:] {
		switch strings.ToLower(strings.TrimSpace(modifier)) {
		case "contains", "startswith", "endswith", "all":
		default:
			return fmt.Errorf("unsupported field modifier %q", modifier)
		}
	}
	return nil
}

func evaluateFixture(path string, rule compiledSigma, positive bool) (FixtureResult, error) {
	resolved, body, sha, err := readFrozen(path, maxFixtureBytes)
	if err != nil {
		return FixtureResult{}, err
	}
	events, err := decodeFixtureEvents(body)
	if err != nil {
		return FixtureResult{}, fmt.Errorf("fixture %s: %w", resolved, err)
	}
	matches := 0
	for _, event := range events {
		if matchSigma(rule, event) {
			matches++
		}
	}
	passed := matches == 0
	if positive {
		passed = matches > 0
	}
	return FixtureResult{Path: resolved, SHA256: sha, Events: len(events), Matches: matches, Passed: passed}, nil
}

func decodeFixtureEvents(body []byte) ([]map[string]any, error) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var raw any
	if err := decoder.Decode(&raw); err != nil {
		return nil, fmt.Errorf("decode JSON: %w", err)
	}
	var events []map[string]any
	switch typed := raw.(type) {
	case map[string]any:
		events = []map[string]any{typed}
	case []any:
		if len(typed) > maxFixtureEvents {
			return nil, fmt.Errorf("fixture has %d events; maximum is %d", len(typed), maxFixtureEvents)
		}
		for index, item := range typed {
			event, ok := item.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("event %d is not a JSON object", index)
			}
			events = append(events, event)
		}
	default:
		return nil, errors.New("fixture must be one JSON object or an array of objects")
	}
	if len(events) == 0 {
		return nil, errors.New("fixture contains no events")
	}
	return events, nil
}

func matchSigma(rule compiledSigma, event map[string]any) bool {
	values := make(map[string]bool, len(rule.selections))
	for name, selection := range rule.selections {
		values[name] = matchSelection(selection, event)
	}
	return rule.condition.eval(values)
}

func matchSelection(selection any, event map[string]any) bool {
	switch typed := selection.(type) {
	case map[string]any:
		for field, expected := range typed {
			if !matchField(field, expected, event) {
				return false
			}
		}
		return true
	case []any:
		for _, item := range typed {
			if matchSelection(item, event) {
				return true
			}
		}
	}
	return false
}

func matchField(expression string, expected any, event map[string]any) bool {
	parts := strings.Split(expression, "|")
	actual, ok := lookupEvent(event, strings.TrimSpace(parts[0]))
	if !ok {
		return false
	}
	modifiers := make([]string, 0, len(parts)-1)
	for _, value := range parts[1:] {
		modifiers = append(modifiers, strings.ToLower(strings.TrimSpace(value)))
	}
	requireAll := false
	filtered := modifiers[:0]
	for _, modifier := range modifiers {
		if modifier == "all" {
			requireAll = true
			continue
		}
		filtered = append(filtered, modifier)
	}
	modifiers = filtered
	values, isList := expected.([]any)
	if !isList {
		values = []any{expected}
	}
	if requireAll {
		for _, value := range values {
			if !matchValue(actual, value, modifiers) {
				return false
			}
		}
		return true
	}
	for _, value := range values {
		if matchValue(actual, value, modifiers) {
			return true
		}
	}
	return false
}

func matchValue(actual, expected any, modifiers []string) bool {
	left := scalarString(actual)
	right := scalarString(expected)
	if len(modifiers) == 0 {
		return globEqual(left, right)
	}
	if len(modifiers) != 1 {
		return false
	}
	switch modifiers[0] {
	case "contains":
		return strings.Contains(strings.ToLower(left), strings.ToLower(right))
	case "startswith":
		return strings.HasPrefix(strings.ToLower(left), strings.ToLower(right))
	case "endswith":
		return strings.HasSuffix(strings.ToLower(left), strings.ToLower(right))
	default:
		return false
	}
}

func lookupEvent(event map[string]any, field string) (any, bool) {
	current := any(event)
	for _, segment := range strings.Split(field, ".") {
		object, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		found := false
		for key, value := range object {
			if strings.EqualFold(key, segment) {
				current, found = value, true
				break
			}
		}
		if !found {
			return nil, false
		}
	}
	return current, true
}

func globEqual(actual, expected string) bool {
	if !strings.ContainsAny(expected, "*?") {
		return strings.EqualFold(actual, expected)
	}
	pattern := regexp.QuoteMeta(expected)
	pattern = strings.ReplaceAll(pattern, "\\*", ".*")
	pattern = strings.ReplaceAll(pattern, "\\?", ".")
	matched, err := regexp.MatchString("(?i)^"+pattern+"$", actual)
	return err == nil && matched
}

func scalarString(value any) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return typed
	case json.Number:
		return typed.String()
	case int:
		return strconv.Itoa(typed)
	case int64:
		return strconv.FormatInt(typed, 10)
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(typed)
	default:
		return fmt.Sprint(typed)
	}
}

func asString(value any) string {
	text, _ := value.(string)
	return text
}

var groupCondition = regexp.MustCompile(`(?i)^(1|all)\s+of\s+([a-z0-9_.?*-]+|them)$`)

func parseCondition(text string, selections map[string]any) (conditionNode, error) {
	text = strings.TrimSpace(text)
	if match := groupCondition.FindStringSubmatch(text); match != nil {
		names := matchingSelections(match[2], selections)
		if len(names) == 0 {
			return nil, errors.New("selection group matches no selections")
		}
		return groupNode{all: strings.EqualFold(match[1], "all"), names: names}, nil
	}
	tokens, err := conditionTokens(text)
	if err != nil {
		return nil, err
	}
	parser := conditionParser{tokens: tokens, selections: selections}
	node, err := parser.parseOr()
	if err != nil {
		return nil, err
	}
	if parser.index != len(tokens) {
		return nil, fmt.Errorf("unexpected token %q", tokens[parser.index])
	}
	return node, nil
}

func matchingSelections(pattern string, selections map[string]any) []string {
	names := make([]string, 0)
	if strings.EqualFold(pattern, "them") {
		for name := range selections {
			names = append(names, name)
		}
	} else {
		for name := range selections {
			if globNameMatch(name, pattern) {
				names = append(names, name)
			}
		}
	}
	sort.Strings(names)
	return names
}

func globNameMatch(name, pattern string) bool {
	expression := regexp.QuoteMeta(pattern)
	expression = strings.ReplaceAll(expression, "\\*", ".*")
	expression = strings.ReplaceAll(expression, "\\?", ".")
	ok, _ := regexp.MatchString("(?i)^"+expression+"$", name)
	return ok
}

func conditionTokens(text string) ([]string, error) {
	result := make([]string, 0)
	var current strings.Builder
	flush := func() {
		if current.Len() > 0 {
			result = append(result, current.String())
			current.Reset()
		}
	}
	for _, r := range text {
		switch r {
		case ' ', '\t', '\r', '\n':
			flush()
		case '(', ')':
			flush()
			result = append(result, string(r))
		default:
			current.WriteRune(r)
		}
	}
	flush()
	if len(result) == 0 {
		return nil, errors.New("empty condition")
	}
	return result, nil
}

type conditionParser struct {
	tokens     []string
	index      int
	selections map[string]any
}

func (p *conditionParser) parseOr() (conditionNode, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.peek("or") {
		p.index++
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = binaryNode{op: "or", left: left, right: right}
	}
	return left, nil
}

func (p *conditionParser) parseAnd() (conditionNode, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for p.peek("and") {
		p.index++
		right, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		left = binaryNode{op: "and", left: left, right: right}
	}
	return left, nil
}

func (p *conditionParser) parseUnary() (conditionNode, error) {
	if p.peek("not") {
		p.index++
		child, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return notNode{child: child}, nil
	}
	if p.index >= len(p.tokens) {
		return nil, errors.New("unexpected end of condition")
	}
	if p.tokens[p.index] == "(" {
		p.index++
		node, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if p.index >= len(p.tokens) || p.tokens[p.index] != ")" {
			return nil, errors.New("missing closing parenthesis")
		}
		p.index++
		return node, nil
	}
	name := p.tokens[p.index]
	p.index++
	if _, ok := p.selections[name]; !ok {
		return nil, fmt.Errorf("unknown selection %q", name)
	}
	return nameNode(name), nil
}

func (p *conditionParser) peek(value string) bool {
	return p.index < len(p.tokens) && strings.EqualFold(p.tokens[p.index], value)
}

func readFrozen(path string, maxBytes int64) (string, []byte, string, error) {
	before, err := targetidentity.InspectBounded(path, maxBytes)
	if err != nil {
		return "", nil, "", err
	}
	if before.Size > maxBytes {
		return "", nil, "", fmt.Errorf("file %s exceeds limit %d", before.Path, maxBytes)
	}
	body, err := os.ReadFile(before.Path)
	if err != nil {
		return "", nil, "", err
	}
	if int64(len(body)) != before.Size {
		return "", nil, "", errors.New("file size changed during read")
	}
	digest := sha256.Sum256(body)
	hash := hex.EncodeToString(digest[:])
	if hash != before.SHA256 {
		return "", nil, "", errors.New("file content changed during read")
	}
	after, err := targetidentity.InspectBounded(before.Path, maxBytes)
	if err != nil {
		return "", nil, "", err
	}
	if after.SHA256 != before.SHA256 || after.Size != before.Size {
		return "", nil, "", errors.New("file changed during validation")
	}
	return filepath.Clean(before.Path), body, hash, nil
}

func cleanPaths(values []string) []string {
	seen := map[string]bool{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" && !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	return result
}
