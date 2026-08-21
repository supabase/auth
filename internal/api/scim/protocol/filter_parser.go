package protocol

import (
	"encoding/json"
	"strconv"
	"strings"
)

// ParseFilter parses the FILTER grammar of RFC 7644, Section 3.4.2.2 into a
// Filter. A filter that does not conform is ErrInvalidFilter, per Table 3 of
// that section.
//
// Precedence is grouping, then "not", then "and", then "or", so "a and b or c"
// reads as "(a and b) or c". The whole grammar is parsed; deciding which of it a
// given store can serve is a separate compiler's job.
func ParseFilter(input string) (Filter, error) {
	tokens, err := lex(input)
	if err != nil {
		return nil, err
	}
	if len(tokens) == 0 {
		return nil, ErrInvalidFilter("filter is empty")
	}

	p := &parser{tokens: tokens}
	filter, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if p.pos != len(p.tokens) {
		return nil, ErrInvalidFilter("unexpected token after filter")
	}
	return filter, nil
}

var compareOps = map[string]CompareOp{
	"eq": OpEqual,
	"ne": OpNotEqual,
	"co": OpContains,
	"sw": OpStartsWith,
	"ew": OpEndsWith,
	"gt": OpGreaterThan,
	"lt": OpLessThan,
	"ge": OpGreaterOrEqual,
	"le": OpLessOrEqual,
}

type tokenKind int

const (
	tokWord tokenKind = iota
	tokString
	tokLParen
	tokRParen
	tokLBracket
	tokRBracket
)

// token is one lexeme. For tokWord, text is the word verbatim; for tokString,
// text is the string with its quotes removed and its escapes resolved.
type token struct {
	kind tokenKind
	text string
}

// lex splits a filter into tokens. Parens and brackets are single tokens; a
// quoted string is one token however many spaces it holds; everything else runs
// to the next space or delimiter, which is enough to carry an attrPath, an
// operator, a keyword, or an unquoted compValue whole.
func lex(input string) ([]token, error) {
	var tokens []token
	runes := []rune(input)
	i, n := 0, len(runes)

	for i < n {
		switch c := runes[i]; c {
		case ' ', '\t', '\n', '\r':
			i++
		case '(':
			tokens = append(tokens, token{kind: tokLParen})
			i++
		case ')':
			tokens = append(tokens, token{kind: tokRParen})
			i++
		case '[':
			tokens = append(tokens, token{kind: tokLBracket})
			i++
		case ']':
			tokens = append(tokens, token{kind: tokRBracket})
			i++
		case '"':
			text, next, err := lexString(runes, i)
			if err != nil {
				return nil, err
			}
			tokens = append(tokens, token{kind: tokString, text: text})
			i = next
		default:
			start := i
			for i < n && !isBoundary(runes[i]) {
				i++
			}
			tokens = append(tokens, token{kind: tokWord, text: string(runes[start:i])})
		}
	}
	return tokens, nil
}

func isBoundary(c rune) bool {
	switch c {
	case ' ', '\t', '\n', '\r', '(', ')', '[', ']', '"':
		return true
	}
	return false
}

// lexString reads the string literal that starts at runes[start] and returns its
// decoded value and the index just past the closing quote. The literal is decoded
// as JSON, which is what compValue's string rule refers to, so its escapes mean
// what they mean in a SCIM document.
func lexString(runes []rune, start int) (string, int, error) {
	i, n := start+1, len(runes)
	for i < n {
		switch runes[i] {
		case '\\':
			i += 2
		case '"':
			literal := string(runes[start : i+1])
			var decoded string
			if err := json.Unmarshal([]byte(literal), &decoded); err != nil {
				return "", 0, ErrInvalidFilter("malformed string in filter")
			}
			return decoded, i + 1, nil
		default:
			i++
		}
	}
	return "", 0, ErrInvalidFilter("unterminated string in filter")
}

type parser struct {
	tokens []token
	pos    int
}

func (p *parser) peek() (token, bool) {
	if p.pos < len(p.tokens) {
		return p.tokens[p.pos], true
	}
	return token{}, false
}

func (p *parser) next() (token, bool) {
	t, ok := p.peek()
	if ok {
		p.pos++
	}
	return t, ok
}

// match consumes the next token if it is of kind, reporting whether it did.
func (p *parser) match(kind tokenKind) bool {
	if t, ok := p.peek(); ok && t.kind == kind {
		p.pos++
		return true
	}
	return false
}

// matchKeyword consumes the next token if it is the word kw, matched without
// regard to case because the grammar's keywords are constants of the language
// rather than data.
func (p *parser) matchKeyword(kw string) bool {
	if t, ok := p.peek(); ok && t.kind == tokWord && strings.EqualFold(t.text, kw) {
		p.pos++
		return true
	}
	return false
}

func (p *parser) parseOr() (Filter, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.matchKeyword("or") {
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = &LogicalExpr{Op: LogicalOr, Left: left, Right: right}
	}
	return left, nil
}

func (p *parser) parseAnd() (Filter, error) {
	left, err := p.parseNot()
	if err != nil {
		return nil, err
	}
	for p.matchKeyword("and") {
		right, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		left = &LogicalExpr{Op: LogicalAnd, Left: left, Right: right}
	}
	return left, nil
}

func (p *parser) parseNot() (Filter, error) {
	if p.matchKeyword("not") {
		if !p.match(tokLParen) {
			return nil, ErrInvalidFilter(`"not" must be followed by a parenthesized filter`)
		}
		inner, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if !p.match(tokRParen) {
			return nil, ErrInvalidFilter(`missing ")" after "not("`)
		}
		return &NotExpr{Inner: inner}, nil
	}
	return p.parsePrimary()
}

func (p *parser) parsePrimary() (Filter, error) {
	if p.match(tokLParen) {
		inner, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if !p.match(tokRParen) {
			return nil, ErrInvalidFilter(`missing ")"`)
		}
		return inner, nil
	}

	path, err := p.parseAttrPath()
	if err != nil {
		return nil, err
	}

	if p.match(tokLBracket) {
		inner, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if !p.match(tokRBracket) {
			return nil, ErrInvalidFilter(`missing "]"`)
		}
		return &ValuePath{Path: path, Filter: inner}, nil
	}

	return p.parseAttrExpr(path)
}

func (p *parser) parseAttrPath() (AttrPath, error) {
	t, ok := p.peek()
	if !ok || t.kind != tokWord {
		return AttrPath{}, ErrInvalidFilter("expected an attribute path")
	}
	path, err := parseAttrPathText(t.text)
	if err != nil {
		return AttrPath{}, err
	}
	p.pos++
	return path, nil
}

// parseAttrPathText splits [URI ":"] ATTRNAME *1subAttr. ATTRNAME and subAttr
// hold no colon, so the last colon in the word ends the URI; the first dot in
// what remains begins the one permitted sub-attribute.
func parseAttrPathText(text string) (AttrPath, error) {
	uri, attr := "", text
	if idx := strings.LastIndex(text, ":"); idx >= 0 {
		uri, attr = text[:idx], text[idx+1:]
		if uri == "" {
			return AttrPath{}, ErrInvalidFilter(strconv.Quote(text) + " is not an attribute path")
		}
	}

	name, sub := attr, ""
	if before, after, found := strings.Cut(attr, "."); found {
		name, sub = before, after
	}

	if !validName(name) || (sub != "" && !validName(sub)) {
		return AttrPath{}, ErrInvalidFilter(strconv.Quote(text) + " is not an attribute path")
	}
	return AttrPath{URI: uri, Name: name, Sub: sub}, nil
}

// validName is ATTRNAME = ALPHA *(nameChar). A second dot would leave a dot in
// sub, which fails here, which is how *1subAttr is enforced.
func validName(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		alpha := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
		if i == 0 {
			if !alpha {
				return false
			}
			continue
		}
		if !alpha && !(r >= '0' && r <= '9') && r != '-' && r != '_' {
			return false
		}
	}
	return true
}

func (p *parser) parseAttrExpr(path AttrPath) (Filter, error) {
	t, ok := p.next()
	if !ok || t.kind != tokWord {
		return nil, ErrInvalidFilter("expected an operator after " + strconv.Quote(pathText(path)))
	}

	if strings.EqualFold(t.text, string(OpPresent)) {
		return &AttrExpr{Path: path, Op: OpPresent}, nil
	}

	op, ok := compareOps[strings.ToLower(t.text)]
	if !ok {
		return nil, ErrInvalidFilter(strconv.Quote(t.text) + " is not a filter operator")
	}

	value, err := p.parseCompValue()
	if err != nil {
		return nil, err
	}
	return &AttrExpr{Path: path, Op: op, Value: value}, nil
}

// parseCompValue reads compValue = false / null / true / number / string. A
// string arrives already decoded; a literal is decoded as JSON, which accepts
// exactly the other four and rejects a bare word such as an unquoted string.
func (p *parser) parseCompValue() (Value, error) {
	t, ok := p.next()
	if !ok {
		return Value{}, ErrInvalidFilter("expected a value")
	}

	switch t.kind {
	case tokString:
		return Value{Raw: t.text}, nil
	case tokWord:
		var raw any
		if err := json.Unmarshal([]byte(t.text), &raw); err != nil {
			return Value{}, ErrInvalidFilter(strconv.Quote(t.text) + " is not a value")
		}
		return Value{Raw: raw}, nil
	default:
		return Value{}, ErrInvalidFilter("expected a value")
	}
}

func pathText(path AttrPath) string {
	text := path.Name
	if path.Sub != "" {
		text += "." + path.Sub
	}
	if path.URI != "" {
		text = path.URI + ":" + text
	}
	return text
}
