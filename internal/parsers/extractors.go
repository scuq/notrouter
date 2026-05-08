package parsers

import (
	"bytes"
	"fmt"
	"net/mail"
	"regexp"
	"strings"
	"text/template"

	"github.com/scuq/notrouter/internal/config"
	"github.com/scuq/notrouter/internal/event"
)

// compiledExtractor is the runtime form of an ExtractorConfig. Each kind
// of extractor has its own struct implementing this interface. Compile
// errors are caught at config load via compileExtractor.
type compiledExtractor interface {
	// apply mutates ev in place. Returns an error only on RUNTIME
	// failures (e.g., template execution error on this specific input).
	// Pattern-not-matching is NOT an error - it's a normal outcome.
	//
	// Returns "matched" semantically through side effects: extractors
	// that didn't match leave ev untouched. dispatchFirstMatch checks
	// whether sub-extractors reported a match via the matched() bool.
	apply(ev *event.Event) error

	// matched reports whether the most recent apply() actually did
	// something. Used by dispatchFirstMatch to know when to stop.
	// Must be called only after apply().
	matched() bool

	// kind returns the extractor type name for error messages.
	kind() string
}

// compileExtractor turns a YAML config into a runtime extractor. Each
// extractor type has its own validation rules.
func compileExtractor(c config.ExtractorConfig) (compiledExtractor, error) {
	switch c.Type {
	case "from_subject_regex":
		return newRegexExtractor(c.Pattern, "subject", c.Type)

	case "from_attribute_regex":
		if c.Source == "" {
			return nil, fmt.Errorf("from_attribute_regex requires 'source'")
		}
		return newRegexExtractor(c.Pattern, c.Source, c.Type)

	case "from_body_kvline":
		if c.Label == "" {
			return nil, fmt.Errorf("from_body_kvline requires 'label'")
		}
		if c.Attribute == "" {
			return nil, fmt.Errorf("from_body_kvline requires 'attribute'")
		}
		return &kvlineExtractor{label: c.Label, attribute: c.Attribute}, nil

	case "from_body_after_label":
		if c.Label == "" {
			return nil, fmt.Errorf("from_body_after_label requires 'label'")
		}
		if c.Attribute == "" {
			return nil, fmt.Errorf("from_body_after_label requires 'attribute'")
		}
		return &afterLabelExtractor{label: c.Label, attribute: c.Attribute}, nil

	case "from_header":
		if c.Header == "" {
			return nil, fmt.Errorf("from_header requires 'header'")
		}
		if c.Attribute == "" {
			return nil, fmt.Errorf("from_header requires 'attribute'")
		}
		return &headerExtractor{header: c.Header, attribute: c.Attribute}, nil

	case "from_template":
		if c.Template == "" {
			return nil, fmt.Errorf("from_template requires 'template'")
		}
		if c.Attribute == "" {
			return nil, fmt.Errorf("from_template requires 'attribute'")
		}
		tpl, err := template.New(c.Attribute).Funcs(templateFuncs).Parse(c.Template)
		if err != nil {
			return nil, fmt.Errorf("template compile: %w", err)
		}
		return &templateExtractor{tpl: tpl, attribute: c.Attribute}, nil

	case "dispatch_first_match":
		if len(c.Alternatives) == 0 {
			return nil, fmt.Errorf("dispatch_first_match requires 'alternatives'")
		}
		alts := make([]compiledExtractor, 0, len(c.Alternatives))
		for i, alt := range c.Alternatives {
			compiled, err := compileExtractor(alt)
			if err != nil {
				return nil, fmt.Errorf("alternative #%d: %w", i+1, err)
			}
			alts = append(alts, compiled)
		}
		return &dispatchFirstMatch{alternatives: alts}, nil

	default:
		return nil, fmt.Errorf("unknown extractor type %q", c.Type)
	}
}

// =====================================================================
// regexExtractor - applies a regex with named captures against either
// the email subject or another attribute. Each named capture becomes
// an attribute on the event. Empty captures don't overwrite existing
// values, so "earlier extractors win" for any given attribute name.
// =====================================================================

type regexExtractor struct {
	re        *regexp.Regexp
	source    string // attribute name to read from
	kindName  string
	wasMatched bool
}

func newRegexExtractor(pattern, source, kindName string) (*regexExtractor, error) {
	if pattern == "" {
		return nil, fmt.Errorf("%s requires 'pattern'", kindName)
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("regex compile: %w", err)
	}
	if len(re.SubexpNames()) <= 1 {
		// No named captures means the regex would extract nothing
		// useful. Operators almost certainly meant to add captures.
		return nil, fmt.Errorf("regex has no named capture groups - use (?P<name>...) syntax")
	}
	return &regexExtractor{re: re, source: source, kindName: kindName}, nil
}

func (e *regexExtractor) kind() string   { return e.kindName }
func (e *regexExtractor) matched() bool  { return e.wasMatched }

func (e *regexExtractor) apply(ev *event.Event) error {
	e.wasMatched = false
	src := ev.Attributes[e.source]
	if src == "" {
		return nil // nothing to match against
	}
	m := e.re.FindStringSubmatch(src)
	if m == nil {
		return nil // no match - silent, normal
	}
	for i, name := range e.re.SubexpNames() {
		if i == 0 || name == "" {
			continue // skip the unnamed-zero group
		}
		if m[i] == "" {
			continue // empty captures don't overwrite
		}
		ev.Attributes[name] = m[i]
	}
	e.wasMatched = true
	return nil
}

// =====================================================================
// kvlineExtractor - finds a line in the body matching "<Label>:<spaces><value>"
// and assigns the value to an attribute. Looks at the "body" attribute
// which the SMTP receiver pre-populates.
// =====================================================================

type kvlineExtractor struct {
	label      string
	attribute  string
	wasMatched bool
}

func (e *kvlineExtractor) kind() string  { return "from_body_kvline" }
func (e *kvlineExtractor) matched() bool { return e.wasMatched }

func (e *kvlineExtractor) apply(ev *event.Event) error {
	e.wasMatched = false
	body := ev.Attributes["body"]
	if body == "" {
		return nil
	}
	prefix := e.label + ":"
	for _, line := range strings.Split(body, "\n") {
		// Match "Label:" anchored to start of line, then any
		// whitespace/spaces, then the value (may be empty).
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		value := strings.TrimSpace(line[len(prefix):])
		// Empty value is still a match - the label was present.
		// We set the attribute but mark matched so chained logic works.
		ev.Attributes[e.attribute] = value
		e.wasMatched = true
		return nil
	}
	return nil
}

// =====================================================================
// afterLabelExtractor - finds the labeled line and captures everything
// from after the colon to the end of the body (including continuation
// lines). Used for fields like CheckMK's Perfdata which may span lines.
// =====================================================================

type afterLabelExtractor struct {
	label      string
	attribute  string
	wasMatched bool
}

func (e *afterLabelExtractor) kind() string  { return "from_body_after_label" }
func (e *afterLabelExtractor) matched() bool { return e.wasMatched }

func (e *afterLabelExtractor) apply(ev *event.Event) error {
	e.wasMatched = false
	body := ev.Attributes["body"]
	if body == "" {
		return nil
	}
	prefix := e.label + ":"
	idx := strings.Index(body, "\n"+prefix)
	startSearch := 0
	if idx == -1 {
		// Could be at start of body (no leading newline).
		if !strings.HasPrefix(body, prefix) {
			return nil
		}
		startSearch = 0
	} else {
		startSearch = idx + 1 // skip the newline before the label
	}

	// Capture from after the colon to end of body. Trim leading
	// whitespace on the same line (the value after the colon) plus
	// any leading/trailing newlines on the multi-line value.
	rest := body[startSearch+len(prefix):]
	value := strings.TrimSpace(rest)
	ev.Attributes[e.attribute] = value
	e.wasMatched = true
	return nil
}

// =====================================================================
// headerExtractor - reads an email header from the raw RFC 5322 message.
// Re-parses headers each time; cheap and avoids needing the receiver
// to pre-populate every header as an attribute.
// =====================================================================

type headerExtractor struct {
	header     string
	attribute  string
	wasMatched bool
}

func (e *headerExtractor) kind() string  { return "from_header" }
func (e *headerExtractor) matched() bool { return e.wasMatched }

func (e *headerExtractor) apply(ev *event.Event) error {
	e.wasMatched = false
	if len(ev.Raw) == 0 {
		return nil
	}
	msg, err := mail.ReadMessage(bytes.NewReader(ev.Raw))
	if err != nil {
		// Couldn't parse headers - silent skip. Receiver already
		// logged a parse warning if applicable.
		return nil
	}
	v := msg.Header.Get(e.header)
	if v == "" {
		return nil
	}
	ev.Attributes[e.attribute] = strings.TrimSpace(v)
	e.wasMatched = true
	return nil
}

// =====================================================================
// templateExtractor - renders a Go text/template against the event's
// attributes and assigns the output to a target attribute.
// =====================================================================

type templateExtractor struct {
	tpl        *template.Template
	attribute  string
	wasMatched bool
}

func (e *templateExtractor) kind() string  { return "from_template" }
func (e *templateExtractor) matched() bool { return e.wasMatched }

func (e *templateExtractor) apply(ev *event.Event) error {
	e.wasMatched = false
	var buf bytes.Buffer
	// Pass the attributes map directly. Templates use {{.attrname}}
	// to access them. This is a different shape from the topic
	// template (which uses .Attributes.X capitalized) but consistent
	// with treating extractors as "operate on attributes" tools.
	if err := e.tpl.Execute(&buf, ev.Attributes); err != nil {
		return fmt.Errorf("template execution: %w", err)
	}
	out := buf.String()
	if out == "" {
		// Empty template output is treated as "didn't apply" - don't
		// overwrite an existing attribute with empty string. Keeps
		// fallback chains working.
		return nil
	}
	ev.Attributes[e.attribute] = out
	e.wasMatched = true
	return nil
}

// =====================================================================
// dispatchFirstMatch - tries each alternative in order, stops at the
// first one that reports matched=true. Used for "either A or B" parse
// paths like CheckMK's state-transition vs lifecycle-event Event field.
// =====================================================================

type dispatchFirstMatch struct {
	alternatives []compiledExtractor
	wasMatched   bool
}

func (e *dispatchFirstMatch) kind() string  { return "dispatch_first_match" }
func (e *dispatchFirstMatch) matched() bool { return e.wasMatched }

func (e *dispatchFirstMatch) apply(ev *event.Event) error {
	e.wasMatched = false
	for _, alt := range e.alternatives {
		if err := alt.apply(ev); err != nil {
			return err
		}
		if alt.matched() {
			e.wasMatched = true
			return nil
		}
	}
	return nil
}
