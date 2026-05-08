package parsers

import (
	"strings"
	"text/template"
)

// templateFuncs is the FuncMap registered with from_template extractors.
// Kept intentionally small - operators learn Go templates anyway, no
// need to invent a new DSL on top.
//
// Note: this is independent of the FuncMap used for profile topic
// templates and Webex output templates. We do NOT touch those existing
// paths in v0.3.1 to keep blast radius small. If/when a unified template
// helper system is desired, that's a separate refactor.
var templateFuncs = template.FuncMap{
	"lower": strings.ToLower,
	"upper": strings.ToUpper,
	"trim":  strings.TrimSpace,

	// default returns the second argument when the first is empty.
	// Useful in chained extraction: "{{ .state | default \"UNKNOWN\" }}".
	"default": func(fallback, val string) string {
		if val == "" {
			return fallback
		}
		return val
	},

	// hasPrefix and hasSuffix for conditional branching.
	"hasPrefix": strings.HasPrefix,
	"hasSuffix": strings.HasSuffix,

	// contains for substring match in conditionals.
	"contains": strings.Contains,
}
