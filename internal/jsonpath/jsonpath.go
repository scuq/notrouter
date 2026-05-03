// Package jsonpath implements a tiny subset of JSONPath sufficient for our
// config use cases. Not a full implementation - we support:
//
//	$           - root
//	$.foo       - object key
//	$.foo.bar   - nested keys
//	$.foo[0]    - array index
//	$.foo[0].b  - nested mix
//
// No filters, no slices, no recursive descent. If you need those, swap this
// out for github.com/PaesslerAG/jsonpath - we kept it stdlib-only on purpose.
package jsonpath

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Get walks the path against a generic decoded JSON value (map[string]any /
// []any / string / float64 / bool). Returns the value at the path or an error.
func Get(v interface{}, path string) (interface{}, error) {
	if path == "" || path == "$" {
		return v, nil
	}
	if !strings.HasPrefix(path, "$") {
		return nil, fmt.Errorf("path must start with $: %q", path)
	}
	tokens, err := tokenize(path[1:])
	if err != nil {
		return nil, err
	}
	for _, tok := range tokens {
		if v == nil {
			return nil, errors.New("path traversed nil")
		}
		switch t := tok.(type) {
		case string:
			m, ok := v.(map[string]interface{})
			if !ok {
				return nil, fmt.Errorf("expected object for key %q", t)
			}
			val, ok := m[t]
			if !ok {
				return nil, fmt.Errorf("key %q not found", t)
			}
			v = val
		case int:
			a, ok := v.([]interface{})
			if !ok {
				return nil, fmt.Errorf("expected array for index [%d]", t)
			}
			if t < 0 || t >= len(a) {
				return nil, fmt.Errorf("index [%d] out of range (len=%d)", t, len(a))
			}
			v = a[t]
		}
	}
	return v, nil
}

// GetString is the common case: pull a string from the path. Numbers and
// booleans are stringified. Returns "" + ok=false on miss.
func GetString(v interface{}, path string) (string, bool) {
	got, err := Get(v, path)
	if err != nil || got == nil {
		return "", false
	}
	switch x := got.(type) {
	case string:
		return x, true
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64), true
	case bool:
		return strconv.FormatBool(x), true
	default:
		return fmt.Sprintf("%v", x), true
	}
}

// tokenize splits ".foo.bar[3].baz" into ["foo", "bar", 3, "baz"]. Strings
// for keys, ints for indices.
func tokenize(s string) ([]interface{}, error) {
	var out []interface{}
	i := 0
	for i < len(s) {
		switch s[i] {
		case '.':
			// Read key until next '.' or '['.
			j := i + 1
			for j < len(s) && s[j] != '.' && s[j] != '[' {
				j++
			}
			if j == i+1 {
				return nil, fmt.Errorf("empty key at offset %d", i)
			}
			out = append(out, s[i+1:j])
			i = j
		case '[':
			end := strings.IndexByte(s[i:], ']')
			if end < 0 {
				return nil, errors.New("unclosed [")
			}
			idx, err := strconv.Atoi(s[i+1 : i+end])
			if err != nil {
				return nil, fmt.Errorf("non-numeric index %q", s[i+1:i+end])
			}
			out = append(out, idx)
			i += end + 1
		default:
			return nil, fmt.Errorf("unexpected char %q at offset %d", s[i], i)
		}
	}
	return out, nil
}
