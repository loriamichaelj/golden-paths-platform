// Package jsonschema validates decoded documents against the subset of JSON
// Schema (2020-12) that the golden-path contract schema uses. Validating with
// the published schema file itself keeps gold validate and CI from disagreeing.
package jsonschema

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// Error is one violation. Path uses dots and indexes, such as spec.databases[0].name.
type Error struct {
	Path    string
	Message string
}

// Schema is a parsed schema document.
type Schema struct {
	root map[string]any
}

// Parse reads a schema from JSON.
func Parse(data []byte) (*Schema, error) {
	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("parse schema: %w", err)
	}
	return &Schema{root: root}, nil
}

// Validate checks doc, which must hold map[string]any, []any, string, bool,
// int, int64, float64 or nil values, and returns every violation found.
func (s *Schema) Validate(doc any) []Error {
	var errs []Error
	s.check(s.root, doc, "", "", &errs)
	return errs
}

func (s *Schema) check(sc map[string]any, v any, path, rule string, out *[]Error) {
	fail := func(format string, args ...any) {
		add(out, path, fmt.Sprintf(format, args...), rule)
	}
	if ref, ok := sc["$ref"].(string); ok {
		target, err := s.resolve(ref)
		if err != nil {
			fail("%v", err)
			return
		}
		s.check(target, v, path, rule, out)
	}
	if c, ok := sc["const"]; ok && fmt.Sprint(c) != fmt.Sprint(v) {
		fail("must be %v (got %s)", c, show(v))
	}
	if list, ok := sc["enum"].([]any); ok && !contains(list, v) {
		fail("must be one of %s (got %s)", joinAny(list), show(v))
	}
	if t, ok := sc["type"].(string); ok && !typeOK(t, v) {
		fail("must be of type %s (got %s)", t, kind(v))
		return
	}
	switch val := v.(type) {
	case map[string]any:
		s.object(sc, val, path, rule, out)
	case []any:
		s.array(sc, val, path, rule, out)
	case string:
		str(sc, val, fail)
	default:
		if f, ok := toFloat(v); ok {
			number(sc, f, fail)
		}
	}
	s.combine(sc, v, path, rule, out)
}

func (s *Schema) object(sc map[string]any, m map[string]any, path, rule string, out *[]Error) {
	for _, name := range stringList(sc["required"]) {
		if _, ok := m[name]; !ok {
			add(out, join(path, name), "required property is missing", rule)
		}
	}
	props, _ := sc["properties"].(map[string]any)
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if child, ok := props[k].(map[string]any); ok {
			s.check(child, m[k], join(path, k), rule, out)
			continue
		}
		switch ap := sc["additionalProperties"].(type) {
		case bool:
			if !ap {
				add(out, join(path, k), "unknown field (rejected)", "")
			}
		case map[string]any:
			s.check(ap, m[k], join(path, k), rule, out)
		}
	}
}

func (s *Schema) array(sc map[string]any, a []any, path, rule string, out *[]Error) {
	if n, ok := toFloat(sc["minItems"]); ok && float64(len(a)) < n {
		add(out, path, fmt.Sprintf("needs at least %d items (got %d)", int(n), len(a)), rule)
	}
	if n, ok := toFloat(sc["maxItems"]); ok && float64(len(a)) > n {
		add(out, path, fmt.Sprintf("allows at most %d items (got %d)", int(n), len(a)), rule)
	}
	if u, ok := sc["uniqueItems"].(bool); ok && u {
		seen := map[string]bool{}
		for i, e := range a {
			key := fmt.Sprint(e)
			if seen[key] {
				add(out, fmt.Sprintf("%s[%d]", path, i), fmt.Sprintf("duplicate item %s", show(e)), rule)
			}
			seen[key] = true
		}
	}
	if items, ok := sc["items"].(map[string]any); ok {
		for i, e := range a {
			s.check(items, e, fmt.Sprintf("%s[%d]", path, i), rule, out)
		}
	}
	if c, ok := sc["contains"].(map[string]any); ok {
		found := false
		for _, e := range a {
			var tmp []Error
			s.check(c, e, path, rule, &tmp)
			if len(tmp) == 0 {
				found = true
				break
			}
		}
		if !found {
			add(out, path, "must contain a matching item", rule)
		}
	}
}

func str(sc map[string]any, v string, fail func(string, ...any)) {
	if n, ok := toFloat(sc["minLength"]); ok && float64(utf8.RuneCountInString(v)) < n {
		fail("must be at least %d characters (got %d)", int(n), utf8.RuneCountInString(v))
	}
	if p, ok := sc["pattern"].(string); ok {
		re, err := regexp.Compile(p)
		switch {
		case err != nil:
			fail("schema pattern %q is not valid: %v", p, err)
		case !re.MatchString(v):
			fail("must match %s (got %q)", p, v)
		}
	}
	if f, ok := sc["format"].(string); ok && !formatOK(f, v) {
		fail("must be a valid %s (got %q)", f, v)
	}
}

func number(sc map[string]any, f float64, fail func(string, ...any)) {
	if n, ok := toFloat(sc["minimum"]); ok && f < n {
		fail("must be at least %v (got %v)", n, f)
	}
	if n, ok := toFloat(sc["maximum"]); ok && f > n {
		fail("must be at most %v (got %v)", n, f)
	}
	if n, ok := toFloat(sc["exclusiveMinimum"]); ok && f <= n {
		fail("must be greater than %v (got %v)", n, f)
	}
}

func (s *Schema) combine(sc map[string]any, v any, path, rule string, out *[]Error) {
	if all, ok := sc["allOf"].([]any); ok {
		for _, e := range all {
			sub, ok := e.(map[string]any)
			if !ok {
				continue
			}
			r := rule
			if d, ok := sub["description"].(string); ok {
				r = d
			}
			s.check(sub, v, path, r, out)
		}
	}
	if anyOf, ok := sc["anyOf"].([]any); ok {
		matched := false
		for _, e := range anyOf {
			sub, ok := e.(map[string]any)
			if !ok {
				continue
			}
			var tmp []Error
			s.check(sub, v, path, "", &tmp)
			if len(tmp) == 0 {
				matched = true
				break
			}
		}
		if !matched {
			add(out, path, "does not match any allowed shape", rule)
		}
	}
	if not, ok := sc["not"].(map[string]any); ok {
		var tmp []Error
		s.check(not, v, path, "", &tmp)
		if len(tmp) == 0 {
			add(out, path, "is not allowed", rule)
		}
	}
	if cond, ok := sc["if"].(map[string]any); ok {
		var tmp []Error
		s.check(cond, v, path, "", &tmp)
		branch := "else"
		if len(tmp) == 0 {
			branch = "then"
		}
		if b, ok := sc[branch].(map[string]any); ok {
			s.check(b, v, path, rule, out)
		}
	}
}

func (s *Schema) resolve(ref string) (map[string]any, error) {
	if !strings.HasPrefix(ref, "#/") {
		return nil, fmt.Errorf("unsupported $ref %q", ref)
	}
	var cur any = s.root
	for _, part := range strings.Split(ref[2:], "/") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("unresolved $ref %q", ref)
		}
		if cur, ok = m[part]; !ok {
			return nil, fmt.Errorf("unresolved $ref %q", ref)
		}
	}
	m, ok := cur.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("$ref %q is not a schema", ref)
	}
	return m, nil
}

func add(out *[]Error, path, msg, rule string) {
	if rule != "" {
		msg += " (" + rule + ")"
	}
	*out = append(*out, Error{Path: path, Message: msg})
}

func join(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

func kind(v any) string {
	switch x := v.(type) {
	case nil:
		return "null"
	case map[string]any:
		return "object"
	case []any:
		return "array"
	case string:
		return "string"
	case bool:
		return "boolean"
	case int, int64:
		return "integer"
	case float64:
		if x == float64(int64(x)) {
			return "integer"
		}
		return "number"
	}
	return fmt.Sprintf("%T", v)
}

func typeOK(t string, v any) bool {
	switch t {
	case "object", "array", "string", "boolean", "null":
		return kind(v) == t
	case "integer":
		return kind(v) == "integer"
	case "number":
		_, ok := toFloat(v)
		return ok
	}
	return true
}

func toFloat(v any) (float64, bool) {
	switch x := v.(type) {
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	case float64:
		return x, true
	}
	return 0, false
}

func show(v any) string {
	switch x := v.(type) {
	case string:
		return fmt.Sprintf("%q", x)
	case map[string]any:
		return "an object"
	case []any:
		return "a list"
	}
	return fmt.Sprint(v)
}

func contains(list []any, v any) bool {
	for _, e := range list {
		if fmt.Sprint(e) == fmt.Sprint(v) {
			return true
		}
	}
	return false
}

func joinAny(list []any) string {
	parts := make([]string, len(list))
	for i, e := range list {
		parts[i] = fmt.Sprint(e)
	}
	return strings.Join(parts, ", ")
}

func stringList(v any) []string {
	list, _ := v.([]any)
	out := make([]string, 0, len(list))
	for _, e := range list {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

var hostname = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)

func formatOK(format, v string) bool {
	switch format {
	case "date":
		_, err := time.Parse("2006-01-02", v)
		return err == nil
	case "uri":
		u, err := url.Parse(v)
		return err == nil && u.Scheme != "" && u.Host != ""
	case "hostname":
		return hostname.MatchString(v)
	}
	return true
}
