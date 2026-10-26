package jsonschema

import (
	"strings"
	"testing"
)

const testSchema = `{
  "type": "object",
  "additionalProperties": false,
  "required": ["name", "mode"],
  "properties": {
    "name": {"$ref": "#/$defs/slug"},
    "mode": {"enum": ["a", "b"]},
    "count": {"type": "integer", "minimum": 1, "maximum": 5},
    "tags": {"type": "array", "minItems": 1, "uniqueItems": true, "items": {"type": "string"}},
    "ttl": {"type": "string", "pattern": "^[1-9][0-9]*h$"},
    "day": {"type": "string", "format": "date"},
    "link": {"type": "string", "format": "uri"}
  },
  "$defs": {"slug": {"type": "string", "pattern": "^[a-z][a-z0-9-]+$"}},
  "allOf": [
    {
      "description": "ttl goes with mode b only",
      "if": {"properties": {"mode": {"const": "b"}}},
      "then": {"required": ["ttl"]},
      "else": {"not": {"required": ["ttl"]}}
    }
  ]
}`

func TestValidate(t *testing.T) {
	s, err := Parse([]byte(testSchema))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		doc  map[string]any
		want []string // substrings, in order; none means valid
	}{
		{"valid", map[string]any{"name": "app-1", "mode": "a"}, nil},
		{"valid b with ttl", map[string]any{"name": "app", "mode": "b", "ttl": "72h"}, nil},
		{"missing required", map[string]any{"mode": "a"}, []string{"name: required property is missing"}},
		{"unknown field", map[string]any{"name": "app", "mode": "a", "extra": 1}, []string{"extra: unknown field (rejected)"}},
		{"bad enum", map[string]any{"name": "app", "mode": "z"}, []string{`mode: must be one of a, b (got "z")`}},
		{"bad pattern via ref", map[string]any{"name": "Bad_Name", "mode": "a"}, []string{"name: must match"}},
		{"wrong type", map[string]any{"name": "app", "mode": "a", "count": "three"}, []string{"count: must be of type integer (got string)"}},
		{"below minimum", map[string]any{"name": "app", "mode": "a", "count": int64(0)}, []string{"count: must be at least 1"}},
		{"above maximum", map[string]any{"name": "app", "mode": "a", "count": int64(9)}, []string{"count: must be at most 5"}},
		{"empty array", map[string]any{"name": "app", "mode": "a", "tags": []any{}}, []string{"tags: needs at least 1 items"}},
		{"duplicate item", map[string]any{"name": "app", "mode": "a", "tags": []any{"x", "x"}}, []string{"tags[1]: duplicate item"}},
		{"bad item type", map[string]any{"name": "app", "mode": "a", "tags": []any{int64(1)}}, []string{"tags[0]: must be of type string"}},
		{"then branch requires ttl", map[string]any{"name": "app", "mode": "b"}, []string{"ttl: required property is missing (ttl goes with mode b only)"}},
		{"else branch rejects ttl", map[string]any{"name": "app", "mode": "a", "ttl": "1h"}, []string{": is not allowed (ttl goes with mode b only)"}},
		{"bad date", map[string]any{"name": "app", "mode": "a", "day": "2026-13-40"}, []string{"day: must be a valid date"}},
		{"bad uri", map[string]any{"name": "app", "mode": "a", "link": "not a uri"}, []string{"link: must be a valid uri"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			errs := s.Validate(c.doc)
			if len(c.want) == 0 {
				if len(errs) != 0 {
					t.Fatalf("want valid, got %v", errs)
				}
				return
			}
			for _, w := range c.want {
				found := false
				for _, e := range errs {
					if strings.Contains(e.Path+": "+e.Message, w) {
						found = true
					}
				}
				if !found {
					t.Errorf("want an error containing %q, got %v", w, errs)
				}
			}
		})
	}
}

func TestContainsAndNumbers(t *testing.T) {
	s, err := Parse([]byte(`{"type":"object","properties":{"envs":{"type":"array","contains":{"const":"prod"}},"n":{"type":"number","exclusiveMinimum":0}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if errs := s.Validate(map[string]any{"envs": []any{"dev", "prod"}, "n": 0.5}); len(errs) != 0 {
		t.Fatalf("want valid, got %v", errs)
	}
	errs := s.Validate(map[string]any{"envs": []any{"dev"}, "n": int64(0)})
	if len(errs) != 2 {
		t.Fatalf("want 2 errors, got %v", errs)
	}
}

func TestParseRejectsBadJSON(t *testing.T) {
	if _, err := Parse([]byte("{nope")); err == nil {
		t.Fatal("want an error")
	}
}
