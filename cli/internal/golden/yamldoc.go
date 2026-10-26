package golden

import (
	"errors"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// parseDoc decodes the first YAML document into plain values (maps, lists,
// strings, int64, float64, bool, nil) and records the source line of every
// path. Timestamps stay strings, because the contract schema treats dates as
// strings.
func parseDoc(data []byte) (any, map[string]int, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, nil, fmt.Errorf("not valid YAML: %w", err)
	}
	if root.Kind == 0 {
		return nil, nil, errors.New("the file is empty")
	}
	if root.Kind != yaml.DocumentNode || len(root.Content) != 1 {
		return nil, nil, errors.New("expected one YAML document")
	}
	lines := map[string]int{}
	v, err := convert(root.Content[0], "", lines)
	if err != nil {
		return nil, nil, err
	}
	return v, lines, nil
}

func convert(n *yaml.Node, path string, lines map[string]int) (any, error) {
	lines[path] = n.Line
	switch n.Kind {
	case yaml.AliasNode:
		return convert(n.Alias, path, lines)
	case yaml.MappingNode:
		m := make(map[string]any, len(n.Content)/2)
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, val := n.Content[i], n.Content[i+1]
			if k.Kind != yaml.ScalarNode {
				return nil, fmt.Errorf("line %d: mapping keys must be plain strings", k.Line)
			}
			if _, dup := m[k.Value]; dup {
				return nil, fmt.Errorf("line %d: duplicate key %q", k.Line, k.Value)
			}
			child := joinPath(path, k.Value)
			v, err := convert(val, child, lines)
			if err != nil {
				return nil, err
			}
			lines[child] = k.Line
			m[k.Value] = v
		}
		return m, nil
	case yaml.SequenceNode:
		list := make([]any, len(n.Content))
		for i, item := range n.Content {
			v, err := convert(item, fmt.Sprintf("%s[%d]", path, i), lines)
			if err != nil {
				return nil, err
			}
			list[i] = v
		}
		return list, nil
	case yaml.ScalarNode:
		switch n.ShortTag() {
		case "!!null":
			return nil, nil
		case "!!bool":
			var b bool
			if err := n.Decode(&b); err != nil {
				return nil, err
			}
			return b, nil
		case "!!int":
			var i int64
			if err := n.Decode(&i); err != nil {
				return nil, err
			}
			return i, nil
		case "!!float":
			var f float64
			if err := n.Decode(&f); err != nil {
				return nil, err
			}
			return f, nil
		}
		return n.Value, nil
	}
	return nil, fmt.Errorf("line %d: unsupported YAML", n.Line)
}

func joinPath(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

// lineFor finds the line of path, falling back to the nearest parent.
func lineFor(lines map[string]int, path string) int {
	for {
		if l, ok := lines[path]; ok {
			return l
		}
		i := strings.LastIndexAny(path, ".[")
		if i < 0 {
			return lines[""]
		}
		path = path[:i]
	}
}
