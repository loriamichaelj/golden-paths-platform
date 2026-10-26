package golden

import (
	"bytes"
	"fmt"
	"regexp"
	"time"

	"gopkg.in/yaml.v3"
)

var slug = regexp.MustCompile(`^[a-z][a-z0-9-]{1,38}[a-z0-9]$`)

// InitOptions are the answers gold init needs.
type InitOptions struct {
	Archetype string
	Cloud     string
	Name      string
	Owner     string
	Now       time.Time
}

// Init writes a contract from the archetype's example with the app's own
// name, owner and cloud. The example's comments and layout are kept.
func (p *Platform) Init(o InitOptions) ([]byte, error) {
	example, ok := p.Examples[o.Archetype]
	if !ok {
		return nil, fmt.Errorf("unknown archetype %q (use one of %v)", o.Archetype, Archetypes)
	}
	if !has(Clouds, o.Cloud) {
		return nil, fmt.Errorf("unknown cloud %q (use one of %v)", o.Cloud, Clouds)
	}
	for _, f := range []struct{ label, v string }{{"name", o.Name}, {"owner", o.Owner}} {
		if !slug.MatchString(f.v) {
			return nil, fmt.Errorf("%s %q must be lowercase letters, digits and hyphens, 3 to 40 characters, starting with a letter", f.label, f.v)
		}
	}

	var root yaml.Node
	if err := yaml.Unmarshal(example, &root); err != nil {
		return nil, err
	}
	doc := root.Content[0]
	set := func(value string, path ...string) error {
		n := doc
		for _, key := range path {
			n = mapValue(n, key)
			if n == nil {
				return fmt.Errorf("the %s example has no %v", o.Archetype, path)
			}
		}
		n.Value, n.Tag, n.Style = value, "!!str", 0
		return nil
	}
	if err := set(o.Name, "metadata", "name"); err != nil {
		return nil, err
	}
	if err := set(o.Owner, "metadata", "owner"); err != nil {
		return nil, err
	}
	if err := set(o.Cloud, "spec", "cloud"); err != nil {
		return nil, err
	}
	if o.Archetype == "custom" {
		// A custom path must be reviewed within 90 days of being written.
		if err := set(o.Now.AddDate(0, 0, 90).Format("2006-01-02"), "spec", "custom", "review_by"); err != nil {
			return nil, err
		}
		mapValue(mapValue(mapValue(doc, "spec"), "custom"), "review_by").Style = yaml.DoubleQuotedStyle
	}

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&root); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func mapValue(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}
