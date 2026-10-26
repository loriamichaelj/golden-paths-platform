// Package golden holds the platform data (catalog, sizes, tiers, schema,
// examples) and the rules gold applies to a golden-path contract.
package golden

import (
	"fmt"
	"io/fs"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"gitlab.com/michaeljloria/golden-paths-platform/cli/internal/jsonschema"
)

// Archetypes lists the app types in catalog order.
var Archetypes = []string{"single-api", "microservices", "event-driven", "microservices-events", "three-tier", "vm-workload", "custom"}

// Clouds lists the supported clouds.
var Clouds = []string{"aws", "azure", "gcp"}

// Module is one building block and the product that provides it on each cloud.
type Module struct {
	Public   bool              `yaml:"public" json:"public"`
	Services map[string]string `yaml:"services" json:"services"`
}

// ArchetypeInfo describes one app type.
type ArchetypeInfo struct {
	Summary string `yaml:"summary" json:"summary"`
	Runtime struct {
		Default string `yaml:"default" json:"default"`
		Dev     string `yaml:"dev" json:"dev"`
	} `yaml:"runtime" json:"runtime"`
	Modules  []string `yaml:"modules" json:"modules"`
	Addons   []string `yaml:"addons" json:"addons,omitempty"`
	Composed bool     `yaml:"composed" json:"composed,omitempty"`
}

// CustomRules are the guardrails on spec.custom.
type CustomRules struct {
	MaxReviewDays int      `yaml:"max_review_days" json:"max_review_days"`
	MaxComponents int      `yaml:"max_components" json:"max_components"`
	LockedInputs  []string `yaml:"locked_inputs" json:"locked_inputs"`
}

// Catalog is golden-paths/catalog.yaml.
type Catalog struct {
	Version    int                          `yaml:"version"`
	Runtimes   map[string]map[string]string `yaml:"runtimes"`
	Modules    map[string]Module            `yaml:"modules"`
	Archetypes map[string]ArchetypeInfo     `yaml:"archetypes"`
	Custom     CustomRules                  `yaml:"custom"`
}

// Size is a CPU and memory range.
type Size struct {
	VCPU      [2]int `yaml:"vcpu" json:"vcpu"`
	MemoryGiB [2]int `yaml:"memory_gib" json:"memory_gib"`
}

// DatabaseTier holds database defaults for a tier.
type DatabaseTier struct {
	Availability string `yaml:"availability" json:"availability"`
	Backups      string `yaml:"backups" json:"backups"`
	RetentionDay int    `yaml:"retention_days" json:"retention_days"`
	PITR         bool   `yaml:"pitr" json:"pitr"`
	RPO          string `yaml:"rpo" json:"rpo"`
	RTO          string `yaml:"rto" json:"rto"`
	RestoreTest  string `yaml:"restore_test" json:"restore_test"`
}

// Tier holds what a service tier sets.
type Tier struct {
	Zones    int          `yaml:"zones" json:"zones"`
	SLO      float64      `yaml:"slo" json:"slo"`
	SLA      *float64     `yaml:"sla" json:"sla,omitempty"`
	Paging   string       `yaml:"paging" json:"paging"`
	Database DatabaseTier `yaml:"database" json:"database"`
}

// Platform is everything gold knows about golden paths.
type Platform struct {
	Catalog   Catalog
	Sizes     map[string]Size
	Tiers     map[string]Tier
	Schema    *jsonschema.Schema
	SchemaRaw []byte
	Examples  map[string][]byte // archetype to example contract
}

// Load reads the platform data from fsys, laid out like golden-paths/.
func Load(fsys fs.FS) (*Platform, error) {
	p := &Platform{Examples: map[string][]byte{}}
	read := func(name string) ([]byte, error) {
		b, err := fs.ReadFile(fsys, name)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", name, err)
		}
		return b, nil
	}
	b, err := read("catalog.yaml")
	if err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(b, &p.Catalog); err != nil {
		return nil, fmt.Errorf("parse catalog.yaml: %w", err)
	}
	if b, err = read("defaults/sizes.yaml"); err != nil {
		return nil, err
	}
	var sizes struct {
		Sizes map[string]Size `yaml:"sizes"`
	}
	if err := yaml.Unmarshal(b, &sizes); err != nil {
		return nil, fmt.Errorf("parse sizes.yaml: %w", err)
	}
	p.Sizes = sizes.Sizes
	if b, err = read("defaults/tiers.yaml"); err != nil {
		return nil, err
	}
	var tiers struct {
		Tiers map[string]Tier `yaml:"tiers"`
	}
	if err := yaml.Unmarshal(b, &tiers); err != nil {
		return nil, fmt.Errorf("parse tiers.yaml: %w", err)
	}
	p.Tiers = tiers.Tiers
	if p.SchemaRaw, err = read("schema/golden-path.schema.json"); err != nil {
		return nil, err
	}
	if p.Schema, err = jsonschema.Parse(p.SchemaRaw); err != nil {
		return nil, err
	}
	names, err := fs.Glob(fsys, "examples/*.yaml")
	if err != nil {
		return nil, err
	}
	for _, name := range names {
		if b, err = read(name); err != nil {
			return nil, err
		}
		var c struct {
			Spec struct {
				Archetype string `yaml:"archetype"`
			} `yaml:"spec"`
		}
		if err := yaml.Unmarshal(b, &c); err != nil || c.Spec.Archetype == "" {
			return nil, fmt.Errorf("example %s has no spec.archetype", name)
		}
		p.Examples[c.Spec.Archetype] = b
	}
	return p, p.check()
}

// check makes sure the data is internally consistent.
func (p *Platform) check() error {
	var problems []string
	for _, a := range Archetypes {
		info, ok := p.Catalog.Archetypes[a]
		if !ok {
			problems = append(problems, "catalog.yaml has no archetype "+a)
			continue
		}
		if _, ok := p.Examples[a]; !ok {
			problems = append(problems, "there is no example for archetype "+a)
		}
		for _, m := range info.Modules {
			if _, ok := p.Catalog.Modules[m]; !ok {
				problems = append(problems, fmt.Sprintf("archetype %s uses unknown module %s", a, m))
			}
		}
		for _, rt := range []string{info.Runtime.Default, info.Runtime.Dev} {
			if _, ok := p.Catalog.Runtimes[rt]; !ok {
				problems = append(problems, fmt.Sprintf("archetype %s uses unknown runtime %q", a, rt))
			}
		}
	}
	for name, m := range p.Catalog.Modules {
		for _, c := range Clouds {
			if m.Services[c] == "" {
				problems = append(problems, fmt.Sprintf("module %s has no service for %s", name, c))
			}
		}
	}
	for _, s := range []string{"S", "M", "L", "XL"} {
		if _, ok := p.Sizes[s]; !ok {
			problems = append(problems, "sizes.yaml has no size "+s)
		}
	}
	for _, t := range []string{"bronze", "silver", "gold"} {
		if _, ok := p.Tiers[t]; !ok {
			problems = append(problems, "tiers.yaml has no tier "+t)
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return fmt.Errorf("platform data is inconsistent:\n  %s", strings.Join(problems, "\n  "))
	}
	return nil
}
