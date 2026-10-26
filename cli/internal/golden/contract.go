package golden

import (
	"fmt"
	"sort"
	"time"

	"gopkg.in/yaml.v3"
)

// Contract is golden-path.yaml.
type Contract struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Metadata   struct {
		Name  string `yaml:"name"`
		Owner string `yaml:"owner"`
	} `yaml:"metadata"`
	Spec Spec `yaml:"spec"`
}

// Spec is the contract body.
type Spec struct {
	Archetype    string     `yaml:"archetype"`
	Cloud        string     `yaml:"cloud"`
	Tier         string     `yaml:"tier"`
	Size         string     `yaml:"size"`
	CostProfile  string     `yaml:"cost_profile"`
	Arch         string     `yaml:"arch"`
	DataClass    string     `yaml:"data_class"`
	Network      string     `yaml:"network"`
	Integrations []string   `yaml:"integrations"`
	Environments []string   `yaml:"environments"`
	Lifecycle    string     `yaml:"lifecycle"`
	TTL          string     `yaml:"ttl"`
	Destroy      string     `yaml:"destroy_policy"`
	Databases    []Database `yaml:"databases"`
	Services     []string   `yaml:"services"`
	Events       *Events    `yaml:"events"`
	Web          []Web      `yaml:"web"`
	Custom       *Custom    `yaml:"custom"`
}

// Database is one requested managed database.
type Database struct {
	Name      string `yaml:"name"`
	Model     string `yaml:"model"`
	Engine    string `yaml:"engine"`
	Size      string `yaml:"size"`
	StorageGB int    `yaml:"storage_gb"`
}

// Events configures the combined path's broker.
type Events struct {
	Broker  string `yaml:"broker"`
	Schemas string `yaml:"schemas"`
}

// Web is one front end.
type Web struct {
	Name   string `yaml:"name"`
	Path   string `yaml:"path"`
	Render string `yaml:"render"`
	Domain string `yaml:"domain"`
	WAF    string `yaml:"waf"`
}

// Custom is the exception path.
type Custom struct {
	Justification string      `yaml:"justification"`
	ExceptionRef  string      `yaml:"exception_ref"`
	ReviewBy      string      `yaml:"review_by"`
	Budget        float64     `yaml:"budget_usd_month"`
	Components    []Component `yaml:"components"`
	Connections   []Conn      `yaml:"connections"`
}

// Component is one catalog module in a custom path.
type Component struct {
	Name   string         `yaml:"name"`
	Module string         `yaml:"module"`
	Size   string         `yaml:"size"`
	Public bool           `yaml:"public"`
	Inputs map[string]any `yaml:"inputs"`
}

// Conn is one allowed connection in a custom path.
type Conn struct {
	Source      string `yaml:"source"`
	Destination string `yaml:"destination"`
	Port        int    `yaml:"port"`
}

// Finding is one problem in a contract.
type Finding struct {
	Path     string `json:"path"`
	Line     int    `json:"line,omitempty"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

// Result is the outcome of validating one file.
type Result struct {
	Path     string    `json:"path"`
	Valid    bool      `json:"valid"`
	Findings []Finding `json:"findings"`
	Contract *Contract `json:"-"`
}

// Validate checks a contract: structure against the schema first, then the
// cross-field rules. With strict, warnings fail validation too.
func (p *Platform) Validate(path string, data []byte, strict bool, now time.Time) Result {
	res := Result{Path: path, Findings: []Finding{}}
	doc, lines, err := parseDoc(data)
	if err != nil {
		res.Findings = append(res.Findings, Finding{Severity: "error", Message: err.Error()})
		return res
	}
	for _, e := range p.Schema.Validate(doc) {
		res.Findings = append(res.Findings, Finding{Path: e.Path, Line: lineFor(lines, e.Path), Severity: "error", Message: e.Message})
	}
	if len(res.Findings) == 0 {
		var c Contract
		if err := yaml.Unmarshal(data, &c); err != nil {
			res.Findings = append(res.Findings, Finding{Severity: "error", Message: fmt.Sprintf("cannot read the contract: %v", err)})
		} else {
			res.Contract = &c
			for _, f := range p.crossCheck(&c, now) {
				f.Line = lineFor(lines, f.Path)
				res.Findings = append(res.Findings, f)
			}
		}
	}
	sort.SliceStable(res.Findings, func(i, j int) bool { return res.Findings[i].Line < res.Findings[j].Line })
	res.Valid = true
	for _, f := range res.Findings {
		if f.Severity == "error" || strict {
			res.Valid = false
		}
	}
	return res
}
