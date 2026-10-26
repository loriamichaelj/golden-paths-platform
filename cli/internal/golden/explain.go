package golden

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
)

// Explanation is what a contract turns into.
type Explanation struct {
	App         string         `json:"app"`
	Owner       string         `json:"owner"`
	Archetype   string         `json:"archetype"`
	Cloud       string         `json:"cloud"`
	Tier        string         `json:"tier"`
	Size        string         `json:"size"`
	Compute     Compute        `json:"compute"`
	Resources   []Resource     `json:"resources"`
	Environment []EnvPlan      `json:"environments"`
	Reliability Reliability    `json:"reliability"`
	Databases   []DatabasePlan `json:"databases,omitempty"`
	Guardrails  []string       `json:"guardrails"`
}

// Compute is the machine range the size turns into.
type Compute struct {
	VCPU      [2]int `json:"vcpu"`
	MemoryGiB [2]int `json:"memory_gib"`
	Arch      string `json:"arch"`
}

// Resource is one building block and the cloud service behind it.
type Resource struct {
	Module  string `json:"module"`
	Service string `json:"service"`
}

// EnvPlan is how one environment runs and who approves changes to it.
type EnvPlan struct {
	Env      string `json:"env"`
	Runtime  string `json:"runtime"`
	Purchase string `json:"purchase"`
	Approval string `json:"approval"`
	Destroy  string `json:"destroy"`
}

// Reliability is the tier's targets.
type Reliability struct {
	Zones  int      `json:"zones"`
	SLO    float64  `json:"slo_percent"`
	SLA    *float64 `json:"sla_percent,omitempty"`
	Paging string   `json:"paging"`
}

// DatabasePlan is one database and the defaults its tier gives it.
type DatabasePlan struct {
	Name         string       `json:"name"`
	Model        string       `json:"model"`
	Engine       string       `json:"engine"`
	Size         string       `json:"size"`
	Module       string       `json:"module"`
	Service      string       `json:"service"`
	TierDefaults DatabaseTier `json:"tier_defaults"`
}

var dbModule = map[string]string{
	"relational": "database-relational",
	"document":   "database-document",
	"key-value":  "database-keyvalue",
	"cache":      "cache",
}

var envOrder = []string{"dev", "stage", "uat", "prod"}

// Explain describes what a valid contract builds. It assumes Validate passed.
func (p *Platform) Explain(c *Contract) Explanation {
	s := c.Spec
	info := p.Catalog.Archetypes[s.Archetype]
	tier := p.Tiers[s.Tier]
	size := p.Sizes[s.Size]

	e := Explanation{
		App: c.Metadata.Name, Owner: c.Metadata.Owner, Archetype: s.Archetype, Cloud: s.Cloud, Tier: s.Tier, Size: s.Size,
		Compute:     Compute{VCPU: size.VCPU, MemoryGiB: size.MemoryGiB, Arch: s.Arch},
		Reliability: Reliability{Zones: tier.Zones, SLO: tier.SLO, SLA: tier.SLA, Paging: tier.Paging},
	}

	// Resources: the path's modules, then what the contract adds.
	seen := map[string]bool{}
	addModule := func(name string) {
		if name == "" || seen[name] {
			return
		}
		seen[name] = true
		e.Resources = append(e.Resources, Resource{Module: name, Service: p.Catalog.Modules[name].Services[s.Cloud]})
	}
	for _, m := range info.Modules {
		addModule(m)
	}
	if s.Custom != nil {
		for _, comp := range s.Custom.Components {
			addModule(comp.Module)
		}
	}
	for _, i := range s.Integrations {
		switch i {
		case "object-storage":
			addModule("object-storage")
		case "event-bus":
			addModule("event-queue")
		case "secrets":
			addModule("secrets")
		}
	}
	if s.Events != nil {
		if s.Events.Broker == "stream" {
			addModule("event-stream")
		} else {
			addModule("event-queue")
		}
	}
	for _, w := range s.Web {
		addModule("cdn")
		addModule("waf")
		if w.Render == "static" {
			addModule("object-storage")
		} else {
			addModule("serverless-containers")
		}
	}
	for _, d := range s.Databases {
		mod := dbModule[d.Model]
		engine := d.Engine
		if engine == "" {
			engine = "default"
		}
		plan := DatabasePlan{Name: d.Name, Model: d.Model, Engine: engine, Size: d.Size, TierDefaults: tier.Database}
		if mod != "" {
			addModule(mod)
			plan.Module, plan.Service = mod, p.Catalog.Modules[mod].Services[s.Cloud]
		} else {
			plan.Module, plan.Service = "(exception)", "wide-column databases are exception-only"
		}
		e.Databases = append(e.Databases, plan)
	}

	// Environments.
	rt := func(name string) string { return p.Catalog.Runtimes[name][s.Cloud] }
	for _, env := range envOrder {
		if !has(s.Environments, env) {
			continue
		}
		plan := EnvPlan{Env: env, Runtime: rt(info.Runtime.Default)}
		if env == "dev" {
			plan.Runtime = rt(info.Runtime.Dev)
		}
		plan.Purchase = purchase(s.CostProfile, env)
		plan.Approval, plan.Destroy = approval(env)
		e.Environment = append(e.Environment, plan)
	}
	if s.Lifecycle == "ephemeral" {
		e.Environment = []EnvPlan{{
			Env: "ephemeral", Runtime: rt(info.Runtime.Dev), Purchase: "spot",
			Approval: "automatic", Destroy: fmt.Sprintf("%s, expires after %s", s.Destroy, s.TTL),
		}}
	}

	e.Guardrails = guardrails(c, tier)
	return e
}

func purchase(profile, env string) string {
	switch {
	case profile == "spot-first" && env == "dev":
		return "spot, on-demand fallback"
	case profile == "reserved" && env == "prod":
		return "reserved"
	}
	return "balanced"
}

func approval(env string) (approve, destroy string) {
	switch env {
	case "dev":
		return "automatic after checks pass", "reviewed MR; no destroy job"
	case "stage":
		return "app team", "reviewed MR; no destroy job"
	case "uat":
		return "app team and QA", "reviewed MR; no destroy job"
	}
	return "platform and app lead (CODEOWNERS), change reference, change window", "never; org policy denies deletes"
}

func guardrails(c *Contract, tier Tier) []string {
	s := c.Spec
	g := []string{
		"no static cloud keys; each pipeline job gets a short-lived OIDC credential",
		"encryption at rest and in transit; every resource tagged owner, env, product, lifecycle, golden_path, gp_tier",
		"each environment in its own account, subscription or project",
	}
	switch s.DataClass {
	case "regulated":
		g = append(g, "regulated data: customer-managed keys, private network access only, access logs kept 1 year")
	case "confidential":
		g = append(g, "confidential data: customer-managed keys, object versioning on")
	}
	switch s.Network {
	case "internal-only":
		g = append(g, "internal-only: no public IPs and no public load balancer")
	case "private":
		g = append(g, "private: reachable only from inside the network")
	}
	if s.CostProfile == "spot-first" {
		g = append(g, "spot capacity outside prod only, with an on-demand fallback")
	}
	if tier.Zones > 1 {
		g = append(g, fmt.Sprintf("tier %s spans %d zones", s.Tier, tier.Zones))
	} else {
		g = append(g, fmt.Sprintf("tier %s runs in one zone", s.Tier))
	}
	if len(s.Databases) > 0 {
		g = append(g, "databases: private access only, identity-based login, deletion protection and a final snapshot in prod")
	}
	if s.Lifecycle == "ephemeral" {
		g = append(g, "ephemeral: expires_at tag, destroyed on demand, on expiry or by the sweeper; never in prod")
	}
	if s.Custom != nil {
		g = append(g, fmt.Sprintf("custom path: catalog modules only, review by %s, budget cap $%.0f a month", s.Custom.ReviewBy, s.Custom.Budget))
	}
	return g
}

// WriteText renders an explanation for people.
func (e Explanation) WriteText(w io.Writer) {
	fmt.Fprintf(w, "%s: %s on %s, tier %s, size %s (owner %s)\n\n", e.App, e.Archetype, e.Cloud, e.Tier, e.Size, e.Owner)
	fmt.Fprintf(w, "Compute: %d-%d vCPU, %d-%d GiB, %s\n\n", e.Compute.VCPU[0], e.Compute.VCPU[1], e.Compute.MemoryGiB[0], e.Compute.MemoryGiB[1], e.Compute.Arch)

	fmt.Fprintf(w, "Resources on %s\n", e.Cloud)
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, r := range e.Resources {
		fmt.Fprintf(tw, "  %s\t%s\n", r.Module, r.Service)
	}
	tw.Flush()

	fmt.Fprintf(w, "\nEnvironments\n")
	tw = tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "  ENV\tRUNTIME\tCOMPUTE\tCHANGES APPROVED BY\tDELETES\n")
	for _, p := range e.Environment {
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\n", p.Env, p.Runtime, p.Purchase, p.Approval, p.Destroy)
	}
	tw.Flush()

	fmt.Fprintf(w, "\nReliability: %d zone(s), SLO %.1f%%", e.Reliability.Zones, e.Reliability.SLO)
	if e.Reliability.SLA != nil {
		fmt.Fprintf(w, ", SLA %.1f%% if customer-facing", *e.Reliability.SLA)
	}
	fmt.Fprintf(w, ", paging %s\n", e.Reliability.Paging)

	for _, d := range e.Databases {
		t := d.TierDefaults
		fmt.Fprintf(w, "\nDatabase %s: %s (%s, size %s) on %s\n", d.Name, d.Model, d.Engine, d.Size, d.Service)
		fmt.Fprintf(w, "  %s, backups %s kept %d days, RPO %s, RTO %s, restore test %s\n", t.Availability, t.Backups, t.RetentionDay, t.RPO, t.RTO, t.RestoreTest)
	}

	fmt.Fprintf(w, "\nGuardrails\n%s\n", "  - "+strings.Join(e.Guardrails, "\n  - "))
}
