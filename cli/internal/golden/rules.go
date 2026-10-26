package golden

import (
	"fmt"
	"strings"
	"time"
)

// enginesFor lists which engines suit each database model.
var enginesFor = map[string][]string{
	"relational":  {"postgres", "mysql", "sqlserver", "default"},
	"document":    {"mongodb", "default"},
	"key-value":   {"default"},
	"wide-column": {"default"},
	"cache":       {"default"},
}

func has(list []string, v string) bool {
	for _, e := range list {
		if e == v {
			return true
		}
	}
	return false
}

// crossCheck applies the rules the schema cannot express.
func (p *Platform) crossCheck(c *Contract, now time.Time) []Finding {
	var out []Finding
	errf := func(path, format string, args ...any) {
		out = append(out, Finding{Path: path, Severity: "error", Message: fmt.Sprintf(format, args...)})
	}
	warnf := func(path, format string, args ...any) {
		out = append(out, Finding{Path: path, Severity: "warning", Message: fmt.Sprintf(format, args...)})
	}
	s := c.Spec

	if s.DataClass == "regulated" && s.Network == "public" {
		errf("spec.network", "data_class regulated needs network private or internal-only, not public")
	}
	if s.DataClass == "confidential" && s.Network == "public" && s.Archetype != "three-tier" && len(s.Web) == 0 {
		warnf("spec.network", "network public with confidential data and no CDN in front; put a web tier or load balancer in front, or use private")
	}
	if s.Lifecycle == "ephemeral" && has(s.Environments, "prod") {
		errf("spec.environments", "an ephemeral contract can't include prod; pipelines never delete prod")
	}
	if s.CostProfile == "reserved" && !has(s.Environments, "prod") {
		warnf("spec.cost_profile", "reserved capacity only pays off in prod, and prod is not in environments")
	}
	if s.Archetype != "microservices-events" {
		if len(s.Services) > 0 {
			errf("spec.services", "services is only used by the microservices-events archetype")
		}
		if s.Events != nil {
			errf("spec.events", "events is only used by the microservices-events archetype")
		}
	}

	seenDB := map[string]bool{}
	for i, d := range s.Databases {
		base := fmt.Sprintf("spec.databases[%d]", i)
		if seenDB[d.Name] {
			errf(base+".name", "database name %q is used twice", d.Name)
		}
		seenDB[d.Name] = true
		engine := d.Engine
		if engine == "" {
			engine = "default"
		}
		if !has(enginesFor[d.Model], engine) {
			errf(base+".engine", "engine %s doesn't fit model %s (use one of %s)", engine, d.Model, strings.Join(enginesFor[d.Model], ", "))
		}
		if d.Model == "wide-column" {
			warnf(base+".model", "wide-column databases are exception-only (Bigtable or Cassandra-compatible)")
		}
	}
	seenWeb := map[string]bool{}
	for i, w := range s.Web {
		if seenWeb[w.Name] {
			errf(fmt.Sprintf("spec.web[%d].name", i), "web name %q is used twice", w.Name)
		}
		seenWeb[w.Name] = true
	}

	if s.Custom != nil {
		out = append(out, p.checkCustom(c, now)...)
	}
	return out
}

func (p *Platform) checkCustom(c *Contract, now time.Time) []Finding {
	var out []Finding
	errf := func(path, format string, args ...any) {
		out = append(out, Finding{Path: path, Severity: "error", Message: fmt.Sprintf(format, args...)})
	}
	cu := c.Spec.Custom
	rules := p.Catalog.Custom

	if review, err := time.Parse("2006-01-02", cu.ReviewBy); err == nil {
		today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
		switch {
		case review.Before(today):
			errf("spec.custom.review_by", "the review date %s has passed; a new review is needed before this exception continues", cu.ReviewBy)
		case review.After(today.AddDate(0, 0, rules.MaxReviewDays)):
			errf("spec.custom.review_by", "review_by must be within %d days (by %s)", rules.MaxReviewDays, today.AddDate(0, 0, rules.MaxReviewDays).Format("2006-01-02"))
		}
	}
	if rules.MaxComponents > 0 && len(cu.Components) > rules.MaxComponents {
		errf("spec.custom.components", "a custom path allows at most %d components (got %d)", rules.MaxComponents, len(cu.Components))
	}

	byName := map[string]Component{}
	for i, comp := range cu.Components {
		base := fmt.Sprintf("spec.custom.components[%d]", i)
		if _, dup := byName[comp.Name]; dup {
			errf(base+".name", "component name %q is used twice", comp.Name)
		}
		byName[comp.Name] = comp
		mod, ok := p.Catalog.Modules[comp.Module]
		if !ok {
			errf(base+".module", "%q is not a catalog module; only catalog modules are allowed, never raw cloud resources", comp.Module)
			continue
		}
		if comp.Public && !mod.Public {
			errf(base+".public", "only load balancers, CDNs and object storage can be public; %s can't", comp.Module)
		}
		if comp.Public && c.Spec.DataClass == "regulated" {
			errf(base+".public", "nothing can be public with regulated data")
		}
		for key := range comp.Inputs {
			if has(rules.LockedInputs, strings.ToLower(key)) {
				errf(base+".inputs."+key, "input %s is owned by the platform and can't be overridden (%s)", key, strings.Join(rules.LockedInputs, ", "))
			}
		}
	}
	for i, conn := range cu.Connections {
		base := fmt.Sprintf("spec.custom.connections[%d]", i)
		for _, end := range []struct{ field, name string }{{"source", conn.Source}, {"destination", conn.Destination}} {
			if end.name != "internet" {
				if _, ok := byName[end.name]; !ok {
					errf(base+"."+end.field, "%q is not a component in this contract (use a component name or internet)", end.name)
				}
			}
		}
		if conn.Source == "internet" && conn.Destination == "internet" {
			errf(base, "a connection can't go from internet to internet")
		}
		if conn.Source == "internet" {
			if dest, ok := byName[conn.Destination]; ok && !dest.Public {
				errf(base+".destination", "traffic from the internet may only reach a public component; %s is not public", conn.Destination)
			}
		}
	}
	return out
}
