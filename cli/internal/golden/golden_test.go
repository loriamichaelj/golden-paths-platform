package golden

import (
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"gitlab.com/michaeljloria/golden-paths-platform/cli/internal/embedded"
)

var now = time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)

func load(t *testing.T) *Platform {
	t.Helper()
	p, err := Load(embedded.FS())
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestEveryExampleIsValidAndWarningFree(t *testing.T) {
	p := load(t)
	for _, a := range Archetypes {
		res := p.Validate(a+".yaml", p.Examples[a], true, now)
		if !res.Valid || len(res.Findings) != 0 {
			t.Errorf("%s example: %+v", a, res.Findings)
		}
	}
}

func TestPlatformDataIsConsistent(t *testing.T) {
	p := load(t)
	if len(p.Examples) != len(Archetypes) {
		t.Fatalf("want %d examples, got %d", len(Archetypes), len(p.Examples))
	}
	// A catalog that names an unknown module must be rejected on load.
	fsys := fstest.MapFS{}
	src := embedded.FS()
	for _, name := range []string{"catalog.yaml", "schema/golden-path.schema.json", "defaults/sizes.yaml", "defaults/tiers.yaml"} {
		b, err := fs.ReadFile(src, name)
		if err != nil {
			t.Fatal(err)
		}
		fsys[name] = &fstest.MapFile{Data: b}
	}
	for a, b := range p.Examples {
		fsys["examples/"+a+".yaml"] = &fstest.MapFile{Data: b}
	}
	broken := strings.Replace(string(fsys["catalog.yaml"].Data), "modules: [network, identity, secrets, serverless-containers, load-balancer]", "modules: [network, no-such-module]", 1)
	fsys["catalog.yaml"] = &fstest.MapFile{Data: []byte(broken)}
	if _, err := Load(fsys); err == nil || !strings.Contains(err.Error(), "no-such-module") {
		t.Fatalf("want an unknown-module error, got %v", err)
	}
}

type edit struct{ from, to string }

func TestRejectedContracts(t *testing.T) {
	p := load(t)
	single := string(p.Examples["single-api"])
	custom := string(p.Examples["custom"])

	cases := []struct {
		name    string
		base    string
		edits   []edit
		appends string
		want    string
	}{
		{"bad enum", single, []edit{{"tier: bronze", "tier: platinum"}}, "", "spec.tier: must be one of bronze, silver, gold"},
		{"unknown field", single, nil, "  instance_type: m7g.large\n", "spec.instance_type: unknown field (rejected)"},
		{"wrong api version", single, []edit{{"platform.example.com/v1", "other/v1"}}, "", "apiVersion: must be platform.example.com/v1"},
		{"bad name", single, []edit{{"name: hello-api", "name: Hello_API"}}, "", "metadata.name: must match"},
		{"spot with prod", single, []edit{{"cost_profile: balanced", "cost_profile: spot-first"}}, "", "Spot capacity is never allowed"},
		{"regulated and public", single, []edit{{"data_class: internal", "data_class: regulated"}, {"network: private", "network: public"}}, "", "regulated needs network private or internal-only"},
		{"ephemeral needs ttl", single, []edit{{"lifecycle: persistent", "lifecycle: ephemeral"}}, "", "spec.ttl: required property is missing"},
		{"persistent rejects ttl", single, nil, "  ttl: 72h\n", "is not allowed"},
		{"ephemeral in prod", single, []edit{{"lifecycle: persistent", "lifecycle: ephemeral\n  ttl: 72h"}}, "", "can't include prod"},
		{"services on wrong path", single, nil, "  services: [other-service]\n", "only used by the microservices-events archetype"},
		{"engine and model disagree", single, nil, "  databases:\n    - {name: main-db, model: relational, engine: mongodb, size: S}\n", "doesn't fit model relational"},
		{"duplicate database", single, nil, "  databases:\n    - {name: main-cache, model: cache, size: S}\n    - {name: main-cache, model: cache, size: S}\n", `database name "main-cache" is used twice`},
		{"duplicate key", single, []edit{{"tier: bronze", "tier: bronze\n  tier: gold"}}, "", `duplicate key "tier"`},
		{"not yaml", "name: [unclosed", nil, "", "not valid YAML"},
		{"empty file", "", nil, "", "empty"},
		{"expired custom review", custom, []edit{{`"2027-01-15"`, `"2026-01-01"`}}, "", "has passed"},
		{"custom review too far out", custom, []edit{{`"2027-01-15"`, `"2027-12-31"`}}, "", "within 180 days"},
		{"custom raw resource", custom, []edit{{"module: serverless-containers", "module: aws_instance"}}, "", "not a catalog module"},
		{"custom public database", custom, []edit{{"{name: assets, module: object-storage}", "{name: assets, module: object-storage}\n      - {name: main-db, module: database-relational, public: true}"}}, "", "only load balancers, CDNs and object storage can be public"},
		{"custom locked input", custom, []edit{{"{name: assets, module: object-storage}", "{name: assets, module: object-storage, inputs: {Encryption: none}}"}}, "", "owned by the platform"},
		{"custom unknown endpoint", custom, []edit{{"destination: assets", "destination: nowhere"}}, "", `"nowhere" is not a component`},
		{"custom internet to private", custom, []edit{{"{source: internet, destination: edge, port: 443}", "{source: internet, destination: api, port: 443}"}}, "", "may only reach a public component"},
		{"custom regulated public", custom, []edit{{"data_class: internal", "data_class: regulated"}, {"network: public", "network: private"}}, "", "nothing can be public with regulated data"},
		{"custom block on other path", single, nil, "  custom: {justification: x}\n", "is not allowed"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := c.base
			for _, e := range c.edits {
				if !strings.Contains(doc, e.from) {
					t.Fatalf("test edit %q not found in base", e.from)
				}
				doc = strings.Replace(doc, e.from, e.to, 1)
			}
			doc += c.appends
			res := p.Validate("c.yaml", []byte(doc), false, now)
			if res.Valid {
				t.Fatal("want a rejected contract, got valid")
			}
			var all []string
			for _, f := range res.Findings {
				all = append(all, f.Path+": "+f.Message)
			}
			if !strings.Contains(strings.Join(all, "\n"), c.want) {
				t.Fatalf("want a finding containing %q, got:\n%s", c.want, strings.Join(all, "\n"))
			}
		})
	}
}

func TestWarningsFailOnlyWhenStrict(t *testing.T) {
	p := load(t)
	doc := strings.NewReplacer("data_class: internal", "data_class: confidential", "network: private", "network: public").Replace(string(p.Examples["single-api"]))
	if res := p.Validate("c.yaml", []byte(doc), false, now); !res.Valid || len(res.Findings) != 1 || res.Findings[0].Severity != "warning" {
		t.Fatalf("want one warning and a valid contract, got %+v", res)
	}
	if res := p.Validate("c.yaml", []byte(doc), true, now); res.Valid {
		t.Fatal("want strict mode to fail on the warning")
	}
}

func TestFindingsCarryLineNumbers(t *testing.T) {
	p := load(t)
	doc := strings.Replace(string(p.Examples["single-api"]), "tier: bronze", "tier: platinum", 1)
	res := p.Validate("c.yaml", []byte(doc), false, now)
	want := 0
	for i, l := range strings.Split(doc, "\n") {
		if strings.Contains(l, "tier: platinum") {
			want = i + 1
		}
	}
	if len(res.Findings) == 0 || res.Findings[0].Line != want {
		t.Fatalf("want a finding on line %d, got %+v", want, res.Findings)
	}
}

func TestInitProducesValidContractsForEveryArchetypeAndCloud(t *testing.T) {
	p := load(t)
	for _, a := range Archetypes {
		for _, cloud := range Clouds {
			data, err := p.Init(InitOptions{Archetype: a, Cloud: cloud, Name: "my-app", Owner: "team-z", Now: now})
			if err != nil {
				t.Fatalf("%s/%s: %v", a, cloud, err)
			}
			res := p.Validate("golden-path.yaml", data, true, now)
			if !res.Valid {
				t.Fatalf("%s/%s: %+v\n%s", a, cloud, res.Findings, data)
			}
			if c := res.Contract; c.Metadata.Name != "my-app" || c.Metadata.Owner != "team-z" || c.Spec.Cloud != cloud {
				t.Errorf("%s/%s: wrong name, owner or cloud: %+v", a, cloud, c.Metadata)
			}
		}
	}
}

func TestInitKeepsCommentsAndSetsCustomReview(t *testing.T) {
	p := load(t)
	data, err := p.Init(InitOptions{Archetype: "custom", Cloud: "azure", Name: "my-app", Owner: "team-z", Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if want := `review_by: "2027-01-24"`; !strings.Contains(string(data), want) {
		t.Fatalf("want %s in:\n%s", want, data)
	}
	if !strings.Contains(string(data), "components:") || !strings.Contains(string(data), "[secrets]") {
		t.Fatalf("flow style lost:\n%s", data)
	}
}

func TestInitRejectsBadInput(t *testing.T) {
	p := load(t)
	for _, o := range []InitOptions{
		{Archetype: "nope", Cloud: "aws", Name: "my-app", Owner: "team"},
		{Archetype: "single-api", Cloud: "mars", Name: "my-app", Owner: "team"},
		{Archetype: "single-api", Cloud: "aws", Name: "My App", Owner: "team"},
		{Archetype: "single-api", Cloud: "aws", Name: "my-app", Owner: "x"},
	} {
		if _, err := p.Init(o); err == nil {
			t.Errorf("want an error for %+v", o)
		}
	}
}

func TestExplain(t *testing.T) {
	p := load(t)
	res := p.Validate("c.yaml", p.Examples["microservices-events"], true, now)
	e := p.Explain(res.Contract)

	services := map[string]string{}
	for _, r := range e.Resources {
		services[r.Module] = r.Service
	}
	for module, want := range map[string]string{
		"kubernetes": "EKS", "event-stream": "Amazon MSK", "event-queue": "SQS with SNS",
		"database-relational": "Aurora or RDS for PostgreSQL", "object-storage": "S3",
	} {
		if services[module] != want {
			t.Errorf("%s: want %q, got %q", module, want, services[module])
		}
	}
	if len(e.Environment) != 4 || e.Environment[0].Env != "dev" || e.Environment[0].Runtime != "EKS Auto Mode" || e.Environment[3].Runtime != "EKS" {
		t.Errorf("unexpected environments: %+v", e.Environment)
	}
	if e.Reliability.Zones != 3 || e.Reliability.SLO != 99.9 || e.Reliability.SLA == nil {
		t.Errorf("unexpected gold tier: %+v", e.Reliability)
	}
	if len(e.Databases) != 1 || e.Databases[0].TierDefaults.RPO != "5m" {
		t.Errorf("unexpected database plan: %+v", e.Databases)
	}

	var text strings.Builder
	e.WriteText(&text)
	for _, want := range []string{"checkout: microservices-events on aws", "Resources on aws", "Guardrails", "platform and app lead"} {
		if !strings.Contains(text.String(), want) {
			t.Errorf("text output lacks %q:\n%s", want, text.String())
		}
	}
}

func TestExplainEphemeralAndEveryExample(t *testing.T) {
	p := load(t)
	for _, a := range Archetypes {
		res := p.Validate("c.yaml", p.Examples[a], true, now)
		if e := p.Explain(res.Contract); len(e.Resources) == 0 || len(e.Environment) == 0 || len(e.Guardrails) == 0 {
			t.Errorf("%s: empty explanation %+v", a, e)
		}
	}
	doc := strings.Replace(string(p.Examples["single-api"]), "lifecycle: persistent", "lifecycle: ephemeral\n  ttl: 72h\n  destroy_policy: both", 1)
	doc = strings.Replace(doc, "environments: [dev, stage, prod]", "environments: [dev]", 1)
	res := p.Validate("c.yaml", []byte(doc), true, now)
	if !res.Valid {
		t.Fatalf("%+v", res.Findings)
	}
	e := p.Explain(res.Contract)
	if len(e.Environment) != 1 || e.Environment[0].Env != "ephemeral" || e.Environment[0].Purchase != "spot" {
		t.Errorf("unexpected ephemeral plan: %+v", e.Environment)
	}
}
