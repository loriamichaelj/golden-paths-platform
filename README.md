# platform

Landing zones, per-cloud modules, golden-path definitions, policy and the `gold` CLI.

App repos consume tagged releases of this repo: path modules by `paths-v*` tags, policy by `policy-v*`, scripts by `scripts-v*`, and the `gold` binary from the package registry. CI/CD components live in the `devops/pipeline` repo.

The contract every app fills in is defined by `golden-paths/schema/golden-path.schema.json`; `golden-paths/examples/` has a valid contract per archetype.
