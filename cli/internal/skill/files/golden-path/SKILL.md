---
name: golden-path
description: Create, check and explain golden-path contracts (golden-path.yaml) with the gold command-line tool. Use when someone wants to set up, change or review how an app is built and run on AWS, Azure or GCP.
---

# Golden path contracts

A golden path is a pre-approved way to build and run an app. The app states what it needs in one file, `golden-path.yaml`, and the platform turns that into infrastructure. The `gold` tool checks and explains the file, so every rule comes from the tool and not from you.

## Rules

- Use `gold` for every check. Never re-implement a rule or guess what a field allows.
- Never run `tofu`, `terraform`, cloud CLIs or anything that applies changes. Changes reach the cloud only through the pipeline after a merge request.
- Never weaken `data_class`, `network`, a WAF setting or a locked input to make validation pass. If a rule blocks the request, explain which rule and why, and suggest the exception route in `reference/custom-paths.md`.
- Never put secrets, keys or tokens in the contract.
- Ask only for what you cannot work out from the repository. Never assume the answers to data sensitivity or who can reach the app; ask.

## Steps

1. Find out the app name, the owning team, the cloud, how critical the app is (`tier`), how sensitive its data is (`data_class`) and who can reach it (`network`).
2. Choose the app type (`archetype`) with `reference/decision-guide.md`.
3. Write the file: `gold init --archetype <type> --cloud <aws|azure|gcp> --name <app> --owner <team>`. It starts from a valid example for that type.
4. Edit the contract for the app. `reference/contract.md` explains every field, and `examples/` has one valid contract per app type.
5. After every edit run `gold validate --strict`, then `gold explain`. Show both results to the person before suggesting a merge request.
6. Fix problems by changing the contract, not by working around the tool.

## Commands

- `gold init`: write a contract from an example for an app type.
- `gold validate [--strict] [--format json] [path]`: check structure and cross-field rules. `--strict` turns warnings into failures.
- `gold explain [--format json] [path]`: show the cloud services, environments, approvals and guardrails the contract produces.
- `gold catalog list|show <type>|modules|schema`: look up app types, building blocks and the JSON Schema.
- `gold doctor`: check the tool, the platform data, the contract in the current folder and this skill.

## Where to look

- `reference/decision-guide.md`: which app type fits.
- `reference/contract.md`: every field, what it does and which values it accepts.
- `reference/custom-paths.md`: the exception route when no app type fits.
- `examples/`: one valid contract per app type.
