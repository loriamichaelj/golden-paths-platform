# When no app type fits

The `custom` type is an approved exception, not a way around the guardrails. Do not use it because it is quicker. Use it only when the person says the platform team approved an exception, and have them provide the details below.

## What the contract needs under `spec.custom`

| Field | Rule |
| --- | --- |
| `justification` | At least 30 characters on what no default path provides |
| `exception_ref` | A link to the approved exception |
| `review_by` | A date within 180 days from today. An expired date fails validation |
| `budget_usd_month` | A monthly cost cap |
| `components` | 1 to 12 catalog modules, each with a `name`, a `module`, and optionally `size`, `public` and `inputs` |
| `connections` | Source, destination (a component name or `internet`) and port. Anything not listed is denied |

## Guardrails `gold validate` enforces

- Only modules from the catalog. Run `gold catalog modules` for the list. Never raw cloud resources.
- Only load balancers, CDNs and object storage can be public, and nothing can be public when the data is `regulated`.
- Traffic from the internet may only reach a component marked `public`.
- Component `inputs` cannot override platform-owned settings: `encryption`, `public_access`, `deletion_protection`, `logging`, `backups` and `tls_version`.

If validation fails on one of these, change the contract. Do not rename an input or reshape a module to get around the rule.
