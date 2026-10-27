# The contract, field by field

`golden-path.yaml` says what an app needs and never how a cloud provides it. Unknown fields are rejected. `gold validate` is the authority; this page explains the intent.

## Top level

| Field | Value |
| --- | --- |
| `apiVersion` | `platform.example.com/v1` |
| `kind` | `GoldenPath` |
| `metadata.name` | App name: lowercase letters, digits and hyphens, 3 to 40 characters |
| `metadata.owner` | Owning team, same format |

## `spec`

| Field | Values | What it does |
| --- | --- | --- |
| `archetype` | `single-api`, `microservices`, `event-driven`, `microservices-events`, `three-tier`, `vm-workload`, `custom` | Picks the path the app runs on |
| `cloud` | `aws`, `azure`, `gcp` | Picks the cloud |
| `tier` | `bronze`, `silver`, `gold` | How critical the app is: sets zones, backups and the reliability target |
| `size` | `S`, `M`, `L`, `XL` | A CPU and memory range; the platform picks the cheapest machine that fits |
| `cost_profile` | `spot-first`, `balanced`, `reserved` | How compute is paid for. `spot-first` is not allowed when the app runs in prod |
| `arch` | `arm64`, `amd64` | CPU architecture. Prefer `arm64` when the app supports it |
| `data_class` | `public`, `internal`, `confidential`, `regulated` | How sensitive the data is. `regulated` needs a private network and cannot be public |
| `network` | `public`, `private`, `internal-only` | Who can reach the app. `internal-only` means no public IPs and no public load balancer |
| `integrations` | `object-storage`, `event-bus`, `secrets` | Extra services added with matching security settings |
| `environments` | `dev`, `stage`, `uat`, `prod` | The environments the app runs in |
| `lifecycle` | `persistent`, `ephemeral` | Permanent, or a temporary environment that deletes itself |
| `ttl` | for example `72h` | How long an ephemeral environment lives. Required when `lifecycle` is `ephemeral`, rejected otherwise |
| `destroy_policy` | `on-demand`, `ttl`, `both` | How an ephemeral environment is deleted. Ephemeral only. An ephemeral contract cannot include `prod` |
| `databases` | list | Managed databases, see below |
| `services` | list of names | The services of a `microservices-events` app. Only for that type |
| `events` | `broker`, `schemas` | The broker type (`stream` or `queue`) and the event schema file. Only for `microservices-events` |
| `web` | list | Front ends, see below |
| `custom` | object | The exception path. Required for `custom` and rejected for every other type |

## `databases`

Each entry has `name`, `model` (`relational`, `document`, `key-value`, `wide-column` or `cache`), `engine`, `size` and optionally `storage_gb`. The engine must suit the model: `postgres`, `mysql` or `sqlserver` for relational, `mongodb` for document, and `default` for the rest. When unsure, use a relational database with `postgres`.

## `web`

Each entry has `name`, `path` (the folder in the repository), `render` (`static` or `server`), and optionally `domain` and `waf` (`managed-rules`).

## Reading the results

- `gold validate` prints each problem with its line number. Errors fail; warnings fail only with `--strict`.
- `gold explain` shows the cloud service behind each building block, what each environment runs on, who approves changes to it, and the guardrails that apply.
