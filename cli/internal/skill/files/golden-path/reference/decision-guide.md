# Choosing an app type

Pick the first type that fits. If you are unsure between two, ask the person which one matches how the app is built today.

| App type (`archetype`) | Choose it when | Runs on |
| --- | --- | --- |
| `single-api` | One service answers HTTP requests. This is the default for a new API. | Serverless containers |
| `microservices` | Several services call each other and need traffic control between them. | Managed Kubernetes with a service mesh |
| `event-driven` | Work arrives as events or queue messages and consumers scale with the backlog. | Managed Kubernetes with event-based scaling |
| `microservices-events` | Services call each other directly and also publish events for anything that can wait. | Managed Kubernetes with both, plus a managed broker |
| `three-tier` | A classic web application: a browser front end, an API and a relational database. | A CDN, serverless containers and managed PostgreSQL |
| `vm-workload` | The app needs virtual machines, for example for licensing, a legacy runtime or GPUs. | Autoscaling virtual machines |
| `custom` | No type above fits and the platform team approved an exception. | Catalog modules the team composes |

## Questions that settle it

- How many deployable services are there? One points to `single-api` or `three-tier`; several point to `microservices`.
- Does anything react to events or queues? If yes with several services, use `microservices-events`; with one consumer service, `event-driven`.
- Is there a browser front end that needs a CDN and a database behind an API? Use `three-tier`.
- Must it run on virtual machines? Use `vm-workload`.
- Is the answer still "none of these"? Read `custom-paths.md`; do not invent fields.

Run `gold catalog show <type>` to see the exact building blocks for a type on each cloud.
