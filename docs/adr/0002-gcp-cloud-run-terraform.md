# ADR-0002: Host on Google Cloud with Cloud Run, Cloud SQL and Terraform

Status: Accepted (planning)

## Context
Owner requires GCP only, defined via Terraform. Need low ops for a solo founder, private DB, a static egress IP customers can allowlist, and no long-lived deploy keys.

## Decision
Cloud Run for api/worker/scheduler jobs; Cloud SQL PostgreSQL (private IP); Memorystore Redis; Pub/Sub + Cloud Tasks; Cloud Storage (CMEK, retention lock) for recordings; Secret Manager and Cloud KMS; Direct VPC egress + Cloud NAT with a reserved static IP; global HTTPS LB with Cloud Armor; Workload Identity Federation for GitHub Actions. Terraform modules per concern, `envs/dev` and `envs/prod`, GCS remote state.

## Consequences
+ Minimal ops; scale-to-zero in dev; managed HA and PITR.
+ Static NAT IP lets customers whitelist direct-mode connections.
− Cloud Run cannot terminate raw TCP SSH; handled by ADR-0003.
− Cloud Run request timeout (max 60 min) caps one WebSocket connection; the client reconnects with the same session ticket (sessions resume within the grant).
− Vendor lock-in accepted; the Terraform modules and container images keep exit cost moderate.
