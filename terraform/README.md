# OpenPrivileged — Terraform (Google Cloud)

Infrastructure for OpenPrivileged on Google Cloud: Cloud Run (api, broker, worker, scheduler job), Cloud SQL PostgreSQL (private IP), Memorystore Redis, Pub/Sub + Cloud Tasks, Cloud Storage, Artifact Registry, Secret Manager + Cloud KMS, a VPC with Direct VPC egress and Cloud NAT on a static IP, a global HTTPS load balancer with Cloud Armor and a managed certificate, an optional SSH gateway on Compute Engine, Cloud Monitoring/Logging, and GitHub Actions deployment through Workload Identity Federation.

> **Status:** written and reviewed by hand during planning. **No `terraform` command (init, plan, validate, fmt, apply) has been run, and no GCP project has been touched.** Expect to fix small provider-version details on first `plan`.

## Layout

```
terraform/
  modules/
    network/        VPC, subnet, private services access, Cloud Router + NAT + static egress IP, firewall
    security/       per-component service accounts, KMS key ring and keys, Secret Manager containers
    registry/       Artifact Registry (Docker)
    storage/        recordings (CMEK, retention), audit exports, log bucket
    messaging/      Pub/Sub topics + subscription, Cloud Tasks queue
    database/       Cloud SQL PostgreSQL 16 + Memorystore Redis + their secrets
    compute/        Cloud Run services/job, Cloud Scheduler, Cloud Armor, HTTPS LB, managed certificate
    ssh_gateway/    optional GCE MIG + global TCP proxy LB for native SSH (port 22)
    observability/  uptime check, alert policies, log-based metric, log sink
    cicd/           Workload Identity Federation pool/provider + deployer service account
  envs/dev/   main.tf variables.tf outputs.tf versions.tf backend.tf terraform.tfvars.example
  envs/prod/  (same files; HA, deletion protection, longer retention, tag-only deploys)
```

## Where each component runs (and why)

| Component | Runs on | Why |
|---|---|---|
| api + web, worker, scheduler job | Cloud Run | Python, stateless, scale to zero or min 1 |
| broker (browser terminal WebSocket) | Cloud Run (60-minute request timeout, CPU always allocated, concurrency 20) | HTTP/WebSocket only |
| broker (native `ssh` on port 22) | Compute Engine MIG behind a global TCP proxy LB (`ssh_gateway`, off by default) | Cloud Run cannot terminate raw TCP/SSH; PROXY protocol keeps client IPs |
| Non-Python upstreams (Netshot, future RDP proxy) | Not in MVP. Later: Cloud Run job/service for Netshot (HTTP + JVM); **GKE Autopilot or a GCE VM** only for an RDP/guacd-style proxy that needs long-lived sockets | See ADR-0003 and LICENSES.md |

## Prerequisites

- A Google Cloud organization or billing account, one **project per environment** (e.g. `vaultgate-dev-…`, `vaultgate-prod-…`) with billing linked.
- Owner (or equivalent) rights for the person running the first apply.
- Terraform >= 1.6 and the `gcloud` CLI authenticated (`gcloud auth application-default login`).
- A DNS zone you control for the public hostname (the managed certificate provisions only after the A record points at the load balancer).
- A GitHub repository `OWNER/REPO` for CI/CD.

## APIs to enable

`env/*/main.tf` enables these through `google_project_service`, but the very first apply needs `serviceusage` and `cloudresourcemanager` reachable. Enable them once by hand if needed:

```
gcloud services enable serviceusage.googleapis.com cloudresourcemanager.googleapis.com --project PROJECT_ID
```
Enabled by Terraform: artifactregistry, cloudkms, cloudscheduler, cloudtasks, compute, iam, iamcredentials, logging, monitoring, pubsub, redis, run, secretmanager, servicenetworking, sqladmin, storage, sts.

## Bootstrap the state bucket (once per environment)

```
gcloud storage buckets create gs://YOUR-STATE-BUCKET-dev --project PROJECT_ID \
  --location europe-west1 --uniform-bucket-level-access --public-access-prevention
gcloud storage buckets update gs://YOUR-STATE-BUCKET-dev --versioning
```
Then put the bucket name in `envs/<env>/backend.tf` (or pass `-backend-config="bucket=…"`). Restrict bucket access to the owner and the CI identity.

## Steps per environment (what the owner would run)

```
cd terraform/envs/dev        # then repeat for prod
cp terraform.tfvars.example terraform.tfvars   # edit values
terraform init
terraform plan -out tfplan
terraform apply tfplan
```
After apply:
1. Create a DNS A record `domain -> lb_ip` output; wait for the managed certificate to become ACTIVE (can take up to ~60 minutes).
2. Add real secret values as new versions (never through Terraform): `printf '%s' "$VALUE" | gcloud secrets versions add vg-dev-oidc-client-secret --data-file=-` for `oidc-client-secret`, `session-signing-key`, `slack-signing-secret`, `netbox-sync-master-token`.
3. Set GitHub Actions variables `GCP_WIF_PROVIDER` and `GCP_DEPLOYER_SA` from the `github_workload_identity_provider` and `github_deployer_service_account` outputs.
4. Let CI push images to the `artifact_registry_url` output, then set `image_tag` (or let CI run `gcloud run deploy`; Terraform ignores image changes after bootstrap) and optionally `enable_ssh_gateway = true`, then `plan`/`apply` again.
5. Give customers the `egress_ip` output for direct-mode allowlisting.
6. Prod only: when the retention period is final, set `lock_retention = true` (**irreversible**).

## Teardown

```
terraform destroy      # dev only; prod has deletion_protection on Cloud SQL / Cloud Run
```
For prod, first set `deletion_protection = false` in the env `main.tf`/modules and apply, and empty retention-locked buckets only after retention expires (locked buckets cannot be deleted early). KMS key rings and keys cannot be deleted; Terraform removal only destroys key versions after a 24-hour scheduled period. Delete the state bucket manually last.

## Security notes

- No service-account keys anywhere; GitHub deploys with Workload Identity Federation constrained to one repository and a ref prefix (`refs/heads/main` in dev, `refs/tags/v` in prod).
- Each Cloud Run service and the SSH VM has its own service account with scoped roles; nothing uses the default compute service account.
- Database password and Redis AUTH are generated by Terraform and stored in Secret Manager (they appear in Terraform state; protect the state bucket). Platform secrets are created empty (placeholder version) and filled out of band.
- Cloud SQL uses private IP only, `ENCRYPTED_ONLY` SSL, backups with PITR (prod). Add CMEK for Cloud SQL as a hardening step.
- Cloud Armor applies SQLi/XSS rules (not to `/ws/*`) and a per-IP rate limit.

## GCP cost estimates (USD/month, estimates not verified quotes)

| Line item | Dev | Prod, 10 customers | Prod, 100 | Prod, 1,000 |
|---|---|---|---|---|
| Cloud Run | 15 | 90 | 250 | 1,500 |
| Cloud SQL | 25 | 230 | 460 | 1,700 |
| Memorystore | 35 | 70 | 105 | 350 |
| SSH gateway VM + proxy LB | 0 | 15 | 50 | 300 |
| HTTPS LB + Cloud Armor | 20 | 45 | 80 | 300 |
| Cloud NAT + static IP | 10 | 20 | 60 | 300 |
| Logging / Monitoring | 10 | 25 | 100 | 900 |
| Cloud Storage | 2 | 5 | 60 | 800 |
| Secret Manager, KMS, Registry, Pub/Sub, Scheduler | 5 | 10 | 40 | 150 |
| Buffer | – | – | – | 600 |
| **Approx. total** | **≈ 120** | **≈ 480** (sum 510, less committed-use) | **≈ 1,150** (sum 1,205) | **≈ 6,900** |

Assumptions and derivations are in HOSTING.md §7.
