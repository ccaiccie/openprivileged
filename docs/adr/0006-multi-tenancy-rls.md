# ADR-0006: Shared database with Postgres row-level security and per-tenant keys

Status: Accepted (planning)

## Context
MSPs hold many end-customer tenants with a technician-to-tenant matrix. A leak between MSP orgs or between customers of one MSP would be a company-ending event. A database per tenant is costly for a solo operator.

## Decision
One Postgres database, shared schema. Every tenant-owned table has `org_id` and `tenant_id`, protected by RLS policies keyed to session variables set in a per-request transaction; app roles have `NOBYPASSRLS`. Secrets use a per-tenant data key wrapped by KMS. Recordings use per-tenant prefixes. Automated cross-tenant tests are a CI gate. Enterprise tier can receive a dedicated database/project from the same Terraform modules.

## Consequences
+ Cheap, simple operations, one migration path.
− A bug in session-variable handling could bypass isolation; mitigated by tests, a default-deny policy, and a middleware that fails closed.
− Noisy-neighbour risk; mitigated by rate limits and per-tenant quotas.
