# ADR-007: Multi-tenancy / org isolation

**Status:** Accepted
**Date:** 2026-08

## Context

PicoSentry is deployed as a shared service that must keep one customer's data
isolated from another's. Two distinct tenancy layers exist in the codebase:

1. **Sandbox job isolation** — `picosentry/sandbox/tenant/` scopes scan jobs
   to a tenant so one tenant cannot read or mutate another's job.
2. **Serve org model** — `picosentry/serve/` models organizations, members,
   tiered usage limits, and org-scoped API queries.

These layers were built independently and use different vocabulary
(`TenantId`/`TenantRegistry` in the sandbox, `Organization`/`org_id` in serve),
so the isolation model needs to be documented as a deliberate decision.

## Decision

**Sandbox layer — tenant-scoped job store.** `TenantId` is a frozen value
object that normalizes to lowercase alphanumeric plus `-`/`_` and rejects
anything else. `DEFAULT_TENANT = TenantId("default")` is the fallback for any
call that does not supply a tenant. `TenantAwareScanJobStore` wraps the
persistent `PersistentScanJobStore` and:

- stamps every job with `tenant_id` (the caller's tenant or the default) on
  `add`;
- enforces isolation on `get`/`update`: if the job's stored tenant differs
  from the requesting tenant, it logs a cross-tenant-access warning and returns
  `None` (deny, not leak);
- filters `list_recent` to the requesting tenant's jobs.

`TenantRegistry` maps API-token hashes to tenants and resolves the effective
tenant from an optional `X-Tenant` header (only if the tenant is registered)
or the token map, falling back to `DEFAULT_TENANT`. Tenants are configured at
startup from `PICODOME_TENANTS` and `PICODOME_TENANT_TOKEN_MAP` env vars.

**Serve layer — organization model.** `Organization` (in
`picosentry/serve/services/orgs.py`) models orgs with a unique `slug`, an
`api_key_hash` (SHA-256 of a `sk_live_*` key, compared with
`hmac.compare_digest`), a tier (`free`/`starter`/`pro`/`enterprise`) with
per-tier usage limits, and membership via `org_users`. The `get_current_org`
dependency (`picosentry/serve/api/deps.py`) resolves the active org for a
request: an `X-Org-API-Key` header (if it starts with `sk_`) selects the org
only when the authenticated user is a member; otherwise it falls back to the
user's first org. `require_org_membership` gates org-scoped routes by
`org_id`. Orchestrator queries (`get_status`, `list_projects`, `run_project`,
`list_intelligence`, `list_alerts`, `get_metrics`) accept an `org_id` and
append `AND org_id = ?` filters, and `Organization.add_project`/`has_project`/
`list_project_ids` scope project visibility to an org.

## Rationale

- **Defense in depth at the data layer:** the sandbox store denies cross-tenant
  reads at the store boundary, not just at the API layer, so a bug in a caller
  cannot leak another tenant's job.
- **Deny-by-default:** an unknown or mismatched tenant resolves to
  `DEFAULT_TENANT` or is rejected, never silently granted another tenant's
  data.
- **Org API keys are membership-checked:** presenting an org key does not grant
  access unless the authenticated user is a member of that org, preventing
  key-only cross-tenant access.
- **Tier limits are enforced at the service layer** via `get_usage`, giving
  operators a per-org quota model without a separate billing service.
- **Two vocabularies reflect two trust domains:** the sandbox tenant is a
  process/job isolation boundary; the serve org is a user-facing billing and
  membership boundary. Keeping them separate avoids conflating job isolation
  with account management.

## Consequences

- Cross-tenant access is denied but only logged as a warning; there is no
  centralized audit of denied cross-tenant attempts beyond the log line.
- `get_current_org` falls back to the user's *first* org when no org key is
  given, which is ambiguous for multi-org users; callers that need a specific
  org must pass `X-Org-API-Key` or use `require_org_membership`.
- The sandbox `TenantRegistry` is in-memory and configured from env at
  startup; tenant changes require a restart.
- Not every serve table is org-scoped (e.g. the audit `org_id` column is
  written as `NULL`); org isolation is applied where the orchestrator and
  routers explicitly pass `org_id`, not universally.
- The two layers are not wired together: a serve org does not map to a sandbox
  `TenantId`, so org-level isolation and sandbox job isolation are enforced
  independently.
