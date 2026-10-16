# Assurance graph schema

Canonical DDL: `src/halvard/graph/schema.sql` (loaded and exercised by `tests/test_graph.py`).

## Shape

```
tenant ─┬─ site
        ├─ entity (person | identity | device | workload | application | data_store | mailbox | site | supplier | ai_agent)
        │     ├─ edge  (owns, uses, member_of, can_access, runs_on, stores, sends_to, acts_for, supplied_by, located_at, delegates_to)
        │     ├─ control   (state + last_fired evidence, tagged with one of the five outcomes)
        │     ├─ sensor    (heartbeat + promised interval → coverage)
        │     └─ finding ──► case ──► action_record ──► ledger
```

## Decisions that matter

1. **Tenant on every row, in every key.** Foreign keys are `(tenant_id, id)`, so the database itself refuses an
   edge between tenants. Application code also scopes every query (see `halvard.tenancy`), and a test tries to cross.
2. **Customer-set beats Halvard-suggested.** `criticality`/`sensitivity` are the customer's. `suggested_*` plus
   `suggestion_evidence` are stored beside them. Suggestions never overwrite; an admin accepts them explicitly.
3. **Coverage is data, not a chart.** `entity.should_be_protected` + `sensor.last_heartbeat` +
   `sensor.promised_interval_s` produce a `coverage_gap` finding when a protected entity is silent
   past its interval. Crown-jewel gaps are incident-level.
4. **Controls record that they fired.** `control.last_fired` and its evidence implement F100 (evidence a
   control worked, not only that a policy exists).
5. **Every control maps to one of five outcomes** (`control.outcome` 1–5): shrink, stop, limit, restore, prove.
   A control that cannot be given an outcome does not ship.
6. **Findings hold evidence ids, not content.** Raw document contents never enter the graph.
7. **Action records mirror Ledger.** `ledger_seq` ties each action to its hash-chained audit entry.
8. **Hierarchy.** `tenant.parent_tenant` models holding companies and service providers; a parent sees a child's
   data only through an explicit delegated grant (never by query inheritance).

## Asset class

`asset_class` (standard | production | clinical | privileged) is what the authority matrix reads to decide the
approval level for destructive actions on that entity.

## Postgres mapping (private/cloud builds)

Same tables. Add row-level security `USING (tenant_id = current_setting('halvard.tenant'))` on each, a per-tenant
data key reference on `tenant`, and partition `finding`/telemetry by `(tenant_id, month)`. Object storage keys are
prefixed `t/<tenant_id>/` and signed URLs are minted only after the same tenant check.
