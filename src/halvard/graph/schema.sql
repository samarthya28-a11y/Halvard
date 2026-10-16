-- Halvard assurance graph, v1 (SQLite dialect for the reference build; Postgres mapping in docs/02).
-- Rules enforced here:
--   * every table carries tenant_id; every foreign key is (tenant_id, id) so an edge can never cross tenants.
--   * entities are typed nodes; relationships are typed edges; findings/controls/actions hang off entities.
--   * criticality and sensitivity: customer-set value wins; Halvard's suggestion is stored beside it with evidence.

PRAGMA foreign_keys = ON;

CREATE TABLE tenant (
  tenant_id      TEXT PRIMARY KEY,
  name           TEXT NOT NULL,
  region         TEXT NOT NULL,                 -- residency choice
  deployment     TEXT NOT NULL CHECK (deployment IN ('cloud','customer_cloud','private','disconnected')),
  operated_by    TEXT NOT NULL CHECK (operated_by IN ('customer','keeper')),
  parent_tenant  TEXT REFERENCES tenant(tenant_id)   -- holding company / service provider hierarchy
);

CREATE TABLE site (
  tenant_id TEXT NOT NULL REFERENCES tenant(tenant_id),
  site_id   TEXT NOT NULL,
  name      TEXT NOT NULL,
  zone_policy TEXT NOT NULL DEFAULT 'standard',   -- F078 blast-radius policy per zone
  PRIMARY KEY (tenant_id, site_id)
);

CREATE TABLE entity (
  tenant_id   TEXT NOT NULL REFERENCES tenant(tenant_id),
  entity_id   TEXT NOT NULL,
  kind        TEXT NOT NULL CHECK (kind IN
              ('person','identity','device','workload','application','data_store',
               'mailbox','site','supplier','ai_agent')),
  display_name TEXT NOT NULL,
  site_id     TEXT,
  -- customer-set properties
  criticality TEXT CHECK (criticality IN ('low','normal','high','crown_jewel')),
  sensitivity TEXT CHECK (sensitivity IN ('public','internal','confidential','regulated')),
  asset_class TEXT NOT NULL DEFAULT 'standard'
              CHECK (asset_class IN ('standard','production','clinical','privileged')),
  should_be_protected INTEGER NOT NULL DEFAULT 1,  -- drives coverage incidents
  -- Halvard suggestions, never silently applied
  suggested_criticality TEXT,
  suggested_sensitivity TEXT,
  suggestion_evidence   TEXT,                      -- JSON list of evidence ids
  attrs       TEXT NOT NULL DEFAULT '{}',          -- JSON, kind-specific (os, version, upn, ...)
  first_seen  REAL NOT NULL,
  last_seen   REAL NOT NULL,
  PRIMARY KEY (tenant_id, entity_id),
  FOREIGN KEY (tenant_id, site_id) REFERENCES site(tenant_id, site_id)
);

CREATE TABLE edge (
  tenant_id TEXT NOT NULL,
  src       TEXT NOT NULL,
  rel       TEXT NOT NULL CHECK (rel IN
            ('owns','uses','member_of','can_access','runs_on','stores','sends_to',
             'acts_for','supplied_by','located_at','delegates_to')),
  dst       TEXT NOT NULL,
  attrs     TEXT NOT NULL DEFAULT '{}',            -- e.g. privilege level, standing vs JIT
  observed_at REAL NOT NULL,
  PRIMARY KEY (tenant_id, src, rel, dst),
  FOREIGN KEY (tenant_id, src) REFERENCES entity(tenant_id, entity_id),
  FOREIGN KEY (tenant_id, dst) REFERENCES entity(tenant_id, entity_id)
);

-- A control is a thing that should be true of an entity (agent installed, encryption on, MFA enforced).
CREATE TABLE control (
  tenant_id  TEXT NOT NULL,
  control_id TEXT NOT NULL,                        -- e.g. WARD.OFFLINE_PREVENTION
  entity_id  TEXT NOT NULL,
  module     TEXT NOT NULL,
  outcome    INTEGER NOT NULL CHECK (outcome BETWEEN 1 AND 5),   -- the five outcomes
  state      TEXT NOT NULL CHECK (state IN ('enforced','audit_only','off','failed','unknown')),
  last_fired REAL,                                 -- F100: evidence the control fired, not only that it is set
  last_fired_evidence TEXT,
  PRIMARY KEY (tenant_id, control_id, entity_id),
  FOREIGN KEY (tenant_id, entity_id) REFERENCES entity(tenant_id, entity_id)
);

CREATE TABLE sensor (
  tenant_id TEXT NOT NULL,
  sensor_id TEXT NOT NULL,
  entity_id TEXT NOT NULL,
  kind      TEXT NOT NULL,                         -- ward, connector:<name>, network, browser, mobile, ot_gateway
  version   TEXT,
  ring      TEXT NOT NULL DEFAULT 'broad',
  last_heartbeat REAL,
  promised_interval_s INTEGER NOT NULL DEFAULT 900,
  PRIMARY KEY (tenant_id, sensor_id),
  FOREIGN KEY (tenant_id, entity_id) REFERENCES entity(tenant_id, entity_id)
);

CREATE TABLE finding (                              -- alert / detection / coverage gap / posture issue
  tenant_id  TEXT NOT NULL,
  finding_id TEXT NOT NULL,
  entity_id  TEXT NOT NULL,
  kind       TEXT NOT NULL,                        -- detection, coverage_gap, vulnerability, posture, tripwire
  module     TEXT NOT NULL,
  technique  TEXT,                                 -- ATT&CK tag (F022)
  confidence REAL NOT NULL CHECK (confidence BETWEEN 0 AND 1),
  evidence   TEXT NOT NULL,                        -- JSON list of evidence ids; no raw content
  case_id    TEXT,
  created_at REAL NOT NULL,
  PRIMARY KEY (tenant_id, finding_id),
  FOREIGN KEY (tenant_id, entity_id) REFERENCES entity(tenant_id, entity_id)
);

CREATE TABLE "case" (
  tenant_id  TEXT NOT NULL,
  case_id    TEXT NOT NULL,
  title      TEXT NOT NULL,
  status     TEXT NOT NULL CHECK (status IN ('open','contained','recovering','closed')),
  confidence REAL NOT NULL,
  impact     TEXT NOT NULL,                        -- plain-language business impact
  campaign_id TEXT,                                -- F021 cross-device story
  legal_hold INTEGER NOT NULL DEFAULT 0,
  opened_at  REAL NOT NULL,
  PRIMARY KEY (tenant_id, case_id)
);

CREATE TABLE action_record (                       -- mirrors the Ledger entry; every action fully described
  tenant_id TEXT NOT NULL,
  action_id TEXT NOT NULL,
  action    TEXT NOT NULL,                         -- key into the authority matrix
  actor     TEXT NOT NULL,                         -- principal id or 'halvard:auto:<policy>'
  reason    TEXT NOT NULL,
  scope     TEXT NOT NULL,                         -- JSON: entity ids and limits
  approval  TEXT NOT NULL,                         -- JSON: rule applied, approvers, time
  reversal  TEXT NOT NULL,                         -- JSON: path, or {"reversible": false, "cannot_undo": [...]}
  case_id   TEXT,
  ledger_seq INTEGER NOT NULL,
  PRIMARY KEY (tenant_id, action_id)
);
