-- WO-H87: one SLA breach row per (incident, sla_type), not one per check.
--
-- `save_sla_breach` carries `ON CONFLICT DO NOTHING`, which reads as dedup
-- protection. It is not: the caller mints a fresh `uuid4()` for `id` on every
-- run (src/incidents/sla.py:133,158) and `id` is the primary key, so there is
-- never a conflict to do nothing about. Every SLA check re-recorded every
-- still-open breach as a NEW row.
--
-- Measured on a live tenant, 2026-08-18:
--     3,577,852 rows / 1,052 MB — the largest table in the database
--     8,284 incidents           — ~430 breach rows per incident
--     1,709 copies of a single incident's single breach
--     growing 3,000-4,700 rows/day, and NOT in RETENTION_PRUNABLE
--
-- For scale, `agent_decisions` — every triage decision ever made — is 27,407
-- rows. This table was 130x larger and held nothing the first row did not.
--
-- Collapse to the EARLIEST row per (client_id, incident_id, sla_type): the
-- first detection is when the SLA actually breached, which is the fact worth
-- keeping. `notified` is OR-ed across the duplicates so a breach already
-- announced is not announced again after the collapse.

BEGIN;

-- Run cross-tenant. This is a platform-wide maintenance operation and MUST see
-- every tenant's rows.
--
-- Not optional: the migration role (`dhruva`) has rolbypassrls = false, and
-- these tables carry FORCE ROW LEVEL SECURITY, so alembic runs with NO tenant
-- context and sees ZERO rows. Verified on a live tenant 2026-08-18 —
-- `SELECT count(*) FROM sla_breaches` returns 0 without this line and 3,577,142
-- with it. Without it the migration commits happily and changes nothing, which
-- is the exact silent-success failure this whole work order is about.
--
-- '__CROSS_TENANT__' is the sentinel the policies already accept
-- (0009_ops_hardening.sql:47), the same one `SOCDatabase.cross_tenant()` sets.
SET LOCAL app.tenant_id = '__CROSS_TENANT__';

CREATE TEMP TABLE _sla_keep ON COMMIT DROP AS
SELECT DISTINCT ON (client_id, incident_id, sla_type)
       id,
       (max(notified) OVER (PARTITION BY client_id, incident_id, sla_type)) AS notified_any
FROM sla_breaches
ORDER BY client_id, incident_id, sla_type, breached_at ASC, id ASC;

UPDATE sla_breaches b
   SET notified = k.notified_any
  FROM _sla_keep k
 WHERE b.id = k.id AND b.notified IS DISTINCT FROM k.notified_any;

DELETE FROM sla_breaches
 WHERE id NOT IN (SELECT id FROM _sla_keep);

-- Now the constraint that makes ON CONFLICT DO NOTHING mean something.
CREATE UNIQUE INDEX IF NOT EXISTS uq_sla_breach_incident_type
    ON sla_breaches (client_id, incident_id, sla_type);

COMMIT;
