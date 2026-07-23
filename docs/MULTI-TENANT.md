# Multi-Tenant DHRUVA Guide

**Version:** v4.3.0
**Last Updated:** 2026-06-12

> **Datastore note:** DHRUVA is Postgres-only since v4.9.0. Troubleshooting
> snippets below assume `DATABASE_URL` is exported and use the `psql` client.

---

## Overview

DHRUVA now supports true multi-tenancy, allowing Managed Security Service Providers (MSSPs) to monitor multiple client organizations from a single platform instance with complete data isolation and per-tenant configurations.

## Key Features

### 🏢 **Complete Tenant Isolation**
- **Data Separation**: All client data completely isolated at database level
- **User Management**: Per-tenant analysts with role-based access control
- **Configuration Encryption**: Client credentials encrypted with Fernet encryption
- **Audit Logging**: Per-tenant audit trails and compliance tracking

### 🤖 **Per-Tenant LLM Providers**
- **Provider Choice**: Each client can use different AI providers (Claude, OpenAI, Groq, Ollama)
- **Failover Chains**: Primary → Fallback provider automatic switching
- **Cost Tracking**: Detailed usage analytics and billing per tenant
- **Budget Controls**: Monthly spending limits with automated alerts

### 📡 **Real-Time Alert Ingestion**
- **Webhook Mode**: Sub-second alert processing via Wazuh integrator
- **Tenant Routing**: Automatic client identification from webhook payloads
- **Signature Validation**: HMAC-SHA256 security with per-tenant secrets
- **Rate Limiting**: Configurable per-tenant request limits

---

## Quick Start

### 1. Run the Interactive Deployment Wizard

```bash
./deploy.sh
# Choose option 1: Interactive Wizard
# Select "multi" when asked about deployment mode
```

The wizard will guide you through:
- Multi-tenant configuration
- First client setup
- LLM provider selection
- Webhook security configuration

### 2. Access the Admin Interface

```bash
# Platform will be available at:
http://your-server:8443

# Login with master admin account:
Username: admin (or custom)
Password: [set during wizard]
Role: mssp_admin
```

### 3. Add More Clients

1. **Go to Admin Tab** → Manage Tenants
2. **Click "Add Tenant"**
3. **Configure client settings:**
   - Organization name and contact info
   - Wazuh/OpenSearch credentials
   - LLM provider preferences
   - Webhook configuration
   - Notification settings

---

## Configuration Examples

### Basic Multi-Tenant Setup

```yaml
# Example tenant configuration
tenants:
  healthcare_corp:
    name: "Healthcare Corp"
    slug: "healthcare-corp"
    config:
      # Wazuh connection for this client
      wazuh:
        api:
          host: "https://healthcare-wazuh.company.com"
          username: "${HEALTHCARE_WAZUH_USER}"
          password: "${HEALTHCARE_WAZUH_PASS}"

      # OpenSearch connection
      opensearch:
        hosts: ["https://healthcare-wazuh.company.com:9200"]
        username: "${HEALTHCARE_OS_USER}"
        password: "${HEALTHCARE_OS_PASS}"

      # LLM configuration
      llm:
        primary_provider: "anthropic"
        fallback_providers: ["openai"]
        usage_tracking:
          enabled: true
          monthly_budget: 1000.00
        providers:
          anthropic:
            api_key: "${HEALTHCARE_CLAUDE_KEY}"
            model: "claude-sonnet-4"
            rate_limits:
              requests_per_minute: 60
          openai:
            api_key: "${HEALTHCARE_OPENAI_KEY}"
            model: "gpt-4o"

      # Webhook configuration
      webhook_config:
        enabled: true
        hmac_secret: "${HEALTHCARE_WEBHOOK_SECRET}"
        rate_limits:
          requests_per_minute: 500
        ip_allowlist:
          - "10.0.0.0/8"
          - "192.168.1.0/24"

      # Notifications
      notifications:
        slack:
          webhook_url: "${HEALTHCARE_SLACK_WEBHOOK}"
          channel: "#security-alerts"
        email:
          recipients:
            - "security@healthcare-corp.com"
            - "it-manager@healthcare-corp.com"
```

### Advanced LLM Provider Configuration

```yaml
# Client with multiple providers and cost optimization
startup_client:
  llm:
    primary_provider: "groq"        # Fast and cost-effective
    fallback_providers: ["openai", "anthropic"]
    usage_tracking:
      enabled: true
      monthly_budget: 200.00
      cost_optimization: true
    providers:
      groq:
        api_key: "${STARTUP_GROQ_KEY}"
        model: "llama-3.1-70b-versatile"
        rate_limits:
          requests_per_minute: 100
      openai:
        api_key: "${STARTUP_OPENAI_KEY}"
        model: "gpt-4o-mini"         # Cheaper model for fallback
      anthropic:
        api_key: "${STARTUP_CLAUDE_KEY}"
        model: "claude-haiku-4"      # Fast and economical
```

---

## Webhook Integration

### Wazuh Configuration

For each client's Wazuh Manager, add to `/var/ossec/etc/ossec.conf`:

```xml
<!-- Healthcare Corp Example -->
<integration>
  <name>custom-webhook</name>
  <hook_url>https://your-dhruva-platform.com/api/v1/webhooks/wazuh/alerts/healthcare-corp</hook_url>
  <level>7</level>
  <api_key>healthcare_webhook_secret_from_env</api_key>
  <alert_format>json</alert_format>
  <max_log>100</max_log>
</integration>
```

### Webhook Endpoints

| Endpoint | Purpose |
|----------|---------|
| `/api/v1/webhooks/wazuh/alerts` | Generic webhook (tenant ID from headers) |
| `/api/v1/webhooks/wazuh/alerts/{tenant_slug}` | Tenant-specific webhook |
| `/api/v1/webhooks/wazuh/status/{tenant_id}` | Processing statistics |

### Security Features

- **HMAC Signature Validation**: Prevents unauthorized webhook calls
- **Rate Limiting**: Per-tenant request limits (configurable)
- **IP Allowlisting**: Restrict webhook sources by IP/CIDR
- **Payload Validation**: Schema validation and size limits
- **Audit Logging**: Complete webhook processing audit trail

---

## User Management

### Master Admin (mssp_admin)
- **Full Access**: All tenants, all features
- **Tenant Management**: Create, configure, delete tenants
- **User Management**: Create analysts for any tenant
- **System Administration**: Platform configuration, licenses

### Tenant Users
- **Tenant-Scoped**: Can only access their assigned tenant's data
- **Role-Based**: admin, senior_analyst, analyst, read_only
- **Feature Access**: Based on license tier and role permissions

### Creating Tenant Users

1. **Login as Master Admin**
2. **Go to Admin Tab** → Manage Users
3. **Click "Add User"**
4. **Set tenant assignment and role:**

```bash
Username: analyst1
Email: analyst1@client-corp.com
Role: analyst
Tenant: client-corp
Password: [secure password]
```

---

## Cost Management

### Usage Analytics

Access detailed cost tracking at:
- `/api/v1/llm-usage/tenant/{tenant_id}/report`
- `/api/v1/llm-usage/tenant/{tenant_id}/budget-alerts`
- `/api/v1/llm-usage/tenant/{tenant_id}/optimization`

### Budget Monitoring

The platform automatically tracks:
- **Token Consumption**: Input/output tokens per provider
- **Cost Calculation**: Real-time cost tracking in USD
- **Monthly Budgets**: Configurable spending limits
- **Alert Thresholds**: 75%, 90%, 100% budget notifications

### Optimization Suggestions

The system provides recommendations for:
- **Provider Selection**: Switch to more cost-effective providers
- **Model Optimization**: Use cheaper models for simple tasks
- **Usage Patterns**: Identify high-cost, low-value usage

---

## Migration from Single-Tenant

### Automatic Migration

The deployment wizard includes a migration option:

```bash
./deploy.sh
# Choose option 1: Interactive Wizard
# Select "migration" when asked about deployment mode
```

This will:
1. **Preserve existing data** in new default tenant
2. **Migrate user accounts** with proper tenant assignment
3. **Convert configurations** to encrypted multi-tenant format
4. **Maintain backward compatibility** during transition

### Manual Migration Steps

If you need to migrate manually:

1. **Backup your data:**
   ```bash
   cp -r /var/lib/ai-soc /var/lib/ai-soc.backup
   cp config/config.yaml config/config.yaml.backup
   cp .env .env.backup
   ```

2. **Run the migration wizard:**
   ```bash
   python src/setup/deployment_wizard.py --config config/config.yaml
   ```

3. **Verify the migration:**
   - Check that existing data appears under default tenant
   - Test login with existing credentials
   - Verify alert processing continues normally

---

## Row-Level Security (RLS) — the DB-layer tenant backstop (WO-H12)

Tenant isolation is enforced in **three** layers, defense-in-depth:

1. **App DAO discipline** — every query appends `_tenant_filter()` (`AND
   client_id = %s`); fail-closed when no tenant context is set.
2. **WO-H8 app query guard** (`_GuardedConnection`) — intercepts every
   `conn.execute()` and *raises* (fail-loud) if a SELECT/UPDATE/DELETE touches a
   tenant table with no tenant predicate. It is a regex heuristic, so it cannot
   catch a query filtered only on a *shared* id (`rule_id`, `technique_id`, …).
3. **WO-H12 Postgres RLS** (migration `0006`) — the database engine itself
   returns only the session tenant's rows, even for a raw
   `SELECT * FROM incidents` with no filter. This closes the class layer 2
   cannot.

**How it works.** Migration `0006` enables `ROW LEVEL SECURITY` + `FORCE` on
every table in `SOCDatabase.TENANT_SCOPED_TABLES` and installs a
`tenant_isolation` policy:

```sql
USING      (client_id = current_setting('app.tenant_id', true)
            OR current_setting('app.tenant_id', true) = '__CROSS_TENANT__')
WITH CHECK (client_id = current_setting('app.tenant_id', true)
            OR current_setting('app.tenant_id', true) = '__CROSS_TENANT__')
```

On every pooled-connection checkout, `store.py` runs
`SELECT set_config('app.tenant_id', <value>, false)` — the tenant id, or
`__CROSS_TENANT__` for an audited bypass (`db.cross_tenant()`), or `''` when no
tenant context is set (→ RLS matches nothing → fail-closed). Re-applying on
every checkout is what stops a pooled connection leaking one tenant's GUC to the
next request.

**FK-scoped child tables (migration `0008`, WO-H29).** `incident_alerts` and
`incident_timeline` (`SOCDatabase.FK_SCOPED_TABLES`) carry no direct `client_id`
— they belong to a tenant transitively through their `incident_id` FK. `0006`
deliberately skipped them; `0008` closes that gap with a **subquery** policy
scoped by membership in the RLS-scoped parent:

```sql
USING      (incident_id IN (SELECT id FROM incidents))
WITH CHECK (incident_id IN (SELECT id FROM incidents))
```

The inner `SELECT id FROM incidents` is itself governed by the `0006` policy, so
it composes automatically with the same `app.tenant_id` GUC / `__CROSS_TENANT__`
sentinel (tenant id → only that tenant's child rows; sentinel → all; unset → none
→ fail-closed). Same NON-superuser / NON-BYPASSRLS role requirement applies — no
new role requirement is introduced.

### ⚠️ CRITICAL: DHRUVA must connect as a NON-superuser, NON-BYPASSRLS role

**PostgreSQL superusers and roles with `BYPASSRLS` skip RLS entirely — even with
`FORCE`.** If DHRUVA connects as such a role, migration `0006` applies cleanly
but has **zero runtime effect** and layer 3 is silently absent.

> **Enforced at boot (WO-H12-followup): this is no longer just documented.** In
> **multi-tenant mode** DHRUVA runs a startup RLS-active assertion
> (`SOCDatabase.verify_rls_active()`): it checks the live role is not
> `rolsuper`/`rolbypassrls` and that `FORCE` RLS is enabled on the scoped tables,
> and **refuses to start** (fail-loud `SystemExit`, like the default-creds/weak-JWT
> gates) if RLS cannot take effect — with the exact fix in the message. So the
> `bundled-db` superuser path can no longer *silently* ship with the backstop off;
> it fails loud until you provision the non-superuser role below. (Single-tenant
> mode skips the gate — RLS is not the isolation boundary there.)

| Deployment path | Connects as | RLS effective? |
|---|---|---|
| `deploy.sh` (interactive install) | `CREATE USER dhruva` → NOSUPERUSER/NOBYPASSRLS, owns the DB | ✅ Yes (FORCE covers the owner) |
| `docker compose --profile bundled-db` | `POSTGRES_USER=dhruva` — created by the postgres entrypoint as a **SUPERUSER** | ❌ **No — bypassed** |
| External/managed Postgres | whatever `DATABASE_URL` names | Depends — must be non-superuser |

**Verify at runtime** (both must be `f`):

```bash
psql "$DATABASE_URL" -c \
  "SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user;"
```

If your role is a superuser (bundled-db or a managed instance that only gives
you a superuser), provision a dedicated non-superuser app role and point
`DATABASE_URL` at it:

```sql
-- Run once as a superuser, against the DHRUVA database.
CREATE ROLE dhruva_app LOGIN PASSWORD '<strong-password>'
    NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;

GRANT CONNECT ON DATABASE dhruva TO dhruva_app;
GRANT USAGE ON SCHEMA public TO dhruva_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES    IN SCHEMA public TO dhruva_app;
GRANT USAGE, SELECT                  ON ALL SEQUENCES IN SCHEMA public TO dhruva_app;
-- So future Alembic-created tables are reachable too:
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO dhruva_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO dhruva_app;
```

Then set `DATABASE_URL=postgresql://dhruva_app:<password>@host:5432/dhruva`.
Run **migrations** (`alembic upgrade head`) as the table **owner/superuser**, but
run the **application** as `dhruva_app`.

> Do not "fix" a superuser deployment by weakening the policy — RLS cannot be
> made to apply to a superuser. The only correct answer is a non-superuser role.

### Rehearsing the migration on a copy (operator pre-flight)

RLS changes DB access semantics, so rehearse on a throwaway clone before
production:

```bash
# 1. Snapshot production schema+data into a scratch database.
createdb dhruva_rehearsal
pg_dump "$DATABASE_URL" | psql "postgresql://.../dhruva_rehearsal"

# 2. Apply the migration against the clone.
DATABASE_URL="postgresql://.../dhruva_rehearsal" alembic upgrade 0006

# 3. Prove RLS with a NON-superuser role (as above), NOT a superuser:
psql "postgresql://dhruva_app:...@host/dhruva_rehearsal" <<'SQL'
  SELECT set_config('app.tenant_id', 'SOME_REAL_TENANT_ID', false);
  SELECT count(*), count(DISTINCT client_id) FROM incidents;  -- 1 distinct tenant
  SELECT set_config('app.tenant_id', '', false);
  SELECT count(*) FROM incidents;                             -- 0 rows (fail-closed)
  SELECT set_config('app.tenant_id', '__CROSS_TENANT__', false);
  SELECT count(DISTINCT client_id) FROM incidents;            -- all tenants
SQL

# 4. Confirm reversibility, then drop the clone.
DATABASE_URL="postgresql://.../dhruva_rehearsal" alembic downgrade 0005
dropdb dhruva_rehearsal
```

To render the exact SQL without touching a database:
`alembic upgrade 0005:0006 --sql` (and `alembic downgrade 0006:0005 --sql`).

---

## Troubleshooting

### Common Issues

**1. Webhook Not Receiving Alerts**
```bash
# Check webhook status
curl https://your-platform.com/api/v1/webhooks/wazuh/status/tenant_id

# Verify Wazuh integrator configuration
# Check /var/ossec/logs/integrations.log on Wazuh Manager
```

**2. LLM Provider Failover Not Working**
```bash
# Check provider status in logs
sudo journalctl -u ai-soc -f | grep llm_provider

# Test provider configuration
python -c "
from src.database.tenant_registry import TenantServiceRegistry
from src.database.store import SOCDatabase
# SOCDatabase resolves its DSN from the DATABASE_URL env var (Postgres-only since v4.9.0)
registry = TenantServiceRegistry(SOCDatabase())
backend = registry.get_llm_backend('tenant_id')
print(backend.get_info())
"
```

**3. Tenant Data Isolation Issues**
```bash
# Verify tenant scoping in database
psql "$DATABASE_URL" -c "
SELECT COUNT(*), client_id FROM agent_decisions GROUP BY client_id;
SELECT COUNT(*), client_id FROM incidents GROUP BY client_id;
"
```

**4. Cost Tracking Not Working**
```bash
# Check llm_usage_metrics table
psql "$DATABASE_URL" -c "
SELECT tenant_id, provider, COUNT(*), SUM(cost_usd)
FROM llm_usage_metrics
GROUP BY tenant_id, provider;
"
```

### Support

For additional help:
- **Documentation**: docs/SETUP-GUIDE.md
- **API Reference**: http://your-platform:8443/docs
- **GitHub Issues**: https://github.com/prathameshsecuresleuths/dhruva/issues
- **Email Support**: info@securesleuths.com

---

## Best Practices

### Security
- **Use strong HMAC secrets** for webhook validation
- **Rotate API keys regularly** through the admin interface
- **Enable IP allowlisting** for webhook sources
- **Review audit logs** regularly for suspicious activity

### Performance
- **Use webhook mode** instead of API polling when possible
- **Configure appropriate provider failover** chains
- **Monitor usage patterns** and optimize provider selection
- **Set realistic rate limits** to prevent abuse

### Cost Management
- **Set monthly budgets** for each tenant
- **Review usage reports** monthly
- **Use cheaper models** for routine analysis
- **Enable cost optimization** suggestions

### Operational
- **Test webhook integration** thoroughly before production
- **Monitor provider health** and circuit breaker status
- **Plan for provider outages** with proper failover chains
- **Keep tenant configurations** backed up securely

---

This completes the multi-tenant setup guide. The platform now provides enterprise-grade multi-tenancy with complete data isolation, flexible LLM provider configurations, and real-time webhook alert processing for maximum performance and scalability.