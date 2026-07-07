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