# SecureSleuths DHRUVA - Setup Guide

**Version:** v4.9.1

---

## What You Received

Your delivery package contains:

```
dhruva-4.9.0.tar.gz                   <-- The platform package
license.key                           <-- (Team/Enterprise only, emailed separately)
```

The platform sits on top of your existing **Wazuh SIEM** and adds AI-powered alert triage, enrichment, and incident management. Community edition works out of the box — no license file needed.

---

## Before You Start

You need three things ready before setup:

### 1. A Linux Server

- Ubuntu 20.04+, Debian 11+, or similar
- 4 GB RAM minimum (8 GB recommended)
- 10 GB free disk space
- Python 3.11 or newer installed
- Can reach your Wazuh Manager over the network

### 2. Your Wazuh Credentials

You will need:

| What | Where to find it | Example |
|------|-------------------|---------|
| Wazuh Manager IP | Your Wazuh server address | `10.0.0.50` |
| Wazuh API username | Wazuh dashboard > Management > Users | `wazuh-wui` |
| Wazuh API password | Set during Wazuh installation | *(your password)* |
| OpenSearch username | Usually `admin` | `admin` |
| OpenSearch password | Set during Wazuh installation | *(your password)* |

If you don't know these, check with whoever installed your Wazuh Manager.

### 3. AI Backend (pick one)

The platform uses an LLM to analyze alerts. The following providers are supported:

| Provider | Setup | Status |
|----------|-------|--------|
| **Anthropic Claude (API)** | API key from [console.anthropic.com](https://console.anthropic.com) | Recommended — battle-tested |
| **Anthropic Claude (CLI)** | Claude Code CLI + Max subscription | Tested — no API key needed |
| **OpenAI (GPT-4o)** | API key from [platform.openai.com](https://platform.openai.com) | Supported |
| **Groq (Llama 3)** | API key from [console.groq.com](https://console.groq.com) | Supported |
| **Ollama (local)** | Install [Ollama](https://ollama.com) and pull a model | Experimental |

> **Note:** Anthropic Claude is the primary tested backend. OpenAI and Groq are supported
> and expected to work well, but have had less production testing. Ollama with local models
> may produce inconsistent results depending on the model used. If you experience issues
> with any provider, we'd love to hear about it.

---

## Step 1: Extract the Package

Open a terminal on your Linux server and run:

```bash
tar xzf dhruva-4.9.0.tar.gz
cd dhruva-4.9.0
```

## Step 2: License (Optional)

**Community Edition users: skip this step.** The platform runs as Community edition
automatically when no license file is present — free forever, no key required.

Community packaging now defaults to:

```bash
DHRUVA_BUILD_PROFILE=auto
```

This means:

- no `license.key` present: Community feature surface
- valid `license.key` present: paid feature surface after restart

If you purchased a **Team** or **Enterprise** license, copy your `license.key` into
the platform folder:

```bash
cp /path/to/license.key .
```

| Tier | Users | Agents | Alerts | Key Features |
|------|-------|--------|--------|-------------|
| **Community** (free) | 5 | Unlimited | Unlimited | AI triage, enrichment, MITRE heatmap, 7 TI feeds, KB, incidents |
| **Team** ($999/mo) | 25 | Unlimited | Unlimited | + Detection Agent, Query Agent, feedback loop, Slack/email, ticketing, reporting |
| **Enterprise** ($2,999/mo) | Unlimited | Unlimited | Unlimited | + Hunt Agent, active response, SOAR, compliance, multi-tenancy, SSO |

To upgrade, contact SecureSleuths at info@securesleuths.in or visit https://securesleuths.in/pricing.

## Step 3: Choose Your Setup Method

The platform offers two setup methods:

```bash
chmod +x deploy.sh
./deploy.sh
```

### Option 1: Interactive Wizard (Recommended)

🚀 **NEW in v4.8.5** - Enhanced guided wizard with advanced features:

- **Multi-tenant LLM providers** - Different AI providers per client
- **Real-time webhook ingestion** - Faster alert processing than API polling
- **Enhanced security** - HMAC signature validation, encrypted configurations
- **Cost tracking** - Per-tenant usage analytics and budget monitoring
- **Intelligent failover** - Automatic provider fallback chains

The Interactive Wizard will guide you through:

1. **Deployment Mode Selection** - Single-tenant, multi-tenant, or migration
2. **Alert Ingestion Method** - Webhook (real-time), API polling, or hybrid
3. **Multi-Provider LLM Setup** - Configure primary and fallback AI providers
4. **Security Configuration** - Generate secrets, configure authentication
5. **Tenant Management** - Set up initial clients and configurations
6. **Configuration Generation** - Create optimized config files

### Option 2: Classic Setup

📋 Traditional step-by-step configuration for existing deployments:

1. **System checks** and dependency installation
2. **Single/multi-tenant** deployment mode selection
3. **Wazuh connection** configuration
4. **Claude AI setup** (API key or CLI mode)
5. **Dashboard credentials** and data directories
6. **Connection testing** and optional services
7. **Notifications and integrations** setup

### Which Should You Choose?

- **Choose Interactive Wizard** if:
  - You're setting up a new deployment
  - You want multi-tenant LLM providers
  - You need real-time webhook ingestion
  - You manage multiple clients (MSP/MSSP)

- **Choose Classic Setup** if:
  - You're upgrading an existing deployment
  - You prefer the familiar setup flow
  - You only need basic single-tenant features

> **Tip:** You can always re-run the wizard later to enable advanced features

## Step 4: Start the Platform

If you chose to install as a system service during setup:

```bash
sudo systemctl start ai-soc
```

If you chose manual mode:

```bash
source venv/bin/activate
python main.py config/config.yaml
```

## Step 5: Open the Dashboard

Open your web browser and go to:

```
http://<your-server-ip>:8443
```

Log in with:
- **Username:** `admin` (or whatever you chose during setup)
- **Password:** the password you set during setup

You should see the Overview dashboard. If Wazuh is generating alerts, they will start appearing within a minute or two.

---

## What the Dashboard Shows You

Once running, the platform has 14 tabs:

| Tab | What it does |
|-----|-------------|
| **Daily Review** | Simplified view for managers -- plain-language summaries of what happened today, grouped incidents, one-click "handled" actions |
| **Overview** | Summary of today's alerts, verdicts, risk scores, automation rate, your assigned incidents, and weekly trend charts |
| **Triage** | Every alert the AI analyzed, with verdict (true positive, false positive, etc.), full reasoning, and human review buttons |
| **Incidents** | Alerts grouped into incidents by related activity, with severity, status tracking, timeline, notes, and assignment |
| **Detection** | Rule tuning proposals -- the AI suggests ways to reduce false positives in your Wazuh rules. Approve, deploy, or run on demand |
| **Hunt** | Threat hunting hypotheses the AI generates based on gaps in your detection coverage. Confirm or dismiss findings |
| **Closed Loop** | Visual overview of how the feedback loop works -- FP detection rate, automation rate, confidence trends |
| **Metrics** | Operational metrics -- alert volumes, response times, AI confidence trends, analyst workload, and SLA tracking |
| **SOAR** | Security orchestration and automated response -- playbook management, approval workflows, and automation stats |
| **MITRE** | ATT&CK framework coverage map -- see which techniques your detections cover and identify gaps |
| **Investigate** | Ask questions about your environment in plain English (e.g., "show me all SSH failures in the last 24 hours") |
| **Respond** | View your Wazuh agents, run active response actions (block IP, isolate host, etc.), check and fix vulnerabilities |
| **Threat Intel** | IOC feeds the platform collects (10 sources) and uses to enrich alerts. View stats and trigger collection |
| **Admin** | Manage user accounts, view audit logs, check system config (admin only) |

---

## Advanced Features Configuration

### Real-Time Webhook Alert Ingestion

🚀 **NEW in v4.8.5** - For faster alert processing, configure Wazuh to push alerts directly to the platform instead of polling:

#### 1. Configure Wazuh Integrator

Add this to your Wazuh Manager's `/var/ossec/etc/ossec.conf`:

```xml
<integration>
  <name>custom-webhook</name>
  <hook_url>https://your-ai-soc-platform.com/api/v1/webhooks/wazuh/alerts</hook_url>
  <level>7</level>
  <api_key>your_webhook_secret_from_env</api_key>
  <alert_format>json</alert_format>
  <max_log>100</max_log>
</integration>
```

#### 2. Performance Comparison

| Method | Alert Latency | CPU Usage | OpenSearch Load | Scalability |
|--------|---------------|-----------|-----------------|-------------|
| **Webhook** | 1-3 seconds | Event-driven | Minimal | Excellent |
| **API Polling** | 10-30 seconds | Constant | High queries/min | Limited |
| **Hybrid** | 1-3 seconds + fallback | Balanced | Low | Best reliability |

### Multi-Tenant LLM Providers

Configure different AI providers per client through the Admin interface:

#### Per-Client Provider Examples:

```yaml
# Healthcare client - High security, Claude
tenant_healthcare:
  llm:
    primary_provider: "anthropic"
    fallback_providers: ["openai"]
    monthly_budget: 1000
    providers:
      anthropic:
        api_key: "sk-ant-healthcare-key"
        model: "claude-sonnet-4"

# Startup client - Cost-conscious, Groq
tenant_startup:
  llm:
    primary_provider: "groq"
    fallback_providers: ["openai", "anthropic"]
    monthly_budget: 200
    providers:
      groq:
        api_key: "gsk-startup-key"
        model: "llama-3.1-70b-versatile"
```

#### Available LLM Providers:

| Provider | Best For | Cost | Speed | Models Available |
|----------|----------|------|-------|------------------|
| **Anthropic** | Security analysis | $$$ | Medium | Claude Sonnet-4, Haiku-4 |
| **OpenAI** | General purpose | $$$ | Medium | GPT-4o, GPT-4o-mini |
| **Groq** | Cost-effective | $ | Fast | Llama-3.1-70b, Mixtral |
| **Ollama** | Private/Local | Free | Variable | Any local model |

### Cost Tracking and Analytics

Access detailed usage reports at `/api/v1/llm-usage/`:

- **Per-tenant cost breakdown**
- **Provider performance metrics**
- **Monthly budget alerts**
- **Optimization suggestions**

### Reducing LLM Cost (`cost_controls`)

The LLM is only billed in **API mode** (a real `ANTHROPIC_API_KEY`); in
subscription/CLI mode these levers still cut load but the spend is notional.
All of them live under `agents.triage.cost_controls` in `config/config.yaml` and
are **safe by construction** — none can suppress an alert that carries a threat
signal (threat-intel hit / known-malicious / baseline anomaly) or that must
always escalate.

> **IMPORTANT — after an upgrade you must edit the config by hand.**
> `scripts/upgrade.sh` **preserves your existing `config.yaml`**, so a new
> toggle shipped in a release does **not** appear in your file automatically.
> Copy the block from the packaged `config/config.yaml` into your live config,
> set the value, and restart (`python main.py config/config.yaml`).

The four levers, cheapest first:

1. **Budget cap** — `cost_controls.budget`: a hard per-tenant monthly spend cap
   that blocks the LLM and escalates once hit.
2. **Dedup** — `cost_controls.dedup` (`enabled: true` by default): collapses a
   burst of identical alerts (~5-min window) to one LLM call.
3. **Noise pre-filter / CVE skip** — `cost_controls.prefilter`: skips whole
   deterministic categories from the LLM. Shipped with
   `skip_rule_groups: ["vulnerability-detector"]` — CVE alerts (the #1 cost
   driver) are dismissed deterministically and stay fully visible on the
   Vulnerabilities tab.
4. **Persistent decision cache** — `cost_controls.decision_cache`
   (**`enabled: false` by default — opt in**): remembers a benign verdict so a
   recurring alert reuses it for **$0** instead of re-calling the LLM, even days
   later or after a restart. To turn it on, set:

   ```yaml
   agents:
     triage:
       cost_controls:
         decision_cache:
           enabled: true          # <-- turn the cache ON here
           write_through: true    # store qualifying verdicts as they happen
           min_confidence: 0.7    # only cache verdicts at/above this confidence
           max_age_hours: 168     # entries go stale after 7 days (0 = never)
           cacheable_verdicts: ["auto_close", "false_positive", "benign", "needs_investigation"]
   ```

   Then restart the platform. Everything the cache stores is visible and
   editable to an admin / senior analyst under **Decision Cache** in the
   dashboard (System group): each entry shows what it matches, how many LLM
   calls it has saved, and **Disable / Edit / Delete** controls — disabling or
   deleting an entry sends the next matching alert back to the LLM. Watch the
   tab's savings strip (and the Metrics/Reports LLM-usage panel) to confirm the
   effect.

### Multi-Tenant Management

For MSPs managing multiple clients:

1. **Admin Dashboard** - Switch between clients, manage users
2. **Encrypted Configurations** - Client credentials encrypted at rest
3. **Isolated Data** - Complete tenant separation
4. **Billing Reports** - Per-client usage and cost tracking

---

## After Setup: Customize for Your Environment

The platform works out of the box, but it gets smarter when you tell it about your environment. These files can be edited at any time -- the platform picks up changes automatically (no restart needed).

### Tell It About Your Servers

Edit `/var/lib/ai-soc/assets.yaml` to list your important servers:

```yaml
assets:
  - hostname: "prod-db-01"
    tier: "tier_1_critical"
    owner: "database-team"
    environment: "production"
    criticality_multiplier: 3.0
    tags: ["database", "pii"]

  - hostname: "staging-*"
    tier: "tier_3_standard"
    criticality_multiplier: 1.0
```

**Why this matters:** An alert on a critical production database gets a much higher risk score than the same alert on a staging server. Without this file, all servers are treated equally.

**Tier levels:**
- `tier_1_critical` (3x risk) -- production databases, auth servers, payment systems
- `tier_2_important` (2x risk) -- production app servers, CI/CD, monitoring
- `tier_3_standard` (1x risk) -- staging, dev, internal tools
- `tier_4_low` (0.5x risk) -- test, sandbox, lab environments

### Tell It About Your Users

Edit `/var/lib/ai-soc/identities.yaml` to list key users and service accounts:

```yaml
users:
  - username: "svc-deploy"
    risk_level: "high_risk"
    risk_multiplier: 2.5
    is_admin: false
    is_service_account: true
    roles: ["deployment"]

  - username: "john.doe"
    risk_level: "standard"
    risk_multiplier: 1.0
    is_admin: false
    roles: ["developer"]
```

**Why this matters:** Activity from admin or service accounts gets extra scrutiny. An unknown username gets flagged as elevated risk automatically.

### Customize Your Risk Rules

Edit `config/guidance/risk_criteria.yaml` to match your organization's policies. This controls:
- Which MITRE ATT&CK techniques get priority treatment
- Business hours and timezone (alerts outside business hours get higher risk)
- Maintenance windows (alerts during patching get lower risk)

### Customize Escalation Logic

Edit `config/guidance/escalation_logic.yaml` to define:
- What should be auto-closed (known scanner noise, maintenance activity)
- What should always escalate to a human (credential access on critical servers, ransomware indicators)

---

## Multi-Tenancy (Managing Multiple Clients)

If you manage security for multiple organizations from one platform (e.g., as a managed security provider), the setup wizard handles everything for you.

Skip this section if you only monitor one environment.

### During Setup

When you run `./deploy.sh`, Step 3 asks:

```
How will you use this platform?

  1) Single Tenant   (most common)
  2) Multi-Tenant    (managed security / MSSP)
```

Choose **2** for multi-tenant. The wizard then:

1. **Asks for your first client's Wazuh details** -- the same connection questions as single-tenant, but labeled "for your first client"
2. **Asks for their Claude AI setup** -- API key or CLI mode for this client
3. **Creates a master admin account** -- this is your account that can see and manage all clients
4. **Generates an encryption key** -- automatically protects all client credentials in the database (saved to `.env`)
5. **Asks for your first client's name** -- e.g., "Acme Corp" (you can add more clients later)
6. **Asks for their notification setup** -- Slack/email for this client

That's it. Start the platform and log in. Your first client is ready.

### After Setup: Adding More Clients

Once the platform is running, you can add more clients entirely from the dashboard -- no command line needed:

1. **Log in** with your master admin account
2. Go to the **Admin** tab
3. Click **Manage Tenants** > **Add Tenant**
4. Enter the new client's name and their Wazuh/Claude/notification details
5. Click **Save** -- the new client is live immediately

### After Setup: Adding Users for Each Client

Each client can have their own analysts who only see that client's data:

1. Go to the **Admin** tab
2. Click **Manage Users** > **Add User**
3. Choose which client the user belongs to
4. Set their role:
   - **Admin** -- can manage users and settings for their client
   - **Senior Analyst** -- full access to triage, investigate, and respond
   - **Analyst** -- standard access to triage and investigate
   - **Read Only** -- can only see the Daily Review summary

### Switching Between Clients

When logged in as the master admin:

- A **client dropdown** appears in the top-right corner of the dashboard
- Select a client to view their data -- all tabs instantly switch to that client
- The selection is remembered in your browser

Regular users don't see the dropdown -- they are locked to their own client's data.

### What's Kept Separate Per Client

| What | Separate per client? |
|------|---------------------|
| Alerts and triage decisions | Yes -- each client only sees their own |
| Incidents and timelines | Yes |
| Detection tuning proposals | Yes |
| Threat hunting findings | Yes |
| SOAR automated actions | Yes |
| MITRE ATT&CK coverage map | Yes |
| Performance metrics and SLAs | Yes |
| Audit trail (who did what) | Yes |
| Wazuh connection details | Yes -- encrypted separately |
| Claude AI key | Yes -- each client can have their own |
| Slack/email notifications | Yes -- each client can have their own channels |
| Threat intelligence feeds | Shared -- all clients benefit from the same intel |

### Important: Back Up Your .env File

The `.env` file contains the encryption key that protects all client credentials. If this file is lost, client configurations cannot be recovered. Keep a secure backup.

---

## Optional: Add Threat Intelligence API Keys

The platform collects threat intelligence from free public feeds automatically. For better coverage, you can add free API keys:

| Service | How to get a key | What it adds |
|---------|-----------------|-------------|
| [AbuseIPDB](https://www.abuseipdb.com/register) | Sign up, free tier available | IP reputation lookups |
| [AlienVault OTX](https://otx.alienvault.com/api) | Sign up, free | Threat pulse data |
| [VirusTotal](https://www.virustotal.com/gui/join-us) | Sign up, free tier | File hash lookups |

Add the keys to your `.env` file:

```
ABUSEIPDB_API_KEY=your_key_here
OTX_API_KEY=your_key_here
VIRUSTOTAL_API_KEY=your_key_here
```

Then restart the platform:

```bash
sudo systemctl restart ai-soc
```

---

## Recommended: Detection Coverage for File Malware + DNS (what TI can and cannot see)

**DHRUVA's threat intelligence is an *alert-enrichment* layer, not a scanner.**
It matches indicators (IPs, domains, file hashes, emails) found **inside Wazuh
alerts** against its IOC store (~68k indicators across 10 feeds). It does NOT
independently sweep disks for malicious files or watch DNS traffic. The
consequence, verified live: a malware file dropped on an endpoint, or a DNS
query to a known-bad domain, produces **no TI flag if Wazuh never raises an
alert carrying that indicator** — there is nothing to enrich.

TI matching itself works end-to-end today: a bad IP in any alert is matched,
and a **FIM (syscheck) alert that carries file hashes is matched against the
hash IOCs automatically** — the enricher reads `syscheck.md5_after` /
`sha1_after` / `sha256_after` and a known-bad hash sets `is_known_malicious`
(2× risk boost, TI-priority triage). What is usually missing on a fresh Wazuh
install is the **Wazuh-side configuration that makes those alerts exist**.
Three additions close the gap:

### 1. FIM with hash reporting on the paths malware lands in

Wazuh's default FIM watches system directories on a 12-hour schedule. Add the
common drop directories with `check_all` (which includes MD5/SHA1/SHA256
hashes — those are what TI matches on) and `report_changes`. On the **agent**
(or via a centralized agent.conf group):

```xml
<syscheck>
  <!-- Linux drop points: fast, realtime, hashed -->
  <directories check_all="yes" realtime="yes">/tmp,/var/tmp,/dev/shm</directories>
  <directories check_all="yes" realtime="yes">/home</directories>

  <!-- Windows agents: user-writable drop points -->
  <directories check_all="yes" realtime="yes">C:\Users\*\Downloads</directories>
  <directories check_all="yes" realtime="yes">C:\Users\*\AppData\Local\Temp</directories>
</syscheck>
```

A new/changed file now raises a syscheck alert (rule 550/554 family) carrying
its hashes → DHRUVA's TI enricher checks them against MalwareBazaar,
ThreatFox, and the other hash feeds automatically. No DHRUVA-side config is
needed.

### 2. VirusTotal integration (managed AV verdict on every FIM hash)

With a free VirusTotal key (same one as in the TI feeds section above), the
Wazuh **manager** can look up every FIM hash and raise a dedicated
high-severity alert when VT flags it:

```xml
<integration>
  <name>virustotal</name>
  <api_key>your_virustotal_api_key</api_key>
  <group>syscheck</group>
  <alert_format>json</alert_format>
</integration>
```

VT-positive alerts (rule 87105) arrive in DHRUVA already flagged as malware
findings and get TI enrichment + triage like any other alert. Mind the free
tier's 4 lookups/min — scope the FIM directories (step 1) accordingly.

### 3. DNS query logging + a rule (so a bad domain becomes an alert)

Nothing in a default Wazuh install logs endpoint DNS queries, so a query to a
known-bad domain is invisible. Two proven routes:

- **Windows:** install Sysmon with DNS logging (event ID 22) and ingest the
  Sysmon channel — the Wazuh Sysmon ruleset decodes `queryName`, and DHRUVA's
  TI enricher matches the domain/URL fields.

  ```xml
  <!-- agent ossec.conf -->
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
  ```

- **Linux:** log resolver traffic (e.g. `dnsmasq` with `log-queries`, or Zeek's
  `dns.log`), ingest it with a `<localfile>` block, and add a small local rule
  so queries become alerts, e.g. `/var/ossec/etc/rules/local_rules.xml`:

  ```xml
  <group name="dns,">
    <rule id="110050" level="3">
      <decoded_as>json</decoded_as>
      <field name="dns_query">\.+</field>
      <description>DNS query logged: $(dns_query)</description>
    </rule>
  </group>
  ```

Once the query surfaces in an alert field, the TI enricher's domain matching
takes over (ClearFake-style bad domains are in the feeds).

**Rule of thumb:** if you can find the indicator in an alert in the Wazuh
dashboard, DHRUVA can enrich it. If no alert carries it, fix the Wazuh config
above — not the TI layer.

---

## Required for the Ransomware + Credential-Dumping Playbooks: Install DHRUVA's Trigger Rules

**In plain terms:** DHRUVA has an investigation playbook for ransomware and one
for credential dumping (LSASS/Mimikatz). Neither one will ever run until you
install one extra rules file on your Wazuh manager. This section is how.

**Why it's needed.** When an alert arrives, DHRUVA picks which playbook to use
by looking at the alert's Wazuh **rule groups**. Stock Wazuh has no group called
`ransomware` or `credential_access` — it records those behaviours as MITRE tags
instead, and the playbook matcher doesn't read MITRE tags. So without this file
those two playbooks sit on disk and never fire. The file ships in the package at:

```
config/wazuh/dhruva-playbook-triggers.xml
```

It adds 19 rules (IDs 120000–120199, a range reserved for DHRUVA) that tag
ransomware and credential-dumping behaviour into the two groups the playbooks
look for.

### 1. Check your prerequisites

Most of the credential-dumping rules read **Sysmon** data. If Sysmon isn't
installed on your Windows endpoints and its log channel isn't being collected,
those rules stay silent. Set that up first (see the Sysmon `<localfile>` block
in the DNS section above). The ransomware rules also rely on FIM — make sure
Wazuh's file integrity monitoring covers your file shares and user directories.

### 2. Copy the file onto the Wazuh manager

```bash
sudo cp config/wazuh/dhruva-playbook-triggers.xml /var/ossec/etc/rules/
sudo chown wazuh:wazuh /var/ossec/etc/rules/dhruva-playbook-triggers.xml
sudo chmod 660 /var/ossec/etc/rules/dhruva-playbook-triggers.xml
```

> **Do not paste these rules into `ai-soc-tuned.xml`.** That file belongs to
> DHRUVA's Detection Agent, which rewrites it in full every time you approve and
> deploy a tuning proposal. Anything you add there by hand is erased on the next
> deploy. Always keep these in their own file.

### 3. Validate before you restart — don't skip this

These rules were written against the Wazuh 4.x ruleset but **must be validated
against your specific Wazuh version** before you rely on them. Rule IDs and
field names shift between releases, and a rule that references a parent rule
your version doesn't have will simply never match — silently.

```bash
sudo /var/ossec/bin/wazuh-logtest -v
```

Paste in a sample log line (for example a Sysmon process-creation event) and
confirm the rule you expect actually fires. If `wazuh-logtest` reports an error
loading the file, fix it **before** restarting — a broken rules file can stop
the manager from starting cleanly.

### 4. Restart Wazuh

```bash
sudo /var/ossec/bin/wazuh-control restart
```

### 5. Tune the two exclusion rules (important, or you'll get noise)

Two rules ship as deliberately empty placeholders because the right values
depend on your environment:

| Rule | What to add |
|------|-------------|
| **120010** | Your approved **backup software**. Backup tools legitimately touch shadow copies and would otherwise look like ransomware. Note this rule matches the **parent** process (`parentImage`) — the backup product launches `vssadmin`/`wmic`, it isn't the process named in the alert. |
| **120030** | Your **EDR/antivirus**. Security tools legitimately read LSASS memory and would otherwise look like credential dumping. |

Edit those two rules to match the tools you actually run. Scope exclusions as
tightly as you can — by **full path**, not just executable name. An attacker who
drops a file named `MsMpEng.exe` into a temp directory gets excluded by a
name-only rule. A broad exclusion is exactly the blind spot an attacker wants.

Rule **120008** (100+ file changes in 60 seconds) is the other one to watch. It
ships at **level 10 on purpose** — it's the most false-positive-prone rule in
the set, because 100 file changes in a minute is routine on a file server during
a patch window, a backup restore, or an antivirus signature drop. At level 10 a
false alarm won't land as `high` severity or burn an AI triage call every
maintenance window.

Scope it to the directories that actually matter for you, and once it's quiet,
you can raise the level. Don't just delete it — it's the rule that catches
ransomware families which randomise file extensions and therefore slip past the
signature-based rule above it.

### 6. Confirm it worked

In the Wazuh dashboard, search for rule IDs in the `120000` range, or check that
new alerts carry `ransomware` or `credential_access` in their rule groups. Once
they do, DHRUVA's triage will start routing those alerts to the matching
playbook automatically. You can confirm which playbook was used on any triaged
alert in the dashboard's decision detail (`playbook_used`).

---

## Optional: Set Up Notifications

### Slack

1. Create a Slack webhook at [api.slack.com/messaging/webhooks](https://api.slack.com/messaging/webhooks)
2. Add it to your `.env` file:
   ```
   SLACK_WEBHOOK_URL=https://hooks.slack.com/services/T.../B.../xxx
   ```
3. Set `notifications.enabled: true` in `config/config.yaml`
4. Restart the platform

### Email

Add SMTP details to your `.env` file:

```
SMTP_HOST=smtp.gmail.com
SMTP_USER=alerts@yourcompany.com
SMTP_PASSWORD=your_app_password
SMTP_FROM=alerts@yourcompany.com
```

Add recipient emails in `config/config.yaml` under `notifications.email.recipients`:

```yaml
notifications:
  enabled: true
  email:
    recipients:
      - "soc-team@yourcompany.com"
      - "it-manager@yourcompany.com"
```

---

## Recommended: Enable Command Logging with Auditd

By default, Wazuh monitors login events (who logged in, from where). To also see **what commands were typed and executed** after login, enable auditd on your monitored endpoints. This gives you full visibility into user activity — critical for investigating incidents.

### Step 1: Install auditd (if not already installed)

```bash
# Debian/Ubuntu
sudo apt install auditd audispd-plugins

# RHEL/CentOS
sudo yum install audit
```

### Step 2: Add command execution rules

Create the audit rules file:

```bash
sudo nano /etc/audit/rules.d/commands.rules
```

Add these rules:

```
# Log all command executions (64-bit and 32-bit)
-a always,exit -F arch=b64 -S execve -k command_exec
-a always,exit -F arch=b32 -S execve -k command_exec
```

### Step 3: Restart auditd

```bash
sudo systemctl restart auditd
```

### Step 4: Verify it's working

Run a test command and check:

```bash
ls /tmp
sudo ausearch -k command_exec --start recent
```

You should see the `ls` command in the output.

### What you get

Once auditd is running, Wazuh automatically picks up the events through its auditd integration (rules 80700+). The AI SOC Platform will then show:

- **Full command lines** with arguments in alert details
- **Process trees** — which process launched which command
- **User attribution** — who ran the command (even through sudo)
- **Timeline correlation** — commands correlated with login events and other alerts

This transforms alerts like "SSH login by wazuh-user" into a full story: "wazuh-user logged in via SSH, then ran `sudo su -`, then executed `systemctl restart nginx`."

> **Performance note:** On busy servers, logging every command can generate high volume. For production databases or high-traffic web servers, consider limiting rules to specific users or directories instead of logging everything.

---

## Docker Deployment (Alternative)

If you prefer Docker over direct installation:

```bash
tar xzf dhruva-4.9.0.tar.gz
cd dhruva-4.9.0

# Copy and edit environment file
cp .env.template .env
nano .env          # Fill in your credentials

# Copy license
cp /path/to/license.key .

# Start
docker compose up -d

# Check logs
docker compose logs -f ai-soc
```

The dashboard will be at `http://<your-server-ip>:8443`.

---

## CORS Configuration

If you access the dashboard from a different domain or IP than where the platform is running (e.g., through a reverse proxy or custom domain), you need to set the CORS origin so the browser allows API requests.

Edit `config/config.yaml`:

```yaml
api:
  cors_origins:
    - "https://soc.yourcompany.com"
```

Replace the URL with the actual address your team uses to access the dashboard. If you access it directly via IP (e.g., `http://192.168.1.50:8443`), you can leave the default or add your IP:

```yaml
api:
  cors_origins:
    - "http://192.168.1.50:8443"
```

The deploy wizard asks for this during setup (Step 6). If you skipped it, edit `config/config.yaml` and restart the platform.

> **Note:** The default is `https://soc.securesleuths.local`. If you see "blocked by CORS policy" errors in your browser console, this is almost always the fix.

---

## Upgrading to a New Version

When SecureSleuths provides a new version, your data is fully preserved during the upgrade. Nothing is lost — your incidents, triage decisions, user accounts, detection proposals, threat intel, and all configuration stay intact.

### What you need

- The new version package (e.g., `dhruva-4.9.0.tar.gz`) provided by SecureSleuths
- Access to the server where the platform is installed

### How to upgrade

Copy the new package to your server and run:

```bash
cd /opt/ai-soc-platform
bash scripts/upgrade.sh /path/to/dhruva-4.9.0.tar.gz
```

The script automatically:

1. Stops the platform
2. Backs up your database and config (saved to `/var/lib/ai-soc/backups/`)
3. Replaces only the code files (not your data or settings)
4. Adds any new config sections with default values
5. Adds any new playbooks (without overwriting your customized ones)
6. Updates Python dependencies
7. Restarts the platform
8. Applies any database changes automatically on first startup

### What is preserved (never touched)

| Your Data | Location |
|-----------|----------|
| Database (all decisions, incidents, users, audit logs) | `/var/lib/ai-soc/ai-soc.db` |
| Asset inventory | `/var/lib/ai-soc/assets.yaml` |
| Identity inventory | `/var/lib/ai-soc/identities.yaml` |
| Local threat intel IOCs | `/var/lib/ai-soc/local_iocs.yaml` |
| Credentials and API keys | `.env` |
| Your configuration | `config/config.yaml` |
| Your customized playbooks | `config/guidance/` |
| Your license | `license.key` |

### If something goes wrong

The upgrade script creates a backup before making any changes. To rollback:

```bash
sudo systemctl stop ai-soc
cp /var/lib/ai-soc/ai-soc.db.pre-upgrade-TIMESTAMP /var/lib/ai-soc/ai-soc.db
sudo systemctl start ai-soc
```

The exact rollback command is printed at the end of the upgrade script.

### Docker upgrades

If you use Docker, replace the image and restart:

```bash
docker compose down
# Replace docker-compose.yml with the new version's file
docker compose up -d
```

Your data volume (`/var/lib/ai-soc`) is mounted externally and is not affected.

---

## Managing the Platform

### Check if it's running

```bash
sudo systemctl status ai-soc
```

### View logs

```bash
# Last 100 lines
sudo journalctl -u ai-soc -n 100

# Follow live
sudo journalctl -u ai-soc -f
```

### Restart after config changes

```bash
sudo systemctl restart ai-soc
```

### Stop the platform

```bash
sudo systemctl stop ai-soc
```

---

## Troubleshooting

### "License file not found"

Make sure `license.key` is in the platform folder (same directory as `main.py`). If you placed it elsewhere, update `LICENSE_FILE` in your `.env` file with the full path.

### "License expired"

Contact SecureSleuths to renew your license. The platform shows a warning in the dashboard 14 days before expiry.

### Dashboard says "Loading..." and never finishes

Check the logs:
```bash
sudo journalctl -u ai-soc -n 50
```

Common causes:
- Wazuh is unreachable (check the IP and firewall rules)
- OpenSearch credentials are wrong
- Claude API key is invalid or missing

### No alerts appearing

1. Verify Wazuh is generating alerts (check the Wazuh dashboard)
2. Check the minimum severity setting in `config/config.yaml` -- default is level 3. Wazuh alerts below this level are ignored.
3. Check the logs for `alert_loop` messages

### Claude errors

- **API mode:** Verify your API key at [console.anthropic.com](https://console.anthropic.com). Make sure you have credits.
- **CLI mode:** Run `claude -p "test"` manually to verify it works. You may need to run `claude login` again.

### Cannot connect to Wazuh

Test from your server:
```bash
curl -k https://<wazuh-ip>:55000/ -u <username>:<password>
curl -k https://<wazuh-ip>:9200/_cluster/health -u admin:<password>
```

If these fail, check:
- Firewall rules between your server and Wazuh
- Wazuh API is enabled and listening
- Credentials are correct

---

## Getting Help

- **Email:** support@securesleuths.com
- **License issues:** Include your client ID (shown in the dashboard under the admin menu)
- **Bug reports:** Include the last 100 lines of logs: `sudo journalctl -u ai-soc -n 100`

---

## Quick Reference

| What | Command |
|------|---------|
| Start platform | `sudo systemctl start ai-soc` |
| Stop platform | `sudo systemctl stop ai-soc` |
| Restart platform | `sudo systemctl restart ai-soc` |
| Check status | `sudo systemctl status ai-soc` |
| View logs | `sudo journalctl -u ai-soc -f` |
| Upgrade | `bash scripts/upgrade.sh /path/to/new-version.tar.gz` |
| Edit credentials | `nano .env` |
| Edit config | `nano config/config.yaml` |
| Edit asset inventory | `nano /var/lib/ai-soc/assets.yaml` |
| Edit user inventory | `nano /var/lib/ai-soc/identities.yaml` |
| Edit risk criteria | `nano config/guidance/risk_criteria.yaml` |
| Edit escalation rules | `nano config/guidance/escalation_logic.yaml` |
| Open dashboard | `http://<server-ip>:8443` |

---

## Need Help?

If the platform is not working as expected, we're here to help.

1. **Collect the log output** — copy the terminal output or, if running as a systemd service, run:
   ```bash
   sudo journalctl -u ai-soc --since "1 hour ago" --no-pager > dhruva-logs.txt
   ```

2. **Email us the log file** at **info@securesleuths.in** with a brief description of what's not working.

We'll review the logs and help resolve the issue — no charge for Community users.

Website: [securesleuths.in](https://securesleuths.in)
