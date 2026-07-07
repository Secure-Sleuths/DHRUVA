"""Knowledge Base service — search, auto-index, and agent context.

Full-text search runs on Postgres ``tsvector`` / ``to_tsquery`` with relevance
ranking, implemented in the store layer (``src/database/store.py``).
"""

import json
import re
import uuid
import structlog
from datetime import datetime, timezone

logger = structlog.get_logger(__name__)

ALLOWED_DOC_TYPES = {
    "analyst_note", "investigation_pattern", "feedback_pattern",
    "hunt_finding", "incident_learning", "guidance",
}


class KnowledgeBaseService:
    """Orchestrates knowledge base search, creation, and auto-indexing."""

    def __init__(self, config: dict, db):
        self.config = config
        self.db = db

        kb_cfg = config.get("knowledge_base", {})
        self.enabled = kb_cfg.get("enabled", True)
        self.auto_index_feedback = kb_cfg.get("auto_index_feedback", True)
        self.auto_index_hunts = kb_cfg.get("auto_index_hunts", True)
        self.auto_index_incidents = kb_cfg.get("auto_index_incidents", True)
        self.auto_index_guidance = kb_cfg.get("auto_index_guidance", True)
        self.max_agent_results = kb_cfg.get("max_agent_results", 3)

        if self.enabled:
            logger.info("knowledge_base_service_ready")

    # ------------------------------------------------------------------
    # Search
    # ------------------------------------------------------------------

    def search(self, query: str, doc_type: str = None,
               tags: list = None, limit: int = 10) -> list[dict]:
        """Search KB using Postgres tsvector/to_tsquery full-text search with relevance ranking."""
        if not self.enabled or not query or not query.strip():
            return []
        fts_query = self._sanitize_fts_query(query)
        if not fts_query:
            return []
        return self.db.search_kb(fts_query, doc_type=doc_type,
                                 tags=tags, limit=limit)

    def search_for_agent(self, rule_description: str = "",
                         mitre_techniques: list = None,
                         limit: int = None) -> str:
        """Search KB and return formatted context for agent prompt injection.

        Returns a string under ~500 tokens, or empty string if no results.
        """
        if not self.enabled:
            return ""

        limit = limit or self.max_agent_results

        # Build query from rule description keywords + MITRE techniques
        query_parts = []
        if rule_description:
            # Extract meaningful keywords (skip short/common words)
            words = re.findall(r'[a-zA-Z]{4,}', rule_description)
            query_parts.extend(words[:8])
        if mitre_techniques:
            query_parts.extend(
                t for t in mitre_techniques if t and t.startswith("T"))

        if not query_parts:
            return ""

        fts_query = self._sanitize_fts_query(" ".join(query_parts))
        if not fts_query:
            return ""

        results = self.db.search_kb(fts_query, limit=limit)
        if not results:
            return ""

        lines = []
        total_chars = 0
        for r in results:
            doc_type = r.get("doc_type", "note")
            title = r.get("title", "")[:80]
            content = r.get("content", "")[:200]
            line = f"- [{doc_type}] {title}: {content}"
            if total_chars + len(line) > 1500:
                break
            lines.append(line)
            total_chars += len(line)

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def create_document(self, doc: dict, created_by: str = "unknown") -> dict:
        """Create a new KB document."""
        doc_type = doc.get("doc_type", "analyst_note")
        if doc_type not in ALLOWED_DOC_TYPES:
            raise ValueError(f"Invalid doc_type: {doc_type}")

        now = datetime.now(timezone.utc).isoformat()
        record = {
            "id": str(uuid.uuid4()),
            "doc_type": doc_type,
            "title": doc["title"],
            "content": doc["content"],
            "tags": doc.get("tags", []),
            "mitre_techniques": doc.get("mitre_techniques", []),
            "source_type": doc.get("source_type"),
            "source_id": doc.get("source_id"),
            "created_by": created_by,
            "created_at": now,
            "client_id": doc.get("client_id"),
        }
        doc_id = self.db.save_kb_document(record)
        record["id"] = doc_id
        logger.info("kb_document_created", doc_id=doc_id, doc_type=doc_type)
        return record

    def update_document(self, doc_id: str, updates: dict) -> bool:
        return self.db.update_kb_document(doc_id, **updates)

    def delete_document(self, doc_id: str) -> bool:
        return self.db.delete_kb_document(doc_id)

    def get_stats(self) -> dict:
        return self.db.get_kb_stats()

    # ------------------------------------------------------------------
    # Auto-indexing
    # ------------------------------------------------------------------

    def index_feedback_pattern(self, pattern: dict,
                               reasoning: str = "") -> str:
        """Auto-index a confirmed feedback pattern into KB."""
        if not self.enabled or not self.auto_index_feedback:
            return ""

        source_id = pattern.get("id", "")
        existing = self.db.get_kb_by_source("feedback_pattern", source_id)
        if existing:
            return existing["id"]

        rule_id = pattern.get("rule_id", "unknown")
        desc = pattern.get("description", "")[:200]
        action = pattern.get("auto_action_taken", "")
        count = pattern.get("occurrence_count", 0)

        content = f"Rule {rule_id}: {desc}\n"
        content += f"Pattern type: {pattern.get('pattern_type', 'unknown')}\n"
        content += f"Occurrences: {count}\n"
        content += f"Action taken: {action}\n"
        if reasoning:
            content += f"Reasoning: {reasoning}\n"
        content += f"Period: {pattern.get('first_seen', '')} to {pattern.get('last_seen', '')}"

        doc = {
            "doc_type": "feedback_pattern",
            "title": f"FP Pattern: Rule {rule_id} — {desc[:80]}",
            "content": content,
            "tags": ["feedback", "false_positive", f"rule_{rule_id}"],
            "source_type": "feedback_pattern",
            "source_id": source_id,
        }
        return self.create_document(doc, created_by="auto")["id"]

    def index_hunt_finding(self, finding: dict) -> str:
        """Auto-index a confirmed hunt finding into KB."""
        if not self.enabled or not self.auto_index_hunts:
            return ""

        source_id = finding.get("id", "")
        existing = self.db.get_kb_by_source("hunt_finding", source_id)
        if existing:
            return existing["id"]

        hypothesis = finding.get("hypothesis", "")
        technique = finding.get("mitre_technique", "")
        summary = finding.get("results_summary", "")
        notes = finding.get("analyst_notes", "")

        content = f"Hypothesis: {hypothesis}\n"
        if technique:
            content += f"MITRE Technique: {technique}\n"
        content += f"Results: {finding.get('result_count', 0)} hits\n"
        if summary:
            content += f"Summary: {summary[:500]}\n"
        if notes:
            content += f"Analyst notes: {notes[:500]}"

        tags = ["hunt", finding.get("priority", "medium")]
        mitre = [technique] if technique else []

        doc = {
            "doc_type": "hunt_finding",
            "title": f"Hunt: {hypothesis[:100]}",
            "content": content,
            "tags": tags,
            "mitre_techniques": mitre,
            "source_type": "hunt_finding",
            "source_id": source_id,
        }
        return self.create_document(doc, created_by="auto")["id"]

    def index_incident_learning(self, incident: dict,
                                notes: list) -> str:
        """Auto-index a resolved incident with analyst notes into KB."""
        if not self.enabled or not self.auto_index_incidents:
            return ""
        if not notes:
            return ""

        source_id = incident.get("id", "")
        existing = self.db.get_kb_by_source("incident_learning", source_id)
        if existing:
            return existing["id"]

        title = incident.get("title", "Incident")[:100]
        severity = incident.get("severity", "unknown")
        summary = incident.get("summary", "")

        # Parse JSON fields safely
        tactics = _safe_json(incident.get("mitre_tactics", "[]"))
        techniques = _safe_json(incident.get("mitre_techniques", "[]"))
        hosts = _safe_json(incident.get("affected_hosts", "[]"))

        content = f"Incident: {title}\n"
        content += f"Severity: {severity}\n"
        content += f"Alerts: {incident.get('alert_count', 0)}\n"
        if summary:
            content += f"Summary: {summary[:500]}\n"
        if hosts:
            content += f"Affected hosts: {', '.join(hosts)}\n"
        if tactics:
            content += f"Tactics: {', '.join(tactics)}\n"
        if techniques:
            content += f"Techniques: {', '.join(techniques)}\n"
        content += f"\nAnalyst Notes:\n"
        for note in notes[:10]:
            content += f"- {note[:200]}\n"

        tags = ["incident", severity]
        mitre = [t for t in techniques if t] if techniques else []

        doc = {
            "doc_type": "incident_learning",
            "title": f"Incident: {title}",
            "content": content,
            "tags": tags,
            "mitre_techniques": mitre,
            "source_type": "incident_learning",
            "source_id": source_id,
            "client_id": incident.get("client_id"),
        }
        return self.create_document(doc, created_by="auto")["id"]

    def index_guidance_docs(self, guidance_loader) -> int:
        """Re-index all guidance documents (full refresh)."""
        if not self.enabled or not self.auto_index_guidance:
            return 0

        self.db.delete_kb_by_type("guidance")
        count = 0

        # Index playbooks
        playbooks = guidance_loader.get_all_playbooks() \
            if hasattr(guidance_loader, 'get_all_playbooks') else {}
        for name, playbook in playbooks.items():
            content = ""
            if isinstance(playbook, dict):
                content = json.dumps(playbook, indent=2, default=str)[:3000]
            elif isinstance(playbook, str):
                content = playbook[:3000]
            self.db.save_kb_document({
                "doc_type": "guidance",
                "title": f"Playbook: {name}",
                "content": content,
                "tags": ["guidance", "playbook", name],
                "source_type": "guidance",
                "source_id": f"playbook_{name}",
                "created_by": "system",
            })
            count += 1

        # Index risk criteria
        risk = guidance_loader.get_risk_criteria_text() \
            if hasattr(guidance_loader, 'get_risk_criteria_text') else ""
        if risk:
            self.db.save_kb_document({
                "doc_type": "guidance",
                "title": "Risk Criteria",
                "content": risk[:3000],
                "tags": ["guidance", "risk_criteria"],
                "source_type": "guidance",
                "source_id": "risk_criteria",
                "created_by": "system",
            })
            count += 1

        # Index escalation logic
        esc = guidance_loader.get_escalation_logic_text() \
            if hasattr(guidance_loader, 'get_escalation_logic_text') else ""
        if esc:
            self.db.save_kb_document({
                "doc_type": "guidance",
                "title": "Escalation Logic",
                "content": esc[:3000],
                "tags": ["guidance", "escalation"],
                "source_type": "guidance",
                "source_id": "escalation_logic",
                "created_by": "system",
            })
            count += 1

        logger.info("kb_guidance_indexed", count=count)
        return count

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _sanitize_fts_query(query: str) -> str:
        """Sanitize user input before full-text search.

        Wraps each token in double quotes for literal matching (implicit AND).
        This is legacy/defensive input cleaning that strips characters once used
        as FTS5 operators; the actual full-text search runs on Postgres
        ``to_tsquery`` in the store layer, which re-escapes the input it
        receives.
        """
        # Strip legacy FTS5 special chars (defensive input cleaning)
        cleaned = re.sub(r'["\(\)\*\^\{\}]', ' ', query)
        # Split into tokens, skip very short words
        tokens = [t.strip() for t in cleaned.split() if len(t.strip()) >= 2]
        if not tokens:
            return ""
        # Quote each token for literal matching
        quoted = [f'"{t}"' for t in tokens[:15]]
        return " ".join(quoted)


def _safe_json(val) -> list:
    """Parse a JSON string or return as-is if already a list."""
    if isinstance(val, list):
        return val
    if isinstance(val, str):
        try:
            parsed = json.loads(val)
            return parsed if isinstance(parsed, list) else []
        except Exception:
            return []
    return []
