"""Shared dependency state for all API route modules.

All global references to services (db, enrichment, agents, etc.) live here.
Route modules import getter functions to access them.

The ``limiter`` instance also lives here to avoid circular imports between
app.py (which creates the FastAPI app and includes routers) and the route
modules (which need to decorate endpoints with rate limits).
"""

import structlog
from slowapi import Limiter
from slowapi.util import get_remote_address

logger = structlog.get_logger(__name__)

# Rate limiter — shared across all route modules and app.py
limiter = Limiter(key_func=get_remote_address)

# Global service references — set by init_api() in app.py
_db = None
_enrichment = None
_triage_agent = None
_detection_agent = None
_feedback_engine = None
_hunt_agent = None
_query_agent = None
_notifications = None
_sla_manager = None
_metrics_calculator = None
_soar_engine = None
_mitre_analyzer = None
_ticketing_service = None
_knowledge_base = None
_config = None
_license_info = None
_ti_collector = None
_platform_users: dict = {}
_platform_roles: dict = {}
_pipeline_monitor = None
_alert_buffer = None
_tenant_registry = None


def get_db():
    return _db

def get_enrichment():
    return _enrichment

def get_triage_agent():
    return _triage_agent

def get_detection_agent():
    return _detection_agent

def get_feedback_engine():
    return _feedback_engine

def get_hunt_agent():
    return _hunt_agent

def get_query_agent():
    return _query_agent

def get_notifications():
    return _notifications

def get_sla_manager():
    return _sla_manager

def get_metrics_calculator():
    return _metrics_calculator

def get_soar_engine():
    return _soar_engine

def get_mitre_analyzer():
    return _mitre_analyzer

def get_ticketing_service():
    return _ticketing_service

def get_knowledge_base():
    return _knowledge_base

def get_config():
    return _config

def get_license_info():
    return _license_info

def get_ti_collector():
    return _ti_collector

def get_platform_users():
    return _platform_users

def get_platform_roles():
    return _platform_roles

def get_pipeline_monitor():
    return _pipeline_monitor

def get_alert_buffer():
    return _alert_buffer

def get_tenant_registry():
    return _tenant_registry
