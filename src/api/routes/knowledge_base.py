"""Knowledge Base routes — search, CRUD, and stats."""

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, Request

from src.api.auth import verify_jwt, require_role
from src.api.dependencies import get_db, get_knowledge_base, limiter
from src.api.feature_gates import require_license_feature

router = APIRouter(prefix="/api/kb")
logger = structlog.get_logger(__name__)

_kb_gate = Depends(require_license_feature("knowledge_base"))


@router.get("/search")
@limiter.limit("200/minute")
async def search_kb(
    request: Request,
    q: str = Query(..., min_length=2),
    type: str = Query(None),
    tags: str = Query(None),
    limit: int = Query(10, ge=1, le=50),
    user: dict = Depends(verify_jwt),
    _gate: None = _kb_gate,
):
    """Full-text search across knowledge base documents."""
    kb = get_knowledge_base()
    if not kb or not kb.enabled:
        return {"results": [], "total": 0, "query": q}

    tag_list = [t.strip() for t in tags.split(",") if t.strip()] if tags else None
    results = kb.search(q, doc_type=type, tags=tag_list, limit=limit)
    return {"results": results, "total": len(results), "query": q}


@router.get("/documents")
@limiter.limit("200/minute")
async def list_documents(
    request: Request,
    type: str = Query(None),
    limit: int = Query(50, ge=1, le=200),
    user: dict = Depends(verify_jwt),
    _gate: None = _kb_gate,
):
    """List knowledge base documents with optional type filter."""
    _db = get_db()
    docs = _db.get_kb_documents(doc_type=type, limit=limit)
    return {"documents": docs, "total": len(docs)}


@router.get("/stats")
@limiter.limit("200/minute")
async def kb_stats(request: Request, user: dict = Depends(verify_jwt), _gate: None = _kb_gate):
    """Knowledge base statistics."""
    _db = get_db()
    return _db.get_kb_stats()


@router.get("/documents/{doc_id}")
@limiter.limit("200/minute")
async def get_document(
    request: Request, doc_id: str,
    user: dict = Depends(verify_jwt),
    _gate: None = _kb_gate,
):
    """Get a single KB document."""
    _db = get_db()
    doc = _db.get_kb_document(doc_id)
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")
    return doc


@router.post("/documents")
@limiter.limit("30/minute")
async def create_document(
    request: Request,
    user: dict = Depends(require_role(
        "admin", "senior_analyst", "analyst", "mssp_admin")),
    _gate: None = _kb_gate,
):
    """Create a new knowledge base document."""
    kb = get_knowledge_base()
    if not kb or not kb.enabled:
        raise HTTPException(status_code=503,
                            detail="Knowledge base is disabled")

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")
    if not body.get("title") or not body.get("content"):
        raise HTTPException(status_code=400,
                            detail="title and content are required")

    actor = user.get("sub", "unknown")
    try:
        doc = kb.create_document(body, created_by=actor)
    except ValueError as e:
        logger.warning("kb_create_validation_failed", error=str(e))
        raise HTTPException(status_code=400, detail="Invalid document data.")

    _db = get_db()
    _db.log_audit(actor, "kb_create", "kb_document", doc["id"],
                  details={"title": doc["title"], "doc_type": doc["doc_type"]},
                  ip_address=request.client.host if request.client else "")

    return {"status": "ok", "document": doc}


@router.put("/documents/{doc_id}")
@limiter.limit("30/minute")
async def update_document(
    request: Request, doc_id: str,
    user: dict = Depends(require_role(
        "admin", "senior_analyst", "mssp_admin")),
    _gate: None = _kb_gate,
):
    """Update a knowledge base document."""
    _db = get_db()
    existing = _db.get_kb_document(doc_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Document not found")

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")
    updates = {}
    for field in ("title", "content", "tags", "mitre_techniques"):
        if field in body:
            updates[field] = body[field]

    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")

    _db.update_kb_document(doc_id, **updates)

    actor = user.get("sub", "unknown")
    _db.log_audit(actor, "kb_update", "kb_document", doc_id,
                  details={"fields": list(updates.keys())},
                  ip_address=request.client.host if request.client else "")

    return {"status": "ok", "document_id": doc_id}


@router.delete("/documents/{doc_id}")
@limiter.limit("30/minute")
async def delete_document(
    request: Request, doc_id: str,
    user: dict = Depends(require_role(
        "admin", "senior_analyst", "mssp_admin")),
    _gate: None = _kb_gate,
):
    """Delete a knowledge base document."""
    _db = get_db()
    existing = _db.get_kb_document(doc_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Document not found")

    _db.delete_kb_document(doc_id)

    actor = user.get("sub", "unknown")
    _db.log_audit(actor, "kb_delete", "kb_document", doc_id,
                  details={"title": existing.get("title", "")},
                  ip_address=request.client.host if request.client else "")

    return {"status": "ok", "document_id": doc_id}
