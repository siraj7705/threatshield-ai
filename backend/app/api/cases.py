"""
ThreatShield AI - Case Management API Routes
"""
import json
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc

from app.core.database import get_db
from app.core.security import get_current_user, require_roles, ADMIN_AND_ANALYST, ADMIN_ONLY, is_admin, can_access_owned_resource
from app.models.case import Case
from app.schemas import CaseCreate, CaseResponse

router = APIRouter(prefix="/api/cases", tags=["Cases"])


def _generate_case_number(case_id: int) -> str:
    now = datetime.now(timezone.utc)
    return f"CASE-{now.year}-{case_id:04d}"


@router.post("", response_model=CaseResponse, status_code=201)
async def create_case(
    case_data: CaseCreate,
    current_user: dict = Depends(require_roles(ADMIN_AND_ANALYST)),
    db: AsyncSession = Depends(get_db),
):
    """Create a new investigation case. Admin/analyst only."""
    new_case = Case(
        case_number="PENDING",
        title=case_data.title,
        description=case_data.description,
        priority=case_data.priority,
        status="open",
        created_by=current_user["id"],
        email_ids=json.dumps(case_data.email_ids or []),
    )
    db.add(new_case)
    await db.flush()
    new_case.case_number = _generate_case_number(new_case.id)

    return CaseResponse.model_validate(new_case)


@router.get("")
async def list_cases(
    status: str = None,
    priority: str = None,
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    List cases with optional filtering.

    Admins see every case. Analysts/investigators only see cases they
    created or are assigned to — a case has no "shared mailbox" equivalent,
    so unlike emails there's no no-owner exception here.
    """
    query = select(Case)
    count_q = select(func.count(Case.id))

    if not is_admin(current_user):
        ownership_filter = (Case.created_by == current_user["id"]) | (Case.assigned_to == current_user["id"])
        query = query.where(ownership_filter)
        count_q = count_q.where(ownership_filter)

    if status:
        query = query.where(Case.status == status)
        count_q = count_q.where(Case.status == status)
    if priority:
        query = query.where(Case.priority == priority)
        count_q = count_q.where(Case.priority == priority)

    total = (await db.execute(count_q)).scalar() or 0

    query = query.order_by(desc(Case.created_at)).offset((page - 1) * per_page).limit(per_page)
    result = await db.execute(query)
    cases = [CaseResponse.model_validate(c) for c in result.scalars().all()]

    return {"total": total, "page": page, "per_page": per_page, "cases": cases}


def _check_case_access(current_user: dict, case: Case):
    """Raise 404 (not 403, to avoid confirming the case exists) if the current user doesn't own/admin this case."""
    if is_admin(current_user):
        return
    owns = case.created_by == current_user["id"] or case.assigned_to == current_user["id"]
    if not owns:
        raise HTTPException(status_code=404, detail="Case not found")


@router.get("/{case_id}", response_model=CaseResponse)
async def get_case(
    case_id: int,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get a specific case by ID — only if you created it, are assigned to it, or are an admin."""
    result = await db.execute(select(Case).where(Case.id == case_id))
    case = result.scalar_one_or_none()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    _check_case_access(current_user, case)
    return CaseResponse.model_validate(case)


@router.put("/{case_id}/status")
async def update_case_status(
    case_id: int,
    body: dict,
    current_user: dict = Depends(require_roles(ADMIN_AND_ANALYST)),
    db: AsyncSession = Depends(get_db),
):
    """Update case status. Admin/analyst only, and only on cases you own (admins exempt)."""
    result = await db.execute(select(Case).where(Case.id == case_id))
    case = result.scalar_one_or_none()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    _check_case_access(current_user, case)

    new_status = body.get("status")
    allowed = ["open", "in_progress", "closed", "resolved"]
    if new_status not in allowed:
        raise HTTPException(status_code=400, detail=f"Status must be one of: {allowed}")

    case.status = new_status
    if new_status in ("closed", "resolved"):
        case.closed_at = datetime.now(timezone.utc)

    return {"message": "Status updated", "case_id": case_id, "status": new_status}


@router.put("/{case_id}/assign")
async def assign_case(
    case_id: int,
    body: dict,
    current_user: dict = Depends(require_roles(ADMIN_AND_ANALYST)),
    db: AsyncSession = Depends(get_db),
):
    """Assign a case to a user. Admin/analyst only, and only on cases you own (admins exempt)."""
    result = await db.execute(select(Case).where(Case.id == case_id))
    case = result.scalar_one_or_none()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    _check_case_access(current_user, case)
    case.assigned_to = body.get("user_id")
    return {"message": "Case assigned", "case_id": case_id}


@router.post("/{case_id}/notes")
async def add_note(
    case_id: int,
    body: dict,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Add a note to a case — only if you own it (created or assigned) or are an admin."""
    result = await db.execute(select(Case).where(Case.id == case_id))
    case = result.scalar_one_or_none()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    _check_case_access(current_user, case)

    note_text = body.get("note", "")
    existing = json.loads(case.notes) if case.notes else []
    existing.append({
        "text": note_text,
        "by": current_user["username"],
        "at": datetime.now(timezone.utc).isoformat()
    })
    case.notes = json.dumps(existing)

    return {"message": "Note added", "case_id": case_id}


@router.delete("/{case_id}")
async def delete_case(
    case_id: int,
    current_user: dict = Depends(require_roles(ADMIN_ONLY)),
    db: AsyncSession = Depends(get_db),
):
    """Delete a case. Admin only."""
    result = await db.execute(select(Case).where(Case.id == case_id))
    case = result.scalar_one_or_none()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    await db.delete(case)
    return {"message": "Case deleted"}