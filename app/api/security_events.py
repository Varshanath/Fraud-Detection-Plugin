import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.database import get_db
from app.ingestion import service
from app.ingestion.schemas import SecurityEventCreate, SecurityEventResponse

router = APIRouter(prefix="/security-events", tags=["security-events"])


@router.post("", response_model=SecurityEventResponse, status_code=201)
def create_event(payload: SecurityEventCreate, db: Session = Depends(get_db)):
    try:
        event = service.create_security_event(db, payload)
    except SQLAlchemyError:
        raise HTTPException(status_code=500, detail="Failed to persist security event")
    return event


@router.get("/{event_id}", response_model=SecurityEventResponse)
def get_event(event_id: uuid.UUID, db: Session = Depends(get_db)):
    try:
        event = service.get_security_event(db, event_id)
    except SQLAlchemyError:
        raise HTTPException(status_code=500, detail="Failed to retrieve security event")

    if event is None:
        raise HTTPException(status_code=404, detail="Security event not found")
    return event
