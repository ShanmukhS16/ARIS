"""ARIS ORM models - SQLAlchemy 2.x declarative style."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import (
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    pass


class Event(Base):
    __tablename__ = "events"

    id: int = Column(Integer, primary_key=True, autoincrement=True)
    ingestion_id: str = Column(String(64), nullable=False, index=True)
    timestamp: datetime = Column(DateTime, nullable=False, index=True)
    host: str = Column(String(256), nullable=False, index=True)
    source_type: str = Column(String(32), nullable=False)  # sysmon, authlog, ecar
    user: Optional[str] = Column(String(256), nullable=True)
    process: Optional[str] = Column(Text, nullable=True)
    raw: Optional[str] = Column(Text, nullable=True)
    parsed: Optional[str] = Column(Text, nullable=True)  # JSON string
    anomaly_score: Optional[float] = Column(Float, nullable=True)
    detection_level: str = Column(String(16), nullable=False, default="none", index=True)

    detections = relationship("Detection", back_populates="event", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_events_source", "source_type"),
    )


class Detection(Base):
    __tablename__ = "detections"

    id: int = Column(Integer, primary_key=True, autoincrement=True)
    event_id: int = Column(Integer, ForeignKey("events.id"), nullable=False, index=True)
    rule_id: str = Column(String(64), nullable=False)
    rule_title: str = Column(String(256), nullable=False)
    severity: str = Column(String(16), nullable=False)
    mitre_attack_id: Optional[str] = Column(String(32), nullable=True)
    mitre_tactic: Optional[str] = Column(String(64), nullable=True)
    matched_fields: Optional[str] = Column(Text, nullable=True)  # JSON

    event = relationship("Event", back_populates="detections")


class Narrative(Base):
    __tablename__ = "narratives"

    id: int = Column(Integer, primary_key=True, autoincrement=True)
    ingestion_id: str = Column(String(64), nullable=False, index=True)
    created_at: datetime = Column(DateTime, nullable=False, default=datetime.utcnow)
    source: str = Column(String(16), nullable=False)  # llm or offline
    content: str = Column(Text, nullable=False)  # JSON string


def new_ingestion_id() -> str:
    return uuid.uuid4().hex[:12]
