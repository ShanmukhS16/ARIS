"""ARIS FastAPI application.

Endpoints:
  GET  /api/health          - Health check
  POST /api/ingest          - Upload and process log files
  GET  /api/events          - List events with filtering
  GET  /api/detections      - List Sigma detections
  GET  /api/stats           - Dashboard summary stats
  POST /api/narrative       - Generate incident narrative
  POST /api/train           - Train ML model on existing data
"""

from __future__ import annotations

import json
import logging
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import func, select
from sqlalchemy.orm import selectinload

from app.config import settings
from app.database import async_session, init_db
from app.ml.anomaly import is_anomaly, load_model, score_event, train_model
from app.models import Detection, Event, Narrative, new_ingestion_id
from app.narrative.generator import generate_narrative
from app.parsers.authlog import parse_authlog_file
from app.parsers.optc import is_ecar_format, parse_optc_file
from app.parsers.sysmon import parse_sysmon_file
from app.sigma_engine.engine import run_rules

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    load_model()
    logger.info("ARIS backend ready")
    yield


app = FastAPI(
    title="ARIS",
    description="Automated Registry and Incident Sifting",
    version="0.5.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---- Health ----

@app.get("/api/health")
async def health():
    return {"status": "ok", "version": "0.5.0"}


# ---- Ingest ----

@app.post("/api/ingest")
async def ingest(file: UploadFile = File(...)):
    """Ingest a log file. Auto-detects format (Sysmon JSONL, auth.log, eCAR)."""
    content = (await file.read()).decode("utf-8", errors="replace")
    filename = file.filename or "unknown"
    ingestion_id = new_ingestion_id()

    # Detect format and parse
    if is_ecar_format(content):
        events = list(parse_optc_file(content))
        source = "ecar"
    elif filename.endswith(".jsonl") or filename.endswith(".json"):
        events = list(parse_sysmon_file(content))
        source = "sysmon"
    elif filename.endswith(".log") or "sshd" in content[:500].lower() or "auth" in filename.lower():
        events = list(parse_authlog_file(content))
        source = "authlog"
    else:
        # Try Sysmon first, fall back to auth.log
        events = list(parse_sysmon_file(content))
        if not events:
            events = list(parse_authlog_file(content))
        source = "auto"

    if not events:
        raise HTTPException(status_code=400, detail="No events parsed from file")

    # Run detection pipeline on each event
    total_sigma = 0
    total_ml = 0
    async with async_session() as session:
        for ev in events:
            ev.ingestion_id = ingestion_id

            # Sigma rules
            dets = run_rules(ev)
            for d in dets:
                ev.detections.append(d)
            total_sigma += len(dets)

            # ML anomaly scoring
            score = score_event(ev)
            if score is not None:
                ev.anomaly_score = score
                if is_anomaly(score):
                    total_ml += 1

            # Set detection level
            if dets and is_anomaly(ev.anomaly_score):
                ev.detection_level = "both"
            elif dets:
                ev.detection_level = "sigma"
            elif is_anomaly(ev.anomaly_score):
                ev.detection_level = "ml"
            else:
                ev.detection_level = "none"

            session.add(ev)
        await session.commit()

    return {
        "ingestion_id": ingestion_id,
        "source": source,
        "events_parsed": len(events),
        "sigma_detections": total_sigma,
        "ml_anomalies": total_ml,
    }


# ---- Events ----

@app.get("/api/events")
async def list_events(
    ingestion_id: Optional[str] = None,
    host: Optional[str] = None,
    detection_level: Optional[str] = None,
    limit: int = Query(default=200, le=1000),
    offset: int = Query(default=0, ge=0),
):
    """List events with optional filtering."""
    stmt = select(Event).options(selectinload(Event.detections)).order_by(Event.timestamp)

    if ingestion_id:
        stmt = stmt.where(Event.ingestion_id == ingestion_id)
    if host:
        stmt = stmt.where(Event.host == host)
    if detection_level and detection_level != "all":
        if detection_level == "any":
            stmt = stmt.where(Event.detection_level != "none")
        else:
            stmt = stmt.where(Event.detection_level == detection_level)

    # Count total matching rows before pagination
    count_stmt = select(func.count()).select_from(stmt.subquery())
    async with async_session() as session:
        total = await session.scalar(count_stmt)

    stmt = stmt.offset(offset).limit(limit)

    async with async_session() as session:
        result = await session.execute(stmt)
        events = result.scalars().all()

    return {
        "items": [
            {
                "id": ev.id,
                "ingestion_id": ev.ingestion_id,
                "timestamp": ev.timestamp.isoformat(),
                "host": ev.host,
                "source_type": ev.source_type,
                "user": ev.user,
                "process": ev.process,
                "anomaly_score": ev.anomaly_score,
                "detection_level": ev.detection_level,
                "detections": [
                    {
                        "rule_id": d.rule_id,
                        "rule_title": d.rule_title,
                        "severity": d.severity,
                        "mitre_attack_id": d.mitre_attack_id,
                        "mitre_tactic": d.mitre_tactic,
                    }
                    for d in ev.detections
                ],
            }
            for ev in events
        ],
        "total": total or 0,
        "limit": limit,
        "offset": offset,
    }


# ---- Detections ----

@app.get("/api/detections")
async def list_detections(
    ingestion_id: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = Query(default=200, le=1000),
):
    """List Sigma detections."""
    stmt = (
        select(Detection)
        .join(Event)
        .options(selectinload(Detection.event))
        .order_by(Event.timestamp)
    )
    if ingestion_id:
        stmt = stmt.where(Event.ingestion_id == ingestion_id)
    if severity:
        stmt = stmt.where(Detection.severity == severity)

    count_stmt = select(func.count()).select_from(stmt.subquery())
    async with async_session() as session:
        total = await session.scalar(count_stmt)

    stmt = stmt.limit(limit)

    async with async_session() as session:
        result = await session.execute(stmt)
        detections = result.scalars().all()

    return {
        "items": [
            {
                "id": d.id,
                "event_id": d.event_id,
                "rule_id": d.rule_id,
                "rule_title": d.rule_title,
                "severity": d.severity,
                "mitre_attack_id": d.mitre_attack_id,
                "mitre_tactic": d.mitre_tactic,
                "event_timestamp": d.event.timestamp.isoformat() if d.event else None,
                "event_host": d.event.host if d.event else None,
                "event_process": d.event.process if d.event else None,
            }
            for d in detections
        ],
        "total": total or 0,
        "limit": limit,
    }


# ---- Stats ----

@app.get("/api/stats")
async def stats(ingestion_id: Optional[str] = None):
    """Dashboard summary statistics."""
    async with async_session() as session:
        base = select(Event)
        if ingestion_id:
            base = base.where(Event.ingestion_id == ingestion_id)

        # Total events
        total = await session.scalar(select(func.count()).select_from(base.subquery()))

        # By detection level
        levels = {}
        for level in ("none", "sigma", "ml", "both"):
            q = base.where(Event.detection_level == level)
            levels[level] = await session.scalar(select(func.count()).select_from(q.subquery()))

        # Unique hosts
        host_sub = base.with_only_columns(func.distinct(Event.host))
        hosts = await session.scalar(
            select(func.count()).select_from(host_sub.subquery())
        )

        # Detection count
        if ingestion_id:
            det_q = (
                select(func.count())
                .select_from(Detection)
                .join(Event)
                .where(Event.ingestion_id == ingestion_id)
            )
        else:
            det_q = select(func.count()).select_from(Detection)
        det_count = await session.scalar(det_q)

        # Most recent ingestion
        latest_q = select(Event.ingestion_id).order_by(Event.id.desc()).limit(1)
        latest_ingestion = await session.scalar(latest_q)

    return {
        "total_events": total or 0,
        "unique_hosts": hosts or 0,
        "total_detections": det_count or 0,
        "by_detection_level": levels,
        "latest_ingestion_id": latest_ingestion,
    }


# ---- Narrative ----

@app.post("/api/narrative")
async def narrative_endpoint(ingestion_id: Optional[str] = None):
    """Generate an incident narrative for a given ingestion (or latest)."""
    async with async_session() as session:
        # Get the target ingestion
        if not ingestion_id:
            latest = await session.scalar(
                select(Event.ingestion_id).order_by(Event.id.desc()).limit(1)
            )
            if not latest:
                raise HTTPException(status_code=404, detail="No events found")
            ingestion_id = latest

        # Load events with detections
        result = await session.execute(
            select(Event)
            .where(Event.ingestion_id == ingestion_id)
            .options(selectinload(Event.detections))
            .order_by(Event.timestamp)
        )
        events = result.scalars().all()

    if not events:
        raise HTTPException(status_code=404, detail=f"No events for ingestion {ingestion_id}")

    # Build inputs for narrative generator
    event_dicts = []
    detection_dicts = []
    technique_ids = set()

    for i, ev in enumerate(events):
        event_dicts.append({
            "timestamp": ev.timestamp.isoformat(),
            "host": ev.host,
            "user": ev.user,
            "process": ev.process,
            "source_type": ev.source_type,
            "anomaly_score": ev.anomaly_score,
            "parsed": ev.parsed,
        })
        for d in ev.detections:
            detection_dicts.append({
                "event_index": i,
                "rule_id": d.rule_id,
                "rule_title": d.rule_title,
                "severity": d.severity,
                "mitre_attack_id": d.mitre_attack_id,
                "mitre_tactic": d.mitre_tactic,
            })
            if d.mitre_attack_id:
                technique_ids.add(d.mitre_attack_id)

    narrative_data = await generate_narrative(
        event_dicts, detection_dicts, list(technique_ids)
    )

    # Persist narrative
    async with async_session() as session:
        n = Narrative(
            ingestion_id=ingestion_id,
            source=narrative_data.get("_source", "unknown"),
            content=json.dumps(narrative_data, default=str),
        )
        session.add(n)
        await session.commit()

    return narrative_data


# ---- Train ----

@app.post("/api/train")
async def train_endpoint():
    """Train the ML model on all current events."""
    from sqlalchemy import update

    async with async_session() as session:
        result = await session.execute(
            select(Event).options(selectinload(Event.detections)).order_by(Event.timestamp)
        )
        events = result.scalars().all()

    if not events:
        raise HTTPException(status_code=400, detail="No events to train on")

    model = train_model(events)

    # Backfill scores using UPDATE statements (events are detached from session)
    scored = 0
    async with async_session() as session:
        for ev in events:
            score = score_event(ev)
            if score is not None:
                has_sigma = len(ev.detections) > 0
                if has_sigma:
                    level = "both" if is_anomaly(score) else "sigma"
                else:
                    level = "ml" if is_anomaly(score) else "none"
                await session.execute(
                    update(Event)
                    .where(Event.id == ev.id)
                    .values(anomaly_score=score, detection_level=level)
                )
                scored += 1
        await session.commit()

    return {
        "events_trained": len(events),
        "events_scored": scored,
        "estimators": model.n_estimators,
    }
