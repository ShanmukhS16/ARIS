"""ARIS FastAPI application.

Endpoints:
  GET  /api/health          - Health check
  POST /api/ingest          - Upload and process log files
  GET  /api/events          - List events with filtering
  GET  /api/detections      - List Sigma detections
  GET  /api/stats           - Dashboard summary stats
  POST /api/narrative       - Generate incident narrative
  POST /api/train           - Train ML model on existing data

Dashboard endpoints:
  GET  /api/overview        - KPIs, time series, severity, top hosts/rules, ATT&CK coverage
  GET  /api/model           - Loaded model metadata and anomaly score histogram
  GET  /api/rules           - Sigma rules with hit counts
  GET  /api/ingestions      - Ingestion job history

Time ranges (`hours`) are relative to the newest event in scope, not
wall-clock time, because ingested datasets are usually historical.
"""

from __future__ import annotations

import calendar
import json
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Optional

import yaml
from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import Integer, case, cast, func, or_, select
from sqlalchemy.orm import selectinload

from app.config import settings
from app.database import async_session, engine, init_db
from app.ml.anomaly import is_anomaly, load_model, model_info, score_event, train_model
from app.models import Detection, Event, Narrative, new_ingestion_id
from app.narrative.attack_kb import get_technique
from app.narrative.generator import generate_narrative
from app.parsers.authlog import parse_authlog_file
from app.parsers.optc import is_ecar_format, parse_optc_file
from app.parsers.sysmon import parse_sysmon_file
from app.sigma_engine.engine import describe_rule, load_rules, run_rules

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
    return {
        "status": "ok",
        "version": "0.5.0",
        "model_loaded": model_info()["loaded"],
        "rules_loaded": len(load_rules()),
        "llm_enabled": bool(settings.anthropic_api_key),
    }


# ---- Query helpers ----

def _scoped(stmt, ingestion_id=None, start=None, end=None):
    """Restrict a statement that touches Event to an ingestion and time window."""
    if ingestion_id:
        stmt = stmt.where(Event.ingestion_id == ingestion_id)
    if start is not None:
        stmt = stmt.where(Event.timestamp >= start)
    if end is not None:
        stmt = stmt.where(Event.timestamp <= end)
    return stmt


async def _window(session, ingestion_id=None, hours=None):
    """Return (start, end) covering the last `hours` before the newest event."""
    q = _scoped(select(func.min(Event.timestamp), func.max(Event.timestamp)), ingestion_id)
    first, last = (await session.execute(q)).one()
    if last is None:
        return None, None
    if hours:
        first = max(first, last - timedelta(hours=hours))
    return first, last


def _epoch(col):
    """SQL expression for a timestamp column as integer Unix seconds."""
    if engine.dialect.name == "sqlite":
        return cast(func.strftime("%s", col), Integer)
    return cast(func.extract("epoch", col), Integer)


def _to_epoch(dt: datetime) -> int:
    return calendar.timegm(dt.timetuple())


def _from_epoch(s: int) -> str:
    return datetime.fromtimestamp(s, timezone.utc).replace(tzinfo=None).isoformat()


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
    q: Optional[str] = None,
    hours: Optional[float] = None,
    order: str = Query(default="asc", pattern="^(asc|desc)$"),
    include_parsed: bool = False,
    limit: int = Query(default=200, le=1000),
    offset: int = Query(default=0, ge=0),
):
    """List events with optional filtering and free-text search."""
    stmt = select(Event).options(selectinload(Event.detections))
    if order == "desc":
        stmt = stmt.order_by(Event.timestamp.desc(), Event.id.desc())
    else:
        stmt = stmt.order_by(Event.timestamp, Event.id)

    if hours:
        async with async_session() as session:
            start, end = await _window(session, ingestion_id, hours)
        stmt = _scoped(stmt, start=start, end=end)
    if ingestion_id:
        stmt = stmt.where(Event.ingestion_id == ingestion_id)
    if q:
        pattern = f"%{q}%"
        stmt = stmt.where(or_(
            Event.process.ilike(pattern),
            Event.host.ilike(pattern),
            Event.user.ilike(pattern),
        ))
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
                **({"parsed": ev.parsed} if include_parsed else {}),
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


# ---- Dashboard ----

TIMESERIES_BUCKETS = 48
LEVELS = ("none", "sigma", "ml", "both")


async def _level_counts(session, ingestion_id, start, end) -> dict[str, int]:
    q = _scoped(
        select(Event.detection_level, func.count()).group_by(Event.detection_level),
        ingestion_id, start, end,
    )
    counts = {lvl: 0 for lvl in LEVELS}
    for lvl, n in (await session.execute(q)).all():
        counts[lvl] = n
    return counts


@app.get("/api/overview")
async def overview(ingestion_id: Optional[str] = None, hours: Optional[float] = None):
    """Everything the Overview page needs in one round trip."""
    async with async_session() as session:
        start, end = await _window(session, ingestion_id, hours)
        if end is None:
            return {"empty": True}

        levels = await _level_counts(session, ingestion_id, start, end)
        total = sum(levels.values())
        detected = total - levels["none"]

        # Previous period of equal length, for trend arrows
        previous = None
        if hours:
            prev = await _level_counts(session, ingestion_id, start - timedelta(hours=hours), start)
            prev_total = sum(prev.values())
            previous = {"total_events": prev_total, "detected_events": prev_total - prev["none"]}

        hosts = await session.scalar(_scoped(
            select(func.count(func.distinct(Event.host))), ingestion_id, start, end))
        hosts_detected = await session.scalar(_scoped(
            select(func.count(func.distinct(Event.host))).where(Event.detection_level != "none"),
            ingestion_id, start, end))

        # Time series of events per bucket, split by detection level
        start_s, end_s = _to_epoch(start), _to_epoch(end)
        width = max(1, -(-(end_s - start_s + 1) // TIMESERIES_BUCKETS))
        n_buckets = (end_s - start_s) // width + 1
        bucket = cast((_epoch(Event.timestamp) - start_s) / width, Integer)
        ts_rows = (await session.execute(_scoped(
            select(bucket, Event.detection_level, func.count()).group_by(bucket, Event.detection_level),
            ingestion_id, start, end,
        ))).all()
        series = [
            {"t": _from_epoch(start_s + i * width), **{lvl: 0 for lvl in LEVELS}}
            for i in range(n_buckets)
        ]
        for b, lvl, n in ts_rows:
            if b is not None and 0 <= b < n_buckets:
                series[b][lvl] += n

        severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for sev, n in (await session.execute(_scoped(
            select(Detection.severity, func.count()).join(Event).group_by(Detection.severity),
            ingestion_id, start, end,
        ))).all():
            severity[sev] = severity.get(sev, 0) + n

        top_hosts = [
            {"host": h, "count": n, "max_score": s}
            for h, n, s in (await session.execute(_scoped(
                select(Event.host, func.count(), func.max(Event.anomaly_score))
                .where(Event.detection_level != "none")
                .group_by(Event.host)
                .order_by(func.count().desc())
                .limit(8),
                ingestion_id, start, end,
            ))).all()
        ]

        rule_hits = {
            rid: n for rid, n in (await session.execute(_scoped(
                select(Detection.rule_id, func.count()).join(Event).group_by(Detection.rule_id),
                ingestion_id, start, end,
            ))).all()
        }

        recent = (await session.execute(_scoped(
            select(Detection, Event)
            .join(Event)
            .order_by(Event.timestamp.desc(), Detection.id.desc())
            .limit(12),
            ingestion_id, start, end,
        ))).all()

    rules = [describe_rule(r) for r in load_rules()]
    top_rules = sorted(
        ({**r, "count": rule_hits.get(r["rule_id"], 0)} for r in rules),
        key=lambda r: r["count"], reverse=True,
    )

    # ATT&CK coverage: every technique our rules cover, with hit counts
    attack = {}
    for r in top_rules:
        tid = r["technique"]
        if not tid:
            continue
        cell = attack.setdefault(tid, {
            "technique": tid,
            "name": (get_technique(tid) or {}).get("name", r["title"]),
            "tactic": r["tactic"],
            "count": 0,
        })
        cell["count"] += r["count"]

    return {
        "empty": False,
        "window": {"start": start.isoformat(), "end": end.isoformat(), "bucket_seconds": width},
        "kpis": {
            "total_events": total,
            "detected_events": detected,
            "sigma_events": levels["sigma"] + levels["both"],
            "ml_events": levels["ml"] + levels["both"],
            "both_events": levels["both"],
            "hosts": hosts or 0,
            "hosts_detected": hosts_detected or 0,
            "detections": sum(severity.values()),
            "critical": severity.get("critical", 0),
        },
        "previous": previous,
        "timeseries": series,
        "severity": severity,
        "top_hosts": top_hosts,
        "top_rules": top_rules,
        "attack_matrix": list(attack.values()),
        "recent_alerts": [
            {
                "id": d.id,
                "rule_id": d.rule_id,
                "rule_title": d.rule_title,
                "severity": d.severity,
                "technique": d.mitre_attack_id,
                "host": ev.host,
                "user": ev.user,
                "timestamp": ev.timestamp.isoformat(),
            }
            for d, ev in recent
        ],
    }


@app.get("/api/model")
async def model_endpoint(ingestion_id: Optional[str] = None, hours: Optional[float] = None):
    """Model metadata plus a histogram of anomaly scores in scope."""
    info = model_info()
    bins = 20
    histogram = [
        {"lo": i / bins, "hi": (i + 1) / bins, **{lvl: 0 for lvl in LEVELS}}
        for i in range(bins)
    ]
    async with async_session() as session:
        start, end = await _window(session, ingestion_id, hours)
        if end is not None:
            b = cast(Event.anomaly_score * bins, Integer)
            rows = (await session.execute(_scoped(
                select(b, Event.detection_level, func.count())
                .where(Event.anomaly_score.isnot(None))
                .group_by(b, Event.detection_level),
                ingestion_id, start, end,
            ))).all()
            for i, lvl, n in rows:
                histogram[min(max(i, 0), bins - 1)][lvl] += n

    scored = sum(sum(h[lvl] for lvl in LEVELS) for h in histogram)
    above = sum(
        sum(h[lvl] for lvl in LEVELS) for h in histogram if h["lo"] >= info["threshold"]
    )
    return {**info, "histogram": histogram, "scored_events": scored, "above_threshold": above}


@app.get("/api/rules")
async def rules_endpoint(ingestion_id: Optional[str] = None, hours: Optional[float] = None):
    """Loaded Sigma rules with hit counts and their YAML source."""
    hits = {}
    async with async_session() as session:
        start, end = await _window(session, ingestion_id, hours)
        if end is not None:
            rows = (await session.execute(_scoped(
                select(Detection.rule_id, func.count(), func.max(Event.timestamp))
                .join(Event)
                .group_by(Detection.rule_id),
                ingestion_id, start, end,
            ))).all()
            hits = {rid: (n, last) for rid, n, last in rows}

    result = []
    for rule in load_rules():
        meta = describe_rule(rule)
        n, last = hits.get(meta["rule_id"], (0, None))
        result.append({
            **meta,
            "hits": n,
            "last_fired": last.isoformat() if last else None,
            "yaml": yaml.safe_dump(rule, sort_keys=False, allow_unicode=True),
        })
    return result


@app.get("/api/ingestions")
async def ingestions(limit: int = Query(default=50, le=500)):
    """Ingestion job history, newest first."""
    detected = func.sum(case((Event.detection_level != "none", 1), else_=0))
    stmt = (
        select(
            Event.ingestion_id,
            func.count(),
            detected,
            func.min(Event.timestamp),
            func.max(Event.timestamp),
            func.max(Event.source_type),
            func.count(func.distinct(Event.host)),
        )
        .group_by(Event.ingestion_id)
        .order_by(func.min(Event.id).desc())
        .limit(limit)
    )
    async with async_session() as session:
        rows = (await session.execute(stmt)).all()
    return [
        {
            "ingestion_id": iid,
            "events": n,
            "detected": int(det or 0),
            "first_event": first.isoformat() if first else None,
            "last_event": last.isoformat() if last else None,
            "source_type": src,
            "hosts": hosts,
        }
        for iid, n, det, first, last, src, hosts in rows
    ]


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
