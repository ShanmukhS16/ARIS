#!/usr/bin/env python3
"""Bulk ingest a generated dataset into ARIS DB and train the ML model.

Reads directly from the dataset directory (no HTTP overhead), runs
Sigma rules and ML scoring inline, then trains/backfills IsolationForest.

Usage:
    cd backend

    # Ingest everything
    python -m scripts.bulk_ingest --dataset-dir ./dataset

    # Ingest only eCAR format
    python -m scripts.bulk_ingest --dataset-dir ./dataset --format ecar

    # Ingest a date range
    python -m scripts.bulk_ingest --dataset-dir ./dataset --start 2024-01-01 --end 2024-01-31

    # Ingest + train ML in one go
    python -m scripts.bulk_ingest --dataset-dir ./dataset --train

    # Limit events per file (for quick testing)
    python -m scripts.bulk_ingest --dataset-dir ./dataset --max-per-file 5000 --train
"""

from __future__ import annotations

import argparse
import asyncio
import gzip
import json
import sys
import time
from datetime import datetime
from pathlib import Path

from sqlalchemy import select, update, func

from app.database import init_db, async_session
from app.models import Event, Detection, new_ingestion_id
from app.parsers.sysmon import parse_sysmon_file
from app.parsers.authlog import parse_authlog_file
from app.parsers.optc import parse_optc_file
from app.sigma_engine.engine import run_rules
from app.ml.anomaly import score_event, is_anomaly, train_model, load_model


def parse_args():
    ap = argparse.ArgumentParser(description="Bulk ingest dataset into ARIS")
    ap.add_argument("--dataset-dir", required=True, help="Path to generated dataset")
    ap.add_argument("--format", choices=["ecar", "sysmon", "authlog", "all"], default="all",
                    help="Which format(s) to ingest")
    ap.add_argument("--start", type=str, default=None, help="Start date YYYY-MM-DD (inclusive)")
    ap.add_argument("--end", type=str, default=None, help="End date YYYY-MM-DD (inclusive)")
    ap.add_argument("--max-per-file", type=int, default=None,
                    help="Max events per file (for quick testing)")
    ap.add_argument("--train", action="store_true", help="Train ML model after ingestion")
    ap.add_argument("--batch-size", type=int, default=1000, help="DB commit batch size")
    return ap.parse_args()


def collect_files(dataset_dir, fmt, start_date, end_date):
    """Collect all gz files matching format and date range."""
    base = Path(dataset_dir)
    formats = ["ecar", "sysmon", "authlog"] if fmt == "all" else [fmt]
    files = []

    for f in formats:
        subdir = base / f
        if not subdir.exists():
            print(f"  Warning: {subdir} does not exist, skipping")
            continue

        for gz in sorted(subdir.glob("*.gz")):
            # Extract date from filename (YYYY-MM-DD.ext.gz)
            date_str = gz.stem.split(".")[0]  # "2024-01-15"
            try:
                file_date = datetime.strptime(date_str, "%Y-%m-%d")
            except ValueError:
                # Fallback: just include it
                files.append((f, gz))
                continue

            if start_date and file_date < datetime.strptime(start_date, "%Y-%m-%d"):
                continue
            if end_date and file_date > datetime.strptime(end_date, "%Y-%m-%d"):
                continue

            files.append((f, gz))

    return files


def parse_file(fmt, gz_path, max_events=None):
    """Read a gzipped file and parse into Event objects."""
    with gzip.open(str(gz_path), "rt", encoding="utf-8") as fh:
        content = fh.read()

    if fmt == "ecar":
        events = list(parse_optc_file(content))
    elif fmt == "sysmon":
        events = list(parse_sysmon_file(content))
    elif fmt == "authlog":
        events = list(parse_authlog_file(content))
    else:
        return []

    if max_events:
        events = events[:max_events]

    return events


async def ingest_events(events, ingestion_id, batch_size=1000):
    """Run Sigma + ML on events and commit to DB in batches."""
    total_sigma = 0
    total_ml = 0

    async with async_session() as session:
        for i, ev in enumerate(events):
            ev.ingestion_id = ingestion_id

            # Sigma
            dets = run_rules(ev)
            for d in dets:
                ev.detections.append(d)
            total_sigma += len(dets)

            # ML scoring (if model loaded)
            score = score_event(ev)
            if score is not None:
                ev.anomaly_score = score
                if is_anomaly(score):
                    total_ml += 1

            # Detection level
            has_sigma = len(dets) > 0
            has_ml = is_anomaly(ev.anomaly_score)
            if has_sigma and has_ml:
                ev.detection_level = "both"
            elif has_sigma:
                ev.detection_level = "sigma"
            elif has_ml:
                ev.detection_level = "ml"
            else:
                ev.detection_level = "none"

            session.add(ev)

            # Batch commit
            if (i + 1) % batch_size == 0:
                await session.commit()

        await session.commit()

    return total_sigma, total_ml


async def train_ml():
    """Train IsolationForest on all events in DB and backfill scores."""
    print("\nTraining IsolationForest...")
    async with async_session() as session:
        result = await session.execute(
            select(Event).options(
                __import__("sqlalchemy.orm", fromlist=["selectinload"]).selectinload(Event.detections)
            ).order_by(Event.timestamp)
        )
        events = result.scalars().all()

    if not events:
        print("  No events in DB, nothing to train on.")
        return

    print(f"  Training on {len(events):,} events...")
    model = train_model(events)
    print(f"  Model trained (estimators={model.n_estimators}, features=256)")

    # Backfill scores
    print("  Backfilling scores...")
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

            if scored % 5000 == 0 and scored > 0:
                await session.commit()
                print(f"\r    Scored {scored:,}/{len(events):,}", end="", flush=True)

        await session.commit()

    # Stats
    anomalies = sum(1 for ev in events if is_anomaly(score_event(ev)))
    print(f"\r    Scored {scored:,} events, {anomalies:,} anomalies")


async def print_summary():
    """Print DB stats after ingestion."""
    async with async_session() as session:
        total = await session.scalar(select(func.count()).select_from(Event))
        sigma = await session.scalar(
            select(func.count()).select_from(Event).where(Event.detection_level.in_(["sigma", "both"]))
        )
        ml = await session.scalar(
            select(func.count()).select_from(Event).where(Event.detection_level.in_(["ml", "both"]))
        )
        both = await session.scalar(
            select(func.count()).select_from(Event).where(Event.detection_level == "both")
        )
        hosts = await session.scalar(
            select(func.count(func.distinct(Event.host))).select_from(Event)
        )
        det_count = await session.scalar(select(func.count()).select_from(Detection))

    print(f"\n--- DB Summary ---")
    print(f"  Total events:    {total:,}")
    print(f"  Unique hosts:    {hosts:,}")
    print(f"  Sigma detections:{det_count:,}")
    print(f"  Sigma flagged:   {sigma:,}")
    print(f"  ML flagged:      {ml:,}")
    print(f"  Both:            {both:,}")


async def main():
    args = parse_args()

    # Init DB
    await init_db()
    load_model()  # Load existing model if available

    # Collect files
    files = collect_files(args.dataset_dir, args.format, args.start, args.end)
    if not files:
        print("No files found matching filters.")
        sys.exit(1)

    print(f"ARIS Bulk Ingestion")
    print(f"  Dataset: {args.dataset_dir}")
    print(f"  Files: {len(files)}")
    if args.start or args.end:
        print(f"  Date filter: {args.start or 'start'} to {args.end or 'end'}")
    if args.max_per_file:
        print(f"  Max per file: {args.max_per_file:,}")
    print()

    total_events = 0
    total_sigma = 0
    total_ml = 0
    t0 = time.time()

    for i, (fmt, gz_path) in enumerate(files):
        ingestion_id = new_ingestion_id()
        fname = gz_path.name

        # Parse
        events = parse_file(fmt, gz_path, args.max_per_file)
        if not events:
            continue

        # Ingest
        sigma, ml = await ingest_events(events, ingestion_id, args.batch_size)
        total_events += len(events)
        total_sigma += sigma
        total_ml += ml

        elapsed = time.time() - t0
        rate = total_events / elapsed if elapsed > 0 else 0
        pct = (i + 1) / len(files) * 100
        tag = f" [{sigma}S {ml}M]" if (sigma or ml) else ""
        print(f"\r  [{pct:5.1f}%] {fmt:7s} {fname:30s} {len(events):>7,} events{tag}  "
              f"[total: {total_events:,}, {rate:,.0f}/s]", end="", flush=True)

        if sigma or ml:
            print()  # Newline for files with detections

    elapsed = time.time() - t0
    print(f"\n\nIngestion done in {elapsed:.0f}s")
    print(f"  Events: {total_events:,}")
    print(f"  Sigma hits: {total_sigma:,}")
    print(f"  ML anomalies: {total_ml:,}")

    # Train if requested
    if args.train:
        await train_ml()

    await print_summary()

    print(f"\nNext steps:")
    print(f"  1. Start the server:  uvicorn app.main:app --reload")
    print(f"  2. Open dashboard:    http://localhost:3000")
    print(f"  3. Or run evaluation: python -m scripts.evaluate_optc --data-dir {args.dataset_dir}/ecar")


if __name__ == "__main__":
    asyncio.run(main())
