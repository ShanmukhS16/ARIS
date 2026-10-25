"""CLI: Train IsolationForest on existing events and backfill anomaly scores.

Usage:
    cd backend
    python -m app.ml.train
"""

from __future__ import annotations

import asyncio
import sys
import time

from sqlalchemy import select, update

from app.database import init_db, async_session
from app.models import Event # type: ignore
from app.ml.anomaly import train_model, score_event


async def main():
    await init_db()

    async with async_session() as session:
        result = await session.execute(select(Event).order_by(Event.timestamp))
        events = result.scalars().all()

    if not events:
        print("No events in the database. Ingest data first.")
        sys.exit(1)

    total = len(events)
    print(f"Training IsolationForest on {total:,} events...")
    model = train_model(events)
    print(f"Model trained. Estimators: {model.n_estimators}, Features: 19")

    print("Backfilling anomaly scores...")
    scored = 0
    t0 = time.time()

    async with async_session() as session:
        for ev in events:
            score = score_event(ev)
            if score is not None:
                await session.execute(
                    update(Event).where(Event.id == ev.id).values(anomaly_score=score)
                )
                scored += 1

            if scored % 5000 == 0 and scored > 0:
                await session.commit()
                elapsed = time.time() - t0
                rate = scored / elapsed
                eta = (total - scored) / rate if rate > 0 else 0
                pct = scored / total * 100
                print(f"\r  [{pct:5.1f}%] {scored:,}/{total:,} scored ({rate:,.0f}/s, ETA {eta:.0f}s)", end="", flush=True)

        await session.commit()

    elapsed = time.time() - t0
    print(f"\r  [100.0%] {scored:,}/{total:,} scored in {elapsed:.0f}s")

    # Summary
    scores = [score_event(ev) for ev in events[:1000]]  # sample
    scores = [s for s in scores if s is not None]
    if scores:
        print(f"Score range: {min(scores):.4f} - {max(scores):.4f}")
        print(f"Mean: {sum(scores)/len(scores):.4f}")
        anomalies = [s for s in scores if s >= 0.5]
        print(f"Anomalies (>= 0.5) in sample: {len(anomalies)}/{len(scores)}")


if __name__ == "__main__":
    asyncio.run(main())
