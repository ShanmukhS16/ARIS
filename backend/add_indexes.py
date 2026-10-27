import sqlite3, time, sys, glob

# Find the database file
dbs = glob.glob("*.db")
if not dbs:
    print("No .db file found in current directory. Pass the path as an argument.")
    print("Usage: python add_indexes.py [path/to/database.db]")
    sys.exit(1)

db_path = sys.argv[1] if len(sys.argv) > 1 else dbs[0]
print(f"Using database: {db_path}")

db = sqlite3.connect(db_path)

indexes = [
    "CREATE INDEX IF NOT EXISTS ix_events_ing_ts ON events(ingestion_id, timestamp)",
    "CREATE INDEX IF NOT EXISTS ix_events_det_host ON events(detection_level, host)",
    "CREATE INDEX IF NOT EXISTS ix_events_ts_det ON events(timestamp, detection_level)",
    "CREATE INDEX IF NOT EXISTS ix_detections_rule ON detections(rule_id)",
    "CREATE INDEX IF NOT EXISTS ix_detections_sev ON detections(severity)",
]

for sql in indexes:
    name = sql.split("ix_")[1].split(" ")[0]
    print(f"Creating index: {name} ...")
    t = time.time()
    db.execute(sql)
    db.commit()
    print(f"  done in {time.time() - t:.1f}s")

print("All indexes created.")
db.close()
