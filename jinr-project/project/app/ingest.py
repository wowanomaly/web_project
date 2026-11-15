import gzip, shutil, httpx, hashlib, os
from sqlalchemy import delete
from .config import LOG_URL, LOG_LOCAL
from .db import SessionLocal
from .models import Hit
from .parser import parse_file
from .detection import classify
from .geoip import lookup
from pathlib import Path


def download_log() -> str:
    os.makedirs(os.path.dirname(LOG_LOCAL), exist_ok=True)
    gz_path = LOG_LOCAL + ".gz"
    with httpx.stream("GET", LOG_URL, timeout=60.0, follow_redirects=True) as r:
        r.raise_for_status()
        with open(gz_path, "wb") as f:
            for chunk in r.iter_bytes():
                f.write(chunk)
    # If it's actually gzip, decompress; otherwise it's already plain text
    try:
        with gzip.open(gz_path, "rb") as src, open(LOG_LOCAL, "wb") as dst:
            shutil.copyfileobj(src, dst)
    except OSError:
        os.replace(gz_path, LOG_LOCAL)
    return LOG_LOCAL


def file_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def ingest(force: bool = False) -> dict:
    path = download_log()
    digest = file_sha256(path)
    hash_path = Path(LOG_LOCAL).parent / "log_hash.txt"  # /app/data/log_hash.txt
    db = SessionLocal()
    try:
        # Skip only if BOTH: hash matches AND db actually has rows.
        if not force:
            rows = db.query(Hit).count()
            if rows > 0 and hash_path.is_file():
                try:
                    if hash_path.read_text(encoding="utf-8").strip() == digest:
                        return {"log_sha256": digest, "rows_inserted": 0}
                except OSError:
                    pass

        db.execute(delete(Hit))
        db.commit()

        inserted = 0
        batch = []
        for rec in parse_file(path):
            is_atk, kind = classify(rec)
            rec["is_attacker"] = is_atk
            rec["attack_kind"] = kind

            if is_atk:
                # only do geo lookups for attackers — saves time
                rec["country"], rec["city"] = lookup(rec["ip"])
            else:
                rec["country"] = None
                rec["city"] = None

            batch.append(Hit(**rec))
            if len(batch) >= 1000:
                db.bulk_save_objects(batch)
                db.commit()
                inserted += len(batch)
                batch.clear()

        if batch:
            db.bulk_save_objects(batch)
            db.commit()
            inserted += len(batch)

        # Write hash ONLY after successful ingestion.
        hash_path.write_text(digest, encoding="utf-8")
        return {"log_sha256": digest, "rows_inserted": inserted}
    finally:
        db.close()
