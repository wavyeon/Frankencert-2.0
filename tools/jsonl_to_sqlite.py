#!/usr/bin/env python3
"""
tools/jsonl_to_sqlite.py

- Reads results/field_pool_extended.jsonl (one JSON object per line)
- Inserts structured fields into SQLite DB at data/fieldpool.db
- Also stores raw JSON in `raw` column for full fidelity.
- Builds useful indexes for fast sampling queries.

Usage:
  python3 tools/jsonl_to_sqlite.py
"""
import sqlite3
import json
import pathlib
import sys
from typing import Any

JSONL = pathlib.Path("results/field_pool_extended.jsonl")
DB = pathlib.Path("data/fieldpool.db")
UNIQUE_CERT_DIR = pathlib.Path("data/unique_certs")  # used later by sampler

if not JSONL.exists():
    print("Missing", JSONL, "- run parser to generate it first.")
    sys.exit(1)

def ensure_tables(cur: sqlite3.Cursor):
    cur.execute("""
    CREATE TABLE IF NOT EXISTS certs (
      fp TEXT PRIMARY KEY,
      file TEXT,
      subject TEXT,
      issuer TEXT,
      serial TEXT,
      version INTEGER,
      not_before TEXT,
      not_after TEXT,
      pubkey_alg TEXT,
      pubkey_size INTEGER,
      sig_alg TEXT,
      extensions_count INTEGER,
      raw JSON
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS ext_index (
      fp TEXT,
      ext_name TEXT,
      ext_value_snippet TEXT,
      PRIMARY KEY (fp, ext_name)
    )
    """)
    # Indexes for frequent queries
    cur.execute("CREATE INDEX IF NOT EXISTS idx_certs_pubkey_alg ON certs(pubkey_alg)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_certs_pubkey_size ON certs(pubkey_size)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_certs_not_before ON certs(not_before)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_ext_index_extname ON ext_index(ext_name)")
    cur.execute("PRAGMA user_version = 1")

def short_snippet(val: Any, length=200):
    try:
        s = json.dumps(val, ensure_ascii=False)
    except Exception:
        s = str(val)
    s = s.replace("\n"," ")
    return s[:length]

def main():
    print("Opening DB:", DB)
    DB.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB))
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    # Speed-oriented pragmas
    cur.execute("PRAGMA journal_mode = WAL")
    cur.execute("PRAGMA synchronous = NORMAL")
    cur.execute("PRAGMA temp_store = MEMORY")
    ensure_tables(cur)

    inserted = 0
    with open(JSONL, "r", encoding="utf-8") as fh:
        batch = []
        ext_rows = []
        for line_no, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception as e:
                print(f"Skipping line {line_no}: JSON parse error: {e}")
                continue
            fp = obj.get("file", "") .split(".")[0] if obj.get("file") else None
            file_name = obj.get("file")
            subject = json.dumps(obj.get("subject", {}), ensure_ascii=False)
            issuer = json.dumps(obj.get("issuer", {}), ensure_ascii=False)
            serial = obj.get("serial")
            version = obj.get("version")
            not_before = obj.get("not_before")
            not_after = obj.get("not_after")
            pubkey_alg = obj.get("pubkey_alg")
            pubkey_size = obj.get("pubkey_size")
            sig_alg = obj.get("sig_alg")
            exts = obj.get("extensions", {})
            ext_count = len(exts) if isinstance(exts, dict) else None
            raw = json.dumps(obj, ensure_ascii=False)
            batch.append((fp, file_name, subject, issuer, serial, version, not_before, not_after, pubkey_alg, pubkey_size, sig_alg, ext_count, raw))
            # prepare ext rows
            if isinstance(exts, dict):
                for ext_name, ext_obj in exts.items():
                    snippet = short_snippet(ext_obj.get("value") if isinstance(ext_obj, dict) and "value" in ext_obj else ext_obj)
                    ext_rows.append((fp, ext_name, snippet))
            # commit in batches
            if len(batch) >= 200:
                cur.executemany("""
                  INSERT OR REPLACE INTO certs (fp,file,subject,issuer,serial,version,not_before,not_after,pubkey_alg,pubkey_size,sig_alg,extensions_count,raw)
                  VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                """, batch)
                cur.executemany("INSERT OR REPLACE INTO ext_index (fp, ext_name, ext_value_snippet) VALUES (?,?,?)", ext_rows)
                conn.commit()
                inserted += len(batch)
                print("Inserted", inserted)
                batch = []
                ext_rows = []
        # final flush
        if batch:
            cur.executemany("""
              INSERT OR REPLACE INTO certs (fp,file,subject,issuer,serial,version,not_before,not_after,pubkey_alg,pubkey_size,sig_alg,extensions_count,raw)
              VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, batch)
            if ext_rows:
                cur.executemany("INSERT OR REPLACE INTO ext_index (fp, ext_name, ext_value_snippet) VALUES (?,?,?)", ext_rows)
            conn.commit()
            inserted += len(batch)
    print("Done. Total inserted (approx):", inserted)
    conn.close()

if __name__ == "__main__":
    main()
