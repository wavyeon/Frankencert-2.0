#!/usr/bin/env python3
"""
tools/jsonl_to_sqlite.py

Load results/field_pool_extended.jsonl (one JSON per line) into SQLite DB:
 - data/fieldpool.db
 - tables: certs, ext_index

This version serializes dict-like fields to JSON strings before insertion
to avoid "type 'dict' is not supported" sqlite3 errors.
"""
import sqlite3
import json
import pathlib
from datetime import datetime

JSONL = pathlib.Path("results/field_pool_extended.jsonl")
DB = pathlib.Path("data/fieldpool.db")
DB.parent.mkdir(parents=True, exist_ok=True)

def ensure_schema(conn):
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS certs (
        fp TEXT PRIMARY KEY,
        file TEXT,
        source_file TEXT,
        collected_at TEXT,
        subject_human TEXT,
        issuer_human TEXT,
        serial TEXT,
        version INTEGER,
        not_before TEXT,
        not_after TEXT,
        pubkey_alg TEXT,
        pubkey_size INTEGER,
        sig_alg_json TEXT,
        subject_json TEXT,
        issuer_json TEXT,
        extensions_count INTEGER
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS ext_index (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        fp TEXT,
        ext_name TEXT,
        ext_critical INTEGER,
        ext_value_snippet TEXT,
        FOREIGN KEY(fp) REFERENCES certs(fp)
    )
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_ext_name ON ext_index(ext_name)")
    conn.commit()

def normalize_value(v):
    """Return JSON string for dict/list, plain str for others (or None)."""
    if v is None:
        return None
    if isinstance(v, (dict, list)):
        try:
            return json.dumps(v, ensure_ascii=False)
        except Exception:
            return json.dumps(str(v), ensure_ascii=False)
    # for nested objects (like asn1crypto native that may be a dict-like)
    try:
        # try json dumpable
        json.dumps(v)
        return v
    except Exception:
        try:
            return json.dumps(str(v), ensure_ascii=False)
        except Exception:
            return str(v)

def ingest():
    if not JSONL.exists():
        print("Missing", JSONL, "- run parser first")
        return

    conn = sqlite3.connect(str(DB))
    ensure_schema(conn)
    cur = conn.cursor()

    inserted = 0
    ext_inserted = 0

    with JSONL.open("r", encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception as e:
                print(f"[{line_no}] json.loads failed:", e)
                continue

            fp = obj.get("fp")
            file = obj.get("file")
            source_file = obj.get("source_file")
            collected_at = obj.get("collected_at")
            subject_human = obj.get("subject_human")
            issuer_human = obj.get("issuer_human")
            serial = obj.get("serial") or obj.get("serial_number") or obj.get("serial_number")
            version = obj.get("version")
            not_before = obj.get("not_before")
            not_after = obj.get("not_after")
            pubkey_alg = obj.get("pubkey_alg")
            pubkey_size = obj.get("pubkey_size")
            sig_alg = obj.get("sig_alg")
            subject_json = obj.get("subject")
            issuer_json = obj.get("issuer")
            extensions_count = obj.get("extensions_count")

            # normalize fields that might be dicts
            sig_alg_json = normalize_value(sig_alg)
            subject_json_s = normalize_value(subject_json)
            issuer_json_s = normalize_value(issuer_json)

            try:
                cur.execute("""
                    INSERT OR REPLACE INTO certs
                    (fp,file,source_file,collected_at,subject_human,issuer_human,serial,version,not_before,not_after,pubkey_alg,pubkey_size,sig_alg_json,subject_json,issuer_json,extensions_count)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """, (
                    fp, file, source_file, collected_at, subject_human, issuer_human, serial, version, not_before, not_after, pubkey_alg, pubkey_size, sig_alg_json, subject_json_s, issuer_json_s, extensions_count
                ))
                inserted += 1
            except Exception as e:
                print(f"[{line_no}] INSERT cert failed for fp={fp}: {e}")
                continue

            # insert extensions into ext_index (if any)
            exts = obj.get("extensions") or {}
            if isinstance(exts, dict):
                for ename, ev in exts.items():
                    # ev is expected to be dict like {"critical": bool, "value_snippet": "..."}
                    try:
                        if isinstance(ev, dict):
                            critical = 1 if ev.get("critical") else 0
                            snippet = ev.get("value_snippet")
                        else:
                            # fallback: store stringified version
                            critical = 0
                            snippet = normalize_value(ev)
                        cur.execute("""
                            INSERT INTO ext_index (fp, ext_name, ext_critical, ext_value_snippet)
                            VALUES (?,?,?,?)
                        """, (fp, ename, critical, snippet))
                        ext_inserted += 1
                    except Exception as e:
                        print(f"[{line_no}] ext insert failed fp={fp} ename={ename}: {e}")
                        continue

            # commit in batches to avoid huge transaction
            if inserted % 200 == 0:
                conn.commit()

    conn.commit()
    conn.close()
    print("Done. certs inserted:", inserted, "ext rows inserted:", ext_inserted)
    print("DB file:", DB)

def main():
    start = datetime.now().isoformat()
    print("Starting ingest at", start)
    ingest()
    print("Finished at", datetime.now().isoformat())

if __name__ == "__main__":
    main()
