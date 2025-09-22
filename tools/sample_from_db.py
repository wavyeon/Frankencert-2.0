#!/usr/bin/env python3
"""
tools/sample_from_db.py

Usage examples:
  python3 tools/sample_from_db.py --limit 200 --where "pubkey_alg LIKE '%rsa%' AND pubkey_size >= 2048"
  python3 tools/sample_from_db.py --limit 500

This will copy the PEM files from data/unique_certs into data/samples/.
"""
import argparse, sqlite3, pathlib, shutil, json

DB = pathlib.Path("data/fieldpool.db")
SRC_DIR = pathlib.Path("data/unique_certs")
OUT = pathlib.Path("data/samples")
OUT.mkdir(parents=True, exist_ok=True)

def run(where_clause, limit):
    conn = sqlite3.connect(str(DB))
    cur = conn.cursor()
    q = f"SELECT file, raw FROM certs WHERE {where_clause} LIMIT {limit}" if where_clause else f"SELECT file, raw FROM certs LIMIT {limit}"
    rows = cur.execute(q).fetchall()
    copied = 0
    for file_name, raw in rows:
        src = SRC_DIR / file_name
        if not src.exists():
            # try find by fp
            try:
                obj = json.loads(raw)
                fname = obj.get("file")
                if fname:
                    src = SRC_DIR / fname
            except Exception:
                pass
        if src.exists():
            dst = OUT / src.name
            if not dst.exists():
                shutil.copy2(src, dst)
                copied += 1
    print("Copied", copied, "files to", OUT)
    conn.close()

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--where", default="", help="SQL WHERE clause (without 'WHERE')")
    p.add_argument("--limit", type=int, default=200, help="how many to sample")
    args = p.parse_args()
    run(args.where, args.limit)
