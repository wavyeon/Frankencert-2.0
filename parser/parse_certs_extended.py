#!/usr/bin/env python3
"""
parser/parse_certs_extended.py

Robust parser: reads data/unique_certs/*.pem (or data/raw_certs if you prefer),
extracts extended metadata and writes results/field_pool_extended.jsonl line-by-line.

Key improvements:
- safe parsing of version (handles int or strings like 'v3')
- per-file try/except so one bad cert doesn't stop the whole run
- immediate write/flush for each record (resilient)
- more informative logging
"""
import pathlib, json, base64, re, sys, traceback
from asn1crypto import pem, x509

IN_DIR = pathlib.Path("data/unique_certs_extracted")
OUT_FILE = pathlib.Path("results/field_pool_extended.jsonl")
OUT_FILE.parent.mkdir(parents=True, exist_ok=True)

def to_iso(dt):
    try:
        return dt.isoformat()
    except Exception:
        return str(dt)

def safe_native(obj):
    try:
        if hasattr(obj, "native"):
            native = obj.native
        else:
            native = obj
        if isinstance(native, (bytes, bytearray)):
            return base64.b64encode(bytes(native)).decode("ascii")
        if isinstance(native, (list, tuple)):
            return [safe_native(x) for x in native]
        if isinstance(native, dict):
            return {str(k): safe_native(v) for k, v in native.items()}
        return native
    except Exception:
        try:
            return str(obj)
        except Exception:
            return None

def parse_version_field(v):
    """
    Accept various forms:
     - integer -> return int
     - string like "v3" or "V3" -> extract digits -> int
     - other -> None
    """
    if v is None:
        return None
    if isinstance(v, int):
        return v
    # asn1crypto sometimes exposes object with .native being 'v3' or similar
    try:
        if isinstance(v, str):
            m = re.search(r'(\d+)', v)
            if m:
                return int(m.group(1))
            # maybe it's a stringified int
            try:
                return int(v)
            except Exception:
                return None
        # fallback: if it's an object that has .native attribute
        if hasattr(v, "native"):
            return parse_version_field(v.native)
    except Exception:
        return None
    return None

def extract_meta_from_der(der_bytes):
    cert = x509.Certificate.load(der_bytes)
    tbs = cert["tbs_certificate"]
    meta = {}

    # version
    try:
        ver_field = tbs.get("version")
        ver_native = ver_field.native if getattr(ver_field, "native", None) is not None else ver_field
        meta["version"] = parse_version_field(ver_native)
    except Exception:
        meta["version"] = None

    # serial
    try:
        meta["serial"] = str(tbs["serial_number"].native)
    except Exception:
        meta["serial"] = None

    # subject / issuer (human-friendly)
    try:
        meta["subject_human"] = tbs["subject"].human_friendly
    except Exception:
        meta["subject_human"] = None
    try:
        meta["issuer_human"] = tbs["issuer"].human_friendly
    except Exception:
        meta["issuer_human"] = None

    # validity
    try:
        nb = tbs["validity"]["not_before"].native
        na = tbs["validity"]["not_after"].native
        meta["not_before"] = to_iso(nb)
        meta["not_after"] = to_iso(na)
    except Exception:
        meta["not_before"] = None
        meta["not_after"] = None

    # subject public key info
    try:
        spki = tbs["subject_public_key_info"]
        try:
            meta["pubkey_alg"] = spki["algorithm"]["algorithm"].native
        except Exception:
            meta["pubkey_alg"] = str(spki["algorithm"]["algorithm"])
        # try to infer RSA modulus bit length if possible
        try:
            pk = spki["public_key"].parsed
            if hasattr(pk, "native") and isinstance(pk.native, dict) and "modulus" in pk.native:
                mod = pk.native.get("modulus")
                if isinstance(mod, int):
                    meta["pubkey_size"] = mod.bit_length()
                else:
                    meta["pubkey_size"] = None
            else:
                meta["pubkey_size"] = None
        except Exception:
            meta["pubkey_size"] = None
    except Exception:
        meta["pubkey_alg"] = None
        meta["pubkey_size"] = None

    # signature algorithm
    try:
        sig = cert["signature_algorithm"]
        meta["sig_alg"] = safe_native(sig.native if hasattr(sig, "native") else str(sig))
    except Exception:
        meta["sig_alg"] = None

    # extensions: name -> {critical, value_snippet}
    exts = {}
    try:
        for e in tbs["extensions"]:
            try:
                key = e["extn_id"].native if isinstance(e["extn_id"].native, str) else e["extn_id"].dotted
            except Exception:
                key = e["extn_id"].dotted
            critical = bool(e["critical"].native) if e["critical"] is not None else False
            try:
                parsed = e["extn_value"].parsed
                val = safe_native(parsed)
            except Exception:
                try:
                    val = safe_native(e["extn_value"].native)
                except Exception:
                    val = str(e["extn_value"])
            # produce small snippet
            try:
                js = json.dumps(val, ensure_ascii=False)
                snippet = js if len(js) <= 300 else js[:300] + "..."
            except Exception:
                snippet = str(val)[:300]
            exts[key] = {"critical": critical, "value_snippet": snippet}
    except Exception:
        pass
    meta["extensions"] = exts
    meta["extensions_count"] = len(exts) if isinstance(exts, dict) else None

    # human-friendly subject/issuer as dict (optional)
    try:
        meta["subject"] = safe_native(tbs["subject"].native)
    except Exception:
        meta["subject"] = None
    try:
        meta["issuer"] = safe_native(tbs["issuer"].native)
    except Exception:
        meta["issuer"] = None

    return meta

def main():
    files = sorted(list(IN_DIR.glob("*.pem")))
    if not files:
        print("No certs found in", IN_DIR)
        return

    written = 0
    with OUT_FILE.open("w", encoding="utf-8") as out_f:
        for p in files:
            try:
                b = p.read_bytes()
            except Exception as e:
                print("skip", p.name, "read error:", e)
                continue
            try:
                if pem.detect(b):
                    _type, _headers, der = pem.unarmor(b)
                else:
                    der = b
            except Exception as e:
                print("skip", p.name, "unarmor error:", e)
                continue

            try:
                meta = extract_meta_from_der(der)
            except Exception as e:
                # print stack for diagnosis but continue
                print("skip", p.name, "meta extraction error:", str(e))
                traceback.print_exc()
                continue

            # bookkeeping
            from datetime import datetime, timezone
            import hashlib
            fp = hashlib.sha256(der).hexdigest()
            rec = {
                "fp": fp,
                "file": f"{fp}.pem",
                "source_file": p.name,
                "collected_at": datetime.now(timezone.utc).isoformat(),
            }
            rec.update(meta)
            # write line
            out_f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            out_f.flush()
            written += 1

    print("wrote", OUT_FILE, "records:", written)

if __name__ == "__main__":
    main()
