#!/usr/bin/env python3
"""
collector/dedupe_and_meta.py

- Deduplicate certificates in data/raw_certs/ by SHA256(DER) fingerprint.
- Writes unique PEM files to data/unique_certs/{fp}.pem (original content preserved).
- Emits data/unique_meta.jsonl: one JSON object per unique cert with useful metadata.

Usage:
  python3 collector/dedupe_and_meta.py

Dependencies:
  pip install asn1crypto tqdm
"""
import pathlib
import hashlib
import json
import base64
import sys
from datetime import datetime

try:
    from asn1crypto import pem, x509
except Exception as e:
    print("Missing dependency 'asn1crypto'. Install with: pip install asn1crypto")
    raise

try:
    from tqdm import tqdm
except Exception:
    # fallback dummy progress
    def tqdm(it, **kwargs):
        return it

ROOT = pathlib.Path(".")
IN_DIR = ROOT / "data" / "raw_certs"
OUT_DIR = ROOT / "data" / "unique_certs"
OUT_META = ROOT / "data" / "unique_meta.jsonl"

OUT_DIR.mkdir(parents=True, exist_ok=True)
OUT_META.parent.mkdir(parents=True, exist_ok=True)

def to_iso(dt):
    if dt is None:
        return None
    # asn1crypto returns datetime/date or strings; try to normalize
    try:
        return dt.isoformat()
    except Exception:
        return str(dt)

def b64_if_bytes(v):
    if isinstance(v, (bytes, bytearray)):
        return base64.b64encode(bytes(v)).decode("ascii")
    return v

def safe_native(obj):
    """
    Try to return a JSON-serializable representation of asn1crypto parsed/native object.
    For bytes -> base64, otherwise try native, then str fallback.
    """
    try:
        # many asn1crypto objects implement .native
        if hasattr(obj, "native"):
            native = obj.native
        else:
            native = obj
        # convert bytes inside structures
        if isinstance(native, (bytes, bytearray)):
            return base64.b64encode(bytes(native)).decode("ascii")
        if isinstance(native, (list, tuple)):
            return [safe_native(x) for x in native]
        if isinstance(native, dict):
            return {str(k): safe_native(v) for k, v in native.items()}
        # primitive types (str, int, bool, None, float)
        return native
    except Exception:
        # fallback to string representation
        try:
            return str(obj)
        except Exception:
            return None

def extract_meta_from_der(der_bytes):
    """
    Parse DER bytes with asn1crypto.x509.Certificate and extract metadata dict.
    """
    meta = {}
    cert = x509.Certificate.load(der_bytes)
    tbs = cert["tbs_certificate"]

    # basic fields
    try:
        meta["subject_human"] = tbs["subject"].human_friendly
    except Exception:
        meta["subject_human"] = None
    try:
        meta["issuer_human"] = tbs["issuer"].human_friendly
    except Exception:
        meta["issuer_human"] = None
    try:
        meta["serial_number"] = str(tbs["serial_number"].native)
    except Exception:
        meta["serial_number"] = None

    # version
    try:
        meta["version"] = int(tbs["version"].native) if tbs["version"] is not None else None
    except Exception:
        meta["version"] = None

    # validity
    try:
        nb = tbs["validity"]["not_before"].native
        na = tbs["validity"]["not_after"].native
        meta["not_before"] = to_iso(nb)
        meta["not_after"] = to_iso(na)
    except Exception:
        meta["not_before"] = None
        meta["not_after"] = None

    # public key info (algorithm + approximate keysize)
    try:
        spki = tbs["subject_public_key_info"]
        # algorithm name
        try:
            meta["pubkey_alg"] = spki["algorithm"]["algorithm"].native
        except Exception:
            meta["pubkey_alg"] = str(spki["algorithm"]["algorithm"])
        # try to infer size for RSA/EC
        try:
            pk = spki["public_key"].parsed
            # for RSA, parsed.native often contains 'modulus'
            if hasattr(pk, "native") and isinstance(pk.native, dict) and "modulus" in pk.native:
                mod = pk.native.get("modulus")
                if isinstance(mod, int):
                    meta["pubkey_size"] = mod.bit_length()
                else:
                    meta["pubkey_size"] = None
            else:
                # EC keys - try to infer curve name
                n = pk.__class__.__name__ if pk is not None else None
                meta["pubkey_parsed_type"] = n
                meta["pubkey_size"] = None
        except Exception:
            meta["pubkey_size"] = None
    except Exception:
        meta["pubkey_alg"] = None
        meta["pubkey_size"] = None

    # signature algorithm
    try:
        meta["sig_alg"] = cert["signature_algorithm"].native
    except Exception:
        try:
            meta["sig_alg"] = str(cert["signature_algorithm"])
        except Exception:
            meta["sig_alg"] = None

    # extensions: store ext name, critical, and a small snippet of native value
    exts = {}
    try:
        for e in tbs["extensions"]:
            try:
                # extn_id.native might be a string or name; fallback to dotted OID
                key = e["extn_id"].native if isinstance(e["extn_id"].native, str) else e["extn_id"].dotted
            except Exception:
                key = e["extn_id"].dotted
            critical = bool(e["critical"].native) if e["critical"] is not None else False
            try:
                parsed = e["extn_value"].parsed
                val = safe_native(parsed)
            except Exception:
                # if parsing fails, store raw bytes (base64)
                try:
                    raw = e["extn_value"].native
                    val = safe_native(raw)
                except Exception:
                    val = None
            # For space, produce a short snippet for quick indexing
            snippet = None
            try:
                js = json.dumps(val, ensure_ascii=False)
                snippet = js if len(js) <= 300 else js[:300] + "..."
            except Exception:
                try:
                    snippet = str(val)[:300]
                except Exception:
                    snippet = None
            exts[key] = {"critical": critical, "value_snippet": snippet}
    except Exception:
        pass
    meta["extensions"] = exts
    meta["extensions_count"] = len(exts) if isinstance(exts, dict) else None

    return meta

def main():
    in_files = sorted(list(IN_DIR.glob("*.pem")))
    if not in_files:
        print("No PEM files found in", IN_DIR)
        return

    seen = set()
    written = 0
    skipped = 0

    # If OUT_META exists, ask whether to overwrite
    if OUT_META.exists():
        print(f"Notice: {OUT_META} already exists. Running will overwrite it.")
    # Write to a temp file then move atomically
    tmp_meta = OUT_META.with_suffix(".tmp.jsonl")

    with tmp_meta.open("w", encoding="utf-8") as meta_f:
        for p in tqdm(in_files, desc="Scanning raw certs"):
            try:
                b = p.read_bytes()
            except Exception as e:
                print("Failed to read", p, e)
                skipped += 1
                continue

            # detect PEM / DER, get der bytes
            try:
                if pem.detect(b):
                    _type, _headers, der_bytes = pem.unarmor(b)
                else:
                    der_bytes = b
            except Exception as e:
                # if unarmor fails, try to skip
                print("Failed to unwrap", p.name, "-", e)
                skipped += 1
                continue

            # fingerprint
            fp = hashlib.sha256(der_bytes).hexdigest()
            if fp in seen:
                # already have identical certificate (by DER fingerprint)
                continue
            seen.add(fp)

            # write unique pem file (preserve original bytes)
            outp = OUT_DIR / f"{fp}.pem"
            try:
                if not outp.exists():
                    # If input was DER (no PEM), convert to PEM for consistency
                    if not pem.detect(b):
                        # build PEM from der
                        b64 = base64.b64encode(der_bytes).decode("ascii")
                        pem_text = "-----BEGIN CERTIFICATE-----\n"
                        # wrap lines at 64 chars
                        for i in range(0, len(b64), 64):
                            pem_text += b64[i:i+64] + "\n"
                        pem_text += "-----END CERTIFICATE-----\n"
                        outp.write_text(pem_text)
                    else:
                        # preserve original PEM content (string)
                        try:
                            outp.write_bytes(b)
                        except TypeError:
                            outp.write_text(b.decode('utf-8', errors='ignore'))
                written += 1
            except Exception as e:
                print("Failed to write unique file:", outp, e)
                skipped += 1
                continue

            # extract metadata
            try:
                meta = extract_meta_from_der(der_bytes)
            except Exception as e:
                print("Meta extraction failed for", p.name, e)
                meta = {}

            # add basic bookkeeping fields
            meta_record = {
                "fp": fp,
                "file": outp.name,
                "source_file": p.name,
                "collected_at": datetime.utcnow().isoformat() + "Z",
                **meta
            }

            # write jsonl
            try:
                meta_f.write(json.dumps(meta_record, ensure_ascii=False) + "\n")
            except Exception as e:
                print("Failed to write meta line for", p.name, e)

    # atomic move
    tmp_meta.replace(OUT_META)
    print(f"Done. Unique written: {len(seen)} (files written this run: {written}), skipped: {skipped}")
    print("Unique certs directory:", OUT_DIR)
    print("Meta JSONL:", OUT_META)

if __name__ == "__main__":
    main()
