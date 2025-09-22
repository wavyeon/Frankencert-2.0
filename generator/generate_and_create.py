#!/usr/bin/env python3
# generator/generate_and_create_fixed.py
"""
Improved generate_and_create:
- robust OpenAI client compatibility (new vs old)
- option to base summary on sampled PEMs (USE_SAMPLES=1 and SAMPLES_DIR)
- robust JSON extraction from LLM output
- optional jsonschema validation
- safer extfile formatting and openssl -extensions v3_req usage
"""
import os
import json
import subprocess
import pathlib
import random
import re
import ast
import time
import collections
from datetime import datetime
from dotenv import load_dotenv
load_dotenv()

# optional libs
try:
    from asn1crypto import pem, x509 as asn1_x509
except Exception:
    pem = None
    asn1_x509 = None

# OpenAI: try new client, fallback to old (for compatibility)
try:
    from openai import OpenAI as OpenAIClient
    new_openai = True
except Exception:
    try:
        import openai
        new_openai = False
    except Exception:
        raise RuntimeError("openai library not found. pip install openai")

# optional jsonschema
try:
    from jsonschema import validate as js_validate, ValidationError
    HAS_JSONSCHEMA = True
except Exception:
    HAS_JSONSCHEMA = False

ROOT = pathlib.Path(os.environ.get("WORKSPACE", ".")).resolve()
FIELD_POOL = ROOT / "results" / "field_pool.json"        # legacy pool
LLM_OUT = ROOT / "results" / "llm_candidates.json"
RAW_OUT = ROOT / "results" / "llm_raw.txt"
GEN_OUT = ROOT / "results" / "generated_certs"
GEN_OUT.mkdir(parents=True, exist_ok=True)

KEYUSAGE_MAP = {
    "digital_signature": "digitalSignature",
    "digitalSignature": "digitalSignature",
    "non_repudiation": "nonRepudiation",
    "content_commitment": "nonRepudiation",
    "key_encipherment": "keyEncipherment",
    "keyEncipherment": "keyEncipherment",
    "data_encipherment": "dataEncipherment",
    "key_agreement": "keyAgreement",
    "keyAgreement": "keyAgreement",
    "key_cert_sign": "keyCertSign",
    "cert_sign": "keyCertSign",
    "crl_sign": "cRLSign",
    "encipher_only": "encipherOnly",
    "decipher_only": "decipherOnly"
}

EKU_MAP = {
    "client_auth": "clientAuth",
    "server_auth": "serverAuth",
    "email_protection": "emailProtection",
    "code_signing": "codeSigning",
    "time_stamping": "timeStamping",
    "ocsp_signing": "OCSPSigning",
    "clientAuth": "clientAuth",
    "serverAuth": "serverAuth",
    "emailProtection": "emailProtection"
}

def normalize_keyusage(ku_list):
    mapped = []
    for k in ku_list:
        k0 = k.strip()
        # try direct mapping or transform underscores -> camelCase
        if k0 in KEYUSAGE_MAP:
            mapped.append(KEYUSAGE_MAP[k0])
            continue
        # common snake_case -> camelCase attempt
        if "_" in k0:
            parts = k0.split("_")
            camel = parts[0].lower() + "".join(p.capitalize() for p in parts[1:])
            if camel in KEYUSAGE_MAP.values():
                mapped.append(camel)
                continue
        # fallback: use as-is but warn
        mapped.append(k0)
    return mapped

def normalize_eku(eku_list):
    mapped = []
    for e in eku_list:
        e0 = e.strip()
        if e0 in EKU_MAP:
            mapped.append(EKU_MAP[e0])
        else:
            # try basic snake->camel
            if "_" in e0:
                parts = e0.split("_")
                camel = parts[0].lower() + "".join(p.capitalize() for p in parts[1:])
                mapped.append(camel)
            else:
                mapped.append(e0)
    return mapped

# Config from env
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")
MODEL = os.environ.get("OPENAI_MODEL", "gpt-3.5-turbo")
NUM_CANDIDATES = int(os.environ.get("NUM_CANDIDATES", "5"))
TEMPERATURE = float(os.environ.get("OPENAI_TEMPERATURE", "0.2"))
MAX_TOKENS = int(os.environ.get("OPENAI_MAX_TOKENS", "700"))

USE_SAMPLES = os.environ.get("USE_SAMPLES", "") not in ("", "0", "false", "False")
SAMPLES_DIR = pathlib.Path(os.environ.get("SAMPLES_DIR", ROOT / "data" / "samples"))

if not OPENAI_API_KEY:
    print("OPENAI_API_KEY not set. Exiting.")
    raise SystemExit(1)

# init client
if new_openai:
    client = OpenAIClient(api_key=OPENAI_API_KEY)
else:
    import openai
    openai.api_key = OPENAI_API_KEY
    client = openai  # fall back

def safe_str(s):
    if s is None:
        return ""
    out = str(s)
    # remove newlines, limit length
    out = out.replace("\n", " ").replace("\r", " ")
    if len(out) > 400:
        out = out[:400] + "..."
    return out

def summarize_field_pool(fp_json, top_n_ext=8, rare_n=6, sample_fps=None):
    """
    Summarize the JSON field pool. If sample_fps (set of filenames or fps) is provided,
    only include those items.
    """
    with open(fp_json, 'r', encoding='utf-8') as f:
        pool = json.load(f)

    ext_counts = collections.Counter()
    value_examples = collections.defaultdict(set)
    subjects = collections.Counter()
    issuers = collections.Counter()
    included = 0
    for item in pool:
        # If sample_fps provided, match by 'file' or by fingerprint-like name
        if sample_fps:
            fname = item.get("file","")
            fp_candidate = fname.replace(".pem","")
            if fname not in sample_fps and fp_candidate not in sample_fps:
                continue
        included += 1
        subjects[item.get("subject","")] += 1
        issuers[item.get("issuer","")] += 1
        exts = item.get("extensions", {})
        for k, v in exts.items():
            ext_counts[k] += 1
            try:
                value_examples[k].add(safe_str(v))
            except Exception:
                value_examples[k].add(repr(v)[:120])
    common_exts = ext_counts.most_common(top_n_ext)
    rare_exts = [k for k, c in ext_counts.most_common()[:-rare_n-1:-1]] if ext_counts else []
    summary = {
        "num_pool_items_total": len(pool),
        "num_pool_items_included": included,
        "top_subjects": [s for s,c in subjects.most_common(5)],
        "top_issuers": [s for s,c in issuers.most_common(5)],
        "top_extensions": [{ "ext": k, "count": c, "examples": list(value_examples[k])[:2]} for k, c in common_exts],
        "rare_extensions": rare_exts
    }
    return summary

def summarize_from_pems(samples_dir, top_n_ext=8, rare_n=6):
    """
    If sample PEMs are present, parse them (asn1crypto) and build summary.
    """
    if asn1_x509 is None:
        raise RuntimeError("asn1crypto not installed; cannot summarize PEMs. Install asn1crypto.")
    ext_counts = collections.Counter()
    value_examples = collections.defaultdict(set)
    subjects = collections.Counter()
    issuers = collections.Counter()
    items = []
    for p in pathlib.Path(samples_dir).glob("*.pem"):
        b = p.read_bytes()
        try:
            if pem.detect(b):
                _t, _h, der = pem.unarmor(b)
            else:
                der = b
            cert = asn1_x509.Certificate.load(der)
            tbs = cert['tbs_certificate']
            subj = safe_str(tbs['subject'].human_friendly)
            iss = safe_str(tbs['issuer'].human_friendly)
            subjects[subj] += 1
            issuers[iss] += 1
            exts = {}
            for e in tbs['extensions']:
                key = e['extn_id'].native
                try:
                    val = e['extn_value'].parsed
                    native = val.native
                except Exception:
                    native = safe_str(e['extn_value'])
                exts[key] = safe_str(native)
                ext_counts[key] += 1
                value_examples[key].add(safe_str(native)[:200])
            items.append({"file": p.name, "subject": subj, "issuer": iss, "extensions": exts})
        except Exception as ex:
            # ignore parse errors for summary
            continue
    common_exts = ext_counts.most_common(top_n_ext)
    rare_exts = [k for k, c in ext_counts.most_common()[:-rare_n-1:-1]] if ext_counts else []
    summary = {
        "num_samples": len(items),
        "top_subjects": [s for s,c in subjects.most_common(5)],
        "top_issuers": [s for s,c in issuers.most_common(5)],
        "top_extensions": [{ "ext": k, "count": c, "examples": list(value_examples[k])[:2]} for k, c in common_exts],
        "rare_extensions": rare_exts
    }
    return summary

def build_prompt(summary, num_candidates):
    short = json.dumps(summary, ensure_ascii=False)
    prompt = f"""
You are a security engineer creating X.509 certificate field combinations likely to trigger semantic/logic edge-cases in TLS libraries (OpenSSL, GnuTLS, NSS).
Given the compact summary of observed certificate fields below, produce up to {num_candidates} candidate certificate FIELD-SETS (not full PEMs).
For each candidate return a JSON object with these keys:
- id (int or short string)
- fields: {{ "version": <int>, "serial": <string>, "basicConstraints": <string like 'CA:FALSE'>, "keyUsage": [..], "keyUsage_critical": true/false, "eku": [..] (optional), "subjectAltName": "DNS:..." (optional) }}
- rationale: one-sentence reason why this is suspicious
- expected_reaction: one of ["accept","reject","warning","crash","unknown"]

Constraints:
- Use plausible values drawn from the summary or realistic values.
- Prefer semantic contradictions (e.g., keyCertSign with basicConstraints CA:FALSE), unusual critical flags, missing-but-declared fields, or critical extensions that differ from common usage.
- Return ONLY a JSON array as the entire response (no extra commentary).

Summary:
{short}
"""
    return prompt

def extract_json_array_from_text(text):
    """
    Robustly extract the first balanced JSON array from text.
    Finds first '[' then finds matching closing ']' by tracking bracket depth.
    """
    s = text
    start = s.find('[')
    if start == -1:
        raise ValueError("No '[' found in text to extract JSON array")
    depth = 0
    for i in range(start, len(s)):
        if s[i] == '[':
            depth += 1
        elif s[i] == ']':
            depth -= 1
            if depth == 0:
                candidate = s[start:i+1]
                return candidate
    raise ValueError("No balanced JSON array found")

def call_llm(prompt, model=MODEL, max_tokens=MAX_TOKENS, temperature=TEMPERATURE, attempts=3):
    raw_text = None
    for attempt in range(attempts):
        try:
            if new_openai:
                resp = client.chat.completions.create(
                    model=model,
                    messages=[{"role":"system","content":"You are a helpful security engineer."},
                              {"role":"user","content":prompt}],
                    max_tokens=max_tokens,
                    temperature=temperature
                )
                raw_text = resp.choices[0].message.content
            else:
                resp = client.ChatCompletion.create(
                    model=model,
                    messages=[{"role":"system","content":"You are a helpful security engineer."},
                              {"role":"user","content":prompt}],
                    max_tokens=max_tokens,
                    temperature=temperature,
                    n=1
                )
                raw_text = resp['choices'][0]['message']['content']
            if raw_text:
                return raw_text
        except Exception as e:
            print("OpenAI call failed (attempt", attempt+1, "):", e)
            time.sleep(1 + attempt*2)
    raise RuntimeError("OpenAI call consistently failed")

def sanitize_serial(s):
    if s is None:
        return None
    s = str(s)
    s = s.strip()
    s = s.replace("\n","").replace("\r","")
    # keep only hex/digits/letters and -_
    s = re.sub(r'[^0-9A-Za-z\-_.:]', '', s)
    if len(s) == 0:
        s = hex(random.getrandbits(64))
    return s

# Main flow
if __name__ == "__main__":
    # build summary: prefer samples if requested
    if USE_SAMPLES and SAMPLES_DIR.exists() and any(SAMPLES_DIR.glob("*.pem")):
        print("Using sampled PEMs from", SAMPLES_DIR)
        summary = summarize_from_pems(SAMPLES_DIR)
    elif FIELD_POOL.exists():
        # optionally restrict to sample list in SAMPLES_DIR if USE_SAMPLES but we couldn't parse PEMs
        sample_fps = None
        if USE_SAMPLES and SAMPLES_DIR.exists():
            sample_fps = set(p.name for p in SAMPLES_DIR.glob("*.pem"))
            print("Filtering field_pool.json to included sample filenames:", len(sample_fps))
        summary = summarize_field_pool(FIELD_POOL, sample_fps=sample_fps)
    else:
        print("No field pool or samples found. Exiting.")
        raise SystemExit(1)

    prompt = build_prompt(summary, NUM_CANDIDATES)
    print("Calling OpenAI...", MODEL, "candidates=", NUM_CANDIDATES)
    raw_text = call_llm(prompt)
    raw_text = raw_text.strip()
    # save raw
    with open(RAW_OUT, "w", encoding="utf-8") as f:
        f.write(raw_text)
    # extract JSON array
    try:
        arr_text = extract_json_array_from_text(raw_text)
        candidates = json.loads(arr_text)
    except Exception as e:
        print("Failed to extract/parse JSON array from LLM output:", e)
        # try ast literal_eval as last resort
        try:
            candidates = ast.literal_eval(raw_text)
        except Exception as e2:
            print("Also failed to literal_eval:", e2)
            print("See raw output at", RAW_OUT)
            raise

    # optional schema validation
    if HAS_JSONSCHEMA:
        schema = {
            "type":"object",
            "properties":{
                "id": {"type": ["integer","string"]},
                "fields": {"type": "object"},
                "rationale": {"type": "string"},
                "expected_reaction": {"type":"string", "enum":["accept","reject","warning","crash","unknown"]}
            },
            "required":["id","fields","rationale"]
        }
        valid = []
        for c in candidates:
            try:
                js_validate(instance=c, schema=schema)
                valid.append(c)
            except ValidationError as ve:
                print("Candidate failed schema validation, skipping:", c.get("id"), ve)
        candidates = valid
        print("Candidates after schema validation:", len(candidates))

    # save parsed candidates
    with open(LLM_OUT, "w", encoding="utf-8") as f:
        json.dump(candidates, f, ensure_ascii=False, indent=2)
    print("Saved", len(candidates), "candidates to", LLM_OUT)

    # Create certificates
    def create_cert_from_fields(cand, out_dir: pathlib.Path):
        idx = cand.get("id", random.randint(1000,9999))
        key_path = out_dir / f"key_{idx}.pem"
        csr_path = out_dir / f"req_{idx}.pem"
        cert_path = out_dir / f"cert_{idx}.pem"
        subj = f"/CN=gen{idx}.example"
        # 1) generate key
        subprocess.run(["openssl","genpkey","-algorithm","RSA","-out",str(key_path),"-pkeyopt","rsa_keygen_bits:2048"], check=True)
        # 2) create CSR
        subprocess.run(["openssl","req","-new","-key",str(key_path),"-out",str(csr_path),"-subj",subj], check=True)
        # 3) build extension file with proper section header and normalized names
        bc = cand.get('fields', {}).get('basicConstraints', '')
        ku = cand.get('fields', {}).get('keyUsage', []) or []
        eku = cand.get('fields', {}).get('eku', []) or []
        ku_critical = cand.get('fields', {}).get('keyUsage_critical') or cand.get('keyUsage_critical', False)
    
        ext_lines = []
        # include v3_req header since we call -extensions v3_req
        ext_lines.append("[ v3_req ]")
    
        if bc:
            # basicConstraints syntax: critical,CA:TRUE or CA:FALSE
            # If user included "critical" in bc string we won't double add it; typical LLM gives "CA:FALSE" so just put it
            ext_lines.append(f"basicConstraints = {bc}")
    
        if ku:
            mapped_ku = normalize_keyusage(ku)
            # OpenSSL allows 'keyUsage = critical, digitalSignature, keyEncipherment' or without critical
            if ku_critical:
                ext_lines.append("keyUsage = critical," + ",".join(mapped_ku))
            else:
                ext_lines.append("keyUsage = " + ",".join(mapped_ku))
    
        if eku:
            mapped_eku = normalize_eku(eku)
            # extendedKeyUsage expects comma-separated short names
            ext_lines.append("extendedKeyUsage = " + ",".join(mapped_eku))
    
        extfile = out_dir / f"ext_{idx}.cnf"
        extfile.write_text("\n".join(ext_lines))
        # 4) sign
        subprocess.run([
            "openssl","x509","-req","-in",str(csr_path),"-signkey",str(key_path),
            "-out",str(cert_path),"-days","365","-extfile",str(extfile),"-extensions","v3_req"
        ], check=True)
        return cert_path, key_path

    for cand in candidates:
        try:
            certp, keyp = create_cert_from_fields(cand, GEN_OUT)
            print("Generated:", certp.name)
        except subprocess.CalledProcessError as e:
            print("OpenSSL generation failed for candidate", cand.get("id"), e)

    print("All done at", datetime.utcnow().isoformat() + "Z")
