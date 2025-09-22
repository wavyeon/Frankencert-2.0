# generator/generate_and_create.py
import os
import json
import subprocess
import pathlib
import random
import re
import ast
import time
import collections
import openai

# Config from env
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")
MODEL = os.environ.get("OPENAI_MODEL", "gpt-3.5-turbo")
NUM_CANDIDATES = int(os.environ.get("NUM_CANDIDATES", "5"))  # default 5 (keep small to save cost)
TEMPERATURE = float(os.environ.get("OPENAI_TEMPERATURE", "0.2"))
MAX_TOKENS = int(os.environ.get("OPENAI_MAX_TOKENS", "700"))

if not OPENAI_API_KEY:
    print("OPENAI_API_KEY not set. Exiting.")
    raise SystemExit(1)
openai.api_key = OPENAI_API_KEY

ROOT = pathlib.Path("/workspace")
FIELD_POOL = ROOT / "results" / "field_pool.json"
LLM_OUT = ROOT / "results" / "llm_candidates.json"
RAW_OUT = ROOT / "results" / "llm_raw.txt"
GEN_OUT = ROOT / "results" / "generated_certs"
GEN_OUT.mkdir(parents=True, exist_ok=True)

# Helper: summarize field_pool to keep prompt small
def summarize_field_pool(fp_json, top_n_ext=8, rare_n=6):
    with open(fp_json, 'r', encoding='utf-8') as f:
        pool = json.load(f)
    ext_counts = collections.Counter()
    value_examples = collections.defaultdict(set)
    subjects = collections.Counter()
    issuers = collections.Counter()
    for item in pool:
        subjects[item.get("subject","")] += 1
        issuers[item.get("issuer","")] += 1
        exts = item.get("extensions", {})
        for k, v in exts.items():
            ext_counts[k] += 1
            try:
                value_examples[k].add(str(v)[:120])
            except Exception:
                value_examples[k].add(repr(v)[:120])
    common_exts = ext_counts.most_common(top_n_ext)
    rare_exts = [k for k, c in ext_counts.most_common()[:-rare_n-1:-1]] if ext_counts else []
    summary = {
        "num_certs": len(pool),
        "top_subjects": [s for s,c in subjects.most_common(5)],
        "top_issuers": [s for s,c in issuers.most_common(5)],
        "top_extensions": [{ "ext": k, "count": c, "examples": list(value_examples[k])[:2]} for k, c in common_exts],
        "rare_extensions": rare_exts
    }
    return summary

# Build prompt (concise)
def build_prompt(summary, num_candidates):
    short = json.dumps(summary, ensure_ascii=False)
    prompt = f"""
You are a security engineer creating X.509 certificate field combinations likely to trigger semantic/logic edge-cases in TLS libraries (OpenSSL, GnuTLS, NSS).
Given the compact summary of observed certificate fields below, produce up to {num_candidates} candidate certificate FIELD-SETS (not full PEMs).
For each candidate return a JSON object with these keys:
- id (int)
- fields: {{ "version": <int>, "serial": <string>, "basicConstraints": <string like 'CA:FALSE'>, "keyUsage": [..], "keyUsage_critical": true/false, "eku": [..] (optional) }}
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

# Step 1: check field pool exists
if not FIELD_POOL.exists():
    print("No field pool found. Exiting.")
    raise SystemExit(1)

summary = summarize_field_pool(FIELD_POOL)
prompt = build_prompt(summary, NUM_CANDIDATES)

# Step 2: call OpenAI (with retries)
print("Calling OpenAI...", MODEL, "candidates=", NUM_CANDIDATES)
retry = 0
raw_text = None
while retry < 3:
    try:
        resp = openai.ChatCompletion.create(
            model=MODEL,
            messages=[{"role":"system","content":"You are a helpful security engineer."},
                      {"role":"user","content":prompt}],
            max_tokens=MAX_TOKENS,
            temperature=TEMPERATURE,
            n=1,
        )
        raw_text = resp['choices'][0]['message']['content'].strip()
        break
    except Exception as e:
        print("OpenAI call failed (attempt", retry+1, "):", e)
        retry += 1
        time.sleep(1 + retry*2)
if raw_text is None:
    print("OpenAI call failed after retries. Exiting.")
    raise SystemExit(1)

# Save raw output for debugging
with open(RAW_OUT, "w", encoding="utf-8") as f:
    f.write(raw_text)

# Step 3: extract JSON array from model output robustly
m = re.search(r'(\[.*\])', raw_text, flags=re.S)
json_text = m.group(1) if m else raw_text
try:
    candidates = json.loads(json_text)
except Exception:
    try:
        candidates = ast.literal_eval(json_text)
    except Exception as e:
        print("Failed to parse LLM output as JSON:", e)
        print("Raw output saved to", RAW_OUT)
        raise

# Save parsed candidates
with open(LLM_OUT, "w", encoding="utf-8") as f:
    json.dump(candidates, f, indent=2, ensure_ascii=False)
print("Saved", len(candidates), "candidates to", LLM_OUT)

# Step 4: create certificates for each candidate (simple self-signed)
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
    # 3) build extension file
    bc = cand.get('fields', {}).get('basicConstraints', '')
    ku = cand.get('fields', {}).get('keyUsage', [])
    eku = cand.get('fields', {}).get('eku', [])
    ext_lines = []
    if bc:
        ext_lines.append(f"basicConstraints={bc}")
    if ku:
        # OpenSSL expects comma-separated list without spaces
        ext_lines.append("keyUsage=" + ",".join(ku))
    if eku:
        ext_lines.append("extendedKeyUsage=" + ",".join(eku))
    extfile = out_dir / f"ext_{idx}.cnf"
    extfile.write_text("\n".join(ext_lines))
    # 4) sign
    subprocess.run(["openssl","x509","-req","-in",str(csr_path),"-signkey",str(key_path),"-out",str(cert_path),"-days","365","-extfile",str(extfile)], check=True)
    return cert_path, key_path

for cand in candidates:
    try:
        certp, keyp = create_cert_from_fields(cand, GEN_OUT)
        print("Generated:", certp.name)
    except subprocess.CalledProcessError as e:
        print("OpenSSL generation failed for candidate", cand.get("id"), e)

print("All done.")
