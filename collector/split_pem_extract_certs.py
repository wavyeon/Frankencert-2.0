#!/usr/bin/env python3
# collector/split_pem_extract_certs.py
"""
Extract all PEM CERTIFICATE blocks from files under data/unique_certs/
and write each extracted certificate as a separate file under
data/unique_certs_extracted/{origfp}_{idx}.pem

This helps when some .pem files contain multiple blocks or non-certificate blocks.
"""
import re, pathlib, os
IN = pathlib.Path("data/unique_certs")
OUT = pathlib.Path("data/unique_certs_extracted")
OUT.mkdir(parents=True, exist_ok=True)

pem_re = re.compile(rb'-----BEGIN ([A-Z ]+)-----(.*?)-----END \1-----', re.DOTALL)

count_in = 0
count_out = 0
for p in sorted(IN.glob("*.pem")):
    b = p.read_bytes()
    matches = list(pem_re.finditer(b))
    if not matches:
        # try to treat entire file as DER? skip
        continue
    idx = 0
    for m in matches:
        block_type = m.group(1).decode('ascii', errors='ignore')
        block_body = m.group(0)  # full PEM including headers
        if block_type.strip() != "CERTIFICATE":
            continue
        idx += 1
        out_name = f"{p.stem}_{idx}.pem"
        out_path = OUT / out_name
        out_path.write_bytes(block_body)
        count_out += 1
    if idx > 0:
        count_in += 1

print("Done. Processed files with cert blocks:", count_in, "Written cert files:", count_out)
