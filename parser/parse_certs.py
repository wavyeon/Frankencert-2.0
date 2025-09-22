import glob, json, pathlib, base64
from asn1crypto import pem, x509

in_dir = pathlib.Path("data/raw_certs")
out_file = pathlib.Path("results/field_pool.json")
out_file.parent.mkdir(parents=True, exist_ok=True)

def safe_serialize(obj):
    """JSON으로 직렬화할 수 없으면 문자열(또는 base64)로 변환해 반환."""
    try:
        json.dumps(obj)
        return obj
    except Exception:
        if isinstance(obj, (bytes, bytearray)):
            return base64.b64encode(bytes(obj)).decode('ascii')
        try:
            return str(obj)
        except Exception:
            return repr(obj)

pool=[]
for path in in_dir.glob("*.pem"):
    b = path.read_bytes()
    try:
        if pem.detect(b):
            p_type, _headers, der_bytes = pem.unarmor(b)
            if isinstance(p_type, bytes):
                p_type = p_type.decode('utf-8', errors='ignore')
            if p_type.upper() != 'CERTIFICATE':
                print("skip (not certificate):", path.name, "type:", p_type)
                continue
            cert = x509.Certificate.load(der_bytes)
        else:
            try:
                cert = x509.Certificate.load(b)
            except Exception as e:
                print("skip (not parseable):", path.name, e)
                continue

        tbs = cert['tbs_certificate']
        subj = tbs['subject'].human_friendly
        issuer = tbs['issuer'].human_friendly
        serial = str(tbs['serial_number'].native)
        exts = {}
        for e in tbs['extensions']:
            key = e['extn_id'].native
            try:
                val = e['extn_value'].parsed
            except Exception:
                val = e['extn_value']
            try:
                native = val.native
            except Exception:
                native = str(val)
            exts[key] = safe_serialize(native)

        pool.append({
            "file": str(path.name),
            "subject": subj,
            "issuer": issuer,
            "serial": serial,
            "extensions": exts
        })
    except Exception as ex:
        print("failed parse", path, ex)

with open(out_file, "w", encoding="utf-8") as f:
    json.dump(pool, f, indent=2, ensure_ascii=False)
print("parser: wrote", out_file)

