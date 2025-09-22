import pathlib,json,base64
from asn1crypto import pem, x509
from datetime import datetime

IN_DIR = pathlib.Path("data/unique_certs")
OUT_JSONL = pathlib.Path("results/field_pool_extended.jsonl")
OUT_JSONL.parent.mkdir(parents=True, exist_ok=True)

def to_iso(dt):
    try:
        return dt.isoformat()
    except:
        return str(dt)

def serialize_val(v):
    try:
        json.dumps(v)
        return v
    except:
        if isinstance(v, (bytes, bytearray)):
            return base64.b64encode(bytes(v)).decode()
        return str(v)

with open(OUT_JSONL, "w", encoding="utf-8") as out:
    for p in IN_DIR.glob("*.pem"):
        try:
            b=p.read_bytes()
            if pem.detect(b):
                _t,_h,der = pem.unarmor(b)
            else:
                der=b
            cert=x509.Certificate.load(der)
            tbs=cert['tbs_certificate']
            rec={}
            rec['file']=p.name
            rec['version']=int(tbs['version'].native) if tbs['version'] else None
            rec['serial']=str(tbs['serial_number'].native)
            # validity
            nb = tbs['validity']['not_before'].native
            na = tbs['validity']['not_after'].native
            rec['not_before']=to_iso(nb)
            rec['not_after']=to_iso(na)
            # subject/issuer as dict
            rec['subject']=tbs['subject'].native
            rec['issuer']=tbs['issuer'].native
            # public key type/size
            spki = tbs['subject_public_key_info']
            alg = spki['algorithm']['algorithm'].native
            rec['pubkey_alg']=alg
            try:
                # rsa size
                pk = spki['public_key'].parsed
                if hasattr(pk, 'native') and isinstance(pk.native, dict) and 'modulus' in pk.native:
                    rec['pubkey_size']=pk.native.get('modulus').bit_length()
            except Exception:
                pass
            # signature algorithm
            rec['sig_alg']=cert['signature_algorithm'].native
            # extensions - collect names, critical and simplified value
            exts={}
            for e in tbs['extensions']:
                oid = e['extn_id'].dotted
                name = e['extn_id'].native if isinstance(e['extn_id'].native, str) else oid
                try:
                    val = e['extn_value'].parsed
                    val_native = val.native
                except Exception:
                    val_native = str(e['extn_value'].native)
                exts[name] = {'critical': bool(e['critical'].native), 'value': serialize_val(val_native)}
            rec['extensions']=exts
            out.write(json.dumps(rec, ensure_ascii=False) + "\n")
        except Exception as ex:
            print("skip", p.name, ex)
print("wrote", OUT_JSONL)