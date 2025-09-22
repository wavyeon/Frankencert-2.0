# 간단 샘플: 직접 self-signed certs 몇 개 생성하거나 crt.sh에서 수동 다운로드 하는 예시
import subprocess, os, pathlib

out_dir = pathlib.Path("data/raw_certs")
out_dir.mkdir(parents=True, exist_ok=True)

# 5개 샘플 self-signed cert 생성 (초기용)
for i in range(1,6):
    key = out_dir / f"key{i}.pem"
    cert = out_dir / f"cert{i}.pem"
    subj = f"/CN=sample{i}.example"
    if not cert.exists():
        subprocess.run(["openssl", "req", "-x509", "-nodes", "-days", "365",
                        "-newkey", "rsa:2048", "-keyout", str(key), "-out", str(cert),
                        "-subj", subj], check=True)
        print("generated", cert)
print("collector: done")

