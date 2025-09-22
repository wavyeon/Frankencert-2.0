import subprocess, glob, pathlib, time

gen_dir = pathlib.Path("results/generated_certs")
logs = pathlib.Path("results/test_logs")
logs.mkdir(parents=True, exist_ok=True)

certs = list(gen_dir.glob("cert_*.pem"))
keys = [gen_dir / f"key_{p.stem.split('_')[-1]}.pem" for p in certs]

for cert, key in zip(certs, keys):
    port = 4443
    # start server
    server = subprocess.Popen(["openssl","s_server","-cert",str(cert),"-key",str(key),"-accept",str(port)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    time.sleep(0.8)  # 서버가 뜰 시간
    try:
        out = subprocess.run(["openssl","s_client","-connect",f"127.0.0.1:{port}","-brief"], capture_output=True, text=True, timeout=10)
        logf = logs / f"test_{cert.stem}.log"
        logf.write_text(out.stdout + "\n\nSTDERR:\n" + out.stderr)
        print("tested", cert.name, "-> log:", logf)
    except Exception as e:
        print("test failed", cert, e)
    finally:
        server.terminate()
        server.wait()

