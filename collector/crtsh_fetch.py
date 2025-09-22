#!/usr/bin/env python3
"""
crt.sh domain-based fetcher (safe & polite).
Usage:
  - put domains (one per line) in collector/domains.txt OR let script use built-in list.
  - python3 collector/crtsh_fetch_by_domains.py [max_per_domain]
"""
import requests, time, pathlib, hashlib, sys, json

OUT = pathlib.Path("data/raw_certs")
OUT.mkdir(parents=True, exist_ok=True)
DOMFILE = pathlib.Path("collector/domains.txt")

# built-in short list (you can expand or replace by collector/domains.txt)
builtin_domains = [
 "google.com","facebook.com","amazon.com","youtube.com","wikipedia.org",
 "baidu.com","yahoo.com","twitter.com","instagram.com","linkedin.com",
 "apple.com","microsoft.com","naver.com","daum.net","kakao.com"
]

# headers to look like a normal browser (reduce bot-blocking)
HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
    "Accept": "application/json, text/javascript, */*; q=0.01"
}

def load_domains():
    if DOMFILE.exists():
        doms = [l.strip() for l in open(DOMFILE, 'r', encoding='utf-8') if l.strip() and not l.startswith("#")]
        return doms
    return builtin_domains

def fetch_for_domain(domain, max_items=50, sleep=0.6):
    qurl = f"https://crt.sh/?q={domain}&output=json"
    print(f"[{domain}] requesting {qurl}")
    try:
        r = requests.get(qurl, headers=HEADERS, timeout=30)
    except Exception as e:
        print("  request failed:", e)
        return 0
    if r.status_code != 200:
        print("  non-200:", r.status_code)
        print("  preview:", r.text[:200].replace('\\n',' '))
        return 0
    # try parse json
    try:
        arr = r.json()
    except Exception as e:
        print("  json parse failed:", e)
        print("  preview:", r.text[:400].replace('\\n',' '))
        return 0
    saved = 0
    seen_ids = set()
    for item in arr:
        cid = item.get("min_cert_id") or item.get("id")
        if not cid: 
            continue
        if cid in seen_ids:
            continue
        seen_ids.add(cid)
        pem_url = f"https://crt.sh/?d={cid}"
        try:
            pr = requests.get(pem_url, headers={"User-Agent": HEADERS["User-Agent"]}, timeout=30)
            if pr.status_code != 200:
                continue
            content = pr.text
            if "BEGIN CERTIFICATE" not in content:
                continue
            fp = hashlib.sha256(content.encode()).hexdigest()
            fname = OUT / f"crtsh_{domain}_{cid}_{fp[:12]}.pem"
            if not fname.exists():
                fname.write_text(content)
                saved += 1
                print("  saved:", fname)
            if saved >= max_items:
                break
            time.sleep(sleep)
        except Exception as e:
            print("  error downloading cert", cid, e)
            time.sleep(sleep)
    return saved

if __name__=="__main__":
    max_per_domain = 50
    if len(sys.argv) >= 2:
        max_per_domain = int(sys.argv[1])
    domains = load_domains()
    total = 0
    for d in domains:
        try:
            n = fetch_for_domain(d, max_items=max_per_domain)
            total += n
        except KeyboardInterrupt:
            break
    print("Done. total saved:", total)