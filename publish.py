#!/usr/bin/env python3
"""Encrypt רדאר articles into data.enc for the static TV site.

Usage: RADAR_KEY=<passphrase> python3 -I publish.py <articles_dir> <repo_dir>

<articles_dir> holds one JSON file per article (as saved by an ArtifactData
query with out_dir: either the article object itself or {"id","data":{...}}).
Writes <repo_dir>/data.enc. The salt is kept from the existing data.enc so the
viewer's cached key keeps working.
"""
import base64, glob, json, os, re, sys
from datetime import datetime, timezone

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
except ImportError:
    sys.exit("missing package: pip install cryptography --break-system-packages")

ITER = 150_000
KEEP = 300
IL_RE = re.compile(r"ישראל|תל אביב|השקל|הבורסה בת")
VC_RE = re.compile(r"גייס|גיוס|רוכש|רכיש|רכוש|נמכר|אקזיט|הנפק|שווי|קרן |קרנות|משקיע")
AI_RE = re.compile(r"AI|בינה מלאכותית|סוכנ|מודל|GPT|אנבידיה|Nvidia|Claude|Anthropic|OpenAI")
FIELDS = ("id", "region", "topic", "title", "dek", "body", "source", "author", "sourceUrl", "publishedAt", "addedAt")


def norm(a):
    t, title = a.get("topic"), a.get("title", "")
    region = a.get("region")
    if region not in ("il", "world"):
        region = "il" if t == "il" or IL_RE.search(title) else "world"
    if t not in ("ai", "vc", "general"):
        if t in ("market", "pm"):
            t = "general"
        else:
            t = "vc" if VC_RE.search(title) else "ai" if AI_RE.search(title) else "general"
    a = {**a, "region": region, "topic": t}
    return {k: a[k] for k in FIELDS if a.get(k) not in (None, "")}


def b64(b):
    return base64.b64encode(b).decode()


def main():
    key = os.environ.get("RADAR_KEY", "").strip().lower()
    if len(sys.argv) != 3 or not key:
        sys.exit(__doc__)
    src, repo = sys.argv[1], sys.argv[2]
    arts = []
    for f in glob.glob(os.path.join(src, "**", "*.json"), recursive=True):
        d = json.load(open(f, encoding="utf-8"))
        if isinstance(d.get("data"), dict) and "title" not in d:
            d = {"id": d.get("id"), **d["data"]}
        if d.get("id") and d.get("title"):
            arts.append(norm(d))
    if not arts:
        sys.exit("no articles found in " + src)
    arts.sort(key=lambda a: a.get("publishedAt", ""), reverse=True)
    arts = arts[:KEEP]
    payload = json.dumps({"updatedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                          "articles": arts}, ensure_ascii=False, separators=(",", ":")).encode()

    out = os.path.join(repo, "data.enc")
    salt = None
    if os.path.exists(out):
        try:
            salt = base64.b64decode(json.load(open(out))["salt"])
        except Exception:
            salt = None
    salt = salt or os.urandom(16)
    k = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITER).derive(key.encode())
    iv = os.urandom(12)
    ct = AESGCM(k).encrypt(iv, payload, None)
    json.dump({"v": 1, "kdf": "PBKDF2-SHA256", "iter": ITER, "salt": b64(salt), "iv": b64(iv), "ct": b64(ct)},
              open(out, "w"))
    print(f"wrote {out}: {len(arts)} articles, {os.path.getsize(out)//1024} KB")


if __name__ == "__main__":
    main()
