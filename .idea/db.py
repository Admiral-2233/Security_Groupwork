# db.py - Tiny JSON-backed directory (REQUIRED directory functions)  :contentReference[oaicite:16]{index=16}
import json, os
DB_PATH = "users.json"

def load_db():
    return json.load(open(DB_PATH, "r", encoding="utf-8")) if os.path.exists(DB_PATH) else {}

def save_db(d):
    json.dump(d, open(DB_PATH, "w", encoding="utf-8"), ensure_ascii=False, indent=2)

def upsert_user(db, user_id: str, pubkey_b64url: str, meta=None):
    db[user_id] = {"pubkey": pubkey_b64url, "meta": meta or {}}
    save_db(db)

def get_pubkey(db, user_id: str):
    u = db.get(user_id)
    return u and u["pubkey"]

def list_users(db):
    return sorted(list(db.keys()))
