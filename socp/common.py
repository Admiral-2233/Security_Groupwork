# common.py - Small helpers (canonical JSON, base64url, time)
import base64, json, time, uuid

def now_ms() -> int:
    return int(time.time() * 1000)

def new_uuid() -> str:
    # MUST: UUID v4 for all identifiers (users/servers).  :contentReference[oaicite:11]{index=11}
    return str(uuid.uuid4())

def b64url_encode(b: bytes) -> str:
    # MUST: base64url w/o padding in JSON.  :contentReference[oaicite:12]{index=12}
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")

def b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)

def canonical_json(obj: dict) -> bytes:
    # MUST: envelope.sig signs canonical payload (sorted keys, no spaces).  :contentReference[oaicite:13]{index=13}
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
