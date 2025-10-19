# envelope.py - SOCP JSON envelope builder/validator
from common import canonical_json, b64url_encode, b64url_decode
from crypto_socp import sign_pss, verify_pss

def make_envelope(typ: str, frm: str, to: str, payload: dict, priv_key, ts: int):
    # MUST fields: type/from/to/ts/payload/sig  :contentReference[oaicite:15]{index=15}
    env = {"type": typ, "from": frm, "to": to, "ts": ts, "payload": payload, "sig": ""}
    env["sig"] = b64url_encode(sign_pss(priv_key, canonical_json(payload)))
    return env

def verify_envelope(env: dict, pub_key) -> bool:
    sig = b64url_decode(env.get("sig", ""))
    return verify_pss(pub_key, canonical_json(env["payload"]), sig)
