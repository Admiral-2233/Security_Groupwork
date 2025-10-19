# client.py - SOCP CLI client (MUST-compliant E2EE + signatures)
import asyncio, websockets, json, sys, os
from websockets.client import connect as ws_connect
from common import now_ms, b64url_encode, b64url_decode, canonical_json
from crypto_socp import (gen_rsa4096_pair, export_pub_b64url, import_pub_b64url,
                         rsa_oaep_encrypt, rsa_oaep_decrypt, sign_pss, verify_pss)
from envelope import make_envelope
from db import get_pubkey, upsert_user, load_db

DB = load_db()

def dm_content_sig(priv, ct_b64, frm, to, ts):
    return b64url_encode(sign_pss(priv, (ct_b64 + frm + to + str(ts)).encode("utf-8")))

def pub_content_sig(priv, ct_b64, frm, ts):
    return b64url_encode(sign_pss(priv, (ct_b64 + frm + str(ts)).encode("utf-8")))

async def run(user_id: str, server_url: str):
    # Load/generate user keys
    pem_path = f"{user_id}.pem"
    if os.path.exists(pem_path):
        from Crypto.PublicKey import RSA
        PRIV = RSA.import_key(open(pem_path, "rb").read())
        PUB  = PRIV.publickey()
    else:
        PRIV, PUB = gen_rsa4096_pair()
        open(pem_path, "wb").write(PRIV.export_key())
    PUB_B64 = export_pub_b64url(PUB)

    # Public channel keys (once received)
    channel_pub = None
    channel_priv = None

    async with ws_connect(server_url) as ws:
        # HELLO (first frame can be unsigned)
        hello = {"type":"USER_HELLO","from":user_id,"to":"server","ts":now_ms(),
                 "payload":{"client":"cli-v1","pubkey":PUB_B64}, "sig":""}
        await ws.send(json.dumps(hello, separators=(",", ":")))

        async def rx():
            nonlocal channel_pub, channel_priv
            while True:
                msg = await ws.recv()
                env = json.loads(msg)
                typ = env["type"]
                if typ == "USER_DELIVER":
                    # DM: decrypt and verify signature (content_sig: ciphertext|from|to|ts)
                    ct = b64url_decode(env["payload"]["ciphertext"])
                    pt = rsa_oaep_decrypt(PRIV, ct).decode("utf-8", "ignore")
                    ok = verify_pss(import_pub_b64url(env["payload"]["sender_pub"]),
                                    (env["payload"]["ciphertext"] + env["from"] + env["to"] + str(env["ts"])).encode("utf-8"),
                                    b64url_decode(env["payload"]["content_sig"]))
                    print(f"\n<DM from {env['payload'].get('sender','?')}> {pt} [{'OK' if ok else 'BAD_SIG'}]")

                elif typ == "MSG_PUBLIC_CHANNEL":
                    # Group chat: decrypt with channel private key and verify content_sig per public rules (ciphertext|from|ts)
                    if channel_priv is None:
                        print("\n[Public] message received but channel private key not installed yet.")
                        continue
                    ct = b64url_decode(env["payload"]["ciphertext"])
                    pt = rsa_oaep_decrypt(channel_priv, ct).decode("utf-8", "ignore")
                    ok = verify_pss(import_pub_b64url(env["payload"]["sender_pub"]),
                                    (env["payload"]["ciphertext"] + env["from"] + str(env["ts"])).encode("utf-8"),
                                    b64url_decode(env["payload"]["content_sig"]))
                    print(f"\n[Public] {env['from']}: {pt} [{'OK' if ok else 'BAD_SIG'}]")

                elif typ == "PUBLIC_CHANNEL_KEY_SHARE_USER":
                    # Receive channel private key wrap: unwrap to get channel private key; save channel public key
                    from Crypto.PublicKey import RSA
                    wrapped = b64url_decode(env["payload"]["wrapped_private"])
                    try:
                        pem = rsa_oaep_decrypt(PRIV, wrapped)
                        channel_priv = RSA.import_key(pem)
                        # creator_pub is the channel public key
                        channel_pub = import_pub_b64url(env["payload"]["creator_pub"])
                        print("[Public] channel key installed.")
                    except Exception as e:
                        print("[Public] failed to install channel key:", e)

                elif typ == "USER_LIST":
                    print("\nOnline:", ", ".join(env["payload"]["users"]))
                elif typ.startswith("USER_FILE"):
                    print(f"\n<File> {typ} {env['payload']}")
                elif typ == "ERROR":
                    print("\n[ERROR]", env["payload"])

        async def tx():
            print("Commands: /list | /tell <user> <text> | /all <text> | /file <user> <path>")
            while True:
                line = await asyncio.get_event_loop().run_in_executor(None, sys.stdin.readline)
                if not line: break
                line = line.strip()
                if line == "/list":
                    env = make_envelope("CLIENT_CMD", user_id, "server", {"cmd":"/list"}, PRIV, now_ms())
                    await ws.send(json.dumps(env, separators=(",", ":")))
                elif line.startswith("/tell "):
                    try:
                        _, dst, text = line.split(" ", 2)
                    except ValueError:
                        print("usage: /tell <user> <text>"); continue
                    pk_b64 = get_pubkey(DB, dst)
                    if not pk_b64:
                        env = make_envelope("CLIENT_CMD", user_id, "server", {"cmd":f"/getpub {dst}"}, PRIV, now_ms())
                        await ws.send(json.dumps(env, separators=(",", ":"))); continue
                    ct = rsa_oaep_encrypt(import_pub_b64url(pk_b64), text.encode("utf-8"))
                    ct_b64 = b64url_encode(ct); ts = now_ms()
                    payload = {"ciphertext":ct_b64, "sender":user_id, "sender_pub":export_pub_b64url(PUB),
                               "content_sig": dm_content_sig(PRIV, ct_b64, user_id, dst, ts)}
                    env = {"type":"MSG_DIRECT","from":user_id,"to":dst,"ts":ts,"payload":payload,
                           "sig": b64url_encode(sign_pss(PRIV, canonical_json(payload)))}
                    await ws.send(json.dumps(env, separators=(",", ":")))
                elif line.startswith("/all "):
                    text = line[5:]
                    if channel_pub is None:
                        print("[Public] waiting for channel key share..."); continue
                    ct = rsa_oaep_encrypt(channel_pub, text.encode("utf-8"))
                    ct_b64 = b64url_encode(ct); ts = now_ms()
                    payload = {"ciphertext": ct_b64, "sender_pub": export_pub_b64url(PUB),
                               "content_sig": pub_content_sig(PRIV, ct_b64, user_id, ts)}
                    env = {"type":"MSG_PUBLIC_CHANNEL","from":user_id,"to":"g-public","ts":ts,
                           "payload": payload, "sig": b64url_encode(sign_pss(PRIV, canonical_json(payload)))}
                    await ws.send(json.dumps(env, separators=(",", ":")))
                elif line.startswith("/file "):
                    try:
                        _, dst, path = line.split(" ", 2)
                        data = open(path, "rb").read()
                    except Exception:
                        print("usage: /file <user> <path>"); continue
                    from math import ceil
                    env = make_envelope("FILE_START", user_id, dst, {
                        "file_id": f"file-{now_ms()}",
                        "name": os.path.basename(path),
                        "size": len(data),
                        "sha256": "NA",
                        "mode": "dm"
                    }, PRIV, now_ms())
                    await ws.send(json.dumps(env, separators=(",", ":")))
                    # Split into chunks and apply RSA-OAEP to each (same as message)
                    pk_b64 = get_pubkey(DB, dst)
                    if not pk_b64:
                        print("unknown dst pubkey"); continue
                    pub = import_pub_b64url(pk_b64)
                    off, index = 0, 0
                    while off < len(data):
                        chunk = data[off:off+400]; off += 400; index += 1
                        ct_b64 = b64url_encode(rsa_oaep_encrypt(pub, chunk))
                        env = make_envelope("FILE_CHUNK", user_id, dst, {
                            "file_id": env["payload"]["file_id"], "index": index, "ciphertext": ct_b64
                        }, PRIV, now_ms())
                        await ws.send(json.dumps(env, separators=(",", ":")))
                    await ws.send(json.dumps(make_envelope("FILE_END", user_id, dst,
                                                           {"file_id": env["payload"]["file_id"]}, PRIV, now_ms()),
                                             separators=(",", ":")))
                else:
                    print("Unknown command")
        await asyncio.gather(rx(), tx())

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python client.py <user_uuid_v4> <ws://host:port>"); sys.exit(1)
    asyncio.run(run(sys.argv[1], sys.argv[2]))
