# gui_client.py - Desktop GUI client for SOCP v1.3
# - Qt UI (PySide6) + asyncio websockets via qasync (no freezing UI)
# - End-to-end crypto stays the same: RSA-OAEP + RSASSA-PSS
# - Implements: /list, /tell, public channel (/all), file send (chunked)
#
# Quick start:
#   python gui_client.py     # enter server URL and your UUID v4, then Connect

import sys, os, json, asyncio, contextlib
from pathlib import Path

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLineEdit, QPushButton, QListWidget, QTextEdit, QLabel,
    QFileDialog, QMessageBox, QSplitter, QFrame, QAbstractItemView
)
from PySide6.QtCore import Qt, QObject, Signal

from qasync import QEventLoop, asyncSlot
import websockets

# --- import your existing SOCP building blocks ---
from common import now_ms, b64url_encode, b64url_decode, canonical_json, new_uuid
from crypto_socp import (
    gen_rsa4096_pair, export_pub_b64url, import_pub_b64url,
    rsa_oaep_encrypt, rsa_oaep_decrypt, sign_pss, verify_pss
)
from envelope import make_envelope
from db import load_db, save_db, get_pubkey, upsert_user

# ------------------------------------------------
# Low-level SOCP client engine (QObject + asyncio)
# ------------------------------------------------
class SocpClient(QObject):
    connected = Signal()
    disconnected = Signal()
    error = Signal(str)
    info = Signal(str)

    users_updated = Signal(list)            # ["uuid1","uuid2",...]
    dm_received = Signal(str, str, bool)    # (from, text, sig_ok)
    pub_received = Signal(str, str, bool)   # (from, text, sig_ok)

    def __init__(self):
        super().__init__()
        self.ws = None
        self.rx_task = None
        self.url = ""
        self.user_id = ""
        self.PRIV = None
        self.PUB = None
        self.PUB_B64 = ""
        self.DB = load_db()

        # Public channel keys (filled after key share)
        self.channel_pub = None
        self.channel_priv = None

    # --- key management ---
    def _ensure_user_keys(self, user_id: str):
        """Load or create a long-term RSA-4096 keypair for this user."""
        pem_path = Path(f"{user_id}.pem")
        from Crypto.PublicKey import RSA
        if pem_path.exists():
            self.PRIV = RSA.import_key(pem_path.read_bytes())
            self.PUB = self.PRIV.publickey()
        else:
            self.PRIV, self.PUB = gen_rsa4096_pair()
            pem_path.write_bytes(self.PRIV.export_key())
        self.PUB_B64 = export_pub_b64url(self.PUB)

    # --- connect / disconnect ---
    @asyncSlot(str, str)
    async def connect_to(self, server_url: str, user_id: str):
        """Open a WS to the SOCP server and perform USER_HELLO."""
        if self.ws:
            self.error.emit("Already connected.")
            return
        self.url = server_url.strip()
        self.user_id = user_id.strip()
        if not self.user_id:
            self.error.emit("User ID (UUID v4) required.")
            return
        self._ensure_user_keys(self.user_id)

        try:
            self.ws = await websockets.connect(self.url)
        except Exception as e:
            self.ws = None
            self.error.emit(f"Connect failed: {e}")
            return

        # USER_HELLO: first frame may omit envelope.sig (per spec)
        hello = {
            "type": "USER_HELLO",
            "from": self.user_id,
            "to": "server",
            "ts": now_ms(),
            "payload": {"client": "gui-v1", "pubkey": self.PUB_B64},
            "sig": ""
        }
        try:
            await self.ws.send(json.dumps(hello, separators=(",", ":")))
        except Exception as e:
            await self._safe_close()
            self.error.emit(f"Handshake send failed: {e}")
            return

        # start RX loop
        self.rx_task = asyncio.create_task(self._rx_loop())
        self.connected.emit()
        self.info.emit("Connected and sent USER_HELLO.")

    @asyncSlot()
    async def disconnect(self):
        await self._safe_close()
        self.disconnected.emit()

    async def _safe_close(self):
        try:
            if self.rx_task:
                self.rx_task.cancel()
                with contextlib.suppress(Exception):
                    await self.rx_task
        except Exception:
            pass
        finally:
            self.rx_task = None
            if self.ws:
                try:
                    await self.ws.close()
                except Exception:
                    pass
                self.ws = None

    # --- tx helpers ---
    async def send_list(self):
        if not self.ws: return
        env = make_envelope("CLIENT_CMD", self.user_id, "server", {"cmd": "/list"}, self.PRIV, now_ms())
        await self.ws.send(json.dumps(env, separators=(",", ":")))

    async def send_dm(self, dst_user: str, text: str):
        """/tell <dst> <text> with RSA-OAEP + RSASSA-PSS content_sig."""
        if not self.ws or not text.strip(): return
        pk_b64 = get_pubkey(self.DB, dst_user)
        if not pk_b64:
            # ask server for pubkey and ask user to retry
            env = make_envelope("CLIENT_CMD", self.user_id, "server", {"cmd": f"/getpub {dst_user}"}, self.PRIV, now_ms())
            await self.ws.send(json.dumps(env, separators=(",", ":")))
            self.info.emit("Requested pubkey from server. Try again after it returns.")
            return
        ct = rsa_oaep_encrypt(import_pub_b64url(pk_b64), text.encode("utf-8"))
        ct_b64 = b64url_encode(ct); ts = now_ms()
        content_sig = b64url_encode(
            sign_pss(self.PRIV, (ct_b64 + self.user_id + dst_user + str(ts)).encode("utf-8"))
        )
        payload = {"ciphertext": ct_b64, "sender": self.user_id,
                   "sender_pub": self.PUB_B64, "content_sig": content_sig}
        env = {"type": "MSG_DIRECT", "from": self.user_id, "to": dst_user,
               "ts": ts, "payload": payload,
               "sig": b64url_encode(sign_pss(self.PRIV, canonical_json(payload)))}
        await self.ws.send(json.dumps(env, separators=(",", ":")))

    async def send_public(self, text: str):
        """/all <text> in public channel; encrypt under channel_pub."""
        if not self.ws or not text.strip(): return
        if self.channel_pub is None:
            self.info.emit("Public channel key not installed yet.")
            return
        ct = rsa_oaep_encrypt(self.channel_pub, text.encode("utf-8"))
        ct_b64 = b64url_encode(ct); ts = now_ms()
        content_sig = b64url_encode(
            sign_pss(self.PRIV, (ct_b64 + self.user_id + str(ts)).encode("utf-8"))
        )
        payload = {"ciphertext": ct_b64, "sender_pub": self.PUB_B64, "content_sig": content_sig}
        env = {"type": "MSG_PUBLIC_CHANNEL", "from": self.user_id, "to": "g-public",
               "ts": ts, "payload": payload,
               "sig": b64url_encode(sign_pss(self.PRIV, canonical_json(payload)))}
        await self.ws.send(json.dumps(env, separators=(",", ":")))

    async def send_file(self, dst_user: str, path: str):
        """Send a file as RSA-encrypted chunks (demo-friendly)."""
        if not self.ws: return
        try:
            data = Path(path).read_bytes()
        except Exception as e:
            self.error.emit(f"Read file failed: {e}"); return
        # manifest
        file_id = f"file-{now_ms()}"
        env = make_envelope("FILE_START", self.user_id, dst_user, {
            "file_id": file_id, "name": Path(path).name, "size": len(data), "sha256": "NA", "mode": "dm"
        }, self.PRIV, now_ms())
        await self.ws.send(json.dumps(env, separators=(",", ":")))

        pk_b64 = get_pubkey(self.DB, dst_user)
        if not pk_b64:
            self.info.emit("Unknown dst pubkey; ask /getpub first.")
            return
        pub = import_pub_b64url(pk_b64)
        off, idx = 0, 0
        while off < len(data):
            chunk = data[off:off+400]; off += 400; idx += 1
            ct_b64 = b64url_encode(rsa_oaep_encrypt(pub, chunk))
            env = make_envelope("FILE_CHUNK", self.user_id, dst_user,
                                {"file_id": file_id, "index": idx, "ciphertext": ct_b64},
                                self.PRIV, now_ms())
            await self.ws.send(json.dumps(env, separators=(",", ":")))
        await self.ws.send(json.dumps(
            make_envelope("FILE_END", self.user_id, dst_user, {"file_id": file_id}, self.PRIV, now_ms()),
            separators=(",", ":")
        ))

    # --- rx loop ---
    async def _rx_loop(self):
        try:
            while True:
                msg = await self.ws.recv()
                env = json.loads(msg)
                typ = env.get("type", "")
                if typ == "USER_LIST":
                    users = env["payload"]["users"]
                    self.users_updated.emit(users)
                elif typ == "PUBKEY_REPLY":
                    upsert_user(self.DB, env["payload"]["user_id"], env["payload"]["pubkey"])
                    self.info.emit(f"Pubkey stored for {env['payload']['user_id']}")
                elif typ == "USER_DELIVER":
                    try:
                        ct = b64url_decode(env["payload"]["ciphertext"])
                        pt = rsa_oaep_decrypt(self.PRIV, ct).decode("utf-8", "ignore")
                    except Exception:
                        pt = "<decrypt failed>"
                    ok = verify_pss(
                        import_pub_b64url(env["payload"]["sender_pub"]),
                        (env["payload"]["ciphertext"] + env["from"] + env["to"] + str(env["ts"])).encode("utf-8"),
                        b64url_decode(env["payload"]["content_sig"])
                    )
                    self.dm_received.emit(env["from"], pt, bool(ok))
                elif typ == "MSG_PUBLIC_CHANNEL":
                    if self.channel_priv is None:
                        self.info.emit("Got public msg but channel key not ready.")
                        continue
                    try:
                        ct = b64url_decode(env["payload"]["ciphertext"])
                        pt = rsa_oaep_decrypt(self.channel_priv, ct).decode("utf-8", "ignore")
                    except Exception:
                        pt = "<decrypt failed>"
                    ok = verify_pss(
                        import_pub_b64url(env["payload"]["sender_pub"]),
                        (env["payload"]["ciphertext"] + env["from"] + str(env["ts"])).encode("utf-8"),
                        b64url_decode(env["payload"]["content_sig"])
                    )
                    self.pub_received.emit(env["from"], pt, bool(ok))
                elif typ == "PUBLIC_CHANNEL_KEY_SHARE_USER":
                    # Install channel private key (wrapped with my pub); keep creator_pub as channel_pub
                    from Crypto.PublicKey import RSA
                    try:
                        wrapped = b64url_decode(env["payload"]["wrapped_private"])
                        pem = rsa_oaep_decrypt(self.PRIV, wrapped)
                        self.channel_priv = RSA.import_key(pem)
                        self.channel_pub = import_pub_b64url(env["payload"]["creator_pub"])
                        self.info.emit("Public channel key installed.")
                    except Exception as e:
                        self.error.emit(f"Install channel key failed: {e}")
                elif typ.startswith("USER_FILE"):
                    self.info.emit(f"File part: {typ} {env['payload']}")
                elif typ == "ERROR":
                    self.error.emit(json.dumps(env["payload"]))
                elif typ == "ACK":
                    self.info.emit("ACK: " + env["payload"].get("msg_ref",""))
                    await self.send_list()
                # ignore others for brevity
        except asyncio.CancelledError:
            pass
        except Exception as e:
            self.error.emit(f"RX loop error: {e}")
        finally:
            # connection closed
            if self.ws:
                try:
                    await self.ws.close()
                except Exception:
                    pass
            self.ws = None
            self.disconnected.emit()

# --------------------
# Qt MainWindow (GUI)
# --------------------
class ChatWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SOCP v1.3 - Desktop GUI Client")
        self.resize(980, 640)

        self.engine = SocpClient()
        self._build_ui()
        self._wire_signals()

    def _build_ui(self):
        # --- Top bar: server URL + user id + connect/disconnect
        self.edt_url = QLineEdit("ws://127.0.0.1:9000")
        self.edt_user = QLineEdit(new_uuid())  # generate a v4 for convenience
        self.btn_connect = QPushButton("Connect")
        self.btn_disconnect = QPushButton("Disconnect")
        self.btn_disconnect.setEnabled(False)

        top = QHBoxLayout()
        top.addWidget(QLabel("Server:"))
        top.addWidget(self.edt_url, 3)
        top.addWidget(QLabel("User UUID:"))
        top.addWidget(self.edt_user, 2)
        top.addWidget(self.btn_connect)
        top.addWidget(self.btn_disconnect)

        # --- Left: online users
        self.lst_users = QListWidget()
        self.lst_users.setMinimumWidth(220)
        self.lst_users.setSelectionMode(QAbstractItemView.SingleSelection)

        # --- Right: chat log + input + buttons
        self.txt_log = QTextEdit()
        self.txt_log.setReadOnly(True)

        self.edt_input = QLineEdit()
        self.btn_send_dm = QPushButton("Send DM")
        self.btn_send_pub = QPushButton("Send /all")
        self.btn_file = QPushButton("Send File")

        input_row = QHBoxLayout()
        input_row.addWidget(self.edt_input, 5)
        input_row.addWidget(self.btn_send_dm)
        input_row.addWidget(self.btn_send_pub)
        input_row.addWidget(self.btn_file)

        right = QVBoxLayout()
        right.addWidget(self.txt_log, 6)
        right.addLayout(input_row)

        # --- Layout with splitter
        splitter = QSplitter()
        lw = QWidget(); lw.setLayout(QVBoxLayout()); lw.layout().addWidget(QLabel("Online Users")); lw.layout().addWidget(self.lst_users)
        rw = QWidget(); rw.setLayout(right)
        splitter.addWidget(lw); splitter.addWidget(rw)
        splitter.setStretchFactor(1, 1)

        root = QVBoxLayout()
        root.addLayout(top)
        root.addWidget(splitter)

        wrapper = QWidget(); wrapper.setLayout(root)
        self.setCentralWidget(wrapper)

    def _wire_signals(self):
        # Engine <-> UI
        self.engine.connected.connect(lambda: self._append("[info] Connected."))
        self.engine.disconnected.connect(lambda: self._append("[info] Disconnected."))
        self.engine.error.connect(lambda s: self._append(f"[error] {s}"))
        self.engine.info.connect(lambda s: self._append(f"[info] {s}"))
        self.engine.users_updated.connect(self._update_users)
        self.engine.dm_received.connect(self._on_dm)
        self.engine.pub_received.connect(self._on_pub)

        # Buttons
        self.btn_connect.clicked.connect(self._on_connect_clicked)
        self.btn_disconnect.clicked.connect(self._on_disconnect_clicked)
        self.btn_send_dm.clicked.connect(self._on_send_dm)
        self.btn_send_pub.clicked.connect(self._on_send_pub)
        self.btn_file.clicked.connect(self._on_send_file)

    def _append(self, line: str):
        self.txt_log.append(line)

    def _update_users(self, users: list):
        self.lst_users.clear()
        for u in users:
            self.lst_users.addItem(u)

    def _on_dm(self, sender: str, text: str, ok: bool):
        self._append(f"<DM {sender}> {text} [{'OK' if ok else 'BAD_SIG'}]")

    def _on_pub(self, sender: str, text: str, ok: bool):
        self._append(f"[Public] {sender}: {text} [{'OK' if ok else 'BAD_SIG'}]")

    # --- UI actions ---
    def _on_connect_clicked(self):
        url = self.edt_url.text().strip()
        uid = self.edt_user.text().strip()
        if not url or not uid:
            QMessageBox.warning(self, "Oops", "Please fill server URL and UUID v4.")
            return
        self.btn_connect.setEnabled(False)
        self.btn_disconnect.setEnabled(True)
        # async connect (qasync ensures this runs on asyncio loop)
        self.engine.connect_to(url, uid)

        # Query /list after connected (small delay)
        asyncio.get_event_loop().call_later(0.8, lambda: asyncio.create_task(self.engine.send_list()))

    def _on_disconnect_clicked(self):
        self.btn_disconnect.setEnabled(False)
        self.btn_connect.setEnabled(True)
        asyncio.create_task(self.engine.disconnect())

    def _pick_selected_user(self) -> str | None:
        item = self.lst_users.currentItem()
        if not item: return None
        return item.text().strip()

    def _on_send_dm(self):
        dst = self._pick_selected_user()
        if not dst:
            QMessageBox.information(self, "Select user", "Pick a user from the list (left) first.")
            return
        text = self.edt_input.text()
        if not text.strip(): return
        asyncio.create_task(self.engine.send_dm(dst, text))
        self.edt_input.clear()

    def _on_send_pub(self):
        text = self.edt_input.text()
        if not text.strip(): return
        asyncio.create_task(self.engine.send_public(text))
        self.edt_input.clear()

    def _on_send_file(self):
        dst = self._pick_selected_user()
        if not dst:
            QMessageBox.information(self, "Select user", "Pick a user from the list (left) first.")
            return
        path, _ = QFileDialog.getOpenFileName(self, "Choose a file to send")
        if not path: return
        asyncio.create_task(self.engine.send_file(dst, path))


# ---------------
# App bootstrap
# ---------------
if __name__ == "__main__":
    import contextlib
    app = QApplication(sys.argv)
    loop = QEventLoop(app)
    asyncio.set_event_loop(loop)
    win = ChatWindow()
    win.show()
    with loop:
        loop.run_forever()
