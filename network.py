# network.py - WebSocket transport, handshake, and optional NAT (UPnP).
# Default behavior: UPnP is DISABLED; enable it only by setting CHAT_USE_UPNP=1.
# Handshake is text-only:
#   client -> server:  <PEM public key>
#   server -> client:  SESSKEY:<base64(RSA_encrypt(session_aes_key))>
#   client -> server:  NAME:<username>
# After that, both sides exchange AES-encrypted text frames (base64 strings).
#
# Notes:
# - Keep all Qt networking calls on the Qt thread (call connect_to_peer from GUI/Qt thread).
# - Zeroconf callbacks happen on their own thread; make sure to bounce into Qt thread before dialing.

from PySide6.QtWebSockets import QWebSocketServer, QWebSocket
from PySide6.QtNetwork import QHostAddress
from PySide6.QtCore import QObject, Signal, Slot, QUrl
from Crypto.PublicKey import RSA
from crypto import generate_rsa_keypair, rsa_encrypt, rsa_decrypt, generate_aes_key
import base64
import os

# ------------------------------
# Per-peer connection wrapper
# ------------------------------
class PeerConnection(QObject):
    """Wraps a QWebSocket and an AES session key; exposes 'send_text' and 'send_file' APIs."""
    message_received = Signal(str, str)           # (from_peer, message_text)
    file_received = Signal(str, bytes, str)       # (from_peer, file_bytes, filename)

    def __init__(self, socket: QWebSocket, peer_name: str, aes_key: bytes, parent=None):
        super().__init__(parent)
        self.socket = socket
        self.peer_name = peer_name or "UnknownPeer"
        self.aes_key = aes_key

        # Hook raw WS signals to our handlers
        self.socket.textMessageReceived.connect(self._on_text_msg)
        self.socket.disconnected.connect(self._on_disconnected)

    def send_text(self, text: str):
        # Encrypt with AES (returns base64 text) and ship it out.
        from crypto import aes_encrypt
        encrypted = aes_encrypt(self.aes_key, text)
        self.socket.sendTextMessage(encrypted)

    def send_file(self, file_bytes: bytes, filename: str):
        # Package files as: "FILE:<filename>:<base64-raw-bytes>" and encrypt the WHOLE string.
        from crypto import aes_encrypt
        b64 = base64.b64encode(file_bytes).decode("ascii")
        payload = f"FILE:{filename}:{b64}"
        encrypted = aes_encrypt(self.aes_key, payload)
        self.socket.sendTextMessage(encrypted)

    @Slot(str)
    def _on_text_msg(self, encrypted_msg: str):
        # Some plaintext control frames (during/around handshake) may still appear on this socket.
        # Ignore anything that is obviously not an AES-encrypted/base64 payload.
        if encrypted_msg.startswith(("NAME:", "SESSKEY:", "-----BEGIN ")):
            return

        from crypto import aes_decrypt
        try:
            plaintext = aes_decrypt(self.aes_key, encrypted_msg)
        except Exception as e:
            # Not a valid base64/AES payload -> drop quietly (handoff to server/client handshake handlers)
            print("[peer] drop non-AES text:", encrypted_msg[:32], e)
            return

        if isinstance(plaintext, bytes):
            try:
                plaintext = plaintext.decode("utf-8", errors="ignore")
            except Exception:
                plaintext = ""

        # File payload?
        if isinstance(plaintext, str) and plaintext.startswith("FILE:"):
            try:
                _, fname, b64 = plaintext.split(":", 2)
                raw = base64.b64decode(b64.encode("ascii"))
                self.file_received.emit(self.peer_name, raw, fname)
            except Exception:
                return
        else:
            self.message_received.emit(self.peer_name, str(plaintext))

        # File payload?
        if isinstance(plaintext, str) and plaintext.startswith("FILE:"):
            # Format: FILE:<filename>:<base64>
            try:
                _, fname, b64 = plaintext.split(":", 2)
                raw = base64.b64decode(b64.encode("ascii"))
                self.file_received.emit(self.peer_name, raw, fname)
            except Exception:
                # ignore malformed payloads
                return
        else:
            # Normal chat message.
            self.message_received.emit(self.peer_name, str(plaintext))

    def _on_disconnected(self):
        # Socket closed; clean up.
        try:
            self.socket.deleteLater()
        except Exception:
            pass


# ------------------------------
# Network manager: server + dialer + handshake + (optional) UPnP
# ------------------------------
class NetworkManager(QObject):
    """Owns the WS server, outgoing dials, handshake state, and a map of active PeerConnections."""
    new_connection = Signal(PeerConnection)   # Emitted right after a PeerConnection is created
    connection_labeled = Signal(str)

    def __init__(self, listen_port: int, local_name: str = "", use_upnp: bool | None = None, parent=None):
        super().__init__(parent)
        self.listen_port = listen_port
        self.local_name = local_name or ""
        self.server = QWebSocketServer("ChatServer", QWebSocketServer.NonSecureMode)
        self.connections = {}          # name -> PeerConnection
        self._socket_to_conn = {}      # QWebSocket -> PeerConnection
        self._pending = {}             # QWebSocket -> {"aes_key": bytes|None, "peer_name": str|None}
        self.external_port = None      # filled only if UPnP succeeds

        # RSA identity for this node (used to unwrap AES)
        self.priv_key, self.pub_key = generate_rsa_keypair()

        # Listen on all IPv4 addresses
        if not self.server.listen(QHostAddress.AnyIPv4, self.listen_port):
            # 如果请求的端口（如 9000）占用，则回退到 0 让系统分配空闲端口
            if not self.server.listen(QHostAddress.AnyIPv4, 0):
                raise RuntimeError(f"Failed to open port {self.listen_port} for WebSocket server.")
            # 记录系统实际分配的端口
            self.listen_port = self.server.serverPort()
            print(f"[net] requested port busy; using {self.listen_port} instead")
        else:
            print(f"[net] listening on 0.0.0.0:{self.listen_port}")

        self.server.newConnection.connect(self._handle_new_connection)

        print(f"[net] listening on 0.0.0.0:{self.listen_port}")

        # UPnP toggle: default OFF; enable only if CHAT_USE_UPNP=1 (or pass use_upnp=True) ---
        if use_upnp is None:
            env_flag = os.getenv("CHAT_USE_UPNP", "0").lower()
            self.use_upnp = env_flag in ("1", "true", "yes", "on")
        else:
            self.use_upnp = bool(use_upnp)

        if self.use_upnp:
            self._setup_upnp()
        else:
            print("[UPnP] disabled (LAN mode). Set CHAT_USE_UPNP=1 to enable.")

    # Public API -------------

    def connect_to_peer(self, peer_name: str, host: str, port: int):
        """Dial out to a discovered peer (host:port). Call this from the Qt thread."""
        sock = QWebSocket()
        # Keep temporary state for this socket until handshake completes
        self._pending[sock] = {"aes_key": None, "peer_name": peer_name or None}

        sock.connected.connect(lambda: self._on_client_connected(sock))
        sock.textMessageReceived.connect(lambda msg: self._on_client_text(sock, msg))
        sock.disconnected.connect(lambda: self._cleanup_socket(sock))

        sock.errorOccurred.connect(lambda err: print("[dial] error:", err, "-", sock.errorString()))
        sock.stateChanged.connect(lambda st: print("[dial] state:", st))

        url = QUrl(f"ws://{host}:{port}")
        print(f"[dial] connecting to {peer_name or host} at {url.toString()} ...")
        sock.open(url)

    # ------------- Server side -------------

    def _handle_new_connection(self):
        client_sock = self.server.nextPendingConnection()
        # Initialize pending state for handshake
        self._pending[client_sock] = {"aes_key": None, "peer_name": None}

        client_sock.textMessageReceived.connect(lambda msg: self._on_server_text(client_sock, msg))
        client_sock.disconnected.connect(lambda: self._cleanup_socket(client_sock))
        print("[server] incoming socket accepted")

    def _on_server_text(self, sock: QWebSocket, msg: str):
        """Server-side: handle client's first messages (PEM, then NAME)."""
        state = self._pending.get(sock, {"aes_key": None, "peer_name": None})

        # 1) First expected message is the client's PEM public key.
        if msg.startswith("-----BEGIN PUBLIC KEY-----"):
            try:
                client_pub = RSA.import_key(msg.encode("utf-8"))
            except Exception as e:
                print("[server] invalid client public key:", e)
                sock.close()
                return
            # Create fresh AES key for this connection, encrypt it with client's RSA pub
            aes_key = generate_aes_key()
            enc = rsa_encrypt(client_pub, aes_key)
            b64 = base64.b64encode(enc).decode("ascii")
            sock.sendTextMessage("SESSKEY:" + b64)
            print("[server] sent SESSKEY to client")
            # Stash AES and also create a PeerConnection (name may be unknown yet)
            state["aes_key"] = aes_key
            self._pending[sock] = state
            conn = PeerConnection(sock, "UnknownPeer", aes_key)
            self._socket_to_conn[sock] = conn
            self._insert_connection("UnknownPeer", conn)
            self.new_connection.emit(conn)
            return

        # 2) Next expected message is "NAME:<peername>"
        if msg.startswith("NAME:"):
            name = msg.split(":", 1)[1].strip() or "UnknownPeer"
            state["peer_name"] = name
            self._pending[sock] = state
            conn = self._socket_to_conn.get(sock)
            if conn:
                self._rename_connection(conn, name)
            print("[server] peer is:", name)
            return

        # 3) Anything else is likely encrypted chat traffic; PeerConnection will handle it.

    # Client side -------------

    def _on_client_connected(self, sock: QWebSocket):
        """Client-side: send our PEM public key as the very first message."""
        pem = self.pub_key.export_key().decode("utf-8")
        sock.sendTextMessage(pem)
        print("[client] connected, sent PEM")

    def _on_client_text(self, sock: QWebSocket, msg: str):
        """Client-side: handle 'SESSKEY:<b64>' and 'NAME:<peer>' (rare) from server."""
        state = self._pending.get(sock, {"aes_key": None, "peer_name": None})

        if msg.startswith("SESSKEY:"):
            b64 = msg.split(":", 1)[1]
            try:
                enc = base64.b64decode(b64.encode("ascii"))
                aes_key = rsa_decrypt(self.priv_key, enc)
            except Exception as e:
                print("[client] failed to decrypt session key:", e)
                sock.close()
                return
            state["aes_key"] = aes_key
            self._pending[sock] = state
            # Create PeerConnection and announce our name
            conn = PeerConnection(sock, state.get("peer_name") or "UnknownPeer", aes_key)
            self._socket_to_conn[sock] = conn
            self._insert_connection(conn.peer_name, conn)
            self.new_connection.emit(conn)
            if self.local_name:
                sock.sendTextMessage(f"NAME:{self.local_name}")
                print("[client] AES ready; sent NAME:", self.local_name)
            return

        if msg.startswith("NAME:"):
            # Server shouldn't need to send this normally, but if it does, update mapping.
            name = msg.split(":", 1)[1].strip() or "UnknownPeer"
            state["peer_name"] = name
            self._pending[sock] = state
            conn = self._socket_to_conn.get(sock)
            if conn:
                self._rename_connection(conn, name)
            print("[client] server advertised NAME:", name)
            return

        # Otherwise it's encrypted chat/file text, handled by PeerConnection; ignore here.

    # ------------- Helpers -------------

    def _insert_connection(self, name: str, conn: PeerConnection):
        """Insert or label a connection. If a final (non-UnknownPeer) name already exists,
        close the newer duplicate instead of suffixing."""
        base = name or "UnknownPeer"

        # 对最终用户名（非 UnknownPeer）执行去重：已存在就关闭“新来的”
        if base != "UnknownPeer":
            existing = self.connections.get(base)
            if existing is not None and existing is not conn:
                print(f"[net] duplicate connection to '{base}' detected; closing newer socket")
                try:
                    conn.socket.close()  # 断开新连接；_cleanup_socket 会收尾
                except Exception:
                    pass
                return

            # 没有冲突，正常登记
            conn.peer_name = base
            self.connections[base] = conn
            print(f"[net] connection labeled as '{base}'")
            self.connection_labeled.emit(base)
            return

        # 对 UnknownPeer，允许暂存多条（稍后会被重命名/清理）
        final = base
        i = 2
        while final in self.connections and self.connections[final] is not conn:
            final = f"{base}-{i}"
            i += 1
        conn.peer_name = final
        self.connections[final] = conn
        print(f"[net] connection labeled as '{final}'")

        self.connection_labeled.emit(final)

    def _rename_connection(self, conn: PeerConnection, new_name: str):
        """Rename a connection's dictionary key safely, with de-duplication by name."""
        # 先把旧 key 删掉（可能是 UnknownPeer 或带后缀）
        for k, v in list(self.connections.items()):
            if v is conn:
                del self.connections[k]
                break
        # 再按新名字插入（_insert_connection 会做去重：若已有同名则关闭本连接）
        self._insert_connection(new_name, conn)

    def _cleanup_socket(self, sock: QWebSocket):
        """On disconnect, drop all state and mapping for this socket."""
        if sock in self._pending:
            del self._pending[sock]
        conn = self._socket_to_conn.pop(sock, None)
        if conn:
            for k, v in list(self.connections.items()):
                if v is conn:
                    del self.connections[k]
                    break
            try:
                conn.deleteLater()
            except Exception:
                pass
        try:
            sock.deleteLater()
        except Exception:
            pass
        print("[net] socket cleaned up")

    def _setup_upnp(self):
        """Try to create a TCP port mapping via UPnP; ignore if unsupported."""
        try:
            # Import here so users who don't install miniupnpc are fine when UPnP is off.
            import miniupnpc
            upnp = miniupnpc.UPnP()
            upnp.discoverdelay = 200
            ndev = upnp.discover()
            if ndev == 0:
                print("[UPnP] no IGD discovered; skipping.")
                return
            upnp.selectigd()
            local_ip = upnp.lanaddr
            external_ip = upnp.externalipaddress()

            # Try to map the same external port as our listen_port
            preferred = int(self.listen_port)

            def mapping_of(port: int):
                try:
                    return upnp.getspecificportmapping(port, 'TCP')
                except Exception:
                    return None

            # If mapped to us already, reuse
            m = mapping_of(preferred)
            if m:
                # Defensive parsing across miniupnpc versions
                internal_client = None
                internal_port = None
                try:
                    if isinstance(m, (list, tuple)):
                        internal_client = m[0]
                        internal_port = int(m[1]) if len(m) > 1 else None
                    elif hasattr(m, "internalClient"):
                        internal_client = getattr(m, "internalClient", None)
                        internal_port = int(getattr(m, "internalPort", 0))
                except Exception:
                    pass
                if internal_client == local_ip and internal_port == preferred:
                    self.external_port = preferred
                    print(f"[UPnP] port {preferred} already mapped to me. External IP: {external_ip}")
                    return
                else:
                    # Try to reclaim by deleting
                    try:
                        upnp.deleteportmapping(preferred, 'TCP')
                        print(f"[UPnP] removed conflicting mapping on {preferred}")
                    except Exception as e:
                        print(f"[UPnP] cannot remove conflicting mapping on {preferred}: {e}")

            try:
                ok = upnp.addportmapping(preferred, 'TCP', local_ip, self.listen_port, 'P2PChat', '')
                if ok:
                    self.external_port = preferred
                    print(f"[UPnP] mapped {preferred} -> {local_ip}:{self.listen_port}. External IP: {external_ip}")
                    return
            except Exception as e:
                print(f"[UPnP] addportmapping({preferred}) failed: {e}")

            # Fallback
            # scan a tiny range for a free external port
            for ext in range(self.listen_port, self.listen_port + 21):
                if ext == preferred:
                    continue
                if mapping_of(ext):
                    continue
                try:
                    ok = upnp.addportmapping(ext, 'TCP', local_ip, self.listen_port, 'P2PChat', '')
                    if ok:
                        self.external_port = ext
                        print(f"[UPnP] mapped {ext} -> {local_ip}:{self.listen_port}. External IP: {external_ip}")
                        return
                except Exception as e:
                    print(f"[UPnP] addportmapping({ext}) failed: {e}")
                    continue

            print("[UPnP] unable to map any external port; continuing without UPnP.")
            self.external_port = None

        except Exception as e:
            print("[UPnP] port forwarding not available:", e)
            self.external_port = None
