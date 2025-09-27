# chat.py
# High-level chat logic gluing discovery + network to the GUI.
from PySide6.QtCore import QObject, Signal
from network import NetworkManager
from discovery import register_service, start_discovery
import os

class ChatSystem(QObject):
    # GUI cares about these:
    user_joined = Signal(str)
    user_left = Signal(str)
    message_received = Signal(str, str)        # (from_user, message_text)
    file_received = Signal(str, bytes, str)    # (from_user, file_bytes, filename)

    # NEW: thread-safe dial request (name, host, port); emitted from Zeroconf thread,
    # handled in Qt (GUI) thread.
    dial_request = Signal(str, str, int)

    def __init__(self, local_username: str, listen_port: int):
        super().__init__()
        self.local_username = local_username

        # Transport (WS server + RSA + optional UPnP off by default)
        self.network = NetworkManager(listen_port, local_name=local_username)
        self.network.new_connection.connect(self._on_new_connection)

        # If your network.py added connection_labeled signal, you can surface names to GUI:
        try:
            self.network.connection_labeled.connect(self._on_conn_labeled)  # optional
        except Exception:
            pass

        # Zeroconf: register and browse. IMPORTANT: register with the *actual* listen port,
        # in case NetworkManager fell back to a random free port.
        self._service = register_service(local_username, self.network.listen_port)
        self._browser = start_discovery(self._on_peer_found)  # keep a ref to avoid GC

        # Connect the cross-thread dial signal to a slot that runs on the Qt thread.
        self.dial_request.connect(self._dial_peer)

        # (Optional) manual dial via env var, handy for debugging without mDNS
        manual = os.environ.get("CHAT_PEER")  # e.g. "192.168.0.23:9000"
        if manual:
            host, port = manual.split(":")
            self.dial_request.emit("ManualPeer", host, int(port))

        self._dialed_endpoints = set()  # {(host, port)}

    # discovery callbacks

    def _on_peer_found(self, peer_name: str, addr: str, port: int):
        """Called by Zeroconf thread when a peer is found. Do NOT touch Qt here.
        Just emit a signal; Qt will queue it to our thread safely."""
        if peer_name == self.local_username:
            return
        print(f"[mdns] found {peer_name} @ {addr}:{port}")
        # queue to GUI thread
        #try:
           # self.dial_request.emit(peer_name, addr, int(port))
        #except Exception:
            # be defensive if port is already int
           # self.dial_request.emit(peer_name, addr, port)

        # 只有本地用户名 < 对端用户名时，才由我来拨号；否则我只被动接入
        if self.local_username < peer_name:
            print(f"[mdns] found {peer_name} @ {addr}:{port} (I will dial)")
            self.dial_request.emit(peer_name, addr, int(port))
        else:
            print(f"[mdns] found {peer_name} @ {addr}:{port} (I will wait)")

    def _dial_peer(self, peer_name: str, host: str, port: int):
        key = (host, int(port))
        if key in self._dialed_endpoints:
            print("[dial] skip duplicate", key)
            return
        self._dialed_endpoints.add(key)
        self.network.connect_to_peer(peer_name, host, int(port))

    def _on_new_connection(self, peer_conn):
        """When a new (possibly not-yet-named) encrypted connection is created."""
        if getattr(peer_conn, "peer_name", None) and peer_conn.peer_name != "UnknownPeer":
            self.user_joined.emit(peer_conn.peer_name)
        peer_conn.message_received.connect(self.message_received)
        peer_conn.file_received.connect(self.file_received)

    def _on_conn_labeled(self, name: str):
        """If network layer reports a final/updated label, surface it to GUI."""
        if name and name != "UnknownPeer" and name != self.local_username:
            self.user_joined.emit(name)

    # ---- send APIs ----

    def send_message(self, target: str, text: str):
        if not text:
            return
        if target == "ALL":
            for name, conn in list(self.network.connections.items()):
                conn.send_text(f"[{self.local_username}]: {text}")
                # intentional classroom backdoor: plaintext logging (do not keep in real apps)
                try:
                    with open("chat_logs.txt", "a", encoding="utf-8") as logf:
                        logf.write(f"(broadcast) {self.local_username}->{name}: {text}\n")
                except Exception:
                    pass
            return
        conn = self.network.connections.get(target)
        if conn:
            conn.send_text(f"[{self.local_username} -> {target}]: {text}")
            try:
                with open("chat_logs.txt", "a", encoding="utf-8") as logf:
                    logf.write(f"(private) {self.local_username}->{target}: {text}\n")
            except Exception:
                pass

    def send_file(self, target: str, file_path: str):
        if not file_path or not os.path.exists(file_path):
            return False, "File not found."
        try:
            with open(file_path, "rb") as f:
                data = f.read()
        except Exception as e:
            return False, f"Failed to read file: {e}"
        filename = os.path.basename(file_path)
        if target == "ALL":
            for _, conn in list(self.network.connections.items()):
                conn.send_file(data, filename)
            return True, "File broadcast."
        conn = self.network.connections.get(target)
        if conn:
            conn.send_file(data, filename)
            return True, "File sent."
        return False, "Target not connected."
