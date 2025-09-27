# discovery.py
#
# Zeroconf (mDNS) advertise + browse with update_service support
from zeroconf import Zeroconf, ServiceInfo, ServiceBrowser
import socket

SERVICE_TYPE = "_p2pchat._tcp.local."
zeroconf = Zeroconf()

def _get_local_ip() -> str:
    """Best-effort to get a usable local IPv4 (not 127.x)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"
    finally:
        s.close()

def register_service(peer_name: str, port: int):
    """Advertise our chat service on mDNS."""
    hostname = socket.gethostname()
    ip_addr = _get_local_ip()
    info = ServiceInfo(
        SERVICE_TYPE,
        f"{peer_name}.{SERVICE_TYPE}",
        addresses=[socket.inet_aton(ip_addr)],
        port=port,
        properties={"peer_name": peer_name},
        server=f"{hostname}.local."
    )
    zeroconf.register_service(info)
    return info

class ChatServiceListener:
    """Listener that notifies when peers appear/update/disappear."""
    def __init__(self, on_peer_found, on_peer_removed=None):
        self.on_peer_found = on_peer_found
        self.on_peer_removed = on_peer_removed

    def add_service(self, zc: Zeroconf, type_: str, name: str):
        info = zc.get_service_info(type_, name)
        if not info or not info.addresses:
            return
        try:
            addr = socket.inet_ntoa(info.addresses[0])
            port = info.port
            # prefer property
            # fall back to service instance name
            peer_name = info.properties.get(b"peer_name", b"").decode("utf-8") or name.split(".", 1)[0]
            if self.on_peer_found:
                self.on_peer_found(peer_name, addr, port)
        except Exception:
            # swallow malformed entries safely
            pass

    def update_service(self, zc: Zeroconf, type_: str, name: str):
        # Treat updates same as add: re-fetch info and notify.
        self.add_service(zc, type_, name)

    def remove_service(self, zc: Zeroconf, type_: str, name: str):
        if self.on_peer_removed:
            try:
                peer_name = name.split(".", 1)[0]
                self.on_peer_removed(peer_name)
            except Exception:
                pass

def start_discovery(on_peer_found, on_peer_removed=None):
    """Start browsing peers; keep and return the browser so it isn't GC'd."""
    listener = ChatServiceListener(on_peer_found, on_peer_removed)
    browser = ServiceBrowser(zeroconf, SERVICE_TYPE, listener)
    return browser
