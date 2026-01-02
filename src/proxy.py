# TODO: implement a TCP-based HTTP forward proxy with blocking and logging
import socket
import threading
from datetime import datetime
from pathlib import Path

LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 8888

BLOCKLIST_PATH = Path("config/blocked_domains.txt")
LOG_PATH = Path("logs/proxy.log")

MAX_HEADER = 64 * 1024  # 64 KB
TIMEOUT = 10


def load_blocklist():
    if not BLOCKLIST_PATH.exists():
        return set()
    blocked = set()
    for line in BLOCKLIST_PATH.read_text(encoding="utf-8", errors="ignore").splitlines():
        s = line.strip().lower()
        if not s or s.startswith("#"):
            continue
        blocked.add(s)
    return blocked


def log(msg: str) -> None:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with LOG_PATH.open("a", encoding="utf-8") as f:
        f.write(msg + "\n")


def recv_until(sock: socket.socket, marker: bytes) -> bytes:
    data = b""
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
        if len(data) > MAX_HEADER:
            raise ValueError("Headers too large")
    return data


def parse_request(headers_blob: bytes):
    # returns: method, target, version, headers_dict, body_start
    head, body_start = (headers_blob.split(b"\r\n\r\n", 1) + [b""])[:2]
    lines = head.split(b"\r\n")
    if not lines:
        raise ValueError("Empty request")

    method, target, version = lines[0].decode("iso-8859-1").split(" ", 2)

    headers = {}
    for ln in lines[1:]:
        if b":" in ln:
            k, v = ln.split(b":", 1)
            headers[k.decode("iso-8859-1").strip().lower()] = v.decode("iso-8859-1").strip()

    return method, target, version, headers, body_start


def extract_host_port_path(method: str, target: str, headers: dict):
    # Supports absolute URI and relative + Host
    if method.upper() == "CONNECT":
        raise NotImplementedError("CONNECT not implemented in this basic version (HTTP only).")

    target = target.strip()
    host = ""
    port = 80
    path = target

    if target.startswith("http://") or target.startswith("https://"):
        scheme_sep = target.find("://")
        rest = target[scheme_sep + 3 :]
        slash = rest.find("/")
        hostport = rest if slash == -1 else rest[:slash]
        path = "/" if slash == -1 else rest[slash:]

        if ":" in hostport:
            host, p = hostport.split(":", 1)
            port = int(p)
        else:
            host = hostport
            port = 80
    else:
        host_hdr = headers.get("host", "")
        if not host_hdr:
            raise ValueError("No Host header")
        if ":" in host_hdr:
            host, p = host_hdr.rsplit(":", 1)
            port = int(p)
        else:
            host = host_hdr
            port = 80

    return host.lower().strip(), port, path


def is_blocked(host: str, blocked: set[str]) -> bool:
    h = host.lower().strip()
    if h in blocked:
        return True
    # suffix match: block example.com also blocks a.example.com
    for b in blocked:
        if h == b or h.endswith("." + b):
            return True
    return False


def send_error(client: socket.socket, code: int, msg: str):
    body = f"{code} {msg}\n".encode()
    resp = (
        f"HTTP/1.1 {code} {msg}\r\n"
        f"Content-Type: text/plain; charset=utf-8\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode() + body
    client.sendall(resp)


def handle_client(client: socket.socket, addr):
    client.settimeout(TIMEOUT)
    blocked = load_blocklist()

    client_ip, client_port = addr
    start = datetime.utcnow().isoformat() + "Z"

    dest = "-"
    action = "allowed"
    status = "-"
    up = 0
    down = 0

    server = None
    try:
        raw = recv_until(client, b"\r\n\r\n")
        method, target, version, headers, body_start = parse_request(raw)
        host, port, path = extract_host_port_path(method, target, headers)
        dest = f"{host}:{port}"

        if is_blocked(host, blocked):
            action = "blocked"
            status = "403"
            send_error(client, 403, "Forbidden")
            return

        # connect destination
        server = socket.create_connection((host, port), timeout=TIMEOUT)
        server.settimeout(TIMEOUT)

        # rewrite request line to origin form (path)
        req_line = f"{method} {path} {version}\r\n".encode("iso-8859-1")
        # rebuild headers, drop Proxy-Connection, force Connection: close
        out = []
        for k, v in headers.items():
            if k in ("proxy-connection", "connection"):
                continue
            out.append(f"{k}: {v}\r\n".encode("iso-8859-1"))
        out.append(b"Connection: close\r\n")
        out.append(b"\r\n")

        req = req_line + b"".join(out)
        server.sendall(req)
        up += len(req)

        # (basic) forward any body already present (for GET usually none)
        if body_start:
            server.sendall(body_start)
            up += len(body_start)

        # stream response back
        first = server.recv(8192)
        if first:
            if first.startswith(b"HTTP/"):
                status = first.split(b" ", 2)[1].decode("iso-8859-1", errors="ignore")
            client.sendall(first)
            down += len(first)

        while True:
            chunk = server.recv(8192)
            if not chunk:
                break
            client.sendall(chunk)
            down += len(chunk)

    except NotImplementedError:
        action = "error"
        status = "501"
        try:
            send_error(client, 501, "Not Implemented")
        except Exception:
            pass
    except Exception:
        action = "error"
        status = "502"
        try:
            send_error(client, 502, "Bad Gateway")
        except Exception:
            pass
    finally:
        end = datetime.utcnow().isoformat() + "Z"
        log(
            f"{start} client={client_ip}:{client_port} dest={dest} "
            f"action={action} status={status} up={up} down={down} end={end}"
        )
        try:
            client.close()
        except Exception:
            pass
        if server:
            try:
                server.close()
            except Exception:
                pass


def main():
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((LISTEN_HOST, LISTEN_PORT))
    s.listen(100)

    print(f"Proxy running on {LISTEN_HOST}:{LISTEN_PORT}")
    print("Test: curl -x http://127.0.0.1:8888 http://example.com")

    while True:
        client, addr = s.accept()
        t = threading.Thread(target=handle_client, args=(client, addr), daemon=True)
        t.start()


if __name__ == "__main__":
    main()


