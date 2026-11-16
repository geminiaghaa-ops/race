#!/usr/bin/env python3
"""
race.py - Send multiple raw HTTP requests concurrently to test race conditions.

Two engines are available:

  1) HTTP/2 Single-Packet Attack  (--engine http2, or auto when the server speaks h2)
     A faithful implementation of the single-packet attack (PortSwigger research):
       a) The connection is warmed up first (preface + SETTINGS are sent and the
          server's SETTINGS frame is received and ACKed) so the HTTP/2 handshake is
          already complete before the timing-critical packet is sent.
       b) For every request, all frames are sent EXCEPT the final frame (the last
          byte of the body, or - for a body-less request - an empty END_STREAM
          DATA frame).
       c) Finally, only the withheld final frames of every stream are flushed in a
          single sendall(). Because they leave in one TCP packet, all requests are
          completed on the server at essentially the same instant -> near-zero jitter.
     Request size/count no longer matters: the timing packet is always a single packet.

  2) HTTP/1.1 Last-Byte Sync  (--engine http1, automatic fallback when h2 is absent)
     Each request uses its own connection. Every connection sends all but the last
     byte, waits on a barrier until all are ready, then fires the last byte together.

Requirement for the HTTP/2 engine:
    pip install h2

Typical usage:
    # Fire the same request 30 times at once (last-byte or single-packet):
    python race.py --tls --repeat 30 request.txt

    # Templated brute force: one request per wordlist entry, shared session/csrf:
    python race.py --tls --wordlist passwords.txt --prime /login login.tmpl

    # Explicit engine / host:
    python race.py --tls --engine http2 req1.txt req2.txt
    python race.py --host target.com --port 8443 --tls req1.txt req2.txt

How to capture a request:
    In Burp, right-click the request -> "Copy to file" (or paste the raw text into a
    .txt file). The file must start with the request line, e.g. "POST /login HTTP/1.1".

Template placeholders (used with --wordlist and/or --prime):
    §§            -> replaced with each wordlist entry (change with --marker)
    {{SESSION}}   -> replaced with the session cookie value fetched by --prime
    {{CSRF}}      -> replaced with the CSRF token fetched by --prime
"""

import argparse
import http.client
import os
import re
import socket
import ssl
import sys
import threading
import time

try:
    import h2.connection
    import h2.config
    import h2.events
    import h2.exceptions
    HAVE_H2 = True
except ImportError:
    HAVE_H2 = False


# ---------------------------------------------------------------------------
# Raw request parsing / normalization
# ---------------------------------------------------------------------------

def load_raw(path):
    with open(path, "rb") as f:
        return f.read()


def normalize_crlf(data: bytes) -> bytes:
    text = data.decode("utf-8", errors="ignore")
    text = text.replace("\r\n", "\n").replace("\n", "\r\n")
    return text.encode("utf-8")


def extract_host(data: bytes):
    m = re.search(rb"^Host:\s*(.+?)\r?$", data, re.MULTILINE | re.IGNORECASE)
    return m.group(1).decode().strip() if m else None


def fix_content_length(data: bytes) -> bytes:
    """Recompute the Content-Length header to match the actual body length."""
    if b"\r\n\r\n" not in data:
        return data
    head, body = data.split(b"\r\n\r\n", 1)
    if re.search(rb"content-length:", head, re.IGNORECASE) is None:
        return data
    new_head = re.sub(
        rb"(?i)(content-length:\s*)\d+",
        lambda m: m.group(1) + str(len(body)).encode(),
        head,
    )
    return new_head + b"\r\n\r\n" + body


def parse_raw_request(data: bytes):
    """Raw HTTP/1.1 -> (method, path, host_header, headers_list, body) for HTTP/2."""
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    request_line = lines[0].decode(errors="ignore")
    parts = request_line.split(" ")
    if len(parts) < 2:
        raise ValueError(f"Invalid request line: {request_line!r}")
    method, path = parts[0], parts[1]
    headers = []
    host = None
    # Connection-specific headers are illegal in HTTP/2; Host/Content-Length are
    # replaced by pseudo-headers / computed automatically.
    skip = {"connection", "keep-alive", "transfer-encoding", "upgrade",
            "proxy-connection", "host", "content-length"}
    for line in lines[1:]:
        if not line:
            continue
        name, _, value = line.partition(b":")
        name_s = name.decode(errors="ignore").strip()
        value_s = value.decode(errors="ignore").strip()
        if name_s.lower() == "host":
            host = value_s
        if name_s.lower() in skip:
            continue
        headers.append((name_s.lower(), value_s))
    return method, path, host, headers, body


# ---------------------------------------------------------------------------
# Priming: fetch a fresh session cookie + CSRF token
# ---------------------------------------------------------------------------

def prime_session(host, port, use_tls, path, cookie_name, csrf_field, timeout):
    """GET `path` once and extract (session_cookie_value, csrf_token)."""
    if use_tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        conn = http.client.HTTPSConnection(host, port, context=ctx, timeout=timeout)
    else:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)

    conn.request("GET", path, headers={"User-Agent": "race.py", "Accept": "text/html"})
    resp = conn.getresponse()
    body = resp.read().decode("utf-8", errors="ignore")
    set_cookie = resp.getheader("Set-Cookie") or ""
    conn.close()

    session = None
    m = re.search(re.escape(cookie_name) + r"=([^;,\s]+)", set_cookie)
    if m:
        session = m.group(1)

    csrf = None
    # Try both attribute orders: name=...value=... and value=...name=...
    patterns = [
        r'name=["\']?' + re.escape(csrf_field) + r'["\']?[^>]*?value=["\']([^"\']+)["\']',
        r'value=["\']([^"\']+)["\'][^>]*?name=["\']?' + re.escape(csrf_field) + r'["\']?',
    ]
    for pat in patterns:
        cm = re.search(pat, body, re.IGNORECASE)
        if cm:
            csrf = cm.group(1)
            break

    return session, csrf


def apply_prime(template: bytes, session, csrf):
    """Substitute {{SESSION}} / {{CSRF}} placeholders in a template."""
    if b"{{SESSION}}" in template:
        if session is None:
            raise RuntimeError("Template uses {{SESSION}} but --prime found no session cookie.")
        template = template.replace(b"{{SESSION}}", session.encode())
    if b"{{CSRF}}" in template:
        if csrf is None:
            raise RuntimeError("Template uses {{CSRF}} but --prime found no CSRF token.")
        template = template.replace(b"{{CSRF}}", csrf.encode())
    return template


# ---------------------------------------------------------------------------
# Engine 1: HTTP/2 Single-Packet Attack  (warm-up + withhold-final-frame)
# ---------------------------------------------------------------------------

def try_negotiate_h2(host, port, timeout):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    raw = socket.create_connection((host, port), timeout=timeout)
    raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    sock = ctx.wrap_socket(raw, server_hostname=host)
    if sock.selected_alpn_protocol() == "h2":
        return sock
    sock.close()
    return None


def _drain_outbound(conn, sock):
    data = conn.data_to_send()
    if data:
        sock.sendall(data)


def run_http2_single_packet(host, port, timeout, parsed_requests, gap=0.10, verbose=True):
    if not HAVE_H2:
        print("[!] The 'h2' library is not installed. Run: pip install h2", file=sys.stderr)
        return None

    sock = try_negotiate_h2(host, port, timeout)
    if sock is None:
        return None  # caller falls back to the http1 engine

    cfg = h2.config.H2Configuration(client_side=True, header_encoding="utf-8")
    conn = h2.connection.H2Connection(config=cfg)

    # ---- Step (a): warm up the connection, separate from the attack packet ----
    conn.initiate_connection()
    _drain_outbound(conn, sock)  # preface + client SETTINGS

    # Wait for the server SETTINGS and ACK it so the h2 handshake is complete.
    sock.settimeout(min(timeout, 3.0))
    handshake_deadline = time.time() + min(timeout, 3.0)
    got_settings = False
    while time.time() < handshake_deadline and not got_settings:
        try:
            data_in = sock.recv(65535)
        except socket.timeout:
            break
        if not data_in:
            break
        for event in conn.receive_data(data_in):
            if isinstance(event, h2.events.RemoteSettingsChanged):
                got_settings = True
        _drain_outbound(conn, sock)  # SETTINGS ACK / WINDOW_UPDATE

    # ---- Step (b): send everything EXCEPT each stream's final frame ----
    stream_map = {}   # sid -> index
    finals = []       # (sid, final_bytes) withheld until the timing packet
    for i, (method, path, host_hdr, headers, body) in enumerate(parsed_requests):
        sid = conn.get_next_available_stream_id()
        stream_map[sid] = i
        h2_headers = [
            (":method", method),
            (":path", path),
            (":scheme", "https"),
            (":authority", host_hdr or host),
        ] + headers

        if body:
            conn.send_headers(sid, h2_headers, end_stream=False)
            if len(body) > 1:
                pre = body[:-1]
                # Flow-control guard for bodies larger than the window (rare here).
                win = conn.local_flow_control_window(sid)
                if len(pre) > win:
                    pre = pre[:win]
                if pre:
                    conn.send_data(sid, pre, end_stream=False)
                # Whatever body remains becomes the final frame (normally 1 byte).
                finals.append((sid, body[len(pre):]))
            else:
                # Body is exactly one byte; send nothing early.
                finals.append((sid, body))
        else:
            # Body-less request: HEADERS without END_STREAM; final frame is an
            # empty END_STREAM DATA frame.
            conn.send_headers(sid, h2_headers, end_stream=False)
            finals.append((sid, b""))

    _drain_outbound(conn, sock)  # the "bulk" send; may span several packets - fine.

    # Brief pause so the server fully buffers the bulk before the single-packet flush.
    if gap > 0:
        time.sleep(gap)

    # ---- Step (c): flush ONLY the final frames -> the real single packet ----
    for sid, final_bytes in finals:
        conn.send_data(sid, final_bytes, end_stream=True)
    payload = conn.data_to_send()
    if verbose:
        print(f"[*] HTTP/2 single-packet: {len(parsed_requests)} requests | "
              f"final packet (withheld frames only) = {len(payload)} bytes in one sendall()")
    t_send = time.time()
    sock.sendall(payload)

    # ---- Read responses ----
    buffers = {sid: {"status": None, "headers": None, "body": b"", "err": None} for sid in stream_map}
    ended = set()
    sock.settimeout(timeout)
    start = time.time()
    while len(ended) < len(stream_map) and (time.time() - start) < timeout:
        try:
            data_in = sock.recv(65535)
        except socket.timeout:
            break
        if not data_in:
            break
        try:
            events = conn.receive_data(data_in)
        except h2.exceptions.ProtocolError as e:
            for sid in stream_map:
                if sid not in ended:
                    buffers[sid]["err"] = f"protocol error: {e}"
            break
        _drain_outbound(conn, sock)
        for event in events:
            if isinstance(event, h2.events.ResponseReceived):
                sid = event.stream_id
                if sid in buffers:
                    buffers[sid]["headers"] = event.headers
                    buffers[sid]["status"] = dict(event.headers).get(":status")
            elif isinstance(event, h2.events.DataReceived):
                sid = event.stream_id
                if sid in buffers:
                    buffers[sid]["body"] += event.data
                try:
                    conn.acknowledge_received_data(len(event.data), sid)
                except Exception:
                    pass
            elif isinstance(event, h2.events.StreamEnded):
                ended.add(event.stream_id)
            elif isinstance(event, h2.events.StreamReset):
                sid = event.stream_id
                if sid in buffers:
                    buffers[sid]["err"] = f"RST_STREAM (code={event.error_code})"
                ended.add(sid)
            elif isinstance(event, h2.events.ConnectionTerminated):
                for sid in stream_map:
                    if sid not in ended:
                        buffers[sid]["err"] = f"GOAWAY (code={event.error_code})"
                        ended.add(sid)

    try:
        sock.close()
    except Exception:
        pass

    results = [None] * len(parsed_requests)
    elapsed = (time.time() - t_send) * 1000
    for sid, idx in stream_map.items():
        b = buffers[sid]
        results[idx] = (b["status"], b["body"], elapsed, b["err"], b["headers"])
    return results


# ---------------------------------------------------------------------------
# Engine 2: HTTP/1.1 Last-Byte Sync
# ---------------------------------------------------------------------------

def make_socket_factory(host, port, use_tls, timeout):
    def factory():
        raw = socket.create_connection((host, port), timeout=timeout)
        raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_alpn_protocols(["http/1.1"])  # keep this engine on HTTP/1.1
            return ctx.wrap_socket(raw, server_hostname=host)
        return raw
    return factory


class Http1Worker(threading.Thread):
    def __init__(self, idx, label, request_bytes, sock_factory, barrier, results, sync_mode, timeout):
        super().__init__()
        self.idx = idx
        self.label = label
        self.request_bytes = request_bytes
        self.sock_factory = sock_factory
        self.barrier = barrier
        self.results = results
        self.sync_mode = sync_mode
        self.timeout = timeout

    def run(self):
        sock = None
        try:
            sock = self.sock_factory()
            if self.sync_mode == "last-byte" and len(self.request_bytes) > 1:
                body, last = self.request_bytes[:-1], self.request_bytes[-1:]
                sock.sendall(body)
                self._safe_barrier()  # wait until every worker has sent its bulk
                sock.sendall(last)
            else:
                self._safe_barrier()
                sock.sendall(self.request_bytes)

            t0 = time.time()
            sock.settimeout(self.timeout)
            resp = b""
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    resp += chunk
                    if len(resp) > 262144:
                        break
            except socket.timeout:
                pass
            elapsed = (time.time() - t0) * 1000
            status_line = resp.split(b"\r\n", 1)[0].decode(errors="ignore") if resp else None
            # headers=None signals "body already holds the full raw response".
            self.results[self.idx] = (status_line, resp, elapsed, None, None)
        except Exception as e:
            self.results[self.idx] = (None, b"", 0, str(e), None)
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

    def _safe_barrier(self):
        try:
            self.barrier.wait(timeout=self.timeout)
        except threading.BrokenBarrierError:
            pass


def run_http1_last_byte(host, port, use_tls, timeout, raw_items, sync_mode):
    n = len(raw_items)
    sock_factory = make_socket_factory(host, port, use_tls, timeout)
    barrier = threading.Barrier(n)
    results = [None] * n
    threads = [
        Http1Worker(i, label, data, sock_factory, barrier, results, sync_mode, timeout)
        for i, (label, data) in enumerate(raw_items)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return results


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def sanitize(name):
    return re.sub(r"[^A-Za-z0-9._-]", "_", name)[:40]


def _truncate(text, limit):
    if limit and len(text) > limit:
        return text[:limit] + f"\n... [truncated, {len(text) - limit} more bytes; use --max-body 0 for all]"
    return text


def format_response(status, body, headers, max_body):
    """Reconstruct a human-readable response from either engine."""
    if headers is not None:
        # HTTP/2: rebuild status line + headers, then the DATA body.
        lines = [f":status {status}"]
        for k, v in headers:
            if k == ":status":
                continue
            lines.append(f"{k}: {v}")
        head = "\r\n".join(lines)
        text = head + "\r\n\r\n" + body.decode("utf-8", errors="replace")
    else:
        # HTTP/1.1: body already contains the full raw response.
        text = body.decode("utf-8", errors="replace")
    return _truncate(text, max_body)


def print_results(n, raw_items, results, host, port, engine_used,
                  save_dir=None, verbose=False, max_body=2048):
    print(f"\n[*] {n} requests to {host}:{port} | engine: {engine_used}")
    if save_dir:
        os.makedirs(save_dir, exist_ok=True)
    print("\n[*] Results:")
    groups = {}
    for i, (label, raw) in enumerate(raw_items):
        status, body, elapsed, err, headers = results[i]
        blen = len(body) if body else 0
        if save_dir and body:
            fn = os.path.join(save_dir, f"{i:03d}_{sanitize(label)}.http")
            with open(fn, "wb") as f:
                f.write(body)
        if err:
            print(f"  [{i:>3}] {label:<24} -> ERROR: {err}")
            continue
        shown = status if status else "(no response)"
        print(f"  [{i:>3}] {label:<24} -> {shown:<20} len={blen:<7} ({elapsed:.1f} ms)")
        groups.setdefault((str(status), blen), []).append(i)

        if verbose:
            bar = "-" * 70
            print(f"\n{bar}\n### [{i}] {label}  -- REQUEST SENT")
            print(bar)
            print(_truncate(raw.decode("utf-8", errors="replace"), max_body))
            print(f"{bar}\n### [{i}] {label}  -- RESPONSE  ({elapsed:.1f} ms)")
            print(bar)
            if err:
                print(f"ERROR: {err}")
            else:
                print(format_response(status, body, headers, max_body))
            print(bar + "\n")

    if len(groups) > 1:
        print("\n[*] Responses are NOT uniform (likely a race winner / outlier):")
        for (status, blen), idxs in sorted(groups.items(), key=lambda kv: len(kv[1])):
            labels = ", ".join(raw_items[i][0] for i in idxs[:8])
            more = "" if len(idxs) <= 8 else f" (+{len(idxs) - 8} more)"
            print(f"    status={status} len={blen} -> {len(idxs)} request(s): [{labels}{more}]")
    else:
        print("\n[*] All responses were identical (same status/length) - no observable "
              "race effect, or the endpoint is idempotent.")
    if save_dir:
        print(f"\n[*] Response bodies saved under: {save_dir}")


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def build_argparser():
    ap = argparse.ArgumentParser(
        description="Send raw HTTP requests concurrently to test race conditions "
                    "(HTTP/2 single-packet attack, or HTTP/1.1 last-byte sync).")
    ap.add_argument("files", nargs="+",
                    help="Raw request file(s). With --wordlist, exactly one template file.")
    ap.add_argument("--host", help="Target host (defaults to the Host header of the first file).")
    ap.add_argument("--port", type=int, default=None, help="Target port (default 443 with --tls, else 80).")
    ap.add_argument("--tls", action="store_true", help="Use TLS/HTTPS (required for the HTTP/2 engine).")
    ap.add_argument("--repeat", type=int, default=1, help="Fire each file N times concurrently.")
    ap.add_argument("--engine", choices=["auto", "http2", "http1"], default="auto",
                    help="auto: try HTTP/2 single-packet, fall back to HTTP/1.1 last-byte-sync.")
    ap.add_argument("--sync", choices=["last-byte", "connect"], default="last-byte",
                    help="HTTP/1.1 engine synchronization mode.")
    ap.add_argument("--gap", type=float, default=0.10,
                    help="Seconds between the bulk send and the final single-packet flush (HTTP/2).")
    ap.add_argument("--fix-cl", action="store_true",
                    help="Recompute Content-Length to match the body (auto-on with --wordlist).")
    # Templating
    ap.add_argument("--wordlist",
                    help="Wordlist file; builds one request per entry from a single template file.")
    ap.add_argument("--marker", default="§§",
                    help="Placeholder in the template replaced by each wordlist entry (default §§).")
    # Priming (fetch a fresh session cookie + CSRF token before attacking)
    ap.add_argument("--prime", metavar="PATH",
                    help="GET this path first and inject {{SESSION}}/{{CSRF}} into the template.")
    ap.add_argument("--cookie-name", default="session", help="Session cookie name for --prime (default 'session').")
    ap.add_argument("--csrf-field", default="csrf", help="CSRF form field name for --prime (default 'csrf').")
    ap.add_argument("--save-responses", metavar="DIR", help="Write each response body to DIR for inspection.")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="Print the request sent and the full response (status/headers/body) for each item.")
    ap.add_argument("--max-body", type=int, default=2048,
                    help="Max bytes of request/response to print with -v (0 = unlimited; default 2048).")
    ap.add_argument("--timeout", type=float, default=10, help="Socket timeout in seconds (default 10).")
    return ap


def main():
    # Make stdout robust regardless of the console codepage.
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    args = build_argparser().parse_args()

    # Resolve host/port early (needed for --prime).
    first_raw = normalize_crlf(load_raw(args.files[0]))
    host = args.host or extract_host(first_raw)
    if not host:
        print("Error: could not determine the host; pass --host.", file=sys.stderr)
        sys.exit(1)
    host = host.split(":")[0]  # strip any :port from the Host header
    port = args.port or (443 if args.tls else 80)

    # Optional priming: fetch one fresh session cookie + CSRF token to share.
    session = csrf = None
    if args.prime:
        session, csrf = prime_session(host, port, args.tls, args.prime,
                                      args.cookie_name, args.csrf_field, args.timeout)
        print(f"[*] Primed via {args.prime}: session={'set' if session else 'MISSING'}, "
              f"csrf={'set' if csrf else 'MISSING'}")

    # Build the request list.
    raw_items = []  # (label, normalized_bytes)
    if args.wordlist:
        if len(args.files) != 1:
            print("Error: with --wordlist you must pass exactly one template file.", file=sys.stderr)
            sys.exit(1)
        template = load_raw(args.files[0])
        if args.prime:
            template = apply_prime(template, session, csrf)
        marker_b = args.marker.encode()
        if marker_b not in template:
            print(f"Error: marker {args.marker!r} not found in the template file.", file=sys.stderr)
            sys.exit(1)
        with open(args.wordlist, "r", encoding="utf-8", errors="ignore") as f:
            words = [w.strip() for line in f for w in line.split() if w.strip()]
        if not words:
            print("Error: the wordlist is empty.", file=sys.stderr)
            sys.exit(1)
        for w in words:
            data = normalize_crlf(template.replace(marker_b, w.encode()))
            data = fix_content_length(data)  # body length changes per word
            raw_items.append((w, data))
    else:
        for path in args.files:
            data = load_raw(path)
            if args.prime:
                data = apply_prime(data, session, csrf)
            data = normalize_crlf(data)
            if args.fix_cl:
                data = fix_content_length(data)
            for i in range(args.repeat):
                label = os.path.basename(path) if args.repeat == 1 else f"{os.path.basename(path)}#{i+1}"
                raw_items.append((label, data))

    n = len(raw_items)
    if n < 2:
        print("[!] Warning: a race test needs at least 2 requests (use --repeat or more files).",
              file=sys.stderr)

    results = None
    engine_used = None

    if args.engine in ("auto", "http2"):
        if not args.tls:
            if args.engine == "http2":
                print("[!] The HTTP/2 engine requires --tls. Falling back to HTTP/1.1.", file=sys.stderr)
        else:
            try:
                parsed = [parse_raw_request(data) for _, data in raw_items]
            except ValueError as e:
                print(f"Error parsing request: {e}", file=sys.stderr)
                sys.exit(1)
            h2_results = run_http2_single_packet(host, port, args.timeout, parsed, gap=args.gap)
            if h2_results is not None:
                results = h2_results
                engine_used = "http2-single-packet"
            elif args.engine == "http2":
                print("[!] Server did not negotiate HTTP/2 (ALPN failed).", file=sys.stderr)
                sys.exit(1)

    if results is None:
        print(f"[*] HTTP/1.1 last-byte-sync engine on {host}:{port} (tls={args.tls})")
        results = run_http1_last_byte(host, port, args.tls, args.timeout, raw_items, args.sync)
        engine_used = f"http1-{args.sync}-sync"

    print_results(n, raw_items, results, host, port, engine_used,
                  save_dir=args.save_responses, verbose=args.verbose, max_body=args.max_body)


if __name__ == "__main__":
    main()
