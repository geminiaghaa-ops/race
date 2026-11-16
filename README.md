# race.py — Race Condition Request Sender

A small, dependency-light tool for testing HTTP **race conditions** by firing many
raw requests so they hit the server at (as close as possible to) the same instant.

It implements the two techniques from PortSwigger's race-condition research:

- **HTTP/2 single-packet attack** — the most precise method. All requests are pre-loaded,
  then each stream's *final frame* is withheld and flushed together in a single TCP
  packet, so the server completes them almost simultaneously. Network jitter is
  effectively removed and request size/count no longer matter.
- **HTTP/1.1 last-byte sync** — automatic fallback when the server has no HTTP/2. Each
  request uses its own connection, sends all but the last byte, waits on a barrier,
  then all connections fire the last byte together.

> ⚠️ **Authorized use only.** Use this against systems you own or are explicitly
> permitted to test (e.g. a bug-bounty scope or a training lab). You are responsible
> for how you use it.

---

## Requirements

- Python 3.8+
- For the HTTP/2 engine: the [`h2`](https://pypi.org/project/h2/) library

```bash
pip install h2
```

The HTTP/1.1 engine needs no third-party packages.

---

## Quick start

Capture a raw request (in Burp: right-click → **Copy to file**, or paste the raw text
into a `.txt` file). It must start with the request line, e.g. `POST /login HTTP/1.1`.

**1) Fire the same request many times at once** (classic single-endpoint race —
limit bypass, double-spend, coupon reuse, etc.):

```bash
python race.py --tls --repeat 30 request.txt
```

**2) Templated brute force / multi-value race** — one request per wordlist entry,
all sharing one session + CSRF token:

```bash
python race.py --tls --wordlist wordlist.txt --prime /login examples/login.tmpl
```

**3) Several different requests together** (e.g. a state-dependent multi-step race):

```bash
python race.py --tls req_a.txt req_b.txt req_c.txt
```

---

## How it works

By default the engine is `auto`:

1. It opens a TLS connection and tries to negotiate HTTP/2 via ALPN.
2. If the server speaks **h2**, it runs the **single-packet attack**.
3. Otherwise it falls back to the **HTTP/1.1 last-byte-sync** engine.

Force one with `--engine http2` or `--engine http1`. The HTTP/2 engine requires `--tls`.

### Single-packet attack sequence

1. **Warm up** — send the HTTP/2 preface + SETTINGS and wait for the server's SETTINGS,
   so the handshake is fully done *before* the timing-critical send.
2. **Bulk send** — for every request, send the headers and all of the body except the
   final byte (this may span several packets — it does not matter).
3. **Fire** — flush only the withheld final frames of every stream in a single
   `sendall()`. This last packet is what synchronizes the requests.

`--gap` (default `0.10s`) is the pause between the bulk send and the final flush.

---

## Templating

Used with `--wordlist` and/or `--prime`. Placeholders in a template file:

| Placeholder   | Replaced with                                             |
|---------------|-----------------------------------------------------------|
| `§§`          | each wordlist entry (change the token with `--marker`)    |
| `{{SESSION}}` | the session cookie value fetched by `--prime`             |
| `{{CSRF}}`    | the CSRF token fetched by `--prime`                       |

`Content-Length` is recomputed automatically in wordlist mode (the body length changes
per entry). For a single non-templated file, add `--fix-cl` if you edited its body.

### `--prime` (auto session + CSRF)

Many endpoints need a fresh, matching **session cookie + CSRF token**. `--prime PATH`
performs one `GET PATH` first, extracts both, and injects them into the template so
every parallel request shares the same valid pair:

```bash
python race.py --tls --wordlist wordlist.txt \
  --prime /login --cookie-name session --csrf-field csrf \
  examples/login.tmpl
```

- `--cookie-name` — session cookie name to read from `Set-Cookie` (default `session`).
- `--csrf-field`  — form field name to read the token from in the HTML (default `csrf`).

If your target doesn't use CSRF, just omit `{{CSRF}}` from the template; if it doesn't
set a cookie you care about, omit `{{SESSION}}`.

---

## Example template

`examples/login.tmpl` (edit `Host`, path, username, and field names for your target):

```
POST /login HTTP/1.1
Host: TARGET-HOST
Cookie: session={{SESSION}}
Content-Type: application/x-www-form-urlencoded
Content-Length: 0

csrf={{CSRF}}&username=admin&password=§§
```

---

## Reading the output

Each request prints its status, response body length, and elapsed time. Responses are
then grouped by `(status, length)`:

```
[*] Results:
  [  0] 123456          -> 200   len=4105  (511.2 ms)
  ...
  [  9] hunter2         -> 302   len=0     (511.2 ms)
  ...

[*] Responses are NOT uniform (likely a race winner / outlier):
    status=302 len=0    -> 1 request(s): [hunter2]
    status=400 len=20   -> 3 request(s): [...]
    status=200 len=4105 -> 14 request(s): [...]
```

The **outlier group** is usually the interesting one — e.g. a `302` redirect among a
sea of `200` "failed" pages means that request succeeded.

To actually *see* what was sent and received, add **`-v` / `--verbose`**: it prints, for
every item, the exact request that was sent and the full response (status line, headers,
and body). This is the fastest way to understand a puzzling result — e.g. why every
request came back `400`. Output is capped at `--max-body` bytes per request/response
(default `2048`; use `--max-body 0` for the full body). Use `--save-responses DIR` to
dump every response body to disk instead.

```bash
python race.py --tls -v --max-body 500 req1.txt req2.txt
```

---

## All options

| Option                | Description                                                            |
|-----------------------|------------------------------------------------------------------------|
| `files`               | One or more raw request files. With `--wordlist`, exactly one template. |
| `--host HOST`         | Target host (defaults to the `Host:` header of the first file).        |
| `--port PORT`         | Target port (default `443` with `--tls`, else `80`).                   |
| `--tls`               | Use TLS/HTTPS. Required for the HTTP/2 engine.                         |
| `--repeat N`          | Fire each file `N` times concurrently.                                 |
| `--engine`            | `auto` (default), `http2`, or `http1`.                                 |
| `--sync`              | HTTP/1.1 mode: `last-byte` (default) or `connect`.                     |
| `--gap SECONDS`       | Delay between bulk send and final flush, HTTP/2 (default `0.10`).      |
| `--fix-cl`            | Recompute `Content-Length` (auto-on with `--wordlist`).               |
| `--wordlist FILE`     | Build one request per entry from a single template file.               |
| `--marker STR`        | Wordlist placeholder token (default `§§`).                             |
| `--prime PATH`        | `GET PATH` first; inject `{{SESSION}}` / `{{CSRF}}`.                    |
| `--cookie-name NAME`  | Session cookie name for `--prime` (default `session`).                 |
| `--csrf-field NAME`   | CSRF field name for `--prime` (default `csrf`).                        |
| `--save-responses DIR`| Write each response body to `DIR`.                                     |
| `-v`, `--verbose`     | Print the request sent and the full response (status/headers/body).    |
| `--max-body N`        | Max bytes printed per request/response with `-v` (`0` = all; def 2048).|
| `--timeout SECONDS`   | Socket timeout (default `10`).                                         |

---

## Tips & gotchas

- **Session/CSRF must be fresh and matched.** Prefer `--prime` so every run grabs a new
  valid pair. If you hardcode them in a file, capture a *new* request each time — many
  apps rotate the session cookie after a successful action.
- **Not every race needs many values.** For "use one thing twice" bugs, the same request
  with `--repeat 2` (or more) is often enough.
- **HTTP/2 gives the tightest window.** If the target only offers HTTP/1.1, the last-byte
  engine still works but has more jitter; try a few runs.
- **Tune `--gap`** if the server is slow to buffer the bulk before the final packet.
- The tool intentionally reads at most 256 KB of an HTTP/1.1 response body.
- **Git Bash on Windows** rewrites a leading-slash argument like `--prime /login` into a
  Windows path (e.g. `D:/Program Files/Git/login`). Prefix the command with
  `MSYS_NO_PATHCONV=1`, or use `--prime //login`, or run it from PowerShell / `cmd`.

---

## Files

```
race.py               # the tool
README.md             # this document
examples/login.tmpl   # templated login (wordlist + prime)
examples/single.txt   # single raw request (use with --repeat)
examples/wordlist.txt # sample wordlist
```
