# HTTP Connection Reuse

## Summary

The HTTP engine (`nettacker/core/lib/http.py`) sends every request through a
**single, process-wide `aiohttp.ClientSession`** that lives on one background
event loop, instead of opening a brand-new session (and a brand-new TCP/TLS
connection) for every request. This lets requests to the same target reuse an
already-open connection (HTTP keep-alive), which removes most of the per-request
setup cost.

## Before vs after

**Before:** each request ran `asyncio.run(send_request(...))`, and
`send_request` opened its own `async with aiohttp.ClientSession()`. Every single
request therefore paid for:

1. creating and tearing down a fresh event loop,
2. building a new `ClientSession` + connector (an empty connection pool),
3. a new TCP connection — **plus a full TLS handshake for HTTPS**,

and then threw all of it away. Reuse was impossible because the pool was
discarded before the next request existed.

**After:** one long-lived pool is shared by the whole process:

- `_get_loop()` starts **one event loop in one daemon thread**
  (`loop.run_forever()`) on first use and keeps it for the process lifetime.
- `_get_session()` creates **one `ClientSession`** on that loop, with a
  `TCPConnector(limit=0, ttl_dns_cache=300)` — that connector *is* the
  persistent connection pool, and it caches DNS for 300s.
- `send_request_sync()` is the blocking entry point for Nettacker's worker
  threads. It hands the request coroutine to the shared loop with
  `asyncio.run_coroutine_threadsafe(coro, loop).result()`, so callers stay
  synchronous while every request reuses the one pool.
- `@atexit` closes the session and stops the loop on shutdown.

A background thread + `run_coroutine_threadsafe` is needed (rather than simply
sharing a session) because an aiohttp session and its connections are bound to
the loop that created them and are not thread-safe. Pinning the session to one
loop and marshaling every request onto that loop keeps a single shared pool safe
across all of Nettacker's worker threads.

## How reuse works, and how it behaves with many targets

Keep-alive reuse is **per endpoint** — the pool keys connections by
`(host, port, is_ssl, ...)`. So:

- Connections are reused **within a target**, never across targets (different
  host = different connection, which is unavoidable).
- Minimum **one connection per target**. Scanning 1000 targets opens at least
  ~1000 connections over the run; the win comes from each target receiving many
  requests (many modules/sub-steps) that all ride its one connection.
- Concurrent open connections are bounded by the worker/thread pool
  (`-M` / `-t`), **not** by the number of targets. As the scan moves on from a
  target, its idle connection is closed after the connector's 15s keepalive
  timeout.

## Measured impact

Two experiments against local instrumented servers (see caveats):

**Controlled micro-benchmark** (reproducible): reusing the pool was ~1.8x faster
on plain HTTP and ~2.8x faster on HTTPS, and opened **0** new TCP connections in
steady state versus one per request. The HTTPS gap is larger because the TLS
handshake is paid once instead of per request.

**Full `-m all` A/B** (directional — see caveat): with the shared session,
requests reused connections at ~**82 requests per connection** versus ~**1**
for the per-request version, and cost ~**0.19 ms of CPU per request** versus
~**54 ms** (the old path spends most of its CPU creating and destroying an event
loop + session per request). Peak RSS was essentially unchanged (~76 MB either
way): the unbounded pool did not grow memory on these workloads.

## Caveats and failure modes considered

- **Shared cookie jar / state bleed.** One session means one process-wide cookie
  jar. A `Set-Cookie` from one response is replayed on later requests to the same
  host (host-wide, for the process lifetime). In the `-m all` A/B this affected
  ~100% of requests against a hostname target, versus 0% for the old
  stateless-per-request behavior. It does **not** cross targets (the jar is
  domain-keyed), and aiohttp's default jar ignores cookies for bare-IP hosts, so
  it is inert for raw-IP targets. If stateless probes are required, construct the
  session with `cookie_jar=aiohttp.DummyCookieJar()`.
- **Single background loop.** All HTTP for the process runs on one loop in one
  thread. `_get_loop()` only rebuilds when `_loop is None`, so if that thread
  stalls or dies it is not recreated. This is a single point of failure to keep
  in mind; a health check / restart would harden it.
- **Stale keep-alive reuse.** A pooled connection can be closed by the server or
  an intermediary before the client notices, so the next request on it can fail
  with `ServerDisconnectedError`. The engine's `retries` loop covers this when
  `retries >= 1`.
- **`--retries 0`.** The retry loop is `for _i in range(options["retries"]):`
  with `response` assigned only inside the loop, so `--retries 0` raises
  `UnboundLocalError: local variable 'response' referenced before assignment` on
  every HTTP sub-step. Use `retries >= 1` (the default is 1).
- **Unbounded pool (`limit=0`).** Pooled connections stay open until the 15s
  idle timeout. Very wide concurrent fan-out could hold many sockets open at
  once; `limit` / `limit_per_host` are the knobs if a scan hits
  "too many open files".
- **DNS cache.** `ttl_dns_cache=300` pins host→IP for 5 minutes, so a target
  whose DNS changes mid-scan is not re-resolved within that window.

> Note on the full-scan A/B: end-to-end `-m all` runs were nondeterministic
> run-to-run (coverage and wall time varied), so the reuse / CPU / cookie
> numbers above are directional. The controlled micro-benchmark is the
> reproducible measurement.
