"""Stage 3 active verification (opt-in).

GET only, no redirects, no payloads. Resolves through a public resolver and
pins the connection to that address so the corporate vantage point doesn't
distort the result (CONTEXT #11). Stores metadata only - never bodies
(CONTEXT #13) - and computes size/hash/title/counts only when bytes were
actually received (CONTEXT #12).

The SSRF gate is injected (`ssrf_check`) so the caller can pass the exact
validator the Reachability feature uses.
"""

import asyncio
import hashlib
import ipaddress
import re
import secrets
import socket
import time
from typing import Any, Awaitable, Callable, Dict, List, Optional, Sequence

import httpx

from .rules import RANDOM_CANARY_TOKEN
from .signatures import Signature

DOH_URL = "https://cloudflare-dns.com/dns-query"
DOH_RESOLVER_LABEL = "cloudflare-doh(1.1.1.1)"
SYSTEM_RESOLVER_LABEL = "system"
DEFAULT_USER_AGENT = "SKYLAR-ExposureCheck/1.0 (+https://github.com/networkitout/skylar-asi)"
DEFAULT_MAX_BODY_BYTES = 256 * 1024
HASH_PREFIX_LEN = 16
MAX_SECRET_MATCHES = 1000

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

SsrfCheck = Callable[[List[str]], Optional[str]]


def random_canary(path: str) -> str:
    return path.replace(RANDOM_CANARY_TOKEN, secrets.token_hex(6))


def probe_paths_for(signature: Signature) -> List[Dict[str, str]]:
    """Baseline + canary + suspect paths, canaries randomized where marked."""
    paths = [{"kind": "baseline", "path": "/" + secrets.token_hex(8)}]
    for p in signature.canary_paths:
        paths.append({"kind": "canary", "path": random_canary(p)})
    for p in signature.verify.suspect_paths:
        paths.append({"kind": "suspect", "path": p})
    return paths


def summarize_response(status: int, body: Optional[bytes], headers: Optional[Dict[str, str]],
                       secret_patterns: Sequence[str], debug_markers: Sequence[str]) -> Dict[str, Any]:
    """Metadata for a probe response. With status 0 (nothing received) every
    derived field stays None - the scripting-bug regression (CONTEXT #12)."""
    out: Dict[str, Any] = {
        "status": int(status or 0), "size": None, "content_type": None, "title": None,
        "sha256_prefix": None, "secret_match_count": None, "debug_marker_count": None,
    }
    if not status or body is None:
        return out
    headers = {k.lower(): v for k, v in (headers or {}).items()}
    out["size"] = len(body)
    out["content_type"] = (headers.get("content-type") or "")[:100] or None
    out["sha256_prefix"] = hashlib.sha256(body).hexdigest()[:HASH_PREFIX_LEN]
    text = body.decode("utf-8", errors="replace")
    m = _TITLE_RE.search(text)
    if m:
        out["title"] = re.sub(r"\s+", " ", m.group(1)).strip()[:200] or None
    secret_hits = 0
    for pattern in secret_patterns:
        try:
            secret_hits += len(re.findall(pattern, text))
        except re.error:
            continue
        if secret_hits >= MAX_SECRET_MATCHES:
            break
    out["secret_match_count"] = min(secret_hits, MAX_SECRET_MATCHES)
    lowered = text.lower()
    out["debug_marker_count"] = sum(1 for marker in debug_markers if marker.lower() in lowered)
    return out


async def resolve_public(hostname: str, client: httpx.AsyncClient) -> Dict[str, Any]:
    """Resolve via DNS-over-HTTPS; fall back to the system resolver and say
    which one answered so a filtered vantage point is distinguishable."""
    ips: List[str] = []
    try:
        for rtype in ("A", "AAAA"):
            resp = await client.get(DOH_URL, params={"name": hostname, "type": rtype},
                                    headers={"Accept": "application/dns-json"}, timeout=10.0)
            if resp.status_code != 200:
                continue
            for answer in (resp.json().get("Answer") or []):
                if answer.get("type") in (1, 28) and answer.get("data"):
                    data = str(answer["data"]).strip()
                    try:
                        ipaddress.ip_address(data)
                    except ValueError:
                        continue
                    if data not in ips:
                        ips.append(data)
        if ips:
            return {"ips": ips, "resolver": DOH_RESOLVER_LABEL, "error": None}
        doh_error = "public resolver returned no A/AAAA answers"
    except Exception as e:
        doh_error = f"public resolver unavailable ({type(e).__name__})"

    try:
        loop = asyncio.get_running_loop()
        addrinfo = await loop.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
        for _family, _type, _proto, _canon, sockaddr in addrinfo:
            if sockaddr[0] not in ips:
                ips.append(sockaddr[0])
    except Exception:
        pass
    if ips:
        return {"ips": ips, "resolver": SYSTEM_RESOLVER_LABEL, "error": None,
                "note": doh_error}
    return {"ips": [], "resolver": None, "error": f"{doh_error}; system resolver also failed"}


async def probe(client: httpx.AsyncClient, hostname: str, ip: str, path: str, user_agent: str,
                max_bytes: int = DEFAULT_MAX_BODY_BYTES, scheme: str = "https") -> Dict[str, Any]:
    """Single pinned GET. Returns status/body/headers/error/elapsed_ms; body is
    None when nothing was received."""
    host_for_url = f"[{ip}]" if ":" in ip else ip
    url = f"{scheme}://{host_for_url}{path}"
    result: Dict[str, Any] = {"status": 0, "body": None, "headers": {}, "error": None, "elapsed_ms": None}
    start = time.perf_counter()
    try:
        extensions = {"sni_hostname": hostname} if scheme == "https" else {}
        async with client.stream("GET", url, headers={"Host": hostname, "User-Agent": user_agent},
                                 extensions=extensions) as resp:
            chunks = []
            received = 0
            async for chunk in resp.aiter_bytes():
                if received + len(chunk) > max_bytes:
                    chunks.append(chunk[: max_bytes - received])
                    received = max_bytes
                    break
                chunks.append(chunk)
                received += len(chunk)
            result["status"] = resp.status_code
            result["headers"] = dict(resp.headers)
            result["body"] = b"".join(chunks)
    except httpx.TimeoutException:
        result["error"] = "Connection timed out"
    except httpx.ConnectError:
        result["error"] = "Connection failed or SSL error"
    except httpx.RequestError as e:
        result["error"] = f"Request failed: {type(e).__name__}"
    except Exception as e:
        result["error"] = f"Check failed: {type(e).__name__}"
    result["elapsed_ms"] = int((time.perf_counter() - start) * 1000)
    return result


async def verify_host(hostname: str, signature: Signature, ssrf_check: SsrfCheck,
                      user_agent: str = DEFAULT_USER_AGENT, timeout: float = 10.0,
                      delay_between: float = 0.25, max_bytes: int = DEFAULT_MAX_BODY_BYTES,
                      client: Optional[httpx.AsyncClient] = None) -> Dict[str, Any]:
    """Probe one host: resolve publicly, gate through the SSRF check, pin,
    then GET the baseline/canary/suspect paths. Returns metadata only."""
    out: Dict[str, Any] = {
        "host": hostname, "resolver": None, "resolved_ip": None, "resolve_error": None,
        "blocked": False, "version_header": None, "server_header": None, "probes": [],
    }
    own_client = client is None
    client = client or httpx.AsyncClient(follow_redirects=False, timeout=timeout, verify=True)
    try:
        resolved = await resolve_public(hostname, client)
        out["resolver"] = resolved.get("resolver")
        if resolved.get("note"):
            out["resolve_note"] = resolved["note"]
        if not resolved["ips"]:
            out["resolve_error"] = resolved["error"]
            return out

        blocked_reason = ssrf_check(resolved["ips"])
        ip = next((i for i in resolved["ips"] if ipaddress.ip_address(i).version == 4), resolved["ips"][0])
        out["resolved_ip"] = ip
        if blocked_reason:
            out["blocked"] = True
            out["resolve_error"] = blocked_reason
            return out

        header_name = (signature.version_spec.header or "").lower()
        scheme = "https"
        for i, item in enumerate(probe_paths_for(signature)):
            if i and delay_between:
                await asyncio.sleep(delay_between)
            raw = await probe(client, hostname, ip, item["path"], user_agent, max_bytes, scheme=scheme)
            # An origin with no TLS at all: fall back to plain HTTP for the
            # rest of the host (decided on the baseline so results stay
            # comparable), and record which scheme answered.
            if i == 0 and raw["status"] == 0 and raw["error"] and "Connection failed" in raw["error"]:
                scheme = "http"
                raw = await probe(client, hostname, ip, item["path"], user_agent, max_bytes, scheme=scheme)
            headers = {k.lower(): v for k, v in (raw.get("headers") or {}).items()}
            summary = summarize_response(raw["status"], raw["body"], headers,
                                         signature.verify.secret_patterns, signature.verify.debug_markers)
            summary.update({
                "path": item["path"], "kind": item["kind"], "error": raw["error"], "scheme": scheme,
                "elapsed_ms": raw["elapsed_ms"], "location": (headers.get("location") or "")[:300] or None,
            })
            out["probes"].append(summary)
            if raw["status"]:
                if header_name and headers.get(header_name) and not out["version_header"]:
                    out["version_header"] = headers[header_name][:120]
                if headers.get("server") and not out["server_header"]:
                    out["server_header"] = headers["server"][:120]
        out["scheme"] = scheme
        return out
    finally:
        if own_client:
            await client.aclose()
