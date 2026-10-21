"""External lookups used by the rules: Cloudflare IP ranges (EXP-003),
RDAP hosting attribution (EXP-004) and the release feed (EXP-005).

All of these degrade gracefully: a failed lookup returns a fallback and a
note for the run's coverage_note rather than aborting the fire drill.
"""

import asyncio
import time
from typing import Any, Dict, List, Optional, Tuple

import httpx

CLOUDFLARE_IPS_V4_URL = "https://www.cloudflare.com/ips-v4"
CLOUDFLARE_IPS_V6_URL = "https://www.cloudflare.com/ips-v6"
RDAP_URL = "https://rdap.org/ip/{ip}"

# Published ranges as of 2026-10-20; used only when the live fetch fails.
CLOUDFLARE_RANGES_FALLBACK = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
    "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
]

_ranges_cache: Dict[str, Any] = {"fetched_at": 0.0, "ranges": None}
RANGES_TTL_SECONDS = 24 * 3600


def _parse_range_list(text: str) -> List[str]:
    return [line.strip() for line in text.splitlines() if line.strip() and "/" in line]


async def get_cloudflare_ranges(client: Optional[httpx.AsyncClient] = None,
                                force: bool = False) -> Tuple[List[str], Optional[str]]:
    """Return (ranges, note). The note is non-None when the fallback list
    was used so the run can say so."""
    now = time.time()
    if not force and _ranges_cache["ranges"] and now - _ranges_cache["fetched_at"] < RANGES_TTL_SECONDS:
        return _ranges_cache["ranges"], None

    own_client = client is None
    client = client or httpx.AsyncClient(timeout=15.0)
    try:
        v4, v6 = await asyncio.gather(client.get(CLOUDFLARE_IPS_V4_URL), client.get(CLOUDFLARE_IPS_V6_URL))
        v4.raise_for_status()
        v6.raise_for_status()
        ranges = _parse_range_list(v4.text) + _parse_range_list(v6.text)
        if not ranges:
            raise ValueError("empty range list")
        _ranges_cache.update(fetched_at=now, ranges=ranges)
        return ranges, None
    except Exception as e:
        return list(CLOUDFLARE_RANGES_FALLBACK), f"Cloudflare IP ranges fetched from bundled fallback ({type(e).__name__})."
    finally:
        if own_client:
            await client.aclose()


def parse_rdap(data: Dict[str, Any]) -> Dict[str, Optional[str]]:
    """Pull a human-readable provider out of an RDAP IP response."""
    name = data.get("name")
    registrant = None
    for entity in data.get("entities") or []:
        roles = [r.lower() for r in (entity.get("roles") or [])]
        if "registrant" not in roles:
            continue
        vcard = entity.get("vcardArray") or []
        if len(vcard) == 2 and isinstance(vcard[1], list):
            for prop in vcard[1]:
                if isinstance(prop, list) and len(prop) >= 4 and prop[0] == "fn" and isinstance(prop[3], str):
                    registrant = prop[3].strip()
                    break
        if registrant:
            break
    asn = None
    for link in data.get("links") or []:
        href = str(link.get("href") or "")
        if "/autnum/" in href:
            asn = href.rsplit("/", 1)[-1]
            break
    return {"provider": registrant or name, "name": name, "asn": asn,
            "handle": data.get("handle"), "country": data.get("country")}


async def lookup_hosting(ips: List[str], client: Optional[httpx.AsyncClient] = None,
                         concurrency: int = 4) -> Tuple[Dict[str, Dict[str, Any]], Optional[str]]:
    """RDAP each IP once. Returns ({ip: info}, note)."""
    unique = sorted({ip for ip in ips if ip})
    if not unique:
        return {}, None
    own_client = client is None
    client = client or httpx.AsyncClient(timeout=15.0, follow_redirects=True,
                                         headers={"Accept": "application/rdap+json"})
    sem = asyncio.Semaphore(concurrency)
    results: Dict[str, Dict[str, Any]] = {}
    failures = 0

    async def one(ip: str):
        nonlocal failures
        async with sem:
            try:
                resp = await client.get(RDAP_URL.format(ip=ip))
                if resp.status_code != 200:
                    failures += 1
                    return
                results[ip] = parse_rdap(resp.json())
            except Exception:
                failures += 1

    try:
        await asyncio.gather(*(one(ip) for ip in unique))
    finally:
        if own_client:
            await client.aclose()
    note = f"RDAP lookup failed for {failures} of {len(unique)} origin IP(s)." if failures else None
    return results, note


async def fetch_version_feed(url: Optional[str], client: Optional[httpx.AsyncClient] = None
                             ) -> Tuple[Optional[Any], Optional[str]]:
    """Fetch the signature's release feed JSON. Returns (data, note)."""
    if not url:
        return None, None
    own_client = client is None
    client = client or httpx.AsyncClient(timeout=15.0, follow_redirects=True)
    try:
        resp = await client.get(url)
        resp.raise_for_status()
        return resp.json(), None
    except Exception as e:
        return None, f"Release feed unavailable ({type(e).__name__}); version currency limited to EOL-branch checks."
    finally:
        if own_client:
            await client.aclose()
