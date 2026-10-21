"""Stage 1 collector: aggregated groups from the Cloudflare GraphQL API.

Never raw events (CONTEXT #1). Three grouped queries per zone per time
chunk, summed in code:

  paths      host/path/method/edge/origin status with counts (EXP-001/002/007)
  ips        host/clientIP for origin-2xx matching paths -> distinct IPs (EXP-001)
  self_calls host/path/method/clientIP for self-call paths  -> origin IP  (EXP-004)

The GraphQL call is injected so this module stays free of main.py and the
tests can feed canned responses.
"""

import fnmatch
import json
from datetime import datetime, timedelta
from typing import Any, Awaitable, Callable, Dict, List, Optional, Set, Tuple

from .rules import ip_in_networks, parse_networks
from .signatures import Signature

GraphQLFn = Callable[[str], Awaitable[Dict[str, Any]]]

DATASET = "httpRequestsAdaptiveGroups"
DEFAULT_LIMIT = 10000
DEFAULT_CHUNK_SECONDS = 24 * 3600
SAMPLED_NOTE = ("Counts come from Cloudflare's adaptive-sampled HTTP dataset and are estimates; "
                "low-traffic hosts may be missing entirely. 'Not seen' is not 'not present'.")


class GraphQLAuthzError(Exception):
    pass


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def glob_to_like(pattern: str) -> str:
    """fnmatch pattern -> SQL LIKE pattern for clientRequestPath_like."""
    out = []
    for ch in pattern:
        if ch == "*":
            out.append("%")
        elif ch == "?":
            out.append("_")
        elif ch in ("%", "_"):
            out.append("\\" + ch)
        else:
            out.append(ch)
    return "".join(out)


def _path_filter_clause(signature: Signature, include_canaries: bool = True) -> str:
    """OR of _like clauses for path patterns plus exact canary/self-call paths."""
    clauses = [f'{{ clientRequestPath_like: {json.dumps(glob_to_like(p))} }}' for p in signature.path_patterns]
    exact: List[str] = []
    if include_canaries:
        exact += [p for p in signature.canary_paths if "RANDOM" not in p]
    exact += list(signature.self_call_paths)
    if exact:
        clauses.append(f'{{ clientRequestPath_in: {json.dumps(sorted(set(exact)))} }}')
    return f"OR: [{', '.join(clauses)}]"


def build_paths_query(zone_tag: str, start: datetime, end: datetime, signature: Signature,
                      limit: int = DEFAULT_LIMIT) -> str:
    return """
    query {
      viewer {
        zones(filter: { zoneTag: %s }) {
          %s(
            limit: %d
            orderBy: [count_DESC]
            filter: { datetime_geq: %s, datetime_lt: %s, %s }
          ) {
            count
            avg { sampleInterval }
            dimensions {
              clientRequestHTTPHost
              clientRequestPath
              clientRequestHTTPMethodName
              edgeResponseStatus
              originResponseStatus
            }
          }
        }
      }
    }
    """ % (json.dumps(zone_tag), DATASET, limit, json.dumps(_iso(start)), json.dumps(_iso(end)),
           _path_filter_clause(signature))


def build_ips_query(zone_tag: str, start: datetime, end: datetime, signature: Signature,
                    limit: int = DEFAULT_LIMIT) -> str:
    return """
    query {
      viewer {
        zones(filter: { zoneTag: %s }) {
          %s(
            limit: %d
            orderBy: [count_DESC]
            filter: {
              datetime_geq: %s, datetime_lt: %s,
              originResponseStatus_geq: 200, originResponseStatus_lt: 300,
              %s
            }
          ) {
            count
            dimensions {
              clientRequestHTTPHost
              clientIP
            }
          }
        }
      }
    }
    """ % (json.dumps(zone_tag), DATASET, limit, json.dumps(_iso(start)), json.dumps(_iso(end)),
           _path_filter_clause(signature, include_canaries=False))


def build_self_call_query(zone_tag: str, start: datetime, end: datetime, signature: Signature,
                          limit: int = 5000) -> str:
    return """
    query {
      viewer {
        zones(filter: { zoneTag: %s }) {
          %s(
            limit: %d
            orderBy: [count_DESC]
            filter: { datetime_geq: %s, datetime_lt: %s, clientRequestPath_in: %s }
          ) {
            count
            dimensions {
              clientRequestHTTPHost
              clientRequestPath
              clientRequestHTTPMethodName
              clientIP
            }
          }
        }
      }
    }
    """ % (json.dumps(zone_tag), DATASET, limit, json.dumps(_iso(start)), json.dumps(_iso(end)),
           json.dumps(list(signature.self_call_paths)))


def build_settings_query(zone_tag: str) -> str:
    return """
    query {
      viewer {
        zones(filter: { zoneTag: %s }) {
          settings {
            %s { enabled maxDuration maxPageSize notOlderThan }
          }
        }
      }
    }
    """ % (json.dumps(zone_tag), DATASET)


def extract_groups(response: Dict[str, Any], node: str = DATASET) -> List[Dict[str, Any]]:
    """Unwrap viewer.zones[0].<node>; raise on GraphQL errors (authz is its
    own type so callers can skip the zone with a note)."""
    errors = response.get("errors")
    if errors:
        for error in errors:
            if (error.get("extensions") or {}).get("code") == "authz":
                raise GraphQLAuthzError(str(error.get("message") or "authz"))
        raise Exception(f"GraphQL query failed: {errors}")
    zones = ((response.get("data") or {}).get("viewer") or {}).get("zones") or []
    if not zones:
        return []
    return zones[0].get(node) or []


class ExposureCollector:
    """Accumulates normalized groups across zones and time chunks."""

    def __init__(self, graphql: GraphQLFn, signature: Signature, cf_ranges: Optional[List[str]] = None,
                 limit: int = DEFAULT_LIMIT):
        self.graphql = graphql
        self.signature = signature
        self.limit = limit
        self.cf_networks = parse_networks(cf_ranges or [])
        self._paths: Dict[Tuple[str, str, str, Optional[int], Optional[int]], Dict[str, Any]] = {}
        self._ips: Dict[str, Set[str]] = {}
        self._self_calls: Dict[Tuple[str, str, str, str], Dict[str, Any]] = {}
        self._host_zone: Dict[str, Tuple[str, str]] = {}
        self.notes: List[str] = []
        self.truncated: Set[str] = set()
        self.sampled = False
        self.queries = 0
        self.zone_errors: Dict[str, str] = {}

    # ------------------------------------------------------------ queries

    async def _run(self, query: str) -> List[Dict[str, Any]]:
        self.queries += 1
        response = await self.graphql(query)
        return extract_groups(response)

    async def zone_limits(self, zone_tag: str) -> Dict[str, Any]:
        try:
            self.queries += 1
            response = await self.graphql(build_settings_query(zone_tag))
            zones = ((response.get("data") or {}).get("viewer") or {}).get("zones") or []
            settings = ((zones[0] if zones else {}).get("settings") or {}).get(DATASET) or {}
            return settings
        except Exception:
            return {}

    async def collect_zone(self, zone_tag: str, zone_name: str, window_start: datetime,
                           window_end: datetime, progress: Optional[Callable[[str], None]] = None) -> None:
        limits = await self.zone_limits(zone_tag)
        if limits.get("enabled") is False:
            self.zone_errors[zone_name] = "dataset not enabled for this zone/plan"
            return
        not_older = limits.get("notOlderThan")
        if not_older:
            earliest = window_end - timedelta(seconds=int(not_older))
            if earliest > window_start:
                self.notes.append(f"{zone_name}: plan retention limits the window to the last {int(not_older) // 3600}h.")
                window_start = earliest
        chunk = DEFAULT_CHUNK_SECONDS
        if limits.get("maxDuration"):
            chunk = min(chunk, int(limits["maxDuration"]))
        page_size = limits.get("maxPageSize")
        limit = min(self.limit, int(page_size)) if page_size else self.limit

        start = window_start
        while start < window_end:
            end = min(start + timedelta(seconds=chunk), window_end)
            if progress:
                progress(f"{zone_name}: {_iso(start)} to {_iso(end)}")
            try:
                await self._collect_chunk(zone_tag, zone_name, start, end, limit)
            except GraphQLAuthzError as e:
                self.zone_errors[zone_name] = f"no analytics access ({e})"
                return
            except Exception as e:
                self.zone_errors[zone_name] = str(e)[:200]
                return
            start = end

    async def _collect_chunk(self, zone_tag: str, zone_name: str, start: datetime, end: datetime, limit: int) -> None:
        sig = self.signature
        paths = await self._run(build_paths_query(zone_tag, start, end, sig, limit))
        if len(paths) >= limit:
            self.truncated.add(f"{zone_name} paths {_iso(start)}")
        for group in paths:
            dims = group.get("dimensions") or {}
            host = (dims.get("clientRequestHTTPHost") or "").lower()
            if not host:
                continue
            interval = ((group.get("avg") or {}).get("sampleInterval") or 1)
            if interval and float(interval) > 1:
                self.sampled = True
            key = (host, dims.get("clientRequestPath") or "", (dims.get("clientRequestHTTPMethodName") or "").upper(),
                   dims.get("edgeResponseStatus"), dims.get("originResponseStatus"))
            row = self._paths.setdefault(key, {
                "host": host, "path": key[1], "method": key[2],
                "edge_status": key[3], "origin_status": key[4], "count": 0, "kind": "path",
                "zone_id": zone_tag, "zone_name": zone_name,
            })
            row["count"] += int(group.get("count") or 0)
            self._host_zone.setdefault(host, (zone_tag, zone_name))

        ips = await self._run(build_ips_query(zone_tag, start, end, sig, limit))
        if len(ips) >= limit:
            self.truncated.add(f"{zone_name} ips {_iso(start)}")
        for group in ips:
            dims = group.get("dimensions") or {}
            host = (dims.get("clientRequestHTTPHost") or "").lower()
            ip = dims.get("clientIP")
            if host and ip:
                self._ips.setdefault(host, set()).add(ip)
                self._host_zone.setdefault(host, (zone_tag, zone_name))

        if sig.self_call_paths:
            calls = await self._run(build_self_call_query(zone_tag, start, end, sig))
            for group in calls:
                dims = group.get("dimensions") or {}
                host = (dims.get("clientRequestHTTPHost") or "").lower()
                ip = dims.get("clientIP")
                if not host or not ip:
                    continue
                key = (host, dims.get("clientRequestPath") or "", (dims.get("clientRequestHTTPMethodName") or "").upper(), ip)
                row = self._self_calls.setdefault(key, {
                    "host": host, "path": key[1], "method": key[2], "source_ip": ip,
                    "edge_status": None, "origin_status": None, "count": 0, "kind": "self_call",
                    "zone_id": zone_tag, "zone_name": zone_name,
                })
                row["count"] += int(group.get("count") or 0)

    # ------------------------------------------------------------ results

    def groups(self) -> List[Dict[str, Any]]:
        return list(self._paths.values()) + list(self._self_calls.values())

    def host_stats(self) -> Dict[str, Dict[str, Any]]:
        stats = {}
        for host, ips in self._ips.items():
            cf = sum(1 for ip in ips if ip_in_networks(ip, self.cf_networks)) if self.cf_networks else 0
            stats[host] = {"distinct_ips_2xx": len(ips), "cf_range_ips_2xx": cf}
        return stats

    def host_zone(self, host: str) -> Tuple[Optional[str], Optional[str]]:
        return self._host_zone.get(host, (None, None))

    def coverage_note(self) -> str:
        parts = [SAMPLED_NOTE]
        if self.truncated:
            parts.append(f"{len(self.truncated)} query chunk(s) hit the row limit; the busiest hosts are complete, "
                         "the long tail may be cut.")
        if self.zone_errors:
            parts.append(f"{len(self.zone_errors)} zone(s) skipped: " +
                         "; ".join(f"{z} ({e})" for z, e in list(self.zone_errors.items())[:5]))
        parts.extend(self.notes[:10])
        return " ".join(parts)


def matching_paths(groups: List[Dict[str, Any]], patterns: List[str]) -> List[Dict[str, Any]]:
    return [g for g in groups if any(fnmatch.fnmatchcase(g.get("path") or "", p) for p in patterns)]
