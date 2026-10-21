"""Technology signature files.

A signature describes one affected technology: which paths hint at it, which
impossible paths expose catch-all hosts, how to read a version header, and
what to probe during active verify. Adding a technology means adding a YAML
file to the signatures directory, not writing code (CONTEXT: reusability).
"""

import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import yaml

DEFAULT_SIGNATURES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "signatures")

_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,99}$")


@dataclass
class VersionSpec:
    header: Optional[str] = None
    extract: Optional[str] = None
    version_feed: Optional[str] = None
    eol_branches: List[str] = field(default_factory=list)


@dataclass
class VerifySpec:
    suspect_paths: List[str] = field(default_factory=list)
    secret_patterns: List[str] = field(default_factory=list)
    debug_markers: List[str] = field(default_factory=list)


MITIGATION_KINDS = ("cloudflare_waf", "origin", "patch")


@dataclass
class MitigationExpression:
    """One WAF rule expression; Cloudflare's body-inspection fields differ by plan."""
    expression: str
    plan: Optional[str] = None
    note: Optional[str] = None


@dataclass
class Mitigation:
    """A protective action the operator can take, shipped with the signature
    so the UI can show it next to the findings it addresses. Nothing here is
    ever applied automatically - the app stays read-only against Cloudflare."""
    id: str
    kind: str
    title: str
    summary: str = ""
    action: Optional[str] = None
    expressions: List[MitigationExpression] = field(default_factory=list)
    snippet: Optional[str] = None
    steps: List[str] = field(default_factory=list)
    caveats: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "title": self.title,
            "summary": self.summary,
            "action": self.action,
            "expressions": [{"expression": e.expression, "plan": e.plan, "note": e.note} for e in self.expressions],
            "snippet": self.snippet,
            "steps": self.steps,
            "caveats": self.caveats,
        }


@dataclass
class Signature:
    name: str
    version: str
    title: str
    description: str
    path_patterns: List[str]
    min_distinct_ips: int
    canary_paths: List[str]
    min_canary_hits: int
    self_call_paths: List[str]
    version_spec: VersionSpec
    verify: VerifySpec
    report: Dict[str, Any]
    mitigations: List[Mitigation] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "title": self.title,
            "description": self.description,
            "path_patterns": self.path_patterns,
            "min_distinct_ips": self.min_distinct_ips,
            "canary_paths": self.canary_paths,
            "min_canary_hits": self.min_canary_hits,
            "self_call_paths": self.self_call_paths,
            "version_header": self.version_spec.header,
            "eol_branches": self.version_spec.eol_branches,
            "suspect_paths": self.verify.suspect_paths,
            "secret_pattern_count": len(self.verify.secret_patterns),
            "managed_platforms": (self.report or {}).get("managed_platforms", []),
            "notes": (self.report or {}).get("notes"),
            "mitigations": [m.to_dict() for m in self.mitigations],
        }


class SignatureError(ValueError):
    pass


def _as_str_list(value, field_name: str) -> List[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise SignatureError(f"'{field_name}' must be a list of strings")
    return value


def _parse_mitigations(value: Any) -> List[Mitigation]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise SignatureError("'mitigations' must be a list")
    out: List[Mitigation] = []
    seen_ids: set = set()
    for i, item in enumerate(value):
        where = f"mitigations[{i}]"
        if not isinstance(item, dict):
            raise SignatureError(f"{where} must be a mapping")
        mid = str(item.get("id") or "").strip()
        if not mid:
            raise SignatureError(f"{where} needs an 'id'")
        if mid in seen_ids:
            raise SignatureError(f"{where} duplicates id {mid!r}")
        seen_ids.add(mid)
        kind = str(item.get("kind") or "").strip()
        if kind not in MITIGATION_KINDS:
            raise SignatureError(f"{where}.kind must be one of {', '.join(MITIGATION_KINDS)}")
        title = str(item.get("title") or "").strip()
        if not title:
            raise SignatureError(f"{where} needs a 'title'")

        expressions: List[MitigationExpression] = []
        raw_exprs = item.get("expressions") or []
        if not isinstance(raw_exprs, list):
            raise SignatureError(f"{where}.expressions must be a list")
        for j, raw in enumerate(raw_exprs):
            if not isinstance(raw, dict) or not str(raw.get("expression") or "").strip():
                raise SignatureError(f"{where}.expressions[{j}] needs an 'expression' string")
            expressions.append(MitigationExpression(
                expression=str(raw["expression"]).strip(),
                plan=(str(raw["plan"]).strip() if raw.get("plan") else None),
                note=(str(raw["note"]).strip() if raw.get("note") else None),
            ))
        if kind == "cloudflare_waf" and not expressions:
            raise SignatureError(f"{where} is a cloudflare_waf mitigation but lists no expressions")

        out.append(Mitigation(
            id=mid,
            kind=kind,
            title=title,
            summary=str(item.get("summary") or "").strip(),
            action=(str(item["action"]).strip() if item.get("action") else None),
            expressions=expressions,
            snippet=(str(item["snippet"]).rstrip() if item.get("snippet") else None),
            steps=_as_str_list(item.get("steps"), f"{where}.steps"),
            caveats=(str(item["caveats"]).strip() if item.get("caveats") else None),
        ))
    return out


def parse_signature(data: Dict[str, Any]) -> Signature:
    if not isinstance(data, dict):
        raise SignatureError("signature must be a mapping")
    name = str(data.get("name") or "").strip()
    if not _NAME_RE.match(name):
        raise SignatureError("signature 'name' must be lowercase alphanumeric with . _ -")

    path_patterns = _as_str_list(data.get("path_patterns"), "path_patterns")
    if not path_patterns:
        raise SignatureError("'path_patterns' must list at least one pattern")

    version_label = str(data.get("signature_version") or "1")
    version_data = data.get("version") or {}
    if not isinstance(version_data, dict):
        raise SignatureError("'version' must be a mapping (header/extract/version_feed/eol_branches)")

    version_spec = VersionSpec(
        header=(version_data.get("header") or None),
        extract=(version_data.get("extract") or None),
        version_feed=(version_data.get("version_feed") or None),
        eol_branches=[str(b) for b in (version_data.get("eol_branches") or [])],
    )
    if version_spec.extract:
        try:
            re.compile(version_spec.extract)
        except re.error as e:
            raise SignatureError(f"version.extract is not a valid regex: {e}")

    verify_data = data.get("verify") or {}
    verify = VerifySpec(
        suspect_paths=_as_str_list(verify_data.get("suspect_paths"), "verify.suspect_paths"),
        secret_patterns=_as_str_list(verify_data.get("secret_patterns"), "verify.secret_patterns"),
        debug_markers=_as_str_list(verify_data.get("debug_markers"), "verify.debug_markers"),
    )
    for pattern in verify.secret_patterns:
        try:
            re.compile(pattern)
        except re.error as e:
            raise SignatureError(f"verify.secret_patterns entry {pattern!r} is not a valid regex: {e}")

    return Signature(
        name=name,
        version=version_label,
        title=str(data.get("title") or name),
        description=str(data.get("description") or "").strip(),
        path_patterns=path_patterns,
        min_distinct_ips=int(data.get("min_distinct_ips") or 10),
        canary_paths=_as_str_list(data.get("canary_paths"), "canary_paths"),
        min_canary_hits=int(data.get("min_canary_hits") or 2),
        self_call_paths=_as_str_list(data.get("self_call_paths"), "self_call_paths"),
        version_spec=version_spec,
        verify=verify,
        report=data.get("report") or {},
        mitigations=_parse_mitigations(data.get("mitigations")),
    )


def load_signature_file(path: str) -> Signature:
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    return parse_signature(data)


def list_signatures(directory: Optional[str] = None) -> Dict[str, Signature]:
    """Load every *.yaml / *.yml signature in the directory keyed by name.

    A malformed file is skipped (and reported on stderr) rather than taking
    the whole feature down during a fire drill.
    """
    directory = directory or DEFAULT_SIGNATURES_DIR
    found: Dict[str, Signature] = {}
    if not os.path.isdir(directory):
        return found
    for filename in sorted(os.listdir(directory)):
        if not filename.lower().endswith((".yaml", ".yml")):
            continue
        full = os.path.join(directory, filename)
        try:
            sig = load_signature_file(full)
        except (SignatureError, yaml.YAMLError, OSError) as e:
            print(f"Exposure: skipping signature {filename}: {e}")
            continue
        found[sig.name] = sig
    return found


def get_signature(name: str, directory: Optional[str] = None) -> Optional[Signature]:
    return list_signatures(directory).get(name)
