"""Handoff workbook for an exposure run, plus the table styling shared by
every XLSX export.

A spreadsheet is a light-background medium that gets printed and forwarded,
so the SKYLAR palette (docs/UI_CONVENTIONS.md) is applied as accents on white
rather than as a dark theme: brand orange for the wordmark and headline KPI,
the status tints for verdict / version / coverage cells, bg-surface as the
table header band. Tints are the documented rgba overlays composited onto
white. Nothing here touches the network or the database; callers pass plain
objects with the attributes named below.
"""

import io
import json
from datetime import datetime
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence

import branding
from openpyxl import Workbook
from openpyxl.cell.rich_text import CellRichText, TextBlock
from openpyxl.cell.text import InlineFont
from openpyxl.formatting.rule import FormulaRule
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.styles.colors import Color
from openpyxl.utils import get_column_letter
from openpyxl.worksheet.datavalidation import DataValidation

from . import rules

# ---------------------------------------------------------------- palette

BRAND_ORANGE = "E56A1F"
BRAND_BLUE = "2496ED"
SURFACE = "161B24"          # table header band
TEXT = "1C222D"             # body text on white
TEXT_SECONDARY = "4B5563"
TEXT_TERTIARY = "6B7280"
BORDER = "D5DAE1"
BAND = "F3F5F8"             # zebra rows, code cells
WHITE = "FFFFFF"
MONO = "Consolas"           # code and JSON only; everything else is the workbook default face

# One type scale, 12pt floor so nothing needs zooming in a handoff.
SIZE_BODY = 12
SIZE_TITLE = 14             # block titles (mitigations)
SIZE_SUBTITLE = 16          # sheet titles
SIZE_WORDMARK = 24
SIZE_KPI = 28
LINE_PT = 16                # row height per wrapped line at SIZE_BODY

# tier -> (fill, text). Fills are the 2.5 / 2.6 tints on white; text is the
# token darkened ~20% so it reads on a light fill.
TIERS = {
    "critical": ("FBE4E4", "B53C3B"),
    "high": ("F9E6DE", "AD461A"),
    "medium": ("FDF1DF", "BF7F1F"),
    "low": ("E7F1F7", "4C829F"),
    "success": ("EAF5EF", "3F8B64"),
    "neutral": ("EEF0F3", "4B5563"),
    "brand": ("FCF0E9", BRAND_ORANGE),
    "info": ("E9F4FD", "1F6FB0"),
}

VERDICT_TIER = {
    rules.VERDICT_LIKELY: "critical",
    rules.VERDICT_MISROUTED: "high",
    rules.VERDICT_CATCH_ALL: "low",
    rules.VERDICT_INFO: "neutral",
}
VERDICT_LABEL = {
    rules.VERDICT_LIKELY: "Likely affected",
    rules.VERDICT_MISROUTED: "Misrouted DNS",
    rules.VERDICT_CATCH_ALL: "Catch-all (excluded)",
    rules.VERDICT_INFO: "Informational",
}
VERSION_TIER = {"eol": "critical", "behind": "high", "current": "success", "unknown": "neutral"}
WAF_TIER = {"enabled": "success", "disabled": "medium", "unknown": "neutral"}
GAP_TIER = {
    "Version unknown": "medium",
    "Owner unknown": "medium",
    "Active verify inconclusive": "medium",
    "Untrusted origin status": "high",
    "Edge coverage": "medium",
    "Passive only": "low",
}
DECISIONS = ["patch", "restrict", "offline", "n/a"]

ACTION_VERDICTS = (rules.VERDICT_LIKELY, rules.VERDICT_MISROUTED)


# ---------------------------------------------------------------- style kit

def sanitize_cell(value):
    """Neutralize spreadsheet formula injection: a leading =, +, -, @ or tab
    in a text cell would execute as a formula when opened in Excel/Sheets."""
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t"):
        return "'" + value
    return value


def _fill(hex_color: str) -> PatternFill:
    return PatternFill(start_color=hex_color, end_color=hex_color, fill_type="solid")


def _font(size: float = SIZE_BODY, bold: bool = False, color: str = TEXT, name: Optional[str] = None) -> Font:
    return Font(size=size, bold=bold, color=color, name=name)


def _lines(text: Any, chars_per_line: int) -> int:
    """Wrapped line estimate for merged cells, which Excel will not auto-fit."""
    total = 0
    for part in str(text or "").split("\n"):
        total += max(1, -(-len(part) // chars_per_line))
    return total


def _bottom(color: str = BORDER) -> Border:
    return Border(bottom=Side(style="thin", color=color))


def _box(color: str = BORDER) -> Border:
    side = Side(style="thin", color=color)
    return Border(left=side, right=side, top=side, bottom=side)


def tier_cell(cell, tier: Optional[str], bold: bool = True):
    """Colour a cell like a status badge."""
    fill, text = TIERS.get(tier or "neutral", TIERS["neutral"])
    cell.fill = _fill(fill)
    cell.font = _font(bold=bold, color=text)
    cell.alignment = Alignment(horizontal="left", vertical="center")


def set_widths(ws, widths: Sequence[float]):
    for i, width in enumerate(widths, start=1):
        ws.column_dimensions[get_column_letter(i)].width = width


def finish_sheet(ws, tab_color: Optional[str] = None, title_rows: Optional[str] = "1:1", gridlines: bool = False,
                 footer: str = "SKYLAR"):
    """Print and chrome settings shared by every sheet."""
    ws.sheet_view.showGridLines = gridlines
    if tab_color:
        ws.sheet_properties.tabColor = tab_color
    ws.page_setup.orientation = "landscape"
    ws.page_setup.fitToWidth = 1
    ws.page_setup.fitToHeight = 0
    ws.sheet_properties.pageSetUpPr.fitToPage = True
    if title_rows:
        ws.print_title_rows = title_rows
    ws.oddFooter.left.text = footer
    ws.oddFooter.left.size = 8
    ws.oddFooter.right.text = "Page &P of &N"
    ws.oddFooter.right.size = 8


def write_table(ws, headers: Sequence[str], rows: Iterable[Sequence[Any]], *,
                widths: Optional[Sequence[float]] = None,
                wrap: Sequence[int] = (),
                mono: Sequence[int] = (),
                numeric: Sequence[int] = (),
                tiers: Optional[Dict[int, Callable[[Any], Optional[str]]]] = None,
                editable: Sequence[int] = (),
                freeze: str = "A2") -> int:
    """Header row in row 1, data from row 2, so filters, sorting and pivots
    work as users expect. Column indexes are 0-based. Returns the last row."""
    tiers = tiers or {}
    ws.append(list(headers))
    for i, cell in enumerate(ws[1]):
        is_editable = i in editable
        cell.fill = _fill(TIERS["info"][0] if is_editable else SURFACE)
        cell.font = _font(bold=True, color=TIERS["info"][1] if is_editable else WHITE)
        cell.alignment = Alignment(vertical="center", horizontal="right" if i in numeric else "left")
        cell.border = _bottom(SURFACE)
    ws.row_dimensions[1].height = 26

    auto_widths = [len(str(h)) + 2 for h in headers]
    last_row = 1
    for r, row in enumerate(rows, start=2):
        clean = [sanitize_cell(v) if v is not None else "" for v in row]
        ws.append(clean)
        last_row = r
        banded = r % 2 == 0
        for i, value in enumerate(clean[:len(headers)]):
            cell = ws.cell(row=r, column=i + 1)
            cell.border = _bottom()
            cell.alignment = Alignment(vertical="top", wrap_text=i in wrap,
                                       horizontal="right" if i in numeric else "left")
            cell.font = _font(name=MONO if i in mono else None)
            if i in editable:
                cell.fill = _fill(TIERS["info"][0])
            elif banded:
                cell.fill = _fill(BAND)
            if i in numeric and isinstance(value, (int, float)):
                cell.number_format = "#,##0"
            if i in tiers:
                tier_cell(cell, tiers[i](value))
            if i not in wrap:
                auto_widths[i] = max(auto_widths[i], min(len(str(value)) + 2, 50))

    # Column width units are based on the default 11pt face; scale for 12pt.
    set_widths(ws, widths or [round(w * 1.12, 1) for w in auto_widths])
    if last_row > 1:
        ws.auto_filter.ref = f"A1:{get_column_letter(len(headers))}{last_row}"
    ws.freeze_panes = freeze
    return last_row


# ---------------------------------------------------------------- cover sheet helpers

def _wordmark(size: float = SIZE_WORDMARK) -> CellRichText:
    sky = InlineFont(b=True, sz=size, color=Color(rgb=BRAND_ORANGE))
    lar = InlineFont(b=True, sz=size, color=Color(rgb=BRAND_BLUE))
    return CellRichText(TextBlock(sky, "SKY"), TextBlock(lar, "LAR"))


LOGO_ROWS = (2, 3)


def place_logo(ws, anchor_col: int = 2) -> bool:
    """Rendered wordmark + tagline across LOGO_ROWS; rich text if no image
    backend is available. Returns True when an image was placed."""
    first, last = LOGO_ROWS
    png = branding.wordmark_png(size=96)
    if png:
        from openpyxl.drawing.image import Image as XLImage
        img = XLImage(io.BytesIO(png))
        img.width, img.height = img.width // 2, img.height // 2   # rendered at 2x
        ws.add_image(img, f"{get_column_letter(anchor_col)}{first}")
        per_row = (img.height * 0.75) / (last - first + 1) + 3   # px -> pt, plus breathing room
        for r in range(first, last + 1):
            ws.row_dimensions[r].height = per_row
        return True
    mark = ws.cell(row=first, column=anchor_col)
    mark.value = _wordmark()
    mark.font = _font(SIZE_WORDMARK, bold=True)
    ws.row_dimensions[first].height = 34
    tag = ws.cell(row=last, column=anchor_col, value=branding.TAGLINE.upper())
    tag.font = _font(bold=True, color=TEXT_TERTIARY)
    return False


def _section(ws, row: int, title: str, first_col: int = 2, last_col: int = 7) -> int:
    """Uppercase section label with a rule underneath; returns the next row."""
    for c in range(first_col, last_col + 1):
        cell = ws.cell(row=row, column=c)
        cell.border = _bottom(TEXT_TERTIARY)
    label = ws.cell(row=row, column=first_col, value=title.upper())
    label.font = _font(bold=True, color=TEXT_TERTIARY)
    label.alignment = Alignment(vertical="bottom")
    ws.row_dimensions[row].height = 22
    return row + 1


COVER_COL_WIDTH = 26
COVER_VALUE_COLS = 5


def _kv(ws, row: int, key: str, value: Any, first_col: int = 2, last_col: int = 7, tier: Optional[str] = None) -> int:
    k = ws.cell(row=row, column=first_col, value=key)
    k.font = _font(bold=True, color=TEXT_SECONDARY)
    k.alignment = Alignment(vertical="top")
    v = ws.cell(row=row, column=first_col + 1, value=sanitize_cell(value))
    v.font = _font()
    v.alignment = Alignment(vertical="top", wrap_text=True)
    if tier:
        tier_cell(v, tier)
        v.alignment = Alignment(vertical="top", wrap_text=True)
    ws.merge_cells(start_row=row, start_column=first_col + 1, end_row=row, end_column=last_col)
    # Merged cells never auto-fit, so size the row for the wrapped text.
    chars = int(COVER_COL_WIDTH * (last_col - first_col) * 0.9)
    ws.row_dimensions[row].height = LINE_PT * _lines(value, chars) + 4
    return row + 1


def _kpi_tile(ws, row: int, col: int, label: str, value: Any, sub: str = "", headline: bool = False):
    """Three stacked cells styled like the 5.3 KPI card."""
    cells = [ws.cell(row=row + i, column=col) for i in range(3)]
    cells[0].value = label.upper()
    cells[0].font = _font(bold=True, color=TEXT_TERTIARY)
    cells[0].alignment = Alignment(vertical="bottom", wrap_text=True)
    cells[1].value = value
    cells[1].font = _font(SIZE_KPI, bold=True, color=BRAND_ORANGE if headline else TEXT)
    cells[1].number_format = "#,##0"
    cells[1].alignment = Alignment(vertical="center")
    cells[2].value = sub
    cells[2].font = _font(color=TEXT_TERTIARY)
    cells[2].alignment = Alignment(vertical="top", wrap_text=True)
    side = Side(style="thin", color=BORDER)
    for i, cell in enumerate(cells):
        cell.fill = _fill(TIERS["brand"][0] if headline else BAND)
        cell.border = Border(left=side, right=side, top=side if i == 0 else None, bottom=side if i == 2 else None)
    ws.row_dimensions[row].height = 24
    ws.row_dimensions[row + 1].height = 40
    ws.row_dimensions[row + 2].height = LINE_PT * 2 + 4


# ---------------------------------------------------------------- builder

def _fmt(dt: Optional[datetime]) -> str:
    return dt.strftime("%Y-%m-%d %H:%M UTC") if dt else ""


def build_exposure_workbook(run, hosts: Sequence[Any], findings: Sequence[Any], probes: Sequence[Any],
                            signature=None, now: Optional[datetime] = None) -> Workbook:
    """Summary, Action Items, Evidence, Cleared, Intel Gaps, Mitigations.

    `run`, `hosts`, `findings`, `probes` are the ExposureRun / ExposureHost /
    ExposureFinding / ExposureProbe rows (or anything with the same
    attributes); `signature` is the parsed Signature or None.
    """
    now = now or datetime.utcnow()
    findings_by_host: Dict[str, List[Any]] = {}
    for f in findings:
        findings_by_host.setdefault(f.host, []).append(f)
    stats = run.stats or {}
    verdicts = stats.get("verdicts") or {}
    sig_title = signature.title if signature else run.signature_name
    action_hosts = [h for h in hosts if h.verdict in ACTION_VERDICTS]

    wb = Workbook()

    # ---- Summary (cover)
    ws = wb.active
    ws.title = "Summary"
    set_widths(ws, [3] + [COVER_COL_WIDTH] * 6 + [3])

    place_logo(ws)
    title_row = LOGO_ROWS[1] + 1
    ws.cell(row=title_row, column=2, value="Exposure analysis handoff").font = _font(SIZE_SUBTITLE, color=TEXT)
    ws.row_dimensions[title_row].height = 24
    ws.cell(row=title_row + 1, column=2,
            value=f"{sig_title}  ·  run #{run.id}  ·  generated {_fmt(now)}").font = _font(color=TEXT_TERTIARY)
    tiles_row = title_row + 3

    undecided = sum(1 for h in action_hosts if not h.decision)
    unowned = sum(1 for h in action_hosts if not h.owner)

    def undecided_in(verdict: str) -> str:
        n = sum(1 for h in action_hosts if h.verdict == verdict and not h.decision)
        return f"{n:,} without a decision" if n else "all decided"

    tiles = [
        ("Likely affected", verdicts.get("likely_affected", 0), undecided_in(rules.VERDICT_LIKELY), True),
        ("Misrouted DNS", verdicts.get("misrouted", 0), undecided_in(rules.VERDICT_MISROUTED), False),
        ("Catch-all (excluded)", verdicts.get("catch_all", 0), "answer every path; not evidence", False),
        ("Hosts seen", stats.get("hosts", 0), "with matching traffic", False),
        ("Zones analysed", stats.get("zones", 0), f"{stats.get('graphql_queries', 0):,} GraphQL queries", False),
    ]
    for i, (label, value, sub, headline) in enumerate(tiles):
        _kpi_tile(ws, tiles_row, 2 + i, label, value, sub, headline)

    row = _section(ws, tiles_row + 4, "Run details")
    row = _kv(ws, row, "Signature", f"{sig_title} ({run.signature_name} v{run.signature_version})")
    row = _kv(ws, row, "Run", f"#{run.id} · {run.status}")
    row = _kv(ws, row, "Window (UTC)", f"{_fmt(run.window_start)} to {_fmt(run.window_end)}")
    row = _kv(ws, row, "Mode", "passive + active verify (GET probes)" if run.verify_enabled else "passive only")
    row = _kv(ws, row, "Coverage", run.coverage_note or "")
    if signature and signature.description:
        row = _kv(ws, row, "About", signature.description)

    row = _section(ws, row + 1, "Decisions on action items")
    counts = {d: 0 for d in DECISIONS}
    for h in action_hosts:
        if h.decision in counts:
            counts[h.decision] += 1
    row = _kv(ws, row, "Open (no decision)", undecided, tier="medium" if undecided else "success")
    row = _kv(ws, row, "No owner assigned", unowned, tier="medium" if unowned else "success")
    for d in DECISIONS:
        row = _kv(ws, row, d, counts[d], tier="neutral")

    row = _section(ws, row + 1, "Managed WAF coverage")
    coverage = run.edge_coverage or {}
    if coverage:
        by_state: Dict[str, List[str]] = {}
        for zone, state in coverage.items():
            by_state.setdefault(state, []).append(zone)
        for state in ("enabled", "disabled", "unknown"):
            zones = sorted(by_state.get(state, []))
            if not zones and state != "disabled":
                continue
            preview = ", ".join(zones[:6]) + (f" … and {len(zones) - 6:,} more" if len(zones) > 6 else "")
            row = _kv(ws, row, f"{state} ({len(zones):,} zone{'s' if len(zones) != 1 else ''})",
                      preview or "none", tier=WAF_TIER.get(state, "neutral"))
        row = _kv(ws, row, "Detail", "Per-zone rows are on the Intel Gaps sheet under 'Edge coverage'.")
    else:
        row = _kv(ws, row, "Zones", "no coverage data recorded")

    row = _section(ws, row + 1, "In this workbook")
    guide = [
        ("Action Items", "Hosts that need a decision. Blue columns (owner, contact, decision, notes) are yours to fill in; "
                         "rows without a decision stay highlighted until you pick one."),
        ("Evidence", "Every rule that fired and every active probe, with the raw evidence JSON."),
        ("Cleared", "Hosts seen in the window that did not meet a detection threshold, and why."),
        ("Intel Gaps", "What the run could not determine - unknown versions, missing owners, untrusted origins."),
        ("Mitigations", "WAF rule expressions per plan, origin configuration, and patch guidance from the signature."),
    ]
    for name, text in guide:
        row = _kv(ws, row, name, text)

    row = _section(ws, row + 1, "Verdict legend")
    for verdict in (rules.VERDICT_LIKELY, rules.VERDICT_MISROUTED, rules.VERDICT_CATCH_ALL, rules.VERDICT_INFO):
        row = _kv(ws, row, VERDICT_LABEL[verdict], verdict, tier=VERDICT_TIER[verdict])
    finish_sheet(ws, tab_color=BRAND_ORANGE, title_rows=None)

    # ---- Action Items
    action_rows = []
    for h in action_hosts:
        primary = sorted(findings_by_host.get(h.host, []), key=lambda f: -rules.VERDICT_RANK.get(f.verdict, -1))
        lead = primary[0] if primary else None
        action_rows.append([
            h.host, h.zone_name, h.verdict, lead.rule_id if lead else "", lead.confidence if lead else "",
            h.detected_version or "", h.version_status or "unknown", h.hosting_provider or "", h.origin_ip or "",
            h.owner or "", h.contact or "", h.decision or "", h.notes or "",
            lead.detail if lead else "",
        ])
    ws = wb.create_sheet("Action Items")
    last = write_table(
        ws,
        ["Host", "Zone", "Verdict", "Rule", "Confidence", "Version", "Version status", "Hosting", "Origin IP",
         "Owner", "Contact", "Decision", "Notes", "Detail"],
        action_rows,
        widths=[38, 24, 20, 11, 13, 12, 17, 26, 20, 22, 26, 13, 38, 84],
        wrap=(13,), editable=(9, 10, 11, 12),
        tiers={2: VERDICT_TIER.get, 6: VERSION_TIER.get},
        freeze="B2",
    )
    if last > 1:
        decision_col = get_column_letter(12)
        dv = DataValidation(type="list", formula1=f'"{",".join(DECISIONS)}"', allow_blank=True,
                            showErrorMessage=True, errorTitle="Decision",
                            error="Pick one of: " + ", ".join(DECISIONS))
        ws.add_data_validation(dv)
        dv.add(f"{decision_col}2:{decision_col}{last}")
        ws.conditional_formatting.add(
            f"{decision_col}2:{decision_col}{last}",
            FormulaRule(formula=[f'ISBLANK(${decision_col}2)'], fill=_fill(TIERS["medium"][0]),
                        font=Font(color=TIERS["medium"][1], bold=True)),
        )
    finish_sheet(ws, tab_color=TIERS["critical"][1])

    # ---- Evidence
    evidence_rows = [[f.host, f.rule_id, f.verdict, f.confidence, "yes" if f.origin_status_trusted else "NO",
                      f.detail or "", json.dumps(f.evidence or {}, sort_keys=True)[:2000]] for f in findings]
    for p in probes:
        evidence_rows.append([p.host, "probe", p.kind or "", "verified", "",
                              f"{p.path} -> {p.status or 'no response'}" + (f" ({p.error})" if p.error else ""),
                              json.dumps({"size": p.size, "content_type": p.content_type, "title": p.title,
                                          "sha256_prefix": p.sha256_prefix, "secret_match_count": p.secret_match_count,
                                          "debug_marker_count": p.debug_marker_count, "location": p.location})])
    ws = wb.create_sheet("Evidence")
    write_table(
        ws,
        ["Host", "Rule", "Verdict/Kind", "Confidence", "Origin status trusted", "Detail", "Evidence (JSON)"],
        evidence_rows,
        widths=[38, 11, 22, 13, 14, 80, 72],
        wrap=(5, 6), mono=(6,),
        tiers={2: lambda v: VERDICT_TIER.get(v, "neutral"), 4: lambda v: "high" if v == "NO" else None},
        freeze="B2",
    )
    finish_sheet(ws, tab_color=BRAND_BLUE)

    # ---- Cleared
    cleared_rows = []
    for h in hosts:
        if h.verdict in ACTION_VERDICTS:
            continue
        s = h.summary or {}
        reason = "catch-all host (answers every path)" if h.verdict == rules.VERDICT_CATCH_ALL else \
                 "matching traffic below detection threshold" if s.get("origin_2xx") else "no origin 2xx on matching paths"
        cleared_rows.append([h.host, h.zone_name, h.verdict or "none", s.get("matching_requests", 0),
                             s.get("origin_2xx", 0), s.get("distinct_ips_2xx", 0), reason])
    ws = wb.create_sheet("Cleared")
    write_table(
        ws,
        ["Host", "Zone", "Verdict", "Matching requests (est.)", "Origin 2xx (est.)", "Distinct IPs", "Why cleared"],
        cleared_rows,
        widths=[38, 24, 24, 26, 20, 16, 56],
        numeric=(3, 4, 5),
        tiers={2: lambda v: VERDICT_TIER.get(v, "neutral")},
        freeze="B2",
    )
    finish_sheet(ws, tab_color=TIERS["success"][1])

    # ---- Intel Gaps
    gap_rows = []
    for h in hosts:
        if h.verdict in ACTION_VERDICTS and (h.version_status or "unknown") == "unknown":
            gap_rows.append([h.host, "Version unknown", "Ask the owner which runtime version is deployed; no header exposed."])
        if h.verify_error:
            gap_rows.append([h.host, "Active verify inconclusive", h.verify_error])
        if not h.owner and h.verdict in ACTION_VERDICTS:
            gap_rows.append([h.host, "Owner unknown", "No owner recorded; assign before the advisory lands."])
    for f in findings:
        if f.rule_id == "EXP-001" and f.verdict == rules.VERDICT_INFO:
            gap_rows.append([f.host, "Untrusted origin status", f.detail or ""])
        if f.rule_id == "EXP-006":
            gap_rows.append([f.host, "Edge coverage", f.detail or ""])
    if not run.verify_enabled:
        gap_rows.append(["(all)", "Passive only", "Active verify was off; version headers and canary confirmation were not collected."])
    ws = wb.create_sheet("Intel Gaps")
    write_table(ws, ["Host", "Gap", "Detail"], gap_rows, widths=[38, 30, 100], wrap=(2,),
                tiers={1: lambda v: GAP_TIER.get(v, "neutral")}, freeze="B2")
    finish_sheet(ws, tab_color=TIERS["medium"][1])

    # ---- Mitigations
    ws = wb.create_sheet("Mitigations")
    _write_mitigations(ws, signature)
    finish_sheet(ws, tab_color=TIERS["low"][1], title_rows=None)

    return wb


def _write_mitigations(ws, signature):
    set_widths(ws, [28, 120])
    ws.cell(row=1, column=1, value="Mitigations").font = _font(SIZE_SUBTITLE, color=TEXT)
    ws.row_dimensions[1].height = 24
    intro = ws.cell(row=2, column=1, value="Shipped with the signature; nothing is applied automatically. Pick the WAF rule "
                                           "that matches the zone's plan - request-body fields are Enterprise-only.")
    intro.font = _font(color=TEXT_TERTIARY)
    intro.alignment = Alignment(vertical="top", wrap_text=True)
    ws.merge_cells(start_row=2, start_column=1, end_row=2, end_column=2)
    ws.row_dimensions[2].height = LINE_PT * _lines(intro.value, 130) + 4
    mitigations = list(getattr(signature, "mitigations", None) or [])
    row = 4
    if not mitigations:
        ws.cell(row=row, column=1, value="The signature file defines no mitigations.").font = _font(color=TEXT_SECONDARY)
        return

    kind_label = {"cloudflare_waf": "WAF rule", "origin": "Origin config", "patch": "Patch"}

    def label(r: int, text: str, tier: Optional[str] = None):
        cell = ws.cell(row=r, column=1, value=text)
        if tier:
            tier_cell(cell, tier)
        else:
            cell.font = _font(bold=True, color=TEXT_SECONDARY)
        cell.alignment = Alignment(vertical="top", wrap_text=True)

    # Column B is never merged, so Excel auto-fits these wrapped rows on open.
    def body(r: int, text: Any, mono: bool = False, tier: Optional[str] = None, muted: bool = False):
        cell = ws.cell(row=r, column=2, value=sanitize_cell(text))
        cell.alignment = Alignment(vertical="top", wrap_text=True)
        if mono:
            cell.font = _font(name=MONO)
            cell.fill = _fill(BAND)
            cell.border = _box()
        elif tier:
            tier_cell(cell, tier, bold=False)
            cell.alignment = Alignment(vertical="top", wrap_text=True)
        else:
            cell.font = _font(color=TEXT_TERTIARY if muted else TEXT)

    for m in mitigations:
        label(row, kind_label.get(m.kind, m.kind), tier="neutral")
        title = ws.cell(row=row, column=2, value=m.title + (f"  ·  action: {m.action}" if m.action else ""))
        title.font = _font(SIZE_TITLE, bold=True, color=TEXT)
        title.border = _bottom(TEXT_TERTIARY)
        title.alignment = Alignment(vertical="center")
        ws.row_dimensions[row].height = 26
        row += 1
        if m.summary:
            label(row, "Summary"); body(row, m.summary); row += 1
        for e in m.expressions:
            label(row, f"Expression · {e.plan}" if e.plan else "Expression")
            body(row, e.expression, mono=True)
            row += 1
            if e.note:
                label(row, ""); body(row, e.note, muted=True); row += 1
        if m.snippet:
            label(row, "Config"); body(row, m.snippet, mono=True); row += 1
        if m.steps:
            label(row, "Steps"); body(row, "\n".join(f"{i}. {s}" for i, s in enumerate(m.steps, start=1))); row += 1
        if m.caveats:
            label(row, "Caveats"); body(row, m.caveats, tier="medium"); row += 1
        row += 1
