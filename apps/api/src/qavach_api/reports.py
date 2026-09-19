"""Executive PDF (T-094) and asset-register XLSX (T-095).

Both are *renderings of the Crypto Risk Register* (I5): they add no analysis and
compute no score. Whatever the register says is what is printed, so the PDF, the
XLSX, the JSON and the UI cannot disagree. Neither goes into the CBOM.

Presentation rules carried over from the invariants:

* **I1** - Grover-affected is informational and never in the "act now" section or
  in an alarm colour; classical-weak is called out as "urgent, not a quantum
  issue".
* **I8** - UNKNOWN is shown hatched grey / stated as a *coverage failure*, is
  counted separately, and never appears in a "safe" figure.
* **I3** - every figure that depends on `Z` names the scenario that produced it.
* Nothing wall-clock-dependent is written (`invariant=1`, fixed workbook
  properties), so the same scan renders to the same bytes.
"""

from __future__ import annotations

import io
from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any
from xml.sax.saxutils import escape

from openpyxl import Workbook
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

CLASS_LABEL = {
    "quantum-vulnerable": "Quantum-vulnerable",
    "classical-weak": "Classically weak (urgent - not a quantum issue)",
    "grover-affected": "Grover-affected (informational)",
    "quantum-safe": "Quantum-safe",
    "unknown": "Unclassified (coverage failure)",
}
CLASS_ORDER = list(CLASS_LABEL)
BAND_LABEL = {
    "overdue": "Overdue",
    "imminent": "Imminent",
    "planned": "Planned",
    "not-applicable": "Not applicable",
    "coverage-gap": "Coverage gap",
}
# hex without '#'. UNKNOWN is grey and hatched - never green (I8).
CLASS_FILL = {
    "quantum-vulnerable": "F4B6B6",
    "classical-weak": "F8D9A0",
    "grover-affected": "C9DDF2",
    "quantum-safe": "C6E5C9",
    "unknown": "BFBFBF",
}
HEURISTIC = (
    "Y (migration time) and the effort figures are planning heuristics from configured "
    "policy, not measurements. Scores are reproducible from the policy snapshot named "
    "in this report."
)


def _recommendation(entry: Mapping[str, Any]) -> str:
    rec = entry.get("recommendation") or {}
    if rec.get("primary"):
        return f"{rec['primary']['name']} ({rec['primary']['standard']})"
    return str(rec.get("reason") or "")


def _label(entry: Mapping[str, Any], labels: Mapping[str, str]) -> str:
    return labels.get(entry["bom_ref"], entry["bom_ref"])


def _z_line(entry: Mapping[str, Any]) -> str:
    z = entry.get("z_effective")
    if not z:
        return ""
    return f"{z['date']} ({z['scenario']}{'; binding' if z['binding'] else ''})"


def build_xlsx(
    register: Mapping[str, Any], labels: Mapping[str, str], scan: Mapping[str, Any]
) -> bytes:
    wb = Workbook()
    wb.properties.creator = "QAVACH"
    wb.properties.created = wb.properties.modified = datetime(2000, 1, 1)

    summary = wb.active
    assert summary is not None
    summary.title = "Summary"
    s = register["summary"]
    rows: list[tuple[str, Any]] = [
        ("Scan", scan["id"]),
        ("Target", scan["target_ref"]),
        ("As of", register["as_of"]),
        ("Policy snapshot", register["policy"]["snapshot_id"]),
        ("Z scenario", register["policy"]["z_scenario"]),
        ("Entries (asset x system)", s["total"]),
        ("", ""),
    ]
    rows += [
        (CLASS_LABEL[c], s["by_finding_class"].get(c, 0))
        for c in CLASS_ORDER
        if c in s["by_finding_class"]
    ]
    rows += [
        ("", ""),
        ("Coverage failures", s["coverage_failures"]),
        ("", s["coverage_failure_note"]),
    ]
    rows += [("", ""), ("Note", HEURISTIC)]
    for row_values in rows:
        summary.append(list(row_values))
    summary.column_dimensions["A"].width = 46
    summary.column_dimensions["B"].width = 90
    for row in summary.iter_rows(min_col=1, max_col=1):
        row[0].font = Font(bold=True)
    for i, (label, _) in enumerate(rows, start=1):
        for c, text in CLASS_LABEL.items():
            if label == text:
                summary.cell(i, 1).fill = _fill(c)
    summary["B" + str(len(rows))].alignment = Alignment(wrap_text=True, vertical="top")

    ws = wb.create_sheet("Assets")
    header = [
        "Algorithm",
        "System",
        "Finding class",
        "Urgency band",
        "Outcome",
        "Reason",
        "Migration authority",
        "Z (effective)",
        "Recommendation",
        "Roadmap wave",
        "Disputed",
        "Capability only",
        "bom-ref",
    ]
    ws.append(header)
    for cell in ws[1]:
        cell.font = Font(bold=True)
    for e in register["entries"]:
        ws.append(
            [
                _label(e, labels),
                e["system_id"] or "(unassigned)",
                CLASS_LABEL.get(e["finding_class"], e["finding_class"]),
                BAND_LABEL.get(e["band"], e["band"]),
                e["outcome"],
                e["reason"],
                e["migration_authority"],
                _z_line(e),
                _recommendation(e),
                (e.get("roadmap") or {}).get("wave", ""),
                "yes" if e["disputed"] else "",
                "yes" if e["capability_only"] else "",
                e["bom_ref"],
            ]
        )
        ws.cell(ws.max_row, 3).fill = _fill(e["finding_class"])
    for i, width in enumerate([26, 18, 34, 16, 14, 50, 20, 30, 28, 12, 10, 14, 30], start=1):
        ws.column_dimensions[get_column_letter(i)].width = width
    ws.freeze_panes = "A2"
    ws.auto_filter.ref = ws.dimensions

    road = wb.create_sheet("Roadmap")
    plan = register.get("roadmap") or {}
    road.append(["Wave", "Kind", "Units"])
    for cell in road[1]:
        cell.font = Font(bold=True)
    for wave in plan.get("waves", []):
        road.append([wave["index"], wave["kind"], ", ".join(wave["units"])])
    road.append([])
    road.append(["Hybrid bridges (mutual dependencies - a finding, not an error)"])
    for b in plan.get("bridges", []):
        road.append([", ".join(b["members"]), b["variant"], " -> ".join(b["phases"])])
    for title, key in (
        ("Vendor dependencies", "vendor_dependencies"),
        ("Named blockers", "named_blockers"),
        ("Infeasible units", "infeasible"),
    ):
        road.append([])
        road.append([title])
        for item in plan.get(key, []):
            road.append([str(item)])
    road.column_dimensions["A"].width = 60
    road.column_dimensions["B"].width = 16
    road.column_dimensions["C"].width = 100

    out = io.BytesIO()
    wb.save(out)
    return out.getvalue()


def _fill(finding_class: str) -> PatternFill:
    if finding_class == "unknown":
        # hatched, so a colour-blind reader and a black-and-white printout both see "not classified"
        return PatternFill("lightUp", fgColor="7F7F7F", bgColor=CLASS_FILL["unknown"])
    return PatternFill("solid", fgColor=CLASS_FILL[finding_class])


def act_now(entries: Sequence[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    """The "Act now" list, in this order: classically weak entries (broken today,
    whatever Mosca says - the urgency band does not apply to a break that needs no
    quantum computer, which is why SARIF also treats them as errors), then
    quantum-vulnerable entries that are overdue, then imminent.

    Grover-affected is informational (I1) and an unclassified entry is a coverage
    failure, not a verdict (I8); neither may ever be told to a reader as "act now",
    whatever band they were given."""
    weak = [e for e in entries if e["finding_class"] == "classical-weak"]
    quantum = [e for e in entries if e["finding_class"] == "quantum-vulnerable"]
    return weak + [e for band in ("overdue", "imminent") for e in quantum if e["band"] == band]


def build_pdf(
    register: Mapping[str, Any], labels: Mapping[str, str], scan: Mapping[str, Any]
) -> bytes:
    styles = getSampleStyleSheet()
    body = ParagraphStyle("body", parent=styles["BodyText"], fontSize=9.5, leading=13)
    small = ParagraphStyle("small", parent=body, fontSize=8, leading=10.5, textColor=colors.grey)
    cell = ParagraphStyle("cell", parent=body, fontSize=7.5, leading=9.5)
    h1, h2 = styles["Title"], styles["Heading2"]

    def p(text: str, style: ParagraphStyle = body) -> Paragraph:
        return Paragraph(escape(text), style)

    s = register["summary"]
    entries: Sequence[Mapping[str, Any]] = register["entries"]
    total = max(s["total"], 1)
    unknown = s["by_finding_class"].get("unknown", 0)
    story: list[Any] = [
        p("QAVACH - Cryptographic Asset Inventory and PQC Migration Report", h1),
        p(
            f"Target: {scan['target_ref']}  |  Scan: {scan['id']}  |  "
            f"As of: {register['as_of']}  |  Z scenario: {register['policy']['z_scenario']}",
            small,
        ),
        p(f"Policy snapshot: {register['policy']['snapshot_id']}", small),
        Spacer(1, 6 * mm),
        p("Posture", h2),
        p(
            f"{s['total']} (asset, system) entries were assessed. Findings are kept in four "
            "classes: quantum-vulnerable (broken by a future quantum computer), classically "
            "weak (broken today - urgent, but not a quantum issue), Grover-affected "
            "(informational only) and quantum-safe."
        ),
    ]
    rows = [["Finding class", "Entries", "Share"]]
    for c in CLASS_ORDER:
        n = s["by_finding_class"].get(c, 0)
        if n:
            rows.append([CLASS_LABEL[c], str(n), f"{100 * n / total:.0f}%"])
    table = Table(rows, colWidths=[95 * mm, 25 * mm, 25 * mm])
    style = [
        ("GRID", (0, 0), (-1, -1), 0.25, colors.lightgrey),
        ("BACKGROUND", (0, 0), (-1, 0), colors.whitesmoke),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ALIGN", (1, 0), (-1, -1), "RIGHT"),
    ]
    for i, row in enumerate(rows[1:], start=1):
        cls = next(c for c in CLASS_ORDER if CLASS_LABEL[c] == row[0])
        style.append(("BACKGROUND", (0, i), (0, i), colors.HexColor("#" + CLASS_FILL[cls])))
    table.setStyle(TableStyle(style))
    story += [Spacer(1, 3 * mm), table, Spacer(1, 3 * mm)]

    if unknown:
        story.append(
            p(
                f"Coverage: {unknown} of {s['total']} entries ({100 * unknown / total:.0f}%) could "
                "not be classified. This is a coverage failure, not a finding: those assets are "
                "unassessed and are not counted as safe.",
                body,
            )
        )
    else:
        story.append(p("Coverage: every entry was classified."))

    listed = act_now(entries)
    weak = [e for e in listed if e["finding_class"] == "classical-weak"]
    urgent = [e for e in listed if e["band"] == "overdue"]
    imminent = [e for e in listed if e["band"] == "imminent"]
    story += [
        Spacer(1, 4 * mm),
        p("Act now", h2),
        p(
            f"{len(weak)} classically weak (broken today; not a quantum issue), "
            f"{len(urgent)} quantum-vulnerable overdue and {len(imminent)} imminent. "
            "Grover-affected and unclassified entries never appear here."
        ),
    ]
    if listed:
        act = [["Algorithm", "System", "Band", "Class", "Recommended"]]
        for e in listed[:25]:
            act.append(
                [
                    _label(e, labels),
                    e["system_id"] or "-",
                    "Broken today"
                    if e["finding_class"] == "classical-weak"
                    else BAND_LABEL[e["band"]],
                    "classical (not quantum)"
                    if e["finding_class"] == "classical-weak"
                    else "quantum",
                    p(_recommendation(e), cell),
                ]
            )
        t = Table(act, repeatRows=1, colWidths=[26 * mm, 26 * mm, 22 * mm, 34 * mm, 66 * mm])
        t.setStyle(
            TableStyle(
                [
                    ("GRID", (0, 0), (-1, -1), 0.25, colors.lightgrey),
                    ("BACKGROUND", (0, 0), (-1, 0), colors.whitesmoke),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                ]
            )
        )
        story += [Spacer(1, 2 * mm), t]
        if len(listed) > 25:
            story.append(p(f"... and {len(listed) - 25} more in the XLSX register.", small))

    road = register.get("roadmap") or {}
    story += [Spacer(1, 4 * mm), p("Migration roadmap", h2)]
    if road:
        story.append(
            p(
                f"{len(road.get('waves', []))} wave(s); "
                f"{len(road.get('bridges', []))} hybrid-bridge cycle(s); "
                f"{len(road.get('vendor_dependencies', []))} vendor dependenc(ies); "
                f"{len(road.get('infeasible', []))} schedule-infeasible unit(s); "
                f"{road.get('excluded_trust_anchors', 0)} external trust anchor(s) inventoried "
                "but never scheduled."
            )
        )
        for b in road.get("bridges", []):
            story.append(
                p(
                    f"Hybrid bridge ({b['variant']}): {', '.join(b['members'])}. "
                    "A mutual dependency is a finding, not an error: run classical and PQC "
                    "together, then retire the classical half.",
                    body,
                )
            )
    else:
        story.append(p("No roadmap was produced for this scan."))
    story += [Spacer(1, 6 * mm), p(register["heuristics_notice"], small)]

    out = io.BytesIO()
    SimpleDocTemplate(
        out,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=16 * mm,
        bottomMargin=16 * mm,
        title="QAVACH report",
        author="QAVACH",
        invariant=1,
    ).build(story)
    return out.getvalue()
