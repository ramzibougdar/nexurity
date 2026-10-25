#!/usr/bin/env python3
"""Render a Nexurity report (Markdown) from findings.json or incident.json.

    render_report.py --data D --ref REF [--pdf] [--docx]
    render_report.py --folder PATH [--pdf] [--docx]

Reads `<folder>/findings.json` (audit) or `<folder>/incident.json` (incident), writes
`<folder>/report.md`. Every value coming from the target is escaped; every number
(scores, counts, CVSS, exposure window, GDPR deadline) is computed here, never typed
by an agent. Python standard library only.
"""
import argparse
import datetime
import json
import os
import re
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common  # noqa: E402
import cvss4  # noqa: E402
from mask_secrets import mask_text  # noqa: E402

SEVERITIES = ["critical", "high", "medium", "low", "info"]
WEIGHTS = {"critical": 25, "high": 12, "medium": 5, "low": 2, "info": 0}
STATUSES = ["Open", "To confirm", "Fixed"]


class ReportError(Exception):
    pass


# --- escaping ------------------------------------------------------------------

_MD_SPECIAL = re.compile(r"([\\`*_\[\]<>|#~!])")


# URLs, www. hosts and e-mail addresses would become links (GFM autolinks): show them as code.
_AUTOLINK = re.compile(r"(?i)\b(?:[a-z][a-z0-9+.-]*://\S+|www\.\S+|[\w.+-]+@[\w-]+(?:\.[\w-]+)+)")


def _esc_plain(text):
    text = text.replace("&", "&amp;")
    return _MD_SPECIAL.sub(r"\\\1", text)


def esc(value):
    """Escape text from the target for prose and table cells: never a link, image, tag or heading."""
    if value is None:
        return ""
    text = " ".join(mask_text(str(value)).split())
    out, last = [], 0
    for match in _AUTOLINK.finditer(text):
        out.append(_esc_plain(text[last:match.start()]))
        out.append(code_inline(match.group(0)))
        last = match.end()
    out.append(_esc_plain(text[last:]))
    text = "".join(out)
    if re.match(r"^([-+=]|\d+[.)])(\s|$)", text):
        text = "\\" + text
    return text


def code_inline(value):
    """Inline code safe inside a table cell."""
    text = " ".join(mask_text(str(value)).split())
    longest = max((len(m) for m in re.findall(r"`+", text)), default=0)
    fence = "`" * (longest + 1)
    text = text.replace("|", "\\|")
    pad = " " if text.startswith("`") or text.endswith("`") or longest else ""
    return "%s%s%s%s%s" % (fence, pad, text, pad, fence)


_LANG_OK = re.compile(r"^[a-z0-9+#.-]{1,20}$")


def code_block(code, language="text", defang_urls=False):
    text = mask_text(str(code or "")).replace("\r\n", "\n").rstrip("\n")
    if defang_urls:
        text = defang(text)
    longest = max((len(m) for m in re.findall(r"`+", text)), default=0)
    fence = "`" * max(3, longest + 1)
    lang = language if language and _LANG_OK.match(language) else "text"
    return "%s%s\n%s\n%s" % (fence, lang, text, fence)


def defang(text):
    text = re.sub(r"(?i)\bhttp(s?)://", lambda m: "hxxp%s://" % m.group(1), str(text))
    text = re.sub(r"(?i)\b((?:[a-z0-9-]+\.)+)([a-z]{2,24})\b",
                  lambda m: m.group(1)[:-1].replace(".", "[.]") + "[.]" + m.group(2), text)
    return text


def slugify(heading, used):
    text = re.sub(r"\\(.)", r"\1", heading).strip().lower()
    text = re.sub(r"[^\w\- ]", "", text, flags=re.UNICODE)
    slug = text.replace(" ", "-")
    base, n = slug, 0
    while slug in used:
        n += 1
        slug = "%s-%d" % (base, n)
    used.add(slug)
    return slug


# --- dates ---------------------------------------------------------------------

def parse_dt(value):
    if not value:
        return None
    try:
        return datetime.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        try:
            return datetime.datetime.strptime(str(value), "%Y-%m-%d")
        except ValueError:
            raise ReportError("invalid date %r (expected ISO yyyy-mm-ddThh:mm)" % value)


def fmt_date(value, labels):
    dt = parse_dt(value)
    return dt.strftime(labels["date_format"]) if dt else ""


def fmt_dt(value, labels):
    dt = parse_dt(value)
    return dt.strftime(labels["datetime_format"]) if dt else ""


def duration(start, end, labels):
    a, b = parse_dt(start), parse_dt(end)
    if not a or not b:
        return labels["dash"]
    if (a.tzinfo is None) != (b.tzinfo is None):
        a, b = a.replace(tzinfo=None), b.replace(tzinfo=None)
    hours = int(round((b - a).total_seconds() / 3600))
    if hours < 0:
        raise ReportError("the end of the exposure window is before its start")
    days, rest = divmod(hours, 24)
    return labels["duration"].format(d=days, h=rest) if days else labels["duration_hours"].format(h=hours)


# --- findings ------------------------------------------------------------------

def rate(finding):
    """CVSS score and severity, computed from the vector (never from the JSON)."""
    vector = finding.get("cvss_vector")
    if vector:
        try:
            value = cvss4.score(vector)
        except cvss4.InvalidVector as exc:
            raise ReportError("finding %r: invalid CVSS 4.0 vector (%s); send it back to the verifier"
                              % (finding.get("title"), exc))
        stored = finding.get("cvss_score")
        if stored is not None and abs(float(stored) - value) > 1e-9:
            raise ReportError("finding %r: stored CVSS score %s differs from the computed %.1f"
                              % (finding.get("title"), stored, value))
        severity = cvss4.severity(value)
        severity = "info" if severity == "none" else severity
    else:
        value, severity = None, "info"
    adjusted = (finding.get("business_adjustment") or {}).get("severity")
    if adjusted:
        if adjusted not in SEVERITIES:
            raise ReportError("finding %r: unknown adjusted severity %r" % (finding.get("title"), adjusted))
        if not (finding["business_adjustment"].get("justification") or "").strip():
            raise ReportError("finding %r: a business-impact adjustment needs a justification" % finding.get("title"))
    return value, severity, adjusted or severity


def prepare_findings(findings, prefix):
    prepared = []
    for i, finding in enumerate(findings, 1):
        status = finding.get("status", "Open")
        if status not in STATUSES:
            raise ReportError("finding %r: unknown status %r" % (finding.get("title"), status))
        if not (finding.get("title") or "").strip():
            raise ReportError("finding #%d has no title" % i)
        value, base_severity, severity = rate(finding)
        item = dict(finding)
        item.update({"id": "%s-%02d" % (prefix, i), "cvss": value, "base_severity": base_severity,
                     "severity": severity, "status": status})
        prepared.append(item)
    return prepared


def score_of(findings):
    open_findings = [f for f in findings if f["status"] == "Open"]
    penalty = sum(WEIGHTS[f["severity"]] for f in open_findings)
    score = max(0, 100 - penalty)
    level = "good" if score >= 85 else "fair" if score >= 65 else "insufficient" if score >= 40 else "critical"
    to_confirm = sum(1 for f in findings if f["status"] == "To confirm")
    return score, level, to_confirm


def counts(findings):
    return {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITIES}


def areas(findings, labels):
    by_area = {}
    for f in findings:
        name = f.get("area") or labels["dash"]
        entry = by_area.setdefault(name, {"name": name, "total": 0, "weight": 0, "n": dict.fromkeys(SEVERITIES, 0)})
        entry["total"] += 1
        entry["weight"] += WEIGHTS[f["severity"]]
        entry["n"][f["severity"]] += 1
    return sorted(by_area.values(), key=lambda a: (-a["weight"], -a["total"], a["name"]))


# --- Markdown building blocks ---------------------------------------------------

def table(headers, rows, align=None):
    align = align or ["---"] * len(headers)
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join(align) + "|"]
    for row in rows:
        lines.append("| " + " | ".join(row) + " |")
    return "\n".join(lines)


def kv_table(rows):
    return table(["", ""], [["**%s**" % k, v] for k, v in rows if v not in (None, "")])


def bullets(items):
    return "\n".join("- " + esc(item) for item in items if str(item).strip())


def heading_link(number, title, used):
    text = "%02d · %s" % (number, title)
    return text, slugify(text, used)


class Doc:
    def __init__(self):
        self.parts = []

    def add(self, *blocks):
        for block in blocks:
            if block is not None and block != "":
                self.parts.append(block)

    def text(self):
        return "\n\n".join(self.parts).rstrip() + "\n"


def finding_block(f, labels, extra_line=None, with_area=True):
    sev = labels["severity"][f["severity"]]
    cvss_txt = "%.1f" % f["cvss"] if f["cvss"] is not None else labels["dash"]
    if extra_line:
        meta = "**%s** · %s%s**%s** · %s" % (sev, labels["cvss"], labels["colon"], cvss_txt, extra_line)
    else:
        meta = "**%s** · %s%s**%s** · %s%s**%s**" % (sev, labels["cvss"], labels["colon"], cvss_txt, labels["status_label"], labels["colon"],
                                                    labels["status"][f["status"]])
    rows = [(labels["category"], esc(f.get("category")))]
    if with_area:
        rows.append((labels["area"], esc(f.get("area"))))
    if f.get("component"):
        rows.append((labels["component"], code_inline(f["component"])))
    if f.get("cvss_vector"):
        rows.append((labels["cvss_vector"], code_inline(f["cvss_vector"])))
    parts = ["### %s · %s" % (f["id"], esc(f["title"])), meta, kv_table(rows)]
    adj = f.get("business_adjustment") or {}
    if adj.get("severity") and adj["severity"] != f["base_severity"]:
        parts.append("*%s*" % labels["business_adjustment"].format(
            **{"from": labels["severity"][f["base_severity"]], "to": labels["severity"][adj["severity"]],
               "why": esc(adj.get("justification"))}))
    label_desc = labels["description"] if f.get("cvss_vector") else labels["observation"]
    if f.get("description"):
        parts += ["**%s**" % label_desc, esc(f["description"])]
    if f.get("table"):
        t = f["table"]
        parts.append(table([esc(h) for h in t.get("headers", [])],
                           [[esc(c) for c in row] for row in t.get("rows", [])]))
    if f.get("evidence"):
        parts.append("**%s**" % labels["evidence"])
        for ev in f["evidence"]:
            if ev.get("label"):
                parts.append(esc(ev["label"]))
            parts.append(code_block(ev.get("code", ""), ev.get("language", "text"), ev.get("defang", False)))
    if f.get("impact"):
        parts += ["**%s**" % labels["impact"], esc(f["impact"])]
    if f.get("recommendations"):
        parts += ["**%s**" % labels["recommendation"], bullets(f["recommendations"])]
    if f.get("recommendation_code"):
        rc = f["recommendation_code"]
        parts.append(code_block(rc.get("code", ""), rc.get("language", "text")))
    if f.get("references"):
        parts.append("%s%s%s" % (labels["references"], labels["colon"], " · ".join(esc(r) for r in f["references"])))
    return "\n\n".join(parts)


def plan_list(items, labels):
    lines = []
    for item in items or []:
        ref = item.get("ref")
        lines.append("- **%s** · %s" % (esc(ref), esc(item.get("action"))) if ref else
                     "- %s · %s" % (labels["dash"], esc(item.get("action"))))
    return "\n".join(lines)


def counts_table(c, labels):
    return table([labels["severity_long"][s] for s in SEVERITIES], [[str(c[s]) for s in SEVERITIES]],
                 [":---:"] * 5)


def history_table(history, labels, report):
    rows = history or [{"version": report.get("report_version", "1.0"),
                        "date": report.get("report_date"), "purpose": labels["initial_report"]}]
    return table(labels["history_headers"],
                 [[esc(h.get("version")), esc(fmt_date(h.get("date"), labels) or h.get("date") or ""),
                   esc(h.get("purpose"))] for h in rows])


def header(report, labels, title_key, period_key):
    period = report.get("period") or {}
    period_txt = "%s → %s" % (fmt_date(period.get("start"), labels), fmt_date(period.get("end"), labels))
    version = "v%s · %s" % (esc(report.get("report_version", "1.0")), fmt_date(report.get("report_date"), labels))
    parts = ["# %s · %s" % (labels[title_key], esc(report.get("target_name"))), labels["confidential"]]
    if report.get("context"):
        parts.append(esc(report["context"]))
    parts.append(kv_table([(labels["client"], esc(report.get("client"))),
                           (labels["reference"], esc(report.get("ref"))),
                           (labels[period_key], period_txt),
                           (labels["report_version"], version)]))
    return "\n\n".join(parts)


def toc(titles, used, contents_label):
    """Table of contents; anchors follow GitHub's heading slugs."""
    lines, sections = [], []
    for i, title in enumerate(titles, 1):
        text, slug = heading_link(i, title, used)
        sections.append(text)
        lines.append("%d. [%s](#%s)" % (i, title, slug))
    return "## %s\n\n%s" % (contents_label, "\n".join(lines)), sections


# --- audit report -------------------------------------------------------------

def render_audit(report, labels):
    findings = prepare_findings(report.get("findings", []), "V")
    score, level, to_confirm = score_of(findings)
    doc = Doc()
    doc.add(header(report, labels, "audit_title", "audit_period"))
    contents, sections = toc(labels["audit_sections"], set(), labels["contents"])
    doc.add(contents)

    # 01
    doc.add("---", "## " + sections[0], "### " + labels["key_takeaways"])
    doc.add("**%s%s%d / 100** · %s" % (labels["security_score"], labels["colon"], score, labels["level"][level]),
            labels["score_note"].format(n=to_confirm))
    if report.get("summary"):
        doc.add(esc(report["summary"]))
    doc.add(counts_table(counts(findings), labels))
    if findings:
        doc.add("### " + labels["breakdown_by_area"],
                table([labels["area"], labels["findings_word"]] + [labels["severity"][s] for s in SEVERITIES],
                      [[esc(a["name"]), str(a["total"])] + [str(a["n"][s]) for s in SEVERITIES] for a in areas(findings, labels)],
                      ["---", ":---:"] + [":---:"] * 5))
    if report.get("priorities"):
        doc.add("### " + labels["top_priorities"],
                "\n".join("%d. **%s** · %s" % (i, labels["severity"].get(p.get("severity"), esc(p.get("severity"))), esc(p.get("action")))
                          for i, p in enumerate(report["priorities"][:3], 1)))

    # 02
    scope = report.get("scope") or {}
    doc.add("---", "## " + sections[1], "### " + labels["what_we_tested"])
    if scope.get("targets"):
        doc.add(table([labels["target"], labels["type"], labels["environment"], labels["version"]],
                      [[esc(t.get("target")), esc(t.get("type")), esc(t.get("environment")),
                        esc(t.get("version")) or labels["dash"]] for t in scope["targets"]]))
    if scope.get("in_scope"):
        doc.add("**%s**" % labels["in_scope"], bullets(scope["in_scope"]))
    if scope.get("out_of_scope"):
        doc.add("**%s**" % labels["out_of_scope"], bullets(scope["out_of_scope"]))
    doc.add("### " + labels["approach"],
            "\n".join("%d. **%s**%s%s" % (i, a, labels["colon"], b) for i, (a, b) in enumerate(labels["audit_approach"], 1)))
    lines = [labels["standards"]]
    if report.get("tools"):
        lines.append("%s%s%s." % (labels["tools"], labels["colon"], ", ".join(esc(t) for t in report["tools"])))
    doc.add("  \n".join(lines), labels["ai_note"])
    if report.get("local_environment"):
        doc.add("*%s*" % labels["local_note"])

    # 03
    doc.add("---", "## " + sections[2], "### " + labels["how_to_read"], labels["scale_intro"],
            table(labels["scale_headers"],
                  [["**%s**" % labels["severity"][s], r, m, d] for s, r, m, d in labels["scale_rows"]]))

    # 04
    doc.add("---", "## " + sections[3], "### " + labels["vulns_one_by_one"])
    if not findings:
        doc.add(labels["no_findings"])
    for f in findings:
        doc.add(finding_block(f, labels))

    # 05
    doc.add("---", "## " + sections[4], "### " + labels["all_findings"])
    if findings:
        doc.add(table(labels["summary_headers"],
                      [[f["id"], esc(f["title"]), esc(f.get("area")), esc(f.get("category")),
                        "%.1f" % f["cvss"] if f["cvss"] is not None else labels["dash"],
                        labels["severity"][f["severity"]], labels["status"][f["status"]]] for f in findings],
                      ["---", "---", "---", "---", ":---:", "---", "---"]))
    else:
        doc.add(labels["no_findings"])

    # 06
    plan = report.get("action_plan") or {}
    doc.add("---", "## " + sections[5], "### " + labels["what_to_fix_first"])
    for key, label in (("immediate", "plan_immediate"), ("short_term", "plan_short"), ("medium_term", "plan_medium")):
        if plan.get(key):
            doc.add("**%s**" % labels[label], plan_list(plan[key], labels))

    # 07
    doc.add("---", "## " + sections[6], "### " + labels["glossary"],
            "\n".join("- **%s**%s%s" % (a, labels["colon"], b) for a, b in labels["audit_glossary"]),
            "### " + labels["document_history"], history_table(report.get("history"), labels, report),
            labels["audit_disclaimer"], "---", labels["footer"].format(ref=esc(report.get("ref"))))
    return doc.text()


# --- incident report ------------------------------------------------------------

def render_incident(report, labels):
    findings = prepare_findings(report.get("findings", []), "I")
    doc = Doc()
    doc.add(header(report, labels, "incident_title", "period_analysed"))
    contents, sections = toc(labels["incident_sections"], set(), labels["contents"])
    doc.add(contents)

    # 01
    dates = report.get("dates") or {}
    state = report.get("status")
    if state not in labels["incident_state"]:
        raise ReportError("incident status must be one of %s" % ", ".join(labels["incident_state"]))
    end = dates.get("containment") or dates.get("detection")
    doc.add("---", "## " + sections[0], "### " + labels["what_happened"])
    sev = report.get("severity", "critical")
    doc.add("**%s%s%s** · %s" % (labels["incident_status"], labels["colon"], labels["incident_state"][state],
                                  _severity_phrase(sev, labels)))
    doc.add(table([labels["estimated_start"], labels["detection"], labels["containment"], labels["exposure_window"]],
                  [[fmt_dt(dates.get("start"), labels) or labels["dash"], fmt_dt(dates.get("detection"), labels) or labels["dash"],
                    fmt_dt(dates.get("containment"), labels) or labels["dash"], duration(dates.get("start"), end, labels)]]))
    if report.get("summary"):
        doc.add(esc(report["summary"]))
    if report.get("capabilities"):
        doc.add("**%s**" % labels["attacker_could"], bullets(report["capabilities"]))
    if report.get("not_observed"):
        doc.add("**%s**" % labels["not_observed"], bullets(report["not_observed"]))
    if report.get("immediate_actions"):
        doc.add("### " + labels["immediate_actions"],
                "\n".join("%d. **%s** · %s" % (i, labels["severity"].get(a.get("severity"), esc(a.get("severity"))), esc(a.get("action")))
                          for i, a in enumerate(report["immediate_actions"][:3], 1)))

    # 02
    doc.add("---", "## " + sections[1], "### " + labels["what_we_analysed"])
    if report.get("symptoms"):
        doc.add("**%s**" % labels["reported_symptoms"], bullets(report["symptoms"]))
    if report.get("affected_system"):
        doc.add("**%s**" % labels["affected_system"], bullets(report["affected_system"]))
    if report.get("evidence_sources"):
        doc.add("### " + labels["evidence_sources"], labels["evidence_intro"],
                table(labels["evidence_headers"],
                      [[esc(e.get("source")), code_inline(e.get("location", "")), esc(e.get("period")),
                        code_inline(_short_hash(e.get("sha256", "")))] for e in report["evidence_sources"]]))
    doc.add("### " + labels["approach"],
            "\n".join("%d. **%s**%s%s" % (i, a, labels["colon"], b) for i, (a, b) in enumerate(labels["incident_approach"], 1)))
    note = labels["read_only_note"]
    if report.get("limitations"):
        note += " %s%s%s" % (labels["limitations"], labels["colon"], esc(report["limitations"]))
    doc.add(note, labels["ai_note"])

    # 03
    doc.add("---", "## " + sections[2], "### " + labels["how_attack_unfolded"])
    events = sorted(report.get("timeline", []), key=lambda e: parse_dt(e.get("date")) or datetime.datetime.min)
    if events:
        doc.add(table(labels["timeline_headers"],
                      [[fmt_dt(e.get("date"), labels), labels["phase"].get(e.get("phase"), esc(e.get("phase"))),
                        esc(e.get("event")), esc(e.get("details")), esc(e.get("source"))] for e in events]))
    if report.get("timezone"):
        doc.add(labels["times_shown_in"].format(tz=esc(report["timezone"])) +
                ((" " + esc(report["timezone_note"])) if report.get("timezone_note") else ""))

    # 04
    entry = report.get("entry_point") or {}
    doc.add("---", "## " + sections[3], "### " + labels["how_attacker_got_in"])
    if entry:
        rows = [(labels["vector"], esc(entry.get("vector"))),
                (labels["component"], code_inline(entry["component"]) if entry.get("component") else ""),
                (labels["confidence"], labels["confidence_values"].get(entry.get("confidence"), esc(entry.get("confidence"))))]
        if entry.get("finding"):
            rows.append((labels["related_finding"], esc(entry["finding"])))
        doc.add(kv_table(rows))
        if entry.get("description"):
            doc.add(esc(entry["description"]))
        if entry.get("log_extract"):
            doc.add(code_block(entry["log_extract"], "text", defang_urls=True))
        if entry.get("ruled_out"):
            doc.add("**%s**" % labels["ruled_out"], bullets(entry["ruled_out"]))

    # 05
    doc.add("---", "## " + sections[4], "### " + labels["traces"], labels["ioc_intro"])
    if report.get("iocs"):
        doc.add(table(labels["ioc_headers"],
                      [[esc(i.get("type")), code_inline(defang(i.get("value", "")) if (i.get("kind") or i.get("type", "")).lower() in ("url", "domain", "domaine") else i.get("value", "")),
                        esc(i.get("role")), esc(i.get("first_seen")) or labels["dash"], esc(i.get("action")) or labels["dash"]]
                       for i in report["iocs"]]))
    doc.add(labels["defang_note"])

    # 06
    doc.add("---", "## " + sections[5], "### " + labels["flaws_made_possible"],
            counts_table(counts(findings), labels))
    for f in findings:
        extra = "%s%s**%s**" % (labels["role_in_incident"], labels["colon"], esc(f.get("role"))) if f.get("role") else None
        doc.add(finding_block(f, labels, extra_line=extra, with_area=False))

    # 07
    rem = report.get("remediation") or {}
    doc.add("---", "## " + sections[6], "### " + labels["what_to_do"])
    for key, label in (("containment", "rem_containment"), ("eradication", "rem_eradication"), ("hardening", "rem_hardening")):
        if rem.get(key):
            doc.add("**%s**" % labels[label], plan_list(rem[key], labels))
    doc.add(labels["rem_note"])

    # 08
    pdata = report.get("personal_data") or {}
    doc.add("---", "## " + sections[7], "### " + labels["gdpr_obligations"])
    aware = pdata.get("awareness")
    deadline = parse_dt(aware) + datetime.timedelta(hours=72) if aware else None
    doc.add(kv_table([(labels["personal_data_exposed"], esc(pdata.get("exposed"))),
                      (labels["people_affected"], esc(pdata.get("people"))),
                      (labels["became_aware"], fmt_dt(aware, labels)),
                      (labels["notification_deadline"], deadline.strftime(labels["datetime_format"]) if deadline else "")]))
    if pdata.get("categories"):
        doc.add(table(labels["data_headers"],
                      [[esc(c.get("category")), esc(c.get("exposure")), esc(c.get("rationale"))] for c in pdata["categories"]]))
    doc.add("**%s**" % labels["gdpr_requires"], "\n".join("- " + p for p in labels["gdpr_points"]),
            labels["gdpr_decision"].format(controller=esc(pdata.get("controller") or report.get("client"))))

    # 09
    doc.add("---", "## " + sections[8], "### " + labels["glossary"],
            "\n".join("- **%s**%s%s" % (a, labels["colon"], b) for a, b in labels["incident_glossary"]),
            "### " + labels["document_history"], history_table(report.get("history"), labels, report),
            labels["incident_disclaimer"], "---", labels["footer"].format(ref=esc(report.get("ref"))))
    return doc.text()


def _severity_phrase(sev, labels):
    label = labels["severity_long"].get(sev, esc(sev))
    phrase = labels["severity_phrase"]
    return phrase.format(sev=label if phrase.startswith("{sev}") else label.lower())


def _short_hash(value):
    value = str(value or "")
    return value[:4] + "…" + value[-4:] if len(value) > 12 else value


# --- entry point -----------------------------------------------------------------

def load_labels(lang):
    path = os.path.join(common.PLUGIN_ROOT, "i18n", "%s.json" % lang)
    if not os.path.exists(path):
        raise ReportError("no labels for language %r" % lang)
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def render_folder(folder):
    incident_path = os.path.join(folder, "incident.json")
    audit_path = os.path.join(folder, "findings.json")
    if os.path.exists(incident_path):
        report, render = common.read_json(incident_path), render_incident
    elif os.path.exists(audit_path):
        report, render = common.read_json(audit_path), render_audit
    else:
        raise ReportError("no findings.json or incident.json in %s" % folder)
    if not isinstance(report, dict):
        raise ReportError("the report JSON could not be read")
    config = common.read_json(os.path.join(folder, "audit-config.json"), {}) or {}
    lang = report.get("language") or config.get("language") or "en"
    text = render(report, load_labels(lang))
    out = os.path.join(folder, "report.md")
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(text)
    return out


def export(markdown_path, fmt):
    pandoc = shutil.which("pandoc")
    if not pandoc:
        return "pandoc is not installed: the report stays in Markdown (%s)" % markdown_path
    target = os.path.splitext(markdown_path)[0] + "." + fmt
    result = subprocess.run([pandoc, "-f", "gfm", "-o", target, markdown_path], capture_output=True, text=True)
    if result.returncode != 0:
        return "pandoc could not export %s: %s" % (fmt, result.stderr.strip()[:300])
    return target


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--data")
    parser.add_argument("--ref")
    parser.add_argument("--folder")
    parser.add_argument("--pdf", action="store_true")
    parser.add_argument("--docx", action="store_true")
    args = parser.parse_args(argv)
    folder = args.folder
    if not folder:
        if not args.ref:
            parser.error("--ref or --folder is required")
        entry = (common.read_json(os.path.join(common.engagements_dir(common.data_dir(args.data)), "index.json"), {}) or {}).get(args.ref)
        if not entry:
            print("unknown engagement %s" % args.ref, file=sys.stderr)
            return 1
        folder = entry["folder"]
    try:
        out = render_folder(folder)
    except ReportError as exc:
        print("report not generated: %s" % exc, file=sys.stderr)
        return 1
    print(out)
    for fmt, wanted in (("pdf", args.pdf), ("docx", args.docx)):
        if wanted:
            print(export(out, fmt))
    return 0


if __name__ == "__main__":
    sys.exit(main())
