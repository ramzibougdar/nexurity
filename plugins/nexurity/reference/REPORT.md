# Data formats

All JSON. Text values are written in the report language. Values coming from the target are kept as they are:
`render_report.py` escapes them, masks secrets and defangs malicious URLs. Never pre-escape.

## Hunter output

```json
{
  "candidates": [
    {
      "title": "<short title>",
      "area": "<area, e.g. the module or layer>",
      "category": "<OWASP or CWE category>",
      "component": "<file, URL or service>",
      "location": {"file": "<path>", "line": 0},
      "cvss_vector": "CVSS:4.0/AV:_/AC:_/AT:_/PR:_/UI:_/VC:_/VI:_/VA:_/SC:_/SI:_/SA:_",
      "cvss_justification": {"AV": "<why>", "AC": "<why>", "AT": "<why>", "PR": "<why>", "UI": "<why>",
                             "VC": "<why>", "VI": "<why>", "VA": "<why>", "SC": "<why>", "SI": "<why>", "SA": "<why>"},
      "description": "<two to four sentences>",
      "evidence": [{"label": "<file:line>", "language": "<php, js, nginx, text…>", "code": "<exact extract from the target>"}],
      "impact": "<concrete consequence>",
      "recommendations": ["<action>"],
      "references": ["<OWASP, CWE or CVE id>"],
      "confidence": "high|medium|low"
    }
  ],
  "coverage": {"checked": ["<what was reviewed>"], "not_checked": ["<what was not, and why>"]},
  "suspicious_instructions": [{"where": "<file:line>", "text": "<instruction found in the target>"}]
}
```
`cvss_vector` is omitted for an informational observation. No score field: scores are computed.

## Verifier output

```json
{"verdicts": [{"title": "…", "verdict": "confirmed|needs_validation|rejected", "reasoning": "…", "cvss_vector": "corrected vector or the same"}]}
```

## `findings.json` (audit report)

Top level: `ref`, `language` (`en`/`fr`, from `audit-config.json`), `target_name`, `context` (one sentence), `period`
(`{"start", "end"}` as `yyyy-mm-dd`), `report_version`, `report_date`, `summary`, `priorities` (3 ×
`{"severity", "action"}`), `scope` (`{"targets": [{"target","type","environment","version"}], "in_scope": [],
"out_of_scope": []}`), `local_environment` (bool), `tools` (names that actually ran), `findings` (in report
order: most severe first), `action_plan` (`{"immediate": [], "short_term": [], "medium_term": []}` of
`{"ref": "V-01" or null, "action"}`), `history` (optional `[{"version","date","purpose"}]`).

Each finding: the candidate fields above, plus `status` (`Open` · `To confirm` · `Fixed`), optional
`business_adjustment` (`{"severity", "justification"}`), optional `table` (`{"headers", "rows"}`, e.g.
outdated modules), optional `recommendation_code` (`{"language", "code"}`). IDs (`V-01`…) are assigned in
order by the renderer: refer to them in `action_plan` with that order in mind.

## `incident.json` (incident report)

Top level: the header fields above, plus `status` (`confirmed` · `suspected` · `not-confirmed`),
`severity`, `dates` (`{"start", "detection", "containment"}`, ISO `yyyy-mm-ddThh:mm`, with offset if known),
`summary`, `capabilities` [], `not_observed` [], `immediate_actions` (3 × `{"severity", "action"}`),
`symptoms` [], `affected_system` [], `evidence_sources` ([`{"source","location","period","sha256"}`] from
`SHA-256SUMS`), `limitations`, `timeline` ([`{"date","phase","event","details","source"}`], phase one of
`recon`, `intrusion`, `persistence`, `action`, `detection`, `response`), `timezone`, `timezone_note`,
`entry_point` (`{"vector","component","confidence": established|likely|hypothesis,"finding": "I-01",
"description","log_extract","ruled_out": []}`), `iocs` ([`{"kind": ip|file|cron|account|domain|url|hash|other,
"type": label, "value","role","first_seen","action"}`]), `findings` (as above, with `role` instead of
`area`), `remediation` (`{"containment": [], "eradication": [], "hardening": []}` of `{"ref","action"}`),
`personal_data` (`{"exposed","people","awareness": ISO time of awareness,"controller",
"categories": [{"category","exposure","rationale"}]}`).

## Report-writer output

```json
{"context": "…", "summary": "…", "priorities": [{"severity": "critical", "action": "…"}],
 "impacts": {"<finding title>": "plain-language business impact"}, "action_plan": {"immediate": [], "short_term": [], "medium_term": []}}
```
For an incident: `summary`, `immediate_actions`, `remediation` instead of `priorities` and `action_plan`.
