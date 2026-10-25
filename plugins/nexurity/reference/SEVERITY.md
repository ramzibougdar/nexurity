# Severity: CVSS 4.0 only, computed by a script

- Agents never write a score. A hunter gives the full CVSS 4.0 **base vector**
  (`CVSS:4.0/AV:…/AC:…/AT:…/PR:…/UI:…/VC:…/VI:…/VA:…/SC:…/SI:…/SA:…`, in this order) and a one-line
  justification per metric. The verifier checks each metric against the evidence and corrects the vector.
- `python3 "<plugin>/scripts/cvss4.py" --json "<vector>"` validates the vector and returns the base score and
  severity (official FIRST algorithm). An invalid vector goes back to the verifier; it never reaches the
  report with a guessed score.
- Thresholds: critical ≥ 9.0 · high ≥ 7.0 · medium ≥ 4.0 · low ≥ 0.1 · info (no vector, or score 0).
- Business-impact adjustment: a separate field, `business_adjustment: {severity, justification}`. The CVSS
  score itself is never changed; the report shows both.
- A source that gives CVSS 3.1: rewrite the vector in 4.0 and let the script compute the score.

## Metric reminders (base metrics)

| Metric | Values |
|---|---|
| AV attack vector | N network · A adjacent · L local · P physical |
| AC attack complexity | L low · H high |
| AT attack requirements | N none · P present |
| PR privileges required | N none · L low · H high |
| UI user interaction | N none · P passive · A active |
| VC / VI / VA vulnerable system confidentiality / integrity / availability | H high · L low · N none |
| SC / SI / SA subsequent systems confidentiality / integrity / availability | H high · L low · N none |
