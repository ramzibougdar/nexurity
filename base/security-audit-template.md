<!--
TEMPLATE · SECURITY AUDIT REPORT · NEXURITY · v3.0 (Markdown)
--------------------------------------------------------------
Single Markdown file (GitHub-flavoured: tables, fenced code blocks). No images,
no external files, no raw HTML in the rendered content: these comments are the
only HTML, and they are invisible once rendered.
Rating: CVSS 4.0 (base score + vector).

BRANDING (generic template): what the issuer can customise is marked BRAND:
the issuer name under the title and the contact line at the end. Defaults = Nexurity.

FILLING RULES
1. Replace the fields in square brackets [ … ].
2. Duplicate one "### V-xx" block per vulnerability, keeping its order.
   Each finding carries a metadata line:
   severity (critical | high | medium | low | info), status (Open | Fixed | To confirm),
   cvss (base score or —), category, area (free text, e.g. Modules, Server, Back office).
3. Values marked [computed] are never typed by hand: render_report.py computes them
   from the findings, so they always match.
   - Counts: number of findings per severity.
   - Security score: 100 − sum of the weights of the OPEN findings, floor 0.
     Weights: critical 25 · high 12 · medium 5 · low 2 · info 0.
     "Fixed" and "To confirm" findings are not counted.
   - Level: ≥ 85 Good · ≥ 65 Fair, needs strengthening · ≥ 40 Insufficient · < 40 Critical.
   - Breakdown by area: one row per area, most at-risk first (sum of weights, then count).
   - Summary table (section 05): one row per finding, in report order.
4. Any text taken from the audited code, logs or configuration MUST be escaped:
   - in prose and table cells: Markdown characters (\ ` * _ [ ] < > | #) are escaped
     and line breaks removed, so the text can never become a link, an image, a
     heading, a table column or raw HTML;
   - in code blocks: the fence is longer than any run of backticks in the content,
     so the content can never close the block.
5. Export: the file can be converted to PDF or Word with Pandoc, if installed.
-->

# Security audit report · [Website or application name]

<!-- BRAND · issuer name -->
**Nexurity** · Confidential · restricted distribution

[One sentence of context, e.g. Application and configuration audit of [Client]'s PrestaShop 8.1 store, carried out before go-live.]

| | |
|---|---|
| **Client** | [Company name] |
| **Reference** | AUD-2026-[000] |
| **Audit period** | [dd/mm] → [dd/mm/yyyy] |
| **Report version** | v1.0 · [dd month yyyy] |
| **Auditor** | [First Last] |

## Contents

1. [Executive summary](#01--executive-summary)
2. [Scope and method](#02--scope-and-method)
3. [Severity scale](#03--severity-scale)
4. [Detailed findings](#04--detailed-findings)
5. [Summary table](#05--summary-table)
6. [Action plan](#06--action-plan)
7. [Appendices](#07--appendices)

---

## 01 · Executive summary

### Key takeaways

**Security score: [computed] / 100** · [computed level]

Based on the number and severity of open findings. [computed] finding(s) to confirm not counted.

[Summary paragraph for management: overall level, main risk, exposure. E.g.: We identified one critical vulnerability that allows the customer database to be read without authentication. It must be fixed before any go-live. The rest of the platform is sound: updates are recent and the administration area is properly protected.]

| Critical | High | Medium | Low | Informational |
|:---:|:---:|:---:|:---:|:---:|
| [computed] | [computed] | [computed] | [computed] | [computed] |

### Breakdown by area

| Area | Findings | Critical | High | Medium | Low | Info |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| [computed] | [computed] | [computed] | [computed] | [computed] | [computed] | [computed] |

### Top three priorities

1. **Critical** · [Priority action no. 1, starting with a verb: Fix the SQL injection in the search module.]
2. **High** · [Priority action no. 2: Update the three outdated third-party modules.]
3. **Medium** · [Priority action no. 3: Add the HTTP security headers.]

---

## 02 · Scope and method

### What we tested, and how

| Target | Type | Environment | Version |
|---|---|---|---|
| [https://www.example.com] | Public website | Production | [PrestaShop 8.1.7] |
| [https://www.example.com/admin-xxx] | Back office | Production | — |
| [Git repository / code archive] | Source code | Static review | [commit a1b2c3d] |
| [Web server] | Configuration | Production | [PHP 8.2 · Nginx 1.24] |

**In scope**

- [Code review of modules and theme]
- [Passive review of the public website: HTTP headers, TLS, DNS]
- [Server configuration, TLS and HTTP headers]
- [Search for indicators of compromise]

**Out of scope**

- [Active penetration testing and exploitation]
- [Denial-of-service testing]
- [Social engineering]
- [Hosting provider infrastructure]

### Approach

1. **Reconnaissance**: mapping, versions, exposed surface.
2. **Automated analysis**: code, dependency and configuration scanners.
3. **Expert review**: targeted review of sensitive areas, without altering data.
4. **Validation**: every finding independently re-checked, CVSS 4.0 rating.
5. **Reporting**: report, action plan, walkthrough meeting.

Standards: OWASP Top 10 (2021), OWASP ASVS 4.0, CWE Top 25, CVSS 4.0, ANSSI guidelines.
Tools: [Semgrep, dependency audits (composer audit, npm audit, pip-audit), Lynis, testssl.sh, AI-assisted review with independent validation].

---

## 03 · Severity scale

### How to read the levels

CVSS 4.0 base scores (FIRST). The severity may be adjusted for business impact; any adjustment is justified in the finding.

| Severity | CVSS 4.0 | Meaning | Deadline |
|---|---|---|---|
| **Critical** | 9.0 – 10 | Simple remote exploitation, full compromise or massive data leak. | Fix immediately |
| **High** | 7.0 – 8.9 | Significant impact on data or service, realistic exploitation. | Within 7 days |
| **Medium** | 4.0 – 6.9 | Exploitation under specific conditions, or limited impact. | Within 30 days |
| **Low** | 0.1 – 3.9 | Hardening gap, marginal impact. | Next maintenance |
| **Info** | — | Good practice or observation with no direct risk. | To be scheduled |

---

## 04 · Detailed findings

### The vulnerabilities, one by one

<!-- ▼ FINDING · template to duplicate -->
### V-01 · [SQL injection in the search parameter of module X]

**Critical** · CVSS 4.0: **9.3** · Status: **Open**

| | |
|---|---|
| **Category** | A03 · Injection |
| **Area** | [Modules] |
| **Component** | `[modules/x/controllers/front/search.php]` |
| **CVSS 4.0 vector** | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` |

**Description**

[Explain the flaw in two to four clear sentences. E.g.: the value of the `q` parameter is concatenated directly into the SQL query, with no escaping or prepared statement.]

**Evidence**

```php
// [file:line]
$sql = 'SELECT * FROM '._DB_PREFIX_.'product_lang WHERE name LIKE "%'. Tools::getValue('q') .'%"';
// Source: parameter q, controlled by any visitor, no authentication
// Sink: concatenated directly into the SQL query above
```

**Impact**

[Concrete business consequence: the customer table can be read (emails, password hashes); if exploited, the breach must be reported to the data protection authority within 72 hours under the GDPR.]

**Recommendation**

- [Use `pSQL()` or `DbQuery` with bound parameters.]
- [Validate the input's type and length.]
- [Check the logs to confirm no exploitation has occurred.]

References: OWASP A03:2021 · CWE-89
<!-- ▲ end of template -->

### V-02 · [Outdated third-party modules with published vulnerabilities]

**High** · CVSS 4.0: **8.7** · Status: **Open**

| | |
|---|---|
| **Category** | A06 · Vulnerable components |
| **Area** | [Modules] |
| **Component** | [3 modules] |

**Description**

[Description.]

| Module | Installed version | Fixed version | CVE |
|---|---|---|---|
| [module_a] | [1.2.0] | [1.4.3] | [CVE-2026-0000] |
| [module_b] | [2.0.1] | [2.0.6] | [CVE-2026-0000] |

**Impact**

[Impact.]

**Recommendation**

[Recommendation.]

### V-03 · [Missing HTTP security headers]

**Medium** · CVSS 4.0: **5.3** · Status: **Open**

| | |
|---|---|
| **Category** | A05 · Security misconfiguration |
| **Area** | [Server] |
| **Component** | [Web server] |

**Description**

[The `Content-Security-Policy`, `Strict-Transport-Security` and `X-Frame-Options` headers are not sent.]

**Recommendation**

```nginx
# Nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
```

### V-04 · [PHP version exposed in the X-Powered-By header]

**Low** · CVSS 4.0: **[2.1]** · Status: **Open**

| | |
|---|---|
| **Category** | A05 · Security misconfiguration |
| **Area** | [Server] |
| **Component** | [PHP] |

**Description**

[Description.]

**Recommendation**

[Set `expose_php = Off` in `php.ini`.]

### V-05 · [No documented backup policy]

**Info** · CVSS 4.0: **—** · Status: **Open**

| | |
|---|---|
| **Category** | [Resilience] |
| **Area** | [Server] |

**Observation**

[Observation.]

**Suggestion**

[Suggestion.]

---

## 05 · Summary table

### All findings

<!-- [computed] one row per finding, in report order -->
| ID | Finding | Area | Category | CVSS | Severity | Status |
|---|---|---|---|:---:|---|---|
| [computed] | [computed] | [computed] | [computed] | [computed] | [computed] | [computed] |

---

## 06 · Action plan

### What to fix first

**Immediate · 48 h · Stop the exposure**

- **V-01** · [Fix the SQL injection]
- — · [Change administrator passwords]

**Short term · 30 days · Upgrade**

- **V-02** · [Update the modules]
- **V-03** · [Add the HTTP headers]

**Medium term · 3 months · Harden and monitor**

- **V-04** · [Hide version numbers]
- **V-05** · [Formalise backups]
- — · [Schedule a follow-up audit]

---

## 07 · Appendices

### Glossary

- **CVSS**: standard 0–10 score that measures the technical severity of a vulnerability. This report uses version 4.0, published by FIRST.
- **CVE**: public identifier of a known vulnerability.
- **OWASP**: foundation that publishes the reference web security standards.

### Document history

| Version | Date | Purpose |
|---|---|---|
| 1.0 | [dd/mm/yyyy] | Initial report |
| 1.1 | [dd/mm/yyyy] | [Follow-up audit after fixes] |

This report reflects the state of the scope on the audit dates. It is strictly confidential and intended solely for the client named at the top. Testing was carried out with the client's written authorisation, without altering production data.

---

<!-- BRAND · issuer name and contact details -->
Nexurity · [Address] · [Contact email] · [Phone] · [Website]
Ref. AUD-2026-[000] · Confidential
