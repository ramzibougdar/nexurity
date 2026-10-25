# Routing: which recon and hunters for which target

The recon agent detects the stack (never asked in the wizard) and writes `recon.json`. Routing reads it.

| Detected | Agents |
|---|---|
| **Every code audit** | `hunter-web` (any language: generic hunting from every shipped skill), `hunter-deps-secrets`, `hunter-hygiene`; Semgrep and CodeQL run before them (`TOOLS.md`) |
| CMS (WordPress, PrestaShop, Drupal, Joomla, Magento) | + `hunter-cms`, after `cms.py scan` (see below) |
| PHP | + `hunter-php` |
| JS / Node / front end, Python, Ruby, Java, C#, Go | the language rules of `hunter-web` |
| Solana / Anchor / Rust | + `hunter-solana` |
| C, C++, unsafe Rust, native extensions, desktop or mobile apps | the memory-safety and desktop/mobile guides of `hunter-web` (`KNOWLEDGE.md`) |
| `wrangler.toml`, `wrangler.json` or `wrangler.jsonc` present, or Cloudflare WAF/Access rules as code | + `hunter-infra-cloudflare` |
| Server | `recon-server` + `hunter-server` (SSH, web server, PHP-FPM, database, firewall, updates, accounts, sudoers, crons, Docker, permissions, backups) |
| Live website | `recon-site` + `hunter-site-passive` (headers, TLS, cookies, DNS/SPF/DKIM/DMARC, well-known exposed files with one HEAD/GET request each, visible versions) |
| Local website | same as live website, adapted (see below) |
| Quick audit | one hunter only, the first one routing selects for the main stack (`hunter-cms` for a CMS), plus one verifier; no CodeQL |

A project with several stacks gets the union of the hunters. Code audits always run `recon-code` first.
Every audit ends with the knowledge ledger (`KNOWLEDGE.md`): the eleven shipped sources, each used, not
applicable or not run, listed in the report.

## CMS

`python3 "<plugin>/scripts/cms.py" detect <target>` confirms the CMS, its version and root, and lists its
extensions (plugins, modules, themes). When it finds one:
- **Code**: `cms.py scan <cms root> --data "<data>" --out <folder>/tools/cms` compares every file with the
  official release of the same version (diffs of modified files in `tools/cms/diffs/`), lists the known
  CVEs of the core and of each extension, and the updates to install; then `hunter-cms` reviews it,
  alongside the usual PHP hunters.
- **Server**: copy the site root read-only into the engagement folder with `preserve_evidence.py --ssh`,
  then scan the copy.
- **Live website**: when `recon-site` reads the CMS name and version from public signals,
  `cms.py scan --cms <name> --version <version> --data "<data>" --out <folder>/tools/cms` lists its CVEs
  and updates (no file comparison); `hunter-site-passive` reports them as "version publicly exposed with
  known vulnerabilities", to confirm on the code.

## Local websites

A URL is local when its host is `localhost`, `127.0.0.1` or `::1`, ends with `.test`, `.local`,
`.localhost` or `.internal`, or resolves to a loopback or private address (`127.0.0.0/8`, `::1`,
`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`). `recon-site` records `"local": true` in `recon.json`.

For a local site:
- checked as usual: HTTP security headers, cookies, exposed files, visible versions;
- skipped: DNS, SPF, DKIM, DMARC (no public records);
- TLS: plain HTTP or a certificate from a local authority (Laravel Valet, Herd, mkcert) is not a finding;
  only protocol versions and ciphers are checked when HTTPS is served;
- still passive only;
- the report sets `local_environment: true` (it adds a note that production may differ).
- When the site's project folder is on the machine, offer to audit the code too ("Several").
