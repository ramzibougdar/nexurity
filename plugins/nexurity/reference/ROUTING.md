# Routing: which recon and hunters for which target

The recon agent detects the stack (never asked in the wizard) and writes `recon.json`. Routing reads it.

| Detected | Agents |
|---|---|
| PHP | `hunter-php` + `hunter-web` + `hunter-deps-secrets` |
| JS / Node / front end | `hunter-web` + `hunter-deps-secrets` |
| Python | `hunter-web` + `hunter-deps-secrets` (Python rules) |
| Solana / Anchor / Rust | `hunter-solana` + `hunter-deps-secrets` |
| `wrangler.toml` present | + `hunter-infra-cloudflare` |
| Server | `recon-server` + `hunter-server` (SSH, web server, PHP-FPM, database, firewall, updates, accounts, sudoers, crons, Docker, permissions, backups) |
| Live website | `recon-site` + `hunter-site-passive` (headers, TLS, cookies, DNS/SPF/DKIM/DMARC, well-known exposed files with one HEAD/GET request each, visible versions) |
| Local website | same as live website, adapted (see below) |
| Quick audit | one hunter only, the first one routing selects for the main stack, plus one verifier; no CodeQL |

A project with several stacks gets the union of the hunters. Code audits always run `recon-code` first.

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
