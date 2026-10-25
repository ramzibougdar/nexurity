# Deterministic tools

Run by the main thread, never by a hunter. Their results are **leads**, not verdicts: a hunter checks
each lead before turning it into a candidate. Write every output into the engagement folder
(`<folder>/tools/`); the safeguard refuses any other destination.

**Where the tools are**: `python3 "<plugin>/scripts/tools.py" where --data "<data>"` gives each tool's path
(from the PATH, Homebrew, or Nexurity's data folder). Call a tool by that path, for example
`<path of semgrep> scan …`; lynis runs from its own folder (`cd <its folder> && ./lynis audit system …`).
**Installing them**: `/nexurity:setup` installs the missing ones, and the first audit runs it once
automatically (`PIPELINE.md`, step 0). Nothing is ever installed during an engagement, and nothing else
than these tools is installed. A tool still missing is skipped and written in `log.md` ("not run: not
installed").

| Area | Command (examples, adapt paths) |
|---|---|
| CMS | `python3 "<plugin>/scripts/cms.py" scan <cms root> --data "<data>" --out <folder>/tools/cms` (see below) |
| Code analysis | CodeQL on every full audit, for the languages it analyses without a build (see below) |
| Code patterns | `semgrep scan --config auto --json -o <folder>/tools/semgrep.json <target>` |
| PHP dependencies | `composer audit --format=json --working-dir=<target> > <folder>/tools/composer-audit.json` |
| Node dependencies | `npm audit --json --prefix <target> > <folder>/tools/npm-audit.json` |
| Python dependencies | `pip-audit -r <target>/requirements.txt -f json -o <folder>/tools/pip-audit.json` |
| Rust dependencies | `cargo audit --json --file <target>/Cargo.lock > <folder>/tools/cargo-audit.json` |
| Secrets | `gitleaks detect --no-git --source <target> --report-format json --report-path <folder>/tools/gitleaks.json` (or `trufflehog filesystem <target> --json`) |
| Server | `lynis audit system --quick --logfile <folder>/tools/lynis.log --report-file <folder>/tools/lynis-report.dat` (local), or the read-only commands of `hunter-server` over SSH |
| TLS | `testssl.sh --quiet --jsonfile <folder>/tools/testssl.json <host>` |
| Headers | `curl -sI <url>` |
| DNS | `dig +short TXT <domain>`, `dig +short MX <domain>`, `dig +short TXT _dmarc.<domain>` |

**CMS check** (`cms.py`, Python standard library only): it needs the network to reach the official
sources (WordPress.org, the official release archives on GitHub and drupal.org, NVD, OSV.dev,
updates.drupal.org, WPScan when `WPSCAN_API_TOKEN` is set). Only the CMS name, the versions and the
extension names are sent, never code, paths or URLs of the target. It stops after `--budget` seconds (300
by default) and lists what it could not check; `NVD_API_KEY` speeds up the NVD lookups. Release archives
are cached in `<data>/cms-baselines/` (five at most). Without network, `--offline` still compares files
with a cached archive.

**CodeQL** runs on every full code audit (`/nexurity:audit`, not the quick audit), without asking, for each
language of the target that CodeQL can analyse **without building it**: `javascript-typescript`,
`python`, `ruby`, `actions` (GitHub Actions workflows), and `java-kotlin` or `csharp` with
`--build-mode=none`. Languages that need a build (C, C++, Go, Swift, Rust) are skipped and written in
`log.md`; PHP is analysed with codeql-php (below). For each language `<lang>` (query pack
`<pack>`: `javascript`, `python`, `ruby`, `actions`, `java` or `csharp`):
1. Write `<folder>/tools/codeql-config.yml` once, with the Write tool:
   `paths-ignore:` `.nexurity`, `node_modules`, `vendor` and any generated or third-party folder the recon found.
2. `<codeql> database create <folder>/tools/codeql-db-<lang> --language=<lang> --source-root <target>
   --codescanning-config <folder>/tools/codeql-config.yml --overwrite` (add `--build-mode=none` for
   `java-kotlin` and `csharp`).
3. `<codeql> database analyze <folder>/tools/codeql-db-<lang>
   codeql/<pack>-queries:codeql-suites/<pack>-security-extended.qls --format=sarif-latest
   --output <folder>/tools/codeql-<lang>.sarif`.
**PHP with codeql-php**: CodeQL has no PHP support of its own; `/nexurity:setup` installs codeql-php
(Vozec/codeql-php, MIT, pinned commit, built with `cargo`) and `tools.py where` gives its folder
`<codeql-php>`. When the target has PHP and `<codeql-php>` is not null:
`<codeql> database create <folder>/tools/codeql-db-php --language=php --source-root <target>
--search-path <codeql-php>/php --overwrite`, then `<codeql> database analyze <folder>/tools/codeql-db-php
<codeql-php>/php/ql/src/codeql-suites/php-security.qls --format=sarif-latest
--output <folder>/tools/codeql-php.sarif --search-path <codeql-php>/php --additional-packs <codeql-php>`.
The first analysis compiles its queries (about 5 to 10 minutes). codeql-php is a research project that
over-approximates on purpose: its results are leads, and the verifier drops what the code does not
confirm.
Give each command up to 30 minutes. The safeguard only allows these subcommands, never a build command
(`--command`), another build mode or a pack download. Licence: CodeQL is free for open-source code; for
closed-source code it needs a GitHub Advanced Security licence, which is the user's responsibility.

Gitleaks and trufflehog output contains secrets: mask them before showing anything
(`python3 "<plugin>/scripts/mask_secrets.py" <file>`).
