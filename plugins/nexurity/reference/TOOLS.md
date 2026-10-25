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

**CodeQL** is optional: use it only if it is installed **and** the user confirms that the code is open
source or covered by a CodeQL licence (the CLI requires a commercial licence for closed-source code).

Gitleaks and trufflehog output contains secrets: mask them before showing anything
(`python3 "<plugin>/scripts/mask_secrets.py" <file>`).
