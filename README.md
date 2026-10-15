# GhostAction Guard — free GitHub Action

Scans your GitHub Actions workflows for **malicious CI injection** in the
style of the [GhostAction supply-chain campaign](http://thehackernews.com/2026/10/ghostaction-compromises-about-1900.html)
(Oct 2026): ~1,900 accounts compromised, 30,000+ repos targeted. Attackers
push workflow files with deceptive security-sounding names
(`security-audit.yml`, `github_actions_security.yml`) that exfiltrate CI
secrets, cloud keys and API tokens to attacker-controlled endpoints.

Built by [Ingenious AI](https://ingeniousai-security-checks.netlify.app/threat-map.html).
Detection engine ported from Vibe-Code Audit's tested GA-001…GA-008 rule pack.

## What it detects

| Rule | Severity | What |
|------|----------|------|
| GA-001 | HIGH | Deceptive workflow filename (edit-distance match to campaign names) **plus** suspicious behavior — name alone never fires |
| GA-002 | CRITICAL | Secret material sent to an external host in the same run step |
| GA-003 | CRITICAL | `pull_request_target` combined with secret access |
| GA-004 | HIGH | Secret-adjacent step calling an obfuscated endpoint (IP literal, URL shortener, punycode, over-long/hyphen-stuffed labels) |
| GA-005 | HIGH | Environment/secret dump encoded (base64/xxd/hexdump) in a run step |
| GA-006 | HIGH | Split-step exfiltration: harvest in one step, transmit in another, under a deceptive name |
| GA-007 | MEDIUM | Git history mined for secret-shaped tokens (`ghp_`, `AKIA`, `xox-`, private keys) |
| GA-008 | HIGH | Secret staged to a file in one step, exfiltrated from another step (plain filename) |

Every finding reports the exact file and line, severity, detail, concrete
remediation, and an attacker's-eye walkthrough of how the implant works.

## Usage

```yaml
name: Supply-chain guard
on:
  pull_request:
    paths: ['.github/workflows/**']
  push:
    paths: ['.github/workflows/**']

jobs:
  ghostaction-guard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Iceman2050/ghostaction-guard-action@v1
        with:
          fail-on: high   # critical | high | medium | low | never
```

### Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `fail-on` | `high` | Fail the job when a finding at/above this severity exists |
| `working-directory` | `.` | Directory containing `.github/workflows` |
| `paths` | `.github/workflows` | Space-separated workflow files/dirs to scan |

### Outputs

| Output | Description |
|--------|-------------|
| `findings-json` | Full findings report as JSON |
| `finding-count` | Number of findings |

## Guarantees

- **Stdlib only** — no dependencies to install, no supply-chain of its own.
- **Zero network calls** — pure local static analysis; your workflows never leave the runner.
- **Deterministic** — same input, same findings, every time.
- **Never crashes** — malformed YAML is reported as unscannable, never an exception.
- **No false-name alarms** — a security-sounding filename alone is never a finding; it must be paired with secret handling, external egress, or `pull_request_target`.

An empty result means "no findings", never "secure".

## Honest limitations (documented, not hidden)

1. **`$GITHUB_OUTPUT` step-output indirection** — `${{ steps.a.outputs.t }}`
   carrying a secret is not taint-tracked; full taint tracking is out of
   scope for a deterministic scanner.
2. **Trojaned third-party *secret-scanning* actions** — mitigated indirectly
   by action pinning + typosquat checks, not detected directly.
3. **Exfil over `git push` to an attacker repo or raw `python requests`** —
   curl/wget/scp/sftp/ftp cover the campaign's observed payloads.

## Local use

```bash
python3 scan.py .github/workflows --fail-on high
python3 scan.py workflow.yml --format json --output report.json
```

## License

MIT © 2026 Ingenious AI. See [LICENSE](LICENSE).
