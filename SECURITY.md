# Security Policy

## Supported versions

The latest release on the default branch is the supported version. Older
snapshots are not patched; upgrade before reporting if a finding may already
be fixed.

## Reporting a vulnerability

Email **orders@getingeniousai.com** with:

- the tool version (`--version` output or commit SHA),
- a minimal reproduction (config, spec, or fixture — never live secrets),
- the result you observed and the result you expected.

Please do not open a public issue for a suspected vulnerability in the tool
itself. We aim to acknowledge reports within 3 business days.

## Scope note

This tool is a defensive checker. Its verdicts state only what its documented
checks establish — see "How to read a result" in the README. A clean result
is never a guarantee that a system is safe.
