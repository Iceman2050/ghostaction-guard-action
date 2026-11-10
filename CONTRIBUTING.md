# Contributing

Thanks for helping improve an Ingenious AI open-source tool.

## Ground rules

- Keep the tool dependency-light: Python standard library only, unless a
  change is discussed first.
- Every detection change needs a test fixture proving it fires — and one
  proving it does not fire on a benign input.
- Never weaken the honesty standard: verdicts must say exactly what the
  check establishes. "Not detected" never means "safe".
- Do not include real credentials, tokens, or third-party data in fixtures.

## Workflow

1. Fork and branch from the default branch.
2. Run the test suite (`python -m pytest`) before opening a pull request.
3. Describe what your change detects or fixes, with sample output.

## Reporting bugs

Open an issue with the tool version, your OS/Python version, the exact
command, and the output you saw vs. expected.
