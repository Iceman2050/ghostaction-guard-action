# Push instructions — your one tap

The repo is fully built and tested locally. These steps create the GitHub
repo and publish the Action to the Marketplace.

## 1. Create the repo and push (one command)

```bash
cd ~/workspace/oss/ghostaction-guard-action
gh repo create ghostaction-guard-action --public \
  --description "Free GitHub Action: scan workflows for malicious CI injection (Oct 2026 GhostAction campaign)" \
  --source=. --push
```

No `gh` CLI? Alternative: create an empty public repo named
`ghostaction-guard-action` at github.com/new, then:

```bash
cd ~/workspace/oss/ghostaction-guard-action
git init -b main
git add .
git commit -m "GhostAction Guard v1.0.0 — free malicious CI-workflow injection scan"
git remote add origin https://github.com/YOUR-USERNAME/ghostaction-guard-action.git
git push -u origin main
```

## 2. Tag a release

```bash
git tag v1 && git push origin v1
```

## 3. Publish to GitHub Marketplace (2 minutes)

1. Open the repo on GitHub → the "Releases" section will show a
   **"Publish this Action to Marketplace"** prompt (GitHub detects
   `action.yml` automatically).
2. Click it, pick the `red` / `shield` branding (already in action.yml),
   choose a primary category: **"Continuous integration"**,
   and publish.

## 4. Traffic taps (in this order)

1. **r/homelab** — "Project Showcase: Software" flair post (copy is in
   `~/workspace/your_files/traffic-spike-packets-2026-10-15.md`, packet #1).
   AI disclosure in flair + body per their rules.
2. **Show HN** — "Show HN: Free GitHub Action that catches supply-chain
   workflow implants" (packet #5 in the same file).
3. **TLDR** — re-submit now that there's a real repo (their form was
   unverifiable before; the repo link makes the pitch concrete).
4. **awesome-selfhosted / awesome-ci PR** — check each list's CONTRIBUTING
   rules first; the tool is MIT and dependency-free, which is what those
   lists want.

## 5. Keep it alive

- Watch the repo's Issues for the first month — fast maintainer replies
  are what turn a trending repo into a durable one.
- When the next supply-chain campaign breaks, add its TTPs as GA-009+
  and tag v1.1 — each wave is a new launch moment.
