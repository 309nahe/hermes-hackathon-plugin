# AGENTS.md

Conventions for agents working in this repository. The maintainer reviews
every change manually.

## GitHub: always use `gh`

Use the GitHub CLI (`gh`) for all GitHub interaction — issues, branches, pull
requests, checks, reviews and releases. Do not drive GitHub through the web UI.

## Never push to `main`

`main` is review-only. Every change goes through a branch and a pull request
(PR/MR).

For every issue fix:

1. Read the issue first: `gh issue view <n> -R 309nahe/rookguard`.
2. Create a branch off `main` named `<type>/<issue-number>-<short-slug>`, e.g.
   `fix/3-verify-upgrade` or `feat/6-osv-dpkg-fallback`.
3. Implement the smallest change that satisfies the issue, with tests.
4. Run the quality gate below.
5. Push the branch and open a PR with `gh pr create`, body describing the
   change, the test plan, and `Closes #<n>`.
6. Do not merge. The maintainer reviews and merges manually.

Keep a PR scoped to exactly one issue. If the work needs multiple independent
changes, split it into multiple issues first.

## Issues are atomic

- One issue = one independently testable change.
- An issue must state: the problem, the expected behavior, explicit acceptance
  criteria, and the files/surface it touches.
- Do not bundle unrelated fixes, refactors or formatting into an issue or PR.
- If an issue turns out to contain several independent steps, split it before
  starting.

## Workspace handoff: keep UPDATE.md current

`UPDATE.md` is the handoff for continuing this work from another workspace
(VPS, new checkout, agentic coding). Read it first on a fresh machine.

- After every merged PR / closed issue, update `UPDATE.md`: what changed
  (issue by issue), current `main` HEAD, test count, open backlog, resume
  commands.
- Exception to "never push to `main`": `UPDATE.md`-only handoff updates may
  be committed and pushed directly to `main` when the maintainer explicitly
  asks for it (no PR needed). All code changes still go through branch + PR.

## Quality gate

Run from a neutral working directory (not the repo root, where the local
`tools.py` can shadow Hermes's `tools` package):

```bash
cd /tmp && pytest -q /path/to/rookguard/tests/
hermes plugins validate /path/to/rookguard --install-deps
```

CI must pass. Never re-add `|| true` or `continue-on-error: true` to a test
step to make it green.
