# Halvard: rules for every session (owner's standing instructions)

1. **Start of every request: read `.ai/HANDOFF.md` first** and work from it. Do not re-explore the repository or re-derive what it already records. Open `docs/29-product-handoff.md` only when you need the full product picture.
2. **End of every key request or process: update `.ai/HANDOFF.md` before you finish** (state, what changed, what is open, next step), and bump the version (`src/halvard/__init__.py`, `native/halvard-svc/Cargo.toml`, top entry of `CHANGELOG.md`; a test keeps them in step) when the product changed.
3. **Every commit and tag is pushed to GitHub immediately** (`git push origin main --tags`; a `.git/hooks/post-commit` hook pushes commits). Scan the diff for secrets and large files first.
4. Never run `tools/run_acceptance*.py` on Windows. Do not commit failing tests without saying so. Halvard is a reference model, not a shippable endpoint: never describe it as ready to ship.
5. Keep advising on deployment, licensing, commercials and competitors (`docs/24-strategy-and-market.md`).
