# Contributing to VibeGuard

Thanks for considering a contribution! VibeGuard is a **manifest-driven orchestrator**,
so most contributions are small and self-contained.

## Ways to help

- **Report a bug or false positive** — open an issue with the scanner, the finding,
  and a minimal repro.
- **Add a scanner** — scanners are defined by a TOML manifest + a parser (see below).
- **Improve a parser** — normalize a scanner's output more accurately.
- **Docs & examples** — workflow examples, ecosystem guides, fixes.

## Dev setup

```bash
git clone https://github.com/hsvibeguard/vibeguard-cli.git
cd vibeguard-cli
pip install -e ".[dev]"

pytest            # run the suite
ruff check .      # lint
```

## Adding a scanner

1. **Manifest** — `src/vibeguard/scanners/manifests/<name>.toml`: name, tier,
   categories, languages, install strategy (binary/pip/docker), command template,
   output format (json/sarif/text), and the parser module reference.
2. **Parser** — `src/vibeguard/scanners/parsers/<name>.py` exposing
   `parse_output(...) -> list[Finding]`.
3. **Test** — add a test in `tests/` with a captured sample of the scanner's output.
4. `ruff check .` and `pytest` must pass.

## Pull requests

- Keep PRs focused and small.
- Add or adjust tests for any parser or scoring change.
- Run `ruff check .` and `pytest` before pushing.
- By contributing, you agree your work is licensed under the project's **MIT** license.
