# VibeGuard CLI

[![PyPI version](https://img.shields.io/pypi/v/vibeguard-cli.svg)](https://pypi.org/project/vibeguard-cli/)
[![Python](https://img.shields.io/pypi/pyversions/vibeguard-cli.svg)](https://pypi.org/project/vibeguard-cli/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/hsvibeguard/vibeguard-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/hsvibeguard/vibeguard-cli/actions/workflows/ci.yml)
[![GitHub stars](https://img.shields.io/github/stars/hsvibeguard/vibeguard-cli?style=social)](https://github.com/hsvibeguard/vibeguard-cli)

**Unified security scanner orchestrator for local repositories.**

Run **Semgrep, Bandit, Checkov, Gitleaks, Trivy & TruffleHog** with one command — plus ecosystem scanners auto-detected per repo — for one normalized score, deduplicated findings, SARIF for GitHub Code Scanning, and AI-powered fix suggestions.

## Features

- **One Command**: Run multiple security scanners with `vibeguard scan .`
- **Normalized Output**: Unified findings schema across all scanners
- **Score & Grade**: Get a security score (0-100) and letter grade
- **Multiple Output Formats**: Terminal, JSON, SARIF, HTML reports
- **Badge Generator**: Embed security badges in your README
- **CI-Friendly**: Exit codes for automation and threshold checks

## Installation

### From PyPI (Recommended)

```bash
pip install vibeguard-cli
```

### From Source

```bash
git clone https://github.com/hsvibeguard/vibeguard-cli.git
cd vibeguard-cli
pip install -e ".[dev]"
```

### Verify Installation

```bash
vibeguard --version
vibeguard doctor
```

## Quick Start

```bash
# Check your environment
vibeguard doctor

# Initialize in your project
vibeguard init

# Run a security scan
vibeguard scan .

# Generate SARIF for GitHub Code Scanning
vibeguard scan . --output sarif > results.sarif

# Generate HTML report
vibeguard scan . --output html > report.html

# Generate a badge
vibeguard scan . --badge badge.svg
```

## Use in CI/CD

### GitHub Action (recommended)

One step installs VibeGuard + a pinned scanner set and uploads findings to your repo's Security tab:

```yaml
# .github/workflows/security.yml
name: Security
on: [push, pull_request]
permissions:
  contents: read
  security-events: write   # required for SARIF upload
jobs:
  vibeguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: hsvibeguard/vibeguard-cli@v1
        with:
          scanners: broad      # core | broad | full
          threshold: 70        # fail the build below this score (0 = never fail)
```

### pre-commit hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/hsvibeguard/vibeguard-cli
    rev: v1.1.9
    hooks:
      - id: vibeguard
        additional_dependencies: ["semgrep", "bandit", "checkov"]
```

### Docker

The image ships with the scanners baked in — no install step:

```bash
docker run --rm -v "$(pwd):/repo" ghcr.io/hsvibeguard/vibeguard-cli
```

> **Copy-paste workflows** for Python and Next.js projects are in [`examples/`](examples/).

## What VibeGuard is NOT

- **Not a new scanner.** It orchestrates existing, battle-tested tools (Semgrep, Trivy, Gitleaks, Bandit, Checkov, TruffleHog) — it doesn't reinvent detection.
- **Not a replacement for specialist tools.** Need deep SAST tuning? Run Semgrep directly. VibeGuard's value is unifying, deduping, and scoring — not out-detecting the specialists.
- **Not a security guarantee.** A passing score means "no findings from the configured scanners," not "secure." Security isn't a single number.
- **Not a cloud service for your code.** Scanning runs locally / in your CI — your source never leaves your machine.

## VibeGuard vs. running the scanners yourself

You can absolutely run Semgrep, Trivy, Gitleaks, etc. directly — VibeGuard just removes the glue work:

| | Run them separately | VibeGuard |
|---|---|---|
| Install & config | 6 tools, 6 configs | one command / one Action |
| Output | 6 formats | one normalized schema |
| Duplicate findings | manual | deduped across scanners |
| Prioritization | per-tool severities | one 0–100 score + grade |
| CI gating | wire each yourself | one `threshold:` |
| Security tab | upload each SARIF | one SARIF |

If you only use a single scanner, you may not need VibeGuard — the value shows up once you run several.

## Commands

| Command | Description | Tier |
|---------|-------------|------|
| `vibeguard doctor` | Check environment and scanner availability | Free |
| `vibeguard init` | Initialize VibeGuard in a directory | Free |
| `vibeguard scan [path]` | Run security scanners on a codebase | Free |
| `vibeguard report [path]` | Generate reports from cached scan | Free |
| `vibeguard fix [id]` | Generate copy-paste prompt for LLM | Free |
| `vibeguard baseline` | Manage baselines for regression detection | Free |
| `vibeguard patch [id]` | Generate unified diff via LLM (BYOK) | Pro |
| `vibeguard apply <patch>` | Apply patch with git safety checks | Pro |
| `vibeguard live <url>` | DAST scan on running application | Experimental |

## Output Formats

VibeGuard supports multiple output formats:

| Format | Flag | Description |
|--------|------|-------------|
| terminal | `--output terminal` | Rich terminal output (default) |
| json | `--output json` | JSON scan results |
| sarif | `--output sarif` | SARIF 2.1.0 for GitHub Code Scanning |
| html | `--output html` | Standalone HTML report |

### Generate Badge

```bash
vibeguard scan . --badge badge.svg
```

Embed in README:
```markdown
![Security Score](./badge.svg)
```

## Scanner Packs

### Core Pack (Default)
- Semgrep (SAST multi-language)
- Gitleaks (secrets detection)
- Trivy (dependencies/container/IaC)
- Bandit (Python SAST)
- TruffleHog v3 (secrets detection)

### Ecosystem Pack (Auto-Detected)
- npm-audit (JavaScript/Node.js)
- pip-audit (Python)
- cargo-audit (Rust)

### Differentiation Pack
- Checkov (Infrastructure as Code)
- Dockle (Container best practices)
- Nuclei (DAST templates)

## Scoring

- **Base**: 100 points
- **Deductions**: Critical (-20), High (-10), Medium (-5), Low (-2)
- **Category Cap**: Max 50 points per category
- **Grades**: A+ (≥95), A (≥85), B (≥70), C (≥50), D (≥30), F (<30)

## Exit Codes

For CI/CD integration:

| Code | Meaning |
|------|---------|
| 0 | Success, no findings |
| 1 | Success, findings detected |
| 2 | Scan error (partial scan) |
| 3 | No cached scan (report command) |
| 4 | Configuration error |
| 5 | Invalid path |
| 10 | Score below threshold |

### CI Integration

See [Use in CI/CD](#use-in-cicd) above for the GitHub Action, pre-commit hook, and Docker image. Note: in `--ci` mode VibeGuard runs only already-installed scanners (for deterministic builds), which is why the Action installs a pinned scanner set for you.

### Threshold Enforcement

```bash
# Exit with code 10 if score is below 80
vibeguard scan . --threshold 80
```

## Pro Features (BYOK)

VibeGuard Pro features use your own LLM API keys (Bring Your Own Key):

```bash
# Configure your API key (encrypted locally)
vibeguard keys set openai sk-...

# Generate a patch for a finding
vibeguard patch <finding-id>

# Apply the patch safely
vibeguard apply .vibeguard/patches/<finding-id>.patch
```

Supported providers: OpenAI, Anthropic, Google, Azure, Mistral, Groq

## Known limitations

- **CI mode runs only installed scanners.** `--ci` is deterministic and does *not* auto-install tools. The GitHub Action installs a pinned set for you, but a raw `vibeguard scan . --ci` runs only what's already present.
- **The score is a heuristic.** It's a triage/gating aid (deduct per severity), not a calibrated risk model — use it for trends and thresholds, not as an absolute verdict.
- **Coverage varies by language.** Semgrep is broad; some scanners are ecosystem-specific (gosec for Go, pip-audit for Python, cargo-audit for Rust).
- **First CI run is slower** (installs + binary downloads). Cache `~/.vibeguard/bin` to speed subsequent runs.
- **Triage is conservative.** Findings in test fixtures, vendored, or temp paths may be auto-suppressed — use `--no-default-ignore` to see everything.

## Contributing

Contributions are welcome! See **[CONTRIBUTING.md](CONTRIBUTING.md)** — adding a scanner is usually a small manifest + parser. For security issues, see **[SECURITY.md](SECURITY.md)**.

## License

MIT - see [LICENSE](LICENSE) for details.
