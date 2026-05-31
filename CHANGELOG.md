# Changelog

All notable changes to VibeGuard CLI will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-02-02

First stable release of VibeGuard CLI - the unified security scanner orchestrator.

### Added

#### Core Scanning
- 5 core scanners: Semgrep (SAST), Gitleaks (secrets), Trivy (deps/container/IaC), Bandit (Python), TruffleHog v3 (secrets)
- Unified findings schema with normalization across all scanners
- Intelligent deduplication with fingerprint-based matching
- Security scoring (0-100) with letter grades (A+ to F)
- Category-based scoring caps to prevent single-category dominance

#### Ecosystem Scanners (Auto-Detected)
- npm-audit for JavaScript/Node.js projects
- pip-audit for Python projects
- cargo-audit for Rust projects
- Checkov for Infrastructure as Code (Terraform, K8s, Docker)
- Dockle for container image best practices

#### CLI Commands
- `vibeguard doctor` - Environment and scanner availability check
- `vibeguard init` - Project initialization with config files
- `vibeguard scan` - Multi-scanner security scanning with pack selection
- `vibeguard report` - Generate reports from cached scans
- `vibeguard fix` - Generate copy-paste prompts for manual LLM use (FREE)
- `vibeguard patch` - LLM-powered unified diff generation (PRO, BYOK)
- `vibeguard apply` - Safe patch application with git safety checks
- `vibeguard keys` - Encrypted API key management
- `vibeguard config` - Configuration management
- `vibeguard baseline` - Baseline management for regression detection
- `vibeguard import sarif` - Import external SARIF results
- `vibeguard live` - Experimental DAST scanning with Nuclei

#### Output Formats
- Terminal output with Rich formatting
- JSON export for programmatic access
- SARIF 2.1.0 for GitHub Code Scanning integration
- Standalone HTML reports with dark theme
- Badge SVG generation (shields.io style)

#### CI/CD Integration
- CI environment auto-detection (GitHub Actions, GitLab CI, Jenkins, CircleCI, Travis)
- GitHub Actions annotations (errors/warnings in PR diffs)
- Deterministic `--ci` mode for reproducible builds
- Exit codes for automation (0=success, 1=findings, 2=error, 10=threshold)
- Reusable GitHub Action wrapper (`action.yml`)

#### BYOK LLM Integration
- Encrypted local key storage with Fernet
- Support for OpenAI, Anthropic, Google, Azure, Mistral, Groq
- Unified interface via litellm
- Patch safety rules with validation

#### Baseline & Regression
- Save scans as baselines for comparison
- Detect new findings (regressions) and fixed findings (improvements)
- Smart fingerprint matching with line bucketing

#### Triage System
- Automatic classification of findings (actionable, needs review, suppressed)
- Path-based classification (source, tests, generated, vendor)
- Example/placeholder secret detection
- Default ignore patterns for common noise

### Security

- Command injection prevention in `live` command with input validation
- Path traversal protection in binary downloader (Zip Slip fix)
- Shell injection fix in `doctor` command
- Arbitrary code loading prevention with parser module whitelist
- DNS verification for `.localhost` subdomain claims
- GitHub Actions injection fix (moved inputs to environment variables)

### Developer Experience

- Interactive CLI with arrow-key navigation menu
- Persistent menu loop for multi-command sessions
- Helpful error messages with concrete examples
- Auto-bootstrap missing scanners before scanning
- Progress bars with elapsed time tracking
- Custom VibeGuard spinner with brand colors

---

## [0.1.0] - 2026-01-30

Initial development release (internal).

### Added
- Project scaffold with Typer CLI
- Pydantic v2 models (Finding, ScanResult)
- Semgrep scanner integration
- Basic terminal output

[1.0.0]: https://github.com/vibeguard/vibeguard-cli/releases/tag/v1.0.0
[0.1.0]: https://github.com/vibeguard/vibeguard-cli/releases/tag/v0.1.0
