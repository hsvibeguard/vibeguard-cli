# Security Policy

## Reporting a vulnerability

If you discover a security issue in VibeGuard, please report it **privately** —
do not open a public issue:

- Use GitHub's **"Report a vulnerability"** button (this repo → **Security** → **Advisories**), or
- Email **security@vibeguard.co**.

We aim to acknowledge reports within **3 business days** and to ship a fix or
mitigation as fast as we reasonably can. We'll credit you in the release notes
unless you'd prefer to stay anonymous.

## Scope

VibeGuard *orchestrates* third-party scanners (Semgrep, Trivy, Gitleaks, Bandit,
Checkov, TruffleHog, and others). Vulnerabilities in those upstream tools should be
reported to their respective projects. Report to us anything in **VibeGuard's own
code**: the orchestrator, parsers, scoring, patch generation, local key storage, or
the GitHub Action.

## Supported versions

VibeGuard uses a rolling release model. The latest version on PyPI and the `@v1`
Action tag receive security fixes — please keep up to date.

| Version | Supported |
|---|---|
| latest (`@v1` / current PyPI) | ✅ |
| older | ❌ — please upgrade |

## How your code and keys are handled

- **Scanning runs locally / in your CI.** Your source never leaves your machine.
- **Pro patch generation is BYOK.** It uses *your own* LLM API key, stored encrypted
  locally (Fernet). Keys are never transmitted to VibeGuard.
