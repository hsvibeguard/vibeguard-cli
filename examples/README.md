# Examples

Copy-paste GitHub Actions workflows for common project types. Drop one into
`.github/workflows/security.yml` in your repo.

| File | For |
|------|-----|
| [`python.yml`](./python.yml) | Python projects (Semgrep + Bandit + Checkov + pip deps via Trivy) |
| [`nextjs.yml`](./nextjs.yml) | Next.js / JavaScript / TypeScript projects |

Both upload findings to your repo's **Security tab** (GitHub Code Scanning). They
need `permissions: security-events: write`.

Tuning:
- `scanners:` — `core` (fast: Semgrep + Bandit + Gitleaks), `broad` (default), or `full`.
- `threshold:` — fail the build if the security score drops below this (0 = never fail).
  Start at `0` to establish a baseline, then raise it once you've triaged.
