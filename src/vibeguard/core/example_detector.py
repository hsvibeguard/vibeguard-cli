"""Example/placeholder secret detection.

Detects secrets that are clearly examples, placeholders, or test values
to prevent false positives in security scans.
"""

import re

from vibeguard.models.finding import Category, Finding

# Patterns that indicate example/placeholder secrets
# These are commonly used in documentation, tutorials, and test files
_EXAMPLE_PATTERNS: list[re.Pattern[str]] = [
    # AWS example credentials (from AWS documentation)
    re.compile(r"AKIAIOSFODNN7EXAMPLE", re.IGNORECASE),
    re.compile(r"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", re.IGNORECASE),
    re.compile(r"AKIAI44QH8DHBEXAMPLE", re.IGNORECASE),

    # Placeholder patterns
    re.compile(r"x{4,}", re.IGNORECASE),  # xxxx... placeholders
    re.compile(r"0{8,}"),  # Long sequences of zeros
    re.compile(r"1234567890", re.IGNORECASE),  # Common placeholder number

    # Common placeholder text
    re.compile(r"your[-_]?api[-_]?key", re.IGNORECASE),
    re.compile(r"your[-_]?secret", re.IGNORECASE),
    re.compile(r"example[-_]?secret", re.IGNORECASE),
    re.compile(r"test[-_]?secret", re.IGNORECASE),
    re.compile(r"fake[-_]?secret", re.IGNORECASE),
    re.compile(r"your[-_]?token", re.IGNORECASE),
    re.compile(r"your[-_]?password", re.IGNORECASE),
    re.compile(r"insert[-_]?your", re.IGNORECASE),
    re.compile(r"replace[-_]?with", re.IGNORECASE),
    re.compile(r"put[-_]?your", re.IGNORECASE),
    re.compile(r"add[-_]?your", re.IGNORECASE),

    # Example domains and emails
    re.compile(r"@example\.(com|org|net)", re.IGNORECASE),
    re.compile(r"example\.(com|org|net)", re.IGNORECASE),
    re.compile(r"test@", re.IGNORECASE),
    re.compile(r"user@localhost", re.IGNORECASE),
    re.compile(r"admin@localhost", re.IGNORECASE),

    # Template placeholders
    re.compile(r"<your[-_]", re.IGNORECASE),  # <your-api-key>
    re.compile(r"\[your[-_]", re.IGNORECASE),  # [your-api-key]
    re.compile(r"\{your[-_]", re.IGNORECASE),  # {your-api-key}
    re.compile(r"\$\{[A-Z_]+\}"),  # ${VAR_NAME} - shell/env placeholders
    re.compile(r"\{\{[^}]+\}\}"),  # {{var}} - Jinja/template placeholders
    re.compile(r"<%[^%]+%>"),  # ERB/ASP template tags

    # Common development/test prefixes
    re.compile(r"sk[-_]test[-_]", re.IGNORECASE),  # Stripe test keys
    re.compile(r"pk[-_]test[-_]", re.IGNORECASE),  # Stripe test keys
    re.compile(r"sk[-_]live[-_]xxxx", re.IGNORECASE),  # Redacted Stripe keys
    re.compile(r"rk[-_]test[-_]", re.IGNORECASE),  # Stripe restricted test keys
    re.compile(r"api[-_]?key[-_]?here", re.IGNORECASE),
    re.compile(r"secret[-_]?key[-_]?here", re.IGNORECASE),

    # Explicit placeholder markers
    re.compile(r"TODO", re.IGNORECASE),
    re.compile(r"FIXME", re.IGNORECASE),
    re.compile(r"CHANGEME", re.IGNORECASE),
    re.compile(r"PLACEHOLDER", re.IGNORECASE),
    re.compile(r"FAKE[-_]?", re.IGNORECASE),
    re.compile(r"DUMMY[-_]?", re.IGNORECASE),
    re.compile(r"SAMPLE[-_]?", re.IGNORECASE),
    re.compile(r"MOCK[-_]?", re.IGNORECASE),

    # Base64 encoded 'test', 'example', etc.
    re.compile(r"dGVzdA=="),  # 'test' base64
    re.compile(r"ZXhhbXBsZQ=="),  # 'example' base64

    # JWT test tokens (with 'test' or 'example' in payload)
    re.compile(r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*dGVzdA", re.IGNORECASE),

    # GitHub example tokens
    re.compile(r"ghp_xxxx", re.IGNORECASE),
    re.compile(r"github_pat_xxxx", re.IGNORECASE),
]


# Bandit rules about hardcoded credentials that should be checked for examples
BANDIT_CREDENTIAL_RULES = frozenset(["B105", "B106", "B107"])


def is_example_secret(finding: Finding) -> bool:
    """Check if a secret finding is an example/placeholder.

    Checks findings in the SECRETS category, plus Bandit's hardcoded
    credential rules (B105, B106, B107) in the SECURITY category.

    Args:
        finding: The finding to check

    Returns:
        True if the finding appears to be an example/placeholder secret
    """
    # Apply to secrets category
    is_secrets_category = finding.category == Category.SECRETS

    # Also apply to Bandit hardcoded credential rules
    is_bandit_credential = (
        finding.scanner == "bandit" and finding.rule_id in BANDIT_CREDENTIAL_RULES
    )

    if not is_secrets_category and not is_bandit_credential:
        return False

    # Check code snippet
    if finding.code_snippet:
        for pattern in _EXAMPLE_PATTERNS:
            if pattern.search(finding.code_snippet):
                return True

    # Check message (some scanners include secret value in message)
    if finding.message:
        for pattern in _EXAMPLE_PATTERNS:
            if pattern.search(finding.message):
                return True

    # Check title (some scanners include partial secret in title)
    if finding.title:
        for pattern in _EXAMPLE_PATTERNS:
            if pattern.search(finding.title):
                return True

    return False


def get_example_match(finding: Finding) -> str | None:
    """Get the pattern that matched as an example secret.

    Useful for explaining why a secret was classified as an example.

    Args:
        finding: The finding to check

    Returns:
        The matching pattern string, or None if not an example
    """
    if finding.category != Category.SECRETS:
        return None

    texts_to_check = [
        finding.code_snippet,
        finding.message,
        finding.title,
    ]

    for text in texts_to_check:
        if not text:
            continue
        for pattern in _EXAMPLE_PATTERNS:
            match = pattern.search(text)
            if match:
                return match.group(0)

    return None
