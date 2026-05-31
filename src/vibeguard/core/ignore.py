"""Ignore pattern handling for VibeGuard.

Parses .vibeguardignore files and filters findings based on gitignore-style patterns.
"""

import re
from pathlib import Path

from vibeguard.models.finding import Finding

# Built-in default ignore patterns (applied before user patterns)
# These cover common noise directories across most languages/frameworks
DEFAULT_IGNORE_PATTERNS: list[str] = [
    # Version control
    ".git/",
    ".hg/",
    ".svn/",

    # Python caches and bytecode
    ".mypy_cache/",
    "__pycache__/",
    ".pytest_cache/",
    ".ruff_cache/",
    ".tox/",
    ".coverage",
    "htmlcov/",
    ".hypothesis/",
    "*.pyc",
    "*.pyo",
    "*.egg-info/",
    "*.dist-info/",

    # Virtual environments
    ".venv/",
    "venv/",
    ".virtualenv/",

    # JavaScript/Node
    "node_modules/",
    ".next/",
    ".nuxt/",
    ".cache/",
    "coverage/",

    # Build outputs
    "dist/",
    "build/",
    "target/",
    "out/",
    "_build/",

    # IDE/editors
    ".idea/",
    ".vscode/",
    ".vs/",
    "*.swp",
    "*.swo",
    "*~",

    # VibeGuard outputs
    ".vibeguard/cache/",
    ".vibeguard/patches/",
    "vibeguard-report-*.html",
]


def load_ignore_patterns(repo_root: Path) -> list[str]:
    """Load ignore patterns from .vibeguardignore file.

    Args:
        repo_root: Root directory of the repository

    Returns:
        List of gitignore-style patterns
    """
    ignore_file = repo_root / ".vibeguardignore"
    if not ignore_file.exists():
        return []

    patterns: list[str] = []
    try:
        content = ignore_file.read_text(encoding="utf-8")
        for line in content.splitlines():
            line = line.strip()
            # Skip empty lines and comments
            if not line or line.startswith("#"):
                continue
            patterns.append(line)
    except (OSError, UnicodeDecodeError):
        pass

    return patterns


def _pattern_to_regex(pattern: str) -> re.Pattern[str]:
    """Convert gitignore-style pattern to regex.

    Handles:
    - * matches anything except /
    - ** matches anything including /
    - ? matches single char
    - Directory patterns ending with /
    """
    # Normalize path separators
    pattern = pattern.replace("\\", "/")

    # Remove trailing slashes for matching
    is_dir_pattern = pattern.endswith("/")
    pattern = pattern.rstrip("/")

    # Build regex
    regex_parts: list[str] = []
    i = 0
    while i < len(pattern):
        c = pattern[i]
        if c == "*":
            if i + 1 < len(pattern) and pattern[i + 1] == "*":
                # ** matches everything including path separators
                if i + 2 < len(pattern) and pattern[i + 2] == "/":
                    regex_parts.append("(?:.*/)?")
                    i += 3
                    continue
                else:
                    regex_parts.append(".*")
                    i += 2
                    continue
            else:
                # * matches anything except /
                regex_parts.append("[^/]*")
        elif c == "?":
            regex_parts.append("[^/]")
        elif c == ".":
            regex_parts.append(r"\.")
        elif c == "/":
            regex_parts.append("/")
        else:
            regex_parts.append(re.escape(c))
        i += 1

    regex_str = "".join(regex_parts)

    # If pattern doesn't start with /, it can match anywhere in path
    if not pattern.startswith("/"):
        regex_str = f"(?:^|.*/){regex_str}"
    else:
        regex_str = f"^{regex_str[1:]}"  # Remove leading /

    # Directory patterns should match the directory and everything inside
    if is_dir_pattern:
        regex_str = f"{regex_str}(?:/.*)?$"
    else:
        regex_str = f"{regex_str}$"

    return re.compile(regex_str, re.IGNORECASE)


def should_ignore(file_path: str, patterns: list[str], repo_root: Path | None = None) -> bool:
    """Check if a file path matches any ignore pattern.

    Args:
        file_path: File path to check (can be absolute or relative)
        patterns: List of gitignore-style patterns
        repo_root: Repository root for converting absolute paths to relative

    Returns:
        True if the path should be ignored
    """
    if not patterns or not file_path:
        return False

    # Normalize the path
    try:
        path = Path(file_path)
        # Convert to relative path if repo_root is provided and path is absolute
        if repo_root and path.is_absolute():
            try:
                path = path.relative_to(repo_root)
            except ValueError:
                pass  # Path is not relative to repo_root

        # Convert to forward slashes for matching
        normalized_path = str(path).replace("\\", "/")
    except (ValueError, OSError):
        return False

    for pattern in patterns:
        try:
            regex = _pattern_to_regex(pattern)
            if regex.search(normalized_path):
                return True
        except re.error:
            # Invalid pattern, skip
            continue

    return False


def filter_findings(
    findings: list[Finding],
    patterns: list[str],
    repo_root: Path | None = None,
) -> list[Finding]:
    """Filter findings based on ignore patterns.

    Args:
        findings: List of findings to filter
        patterns: List of gitignore-style patterns
        repo_root: Repository root for path resolution

    Returns:
        Filtered list of findings
    """
    if not patterns:
        return findings

    return [
        f for f in findings
        if not should_ignore(f.file_path or "", patterns, repo_root)
    ]


def get_effective_patterns(
    user_patterns: list[str] | None = None,
    use_defaults: bool = True,
) -> list[str]:
    """Combine default and user patterns into effective ignore list.

    Args:
        user_patterns: User-specified patterns from .vibeguardignore
        use_defaults: Whether to include built-in default patterns

    Returns:
        Combined list of patterns (defaults first, then user patterns)
    """
    patterns: list[str] = []

    if use_defaults:
        patterns.extend(DEFAULT_IGNORE_PATTERNS)

    if user_patterns:
        patterns.extend(user_patterns)

    return patterns
