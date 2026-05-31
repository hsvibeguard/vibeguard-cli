"""Path classification for triage.

Classifies file paths into categories (SOURCE, TESTS, GENERATED, VCS, etc.)
using compiled regex patterns for O(1) classification.
"""

import re
from functools import lru_cache

from vibeguard.models.triage import PathClass

# Compiled regex patterns for path classification
# Order matters - first match wins (most specific patterns first)
_PATH_PATTERNS: list[tuple[re.Pattern[str], PathClass]] = [
    # VCS directories (highest priority - always ignore)
    (re.compile(r"(^|/)\.git(/|$)", re.IGNORECASE), PathClass.VCS),
    (re.compile(r"(^|/)\.hg(/|$)", re.IGNORECASE), PathClass.VCS),
    (re.compile(r"(^|/)\.svn(/|$)", re.IGNORECASE), PathClass.VCS),

    # Generated/cache directories
    (re.compile(r"(^|/)\.mypy_cache(/|$)", re.IGNORECASE), PathClass.GENERATED),
    (re.compile(r"(^|/)__pycache__(/|$)", re.IGNORECASE), PathClass.GENERATED),
    (re.compile(r"(^|/)\.pytest_cache(/|$)", re.IGNORECASE), PathClass.GENERATED),
    (re.compile(r"(^|/)\.ruff_cache(/|$)", re.IGNORECASE), PathClass.GENERATED),
    (re.compile(r"(^|/)\.tox(/|$)", re.IGNORECASE), PathClass.GENERATED),
    (re.compile(r"(^|/)\.coverage(/|$)", re.IGNORECASE), PathClass.GENERATED),
    (re.compile(r"(^|/)htmlcov(/|$)", re.IGNORECASE), PathClass.GENERATED),
    (re.compile(r"(^|/)\.hypothesis(/|$)", re.IGNORECASE), PathClass.GENERATED),
    (re.compile(r"(^|/)node_modules(/|$)", re.IGNORECASE), PathClass.GENERATED),
    (re.compile(r"(^|/)\.next(/|$)", re.IGNORECASE), PathClass.GENERATED),
    (re.compile(r"(^|/)\.nuxt(/|$)", re.IGNORECASE), PathClass.GENERATED),
    (re.compile(r"(^|/)dist(/|$)", re.IGNORECASE), PathClass.GENERATED),
    (re.compile(r"(^|/)build(/|$)", re.IGNORECASE), PathClass.GENERATED),
    (re.compile(r"(^|/)target(/|$)", re.IGNORECASE), PathClass.GENERATED),  # Rust/Maven
    (re.compile(r"\.egg-info(/|$)", re.IGNORECASE), PathClass.GENERATED),
    (re.compile(r"\.dist-info(/|$)", re.IGNORECASE), PathClass.GENERATED),
    (re.compile(r"\.pyc$", re.IGNORECASE), PathClass.GENERATED),
    (re.compile(r"\.pyo$", re.IGNORECASE), PathClass.GENERATED),

    # Virtual environments
    (re.compile(r"(^|/)\.venv(/|$)", re.IGNORECASE), PathClass.GENERATED),
    (re.compile(r"(^|/)venv(/|$)", re.IGNORECASE), PathClass.GENERATED),
    (re.compile(r"(^|/)\.virtualenv(/|$)", re.IGNORECASE), PathClass.GENERATED),
    (re.compile(r"(^|/)env(/|$)", re.IGNORECASE), PathClass.GENERATED),
    (re.compile(r"(^|/)\.env(/|$)", re.IGNORECASE), PathClass.CONFIG),  # .env files are config

    # IDE/editor directories
    (re.compile(r"(^|/)\.idea(/|$)", re.IGNORECASE), PathClass.GENERATED),
    (re.compile(r"(^|/)\.vscode(/|$)", re.IGNORECASE), PathClass.GENERATED),
    (re.compile(r"(^|/)\.vs(/|$)", re.IGNORECASE), PathClass.GENERATED),

    # Temp directories
    (re.compile(r"(^|/)tmp(/|$)", re.IGNORECASE), PathClass.TEMP),
    (re.compile(r"(^|/)temp(/|$)", re.IGNORECASE), PathClass.TEMP),
    (re.compile(r"(^|/)\.tmp(/|$)", re.IGNORECASE), PathClass.TEMP),
    (re.compile(r"(^|/)\.temp(/|$)", re.IGNORECASE), PathClass.TEMP),
    (re.compile(r"(^|/)scratch(/|$)", re.IGNORECASE), PathClass.TEMP),

    # Third-party/vendor directories
    (re.compile(r"(^|/)vendor(/|$)", re.IGNORECASE), PathClass.THIRD_PARTY),
    (re.compile(r"(^|/)external(/|$)", re.IGNORECASE), PathClass.THIRD_PARTY),
    (re.compile(r"(^|/)third_party(/|$)", re.IGNORECASE), PathClass.THIRD_PARTY),
    (re.compile(r"(^|/)third-party(/|$)", re.IGNORECASE), PathClass.THIRD_PARTY),
    (re.compile(r"(^|/)deps(/|$)", re.IGNORECASE), PathClass.THIRD_PARTY),
    (re.compile(r"(^|/)packages(/|$)", re.IGNORECASE), PathClass.THIRD_PARTY),

    # Test directories/files
    (re.compile(r"(^|/)tests?(/|$)", re.IGNORECASE), PathClass.TESTS),
    (re.compile(r"(^|/)__tests__(/|$)", re.IGNORECASE), PathClass.TESTS),
    (re.compile(r"(^|/)test_[^/]+\.py$", re.IGNORECASE), PathClass.TESTS),
    (re.compile(r"(^|/)[^/]+_test\.py$", re.IGNORECASE), PathClass.TESTS),
    (re.compile(r"(^|/)conftest\.py$", re.IGNORECASE), PathClass.TESTS),
    (re.compile(r"\.spec\.(js|ts|jsx|tsx)$", re.IGNORECASE), PathClass.TESTS),
    (re.compile(r"\.test\.(js|ts|jsx|tsx)$", re.IGNORECASE), PathClass.TESTS),
    (re.compile(r"(^|/)spec(/|$)", re.IGNORECASE), PathClass.TESTS),
    (re.compile(r"(^|/)fixtures?(/|$)", re.IGNORECASE), PathClass.TESTS),

    # Documentation
    (re.compile(r"(^|/)docs?(/|$)", re.IGNORECASE), PathClass.DOCS),
    (re.compile(r"(^|/)documentation(/|$)", re.IGNORECASE), PathClass.DOCS),
    (re.compile(r"\.md$", re.IGNORECASE), PathClass.DOCS),
    (re.compile(r"\.rst$", re.IGNORECASE), PathClass.DOCS),
    (re.compile(r"\.txt$", re.IGNORECASE), PathClass.DOCS),
    (re.compile(r"(^|/)README", re.IGNORECASE), PathClass.DOCS),
    (re.compile(r"(^|/)CHANGELOG", re.IGNORECASE), PathClass.DOCS),
    (re.compile(r"(^|/)LICENSE", re.IGNORECASE), PathClass.DOCS),
    (re.compile(r"(^|/)CONTRIBUTING", re.IGNORECASE), PathClass.DOCS),

    # Config files (general catch-all for dotfiles and config)
    (re.compile(r"\.toml$", re.IGNORECASE), PathClass.CONFIG),
    (re.compile(r"\.ya?ml$", re.IGNORECASE), PathClass.CONFIG),
    (re.compile(r"\.json$", re.IGNORECASE), PathClass.CONFIG),
    (re.compile(r"\.ini$", re.IGNORECASE), PathClass.CONFIG),
    (re.compile(r"\.cfg$", re.IGNORECASE), PathClass.CONFIG),
    (re.compile(r"\.conf$", re.IGNORECASE), PathClass.CONFIG),
    (re.compile(r"(^|/)\.[\w]+rc$", re.IGNORECASE), PathClass.CONFIG),  # .eslintrc, .prettierrc
]


def classify_path(file_path: str) -> PathClass:
    """Classify a file path into a category.

    Args:
        file_path: The file path to classify (can be absolute or relative)

    Returns:
        PathClass enum value representing the classification
    """
    if not file_path:
        return PathClass.SOURCE

    # Normalize path separators (Windows to Unix style)
    normalized = file_path.replace("\\", "/").lstrip("./")

    for pattern, path_class in _PATH_PATTERNS:
        if pattern.search(normalized):
            return path_class

    return PathClass.SOURCE


@lru_cache(maxsize=1024)
def classify_path_cached(file_path: str) -> PathClass:
    """Cached version of classify_path for repeated lookups.

    Args:
        file_path: The file path to classify

    Returns:
        PathClass enum value representing the classification
    """
    return classify_path(file_path)


def is_noise_path(file_path: str) -> bool:
    """Check if a path is likely to produce noise findings.

    Noise paths include VCS, generated, temp, and third-party directories.

    Args:
        file_path: The file path to check

    Returns:
        True if the path is likely to produce noise
    """
    path_class = classify_path(file_path)
    return path_class in (
        PathClass.VCS,
        PathClass.GENERATED,
        PathClass.TEMP,
        PathClass.THIRD_PARTY,
    )
