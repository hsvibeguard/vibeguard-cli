"""Patch artifact model for generated fixes."""

from __future__ import annotations

import re
from datetime import datetime

from pydantic import BaseModel, Field


class PatchArtifact(BaseModel):
    """A generated patch for a security finding."""

    finding_id: str = Field(..., description="ID of the finding this patch fixes")
    file_path: str = Field(..., description="Path to the file being patched")
    unified_diff: str = Field(..., description="The patch in unified diff format")
    provider: str = Field(..., description="LLM provider used")
    model: str = Field(..., description="LLM model used")
    generated_at: datetime = Field(default_factory=datetime.now)
    manual_review_required: bool = Field(
        default=False,
        description="True if patch contains uncertainty markers",
    )


def validate_unified_diff(diff: str) -> tuple[bool, str]:
    """Validate that a string is a valid unified diff.

    Args:
        diff: The diff string to validate

    Returns:
        Tuple of (is_valid, error_message)
    """
    lines = diff.strip().split("\n")

    if not lines or not lines[0]:
        return False, "Empty diff"

    # Must have file headers
    has_minus_header = any(line.startswith("--- ") for line in lines)
    has_plus_header = any(line.startswith("+++ ") for line in lines)

    if not has_minus_header:
        return False, "Missing '--- ' file header"
    if not has_plus_header:
        return False, "Missing '+++ ' file header"

    # Must have at least one hunk
    has_hunk = any(line.startswith("@@") for line in lines)
    if not has_hunk:
        return False, "Missing @@ hunk marker"

    # Validate hunk format
    hunk_pattern = re.compile(r"^@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@")
    for line in lines:
        if line.startswith("@@"):
            if not hunk_pattern.match(line):
                return False, f"Invalid hunk header format: {line[:50]}"

    # Check for valid lines in hunks
    in_hunk = False
    for line in lines:
        if line.startswith("@@"):
            in_hunk = True
            continue
        if in_hunk and line:
            # Valid line prefixes in a hunk:
            # ' ' - context line
            # '+' - added line
            # '-' - removed line
            # '\' - "No newline at end of file" marker
            if line[0] not in (" ", "+", "-", "\\"):
                # Could be a new file header, which ends the hunk
                if line.startswith("--- ") or line.startswith("+++ "):
                    in_hunk = False
                    continue
                return False, f"Invalid line in hunk: {line[:50]}"

    return True, ""


def extract_diff_from_response(response: str) -> str | None:
    """Extract unified diff from LLM response.

    LLMs often wrap diffs in markdown code blocks. This function
    extracts the actual diff content.

    Args:
        response: Raw LLM response text

    Returns:
        Extracted diff string, or None if no valid diff found
    """
    response = response.strip()

    # Try to find diff in ```diff code block
    if "```diff" in response:
        start = response.find("```diff") + 7
        end = response.find("```", start)
        if end > start:
            candidate = response[start:end].strip()
            if candidate:
                return candidate

    # Try to find diff in generic ``` code block
    if "```" in response:
        # Find first code block
        start = response.find("```")
        if start != -1:
            # Skip the opening ``` and any language identifier
            content_start = response.find("\n", start)
            if content_start != -1:
                content_start += 1
                end = response.find("```", content_start)
                if end > content_start:
                    candidate = response[content_start:end].strip()
                    # Check if it looks like a diff
                    if _looks_like_diff(candidate):
                        return candidate

    # Try raw response (no code blocks)
    if _looks_like_diff(response):
        return response

    # Try to find diff starting with --- anywhere in response
    idx = response.find("--- ")
    if idx != -1:
        # Extract from --- to end or next non-diff content
        candidate = response[idx:].strip()
        # Find where diff ends (blank line followed by non-diff content)
        lines = candidate.split("\n")
        diff_lines = []
        for line in lines:
            if _is_diff_line(line):
                diff_lines.append(line)
            elif not line.strip():
                diff_lines.append(line)
            else:
                # Non-diff line - check if we have a valid diff so far
                if diff_lines:
                    break
        if diff_lines:
            candidate = "\n".join(diff_lines).strip()
            if _looks_like_diff(candidate):
                return candidate

    return None


def _looks_like_diff(text: str) -> bool:
    """Check if text appears to be a unified diff."""
    return text.startswith("--- ") or text.startswith("diff --git")


def _is_diff_line(line: str) -> bool:
    """Check if a line is a valid diff line."""
    if not line:
        return True  # Empty lines are valid
    if line.startswith(("--- ", "+++ ", "@@ ", " ", "+", "-", "\\")):
        return True
    if line.startswith("diff --git"):
        return True
    return False
