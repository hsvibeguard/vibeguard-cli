"""Tests for patch model and diff validation."""

from __future__ import annotations

from datetime import datetime

from vibeguard.models.patch import (
    PatchArtifact,
    extract_diff_from_response,
    validate_unified_diff,
)

# Sample valid unified diffs
VALID_SIMPLE_DIFF = """\
--- a/example.py
+++ b/example.py
@@ -1,3 +1,3 @@
 def hello():
-    print("hello")
+    print("Hello, World!")
     return True
"""

VALID_MULTIFILE_DIFF = """\
--- a/file1.py
+++ b/file1.py
@@ -1,2 +1,2 @@
-old_line
+new_line
 context
--- a/file2.py
+++ b/file2.py
@@ -5,3 +5,4 @@
 context
+added line
 more context
"""

VALID_GIT_DIFF = """\
diff --git a/example.py b/example.py
--- a/example.py
+++ b/example.py
@@ -1,3 +1,3 @@
 def hello():
-    print("hello")
+    print("Hello, World!")
     return True
"""


class TestValidateUnifiedDiff:
    """Tests for validate_unified_diff()."""

    def test_valid_simple_diff(self) -> None:
        """Should accept a valid simple diff."""
        is_valid, error = validate_unified_diff(VALID_SIMPLE_DIFF)
        assert is_valid is True
        assert error == ""

    def test_valid_multifile_diff(self) -> None:
        """Should accept a valid multi-file diff."""
        is_valid, error = validate_unified_diff(VALID_MULTIFILE_DIFF)
        assert is_valid is True
        assert error == ""

    def test_valid_git_diff(self) -> None:
        """Should accept a git-style diff."""
        is_valid, error = validate_unified_diff(VALID_GIT_DIFF)
        assert is_valid is True
        assert error == ""

    def test_empty_diff(self) -> None:
        """Should reject empty diff."""
        is_valid, error = validate_unified_diff("")
        assert is_valid is False
        assert "Empty diff" in error

    def test_whitespace_only_diff(self) -> None:
        """Should reject whitespace-only diff."""
        is_valid, error = validate_unified_diff("   \n\n   ")
        assert is_valid is False
        assert "Empty diff" in error

    def test_missing_minus_header(self) -> None:
        """Should reject diff without --- header."""
        diff = """\
+++ b/example.py
@@ -1,1 +1,1 @@
-old
+new
"""
        is_valid, error = validate_unified_diff(diff)
        assert is_valid is False
        assert "--- " in error

    def test_missing_plus_header(self) -> None:
        """Should reject diff without +++ header."""
        diff = """\
--- a/example.py
@@ -1,1 +1,1 @@
-old
+new
"""
        is_valid, error = validate_unified_diff(diff)
        assert is_valid is False
        assert "+++ " in error

    def test_missing_hunk_marker(self) -> None:
        """Should reject diff without @@ marker."""
        diff = """\
--- a/example.py
+++ b/example.py
-old
+new
"""
        is_valid, error = validate_unified_diff(diff)
        assert is_valid is False
        assert "@@" in error

    def test_invalid_hunk_format(self) -> None:
        """Should reject diff with malformed hunk header."""
        diff = """\
--- a/example.py
+++ b/example.py
@@ invalid @@
-old
+new
"""
        is_valid, error = validate_unified_diff(diff)
        assert is_valid is False
        assert "Invalid hunk header" in error

    def test_accepts_no_newline_marker(self) -> None:
        """Should accept \\ No newline at end of file marker."""
        diff = """\
--- a/example.py
+++ b/example.py
@@ -1,1 +1,1 @@
-old
\\ No newline at end of file
+new
\\ No newline at end of file
"""
        is_valid, error = validate_unified_diff(diff)
        assert is_valid is True

    def test_accepts_context_only_hunk(self) -> None:
        """Should accept a hunk with only context lines."""
        diff = """\
--- a/example.py
+++ b/example.py
@@ -1,3 +1,3 @@
 line1
 line2
 line3
"""
        is_valid, error = validate_unified_diff(diff)
        assert is_valid is True


class TestExtractDiffFromResponse:
    """Tests for extract_diff_from_response()."""

    def test_extracts_from_diff_code_block(self) -> None:
        """Should extract diff from ```diff code block."""
        response = f"""
Here's the fix:

```diff
{VALID_SIMPLE_DIFF}
```

This changes the print statement.
"""
        result = extract_diff_from_response(response)
        assert result is not None
        assert result.startswith("--- a/example.py")

    def test_extracts_from_generic_code_block(self) -> None:
        """Should extract diff from generic ``` code block."""
        response = f"""
Here's the fix:

```
{VALID_SIMPLE_DIFF}
```
"""
        result = extract_diff_from_response(response)
        assert result is not None
        assert "--- a/example.py" in result

    def test_extracts_raw_diff(self) -> None:
        """Should extract diff without code blocks."""
        result = extract_diff_from_response(VALID_SIMPLE_DIFF)
        assert result is not None
        assert result.startswith("--- a/example.py")

    def test_extracts_diff_with_surrounding_text(self) -> None:
        """Should extract diff from response with surrounding text."""
        response = f"""
I'll fix this security issue by sanitizing the input.

{VALID_SIMPLE_DIFF}

This should prevent the vulnerability.
"""
        result = extract_diff_from_response(response)
        assert result is not None
        assert "--- a/example.py" in result

    def test_returns_none_for_no_diff(self) -> None:
        """Should return None if no diff found."""
        response = "Here's some explanation without any diff."
        result = extract_diff_from_response(response)
        assert result is None

    def test_returns_none_for_empty_response(self) -> None:
        """Should return None for empty response."""
        result = extract_diff_from_response("")
        assert result is None

    def test_extracts_git_diff(self) -> None:
        """Should extract git-style diff."""
        response = f"""
```diff
{VALID_GIT_DIFF}
```
"""
        result = extract_diff_from_response(response)
        assert result is not None
        assert "diff --git" in result

    def test_handles_code_block_with_language(self) -> None:
        """Should handle code blocks with language specifier."""
        response = """
```diff
--- a/test.py
+++ b/test.py
@@ -1,1 +1,1 @@
-bad
+good
```
"""
        result = extract_diff_from_response(response)
        assert result is not None
        assert "--- a/test.py" in result


class TestPatchArtifact:
    """Tests for PatchArtifact model."""

    def test_creates_patch_artifact(self) -> None:
        """Should create a valid patch artifact."""
        patch = PatchArtifact(
            finding_id="abc123",
            file_path="example.py",
            unified_diff=VALID_SIMPLE_DIFF,
            provider="openai",
            model="gpt-4",
        )

        assert patch.finding_id == "abc123"
        assert patch.file_path == "example.py"
        assert patch.provider == "openai"
        assert patch.model == "gpt-4"
        assert patch.manual_review_required is False

    def test_sets_generated_at_automatically(self) -> None:
        """Should set generated_at to current time."""
        before = datetime.now()
        patch = PatchArtifact(
            finding_id="abc123",
            file_path="example.py",
            unified_diff=VALID_SIMPLE_DIFF,
            provider="anthropic",
            model="claude-3",
        )
        after = datetime.now()

        assert before <= patch.generated_at <= after

    def test_serializes_to_json(self) -> None:
        """Should serialize to JSON correctly."""
        patch = PatchArtifact(
            finding_id="abc123",
            file_path="example.py",
            unified_diff=VALID_SIMPLE_DIFF,
            provider="openai",
            model="gpt-4",
            manual_review_required=True,
        )

        json_str = patch.model_dump_json()
        assert "abc123" in json_str
        assert "openai" in json_str
        assert "manual_review_required" in json_str

    def test_deserializes_from_json(self) -> None:
        """Should deserialize from JSON correctly."""
        patch = PatchArtifact(
            finding_id="abc123",
            file_path="example.py",
            unified_diff=VALID_SIMPLE_DIFF,
            provider="openai",
            model="gpt-4",
        )

        json_str = patch.model_dump_json()
        loaded = PatchArtifact.model_validate_json(json_str)

        assert loaded.finding_id == patch.finding_id
        assert loaded.file_path == patch.file_path
        assert loaded.provider == patch.provider
