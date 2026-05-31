"""Tests for badge SVG generator."""


from vibeguard.reporters.badge import GRADE_COLORS, generate_badge


class TestBadgeStructure:
    """Test SVG badge structure."""

    def test_badge_is_valid_svg(self) -> None:
        """Badge should be valid SVG."""
        svg = generate_badge(85, "A")
        assert svg.startswith("<svg")
        assert "xmlns=" in svg
        assert "</svg>" in svg

    def test_badge_has_accessibility_label(self) -> None:
        """Badge should have aria-label for accessibility."""
        svg = generate_badge(85, "A")
        assert "aria-label=" in svg

    def test_badge_has_title(self) -> None:
        """Badge should have title element."""
        svg = generate_badge(85, "A")
        assert "<title>" in svg
        assert "</title>" in svg


class TestBadgeContent:
    """Test badge content."""

    def test_badge_contains_score(self) -> None:
        """Badge should display the score."""
        svg = generate_badge(85, "A")
        assert "85" in svg

    def test_badge_contains_grade(self) -> None:
        """Badge should display the grade."""
        svg = generate_badge(85, "A")
        assert ">A<" in svg or " A<" in svg or ">A " in svg

    def test_badge_contains_security_label(self) -> None:
        """Badge should have 'security' label."""
        svg = generate_badge(85, "A")
        assert "security" in svg.lower()


class TestBadgeGradeColors:
    """Test badge color coding by grade."""

    def test_a_plus_is_green(self) -> None:
        """A+ grade should be green."""
        svg = generate_badge(98, "A+")
        assert GRADE_COLORS["A+"] in svg

    def test_a_is_green(self) -> None:
        """A grade should be green."""
        svg = generate_badge(90, "A")
        assert GRADE_COLORS["A"] in svg

    def test_b_is_blue(self) -> None:
        """B grade should be blue."""
        svg = generate_badge(75, "B")
        assert GRADE_COLORS["B"] in svg

    def test_c_is_yellow(self) -> None:
        """C grade should be yellow."""
        svg = generate_badge(55, "C")
        assert GRADE_COLORS["C"] in svg

    def test_d_is_orange(self) -> None:
        """D grade should be orange."""
        svg = generate_badge(35, "D")
        assert GRADE_COLORS["D"] in svg

    def test_f_is_red(self) -> None:
        """F grade should be red."""
        svg = generate_badge(15, "F")
        assert GRADE_COLORS["F"] in svg


class TestBadgeEdgeCases:
    """Test edge cases for badge generation."""

    def test_score_zero(self) -> None:
        """Badge should handle score of 0."""
        svg = generate_badge(0, "F")
        assert "0" in svg
        assert GRADE_COLORS["F"] in svg

    def test_score_hundred(self) -> None:
        """Badge should handle perfect score."""
        svg = generate_badge(100, "A+")
        assert "100" in svg
        assert GRADE_COLORS["A+"] in svg

    def test_a_plus_grade_format(self) -> None:
        """Badge should properly display A+ with plus sign."""
        svg = generate_badge(95, "A+")
        assert "A+" in svg


class TestBadgeDimensions:
    """Test badge dimensions."""

    def test_badge_has_width(self) -> None:
        """Badge should have width attribute."""
        svg = generate_badge(85, "A")
        assert 'width="' in svg

    def test_badge_has_height(self) -> None:
        """Badge should have height of 20 (shields.io standard)."""
        svg = generate_badge(85, "A")
        assert 'height="20"' in svg

    def test_badge_width_varies_with_content(self) -> None:
        """Badge width should vary based on content length."""
        svg_short = generate_badge(0, "F")
        svg_long = generate_badge(100, "A+")

        # Extract width values
        import re

        width_short = int(re.search(r'width="(\d+)"', svg_short).group(1))
        width_long = int(re.search(r'width="(\d+)"', svg_long).group(1))

        # 100 A+ should be wider than 0 F
        assert width_long > width_short


class TestBadgeRendering:
    """Test badge visual elements."""

    def test_badge_has_gradient(self) -> None:
        """Badge should have gradient for visual polish."""
        svg = generate_badge(85, "A")
        assert "linearGradient" in svg

    def test_badge_has_clip_path(self) -> None:
        """Badge should have clip path for rounded corners."""
        svg = generate_badge(85, "A")
        assert "clipPath" in svg

    def test_badge_has_text_shadow(self) -> None:
        """Badge should have text shadow effect."""
        svg = generate_badge(85, "A")
        # Shadow is typically achieved with fill-opacity
        assert "fill-opacity" in svg


class TestGradeColorMapping:
    """Test the GRADE_COLORS mapping."""

    def test_all_grades_have_colors(self) -> None:
        """All grades should have defined colors."""
        expected_grades = ["A+", "A", "B", "C", "D", "F"]
        for grade in expected_grades:
            assert grade in GRADE_COLORS
            assert GRADE_COLORS[grade].startswith("#")

    def test_colors_are_valid_hex(self) -> None:
        """All colors should be valid hex codes."""
        import re

        hex_pattern = re.compile(r"^#[0-9a-fA-F]{6}$")
        for grade, color in GRADE_COLORS.items():
            assert hex_pattern.match(color), f"Invalid color for {grade}: {color}"
