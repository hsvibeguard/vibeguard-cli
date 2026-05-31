"""SVG badge generator for security scores (shields.io style)."""

# Grade color mapping
GRADE_COLORS = {
    "A+": "#22c55e",  # Green
    "A": "#22c55e",  # Green
    "B": "#3b82f6",  # Blue
    "C": "#eab308",  # Yellow
    "D": "#f97316",  # Orange
    "F": "#ef4444",  # Red
}

# SVG template (shields.io flat style)
SVG_TEMPLATE = """<svg xmlns="http://www.w3.org/2000/svg" width="{total_width}" height="20"
  role="img"
  aria-label="security: {score} {grade}">
  <title>security: {score} {grade}</title>
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r">
    <rect width="{total_width}" height="20" rx="3" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#r)">
    <rect width="{label_width}" height="20" fill="#555"/>
    <rect x="{label_width}" width="{value_width}" height="20" fill="{color}"/>
    <rect width="{total_width}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle"
    font-family="Verdana,Geneva,DejaVu Sans,sans-serif"
    text-rendering="geometricPrecision" font-size="110">
    <text aria-hidden="true" x="{label_center}" y="150" fill="#010101"
      fill-opacity=".3" transform="scale(.1)"
      textLength="{label_text_width}">
      security
    </text>
    <text x="{label_center}" y="140" transform="scale(.1)" fill="#fff"
      textLength="{label_text_width}">
      security
    </text>
    <text aria-hidden="true" x="{value_center}" y="150" fill="#010101"
      fill-opacity=".3" transform="scale(.1)"
      textLength="{value_text_width}">
      {score} {grade}
    </text>
    <text x="{value_center}" y="140" transform="scale(.1)" fill="#fff"
      textLength="{value_text_width}">
      {score} {grade}
    </text>
  </g>
</svg>"""


def generate_badge(score: int, grade: str) -> str:
    """Generate an SVG badge for the security score.

    Creates a shields.io-style flat badge with "security" label on the left
    and the score + grade on the right.

    Args:
        score: Security score (0-100)
        grade: Letter grade (A+, A, B, C, D, F)

    Returns:
        SVG string that can be saved to a file or embedded in HTML
    """
    # Get color for the grade
    color = GRADE_COLORS.get(grade, "#6b7280")

    # Calculate dimensions
    label_text = "security"
    value_text = f"{score} {grade}"

    # Approximate character widths (shields.io uses ~6px per character at font-size 11)
    char_width = 6.5
    padding = 10  # Padding on each side

    label_text_width = len(label_text) * char_width * 10  # Scaled for transform
    value_text_width = len(value_text) * char_width * 10

    label_width = int(len(label_text) * char_width + padding * 2)
    value_width = int(len(value_text) * char_width + padding * 2)
    total_width = label_width + value_width

    # Calculate text center positions (in scaled units for transform)
    label_center = (label_width / 2) * 10
    value_center = (label_width + value_width / 2) * 10

    svg = SVG_TEMPLATE.format(
        total_width=total_width,
        label_width=label_width,
        value_width=value_width,
        label_center=int(label_center),
        value_center=int(value_center),
        label_text_width=int(label_text_width),
        value_text_width=int(value_text_width),
        score=score,
        grade=grade,
        color=color,
    )

    return svg
