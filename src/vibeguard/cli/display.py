"""Display utilities and branding for VibeGuard CLI."""

import io
import random  # nosec B311  # noqa: S311  # used for display variety, not security
import sys

from rich.align import Align
from rich.console import Console
from rich.text import Text

LOGO = """[bold red]
██╗   ██╗██╗██████╗ ███████╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
██║   ██║██║██╔══██╗██╔════╝██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
██║   ██║██║██████╔╝█████╗  ██║  ███╗██║   ██║███████║██████╔╝██║  ██║
╚██╗ ██╔╝██║██╔══██╗██╔══╝  ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
 ╚████╔╝ ██║██████╔╝███████╗╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
  ╚═══╝  ╚═╝╚═════╝ ╚══════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝
[/bold red]"""

PRO_BADGE = " [bold cyan]PRO[/bold cyan]"


def get_logo(is_pro: bool = False) -> str:
    """Get the LOGO string, optionally with a PRO badge on the first art line.

    Args:
        is_pro: If True, append a cyan PRO badge to the top-right of the logo.

    Returns:
        The logo markup string (with or without PRO badge).
    """
    if not is_pro:
        return LOGO

    lines = LOGO.split("\n")
    # lines[0] is empty (before first art line), lines[1] is the first row of blocks
    for i, line in enumerate(lines):
        if "██" in line:
            # Insert PRO badge right before the [/bold red] closing tag on this line
            lines[i] = line + PRO_BADGE
            break

    return "\n".join(lines)

# =============================================================================
# VibeGuard Brand Spinner - Custom animated symbols
# =============================================================================

# Brand color (matches logo)
BRAND_COLOR = "bold red"

# Custom spinner frames - alternating security-themed symbols
VIBEGUARD_SPINNER_FRAMES = ["✶", "✢", "✻", "✦", "✧", "✹", "✸", "✷"]

# Spinner definition for Rich
VIBEGUARD_SPINNER = {
    "interval": 100,  # milliseconds between frames
    "frames": VIBEGUARD_SPINNER_FRAMES,
}

# Spinner name for SpinnerColumn (registered below)
VIBEGUARD_SPINNER_NAME = "vibeguard"


def _register_vibeguard_spinner() -> None:
    """Register the VibeGuard spinner with Rich's spinner registry."""
    from rich.spinner import SPINNERS

    if VIBEGUARD_SPINNER_NAME not in SPINNERS:
        SPINNERS[VIBEGUARD_SPINNER_NAME] = VIBEGUARD_SPINNER


# Register on module load
_register_vibeguard_spinner()

MINI_LOGO = "[bold red]* VibeGuard[/bold red]"

TAGLINE = "Security Scanner for AI-Generated Code"

# Cached console for Windows UTF-8 handling
_cached_console: Console | None = None


def get_console() -> Console:
    """Get a console configured for proper output handling.

    On Windows with a real terminal, this creates a console with UTF-8 encoding support.
    For tests and other platforms, returns a standard Console.
    """
    global _cached_console

    # Check if stdout has a buffer AND is a tty (real terminal, not test runner)
    is_real_terminal = (
        hasattr(sys.stdout, "buffer")
        and hasattr(sys.stdout, "isatty")
        and sys.stdout.isatty()
    )

    if sys.platform == "win32" and is_real_terminal:
        # Only create cached console once to avoid issues with multiple wrappers
        if _cached_console is None:
            utf8_stdout = io.TextIOWrapper(
                sys.stdout.buffer, encoding="utf-8", errors="replace", write_through=True
            )
            _cached_console = Console(
                file=utf8_stdout, force_terminal=True, legacy_windows=False
            )
        return _cached_console

    # For tests or non-Windows, use standard console (not cached)
    return Console()


def print_logo(
    console: Console | None = None, centered: bool = True, is_pro: bool = False
) -> None:
    """Print the VibeGuard ASCII logo.

    Args:
        console: Rich Console instance (uses default if None).
        centered: Whether to center the logo in the terminal.
        is_pro: If True, display a PRO badge on the logo.
    """
    c = console or get_console()
    logo = get_logo(is_pro=is_pro)
    try:
        if centered:
            c.print(Align.center(Text.from_markup(logo)))
        else:
            c.print(Text.from_markup(logo))
    except UnicodeEncodeError:
        # Silently skip logo on terminals that can't display it
        pass


def print_tagline(console: Console | None = None, centered: bool = True) -> None:
    """Print the tagline under the logo."""
    c = console or get_console()
    try:
        if centered:
            c.print(Align.center(Text(TAGLINE, style="bold white")))
        else:
            c.print(f"[bold white]{TAGLINE}[/bold white]")
    except UnicodeEncodeError:
        pass


def print_banner(
    console: Console | None = None, centered: bool = True, is_pro: bool = False
) -> None:
    """Print the full banner (logo + tagline).

    Args:
        console: Rich Console instance (uses default if None).
        centered: Whether to center the banner in the terminal.
        is_pro: If True, display a PRO badge on the logo.
    """
    c = console or get_console()
    logo = get_logo(is_pro=is_pro)
    try:
        if centered:
            c.print(Align.center(Text.from_markup(logo)))
            c.print(Align.center(Text(TAGLINE, style="bold white")))
        else:
            c.print(Text.from_markup(logo))
            c.print(f"[bold white]{TAGLINE}[/bold white]")
        c.print()
    except UnicodeEncodeError:
        pass


# =============================================================================
# Fun Status Messages - Security-themed phrases for terminal animations
# =============================================================================

BOOTSTRAP_MESSAGES = [
    "Summoning security scanners",
    "Waking up the guardians",
    "Assembling the vibe protectors",
    "Loading defense protocols",
    "Initializing threat detectors",
    "Calibrating security sensors",
    "Booting up the watchdogs",
    "Powering up shields",
    "Activating perimeter defenses",
    "Deploying scanner drones",
    "Warming up the radar",
    "Spinning up sentinels",
    "Engaging protection matrix",
    "Arming vulnerability hunters",
    "Preparing the security forge",
]

SCANNING_MESSAGES = [
    "Hunting for vulnerabilities",
    "Scanning the vibe frequencies",
    "Checking for secret leaks",
    "Interrogating the codebase",
    "Sniffing out security smells",
    "Probing for weaknesses",
    "Sweeping for threats",
    "Analyzing attack surfaces",
    "Inspecting the perimeter",
    "Tracing suspicious patterns",
    "Decoding potential threats",
    "Examining dark corners",
    "Parsing the danger zones",
    "Evaluating risk vectors",
    "Mapping the threat landscape",
    "Dissecting dependencies",
    "Auditing the code vibes",
    "Chasing down CVEs",
    "Following the breadcrumbs",
    "Detecting anomalies",
]

SCANNER_MESSAGES = {
    "semgrep": [
        "Running static analysis",
        "Pattern matching at scale",
        "Grep-ing for danger",
        "Semantic searching",
        "AST traversal in progress",
        "Finding code anti-patterns",
    ],
    "gitleaks": [
        "Hunting leaked secrets",
        "Scanning for exposed credentials",
        "Detecting hardcoded keys",
        "Checking for API tokens",
        "Sniffing out passwords",
        "Finding secret spillage",
    ],
    "trivy": [
        "Scanning dependencies",
        "Checking for CVEs",
        "Auditing packages",
        "Vulnerability hunting",
        "Inspecting containers",
        "Analyzing supply chain",
    ],
    "bandit": [
        "Python security check",
        "Analyzing Python vibes",
        "Hunting Python pitfalls",
        "Checking for Pythonic sins",
        "Scanning snake code",
        "Evaluating Python safety",
    ],
    "trufflehog": [
        "Deep secret scanning",
        "Digging for buried keys",
        "Truffle hunting mode",
        "Entropy analysis active",
        "Sniffing git history",
        "Unearthing hidden secrets",
    ],
    # Ecosystem scanners
    "npm_audit": [
        "Auditing npm packages",
        "Checking node_modules",
        "Scanning JS dependencies",
        "npm vulnerability check",
        "Package security audit",
        "Node.js supply chain scan",
    ],
    "pip_audit": [
        "Auditing Python packages",
        "Checking pip dependencies",
        "Scanning PyPI packages",
        "Python supply chain audit",
        "Dependency vulnerability scan",
        "pip security check",
    ],
    "cargo_audit": [
        "Auditing Rust crates",
        "Checking Cargo.lock",
        "Scanning Rust dependencies",
        "RustSec advisory check",
        "Crate vulnerability audit",
        "Rust supply chain scan",
    ],
    # Differentiation scanners
    "checkov": [
        "Scanning IaC policies",
        "Checking infrastructure code",
        "Policy compliance audit",
        "Terraform security check",
        "Cloud config validation",
        "IaC misconfiguration scan",
        "K8s manifest analysis",
        "Dockerfile best practices",
    ],
    "dockle": [
        "Scanning container image",
        "CIS Docker benchmark check",
        "Container security audit",
        "Image hardening analysis",
        "Docker compliance scan",
        "Container best practices",
    ],
    # DAST scanner
    "nuclei": [
        "HTTP vulnerability scanning",
        "Template-based detection",
        "Probing web endpoints",
        "DAST scan in progress",
        "Testing web security",
        "Checking for web vulns",
        "HTTP fuzzing active",
        "API security testing",
    ],
}

PATCHING_MESSAGES = [
    "Crafting the fix",
    "Weaving security patches",
    "Generating remediation",
    "Engineering the solution",
    "Building the repair",
    "Forging the patch",
    "Synthesizing the cure",
    "Compiling the antidote",
    "Stitching the vulnerability",
    "Mending the code fabric",
    "Applying healing magic",
    "Sealing the breach",
    "Reinforcing defenses",
    "Hardening the perimeter",
    "Neutralizing the threat",
]

COMPLETION_MESSAGES = [
    "Vibe check complete",
    "Security scan finished",
    "All clear, guardian",
    "Defenses verified",
    "Scan mission accomplished",
    "Protection audit done",
    "Security sweep complete",
    "Threat assessment finished",
    "Code fortress inspected",
    "Safety check done",
]

SUCCESS_MESSAGES = [
    "Your vibes are immaculate",
    "Code is looking secure",
    "No threats detected",
    "Clean bill of health",
    "Security game strong",
    "Fortress is holding",
    "All systems nominal",
    "Defenses are solid",
]

FINDING_MESSAGES = [
    "Found some security concerns",
    "Detected potential issues",
    "Vulnerabilities discovered",
    "Some vibes need attention",
    "Security findings detected",
    "Issues require review",
    "Threats identified",
    "Action items found",
]


def get_bootstrap_message() -> str:
    """Get a random bootstrap status message."""
    return random.choice(BOOTSTRAP_MESSAGES)  # nosec B311


def get_scanning_message() -> str:
    """Get a random general scanning status message."""
    return random.choice(SCANNING_MESSAGES)  # nosec B311


def get_scanner_message(scanner_name: str) -> str:
    """Get a random status message for a specific scanner."""
    messages = SCANNER_MESSAGES.get(scanner_name.lower(), SCANNING_MESSAGES)
    return random.choice(messages)  # nosec B311


def get_patching_message() -> str:
    """Get a random patching status message."""
    return random.choice(PATCHING_MESSAGES)  # nosec B311


def get_completion_message() -> str:
    """Get a random completion status message."""
    return random.choice(COMPLETION_MESSAGES)  # nosec B311


def get_result_message(has_findings: bool) -> str:
    """Get a random result message based on whether findings exist."""
    if has_findings:
        return random.choice(FINDING_MESSAGES)  # nosec B311
    return random.choice(SUCCESS_MESSAGES)  # nosec B311
