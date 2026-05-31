"""Shared test fixtures for VibeGuard tests."""

from datetime import datetime

import pytest

from vibeguard.models.finding import Category, Finding, Severity
from vibeguard.models.scan_result import ScanResult


@pytest.fixture
def sample_finding() -> Finding:
    """Create a sample Finding for testing."""
    return Finding(
        scanner="semgrep",
        rule_id="python.security.eval",
        severity=Severity.HIGH,
        category=Category.SECURITY,
        title="Use of eval",
        message="Avoid using eval() as it can execute arbitrary code",
        file_path="app.py",
        line_start=10,
        line_end=10,
        cwe="CWE-95",
        references=["https://owasp.org/eval"],
        code_snippet="result = eval(user_input)",
    )


@pytest.fixture
def sample_scan_result(sample_finding: Finding) -> ScanResult:
    """Create a sample ScanResult for testing."""
    return ScanResult(
        repo_root="/path/to/repo",
        started_at=datetime.now(),
        finished_at=datetime.now(),
        findings=[sample_finding],
        scanners_run=["semgrep"],
        scanners_skipped=[],
        partial=False,
    )


@pytest.fixture
def semgrep_json_output() -> str:
    """Sample Semgrep JSON output for parser testing."""
    import json
    return json.dumps({
        "results": [
            {
                "check_id": "python.security.audit.dangerous-eval-use",
                "path": "app/utils.py",
                "start": {"line": 42, "col": 5, "offset": 1234},
                "end": {"line": 42, "col": 25, "offset": 1254},
                "extra": {
                    "message": "Detected the use of eval(). This can be dangerous.",
                    "severity": "WARNING",
                    "lines": "    result = eval(user_input)",
                    "fingerprint": "abc123",
                    "metadata": {
                        "cwe": ["CWE-95: Improper Neutralization of Directives"],
                        "references": ["https://owasp.org/eval"],
                    },
                },
            }
        ],
        "errors": [],
    })


@pytest.fixture
def gitleaks_json_output() -> str:
    """Sample Gitleaks JSON output for parser testing."""
    import json
    return json.dumps([
        {
            "Description": "Generic API Key",
            "StartLine": 23,
            "EndLine": 23,
            "StartColumn": 10,
            "EndColumn": 45,
            "Match": "api_key = 'sk_live_xxxxxxxxxxxx'",
            "Secret": "sk_live_xxxxxxxxxxxx",
            "File": "config/settings.py",
            "SymlinkFile": "",
            "Commit": "cd5226711335c68be1e720b318b7bc3135a30eb2",
            "Entropy": 4.5,
            "Author": "developer",
            "Email": "dev@example.com",
            "Date": "2024-01-15T10:30:00Z",
            "Message": "Add config file",
            "Tags": [],
            "RuleID": "generic-api-key",
            "Fingerprint": (
                "cd5226711335c68be1e720b318b7bc3135a30eb2"
                ":config/settings.py:generic-api-key:23"
            )
        },
        {
            "Description": "AWS Access Key",
            "StartLine": 5,
            "EndLine": 5,
            "StartColumn": 1,
            "EndColumn": 40,
            "Match": "AKIAIOSFODNN7EXAMPLE",
            "Secret": "AKIAIOSFODNN7EXAMPLE",
            "File": ".env",
            "RuleID": "aws-access-key-id",
            "Fingerprint": "abc123:.env:aws-access-key-id:5"
        }
    ])


@pytest.fixture
def bandit_json_output() -> str:
    """Sample Bandit JSON output for parser testing."""
    import json
    return json.dumps({
        "errors": [],
        "generated_at": "2024-01-15T10:00:00Z",
        "metrics": {},
        "results": [
            {
                "code": "42     os.system(user_input)\n",
                "col_offset": 4,
                "end_col_offset": 25,
                "filename": "app/utils.py",
                "issue_confidence": "HIGH",
                "issue_cwe": {"id": 78, "link": "https://cwe.mitre.org/data/definitions/78.html"},
                "issue_severity": "HIGH",
                "issue_text": "Possible shell injection via user input in os.system call",
                "line_number": 42,
                "line_range": [42],
                "more_info": "https://bandit.readthedocs.io/en/latest/plugins/b605_start_process_with_a_shell.html",
                "test_id": "B605",
                "test_name": "start_process_with_a_shell"
            },
            {
                "code": "15     password = 'hardcoded_password'\n",
                "filename": "config/settings.py",
                "issue_confidence": "MEDIUM",
                "issue_severity": "LOW",
                "issue_text": "Possible hardcoded password",
                "line_number": 15,
                "line_range": [15],
                "more_info": "https://bandit.readthedocs.io/en/latest/plugins/b105_hardcoded_password_string.html",
                "test_id": "B105",
                "test_name": "hardcoded_password_string"
            },
            {
                "code": "88     eval(user_data)\n",
                "filename": "app/parser.py",
                "issue_confidence": "HIGH",
                "issue_severity": "MEDIUM",
                "issue_text": "Use of eval() detected",
                "line_number": 88,
                "line_range": [88, 89],
                "test_id": "B307",
                "test_name": "eval"
            }
        ]
    })


@pytest.fixture
def trufflehog_jsonl_output() -> str:
    """Sample TruffleHog JSON lines output for parser testing."""
    import json
    lines = [
        json.dumps({
            "SourceMetadata": {
                "Data": {
                    "Filesystem": {
                        "file": "config/secrets.py",
                        "line": 15
                    }
                }
            },
            "SourceID": 1,
            "SourceType": 15,
            "SourceName": "trufflehog - filesystem",
            "DetectorType": 1,
            "DetectorName": "AWS",
            "DecoderName": "PLAIN",
            "Verified": True,
            "Raw": "AKIAIOSFODNN7EXAMPLE",
            "Redacted": "AKIAIOSFODNN7***",
            "ExtraData": None
        }),
        json.dumps({
            "SourceMetadata": {
                "Data": {
                    "Filesystem": {
                        "file": ".env",
                        "line": 3
                    }
                }
            },
            "DetectorType": 10,
            "DetectorName": "Slack",
            "Verified": False,
            "Raw": "xoxb-REDACTED-EXAMPLE-TESTTOKEN",
            "Redacted": "xoxb-***-***-***"
        }),
        json.dumps({
            "SourceMetadata": {
                "Data": {
                    "Filesystem": {
                        "file": "keys/id_rsa",
                        "line": 1
                    }
                }
            },
            "DetectorType": 5,
            "DetectorName": "PrivateKey",
            "Verified": False,
            "Raw": "-----BEGIN RSA PRIVATE KEY-----",
            "Redacted": "-----BEGIN RSA PRIVATE KEY-----***"
        })
    ]
    return "\n".join(lines)


@pytest.fixture
def trivy_json_output() -> str:
    """Sample Trivy JSON output for parser testing."""
    import json
    return json.dumps({
        "SchemaVersion": 2,
        "CreatedAt": "2024-01-15T10:00:00Z",
        "ArtifactName": "/path/to/repo",
        "ArtifactType": "filesystem",
        "Results": [
            {
                "Target": "package-lock.json",
                "Class": "lang-pkgs",
                "Type": "npm",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-1234",
                        "PkgID": "lodash@4.17.20",
                        "PkgName": "lodash",
                        "InstalledVersion": "4.17.20",
                        "FixedVersion": "4.17.21",
                        "Status": "fixed",
                        "Title": "Prototype Pollution in lodash",
                        "Description": (
                            "Lodash versions prior to 4.17.21 are vulnerable to "
                            "prototype pollution."
                        ),
                        "Severity": "HIGH",
                        "CweIDs": ["CWE-400"],
                        "References": ["https://nvd.nist.gov/vuln/detail/CVE-2024-1234"],
                        "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-1234",
                        "PublishedDate": "2024-01-01T00:00:00Z"
                    },
                    {
                        "VulnerabilityID": "CVE-2024-5678",
                        "PkgName": "axios",
                        "InstalledVersion": "0.21.0",
                        "FixedVersion": "",
                        "Title": "Server-Side Request Forgery",
                        "Severity": "CRITICAL",
                        "CweIDs": ["CWE-918"]
                    }
                ]
            },
            {
                "Target": "requirements.txt",
                "Class": "lang-pkgs",
                "Type": "pip",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-9999",
                        "PkgName": "flask",
                        "InstalledVersion": "1.0.0",
                        "FixedVersion": "2.0.0",
                        "Title": "Open Redirect in Flask",
                        "Description": "Flask before 2.0.0 is vulnerable to open redirect.",
                        "Severity": "MEDIUM"
                    }
                ]
            }
        ]
    })


@pytest.fixture
def npm_audit_v7_json_output() -> str:
    """Sample npm audit v7+ JSON output for parser testing."""
    import json
    return json.dumps({
        "auditReportVersion": 2,
        "vulnerabilities": {
            "lodash": {
                "name": "lodash",
                "severity": "high",
                "isDirect": False,
                "via": [
                    {
                        "source": 1094475,
                        "name": "lodash",
                        "dependency": "lodash",
                        "title": "Prototype Pollution in lodash",
                        "url": "https://github.com/advisories/GHSA-p6mc-m468-83gw",
                        "severity": "high",
                        "cwe": ["CWE-1321"],
                        "range": "<4.17.21"
                    }
                ],
                "effects": ["grunt"],
                "range": "<4.17.21",
                "nodes": ["node_modules/lodash"],
                "fixAvailable": {
                    "name": "grunt",
                    "version": "1.5.3",
                    "isSemVerMajor": True
                }
            },
            "axios": {
                "name": "axios",
                "severity": "critical",
                "isDirect": True,
                "via": [
                    {
                        "source": 1092461,
                        "name": "axios",
                        "dependency": "axios",
                        "title": "Server-Side Request Forgery in axios",
                        "url": "https://github.com/advisories/GHSA-cph5-m8f7-6c5x",
                        "severity": "critical",
                        "cwe": ["CWE-918"],
                        "range": "<0.21.2"
                    }
                ],
                "effects": [],
                "range": "<0.21.2",
                "nodes": ["node_modules/axios"],
                "fixAvailable": True
            },
            "minimist": {
                "name": "minimist",
                "severity": "moderate",
                "isDirect": False,
                "via": ["prototype pollution"],
                "effects": ["mkdirp"],
                "range": "<1.2.6",
                "fixAvailable": False
            }
        },
        "metadata": {
            "vulnerabilities": {
                "info": 0,
                "low": 0,
                "moderate": 1,
                "high": 1,
                "critical": 1,
                "total": 3
            },
            "dependencies": {
                "prod": 100,
                "dev": 50,
                "optional": 5,
                "peer": 0,
                "peerOptional": 0,
                "total": 155
            }
        }
    })


@pytest.fixture
def pip_audit_json_output() -> str:
    """Sample pip-audit JSON output for parser testing."""
    import json
    return json.dumps({
        "dependencies": [
            {
                "name": "flask",
                "version": "1.0.0",
                "vulns": [
                    {
                        "id": "PYSEC-2023-62",
                        "fix_versions": ["2.2.5", "2.3.2"],
                        "aliases": ["CVE-2023-30861"],
                        "description": (
                            "Flask is a lightweight WSGI web application framework. "
                            "When all of the following conditions are met, a response "
                            "containing data intended for one client may be cached and "
                            "subsequently sent by a proxy to other clients."
                        )
                    }
                ]
            },
            {
                "name": "requests",
                "version": "2.25.0",
                "vulns": [
                    {
                        "id": "PYSEC-2023-74",
                        "fix_versions": ["2.31.0"],
                        "aliases": ["CVE-2023-32681"],
                        "description": (
                            "Requests is a HTTP library. Since Requests 2.3.0, "
                            "Requests has been leaking Proxy-Authorization headers "
                            "to destination servers when redirected to an HTTPS endpoint."
                        )
                    }
                ]
            },
            {
                "name": "urllib3",
                "version": "1.26.0",
                "vulns": []
            },
            {
                "name": "cryptography",
                "version": "3.4.0",
                "vulns": [
                    {
                        "id": "PYSEC-2023-254",
                        "fix_versions": ["41.0.6"],
                        "aliases": ["CVE-2023-49083"],
                        "description": (
                            "cryptography is a package designed to expose cryptographic "
                            "primitives and recipes to Python developers. Calling `load_pem_pkcs7_certificates` "
                            "or `load_der_pkcs7_certificates` could lead to a NULL-pointer dereference and segfault."
                        )
                    }
                ]
            }
        ]
    })


@pytest.fixture
def cargo_audit_json_output() -> str:
    """Sample cargo-audit JSON output for parser testing."""
    import json
    return json.dumps({
        "database": {
            "advisory-count": 650,
            "last-commit": "2024-01-15T00:00:00Z",
            "last-updated": "2024-01-15T10:00:00Z"
        },
        "lockfile": {
            "dependency-count": 150,
            "path": "/path/to/project/Cargo.lock"
        },
        "settings": {
            "target_arch": None,
            "target_os": None,
            "severity": None,
            "ignore": []
        },
        "vulnerabilities": {
            "list": [
                {
                    "advisory": {
                        "id": "RUSTSEC-2024-0001",
                        "package": "hyper",
                        "title": "Integer overflow in hyper's header parsing",
                        "description": (
                            "A malformed header value could cause an integer overflow "
                            "in hyper's header parsing code, potentially leading to a denial of service."
                        ),
                        "date": "2024-01-10",
                        "aliases": ["CVE-2024-12345"],
                        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                        "categories": ["denial-of-service"],
                        "keywords": ["integer-overflow", "headers"],
                        "references": [],
                        "source": None,
                        "url": "https://rustsec.org/advisories/RUSTSEC-2024-0001"
                    },
                    "versions": {
                        "patched": [">=0.14.28"],
                        "unaffected": ["<0.14.0"]
                    },
                    "package": {
                        "name": "hyper",
                        "version": "0.14.27",
                        "source": "registry+https://github.com/rust-lang/crates.io-index"
                    }
                },
                {
                    "advisory": {
                        "id": "RUSTSEC-2024-0002",
                        "package": "tokio",
                        "title": "Memory corruption in tokio runtime",
                        "description": "A race condition in tokio could lead to memory corruption.",
                        "date": "2024-01-05",
                        "aliases": [],
                        "categories": ["memory-corruption"],
                        "keywords": ["race-condition"]
                    },
                    "versions": {
                        "patched": [">=1.35.1"],
                        "unaffected": []
                    },
                    "package": {
                        "name": "tokio",
                        "version": "1.35.0",
                        "source": "registry+https://github.com/rust-lang/crates.io-index"
                    }
                }
            ],
            "count": 2
        },
        "warnings": {
            "unmaintained": [],
            "unsound": [],
            "yanked": []
        }
    })


@pytest.fixture
def gosec_json_output() -> str:
    """Sample Gosec JSON output for parser testing."""
    import json
    return json.dumps({
        "Issues": [
            {
                "severity": "HIGH",
                "confidence": "HIGH",
                "rule_id": "G101",
                "details": "Potential hardcoded credentials",
                "file": "cmd/server.go",
                "line": "15",
                "code": "password := \"admin123\"",
                "cwe": {"id": "798"}
            },
            {
                "severity": "MEDIUM",
                "confidence": "HIGH",
                "rule_id": "G104",
                "details": "Errors unhandled",
                "file": "internal/handler.go",
                "line": "42",
                "code": "f, _ := os.Open(path)",
                "cwe": {"id": "703"}
            },
            {
                "severity": "LOW",
                "confidence": "MEDIUM",
                "rule_id": "G304",
                "details": "File inclusion via variable",
                "file": "pkg/util.go",
                "line": "88",
                "code": "data, err := os.ReadFile(userPath)"
            }
        ],
        "Stats": {
            "files": 10,
            "lines": 500,
            "nosec": 1,
            "found": 3
        }
    })


@pytest.fixture
def grype_json_output() -> str:
    """Sample Grype JSON output for parser testing."""
    import json
    return json.dumps({
        "matches": [
            {
                "vulnerability": {
                    "id": "CVE-2024-1234",
                    "severity": "Critical",
                    "description": "Remote code execution in example-lib",
                    "fix": {"versions": ["2.0.1"]}
                },
                "artifact": {
                    "name": "example-lib",
                    "version": "1.5.0"
                },
                "matchDetails": [{"type": "exact-direct-match"}]
            },
            {
                "vulnerability": {
                    "id": "CVE-2024-5678",
                    "severity": "High",
                    "description": "SQL injection vulnerability",
                    "fix": {"versions": ["3.2.0", "3.1.5"]}
                },
                "artifact": {
                    "name": "db-connector",
                    "version": "3.0.0"
                },
                "matchDetails": []
            },
            {
                "vulnerability": {
                    "id": "CVE-2024-9999",
                    "severity": "Negligible",
                    "description": "Minor information disclosure"
                },
                "artifact": {
                    "name": "logging-util",
                    "version": "0.9.0"
                },
                "matchDetails": []
            }
        ],
        "source": {
            "type": "directory",
            "target": "/path/to/project"
        }
    })


@pytest.fixture
def kube_linter_json_output() -> str:
    """Sample kube-linter JSON output for parser testing."""
    import json
    return json.dumps({
        "Reports": [
            {
                "Check": "run-as-non-root",
                "Diagnostic": {
                    "Message": "Container is not set to runAsNonRoot"
                },
                "Object": {
                    "K8sObject": {
                        "Namespace": "default",
                        "Name": "my-deploy",
                        "GroupVersionKind": {
                            "Group": "apps",
                            "Version": "v1",
                            "Kind": "Deployment"
                        }
                    }
                },
                "Remediation": "Set runAsNonRoot to true in the pod security context"
            },
            {
                "Check": "no-read-only-root-fs",
                "Diagnostic": {
                    "Message": "Container does not have a read-only root filesystem"
                },
                "Object": {
                    "K8sObject": {
                        "Namespace": "default",
                        "Name": "my-deploy",
                        "GroupVersionKind": {
                            "Group": "apps",
                            "Version": "v1",
                            "Kind": "Deployment"
                        }
                    }
                },
                "Remediation": "Set readOnlyRootFilesystem to true"
            },
            {
                "Check": "latest-tag",
                "Diagnostic": {
                    "Message": "Image uses latest tag"
                },
                "Object": {
                    "K8sObject": {
                        "Namespace": "staging",
                        "Name": "web-app",
                        "GroupVersionKind": {
                            "Group": "apps",
                            "Version": "v1",
                            "Kind": "StatefulSet"
                        }
                    }
                },
                "Remediation": "Use a specific image tag instead of latest"
            }
        ]
    })


@pytest.fixture
def bearer_json_output() -> str:
    """Sample Bearer JSON output for parser testing."""
    import json
    return json.dumps([
        {
            "rule_id": "javascript_lang_hardcoded_secret",
            "severity": "critical",
            "description": "Hardcoded secret detected in source code",
            "filename": "src/config.js",
            "line_number": 12,
            "cwe_ids": ["798"],
            "documentation_url": "https://docs.bearer.com/reference/rules/javascript_lang_hardcoded_secret"
        },
        {
            "rule_id": "ruby_lang_sql_injection",
            "severity": "high",
            "description": "SQL injection vulnerability detected",
            "filename": "app/models/user.rb",
            "line_number": 45,
            "cwe_ids": ["89"],
            "documentation_url": "https://docs.bearer.com/reference/rules/ruby_lang_sql_injection"
        },
        {
            "rule_id": "javascript_lang_logger",
            "severity": "warning",
            "description": "Sensitive data logged",
            "filename": "src/utils/auth.js",
            "line_number": 33,
            "cwe_ids": ["532"]
        }
    ])


@pytest.fixture
def horusec_json_output() -> str:
    """Sample Horusec JSON output for parser testing."""
    import json
    return json.dumps({
        "analysisVulnerabilities": [
            {
                "vulnerabilities": {
                    "severity": "HIGH",
                    "vulnHash": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
                    "details": "Potential SQL injection detected",
                    "file": "src/database/query.py",
                    "line": "25",
                    "code": "cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")"
                }
            },
            {
                "vulnerabilities": {
                    "severity": "CRITICAL",
                    "vulnHash": "f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3",
                    "details": "Hardcoded password found",
                    "file": "config/settings.py",
                    "line": "10",
                    "code": "DB_PASSWORD = 'supersecret123'"
                }
            },
            {
                "vulnerabilities": {
                    "severity": "LOW",
                    "vulnHash": "1234567890abcdef1234567890abcdef",
                    "details": "Use of insecure random number generator",
                    "file": "src/utils/token.go",
                    "line": "8",
                    "code": "rand.Intn(100)"
                }
            }
        ]
    })
