"""Tests for passive fingerprinting module.

Uses httpx.MockTransport injected via _transport parameter — fully
isolated, deterministic, no global patching, no network calls.
"""

from __future__ import annotations

import httpx
import pytest

from php2shell_sentinel.core.fingerprint import fingerprint, FingerprintResult
from php2shell_sentinel.core.models import Confidence

BASE = "https://example.com"


# ---------------------------------------------------------------------------
# Transport factory
# ---------------------------------------------------------------------------

RouteMap = dict[tuple[str, str], httpx.Response | Exception]


def _make_transport(
    routes: RouteMap,
    default: httpx.Response | None = None,
) -> httpx.MockTransport:
    """
    Return an httpx.MockTransport whose handler resolves requests by
    (METHOD, url) against *routes*.

    If a route value is an Exception subclass instance it is raised.
    Unmatched requests return *default* (404 empty) or raise KeyError.
    """
    _default = default if default is not None else httpx.Response(404, text="")

    def _handler(request: httpx.Request) -> httpx.Response:
        key = (request.method, str(request.url))
        result = routes.get(key)
        if result is None:
            return _default
        if isinstance(result, Exception):
            raise result
        return result

    return httpx.MockTransport(_handler)


# ---------------------------------------------------------------------------
# Header correlation
# ---------------------------------------------------------------------------

class TestFingerprintHeaders:
    def test_version_from_x_powered_by(self):
        t = _make_transport({
            ("HEAD", f"{BASE}/"): httpx.Response(
                200, headers={"X-Powered-By": "PHP/8.4.26"}
            ),
        })
        result = fingerprint(BASE + "/", _transport=t)

        assert result.php_detected is True
        assert result.version_hint is not None
        assert result.version_hint.patch == 26
        assert result.confidence in (Confidence.MEDIUM, Confidence.HIGH)

    def test_phpsessid_in_head_response(self):
        t = _make_transport({
            ("HEAD", f"{BASE}/"): httpx.Response(
                200, headers={"Set-Cookie": "PHPSESSID=abc123; path=/"}
            ),
        })
        result = fingerprint(BASE + "/", _transport=t)

        assert result.php_detected is True
        assert any("PHPSESSID" in e for e in result.evidence)

    def test_no_php_signals_returns_low_confidence(self):
        t = _make_transport({
            ("HEAD", f"{BASE}/"): httpx.Response(200, headers={"Server": "nginx/1.24"}),
        })
        result = fingerprint(BASE + "/", _transport=t)

        assert result.php_detected is False
        assert result.confidence == Confidence.LOW

    def test_php_version_in_server_header(self):
        t = _make_transport({
            ("HEAD", f"{BASE}/"): httpx.Response(
                200, headers={"Server": "Apache/2.4.58 PHP/8.3.35"}
            ),
        })
        result = fingerprint(BASE + "/", _transport=t)

        assert result.php_detected is True
        assert result.version_hint is not None
        assert result.version_hint.branch == "8.3"

    def test_x_php_version_header(self):
        t = _make_transport({
            ("HEAD", f"{BASE}/"): httpx.Response(
                200, headers={"X-PHP-Version": "8.2.34"}
            ),
        })
        result = fingerprint(BASE + "/", _transport=t)

        assert result.php_detected is True
        assert result.version_hint is not None
        assert result.version_hint.patch == 34


# ---------------------------------------------------------------------------
# Error-page probe
# ---------------------------------------------------------------------------

class TestFingerprintErrorPage:
    def test_php_fatal_error_in_body(self):
        t = _make_transport({
            ("HEAD", f"{BASE}/"): httpx.Response(200, headers={"Server": "Apache"}),
            ("GET", f"{BASE}/__php2shell_sentinel_probe__.php"): httpx.Response(
                500,
                text="<b>Fatal error</b>: Uncaught Error in /var/www/html/index.php on line 1",
            ),
        })
        result = fingerprint(BASE + "/", _transport=t)

        assert result.php_detected is True
        assert any("Fatal error" in e or "error-page" in e.lower() for e in result.evidence)

    def test_version_extracted_from_error_body(self):
        t = _make_transport({
            ("HEAD", f"{BASE}/"): httpx.Response(200, headers={"Server": "Apache"}),
            ("GET", f"{BASE}/__php2shell_sentinel_probe__.php"): httpx.Response(
                500,
                text="PHP 8.4.26 Fatal error: something wrong on line 1",
            ),
        })
        result = fingerprint(BASE + "/", _transport=t)

        assert result.version_hint is not None
        assert result.version_hint.patch == 26

    def test_clean_404_no_php_evidence(self):
        t = _make_transport({
            ("HEAD", f"{BASE}/"): httpx.Response(200, headers={"Server": "nginx"}),
            ("GET", f"{BASE}/__php2shell_sentinel_probe__.php"): httpx.Response(
                404, text="<html><body>Not Found</body></html>"
            ),
        })
        result = fingerprint(BASE + "/", _transport=t)
        assert result.php_detected is False

    def test_stack_trace_pattern_detected(self):
        t = _make_transport({
            ("HEAD", f"{BASE}/"): httpx.Response(200, headers={"Server": "Apache"}),
            ("GET", f"{BASE}/__php2shell_sentinel_probe__.php"): httpx.Response(
                500,
                text="Stack trace:\n#0 /var/www/html/index.php(12): doSomething()\n",
            ),
        })
        result = fingerprint(BASE + "/", _transport=t)
        assert result.php_detected is True


# ---------------------------------------------------------------------------
# Resilience / error handling
# ---------------------------------------------------------------------------

class TestFingerprintResilience:
    def test_connection_refused_returns_safe_result(self):
        t = _make_transport(
            {},
            default=None,  # will raise on every request
        )
        # Override with error-raising handler
        def _refusing(req: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("connection refused")

        t2 = httpx.MockTransport(_refusing)
        result = fingerprint(BASE + "/", _transport=t2)

        assert isinstance(result, FingerprintResult)
        assert result.php_detected is False
        assert len(result.warnings) > 0

    def test_timeout_returns_safe_result(self):
        def _timing_out(req: httpx.Request) -> httpx.Response:
            raise httpx.TimeoutException("timeout", request=req)

        t = httpx.MockTransport(_timing_out)
        result = fingerprint(BASE + "/", _transport=t)

        assert isinstance(result, FingerprintResult)
        assert result.php_detected is False

    def test_techniques_recorded(self):
        t = _make_transport({
            ("HEAD", f"{BASE}/"): httpx.Response(
                200, headers={"X-Powered-By": "PHP/8.4.26"}
            ),
        })
        result = fingerprint(BASE + "/", _transport=t)
        assert "header-correlation" in result.techniques_used


# ---------------------------------------------------------------------------
# Dataclass contract
# ---------------------------------------------------------------------------

class TestFingerprintResultContract:
    def test_default_values(self):
        r = FingerprintResult(target="test")
        assert r.php_detected is False
        assert r.version_hint is None
        assert r.confidence == Confidence.LOW
        assert r.evidence == []
        assert r.techniques_used == []
        assert r.warnings == []

    def test_target_stored(self):
        r = FingerprintResult(target="https://example.com/")
        assert r.target == "https://example.com/"
