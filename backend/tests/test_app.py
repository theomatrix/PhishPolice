import json
from unittest.mock import MagicMock, patch
import pytest

from app import (
    app,
    validate_url,
    validate_request_data,
    calculate_risk_score,
    determine_verdict,
    build_evidence_list,
    MAX_URL_LENGTH,
    MAX_IMAGE_SIZE,
    MAX_FORMS,
)


@pytest.fixture(autouse=True)
def disable_rate_limiting():
    """Ensure limiter doesn't block test runs."""
    app.config["RATELIMIT_ENABLED"] = False
    yield
    app.config["RATELIMIT_ENABLED"] = True


class TestValidateURL:
    def test_missing_or_invalid_type(self):
        assert validate_url(None) == (False, "Missing or invalid URL")
        assert validate_url(12345) == (False, "Missing or invalid URL")
        assert validate_url("") == (False, "Missing or invalid URL")

    def test_url_too_long(self):
        long_url = "https://example.com/" + ("a" * MAX_URL_LENGTH)
        assert validate_url(long_url) == (False, "URL too long")

    def test_invalid_scheme(self):
        assert validate_url("ftp://example.com") == (False, "Invalid URL scheme")
        assert validate_url("javascript:alert(1)") == (False, "Invalid URL scheme")

    def test_missing_netloc(self):
        assert validate_url("http://") == (False, "Invalid URL format")

    def test_valid_http_and_https(self):
        assert validate_url("http://example.com") == (True, None)
        assert validate_url("https://secure.example.com/login?param=1") == (True, None)


class TestValidateRequestData:
    def test_valid_payload(self):
        data = {
            "url": "https://example.com",
            "image_b64": "data",
            "forms": [{"hasPassword": True}],
        }
        assert validate_request_data(data) == []

    def test_invalid_url(self):
        data = {"url": "invalid-url"}
        errors = validate_request_data(data)
        assert "Invalid URL scheme" in errors

    def test_image_too_large(self):
        data = {
            "url": "https://example.com",
            "image_b64": "A" * (MAX_IMAGE_SIZE + 10),
            "forms": [],
        }
        errors = validate_request_data(data)
        assert "Image too large" in errors

    def test_forms_not_a_list(self):
        data = {
            "url": "https://example.com",
            "forms": "not-a-list",
        }
        errors = validate_request_data(data)
        assert "Forms must be a list" in errors

    def test_too_many_forms(self):
        data = {
            "url": "https://example.com",
            "forms": [{}] * (MAX_FORMS + 1),
        }
        errors = validate_request_data(data)
        assert "Too many forms" in errors


class TestRiskScoreAndVerdict:
    def test_determine_verdict(self):
        assert determine_verdict(0.9) == "phish"
        assert determine_verdict(0.55) == "phish"
        assert determine_verdict(0.54) == "suspicious"
        assert determine_verdict(0.25) == "suspicious"
        assert determine_verdict(0.24) == "safe"
        assert determine_verdict(0.0) == "safe"

    def test_calculate_risk_score_low_risk(self):
        ssl_info = {"security_score": 90, "has_ssl": True, "is_valid": True}
        domain_info = {"is_ip_address": False, "has_suspicious_tld": False, "has_many_subdomains": False}
        forms = []
        suspicious_patterns = []
        dom_analysis = {"hidden_iframes": 0, "external_links_ratio": 0.1}
        visual_info = {"analyzed": True}

        score = calculate_risk_score(
            ssl_info, domain_info, forms, suspicious_patterns, dom_analysis, visual_info
        )
        assert score == 0.0

    def test_calculate_risk_score_high_risk_accumulation(self):
        ssl_info = {
            "security_score": 20,
            "is_self_signed": True,
            "has_ssl": True,
            "is_valid": False,
            "is_expired": True,
        }
        domain_info = {
            "is_ip_address": True,
            "has_suspicious_tld": True,
            "has_many_subdomains": True,
        }
        forms = [
            {"hasPassword": True, "submitsToDifferentDomain": True},
            {"hasPassword": True},
        ]
        suspicious_patterns = ["urgency_notice", "urgency_countdown"]
        dom_analysis = {"hidden_iframes": 2, "external_links_ratio": 0.9}
        visual_info = {}

        score = calculate_risk_score(
            ssl_info, domain_info, forms, suspicious_patterns, dom_analysis, visual_info,
            typosquat_risk=0.35, ct_risk=0.10, visual_risk=0.25, domain_age_risk=0.20
        )
        # Check capping at 0.99
        assert score <= 0.99
        assert score > 0.80


class TestBuildEvidenceList:
    def test_evidence_collection(self):
        ssl_info = {"is_valid": False, "has_ssl": True}
        ssl_summary = "❌ Invalid SSL certificate"
        domain_info = {
            "has_suspicious_subdomain": True,
            "subdomain": "login-verify",
            "has_suspicious_tld": True,
            "suffix": "xyz",
            "is_ip_address": True,
        }
        forms = [
            {"hasPassword": True, "submitsToDifferentDomain": True}
        ]
        suspicious_patterns = []
        dom_analysis = {"hidden_iframes": 1}
        typosquat_result = {
            "is_typosquat": True,
            "suspected_brand": "paypal",
            "similarity_score": 95,
        }
        ct_result = {"checked": True, "warning": "no_certs_found", "details": []}
        visual_info = {
            "analyzed": True,
            "detected_brand": "PayPal",
            "brand_match_confidence": 95,
            "has_urgency_elements": True,
            "is_login_page": True,
            "findings": ["Stolen logo"],
        }
        domain_age_result = {"age_days": 10}

        evidence = build_evidence_list(
            ssl_info, ssl_summary, domain_info, forms, suspicious_patterns, dom_analysis,
            typosquat_result, ct_result, visual_info, domain_age_result
        )

        assert any("TYPOSQUAT" in e for e in evidence)
        assert any("NEW DOMAIN: Registered only 10 days ago" in e for e in evidence)
        assert any("Visual: Detected PayPal branding" in e for e in evidence)
        assert any("Login page detected" in e for e in evidence)
        assert any("Invalid SSL certificate" in e for e in evidence)
        assert any("Suspicious subdomain" in e for e in evidence)
        assert any("High-risk TLD" in e for e in evidence)
        assert any("Uses IP address" in e for e in evidence)
        assert any("form(s) collecting passwords" in e for e in evidence)
        assert any("Hidden iframes detected" in e for e in evidence)

    def test_evidence_clean_safe_domain(self):
        ssl_info = {"is_valid": True, "has_ssl": True}
        ssl_summary = "✅ Valid SSL"
        domain_info = {"has_suspicious_subdomain": False, "has_suspicious_tld": False, "is_ip_address": False}
        forms = []
        suspicious_patterns = []
        dom_analysis = {"hidden_iframes": 0}
        typosquat_result = {"is_typosquat": False}
        ct_result = {"checked": True, "warning": None, "recent_certs_count": 5}
        visual_info = {"analyzed": True, "detected_brand": None}
        domain_age_result = {"age_days": 800}

        evidence = build_evidence_list(
            ssl_info, ssl_summary, domain_info, forms, suspicious_patterns, dom_analysis,
            typosquat_result, ct_result, visual_info, domain_age_result
        )

        assert any("No brand impersonation detected" in e for e in evidence)
        assert any("Established domain: 2+ years old" in e for e in evidence)


class TestAppEndpoints:
    def test_health_check(self, client):
        response = client.get("/api/health")
        assert response.status_code == 200
        data = response.get_json()
        assert data["status"] == "healthy"
        assert data["version"] == "2.2.0"
        assert data["name"] == "PhishPolice"
        assert "features" in data
        assert "ssl_check" in data["features"]

    def test_analyze_no_body(self, client):
        response = client.post("/api/analyze", content_type="application/json")
        assert response.status_code == 400
        data = response.get_json()
        assert "error" in data

    def test_analyze_invalid_json(self, client):
        response = client.post("/api/analyze", data="not a json", content_type="application/json")
        assert response.status_code == 400
        data = response.get_json()
        assert "Invalid JSON payload" in data["error"]

    def test_analyze_validation_failure(self, client):
        response = client.post(
            "/api/analyze",
            data=json.dumps({"url": "invalid-url-format"}),
            content_type="application/json",
        )
        assert response.status_code == 400
        data = response.get_json()
        assert data["error"] == "Validation failed"
        assert len(data["details"]) > 0

    @patch("app.detect_typosquatting")
    @patch("app.get_typosquat_risk_score")
    @patch("app.get_ssl_certificate_info")
    @patch("app.format_ssl_summary")
    @patch("app.check_certificate_transparency")
    @patch("app.get_ct_risk_score")
    @patch("app.quick_domain_checks")
    @patch("app.check_domain_age")
    @patch("app.get_domain_age_risk_score")
    @patch("app.analyze_visual")
    @patch("app.get_visual_risk_score")
    @patch("app.analyze_with_llm")
    def test_analyze_successful_flow(
        self,
        mock_llm,
        mock_visual_score,
        mock_visual,
        mock_domain_age_score,
        mock_domain_age,
        mock_domain_checks,
        mock_ct_score,
        mock_ct,
        mock_ssl_summary,
        mock_ssl_info,
        mock_typosquat_score,
        mock_typosquat,
        client,
    ):
        mock_typosquat.return_value = {"is_typosquat": False}
        mock_typosquat_score.return_value = (0.0, [])
        mock_ssl_info.return_value = {
            "has_ssl": True,
            "is_valid": True,
            "issuer": "DigiCert",
            "expires_in_days": 180,
            "security_score": 90,
        }
        mock_ssl_summary.return_value = "✅ Valid SSL"
        mock_ct.return_value = {"checked": True, "recent_certs_count": 2, "warning": None}
        mock_ct_score.return_value = (0.0, [])
        mock_domain_checks.return_value = {"full_domain": "example.com"}
        mock_domain_age.return_value = {"age_days": 1000, "age_category": "mature"}
        mock_domain_age_score.return_value = (0.0, [])
        mock_visual.return_value = {"analyzed": False}
        mock_visual_score.return_value = (0.0, [])
        mock_llm.return_value = {
            "summary": "Legitimate site",
            "risk_factors": [],
            "recommendation": "Safe to use",
        }

        payload = {
            "url": "https://example.com",
            "hostname": "example.com",
            "forms": [],
            "image_b64": "",
            "suspiciousPatterns": [],
            "dom_signature": "",
            "externalLinks": {"external": 0, "total": 10},
        }

        response = client.post(
            "/api/analyze",
            data=json.dumps(payload),
            content_type="application/json",
        )
        assert response.status_code == 200
        data = response.get_json()
        assert data["verdict"] == "safe"
        assert "score" in data
        assert "evidence" in data
        assert "ssl_info" in data
        assert "domain_info" in data
        assert "ct_info" in data
        assert "visual_info" in data
        assert "llm_analysis" in data
        assert data["domain_info"]["age_category"] == "mature"
