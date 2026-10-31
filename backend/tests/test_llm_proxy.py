import os
from unittest.mock import MagicMock, patch
import pytest
import requests

from utils.llm_proxy import (
    load_env,
    build_analysis_prompt,
    parse_llm_response,
    analyze_with_llm,
    summarize_with_llm,
)


class TestBuildAnalysisPrompt:
    def test_prompt_includes_details(self):
        url = "https://secure-login.bank-update.xyz/login"
        hostname = "secure-login.bank-update.xyz"
        ssl_info = {
            "is_valid": True,
            "issuer": "Let's Encrypt",
            "expires_in_days": 45,
            "is_self_signed": False,
        }
        domain_info = {
            "domain": "bank-update",
            "suffix": "xyz",
            "subdomain": "secure-login",
            "is_ip_address": False,
            "has_suspicious_subdomain": True,
            "has_suspicious_tld": True,
            "has_many_subdomains": False,
        }
        forms = [
            {"hasPassword": True, "hasEmail": True, "submitsToDifferentDomain": True}
        ]
        suspicious_patterns = ["urgent_account_lock"]
        dom_analysis = {
            "hidden_iframes": 1,
            "external_links_ratio": 0.85,
        }

        prompt = build_analysis_prompt(
            url, hostname, ssl_info, domain_info, forms, suspicious_patterns, dom_analysis
        )
        assert url in prompt
        assert hostname in prompt
        assert "Let's Encrypt" in prompt
        assert "Suspicious subdomain: secure-login" in prompt
        assert "Suspicious TLD: .xyz" in prompt
        assert "Password input forms: 1" in prompt
        assert "Email input forms: 1" in prompt
        assert "Forms submitting to external domains: 1" in prompt
        assert "1 hidden iframes detected" in prompt
        assert "High ratio of external links" in prompt


class TestParseLLMResponse:
    def test_standard_response(self):
        text = (
            "SUMMARY: Phishing site impersonating PayPal.\n"
            "RISK_FACTORS: Credential harvesting, Suspicious TLD, External form submission\n"
            "RECOMMENDATION: Do not enter any credentials and close the tab immediately."
        )
        parsed = parse_llm_response(text)
        assert parsed["summary"] == "Phishing site impersonating PayPal."
        assert parsed["risk_factors"] == [
            "Credential harvesting",
            "Suspicious TLD",
            "External form submission",
        ]
        assert parsed["recommendation"] == "Do not enter any credentials and close the tab immediately."

    def test_none_identified_risk_factors(self):
        text = (
            "SUMMARY: Legitimate banking portal.\n"
            "RISK_FACTORS: None identified\n"
            "RECOMMENDATION: Safe to proceed."
        )
        parsed = parse_llm_response(text)
        assert parsed["summary"] == "Legitimate banking portal."
        assert parsed["risk_factors"] == []
        assert parsed["recommendation"] == "Safe to proceed."

    def test_missing_summary_prefix_fallback(self):
        text = "This is an unstructured security summary from the LLM model."
        parsed = parse_llm_response(text)
        assert parsed["summary"].startswith("This is an unstructured")
        assert parsed["risk_factors"] == []


class TestAnalyzeWithLLM:
    def test_analysis_disabled(self):
        with patch("utils.llm_proxy.ENABLE_AI_ANALYSIS", False):
            result = analyze_with_llm("https://example.com", "example.com", {}, {}, [])
            assert "AI analysis disabled" in result["summary"]

    def test_missing_api_key(self):
        with patch("utils.llm_proxy.ENABLE_AI_ANALYSIS", True), \
             patch("utils.llm_proxy.NVIDIA_API_KEY", ""), \
             patch.dict(os.environ, {"NVIDIA_API_KEY": ""}):
            result = analyze_with_llm("https://example.com", "example.com", {}, {}, [])
            assert "AI analysis unavailable" in result["summary"]

    @patch("requests.post")
    def test_successful_ai_response(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "choices": [{
                "message": {
                    "content": (
                        "SUMMARY: High risk phishing site detected.\n"
                        "RISK_FACTORS: Fake login, New domain\n"
                        "RECOMMENDATION: Avoid this site."
                    )
                }
            }]
        }
        mock_post.return_value = mock_resp

        with patch("utils.llm_proxy.ENABLE_AI_ANALYSIS", True), \
             patch("utils.llm_proxy.NVIDIA_API_KEY", "test-key"):
            result = analyze_with_llm("https://evil.com", "evil.com", {}, {}, [])
            assert result["summary"] == "High risk phishing site detected."
            assert result["risk_factors"] == ["Fake login", "New domain"]
            assert result["recommendation"] == "Avoid this site."

    @patch("requests.post")
    def test_rate_limit_429(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 429
        mock_post.return_value = mock_resp

        with patch("utils.llm_proxy.ENABLE_AI_ANALYSIS", True), \
             patch("utils.llm_proxy.NVIDIA_API_KEY", "test-key"):
            result = analyze_with_llm("https://example.com", "example.com", {}, {}, [])
            assert "AI rate limit reached" in result["summary"]

    @patch("requests.post")
    def test_auth_failure_401(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_post.return_value = mock_resp

        with patch("utils.llm_proxy.ENABLE_AI_ANALYSIS", True), \
             patch("utils.llm_proxy.NVIDIA_API_KEY", "test-key"):
            result = analyze_with_llm("https://example.com", "example.com", {}, {}, [])
            assert "AI authentication failed" in result["summary"]

    @patch("requests.post")
    def test_http_500_error(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_post.return_value = mock_resp

        with patch("utils.llm_proxy.ENABLE_AI_ANALYSIS", True), \
             patch("utils.llm_proxy.NVIDIA_API_KEY", "test-key"):
            result = analyze_with_llm("https://example.com", "example.com", {}, {}, [])
            assert "AI unavailable (HTTP 500)" in result["summary"]

    @patch("requests.post")
    def test_empty_choices(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"choices": []}
        mock_post.return_value = mock_resp

        with patch("utils.llm_proxy.ENABLE_AI_ANALYSIS", True), \
             patch("utils.llm_proxy.NVIDIA_API_KEY", "test-key"):
            result = analyze_with_llm("https://example.com", "example.com", {}, {}, [])
            assert "AI returned no response" in result["summary"]

    @patch("requests.post", side_effect=requests.Timeout)
    def test_timeout_handling(self, mock_post):
        with patch("utils.llm_proxy.ENABLE_AI_ANALYSIS", True), \
             patch("utils.llm_proxy.NVIDIA_API_KEY", "test-key"):
            result = analyze_with_llm("https://example.com", "example.com", {}, {}, [])
            assert "AI analysis timed out" in result["summary"]

    @patch("requests.post", side_effect=requests.ConnectionError)
    def test_connection_error(self, mock_post):
        with patch("utils.llm_proxy.ENABLE_AI_ANALYSIS", True), \
             patch("utils.llm_proxy.NVIDIA_API_KEY", "test-key"):
            result = analyze_with_llm("https://example.com", "example.com", {}, {}, [])
            assert "AI service unreachable" in result["summary"]

    @patch("requests.post", side_effect=requests.RequestException)
    def test_request_exception(self, mock_post):
        with patch("utils.llm_proxy.ENABLE_AI_ANALYSIS", True), \
             patch("utils.llm_proxy.NVIDIA_API_KEY", "test-key"):
            result = analyze_with_llm("https://example.com", "example.com", {}, {}, [])
            assert "AI request failed" in result["summary"]


class TestSummarizeWithLLM:
    @patch("utils.llm_proxy.analyze_with_llm")
    def test_summarize_delegation(self, mock_analyze):
        mock_analyze.return_value = {"summary": "Safe domain summary"}
        res = summarize_with_llm("https://example.com", {}, {}, [])
        assert res == "Safe domain summary"

