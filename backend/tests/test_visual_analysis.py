import os
from unittest.mock import MagicMock, patch
import pytest
import requests

from utils.visual_analysis import (
    build_vision_prompt,
    parse_vision_response,
    get_visual_risk_score,
    format_visual_summary,
    analyze_visual,
)


class TestBuildVisionPrompt:
    def test_hostname_in_prompt(self):
        prompt = build_vision_prompt("paypal-secure-verify.com")
        assert "paypal-secure-verify.com" in prompt
        assert "Brand Detection" in prompt
        assert "Login Page" in prompt
        assert "Urgency Elements" in prompt


class TestParseVisionResponse:
    def test_full_response_parsing(self):
        response_text = (
            "BRAND: Microsoft\n"
            "CONFIDENCE: 90%\n"
            "IS_LOGIN: Yes\n"
            "HAS_URGENCY: Yes\n"
            "RISK: High\n"
            "FINDINGS: Fake login form, Copied Office 365 logo, Countdown timer\n"
            "SUMMARY: Page mimics Microsoft 365 sign-in with high confidence."
        )
        result = parse_vision_response(response_text)
        assert result["detected_brand"] == "Microsoft"
        assert result["brand_match_confidence"] == 90
        assert result["is_login_page"] is True
        assert result["has_urgency_elements"] is True
        assert result["visual_risk_score"] == 0.4
        assert len(result["findings"]) == 3
        assert "Fake login form" in result["findings"]
        assert "Microsoft 365 sign-in" in result["summary"]

    def test_no_brand_detected(self):
        response_text = (
            "BRAND: None\n"
            "CONFIDENCE: 0%\n"
            "IS_LOGIN: No\n"
            "HAS_URGENCY: No\n"
            "RISK: Low\n"
            "FINDINGS: Generic blog layout\n"
            "SUMMARY: Normal personal blog."
        )
        result = parse_vision_response(response_text)
        assert result["detected_brand"] is None
        assert result["brand_match_confidence"] == 0
        assert result["is_login_page"] is False
        assert result["has_urgency_elements"] is False
        assert result["visual_risk_score"] == 0.1

    def test_risk_levels(self):
        assert parse_vision_response("RISK: low")["visual_risk_score"] == 0.1
        assert parse_vision_response("RISK: medium")["visual_risk_score"] == 0.25
        assert parse_vision_response("RISK: high")["visual_risk_score"] == 0.4
        assert parse_vision_response("RISK: critical")["visual_risk_score"] == 0.6


class TestGetVisualRiskScore:
    def test_not_analyzed(self):
        score, evidence = get_visual_risk_score({"analyzed": False})
        assert score == 0.0
        assert evidence == ["Visual analysis not performed"]

    def test_brand_impersonation_and_login(self):
        info = {
            "analyzed": True,
            "detected_brand": "PayPal",
            "brand_match_confidence": 85,
            "is_login_page": True,
            "has_urgency_elements": True,
            "findings": ["Stolen logo", "Urgent warning"],
        }
        # 0.15 (brand) + 0.05 (login) + 0.08 (urgency) = 0.28 -> capped at 0.25
        score, evidence = get_visual_risk_score(info)
        assert score == 0.25
        assert any("PayPal" in e for e in evidence)
        assert any("Login page" in e for e in evidence)
        assert any("Urgency/fear" in e for e in evidence)

    def test_low_confidence_brand_no_score_boost(self):
        info = {
            "analyzed": True,
            "detected_brand": "Apple",
            "brand_match_confidence": 50,  # <= 70
            "is_login_page": False,
            "has_urgency_elements": False,
            "findings": [],
        }
        score, evidence = get_visual_risk_score(info)
        assert score == 0.0


class TestFormatVisualSummary:
    def test_not_analyzed(self):
        assert format_visual_summary({"analyzed": False}) == "Visual analysis not available"

    def test_detected_brand(self):
        summary = format_visual_summary({
            "analyzed": True,
            "detected_brand": "Google",
            "brand_match_confidence": 95,
        })
        assert "Detected Google branding (95% match)" in summary

    def test_generic_summary(self):
        summary = format_visual_summary({
            "analyzed": True,
            "detected_brand": None,
            "summary": "Clean documentation page",
        })
        assert "Clean documentation page" in summary


class TestAnalyzeVisual:
    def test_short_image_data(self):
        result = analyze_visual("short-data", "example.com")
        assert result["analyzed"] is False
        assert "No screenshot provided" in result["findings"]

    def test_disabled_visual_analysis(self):
        sample_img = "A" * 150
        with patch("utils.visual_analysis.ENABLE_VISUAL_ANALYSIS", False):
            result = analyze_visual(sample_img, "example.com")
            assert result["analyzed"] is False
            assert "Visual analysis disabled" in result["findings"]

    def test_missing_api_key(self):
        sample_img = "A" * 150
        with patch("utils.visual_analysis.ENABLE_VISUAL_ANALYSIS", True), \
             patch("utils.visual_analysis.NVIDIA_API_KEY", ""), \
             patch.dict(os.environ, {"NVIDIA_API_KEY": ""}):
            result = analyze_visual(sample_img, "example.com")
            assert result["analyzed"] is False
            assert "API key not configured" in result["findings"][0]

    @patch("requests.post")
    def test_successful_analysis(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "choices": [{
                "message": {
                    "content": (
                        "BRAND: Amazon\n"
                        "CONFIDENCE: 92%\n"
                        "IS_LOGIN: Yes\n"
                        "HAS_URGENCY: No\n"
                        "RISK: High\n"
                        "FINDINGS: Phishing portal\n"
                        "SUMMARY: Mimics Amazon sign-in."
                    )
                }
            }]
        }
        mock_post.return_value = mock_resp

        sample_img = "A" * 150
        with patch("utils.visual_analysis.ENABLE_VISUAL_ANALYSIS", True), \
             patch("utils.visual_analysis.NVIDIA_API_KEY", "test-key"):
            result = analyze_visual(sample_img, "fake-amazon.xyz")
            assert result["analyzed"] is True
            assert result["detected_brand"] == "Amazon"
            assert result["brand_match_confidence"] == 92
            assert result["is_login_page"] is True

    @patch("requests.post")
    def test_rate_limited_429(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 429
        mock_post.return_value = mock_resp

        sample_img = "A" * 150
        with patch("utils.visual_analysis.ENABLE_VISUAL_ANALYSIS", True), \
             patch("utils.visual_analysis.NVIDIA_API_KEY", "test-key"):
            result = analyze_visual(sample_img, "example.com")
            assert result["analyzed"] is False
            assert "Visual analysis rate limited" in result["findings"]

    @patch("requests.post")
    def test_auth_failed_401(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_post.return_value = mock_resp

        sample_img = "A" * 150
        with patch("utils.visual_analysis.ENABLE_VISUAL_ANALYSIS", True), \
             patch("utils.visual_analysis.NVIDIA_API_KEY", "test-key"):
            result = analyze_visual(sample_img, "example.com")
            assert result["analyzed"] is False
            assert "Visual analysis authentication failed" in result["findings"]

    @patch("requests.post", side_effect=requests.Timeout)
    def test_timeout_handling(self, mock_post):
        sample_img = "A" * 150
        with patch("utils.visual_analysis.ENABLE_VISUAL_ANALYSIS", True), \
             patch("utils.visual_analysis.NVIDIA_API_KEY", "test-key"):
            result = analyze_visual(sample_img, "example.com")
            assert result["analyzed"] is False
            assert "Visual analysis timed out" in result["findings"]

    @patch("requests.post", side_effect=requests.ConnectionError)
    def test_connection_error(self, mock_post):
        sample_img = "A" * 150
        with patch("utils.visual_analysis.ENABLE_VISUAL_ANALYSIS", True), \
             patch("utils.visual_analysis.NVIDIA_API_KEY", "test-key"):
            result = analyze_visual(sample_img, "example.com")
            assert result["analyzed"] is False
            assert "Visual analysis connection failed" in result["findings"]

