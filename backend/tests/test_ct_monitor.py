from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch
import pytest
import requests

from utils.ct_monitor import (
    is_new_domain,
    check_certificate_transparency,
    get_ct_risk_score,
    format_ct_summary,
)


class TestIsNewDomain:
    def test_suspicious_tld_heuristics(self):
        for tld in [".xyz", ".top", ".work", ".click", ".link", ".online", ".site"]:
            assert is_new_domain(f"suspicious-domain{tld}") is True

    def test_trusted_tld_heuristics(self):
        for domain in ["google.com", "github.org", "university.edu", "service.net"]:
            assert is_new_domain(domain) is False


class TestCheckCertificateTransparency:
    def test_empty_hostname(self):
        result = check_certificate_transparency("")
        assert result["checked"] is False
        assert result["recent_certs_count"] == 0

    @patch("requests.get")
    def test_crt_sh_non_200_response(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 503
        mock_get.return_value = mock_resp

        result = check_certificate_transparency("example.com")
        assert result["checked"] is False
        assert "CT log check unavailable" in result["details"]

    @patch("requests.get")
    def test_crt_sh_empty_cert_list(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = []
        mock_get.return_value = mock_resp

        result = check_certificate_transparency("brandnewdomain.com")
        assert result["checked"] is True
        assert result["recent_certs_count"] == 0
        assert result["warning"] == "no_certs_found"

    @patch("requests.get")
    def test_multiple_issuers_warning(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        # More than 3 distinct issuers
        mock_resp.json.return_value = [
            {"issuer_name": "Issuer A", "entry_timestamp": "2024-01-01T00:00:00"},
            {"issuer_name": "Issuer B", "entry_timestamp": "2024-01-01T00:00:00"},
            {"issuer_name": "Issuer C", "entry_timestamp": "2024-01-01T00:00:00"},
            {"issuer_name": "Issuer D", "entry_timestamp": "2024-01-01T00:00:00"},
        ]
        mock_get.return_value = mock_resp

        result = check_certificate_transparency("multica.com")
        assert result["checked"] is True
        assert result["multiple_issuers"] is True
        assert result["warning"] == "many_issuers"

    @patch("requests.get")
    def test_frequent_reissuance_warning(self, mock_get):
        now_iso = datetime.now().isoformat()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        # 6 certs within last 30 days (> 5) with single issuer
        mock_resp.json.return_value = [
            {"issuer_name": "Common CA", "entry_timestamp": now_iso} for _ in range(6)
        ]
        mock_get.return_value = mock_resp

        result = check_certificate_transparency("frequent.com")
        assert result["checked"] is True
        assert result["certs_last_30_days"] == 6
        assert result["warning"] == "frequent_reissuance"

    @patch("requests.get")
    def test_normal_issuance(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [
            {"issuer_name": "Trusted CA", "entry_timestamp": "2024-01-01T00:00:00"},
            {"issuer_name": "Trusted CA", "entry_timestamp": "2024-06-01T00:00:00"},
        ]
        mock_get.return_value = mock_resp

        result = check_certificate_transparency("standard.com")
        assert result["checked"] is True
        assert result["warning"] is None
        assert result["recent_certs_count"] == 2

    @patch("requests.get", side_effect=requests.Timeout)
    def test_timeout_handling(self, mock_get):
        result = check_certificate_transparency("timeout.com")
        assert result["checked"] is False
        assert "CT log check timed out" in result["details"]

    @patch("requests.get", side_effect=requests.RequestException("Network down"))
    def test_network_exception_handling(self, mock_get):
        result = check_certificate_transparency("error.com")
        assert result["checked"] is False
        assert "CT log check failed" in result["details"]


class TestGetCTRiskScore:
    @patch("utils.ct_monitor.check_certificate_transparency")
    def test_no_certs_risk(self, mock_check):
        mock_check.return_value = {
            "checked": True,
            "warning": "no_certs_found",
            "details": ["No certs found"],
        }
        score, evidence = get_ct_risk_score("target.com")
        assert score == 0.10
        assert evidence == ["No certs found"]

    @patch("utils.ct_monitor.check_certificate_transparency")
    def test_many_issuers_risk(self, mock_check):
        mock_check.return_value = {
            "checked": True,
            "warning": "many_issuers",
            "details": ["Many issuers detected"],
        }
        score, evidence = get_ct_risk_score("target.com")
        assert score == 0.08

    @patch("utils.ct_monitor.check_certificate_transparency")
    def test_frequent_reissuance_risk(self, mock_check):
        mock_check.return_value = {
            "checked": True,
            "warning": "frequent_reissuance",
            "details": ["Frequent reissuance"],
        }
        score, evidence = get_ct_risk_score("target.com")
        assert score == 0.05

    @patch("utils.ct_monitor.check_certificate_transparency")
    def test_normal_risk(self, mock_check):
        mock_check.return_value = {
            "checked": True,
            "warning": None,
            "details": ["Normal pattern"],
        }
        score, evidence = get_ct_risk_score("target.com")
        assert score == 0.0


class TestFormatCTSummary:
    def test_unchecked(self):
        assert format_ct_summary({"checked": False}) == "CT log check unavailable"

    def test_no_certs(self):
        summary = format_ct_summary({"checked": True, "warning": "no_certs_found"})
        assert "No certificates found" in summary

    def test_many_issuers(self):
        summary = format_ct_summary({
            "checked": True,
            "warning": "many_issuers",
            "issuers": ["A", "B", "C", "D"],
        })
        assert "Multiple cert issuers (4)" in summary

    def test_frequent_reissuance(self):
        summary = format_ct_summary({
            "checked": True,
            "warning": "frequent_reissuance",
            "certs_last_30_days": 8,
        })
        assert "Frequent cert reissuance (8 in 30 days)" in summary

    def test_normal_summary(self):
        summary = format_ct_summary({
            "checked": True,
            "warning": None,
            "recent_certs_count": 5,
        })
        assert "CT logs: 5 certs found" in summary

