from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch
import pytest

from utils.domain_age import (
    extract_root_domain,
    parse_date_string,
    categorize_age,
    get_domain_age_risk_score,
    format_domain_age_summary,
    check_with_whois_lib,
    check_with_rdap_fallback,
    check_domain_age,
)


class TestExtractRootDomain:
    def test_strip_www(self):
        assert extract_root_domain("www.example.com") == "example.com"

    def test_simple_domain(self):
        assert extract_root_domain("example.com") == "example.com"

    def test_subdomains(self):
        assert extract_root_domain("deep.sub.example.com") == "example.com"

    def test_compound_tlds(self):
        assert extract_root_domain("portal.bbc.co.uk") == "bbc.co.uk"
        assert extract_root_domain("bank.commbank.com.au") == "commbank.com.au"
        assert extract_root_domain("www.service.co.in") == "service.co.in"

    def test_single_label(self):
        assert extract_root_domain("localhost") == "localhost"


class TestParseDateString:
    def test_datetime_passthrough(self):
        dt = datetime(2025, 5, 1, 12, 0, 0)
        assert parse_date_string(dt) == dt

    def test_iso_with_z(self):
        parsed = parse_date_string("2024-05-15T10:30:00Z")
        assert parsed == datetime(2024, 5, 15, 10, 30, 0)

    def test_iso_without_z(self):
        parsed = parse_date_string("2024-05-15T10:30:00")
        assert parsed == datetime(2024, 5, 15, 10, 30, 0)

    def test_date_only(self):
        parsed = parse_date_string("2024-05-15")
        assert parsed == datetime(2024, 5, 15, 0, 0, 0)

    def test_invalid_date(self):
        assert parse_date_string("invalid-date-string") is None


class TestCategorizeAge:
    def test_categories(self):
        assert categorize_age(5) == "very_new"
        assert categorize_age(29) == "very_new"
        assert categorize_age(30) == "new"
        assert categorize_age(89) == "new"
        assert categorize_age(90) == "young"
        assert categorize_age(364) == "young"
        assert categorize_age(365) == "established"
        assert categorize_age(729) == "established"
        assert categorize_age(730) == "mature"
        assert categorize_age(2000) == "mature"


class TestGetDomainAgeRiskScore:
    @patch("utils.domain_age.check_domain_age")
    def test_unchecked_or_no_age(self, mock_check):
        mock_check.return_value = {"checked": False, "age_days": None, "details": ["Lookup failed"]}
        score, evidence = get_domain_age_risk_score("example.com")
        assert score == 0.0
        assert evidence == ["Lookup failed"]

    @patch("utils.domain_age.check_domain_age")
    def test_very_recent_domain(self, mock_check):
        mock_check.return_value = {"checked": True, "age_days": 3, "details": ["New domain"]}
        score, _ = get_domain_age_risk_score("brand-new.com")
        assert score == 0.20

    @patch("utils.domain_age.check_domain_age")
    def test_less_than_month(self, mock_check):
        mock_check.return_value = {"checked": True, "age_days": 20, "details": []}
        score, _ = get_domain_age_risk_score("recent.com")
        assert score == 0.15

    @patch("utils.domain_age.check_domain_age")
    def test_less_than_90_days(self, mock_check):
        mock_check.return_value = {"checked": True, "age_days": 60, "details": []}
        score, _ = get_domain_age_risk_score("young.com")
        assert score == 0.10

    @patch("utils.domain_age.check_domain_age")
    def test_less_than_180_days(self, mock_check):
        mock_check.return_value = {"checked": True, "age_days": 120, "details": []}
        score, _ = get_domain_age_risk_score("semi-young.com")
        assert score == 0.05

    @patch("utils.domain_age.check_domain_age")
    def test_less_than_year(self, mock_check):
        mock_check.return_value = {"checked": True, "age_days": 300, "details": []}
        score, _ = get_domain_age_risk_score("under-year.com")
        assert score == 0.02

    @patch("utils.domain_age.check_domain_age")
    def test_established_domain(self, mock_check):
        mock_check.return_value = {"checked": True, "age_days": 1500, "details": []}
        score, _ = get_domain_age_risk_score("old.com")
        assert score == 0.0


class TestFormatDomainAgeSummary:
    def test_not_checked(self):
        assert format_domain_age_summary({"checked": False}) == "Domain age: Check unavailable"

    def test_age_unknown(self):
        assert format_domain_age_summary({"checked": True, "age_days": None}) == "Domain age: Unknown"

    def test_very_new_display(self):
        assert "VERY NEW" in format_domain_age_summary({"checked": True, "age_days": 12})

    def test_new_display(self):
        assert "New" in format_domain_age_summary({"checked": True, "age_days": 50})

    def test_young_display(self):
        summary = format_domain_age_summary({"checked": True, "age_days": 200})
        assert "Domain Age: 200 days" in summary

    def test_mature_display(self):
        summary = format_domain_age_summary({"checked": True, "age_days": 800})
        assert "✓ Domain Age: 2+ years" in summary


class TestCheckDomainAge:
    def test_empty_hostname(self):
        result = check_domain_age("")
        assert result["checked"] is False
        assert result["domain"] == ""

    @patch("whois.whois")
    def test_check_with_whois_lib_success(self, mock_whois):
        creation = datetime.now() - timedelta(days=500)
        mock_w = MagicMock()
        mock_w.creation_date = creation
        mock_w.registrar = "GoDaddy.com, LLC"
        mock_whois.return_value = mock_w

        base_result = {"checked": False, "domain": "example.com", "details": []}
        result = check_with_whois_lib("example.com", base_result)
        assert result["checked"] is True
        assert result["age_days"] == 500
        assert result["age_category"] == "established"
        assert result["registrar"] == "GoDaddy.com, LLC"

    @patch("whois.whois")
    def test_check_with_whois_lib_list_creation_date(self, mock_whois):
        creation = datetime.now() - timedelta(days=20)
        mock_w = MagicMock()
        mock_w.creation_date = [creation, datetime(2020, 1, 1)]
        mock_w.registrar = "Namecheap"
        mock_whois.return_value = mock_w

        base_result = {"checked": False, "domain": "example.com", "details": []}
        result = check_with_whois_lib("example.com", base_result)
        assert result["checked"] is True
        assert result["age_days"] == 20
        assert result["warning"] == "very_new"

    @patch("whois.whois", side_effect=Exception("WHOIS server down"))
    def test_check_with_whois_lib_error(self, mock_whois):
        base_result = {"checked": False, "domain": "example.com", "details": []}
        result = check_with_whois_lib("example.com", base_result)
        assert result["checked"] is False
        assert "WHOIS lookup failed" in result["details"]

    @patch("requests.get")
    def test_check_with_rdap_fallback_success(self, mock_get):
        creation = (datetime.now() - timedelta(days=60)).strftime("%Y-%m-%dT%H:%M:%SZ")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "events": [
                {"eventAction": "registration", "eventDate": creation}
            ],
            "entities": [
                {"roles": ["registrar"], "handle": "REG-123"}
            ]
        }
        mock_get.return_value = mock_resp

        base_result = {"checked": False, "domain": "example.com", "details": []}
        result = check_with_rdap_fallback("example.com", base_result)
        assert result["checked"] is True
        assert result["age_days"] == 60
        assert result["warning"] == "new"
        assert result["registrar"] == "REG-123"

    @patch("requests.get")
    def test_check_with_rdap_fallback_non_200(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_get.return_value = mock_resp

        base_result = {"checked": False, "domain": "example.com", "details": []}
        result = check_with_rdap_fallback("example.com", base_result)
        assert result["checked"] is False
        assert "Domain age check unavailable" in result["details"]

