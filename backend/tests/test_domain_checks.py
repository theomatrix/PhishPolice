import pytest
from utils.domain_checks import quick_domain_checks, format_domain_summary


class TestQuickDomainChecks:
    def test_standard_legitimate_domain(self):
        result = quick_domain_checks("https://example.com/path")
        assert result["domain"] == "example"
        assert result["suffix"] == "com"
        assert result["full_domain"] == "example.com"
        assert result["subdomain"] == ""
        assert result["is_ip_address"] is False
        assert result["has_suspicious_subdomain"] is False
        assert result["has_many_subdomains"] is False
        assert result["has_suspicious_tld"] is False

    def test_domain_with_subdomain(self):
        result = quick_domain_checks("https://sub.domain.co.uk")
        assert result["domain"] == "domain"
        assert result["subdomain"] == "sub"
        assert result["suffix"] == "co.uk"
        assert result["full_domain"] == "domain.co.uk"
        assert result["is_ip_address"] is False

    def test_ipv4_address_detection(self):
        result = quick_domain_checks("http://192.168.1.100/login")
        assert result["is_ip_address"] is True

    def test_non_ip_with_four_parts(self):
        result = quick_domain_checks("http://a.b.c.example.com")
        assert result["is_ip_address"] is False

    def test_suspicious_subdomain_keywords(self):
        keywords = ["login", "secure", "signin", "account", "verify", "banking", "paypal"]
        for kw in keywords:
            result = quick_domain_checks(f"https://{kw}.attacker-domain.com")
            assert result["has_suspicious_subdomain"] is True, f"Failed for keyword {kw}"

    def test_clean_subdomain_not_flagged(self):
        result = quick_domain_checks("https://blog.company.com")
        assert result["has_suspicious_subdomain"] is False

    def test_many_subdomains(self):
        result = quick_domain_checks("https://a.b.c.target.com")
        assert result["has_many_subdomains"] is True

        normal_result = quick_domain_checks("https://api.v1.target.com")
        assert normal_result["has_many_subdomains"] is False

    def test_suspicious_tlds(self):
        suspicious_tlds = ["xyz", "top", "work", "click", "tk", "ml", "online", "site"]
        for tld in suspicious_tlds:
            result = quick_domain_checks(f"https://fake-login.{tld}")
            assert result["has_suspicious_tld"] is True, f"Failed for TLD {tld}"

    def test_standard_tlds_not_flagged(self):
        for tld in ["com", "org", "net", "edu", "gov"]:
            result = quick_domain_checks(f"https://service.{tld}")
            assert result["has_suspicious_tld"] is False

    def test_malformed_url_handling(self):
        # Even with malformed or empty inputs, it should return a dictionary with error or defaults
        result = quick_domain_checks("http://")
        assert isinstance(result, dict)
        assert "domain" in result


class TestFormatDomainSummary:
    def test_format_clean_domain(self):
        info = {
            "full_domain": "trusted.org",
            "is_ip_address": False,
            "has_suspicious_subdomain": False,
            "has_many_subdomains": False,
            "has_suspicious_tld": False
        }
        summary = format_domain_summary(info)
        assert "Domain: trusted.org" in summary

    def test_format_ip_address_warning(self):
        info = {
            "full_domain": "192.168.1.1",
            "is_ip_address": True,
            "has_suspicious_subdomain": False,
            "has_many_subdomains": False,
            "has_suspicious_tld": False
        }
        summary = format_domain_summary(info)
        assert "Using IP address instead of domain name" in summary

    def test_format_suspicious_subdomain_warning(self):
        info = {
            "subdomain": "secure-login",
            "full_domain": "evil.com",
            "is_ip_address": False,
            "has_suspicious_subdomain": True,
            "has_many_subdomains": False,
            "has_suspicious_tld": False
        }
        summary = format_domain_summary(info)
        assert "Suspicious subdomain detected: secure-login" in summary

    def test_format_multiple_warnings(self):
        info = {
            "subdomain": "secure.login.verify",
            "suffix": "xyz",
            "full_domain": "evil.xyz",
            "is_ip_address": True,
            "has_suspicious_subdomain": True,
            "has_many_subdomains": True,
            "has_suspicious_tld": True
        }
        summary = format_domain_summary(info)
        assert "Using IP address" in summary
        assert "Suspicious subdomain detected" in summary
        assert "Unusual number of subdomains" in summary
        assert "Suspicious TLD: .xyz" in summary
        assert " | " in summary

