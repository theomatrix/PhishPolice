import socket
import ssl
from unittest.mock import MagicMock, patch
import pytest

from utils.ssl_check import (
    calculate_ssl_security_score,
    format_ssl_summary,
    get_ssl_certificate_info,
)


class TestCalculateSSLSecurityScore:
    def test_no_ssl_score(self):
        cert_info = {"has_ssl": False}
        assert calculate_ssl_security_score(cert_info) == 20

    def test_invalid_cert_score(self):
        cert_info = {"has_ssl": True, "is_valid": False}
        assert calculate_ssl_security_score(cert_info) == 15

    def test_valid_trusted_issuer_long_expiry(self):
        cert_info = {
            "has_ssl": True,
            "is_valid": True,
            "is_self_signed": False,
            "is_expired": False,
            "is_expiring_soon": False,
            "issued_days_ago": 120,
            "issuer": "Let's Encrypt Authority X3",
            "expires_in_days": 200,
        }
        # base: 60 + 20 (trusted issuer) + 10 (>180 days) = 90
        score = calculate_ssl_security_score(cert_info)
        assert score == 90

    def test_self_signed_certificate_penalty(self):
        cert_info = {
            "has_ssl": True,
            "is_valid": True,
            "is_self_signed": True,
            "is_expired": False,
            "is_expiring_soon": False,
            "issued_days_ago": 60,
            "issuer": "Custom CA",
            "expires_in_days": 50,
        }
        # 60 - 30 = 30
        assert calculate_ssl_security_score(cert_info) == 30

    def test_expired_certificate_penalty(self):
        cert_info = {
            "has_ssl": True,
            "is_valid": True,
            "is_self_signed": False,
            "is_expired": True,
            "is_expiring_soon": False,
            "issued_days_ago": 400,
            "issuer": "DigiCert Global Root CA",
            "expires_in_days": -10,
        }
        # 60 - 40 + 20 = 40
        assert calculate_ssl_security_score(cert_info) == 40

    def test_newly_issued_penalty(self):
        cert_info = {
            "has_ssl": True,
            "is_valid": True,
            "is_self_signed": False,
            "is_expired": False,
            "is_expiring_soon": False,
            "issued_days_ago": 3,  # < 7 days
            "issuer": "Custom CA",
            "expires_in_days": 80,
        }
        # 60 - 15 = 45
        assert calculate_ssl_security_score(cert_info) == 45


class TestFormatSSLSummary:
    def test_no_ssl_http(self):
        info = {"has_ssl": False, "certificate_error": "Not using HTTPS"}
        assert "uses HTTP (unencrypted)" in format_ssl_summary(info)

    def test_no_ssl_other_error(self):
        info = {"has_ssl": False, "certificate_error": "Connection failed"}
        assert "❌ No SSL: Connection failed" in format_ssl_summary(info)

    def test_invalid_ssl(self):
        info = {"has_ssl": True, "is_valid": False, "certificate_error": "Self-signed certificate in chain"}
        assert "❌ Invalid SSL certificate" in format_ssl_summary(info)

    def test_valid_ssl_summary(self):
        info = {
            "has_ssl": True,
            "is_valid": True,
            "is_expired": False,
            "is_expiring_soon": False,
            "expires_in_days": 85,
            "is_self_signed": False,
            "issuer": "DigiCert Inc",
            "issued_days_ago": 50,
        }
        summary = format_ssl_summary(info)
        assert "✅ Valid SSL (85 days remaining)" in summary
        assert "Issuer: DigiCert Inc" in summary

    def test_expired_ssl_summary(self):
        info = {
            "has_ssl": True,
            "is_valid": True,
            "is_expired": True,
            "is_expiring_soon": False,
            "expires_in_days": -5,
            "is_self_signed": False,
            "issuer": "Test",
        }
        assert "❌ EXPIRED certificate" in format_ssl_summary(info)

    def test_expiring_soon_summary(self):
        info = {
            "has_ssl": True,
            "is_valid": True,
            "is_expired": False,
            "is_expiring_soon": True,
            "expires_in_days": 12,
            "is_self_signed": False,
            "issuer": "Test",
        }
        assert "⚠️ Expires in 12 days" in format_ssl_summary(info)

    def test_self_signed_summary(self):
        info = {
            "has_ssl": True,
            "is_valid": True,
            "is_expired": False,
            "is_expiring_soon": False,
            "expires_in_days": 100,
            "is_self_signed": True,
        }
        assert "⚠️ Self-signed certificate" in format_ssl_summary(info)


class TestGetSSLCertificateInfo:
    def test_invalid_url_no_hostname(self):
        info = get_ssl_certificate_info("https://")
        assert info["has_ssl"] is False
        assert "no hostname" in info["certificate_error"]

    def test_http_url_rejection(self):
        info = get_ssl_certificate_info("http://example.com")
        assert info["has_ssl"] is False
        assert info["certificate_error"] == "Not using HTTPS"
        assert info["security_score"] == 20

    @patch("ssl.create_default_context")
    @patch("socket.create_connection")
    def test_valid_cert_retrieval(self, mock_socket_conn, mock_ssl_context):
        # Setup mock socket and ssl context
        mock_sock = MagicMock()
        mock_socket_conn.return_value.__enter__.return_value = mock_sock

        mock_ssock = MagicMock()
        mock_context_instance = MagicMock()
        mock_ssl_context.return_value = mock_context_instance
        mock_context_instance.wrap_socket.return_value.__enter__.return_value = mock_ssock

        mock_ssock.getpeercert.return_value = {
            "issuer": ((("organizationName", "DigiCert Inc"),),),
            "subject": ((("commonName", "example.com"),),),
            "notBefore": "Jan 01 00:00:00 2026 GMT",
            "notAfter": "Dec 31 23:59:59 2026 GMT",
        }

        info = get_ssl_certificate_info("https://example.com")
        assert info["has_ssl"] is True
        assert info["is_valid"] is True
        assert info["issuer"] == "DigiCert Inc"
        assert info["subject"] == "example.com"
        assert info["is_self_signed"] is False
        assert info["expires_in_days"] is not None
        assert info["security_score"] > 50

    @patch("ssl.create_default_context")
    @patch("socket.create_connection")
    def test_self_signed_cert_retrieval(self, mock_socket_conn, mock_ssl_context):
        mock_sock = MagicMock()
        mock_socket_conn.return_value.__enter__.return_value = mock_sock

        mock_ssock = MagicMock()
        mock_context_instance = MagicMock()
        mock_ssl_context.return_value = mock_context_instance
        mock_context_instance.wrap_socket.return_value.__enter__.return_value = mock_ssock

        mock_ssock.getpeercert.return_value = {
            "issuer": ((("commonName", "my-custom-host"),),),
            "subject": ((("commonName", "my-custom-host"),),),
            "notBefore": "Jan 01 00:00:00 2026 GMT",
            "notAfter": "Dec 31 23:59:59 2026 GMT",
        }

        info = get_ssl_certificate_info("https://my-custom-host")
        assert info["has_ssl"] is True
        assert info["is_self_signed"] is True

    @patch("ssl.create_default_context")
    @patch("socket.create_connection")
    def test_empty_cert_returned(self, mock_socket_conn, mock_ssl_context):
        mock_sock = MagicMock()
        mock_socket_conn.return_value.__enter__.return_value = mock_sock

        mock_ssock = MagicMock()
        mock_context_instance = MagicMock()
        mock_ssl_context.return_value = mock_context_instance
        mock_context_instance.wrap_socket.return_value.__enter__.return_value = mock_ssock
        mock_ssock.getpeercert.return_value = None

        info = get_ssl_certificate_info("https://example.com")
        assert info["has_ssl"] is False
        assert "No certificate returned" in info["certificate_error"]

    @patch("socket.create_connection", side_effect=socket.timeout)
    def test_connection_timeout(self, mock_socket_conn):
        info = get_ssl_certificate_info("https://timeout.example.com")
        assert info["has_ssl"] is False
        assert info["certificate_error"] == "Connection timeout"
        assert info["security_score"] == 30

    @patch("socket.create_connection", side_effect=socket.gaierror)
    def test_dns_resolution_failed(self, mock_socket_conn):
        info = get_ssl_certificate_info("https://nonexistent-domain-xyz.com")
        assert info["has_ssl"] is False
        assert info["certificate_error"] == "DNS resolution failed"
        assert info["security_score"] == 25

    @patch("socket.create_connection", side_effect=ConnectionRefusedError)
    def test_connection_refused(self, mock_socket_conn):
        info = get_ssl_certificate_info("https://refused.example.com")
        assert info["has_ssl"] is False
        assert info["certificate_error"] == "Connection refused"
        assert info["security_score"] == 20

    @patch("ssl.create_default_context")
    @patch("socket.create_connection")
    def test_ssl_cert_verification_error(self, mock_socket_conn, mock_ssl_context):
        mock_sock = MagicMock()
        mock_socket_conn.return_value.__enter__.return_value = mock_sock

        mock_context_instance = MagicMock()
        mock_ssl_context.return_value = mock_context_instance
        mock_context_instance.wrap_socket.side_effect = ssl.SSLCertVerificationError("Certificate verify failed")

        info = get_ssl_certificate_info("https://invalid-cert.com")
        assert info["has_ssl"] is True
        assert info["is_valid"] is False
        assert "Certificate verification failed" in info["certificate_error"]
        assert info["security_score"] == 15
