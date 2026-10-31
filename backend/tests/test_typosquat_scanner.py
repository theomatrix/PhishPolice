import pytest
from utils.typosquat_scanner import (
    calculate_levenshtein,
    normalize_domain,
    detect_typosquatting,
    check_letter_substitution,
    check_homoglyphs,
    detect_technique,
    get_typosquat_risk_score,
    format_typosquat_summary,
)


class TestLevenshtein:
    def test_identical_strings(self):
        assert calculate_levenshtein("google", "google") == 0

    def test_empty_strings(self):
        assert calculate_levenshtein("", "") == 0
        assert calculate_levenshtein("abc", "") == 3
        assert calculate_levenshtein("", "def") == 3

    def test_single_operations(self):
        # substitution
        assert calculate_levenshtein("cat", "bat") == 1
        # insertion
        assert calculate_levenshtein("cat", "cats") == 1
        # deletion
        assert calculate_levenshtein("cats", "cat") == 1

    def test_case_sensitivity(self):
        assert calculate_levenshtein("Google", "google") == 1


class TestNormalizeDomain:
    def test_strip_www(self):
        assert normalize_domain("www.google.com") == "google"

    def test_extract_domain_name(self):
        assert normalize_domain("paypal.com") == "paypal"
        assert normalize_domain("sub.domain.org") == "domain"

    def test_single_part(self):
        assert normalize_domain("localhost") == "localhost"

    def test_lowercasing(self):
        assert normalize_domain("WWW.MICROSOFT.COM") == "microsoft"


class TestLetterSubstitutionAndHomoglyphs:
    def test_check_letter_substitution(self):
        assert check_letter_substitution("g00gle", "google") is True
        assert check_letter_substitution("paypa1", "paypal") is True
        assert check_letter_substitution("google", "paypal") is False

    def test_check_homoglyphs(self):
        assert check_homoglyphs("arnazon", "amazon") is True  # rn -> m
        assert check_homoglyphs("vvellsfargo", "wellsfargo") is True  # vv -> w
        assert check_homoglyphs("randomdomain", "paypal") is False


class TestDetectTechnique:
    def test_character_insertion(self):
        assert detect_technique("googlle", "google") == "character_insertion"

    def test_character_omission(self):
        assert detect_technique("gogle", "google") == "character_omission"

    def test_character_swap(self):
        assert detect_technique("googly", "google") == "character_swap"

    def test_adjacent_swap(self):
        assert detect_technique("goolge", "google") == "adjacent_swap"


class TestDetectTyposquatting:
    def test_empty_hostname(self):
        result = detect_typosquatting("")
        assert result["is_typosquat"] is False

    def test_legitimate_brand_domains(self):
        for legit in ["google.com", "www.google.com", "paypal.com", "github.com", "apple.com"]:
            result = detect_typosquatting(legit)
            assert result["is_typosquat"] is False
            assert any("Legitimate" in d for d in result["details"])

    def test_levenshtein_typosquat(self):
        result = detect_typosquatting("goggle.com")
        assert result["is_typosquat"] is True
        assert result["suspected_brand"] == "google"
        assert result["similarity_score"] >= 75

    def test_substitution_typosquat_direct(self):
        # Multiple substitutions drop similarity < 0.75, triggering letter_substitution branch
        result = detect_typosquatting("g00g1e.com")
        assert result["is_typosquat"] is True
        assert result["suspected_brand"] == "google"
        assert result["technique"] == "letter_substitution"

    def test_homoglyph_typosquat_branch(self):
        # Multiple homoglyphs / length difference drops similarity < 0.75, triggering homoglyph branch
        result = detect_typosquatting("arnazorn.com")
        assert result["is_typosquat"] is True
        assert result["suspected_brand"] == "amazon"
        assert result["technique"] == "homoglyph"

    def test_single_char_typosquat(self):
        result = detect_typosquatting("paypa1.com")
        assert result["is_typosquat"] is True
        assert result["suspected_brand"] == "paypal"

    def test_unrelated_domain(self):
        result = detect_typosquatting("pythonsoftwarefoundation.org")
        assert result["is_typosquat"] is False


class TestTyposquatRiskScoreAndSummary:
    def test_risk_score_typosquat(self):
        score, evidence = get_typosquat_risk_score("paypa1.com")
        assert score == 0.35
        assert any("paypal" in e.lower() for e in evidence)

    def test_risk_score_legitimate(self):
        score, evidence = get_typosquat_risk_score("google.com")
        assert score == 0.0

    def test_format_summary_typosquat(self):
        result = {
            "is_typosquat": True,
            "suspected_brand": "paypal",
            "similarity_score": 95
        }
        summary = format_typosquat_summary(result)
        assert "TYPOSQUAT ALERT" in summary
        assert "paypal" in summary
        assert "95%" in summary

    def test_format_summary_safe(self):
        result = {"is_typosquat": False}
        summary = format_typosquat_summary(result)
        assert "No typosquatting detected" in summary
