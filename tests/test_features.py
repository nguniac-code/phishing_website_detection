import unittest

from feature_extraction import extract_url_features, normalize_url


class FeatureExtractionTests(unittest.TestCase):
    def test_extracts_expected_features_including_ip_and_https(self):
        features = extract_url_features("https://login.example-site.com/account/verify?id=42")
        self.assertEqual(features["has_https"], 1)
        self.assertEqual(features["has_ip"], 0)
        self.assertEqual(features["num_subdomains"], 1)
        self.assertGreaterEqual(features["suspicious_keyword_count"], 3)
        self.assertEqual(features["path_length"], len("/account/verify"))

    def test_detects_ip_address_url(self):
        features = extract_url_features("http://192.0.2.10/signin")
        self.assertEqual(features["has_ip"], 1)
        self.assertEqual(features["has_https"], 0)

    def test_normalizes_missing_scheme_and_rejects_bad_urls(self):
        self.assertEqual(normalize_url("example.com"), "https://example.com")
        for invalid in ("", "not a url", "ftp://example.com"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    normalize_url(invalid)


if __name__ == "__main__":
    unittest.main()
