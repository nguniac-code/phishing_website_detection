import tempfile
import unittest
from pathlib import Path

from prediction import predict_url


class PredictionTests(unittest.TestCase):
    def test_prediction_requires_a_trained_model(self):
        with tempfile.TemporaryDirectory() as directory:
            missing_model = Path(directory) / "not-trained.joblib"
            with self.assertRaises(FileNotFoundError):
                predict_url("https://example.com", missing_model)

    def test_invalid_url_is_rejected_before_model_loading(self):
        with self.assertRaises(ValueError):
            predict_url("ftp://example.com", "missing.joblib")


if __name__ == "__main__":
    unittest.main()
