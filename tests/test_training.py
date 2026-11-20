import unittest

from train_model import _map_label


class TrainingLabelTests(unittest.TestCase):
    def test_numeric_label_convention_is_configurable(self):
        self.assertEqual(_map_label(0, numeric_phishing_label=0), 1)
        self.assertEqual(_map_label(1, numeric_phishing_label=0), 0)
        self.assertEqual(_map_label(0, numeric_phishing_label=1), 0)
        self.assertEqual(_map_label(1, numeric_phishing_label=1), 1)

    def test_text_labels_are_independent_of_numeric_convention(self):
        self.assertEqual(_map_label("phishing", numeric_phishing_label=0), 1)
        self.assertEqual(_map_label("legitimate", numeric_phishing_label=1), 0)
        self.assertIsNone(_map_label("unknown", numeric_phishing_label=0))


if __name__ == "__main__":
    unittest.main()
