import unittest
from datetime import datetime, timedelta

from backend.main import build_evidence, extract_details, timestamp_is_impossible


class PaymentExtractionTests(unittest.TestCase):
    def test_extracts_labeled_payment_fields_and_evidence(self):
        text = (
            "Google Pay\nPayment successful\n%250.00\n"
            "Transaction ID: 123456789012345\n20/11/2024, 14:30"
        )

        details, sources = extract_details(text)
        evidence = build_evidence(text, details, sources, 91.2, True)

        self.assertEqual(details["amount"], "250.00")
        self.assertEqual(details["transaction_id"], "123456789012345")
        self.assertEqual(details["timestamp"], "20 Nov 2024, 14:30")
        self.assertTrue(all(item["detected"] for item in evidence["items"]))
        self.assertIn("****2345", evidence["items"][2]["snippet"])
        self.assertTrue(evidence["orientation_corrected"])

    def test_does_not_guess_unlabeled_transaction_id(self):
        details, _ = extract_details("Payment successful\n987654321098765\n20/11/2024, 14:30")

        self.assertIsNone(details["transaction_id"])

    def test_ignores_date_and_reference_digits_when_extracting_amount(self):
        details, _ = extract_details(
            "Payment successful\nTransaction ID: 123456789012345\n20/11/2024, 14:30"
        )

        self.assertIsNone(details["amount"])

    def test_flags_future_timestamp(self):
        future = (datetime.now() + timedelta(days=2)).strftime("%d/%m/%Y, %H:%M")

        impossible, message = timestamp_is_impossible(future)

        self.assertTrue(impossible)
        self.assertEqual(message, "Timestamp is in the future")


if __name__ == "__main__":
    unittest.main()
