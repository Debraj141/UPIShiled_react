import unittest
from datetime import datetime, timedelta

from backend.main import build_evidence, extract_details, timestamp_is_impossible
from backend.upi_security import analyze_upi_payload, parse_upi_payload


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


class UPISecurityPayloadTests(unittest.TestCase):
    def rule_ids(self, payload, blocklist=None):
        result = analyze_upi_payload(payload, blocklist)
        return result["verdict"], {reason["id"] for reason in result["reasons"]}, result

    def test_valid_merchant_payload_is_safe(self):
        payload = "upi://pay?pa=acmestore@okaxis&pn=Acme%20Store&am=125.50&cu=INR&tn=Invoice&tr=ORDER123&mc=5411&orgid=123456&sign=ABCDEFGHIJKLMNOPabcdefghijkl"
        verdict, _, result = self.rule_ids(payload)
        self.assertEqual(verdict, "SAFE")
        self.assertLessEqual(result["risk_score"], 34)

    def test_http_link_is_dangerous(self):
        verdict, ids, _ = self.rule_ids("https://pay.example.com/upi")
        self.assertIn("scheme_http", ids)
        self.assertIn(verdict, ("CAUTION", "DANGEROUS"))

    def test_collect_request_is_dangerous(self):
        verdict, ids, _ = self.rule_ids("upi://collect?pa=shop@okaxis&pn=Acme&am=10&cu=INR")
        self.assertEqual(verdict, "DANGEROUS")
        self.assertIn("scheme_collect", ids)

    def test_unknown_scheme_is_dangerous(self):
        _, ids, _ = self.rule_ids("phonepe://pay?pa=shop@okaxis")
        self.assertIn("scheme_unknown", ids)

    def test_missing_payload_is_caution(self):
        verdict, ids, _ = self.rule_ids(None)
        self.assertEqual(verdict, "CAUTION")
        self.assertIn("missing_payload", ids)

    def test_malformed_payload_is_not_safe(self):
        verdict, ids, _ = self.rule_ids("not a valid://%%")
        self.assertIn(verdict, ("CAUTION", "DANGEROUS"))
        self.assertTrue(ids)

    def test_duplicate_parameters_are_flagged(self):
        _, ids, _ = self.rule_ids("upi://pay?pa=shop@okaxis&pa=other@okaxis&am=10&cu=INR")
        self.assertIn("duplicate_param", ids)

    def test_unknown_parameter_is_flagged(self):
        _, ids, _ = self.rule_ids("upi://pay?pa=shop@okaxis&am=10&cu=INR&debug=true")
        self.assertIn("unknown_param", ids)

    def test_bad_percent_encoding_is_flagged(self):
        _, ids, _ = self.rule_ids("upi://pay?pa=shop@okaxis&pn=Bad%ZZ&cu=INR")
        self.assertIn("bad_encoding", ids)

    def test_hidden_character_is_flagged(self):
        _, ids, _ = self.rule_ids("upi://pay?pa=shop@okaxis&pn=Acme\u200bStore&cu=INR")
        self.assertIn("hidden_char", ids)

    def test_huge_parameter_is_flagged(self):
        _, ids, _ = self.rule_ids("upi://pay?pa=shop@okaxis&tn=" + ("A" * 2100))
        self.assertIn("huge_value", ids)

    def test_invalid_vpa_format_is_flagged(self):
        _, ids, _ = self.rule_ids("upi://pay?pa=not-a-vpa&am=10&cu=INR")
        self.assertIn("bad_vpa", ids)

    def test_unknown_psp_handle_is_high_risk(self):
        _, ids, _ = self.rule_ids("upi://pay?pa=shop@unknownpsp&am=10&cu=INR")
        self.assertIn("unknown_handle", ids)

    def test_blocklisted_vpa_is_dangerous(self):
        verdict, ids, _ = self.rule_ids(
            "upi://pay?pa=fraud@paytm&pn=Fraud&am=10&cu=INR",
            {"fraud@paytm"},
        )
        self.assertIn("blocklisted_vpa", ids)
        self.assertEqual(verdict, "DANGEROUS")

    def test_lookalike_brand_name_is_flagged(self):
        _, ids, _ = self.rule_ids("upi://pay?pa=paytm-legit@okaxis&pn=Paytm&am=10&cu=INR")
        self.assertIn("lookalike", ids)

    def test_homoglyph_name_is_flagged(self):
        _, ids, _ = self.rule_ids("upi://pay?pa=store@okaxis&pn=Pаytm&am=10&cu=INR")
        self.assertIn("homoglyph", ids)

    def test_merchant_code_with_personal_vpa_is_flagged(self):
        _, ids, _ = self.rule_ids("upi://pay?pa=person@ybl&pn=Person&am=10&cu=INR&mc=5411")
        self.assertIn("merchant_personal", ids)

    def test_name_not_matching_vpa_is_flagged(self):
        _, ids, _ = self.rule_ids("upi://pay?pa=completelydifferent@okaxis&pn=Totally%20Unrelated%20Merchant&am=10&cu=INR")
        self.assertIn("name_mismatch", ids)

    def test_non_inr_currency_is_flagged(self):
        _, ids, _ = self.rule_ids("upi://pay?pa=shop@okaxis&pn=Shop&am=10&cu=USD")
        self.assertIn("currency", ids)

    def test_high_amount_is_flagged(self):
        _, ids, _ = self.rule_ids("upi://pay?pa=shop@okaxis&pn=Shop&am=50000&cu=INR")
        self.assertIn("high_amount", ids)

    def test_negative_amount_is_flagged(self):
        _, ids, _ = self.rule_ids("upi://pay?pa=shop@okaxis&pn=Shop&am=-10&cu=INR")
        self.assertIn("odd_amount", ids)

    def test_zero_amount_is_flagged(self):
        _, ids, _ = self.rule_ids("upi://pay?pa=shop@okaxis&pn=Shop&am=0&cu=INR")
        self.assertIn("odd_amount", ids)

    def test_nonnumeric_amount_is_flagged(self):
        _, ids, _ = self.rule_ids("upi://pay?pa=shop@okaxis&pn=Shop&am=ten&cu=INR")
        self.assertIn("odd_amount", ids)

    def test_urgent_refund_note_is_flagged(self):
        _, ids, _ = self.rule_ids("upi://pay?pa=shop@okaxis&pn=Shop&am=10&cu=INR&tn=Urgent%20refund")
        self.assertIn("urgency_note", ids)

    def test_prize_note_is_flagged(self):
        _, ids, _ = self.rule_ids("upi://pay?pa=shop@okaxis&pn=Shop&tn=Prize%20winning")
        self.assertIn("urgency_note", ids)

    def test_kyc_note_is_flagged(self):
        _, ids, _ = self.rule_ids("upi://pay?pa=shop@okaxis&pn=Shop&tn=Complete%20KYC")
        self.assertIn("urgency_note", ids)

    def test_cashback_note_is_flagged(self):
        _, ids, _ = self.rule_ids("upi://pay?pa=shop@okaxis&pn=Shop&tn=Cashback%20reward")
        self.assertIn("urgency_note", ids)

    def test_invalid_sign_is_flagged(self):
        _, ids, _ = self.rule_ids("upi://pay?pa=shop@okaxis&pn=Shop&cu=INR&sign=bad!")
        self.assertIn("bad_sign", ids)

    def test_invalid_orgid_is_flagged(self):
        _, ids, _ = self.rule_ids("upi://pay?pa=shop@okaxis&pn=Shop&cu=INR&orgid=*bad*")
        self.assertIn("bad_orgid", ids)

    def test_shop_missing_sign_details_is_flagged(self):
        _, ids, _ = self.rule_ids("upi://pay?pa=shop@okaxis&pn=Shop&am=10&cu=INR&mc=5411")
        self.assertIn("missing_sign_shop", ids)

    def test_zero_width_joiner_is_hidden(self):
        _, ids, _ = self.rule_ids("upi://pay?pa=shop@okaxis&pn=Pay\u200dtm&cu=INR")
        self.assertIn("hidden_char", ids)

    def test_paytm_is_an_approved_handle(self):
        parsed = parse_upi_payload("upi://pay?pa=merchant@paytm&am=10&cu=INR")
        self.assertTrue(parsed["ok"])
        _, ids, _ = self.rule_ids("upi://pay?pa=merchant@paytm&am=10&cu=INR")
        self.assertNotIn("unknown_handle", ids)

    def test_short_url_is_flagged(self):
        _, ids, _ = self.rule_ids("https://bit.ly/paynow")
        self.assertIn("scheme_http", ids)

    def test_parse_result_contains_params(self):
        parsed = parse_upi_payload("upi://pay?pa=shop@okaxis&am=10&cu=INR&tn=Payment")
        self.assertTrue(parsed["ok"])
        self.assertEqual(parsed["params"]["pa"], "shop@okaxis")
        self.assertEqual(parsed["params"]["cu"], "INR")


if __name__ == "__main__":
    unittest.main()
