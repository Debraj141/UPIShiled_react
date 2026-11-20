import unittest
from datetime import datetime, timedelta

from backend.main import build_evidence, extract_details, timestamp_is_impossible
from backend.upi_security import (
    analyze_upi_payload,
    hash_vpa,
    parse_upi_payload,
    validate_p2_reputation,
)


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


class P0PayloadValidationTests(unittest.TestCase):
    def analyze(self, payload):
        return analyze_upi_payload(payload)

    def test_p0_valid_payload_is_safe(self):
        result = self.analyze("upi://pay?pa=acmestore@okaxis&pn=Acme%20Store&am=250&cu=INR")
        self.assertEqual(result["verdict"], "SAFE")
        self.assertEqual(result["risk_score"], 0)

    def test_p0_valid_payload_with_common_fields_is_safe(self):
        result = self.analyze("upi://pay?pa=shop@paytm&pn=City%20Shop&am=49.50&cu=INR&tn=Invoice&tr=TRX123&mc=5411")
        self.assertEqual(result["verdict"], "SAFE")

    def test_p0_http_scheme_is_rejected(self):
        result = self.analyze("http://example.com/upi")
        self.assertIn("scheme_http", {item["id"] for item in result["reasons"]})
        self.assertGreaterEqual(result["risk_score"], 35)

    def test_p0_https_scheme_is_rejected(self):
        result = self.analyze("https://example.com/pay")
        self.assertIn("scheme_http", {item["id"] for item in result["reasons"]})

    def test_p0_collect_scheme_is_critical(self):
        result = self.analyze("upi://collect?pa=shop@okaxis&pn=Shop&am=20&cu=INR")
        ids = {item["id"] for item in result["reasons"]}
        self.assertIn("scheme_collect", ids)
        self.assertEqual(result["verdict"], "DANGEROUS")

    def test_p0_shortener_is_flagged(self):
        result = self.analyze("https://bit.ly/3AbCdEf")
        ids = {item["id"] for item in result["reasons"]}
        self.assertIn("scheme_http", ids)

    def test_p0_duplicate_parameter_is_high(self):
        result = self.analyze("upi://pay?pa=shop@okaxis&pa=second@okaxis&cu=INR")
        duplicate = next(item for item in result["reasons"] if item["id"] == "duplicate_param")
        self.assertEqual(duplicate["severity"], "HIGH")

    def test_p0_unknown_parameter_is_medium(self):
        result = self.analyze("upi://pay?pa=shop@okaxis&cu=INR&extra=1")
        unknown = next(item for item in result["reasons"] if item["id"] == "unknown_param")
        self.assertEqual(unknown["severity"], "MEDIUM")

    def test_p0_bad_percent_encoding_is_flagged(self):
        result = self.analyze("upi://pay?pa=shop@okaxis&pn=Bad%ZZ&cu=INR")
        self.assertIn("bad_encoding", {item["id"] for item in result["reasons"]})

    def test_p0_hidden_character_is_flagged(self):
        result = self.analyze("upi://pay?pa=shop@okaxis&pn=Acme\u200bStore&cu=INR")
        hidden = next(item for item in result["reasons"] if item["id"] == "hidden_char")
        self.assertEqual(hidden["severity"], "HIGH")

    def test_p0_hidden_parameter_key_is_flagged(self):
        result = self.analyze("upi://pay?pa=shop@okaxis&cu\u200d=INR")
        self.assertIn("hidden_char", {item["id"] for item in result["reasons"]})

    def test_p0_oversized_parameter_is_flagged(self):
        result = self.analyze("upi://pay?pa=shop@okaxis&tn=" + ("x" * 2100))
        huge = next(item for item in result["reasons"] if item["id"] == "huge_value")
        self.assertEqual(huge["severity"], "HIGH")

    def test_p0_bad_vpa_is_critical(self):
        result = self.analyze("upi://pay?pa=not-a-vpa&cu=INR")
        bad_vpa = next(item for item in result["reasons"] if item["id"] == "bad_vpa")
        self.assertEqual(bad_vpa["severity"], "CRITICAL")

    def test_p0_unknown_handle_is_high(self):
        result = self.analyze("upi://pay?pa=shop@madeupbank&cu=INR")
        unknown = next(item for item in result["reasons"] if item["id"] == "unknown_handle")
        self.assertEqual(unknown["severity"], "HIGH")

    def test_p0_non_inr_currency_is_high(self):
        result = self.analyze("upi://pay?pa=shop@okaxis&cu=USD")
        currency = next(item for item in result["reasons"] if item["id"] == "currency")
        self.assertEqual(currency["severity"], "HIGH")

    def test_p0_missing_vpa_is_critical(self):
        result = self.analyze("upi://pay?pn=Shop&cu=INR")
        missing = next(item for item in result["reasons"] if item["id"] == "missing_vpa")
        self.assertEqual(missing["severity"], "CRITICAL")

    def test_p0_empty_payload_is_caution(self):
        result = self.analyze("")
        self.assertEqual(result["verdict"], "CAUTION")

    def test_p0_none_payload_is_caution(self):
        result = self.analyze(None)
        self.assertEqual(result["verdict"], "CAUTION")
        self.assertIn("missing_payload", {item["id"] for item in result["reasons"]})


class P1LookalikeAndConsistencyTests(unittest.TestCase):
    def analyze(self, payload):
        return analyze_upi_payload(payload)

    def test_p1_paytm_name_lookalike_is_flagged(self):
        result = self.analyze("upi://pay?pa=paytmlegit@okaxis&pn=Paytm&am=100&cu=INR")
        self.assertIn("lookalike", {item["id"] for item in result["reasons"]})

    def test_p1_phonepe_name_lookalike_is_flagged(self):
        result = self.analyze("upi://pay?pa=store@okaxis&pn=PhonePe&am=100&cu=INR")
        self.assertIn("lookalike", {item["id"] for item in result["reasons"]})

    def test_p1_bank_name_lookalike_is_flagged(self):
        result = self.analyze("upi://pay?pa=sbihelp@okaxis&pn=SBI%20Support&am=100&cu=INR")
        self.assertIn("lookalike", {item["id"] for item in result["reasons"]})

    def test_p1_cyrillic_homoglyph_is_flagged(self):
        result = self.analyze("upi://pay?pa=store@okaxis&pn=Pаytm&am=100&cu=INR")
        self.assertIn("homoglyph", {item["id"] for item in result["reasons"]})

    def test_p1_fullwidth_homoglyph_is_flagged(self):
        result = self.analyze("upi://pay?pa=store@okaxis&pn=Ｐaytm&am=100&cu=INR")
        self.assertIn("homoglyph", {item["id"] for item in result["reasons"]})

    def test_p1_matching_name_and_vpa_is_not_mismatched(self):
        result = self.analyze("upi://pay?pa=acmestore@okaxis&pn=Acme%20Store&am=100&cu=INR")
        self.assertNotIn("name_mismatch", {item["id"] for item in result["reasons"]})

    def test_p1_mismatched_name_is_flagged(self):
        result = self.analyze("upi://pay?pa=completelydifferent@okaxis&pn=Totally%20Unrelated&am=100&cu=INR")
        self.assertIn("name_mismatch", {item["id"] for item in result["reasons"]})

    def test_p1_merchant_code_with_ybl_is_flagged(self):
        result = self.analyze("upi://pay?pa=person@ybl&pn=Person&am=100&cu=INR&mc=5411")
        self.assertIn("merchant_personal", {item["id"] for item in result["reasons"]})

    def test_p1_merchant_code_with_approved_business_handle_is_not_flagged(self):
        result = self.analyze("upi://pay?pa=business@okbiz&pn=Business&am=100&cu=INR&mc=5411")
        self.assertNotIn("merchant_personal", {item["id"] for item in result["reasons"]})

    def test_p1_high_amount_is_high(self):
        result = self.analyze("upi://pay?pa=shop@okaxis&pn=Shop&am=50000&cu=INR")
        high = next(item for item in result["reasons"] if item["id"] == "high_amount")
        self.assertEqual(high["severity"], "HIGH")

    def test_p1_below_high_amount_is_not_high(self):
        result = self.analyze("upi://pay?pa=shop@okaxis&pn=Shop&am=49999&cu=INR")
        self.assertNotIn("high_amount", {item["id"] for item in result["reasons"]})

    def test_p1_negative_amount_is_odd(self):
        result = self.analyze("upi://pay?pa=shop@okaxis&pn=Shop&am=-10&cu=INR")
        odd = next(item for item in result["reasons"] if item["id"] == "odd_amount")
        self.assertEqual(odd["severity"], "MEDIUM")

    def test_p1_non_numeric_amount_is_odd(self):
        result = self.analyze("upi://pay?pa=shop@okaxis&pn=Shop&am=ten&cu=INR")
        self.assertIn("odd_amount", {item["id"] for item in result["reasons"]})

    def test_p1_one_decimal_place_is_odd(self):
        result = self.analyze("upi://pay?pa=shop@okaxis&pn=Shop&am=10.5&cu=INR")
        self.assertIn("odd_amount", {item["id"] for item in result["reasons"]})

    def test_p1_three_decimal_places_is_odd(self):
        result = self.analyze("upi://pay?pa=shop@okaxis&pn=Shop&am=10.555&cu=INR")
        self.assertIn("odd_amount", {item["id"] for item in result["reasons"]})

    def test_p1_refund_note_is_urgent(self):
        result = self.analyze("upi://pay?pa=shop@okaxis&pn=Shop&tn=Refund%20required&cu=INR")
        self.assertIn("urgency_note", {item["id"] for item in result["reasons"]})

    def test_p1_prize_note_is_urgent(self):
        result = self.analyze("upi://pay?pa=shop@okaxis&pn=Shop&tn=Prize%20claim&cu=INR")
        self.assertIn("urgency_note", {item["id"] for item in result["reasons"]})

    def test_p1_kyc_note_is_urgent(self):
        result = self.analyze("upi://pay?pa=shop@okaxis&pn=Shop&tn=Complete%20KYC&cu=INR")
        self.assertIn("urgency_note", {item["id"] for item in result["reasons"]})

    def test_p1_cashback_note_is_urgent(self):
        result = self.analyze("upi://pay?pa=shop@okaxis&pn=Shop&tn=Cashback%20offer&cu=INR")
        self.assertIn("urgency_note", {item["id"] for item in result["reasons"]})

    def test_p1_lottery_note_is_urgent(self):
        result = self.analyze("upi://pay?pa=shop@okaxis&pn=Shop&tn=Lottery%20winning&cu=INR")
        self.assertIn("urgency_note", {item["id"] for item in result["reasons"]})


class P2ReputationTests(unittest.TestCase):
    def test_p2_hash_is_sha256_and_stable(self):
        first = hash_vpa("Merchant@OKAxis")
        second = hash_vpa("merchant@okaxis")
        self.assertEqual(first, second)
        self.assertIsNotNone(first)
        self.assertEqual(len(first), 64)
        self.assertRegex(first, r"^[a-f0-9]{64}$")

    def test_p2_hash_rejects_invalid_vpa(self):
        self.assertIsNone(hash_vpa("not-a-vpa"))
        self.assertIsNone(hash_vpa(""))
        self.assertIsNone(hash_vpa(None))

    def test_p2_plaintext_blocklist_match_is_critical(self):
        result = validate_p2_reputation("fraud@paytm", {"fraud@paytm"})
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["id"], "blocklisted_vpa")
        self.assertEqual(result[0]["severity"], "CRITICAL")

    def test_p2_case_normalized_blocklist_match(self):
        result = validate_p2_reputation("Fraud@Paytm", {"fraud@paytm"})
        self.assertEqual(result[0]["id"], "blocklisted_vpa")

    def test_p2_clean_vpa_is_not_blocklisted(self):
        result = validate_p2_reputation("shop@okaxis", {"fraud@paytm"})
        self.assertEqual(result, [])

    def test_p2_hash_blocklist_match_is_critical(self):
        vpa_hash = hash_vpa("reported@paytm")
        result = validate_p2_reputation("reported@paytm", {vpa_hash})
        self.assertEqual(result[0]["id"], "blocklisted_vpa")

    def test_p2_analyze_payload_includes_blocklist_rule(self):
        result = analyze_upi_payload(
            "upi://pay?pa=fraud@paytm&pn=Fraud&cu=INR",
            {"fraud@paytm"},
        )
        ids = {item["id"] for item in result["reasons"]}
        self.assertIn("blocklisted_vpa", ids)
        self.assertEqual(result["verdict"], "DANGEROUS")

    def test_p2_reason_does_not_include_full_vpa(self):
        result = validate_p2_reputation("fraud@paytm", {"fraud@paytm"})
        reason_text = " ".join(item["reason"] for item in result)
        self.assertNotIn("fraud@paytm", reason_text)


if __name__ == "__main__":
    unittest.main()
