import json
import re
import unicodedata
from pathlib import Path
from urllib.parse import parse_qs, urlsplit, unquote


SECURITY_WEIGHTS = {
    "scheme_http": 55,
    "scheme_collect": 65,
    "scheme_unknown": 55,
    "missing_payload": 35,
    "parse_failure": 60,
    "duplicate_param": 25,
    "unknown_param": 8,
    "bad_encoding": 35,
    "hidden_char": 30,
    "huge_value": 30,
    "bad_vpa": 50,
    "unknown_handle": 35,
    "blocklisted_vpa": 75,
    "homoglyph": 45,
    "lookalike": 35,
    "merchant_personal": 30,
    "name_mismatch": 25,
    "currency": 30,
    "high_amount": 25,
    "odd_amount": 15,
    "urgency_note": 35,
    "bad_sign": 30,
    "bad_orgid": 20,
    "missing_sign_shop": 12,
    "safe": 0,
    "caution_threshold": 35,
    "dangerous_threshold": 65,
}

ALLOWED_PARAMS = {"pa", "pn", "am", "cu", "tn", "tr", "mc", "orgid", "sign"}
VPA_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,254}@[a-z][a-z0-9.-]{1,63}$", re.IGNORECASE)
APPROVED_HANDLES = {
    "okaxis", "oksbi", "okhdfcbank", "okicici", "ybl", "ibl", "axl",
    "paytm", "apl", "upi", "ikwik", "rapl", "yesg", "barodampay",
    "idfcbank", "pthdfc", "aubank", "indus", "rm", "kotak", "unionbank",
    "canarabank", "sbi", "hdfcbank", "icici", "axisbank", "navia",
}
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "rebrand.ly",
    "cutt.ly", "ow.ly", "buff.ly", "shorturl.at",
}
HIDDEN_CHARS = frozenset(
    {"\u200b", "\u200c", "\u200d", "\u200e", "\u200f", "\u2060", "\ufeff"}
)
HOMOGLYPHS = str.maketrans({
    "@": "@", "0": "o", "1": "l", "3": "e", "5": "s",
    "$": "s", "\u0430": "a", "\u0441": "c", "\u0435": "e",
    "\u043e": "o", "\u0440": "p", "\u0445": "x", "\u0456": "i",
})
BRAND_NAMES = (
    "googlepay", "gpay", "phonepe", "paytm", "amazonpay", "bhim",
    "sbi", "hdfc", "icici", "axis", "kotak", "payzapp", "freecharge",
)
PERSONAL_HANDLES = {"ybl", "ibl", "axl", "okaxis", "oksbi", "okhdfcbank", "okicici"}


def _rule(rule_id, severity, reason):
    return {"id": rule_id, "severity": severity, "reason": reason}


def _load_blocklist():
    path = Path(__file__).with_name("upi_blocklist.json")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return {str(item).strip().lower() for item in data.get("reported_vpas", []) if str(item).strip()}
    except (OSError, json.JSONDecodeError, AttributeError):
        return set()


def _contains_hidden(value):
    if not isinstance(value, str):
        return False
    for char in value:
        if char in HIDDEN_CHARS or unicodedata.category(char) in ("Cf", "Cc"):
            return True
    return False


def _normalize(value):
    value = unicodedata.normalize("NFKC", value or "").lower()
    value = value.translate(HOMOGLYPHS)
    return re.sub(r"[^a-z0-9]", "", value)


def _levenshtein(a, b):
    if len(a) < len(b):
        a, b = b, a
    previous = list(range(len(b) + 1))
    for index, char_a in enumerate(a, 1):
        current = [index]
        for index_b, char_b in enumerate(b, 1):
            current.append(min(
                current[-1] + 1,
                previous[index_b] + 1,
                previous[index_b - 1] + (char_a != char_b),
            ))
        previous = current
    return previous[-1]


def _has_bad_encoding(raw):
    if "%" in raw:
        percent_tokens = re.findall(r"%[0-9A-Fa-f]{0,2}", raw)
        if any(not re.fullmatch(r"%[0-9A-Fa-f]{2}", token) for token in percent_tokens):
            return True
        try:
            unquote(raw, errors="strict")
        except (UnicodeDecodeError, UnicodeEncodeError):
            return True
    return False


def parse_upi_payload(raw):
    if not isinstance(raw, str) or not raw.strip():
        return {"ok": False, "reason": "No UPI QR data was found", "scheme": None, "params": {}}

    value = raw.strip()
    try:
        parts = urlsplit(value)
    except ValueError:
        return {"ok": False, "reason": "The UPI link could not be parsed", "scheme": None, "params": {}}

    scheme = (parts.scheme or "").lower()
    if scheme != "upi":
        return {"ok": False, "reason": "The link does not use the UPI scheme", "scheme": scheme, "params": {}}

    if parts.netloc.lower() != "pay":
        return {"ok": False, "reason": "The UPI link is not a payment request", "scheme": "upi", "params": {}}

    query = parts.query
    if _has_bad_encoding(query):
        return {"ok": False, "reason": "The UPI link has bad URL encoding", "scheme": "upi", "params": {}, "bad_encoding": True}

    try:
        parsed = parse_qs(query, keep_blank_values=True, strict_parsing=False)
    except (ValueError, UnicodeDecodeError):
        return {"ok": False, "reason": "The UPI parameters could not be parsed", "scheme": "upi", "params": {}, "parse_failure": True}

    params = {key.lower(): values[0] for key, values in parsed.items()}
    duplicates = sorted({key.lower() for key, values in parsed.items() if len(values) > 1})
    return {"ok": True, "scheme": "upi", "params": params, "duplicates": duplicates}


def analyze_upi_payload(raw, blocklist=None):
    rules = []
    try:
        if not isinstance(raw, str) or not raw.strip():
            rules.append(_rule("missing_payload", "high", "No UPI payment QR data was detected"))
            return _score_rules(rules)

        value = raw.strip()
        try:
            parsed_url = urlsplit(value)
            scheme = (parsed_url.scheme or "").lower()
        except ValueError:
            rules.append(_rule("parse_failure", "high", "The payment link could not be parsed"))
            return _score_rules(rules)

        if scheme in ("http", "https"):
            rules.append(_rule("scheme_http", "high", "The payment link uses HTTP or HTTPS instead of UPI"))
        elif scheme and scheme != "upi":
            rules.append(_rule("scheme_unknown", "high", "The payment link uses an unknown or unsafe scheme"))

        if scheme == "upi":
            if (parsed_url.netloc or "").lower() == "collect":
                rules.append(_rule("scheme_collect", "critical", "This is a collect request rather than a direct payment"))
            elif (parsed_url.netloc or "").lower() != "pay":
                rules.append(_rule("scheme_unknown", "high", "The UPI authority is not the payment action"))

        parsed = parse_upi_payload(value)
        if not parsed["ok"]:
            reason = parsed.get("reason", "The UPI link could not be parsed")
            if parsed.get("bad_encoding"):
                rules.append(_rule("bad_encoding", "high", "The UPI link has malformed URL encoding"))
            elif parsed.get("parse_failure"):
                rules.append(_rule("parse_failure", "high", reason))
            elif scheme == "upi" and parsed_url.netloc.lower() == "collect":
                pass
            elif scheme not in ("http", "https"):
                rules.append(_rule("scheme_unknown", "high", reason))

        if scheme == "upi" and parsed_url.netloc.lower() == "pay":
            params = parsed.get("params", {})
            duplicates = parsed.get("duplicates", [])
            for key in duplicates:
                rules.append(_rule("duplicate_param", "high", f"The UPI parameter '{key}' appears more than once"))

            unknown = sorted(set(params) - ALLOWED_PARAMS)
            for key in unknown:
                rules.append(_rule("unknown_param", "medium", f"The unrecognized UPI parameter '{key}' is present"))

            for key, param_value in params.items():
                if len(param_value) > 2048:
                    rules.append(_rule("huge_value", "high", f"The '{key}' parameter is unusually large"))
                    break
                if _contains_hidden(param_value):
                    rules.append(_rule("hidden_char", "high", f"The '{key}' parameter contains hidden characters"))
                    break

            pa = str(params.get("pa", "")).strip()
            pn = str(params.get("pn", "")).strip()
            am = str(params.get("am", "")).strip()
            cu = str(params.get("cu", "")).strip().upper()
            tn = str(params.get("tn", "")).strip()
            mc = str(params.get("mc", "")).strip()
            orgid = str(params.get("orgid", "")).strip()
            sign = str(params.get("sign", "")).strip()

            if pa:
                if not VPA_RE.fullmatch(pa):
                    rules.append(_rule("bad_vpa", "critical", "The merchant payment address format is invalid"))
                else:
                    handle = pa.rsplit("@", 1)[1].lower()
                    if handle not in APPROVED_HANDLES:
                        rules.append(_rule("unknown_handle", "high", "The VPA uses an unrecognized payment handle"))

                    normalized_vpa = _normalize(pa.rsplit("@", 1)[0])
                    reported = blocklist if blocklist is not None else _load_blocklist()
                    if pa.lower() in reported:
                        rules.append(_rule("blocklisted_vpa", "critical", "This VPA appears in the reported-payment blocklist"))

                    normalized_pn = _normalize(pn)
                    normalized_name = normalized_pn or ""
                    for brand in BRAND_NAMES:
                        for candidate in (normalized_vpa, normalized_name):
                            if candidate and len(candidate) >= 5:
                                distance = _levenshtein(candidate, brand)
                                if (
                                    brand in candidate
                                    or candidate in brand
                                    or distance <= 3
                                ):
                                    rules.append(_rule("lookalike", "high", "The payee name or VPA resembles a known brand"))
                                    break
                        if any(r["id"] == "lookalike" for r in rules):
                            break

                    if pn:
                        homoglyph_pn = pn.translate(HOMOGLYPHS)
                        pn_chars = {unicodedata.category(char) for char in pn}
                        if homoglyph_pn != pn or not pn_chars.isdisjoint({"Cf"}):
                            for brand in BRAND_NAMES:
                                normalized_brand = _normalize(brand)
                                if _levenshtein(_normalize(homoglyph_pn), normalized_brand) <= 1:
                                    rules.append(_rule("homoglyph", "critical", "The payee name may use lookalike Unicode characters"))
                                    break

                    if mc and handle in PERSONAL_HANDLES:
                        rules.append(_rule("merchant_personal", "high", "A merchant code is paired with a personal-looking VPA"))

                    if pn:
                        local_part = _normalize(pa.rsplit("@", 1)[0])
                        normalized_pn = _normalize(pn)
                        if normalized_pn and local_part:
                            shared = normalized_pn[:8] in local_part or local_part[:8] in normalized_pn
                            if len(normalized_pn) >= 8 and len(local_part) >= 8 and not shared:
                                distance = _levenshtein(normalized_pn, local_part)
                                mismatch_threshold = max(6, int(min(len(normalized_pn), len(local_part)) * 0.55))
                                if distance > mismatch_threshold:
                                    rules.append(_rule("name_mismatch", "medium", "The payee name does not appear to match the VPA"))

            if cu and cu != "INR":
                rules.append(_rule("currency", "high", "The requested currency is not INR"))

            try:
                amount = float(am)
                if amount <= 0:
                    rules.append(_rule("odd_amount", "medium", "The pre-filled amount is zero or negative"))
                elif amount >= 50000:
                    rules.append(_rule("high_amount", "high", "The pre-filled amount is unusually high"))
                elif am and "." in am:
                    cents = am.rsplit(".", 1)[1]
                    if len(cents) == 1:
                        rules.append(_rule("odd_amount", "medium", "The amount format is unusual"))
            except (TypeError, ValueError):
                if am:
                    rules.append(_rule("odd_amount", "medium", "The pre-filled amount is not numeric"))

            if re.search(r"\b(refund|prize|lottery|kyc|cashback|reward|urgent|winning)\b", tn, re.I):
                rules.append(_rule("urgency_note", "high", "The payment note contains urgent or reward wording"))

            if sign and not re.fullmatch(r"[A-Za-z0-9+/=_-]{16,512}", sign):
                rules.append(_rule("bad_sign", "high", "The merchant signature has an invalid format"))
            if orgid and not re.fullmatch(r"[A-Za-z0-9._-]{2,64}", orgid):
                rules.append(_rule("bad_orgid", "medium", "The organization identifier has an invalid format"))
            if mc and not orgid and not sign:
                rules.append(_rule("missing_sign_shop", "medium", "A shop-style QR is missing organization or signature details"))
        elif scheme in ("http", "https"):
            if any(host in URL_SHORTENERS for host in (parsed_url.netloc.lower().replace("www.", ""), parsed_url.hostname or "")):
                rules.append(_rule("scheme_http", "high", "The link uses a URL shortener"))

        return _score_rules(rules)
    except Exception:
        return _score_rules([
            _rule("parse_failure", "critical", "The payment details could not be checked safely")
        ])


def _score_rules(rules):
    if not rules:
        rules = [_rule("safe", "low", "No UPI security warning was detected")]

    score = 0
    for rule in rules:
        score += SECURITY_WEIGHTS.get(rule["id"], 0)
    score = min(100, max(0, score))
    if score >= SECURITY_WEIGHTS["dangerous_threshold"]:
        verdict = "DANGEROUS"
    elif score >= SECURITY_WEIGHTS["caution_threshold"]:
        verdict = "CAUTION"
    else:
        verdict = "SAFE"

    severity_rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    unique = {}
    for rule in rules:
        unique.setdefault(rule["id"], rule)
    ordered = sorted(
        unique.values(),
        key=lambda rule: (severity_rank.get(rule["severity"], 0), SECURITY_WEIGHTS.get(rule["id"], 0)),
        reverse=True,
    )
    return {
        "verdict": verdict,
        "risk_score": score,
        "reasons": ordered,
    }
