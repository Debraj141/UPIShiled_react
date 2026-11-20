import json
import re
import unicodedata
import hashlib
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set
from urllib.parse import parse_qsl, urlsplit, unquote


CONFIG: Dict[str, object] = {
    "weights": {
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
        "missing_vpa": 50,
        "bad_vpa": 50,
        "unknown_handle": 35,
        "currency": 30,
        "blocklisted_vpa": 75,
        "homoglyph": 45,
        "lookalike": 35,
        "merchant_personal": 30,
        "name_mismatch": 25,
        "high_amount": 25,
        "odd_amount": 15,
        "urgency_note": 35,
        "bad_sign": 30,
        "bad_orgid": 20,
        "missing_sign_shop": 12,
        "safe": 0,
    },
    "thresholds": {"caution": 35, "dangerous": 65},
    "limits": {
        "per_param_chars": 2048,
        "total_params_chars": 8192,
        "high_amount": 50000,
    },
    "allowed_params": {"pa", "pn", "am", "cu", "tn", "tr", "mc", "orgid", "sign"},
    "approved_handles": {
        "okaxis", "oksbi", "okhdfcbank", "okicici", "ybl", "ibl", "axl",
        "paytm", "apl", "upi", "ikwik", "rapl", "yesg", "barodampay",
        "idfcbank", "pthdfc", "aubank", "indus", "rm", "kotak", "unionbank",
        "canarabank", "sbi", "hdfcbank", "icici", "axisbank", "navia",
    },
    "url_shorteners": {
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "rebrand.ly",
        "cutt.ly", "ow.ly", "buff.ly", "shorturl.at",
    },
    "known_brands": (
        "googlepay", "gpay", "phonepe", "paytm", "amazonpay", "bhim",
        "sbi", "hdfc", "icici", "axis", "kotak", "payzapp", "freecharge",
    ),
    "urgency_words": (
        "refund", "prize", "lottery", "kyc", "cashback", "reward",
        "urgent", "winning",
    ),
    "personal_handles": {
        "ybl", "ibl", "axl", "okaxis", "oksbi", "okhdfcbank", "okicici",
    },
}

VPA_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,254}@[a-z][a-z0-9.-]{1,63}$", re.IGNORECASE)
HIDDEN_CHARS = frozenset(
    {"\u200b", "\u200c", "\u200d", "\u200e", "\u200f", "\u2060", "\ufeff"}
)
HOMOGLYPHS = str.maketrans({
    "@": "@", "0": "o", "1": "l", "3": "e", "5": "s",
    "$": "s", "\u0430": "a", "\u0441": "c", "\u0435": "e",
    "\u043e": "o", "\u0440": "p", "\u0445": "x", "\u0456": "i",
})
def _rule(rule_id: str, severity: str, reason: str) -> Dict[str, str]:
    """Create a normalized security-rule result."""
    return {"id": rule_id, "severity": severity, "reason": reason}


def _load_blocklist() -> Set[str]:
    """Load the optional local reported-VPA blocklist without logging values."""
    path = Path(__file__).with_name("upi_blocklist.json")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return {str(item).strip().lower() for item in data.get("reported_vpas", []) if str(item).strip()}
    except (OSError, json.JSONDecodeError, AttributeError):
        return set()


def hash_vpa(vpa: str) -> Optional[str]:
    """Return a stable SHA-256 hash for a valid normalized VPA."""
    if not isinstance(vpa, str):
        return None
    normalized = vpa.strip().lower()
    if not VPA_RE.fullmatch(normalized):
        return None
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def load_reported_vpa_hashes() -> Set[str]:
    """Load only reported-VPA hashes from the local JSON reputation file."""
    path = Path(__file__).with_name("upi_blocklist.json")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        values = data.get("reported_vpa_hashes", [])
        if not isinstance(values, list):
            return set()
        return {str(value).strip().lower() for value in values if re.fullmatch(r"[a-f0-9]{64}", str(value).strip(), re.I)}
    except (OSError, json.JSONDecodeError, AttributeError):
        return set()


def validate_p2_reputation(vpa: str, blocklist: Optional[Set[str]] = None) -> List[Dict[str, str]]:
    """Check P2 local reputation data against a VPA without retaining the VPA."""
    if not isinstance(vpa, str) or not VPA_RE.fullmatch(vpa.strip()):
        return []

    normalized = vpa.strip().lower()
    reported = blocklist if blocklist is not None else _load_blocklist()
    vpa_hash = hash_vpa(normalized)
    if (
        normalized in reported
        or (vpa_hash and vpa_hash in reported)
        or (vpa_hash and vpa_hash in load_reported_vpa_hashes())
    ):
        return [_rule(
            "blocklisted_vpa",
            "CRITICAL",
            "This VPA appears in the local reported-payment blocklist",
        )]
    return []


def contains_hidden_characters(value: object) -> bool:
    """Return whether text contains hidden, format or control characters."""
    if not isinstance(value, str):
        return False
    for char in value:
        if char in HIDDEN_CHARS or unicodedata.category(char) in ("Cf", "Cc"):
            return True
    return False


def _normalize(value: object) -> str:
    """Normalize text for conservative brand and name comparison."""
    if not isinstance(value, str):
        return ""
    value = unicodedata.normalize("NFKC", value or "").lower()
    value = value.translate(HOMOGLYPHS)
    return re.sub(r"[^a-z0-9]", "", value)


def _levenshtein(a: str, b: str) -> int:
    """Return the edit distance between two normalized strings."""
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


def has_bad_url_encoding(raw: str) -> bool:
    """Check malformed percent escapes and invalid URL-decoded text."""
    if not isinstance(raw, str):
        return True
    if "%" in raw:
        for match in re.finditer(r"%(?![0-9A-Fa-f]{2})", raw):
            del match
            return True
        try:
            unquote(raw, errors="strict")
        except (UnicodeDecodeError, UnicodeEncodeError):
            return True
    if re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", raw):
        return True
    return False


def detect_brand_or_homoglyph(payer_name: str, vpa: str) -> List[Dict[str, str]]:
    """Detect brand lookalikes and Unicode homoglyphs in P1 fields."""
    rules: List[Dict[str, str]] = []
    if not isinstance(payer_name, str):
        payer_name = ""
    if not isinstance(vpa, str):
        vpa = ""

    payer_normalized = _normalize(payer_name)
    local_part = _normalize(vpa.rsplit("@", 1)[0] if "@" in vpa else vpa)
    for brand in CONFIG["known_brands"]:
        for candidate in (payer_normalized, local_part):
            if len(candidate) < 5:
                continue
            distance = _levenshtein(candidate, brand)
            if brand in candidate or candidate in brand or distance <= 3:
                rules.append(_rule(
                    "lookalike",
                    "HIGH",
                    "The payee name or VPA resembles a known brand",
                ))
                break
        if any(rule["id"] == "lookalike" for rule in rules):
            break

    if payer_name:
        transformed = unicodedata.normalize("NFKC", payer_name).translate(HOMOGLYPHS)
        has_non_ascii = any(ord(char) > 127 for char in payer_name)
        if has_non_ascii:
            transformed_normalized = _normalize(transformed)
            for brand in CONFIG["known_brands"]:
                if _levenshtein(transformed_normalized, brand) <= 1:
                    rules.append(_rule(
                        "homoglyph",
                        "CRITICAL",
                        "The payee name may use lookalike Unicode characters",
                    ))
                    break
    return rules


def validate_p1_consistency(payer_name: str, vpa: str, merchant_code: str) -> List[Dict[str, str]]:
    """Check P1 merchant-name, VPA and merchant-code consistency."""
    rules: List[Dict[str, str]] = []
    if not isinstance(payer_name, str):
        payer_name = ""
    if not isinstance(vpa, str):
        vpa = ""
    if not isinstance(merchant_code, str):
        merchant_code = ""

    handle = vpa.rsplit("@", 1)[1].lower() if "@" in vpa else ""
    if merchant_code and handle in CONFIG["personal_handles"]:
        rules.append(_rule(
            "merchant_personal",
            "HIGH",
            "A merchant code is paired with a personal-looking VPA",
        ))

    if payer_name and "@" in vpa:
        name_normalized = _normalize(payer_name)
        local_normalized = _normalize(vpa.rsplit("@", 1)[0])
        if len(name_normalized) >= 5 and len(local_normalized) >= 5:
            name_tokens = set(re.findall(r"[a-z0-9]+", payer_name.lower()))
            local_tokens = set(re.findall(r"[a-z0-9]+", vpa.rsplit("@", 1)[0].lower()))
            shared_significant = bool(name_tokens & local_tokens)
            substring_match = (
                name_normalized[:8] in local_normalized
                or local_normalized[:8] in name_normalized
            )
            distance = _levenshtein(name_normalized, local_normalized)
            mismatch_threshold = max(6, int(min(len(name_normalized), len(local_normalized)) * 0.55))
            if not shared_significant and not substring_match and distance > mismatch_threshold:
                rules.append(_rule(
                    "name_mismatch",
                    "MEDIUM",
                    "The payee name does not appear to match the VPA",
                ))
    return rules


def validate_p1_amount_and_note(amount: str, note: str) -> List[Dict[str, str]]:
    """Check P1 pre-filled amount and urgency wording."""
    rules: List[Dict[str, str]] = []
    amount = amount if isinstance(amount, str) else ""
    note = note if isinstance(note, str) else ""

    if amount:
        try:
            numeric_amount = Decimal(amount)
            if numeric_amount <= 0:
                rules.append(_rule(
                    "odd_amount",
                    "MEDIUM",
                    "The pre-filled amount is zero or negative",
                ))
            elif numeric_amount >= Decimal(CONFIG["limits"]["high_amount"]):
                rules.append(_rule(
                    "high_amount",
                    "HIGH",
                    "The pre-filled amount is unusually high",
                ))
            if "." in amount:
                fraction = amount.rsplit(".", 1)[1]
                if len(fraction) == 1 or len(fraction) > 2:
                    rules.append(_rule(
                        "odd_amount",
                        "MEDIUM",
                        "The amount has an unusual decimal format",
                    ))
        except (InvalidOperation, ValueError):
            rules.append(_rule(
                "odd_amount",
                "MEDIUM",
                "The pre-filled amount is not numeric",
            ))

    urgency_pattern = r"\b(" + "|".join(re.escape(word) for word in CONFIG["urgency_words"]) + r")\b"
    if re.search(urgency_pattern, note, re.IGNORECASE):
        rules.append(_rule(
            "urgency_note",
            "HIGH",
            "The payment note contains urgent or reward wording",
        ))
    return rules


def validate_scheme(parsed_url: object) -> List[Dict[str, str]]:
    """Validate the URL scheme and UPI payment authority."""
    rules: List[Dict[str, str]] = []
    scheme = (getattr(parsed_url, "scheme", "") or "").lower()
    host = (getattr(parsed_url, "hostname", "") or "").lower().replace("www.", "")
    if scheme in ("http", "https"):
        rules.append(_rule(
            "scheme_http",
            "HIGH",
            "The link uses HTTP or HTTPS instead of a native UPI link",
        ))
        shorteners = CONFIG["url_shorteners"]
        if host in shorteners:
            rules.append(_rule(
                "scheme_shortener",
                "HIGH",
                "The payment link uses a known URL shortener",
            ))
        return rules
    if scheme and scheme != "upi":
        rules.append(_rule(
            "scheme_unknown",
            "HIGH",
            "The payment link uses an unsupported scheme",
        ))
        return rules
    authority = (getattr(parsed_url, "netloc", "") or "").lower()
    if authority == "collect":
        rules.append(_rule(
            "scheme_collect",
            "CRITICAL",
            "This is a collect request rather than a direct payment",
        ))
    elif authority != "pay":
        rules.append(_rule(
            "scheme_unknown",
            "HIGH",
            "The UPI link is not using the pay authority",
        ))
    return rules


def parse_upi_payload(raw: Optional[str]) -> Dict[str, object]:
    """Parse a UPI payload and return parameters plus duplicate keys."""
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
    if has_bad_url_encoding(query):
        return {"ok": False, "reason": "The UPI link has bad URL encoding", "scheme": "upi", "params": {}, "bad_encoding": True}

    try:
        pairs = parse_qsl(query, keep_blank_values=True, strict_parsing=False)
    except (ValueError, UnicodeDecodeError):
        return {"ok": False, "reason": "The UPI parameters could not be parsed", "scheme": "upi", "params": {}, "parse_failure": True}

    params: Dict[str, str] = {}
    key_counts: Dict[str, int] = {}
    for raw_key, raw_value in pairs:
        key = raw_key.lower()
        key_counts[key] = key_counts.get(key, 0) + 1
        if key not in params:
            params[key] = raw_value
    duplicates = sorted(key for key, count in key_counts.items() if count > 1)
    return {"ok": True, "scheme": "upi", "params": params, "duplicates": duplicates}


def analyze_upi_payload(raw: Optional[str], blocklist: Optional[Set[str]] = None) -> Dict[str, object]:
    """Analyze P0 payload validation and retain later-layer checks until P1/P2."""
    rules = []
    try:
        if not isinstance(raw, str) or not raw.strip():
            rules.append(_rule("missing_payload", "HIGH", "No UPI payment QR data was detected"))
            return _score_rules(rules)

        value = raw.strip()
        try:
            parsed_url = urlsplit(value)
            scheme = (parsed_url.scheme or "").lower()
        except ValueError:
            rules.append(_rule("parse_failure", "HIGH", "The payment link could not be parsed"))
            return _score_rules(rules)

        rules.extend(validate_scheme(parsed_url))

        parsed = parse_upi_payload(value)
        if not parsed["ok"]:
            reason = parsed.get("reason", "The UPI link could not be parsed")
            if parsed.get("bad_encoding"):
                rules.append(_rule("bad_encoding", "HIGH", "The UPI link has malformed URL encoding"))
            elif parsed.get("parse_failure"):
                rules.append(_rule("parse_failure", "HIGH", reason))
            elif scheme == "upi" and parsed_url.netloc.lower() == "collect":
                pass
            elif scheme not in ("http", "https"):
                rules.append(_rule("scheme_unknown", "HIGH", reason))

        if scheme == "upi" and parsed_url.netloc.lower() == "pay":
            params = parsed.get("params", {})
            duplicates = parsed.get("duplicates", [])
            for key in duplicates:
                rules.append(_rule("duplicate_param", "HIGH", f"The UPI parameter '{key}' appears more than once"))

            unknown = sorted(set(params) - set(CONFIG["allowed_params"]))
            for key in unknown:
                rules.append(_rule("unknown_param", "MEDIUM", f"The unrecognized UPI parameter '{key}' is present"))

            total_param_chars = sum(len(key) + len(value) for key, value in params.items())
            limits = CONFIG["limits"]
            if total_param_chars > limits["total_params_chars"]:
                rules.append(_rule("huge_value", "HIGH", "The UPI payload contains unusually large parameter data"))
            for key, param_value in params.items():
                if len(param_value) > limits["per_param_chars"]:
                    rules.append(_rule("huge_value", "HIGH", f"The '{key}' parameter is unusually large"))
                    break
                if contains_hidden_characters(param_value) or contains_hidden_characters(key):
                    rules.append(_rule("hidden_char", "HIGH", f"The '{key}' parameter contains hidden characters"))
                    break
            pa = str(params.get("pa", "")).strip()
            pn = str(params.get("pn", "")).strip()
            am = str(params.get("am", "")).strip()
            cu = str(params.get("cu", "")).strip().upper()
            tn = str(params.get("tn", "")).strip()
            mc = str(params.get("mc", "")).strip()
            orgid = str(params.get("orgid", "")).strip()
            sign = str(params.get("sign", "")).strip()

            if not pa:
                rules.append(_rule("missing_vpa", "CRITICAL", "The UPI payload does not contain a payment address"))
            else:
                if not VPA_RE.fullmatch(pa):
                    rules.append(_rule("bad_vpa", "CRITICAL", "The merchant payment address format is invalid"))
                else:
                    handle = pa.rsplit("@", 1)[1].lower()
                    approved_handles = CONFIG["approved_handles"]
                    if handle not in approved_handles:
                        rules.append(_rule("unknown_handle", "HIGH", "The VPA uses an unrecognized payment handle"))

                    rules.extend(validate_p2_reputation(pa, blocklist))

                    rules.extend(detect_brand_or_homoglyph(pn, pa))
                    rules.extend(validate_p1_consistency(pn, pa, mc))

            if cu and cu != "INR":
                rules.append(_rule("currency", "HIGH", "The requested currency is not INR"))

            rules.extend(validate_p1_amount_and_note(am, tn))

            if sign and not re.fullmatch(r"[A-Za-z0-9+/=_-]{16,512}", sign):
                rules.append(_rule("bad_sign", "HIGH", "The merchant signature has an invalid format"))
            if orgid and not re.fullmatch(r"[A-Za-z0-9._-]{2,64}", orgid):
                rules.append(_rule("bad_orgid", "MEDIUM", "The organization identifier has an invalid format"))
            if mc and not orgid and not sign:
                rules.append(_rule("missing_sign_shop", "MEDIUM", "A shop-style QR is missing organization or signature details"))
        return _score_rules(rules)
    except Exception:
        return _score_rules([
            _rule("parse_failure", "CRITICAL", "The payment details could not be checked safely")
        ])


def _score_rules(rules: Iterable[Dict[str, str]]) -> Dict[str, object]:
    """Score unique rules and return the safe fail-safe verdict."""
    rules = list(rules)
    if not rules:
        rules = [_rule("safe", "LOW", "No UPI security warning was detected")]

    weights = CONFIG["weights"]
    thresholds = CONFIG["thresholds"]
    score = 0
    for rule in rules:
        score += weights.get(rule["id"], 0)
    score = min(100, max(0, score))
    if score >= thresholds["dangerous"]:
        verdict = "DANGEROUS"
    elif score >= thresholds["caution"]:
        verdict = "CAUTION"
    else:
        verdict = "SAFE"

    severity_rank = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    unique = {}
    for rule in rules:
        unique.setdefault(rule["id"], rule)
    ordered = sorted(
        unique.values(),
        key=lambda rule: (severity_rank.get(rule["severity"], 0), weights.get(rule["id"], 0)),
        reverse=True,
    )
    return {
        "verdict": verdict,
        "risk_score": score,
        "reasons": ordered,
    }
