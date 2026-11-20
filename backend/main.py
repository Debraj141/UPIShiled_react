
from fastapi import FastAPI, UploadFile, File, HTTPException
from starlette.middleware.cors import CORSMiddleware
from PIL import Image, ImageStat
import io
import uuid
import re
import threading
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
import numpy as np

try:
    import cv2
except Exception:
    cv2 = None

try:
    import pytesseract
    import os
    if os.path.isfile(r"C:\Program Files\Tesseract-OCR\tesseract.exe"):
        pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
except Exception:
    pytesseract = None

app = FastAPI(title="UPIShield API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173"
    ],
    allow_origin_regex=r"http://(10(\.\d{1,3}){3}|192\.168(\.\d{1,3}){2}|172\.(1[6-9]|2\d|3[01])(\.\d{1,3}){2}):517[34]",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

HISTORY = []
SEEN_TRANSACTION_IDS = defaultdict(int)
LOCK = threading.Lock()
MAX_IMAGE_BYTES = 8 * 1024 * 1024

APP_SIGNATURES = {
    "Google Pay": {
        "keywords": ("google pay", "gpay", "paid successfully", "payment successful"),
        "colors": ((66, 133, 244), (52, 168, 83)),
    },
    "PhonePe": {
        "keywords": ("phonepe", "phone pe", "payment successful", "transaction id"),
        "colors": ((91, 33, 182), (255, 255, 255)),
    },
    "Paytm": {
        "keywords": ("paytm", "payment successful", "transaction id", "upi ref id"),
        "colors": ((0, 186, 242), (0, 52, 102)),
    },
}

AMOUNT_RE = re.compile(
    r"(?:₹|rs\.?\s*|inr\s*)(\d+(?:,\d{3})*(?:\.\d{1,2})?)",
    re.IGNORECASE,
)
UPI_ID_RE = re.compile(r"\b(?:[a-z0-9._-]+@[a-z][a-z0-9.-]*)\b", re.IGNORECASE)
TX_RE = re.compile(
    r"\b(?:[0-9]{12,18}|[A-Z0-9]{12,24})\b",
    re.IGNORECASE,
)
DATE_RE = re.compile(
    r"\b(?:\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{4}[/-]\d{1,2}[/-]\d{1,2})"
    r"(?:\s*,?\s*(?:at\s*)?\d{1,2}:\d{2}(?::\d{2})?(?:\s*[AP]M)?)?",
    re.IGNORECASE,
)


def extract_ocr(image):
    if pytesseract is None:
        return "", "OCR unavailable"

    try:
        if cv2 is not None:
            rgb = np.array(image.convert("RGB"))
            scale = min(1.0, 1400 / max(rgb.shape[1], 1), 2600 / max(rgb.shape[0], 1))
            rgb = cv2.resize(rgb, (max(1, int(rgb.shape[1] * scale)), max(1, int(rgb.shape[0] * scale))))
            gray = cv2.cvtColor(rgb, cv2.COLOR_RGB2GRAY)
            gray = cv2.bilateralFilter(gray, 5, 35, 35)
            prepared = Image.fromarray(gray)
        else:
            prepared = image.convert("L")
        text = pytesseract.image_to_string(prepared, config="--psm 6")
        return text.strip(), "OCR available"
    except Exception as exc:
        return "", f"OCR unavailable: {type(exc).__name__}"


def detect_app(text, image):
    lowered = text.lower()
    scores = {}
    for app_name, signature in APP_SIGNATURES.items():
        score = sum(4 for keyword in signature["keywords"] if keyword in lowered)
        if app_name.lower() in lowered:
            score += 8
        scores[app_name] = score

    rgb = np.array(image.convert("RGB").resize((64, 64)))
    for app_name, signature in APP_SIGNATURES.items():
        for target in signature["colors"]:
            distance = np.sqrt(np.sum((rgb.astype(int) - np.array(target)) ** 2, axis=2))
            scores[app_name] += int(np.mean(distance < 35) * 4)

    best_app, best_score = max(scores.items(), key=lambda item: item[1])
    if best_score >= 8:
        return best_app, min(99, 55 + best_score * 3)
    return "Unknown", 20


def parse_timestamp(text):
    match = DATE_RE.search(text)
    if not match:
        return None, "No timestamp detected"

    raw = match.group(0).strip()
    normalized = raw.replace(" at ", " ").replace("At ", "").replace(",", "")
    formats = (
        "%d/%m/%Y %H:%M:%S",
        "%d/%m/%Y %H:%M",
        "%d-%m-%Y %H:%M:%S",
        "%d-%m-%Y %H:%M",
        "%d/%m/%y %H:%M",
        "%d-%m-%y %H:%M",
        "%Y/%m/%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%d/%m/%Y",
        "%d-%m-%Y",
        "%Y/%m/%d",
        "%Y-%m-%d",
    )
    for fmt in formats:
        try:
            parsed = datetime.strptime(normalized, fmt)
            return parsed.strftime("%d %b %Y, %H:%M"), None
        except ValueError:
            continue
    return raw, None


def timestamp_is_impossible(text):
    match = DATE_RE.search(text)
    if not match:
        return True, "Timestamp could not be read"

    raw = match.group(0).replace(",", "")
    parsed = None
    for fmt in (
        "%d/%m/%Y %H:%M:%S", "%d/%m/%Y %H:%M", "%d-%m-%Y %H:%M:%S",
        "%d-%m-%Y %H:%M", "%d/%m/%y %H:%M", "%d-%m-%y %H:%M",
        "%Y/%m/%d %H:%M:%S", "%Y-%m-%d %H:%M:%S",
        "%d/%m/%Y", "%d-%m-%Y", "%Y/%m/%d", "%Y-%m-%d",
    ):
        try:
            candidate = raw.replace(" at ", " ")
            parsed = datetime.strptime(candidate, fmt)
            break
        except ValueError:
            continue

    if parsed is None:
        return True, "Timestamp format could not be validated"

    now = datetime.now()
    age_seconds = (now - parsed).total_seconds()
    if parsed > now:
        return True, "Timestamp is in the future"
    if age_seconds > 365 * 24 * 60 * 60:
        return True, "Timestamp is older than one year"
    return False, "Timestamp is plausible"


def extract_details(text):
    amount = None
    amount_match = AMOUNT_RE.search(text)
    if amount_match:
        amount = amount_match.group(1).replace(",", "")
    if amount is None:
        fallback_amount = re.findall(r"(?<![A-Z0-9])(?:\d{1,3}(?:,\d{3})*(?:\.\d{1,2})|\d+(?:\.\d{1,2}))(?![A-Z0-9])", text, re.IGNORECASE)
        if fallback_amount:
            amount = max(fallback_amount, key=len).replace(",", "")

    transaction_id = None
    tx_label = re.search(
        r"(?:transaction id|txn id|upi ref(?:erence)?(?: id)?|utr(?: id)?|reference number)\s*[:\-]?\s*([A-Z0-9]{8,24})",
        text,
        re.IGNORECASE,
    )
    if tx_label:
        transaction_id = tx_label.group(1).upper()
    else:
        candidates = TX_RE.findall(text)
        if candidates:
            transaction_id = max(candidates, key=len).upper()

    timestamp, _ = parse_timestamp(text)
    upi_match = UPI_ID_RE.search(text)
    return {
        "amount": amount,
        "transaction_id": transaction_id,
        "timestamp": timestamp,
        "upi_id": upi_match.group(0) if upi_match else None,
    }


def pixel_consistency(image):
    gray = image.convert("L").resize((320, 640))
    pixels = np.array(gray)
    variance = float(pixels.var())
    stat = ImageStat.Stat(gray)
    contrast = float(stat.extrema[0][1] - stat.extrema[0][0])

    edges = 0
    if cv2 is not None:
        edges = int(cv2.Canny(pixels.astype(np.uint8), 80, 160).mean() * 255)
        edge_ratio = float(cv2.countNonZero(cv2.Canny(pixels.astype(np.uint8), 80, 160)) / pixels.size)
    else:
        edge_ratio = 0.0

    if variance < 150 or contrast < 25:
        return "REVIEW", "Low visual detail or possible blank/cropped image"
    if edge_ratio > 0.28:
        return "REVIEW", "Unusually dense or heavily edited pixel structure"
    return "PASS", "Font and pixel structure look consistent"

@app.get("/health")
def health():
    return {"status": "UPIShield backend running"}


@app.get("/api/v1/history")
def history():
    with LOCK:
        return {"items": list(reversed(HISTORY))}


@app.post("/api/v1/analyze")
async def analyze(file: UploadFile = File(...)):
    if file.content_type not in [
        "image/jpeg", "image/png", "image/webp"
    ]:
        raise HTTPException(400, "Please upload a valid image")

    image_bytes = await file.read()

    if not image_bytes:
        raise HTTPException(400, "Empty image")
    if len(image_bytes) > MAX_IMAGE_BYTES:
        raise HTTPException(400, "Image must be smaller than 8 MB")

    started = time.perf_counter()

    try:
        image = Image.open(io.BytesIO(image_bytes))
        image.verify()
    except Exception:
        raise HTTPException(400, "Invalid image file")

    image = Image.open(io.BytesIO(image_bytes)).convert("RGB")
    text, ocr_status = extract_ocr(image)
    details = extract_details(text)
    app_detected, app_confidence = detect_app(text, image)

    checks = [{
        "name": "Image validation",
        "status": "PASS",
        "message": f"{image.width}x{image.height} valid image received",
    }]
    risk = 0

    pixel_status, pixel_message = pixel_consistency(image)
    checks.append({
        "name": "Font and pixel consistency",
        "status": pixel_status,
        "message": pixel_message,
    })
    if pixel_status != "PASS":
        risk += 25

    if pytesseract is None or not text:
        checks.append({
            "name": "OCR and text extraction",
            "status": "REVIEW",
            "message": ocr_status if ocr_status.startswith("OCR") else "Text could not be extracted",
        })
        risk += 20
    else:
        checks.append({
            "name": "OCR and text extraction",
            "status": "PASS",
            "message": "Payment text extracted for forensic checks",
        })

    if app_detected == "Unknown":
        checks.append({
            "name": "UPI layout recognition",
            "status": "REVIEW",
            "message": "No supported layout was recognized with sufficient confidence",
        })
        risk += 25
    else:
        lowered = text.lower()
        required_success = "payment successful" in lowered or "paid successfully" in lowered
        app_keyword_present = app_detected.lower() in lowered or any(
            keyword in lowered
            for keyword in APP_SIGNATURES[app_detected]["keywords"][:2]
        )
        layout_ok = required_success and app_keyword_present
        checks.append({
            "name": "UPI layout recognition",
            "status": "PASS" if layout_ok else "REVIEW",
            "message": (
                f"Recognized as {app_detected} layout"
                if layout_ok
                else f"{app_detected} layout was detected, but expected confirmation labels are missing"
            ),
        })
        if not layout_ok:
            risk += 35

    impossible, timestamp_message = timestamp_is_impossible(text)
    checks.append({
        "name": "Timestamp validation",
        "status": "REVIEW" if impossible else "PASS",
        "message": timestamp_message,
    })
    if impossible:
        risk += 30

    reused_count = 0
    transaction_id = details["transaction_id"]
    if transaction_id:
        with LOCK:
            SEEN_TRANSACTION_IDS[transaction_id] += 1
            reused_count = SEEN_TRANSACTION_IDS[transaction_id]
        reuse_status = "REVIEW" if reused_count > 1 else "PASS"
        reuse_message = (
            "Transaction ID was reused in a previous analysis"
            if reused_count > 1
            else "Transaction ID has not been reused in this session"
        )
        if reused_count > 1:
            risk += 40
    else:
        reuse_status = "REVIEW"
        reuse_message = "No transaction or UTR ID could be extracted"
        risk += 15
    checks.append({
        "name": "Reused transaction ID",
        "status": reuse_status,
        "message": reuse_message,
    })

    risk_score = min(100, risk)
    has_core_details = bool(details["amount"] and transaction_id and details["timestamp"])
    if app_detected == "Unknown" or pytesseract is None or not text or not has_core_details:
        verdict = "INCONCLUSIVE"
    elif risk_score >= 40:
        verdict = "SUSPICIOUS"
    else:
        verdict = "REAL"

    if verdict == "REAL":
        summary = "The screenshot matches the recognized layout and passed the available forensic checks."
    elif verdict == "SUSPICIOUS":
        summary = "One or more strong authenticity indicators failed. Verify the payment in the official app."
    else:
        summary = "The evidence is incomplete. Verify the payment directly in the official UPI or bank app."

    elapsed_ms = round((time.perf_counter() - started) * 1000)
    analysis_id = str(uuid.uuid4())
    result = {
        "analysis_id": analysis_id,
        "app_detected": app_detected,
        "verdict": verdict,
        "risk_score": risk_score,
        "confidence": round(app_confidence / 100, 2),
        "extracted_data": details,
        "checks": checks,
        "summary": summary,
        "processing_ms": elapsed_ms,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    with LOCK:
        HISTORY.append({**result, "id": analysis_id})
        if len(HISTORY) > 100:
            del HISTORY[:-100]
    return result


frontend_dir = Path(__file__).resolve().parent.parent / "dist"
if frontend_dir.is_dir():
    from fastapi.staticfiles import StaticFiles

    app.mount("/", StaticFiles(directory=str(frontend_dir), html=True), name="frontend")
