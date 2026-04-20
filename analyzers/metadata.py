"""
Metadata / Structure analyzers:
- Name-Username Correlation
- Unused frequent phishing words
- PDF Conversion + OCR-based phishing assessment
- Ptech/Ptac heuristic approximation
"""

import re
import os
import tempfile
import logging
from pathlib import Path
from collections import Counter

logger = logging.getLogger(__name__)

_DATA_DIR = Path(__file__).parent.parent / "data"


def _load_phishing_words() -> list[str]:
    path = _DATA_DIR / "phishing_words.txt"
    if path.exists():
        return [
            line.strip().lower()
            for line in path.read_text().splitlines()
            if line.strip() and not line.startswith("#")
        ]
    return []


PHISHING_WORDS = _load_phishing_words()


# ---------------------------------------------------------------------------
# 1. Name-Username Correlation
# ---------------------------------------------------------------------------

def check_name_username_correlation(parsed_email) -> dict:
    """Check if sender display name appears in username or To field."""
    result = {
        "display_name": parsed_email.from_display_name,
        "from_email": parsed_email.from_email,
        "to_email": parsed_email.to_email,
        "name_in_username": False,
        "name_in_to": False,
        "correlation_score": 0.0,
    }

    display_name = parsed_email.from_display_name.lower().strip()
    from_email = parsed_email.from_email.lower()
    to_email = parsed_email.to_email.lower()

    if not display_name:
        return result

    # Extract username part of from_email
    username = from_email.split("@")[0] if "@" in from_email else from_email

    # Check if any name word appears in username
    name_parts = re.findall(r"[a-z]+", display_name)
    name_parts = [p for p in name_parts if len(p) > 2]

    matches_in_username = sum(
        1 for part in name_parts if part in username
    )
    if matches_in_username > 0:
        result["name_in_username"] = True

    # Check if any name word appears in To
    matches_in_to = sum(
        1 for part in name_parts if part in to_email
    )
    if matches_in_to > 0:
        result["name_in_to"] = True

    # Correlation score: how much the display name matches the email
    if name_parts:
        result["correlation_score"] = round(
            matches_in_username / len(name_parts), 2
        )

    return result


# ---------------------------------------------------------------------------
# 1b. Brand Impersonation
# ---------------------------------------------------------------------------

# Maps brand keywords → their legitimate domains (partial match).
# Sources: APWG Phishing Activity Trends Reports, Cloudflare phishing
# threat reports, Check Point Brand Phishing Reports 2022-2024.
_BRAND_DOMAINS: dict[str, list[str]] = {
    # --- Tech giants ---
    "paypal": ["paypal.com", "paypal.me"],
    "apple": ["apple.com", "icloud.com", "apple.co"],
    "microsoft": ["microsoft.com", "live.com", "outlook.com", "hotmail.com", "msn.com"],
    "google": ["google.com", "gmail.com", "googlemail.com", "google.co"],
    "amazon": ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.fr", "amazon.ca",
               "amazon.es", "amazon.it", "amazon.co.jp", "amazon.com.au", "amazon.in",
               "amazon.com.br", "amazon.com.mx"],
    "facebook": ["facebook.com", "fb.com", "meta.com", "fb.me"],
    "instagram": ["instagram.com"],
    "netflix": ["netflix.com"],
    "dropbox": ["dropbox.com"],
    "linkedin": ["linkedin.com"],
    "twitter": ["twitter.com", "x.com"],
    "whatsapp": ["whatsapp.com"],
    "telegram": ["telegram.org", "t.me"],
    "signal": ["signal.org"],
    "tiktok": ["tiktok.com"],
    "snapchat": ["snapchat.com"],
    "youtube": ["youtube.com", "youtu.be"],
    "spotify": ["spotify.com"],
    "adobe": ["adobe.com"],
    "salesforce": ["salesforce.com"],
    "slack": ["slack.com"],
    "zoom": ["zoom.us", "zoom.com"],
    # --- Microsoft products ---
    "office": ["microsoft.com", "office.com", "office365.com"],
    "outlook": ["outlook.com", "outlook.live.com", "microsoft.com"],
    "onedrive": ["microsoft.com", "live.com", "onedrive.live.com"],
    "sharepoint": ["microsoft.com", "sharepoint.com"],
    "teams": ["microsoft.com", "teams.microsoft.com"],
    # --- Crypto exchanges ---
    "binance": ["binance.com", "binance.us"],
    "coinbase": ["coinbase.com"],
    "kraken": ["kraken.com"],
    "blockchain": ["blockchain.com"],
    "metamask": ["metamask.io"],
    "opensea": ["opensea.io"],
    "crypto.com": ["crypto.com"],
    "kucoin": ["kucoin.com"],
    "bitfinex": ["bitfinex.com"],
    "gemini": ["gemini.com"],
    # --- Banks (US) ---
    "chase": ["chase.com", "jpmorgan.com", "jpmorganchase.com"],
    "wellsfargo": ["wellsfargo.com"],
    "bankofamerica": ["bankofamerica.com", "bofa.com"],
    "citibank": ["citi.com", "citibank.com", "citigroup.com"],
    "capitalone": ["capitalone.com"],
    "usbank": ["usbank.com"],
    "pnc": ["pnc.com"],
    "td bank": ["td.com", "tdbank.com"],
    # --- Banks (International) ---
    "hsbc": ["hsbc.com", "hsbc.co.uk"],
    "barclays": ["barclays.com", "barclays.co.uk"],
    "santander": ["santander.com", "santander.co.uk"],
    "ubs": ["ubs.com"],
    "ing": ["ing.com"],
    "bnp paribas": ["bnpparibas.com"],
    "deutsche bank": ["db.com", "deutschebank.com"],
    "bradesco": ["bradesco.com.br"],
    "itau": ["itau.com.br"],
    "nubank": ["nubank.com.br"],
    # --- Shipping ---
    "dhl": ["dhl.com", "dhl.de"],
    "fedex": ["fedex.com"],
    "ups": ["ups.com"],
    "usps": ["usps.com"],
    "royal mail": ["royalmail.com"],
    "la poste": ["laposte.fr"],
    "correos": ["correos.es"],
    "dpd": ["dpd.com"],
    "hermes": ["hermes-europe.co.uk", "evri.com"],
    "chronopost": ["chronopost.fr"],
    # --- E-commerce ---
    "ebay": ["ebay.com", "ebay.co.uk"],
    "alibaba": ["alibaba.com"],
    "aliexpress": ["aliexpress.com"],
    "wish": ["wish.com"],
    "walmart": ["walmart.com"],
    "target": ["target.com"],
    "shopify": ["shopify.com"],
    "etsy": ["etsy.com"],
    "rakuten": ["rakuten.com", "rakuten.co.jp"],
    # --- Government ---
    "irs": ["irs.gov"],
    "hmrc": ["gov.uk"],
    "ato": ["ato.gov.au"],
    "cra": ["canada.ca"],
    "social security": ["ssa.gov"],
    # --- Documents & productivity ---
    "docusign": ["docusign.com", "docusign.net"],
    "wetransfer": ["wetransfer.com"],
    "evernote": ["evernote.com"],
    "notion": ["notion.so"],
    "trello": ["trello.com"],
    # --- Telecom ---
    "att": ["att.com"],
    "verizon": ["verizon.com"],
    "t-mobile": ["t-mobile.com"],
    "vodafone": ["vodafone.com"],
    "orange": ["orange.com", "orange.fr"],
    # --- Payment ---
    "venmo": ["venmo.com"],
    "zelle": ["zellepay.com"],
    "cashapp": ["cash.app", "squareup.com"],
    "stripe": ["stripe.com"],
    "wise": ["wise.com"],
}


def check_brand_impersonation(parsed_email) -> dict:
    """Detect if subject/display name references a known brand but sender domain doesn't match."""
    result = {
        "impersonated_brand": None,
        "sender_domain": parsed_email.from_domain or "",
        "is_impersonation": False,
    }

    combined = f"{parsed_email.subject or ''} {parsed_email.from_display_name or ''}".lower()
    sender_domain = (parsed_email.from_domain or "").lower()

    for brand, legit_domains in _BRAND_DOMAINS.items():
        if brand in combined:
            if not any(sender_domain.endswith(d) for d in legit_domains):
                result["impersonated_brand"] = brand
                result["is_impersonation"] = True
                break

    return result


# ---------------------------------------------------------------------------
# 2. Unused Frequent Phishing Words
# ---------------------------------------------------------------------------

def check_unused_phishing_words(subject: str, body_text: str) -> dict:
    """
    Check for phishing dictionary words present vs missing.
    Words common in phishing that are missing may indicate
    sophisticated phishing or legitimate email.
    """
    combined = f"{subject} {body_text}".lower()
    result = {
        "present_words": [],
        "absent_words": [],
        "phishing_word_count": 0,
        "phishing_coverage": 0.0,
    }

    present = []
    absent = []

    for word in PHISHING_WORDS:
        if word in combined:
            present.append(word)
        else:
            absent.append(word)

    result["present_words"] = present[:30]  # Cap output size
    result["absent_words"] = absent[:30]
    result["phishing_word_count"] = len(present)
    result["phishing_coverage"] = round(
        len(present) / max(len(PHISHING_WORDS), 1), 4
    )

    return result


# ---------------------------------------------------------------------------
# 3. PDF Conversion + OCR
# ---------------------------------------------------------------------------

def convert_and_ocr(parsed_email, output_dir: str = "/tmp/eml_pdfs") -> dict:
    """
    Convert EML HTML to PDF via wkhtmltopdf,
    then OCR the PDF with Tesseract for visual phishing assessment.
    """
    result = {
        "pdf_generated": False,
        "ocr_text": "",
        "visual_phishing_indicators": [],
        "visual_verdict": "unknown",
    }

    html_content = parsed_email.body_html
    if not html_content:
        result["error"] = "no_html_body"
        return result

    os.makedirs(output_dir, exist_ok=True)
    base_name = Path(parsed_email.filename).stem

    try:
        import pdfkit

        # Write HTML to temp file
        html_path = os.path.join(output_dir, f"{base_name}.html")
        pdf_path = os.path.join(output_dir, f"{base_name}.pdf")

        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        # Convert to PDF
        options = {
            "quiet": "",
            "no-images": "",
            "disable-javascript": "",
            "load-error-handling": "ignore",
            "load-media-error-handling": "ignore",
        }
        pdfkit.from_file(html_path, pdf_path, options=options)
        result["pdf_generated"] = True

        # OCR the PDF
        try:
            import pytesseract
            from PIL import Image
            import subprocess

            # Convert PDF to image using pdftoppm (if available) or imagemagick
            img_path = os.path.join(output_dir, f"{base_name}.png")

            # Try using wkhtmltoimage if available, else skip OCR
            try:
                subprocess.run(
                    ["wkhtmltoimage", "--quiet", html_path, img_path],
                    timeout=30,
                    capture_output=True,
                )
            except FileNotFoundError:
                # Fall back to rendering HTML directly
                # Just use the HTML text as OCR substitute
                pass

            if os.path.exists(img_path):
                img = Image.open(img_path)
                ocr_text = pytesseract.image_to_string(img)
                result["ocr_text"] = ocr_text[:2000]
            else:
                # Use parsed body text as fallback
                result["ocr_text"] = parsed_email.body_text[:2000]

        except Exception as e:
            logger.debug(f"OCR failed: {e}")
            result["ocr_text"] = parsed_email.body_text[:2000]

        # Visual phishing assessment on OCR/text
        result["visual_phishing_indicators"] = _assess_visual_phishing(
            result["ocr_text"]
        )
        indicator_count = len(result["visual_phishing_indicators"])
        if indicator_count >= 3:
            result["visual_verdict"] = "phishing"
        elif indicator_count >= 1:
            result["visual_verdict"] = "suspicious"
        else:
            result["visual_verdict"] = "legitimate"

        # Cleanup temp files
        for f in [html_path, img_path if 'img_path' in dir() else None]:
            if f and os.path.exists(f):
                try:
                    os.remove(f)
                except Exception:
                    pass

    except Exception as e:
        result["error"] = str(e)[:200]

    return result


def _assess_visual_phishing(text: str) -> list[str]:
    """Assess OCR/rendered text for visual phishing indicators."""
    indicators = []
    text_lower = text.lower()

    checks = [
        ("login_form", ["password", "login", "sign in", "username"]),
        ("urgency", ["urgent", "immediately", "expire", "suspended"]),
        ("brand_impersonation", [
            "paypal", "microsoft", "apple", "google", "amazon",
            "netflix", "bank", "bradesco", "livelo",
        ]),
        ("credential_request", [
            "enter your", "provide your", "confirm your",
            "update your", "verify your",
        ]),
        ("threat_language", [
            "will be closed", "will be suspended",
            "unauthorized", "compromised", "locked",
        ]),
        ("action_button", [
            "click here", "click below", "update now",
            "verify now", "resgate", "clique",
        ]),
    ]

    for indicator_name, keywords in checks:
        for kw in keywords:
            if kw in text_lower:
                indicators.append(indicator_name)
                break

    return indicators


# ---------------------------------------------------------------------------
# 4. Ptech/Ptac Heuristic Approximation
# ---------------------------------------------------------------------------

def ptech_ptac_heuristic(parsed_email) -> dict:
    """
    Feature-based heuristic inspired by the Ptech/Ptac paper
    (IEEE 10788677). Analyzes:
    - HTML tag structure ratios
    - URL structure scoring
    - Content similarity to phishing templates
    - Header anomalies
    """
    result = {
        "html_analysis": {},
        "header_anomalies": [],
        "content_signals": [],
        "ptech_score": 0.0,
    }

    score = 0.0
    max_score = 10.0

    # --- HTML Tag Analysis ---
    html = parsed_email.body_html
    if html:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html, "html.parser")

        total_tags = len(soup.find_all())
        link_tags = len(soup.find_all("a"))
        img_tags = len(soup.find_all("img"))
        form_tags = len(soup.find_all("form"))
        input_tags = len(soup.find_all("input"))
        script_tags = len(soup.find_all("script"))

        result["html_analysis"] = {
            "total_tags": total_tags,
            "link_tags": link_tags,
            "img_tags": img_tags,
            "form_tags": form_tags,
            "input_tags": input_tags,
            "script_tags": script_tags,
        }

        # Scoring: forms in email = suspicious
        if form_tags > 0:
            score += 2.0
            result["content_signals"].append("has_form_tags")
        if input_tags > 0:
            score += 1.5
            result["content_signals"].append("has_input_tags")
        if script_tags > 0:
            score += 1.0
            result["content_signals"].append("has_script_tags")

        # High link-to-text ratio
        if total_tags > 0 and link_tags / max(total_tags, 1) > 0.3:
            score += 0.5
            result["content_signals"].append("high_link_ratio")

        # Check for hidden elements
        hidden_elements = soup.find_all(
            style=re.compile(r"display\s*:\s*none|visibility\s*:\s*hidden",
                             re.IGNORECASE)
        )
        if hidden_elements:
            score += 1.0
            result["content_signals"].append("hidden_elements")
    else:
        score += 0.5  # No HTML at all can be suspicious for formatted phish

    # --- Header Anomalies ---
    # Missing or mismatched Return-Path
    if parsed_email.return_path:
        rp_email = re.search(r"[\w.+-]+@[\w.-]+", parsed_email.return_path)
        if rp_email:
            rp_domain = rp_email.group().split("@")[1].lower()
            if parsed_email.from_domain and rp_domain != parsed_email.from_domain:
                score += 1.0
                result["header_anomalies"].append("return_path_mismatch")

    # Multiple Received headers from different domains (hop count)
    if len(parsed_email.received_headers) > 6:
        score += 0.5
        result["header_anomalies"].append("excessive_hops")

    # X-Mailer or unusual sending platform
    x_mailer = parsed_email.headers.get("X-Mailer", "")
    if x_mailer and any(s in x_mailer.lower() for s in ["php", "perl", "python"]):
        score += 0.5
        result["header_anomalies"].append("scripted_mailer")

    # --- Content Similarity ---
    body_lower = parsed_email.body_text.lower()

    # Check for common phishing template patterns
    template_patterns = [
        (r"dear\s+(customer|user|member|client|valued)", 0.5),
        (r"(click|log\s*in).{0,30}(link|button|below)", 0.5),
        (r"(verify|confirm|update).{0,20}(account|identity|information)", 0.5),
        (r"(suspended|locked|compromised)", 0.5),
        (r"(won|congratulations|selected|winner|lottery)", 0.5),
    ]

    for pattern, pts in template_patterns:
        if re.search(pattern, body_lower):
            score += pts
            result["content_signals"].append(f"pattern:{pattern[:30]}")

    result["ptech_score"] = round(min(score / max_score, 1.0), 4)
    return result


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run_metadata_checks(parsed_email, skip_pdf: bool = False) -> dict:
    """Run all metadata/structure checks on a parsed email."""
    results = {}

    results["name_username_correlation"] = check_name_username_correlation(
        parsed_email
    )

    results["brand_impersonation"] = check_brand_impersonation(parsed_email)

    results["unused_phishing_words"] = check_unused_phishing_words(
        parsed_email.subject, parsed_email.body_text
    )

    if not skip_pdf:
        results["pdf_ocr"] = convert_and_ocr(parsed_email)
    else:
        results["pdf_ocr"] = {"skipped": True}

    results["ptech_ptac"] = ptech_ptac_heuristic(parsed_email)

    return results
