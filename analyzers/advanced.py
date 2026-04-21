"""
Advanced analyzers for thesis-level phishing statistics:
- Header anomalies (Reply-To mismatch, X-Mailer, envelope sender, hop timing)
- Temporal features (send hour, day, timezone, business hours)
- Subject line patterns (RE:/FW: abuse, length, caps ratio, special chars)
- Obfuscation detection (homoglyphs, punycode, data: URIs, base64 URLs)
- Structural ratios (HTML-to-text, image-to-text, link-to-word)
- MIME structure (part count, depth, content type anomalies)
"""

import re
import math
import logging
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime, parseaddr
from typing import Optional
from urllib.parse import urlparse, unquote

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Unicode homoglyph map (most common Latin lookalikes from Cyrillic, Greek, etc.)
# Source: Unicode Technical Report #36 — Unicode Security Considerations
# ---------------------------------------------------------------------------
_HOMOGLYPH_MAP = {
    "\u0430": "a",  # Cyrillic а
    "\u0435": "e",  # Cyrillic е
    "\u043e": "o",  # Cyrillic о
    "\u0440": "p",  # Cyrillic р
    "\u0441": "c",  # Cyrillic с
    "\u0443": "y",  # Cyrillic у
    "\u0445": "x",  # Cyrillic х
    "\u0456": "i",  # Cyrillic і
    "\u0458": "j",  # Cyrillic ј
    "\u04bb": "h",  # Cyrillic һ
    "\u0501": "d",  # Cyrillic ԁ
    "\u051b": "q",  # Cyrillic ԛ
    "\u0261": "g",  # Latin ɡ
    "\u1d00": "a",  # Small cap A
    "\u0251": "a",  # Latin alpha ɑ
    "\u03bf": "o",  # Greek omicron ο
    "\u03b1": "a",  # Greek alpha α
    "\u03b5": "e",  # Greek epsilon ε
    "\u03b9": "i",  # Greek iota ι
    "\u03ba": "k",  # Greek kappa κ
    "\u03bd": "v",  # Greek nu ν
    "\u03c1": "p",  # Greek rho ρ
    "\u03c4": "t",  # Greek tau τ
    "\u0237": "j",  # Latin dotless j ȷ
    "\u0131": "i",  # Latin dotless i ı
    "\u2010": "-",  # Hyphen ‐
    "\u2011": "-",  # Non-breaking hyphen ‑
    "\u2012": "-",  # Figure dash ‒
    "\u2013": "-",  # En dash –
    "\u2014": "-",  # Em dash —
    "\uff0e": ".",  # Fullwidth period ．
    "\u2024": ".",  # One dot leader ․
    "\uff0f": "/",  # Fullwidth solidus ／
}

_HOMOGLYPH_CHARS = set(_HOMOGLYPH_MAP.keys())


# ---------------------------------------------------------------------------
# 1. Header Anomalies
# ---------------------------------------------------------------------------

def check_header_anomalies(parsed_email) -> dict:
    """Extract header-based anomaly features."""
    result = {
        # Reply-To mismatch
        "has_reply_to": bool(parsed_email.reply_to),
        "reply_to_email": parsed_email.reply_to_email,
        "reply_to_domain": parsed_email.reply_to_domain,
        "reply_to_mismatch": False,
        "reply_to_domain_mismatch": False,
        # X-Mailer
        "x_mailer": parsed_email.x_mailer,
        "x_mailer_category": "unknown",
        # Envelope sender
        "return_path_mismatch": False,
        "return_path_domain": "",
        # Received chain
        "received_hop_count": len(parsed_email.received_headers),
        "received_hop_delays": [],
        "max_hop_delay_seconds": 0,
        "total_transit_seconds": 0,
        # Originating IP
        "has_x_originating_ip": bool(parsed_email.x_originating_ip),
    }

    # --- Reply-To vs From mismatch ---
    if parsed_email.reply_to_email and parsed_email.from_email:
        result["reply_to_mismatch"] = (
            parsed_email.reply_to_email.lower() != parsed_email.from_email.lower()
        )
        if parsed_email.reply_to_domain and parsed_email.from_domain:
            result["reply_to_domain_mismatch"] = (
                parsed_email.reply_to_domain != parsed_email.from_domain
            )

    # --- X-Mailer categorization ---
    xm = (parsed_email.x_mailer or "").lower()
    if not xm:
        result["x_mailer_category"] = "none"
    elif any(s in xm for s in ["php", "perl", "python", "ruby", "node"]):
        result["x_mailer_category"] = "scripted"
    elif any(s in xm for s in ["outlook", "thunderbird", "apple mail", "gmail", "yahoo"]):
        result["x_mailer_category"] = "legitimate_client"
    elif any(s in xm for s in ["postfix", "sendmail", "exim", "exchange"]):
        result["x_mailer_category"] = "mta"
    elif any(s in xm for s in ["mailchimp", "sendgrid", "amazonses", "ses", "mandrill", "constant contact"]):
        result["x_mailer_category"] = "bulk_sender"
    else:
        result["x_mailer_category"] = "other"

    # --- Return-Path vs From domain ---
    if parsed_email.return_path:
        rp_match = re.search(r"[\w.+-]+@[\w.-]+", parsed_email.return_path)
        if rp_match:
            rp_domain = rp_match.group().split("@")[1].lower()
            result["return_path_domain"] = rp_domain
            if parsed_email.from_domain and rp_domain != parsed_email.from_domain:
                result["return_path_mismatch"] = True

    # --- Received header hop timing ---
    hop_times = _parse_received_times(parsed_email.received_headers)
    delays = []
    if len(hop_times) >= 2:
        for i in range(len(hop_times) - 1):
            delay = (hop_times[i] - hop_times[i + 1]).total_seconds()
            delays.append(round(abs(delay), 1))

    result["received_hop_delays"] = delays
    result["max_hop_delay_seconds"] = max(delays) if delays else 0
    result["total_transit_seconds"] = sum(delays) if delays else 0

    return result


def _parse_received_times(received_headers: list[str]) -> list[datetime]:
    """Extract timestamps from Received headers (newest first)."""
    times = []
    # Pattern: "; <date>" at end of Received header
    date_pattern = re.compile(r";\s*(.+)$")

    for header in received_headers:
        header_str = str(header)
        match = date_pattern.search(header_str)
        if match:
            try:
                dt = parsedate_to_datetime(match.group(1).strip())
                times.append(dt)
            except Exception:
                pass
    return times


# ---------------------------------------------------------------------------
# 2. Temporal Features
# ---------------------------------------------------------------------------

def extract_temporal_features(parsed_email) -> dict:
    """Extract time-based features from the Date header."""
    result = {
        "send_hour_utc": None,
        "send_day_of_week": None,      # 0=Monday, 6=Sunday
        "send_day_name": None,
        "send_timezone_offset": None,   # Hours from UTC
        "is_business_hours": None,      # 9-17 in sender's timezone
        "is_weekend": None,
        "is_night": None,               # 22-06 in sender's timezone
        "date_parsed": False,
    }

    date_str = parsed_email.date
    if not date_str:
        return result

    try:
        dt = parsedate_to_datetime(date_str)
        result["date_parsed"] = True

        # UTC time
        dt_utc = dt.astimezone(timezone.utc)
        result["send_hour_utc"] = dt_utc.hour
        result["send_day_of_week"] = dt_utc.weekday()
        result["send_day_name"] = dt_utc.strftime("%A")

        # Timezone offset
        if dt.tzinfo:
            offset = dt.utcoffset()
            if offset:
                result["send_timezone_offset"] = offset.total_seconds() / 3600

        # Local time analysis (use original timezone if available)
        local_hour = dt.hour
        result["is_business_hours"] = 9 <= local_hour < 17
        result["is_weekend"] = dt.weekday() >= 5
        result["is_night"] = local_hour >= 22 or local_hour < 6

    except Exception as e:
        logger.debug(f"Date parse error: {e}")

    return result


# ---------------------------------------------------------------------------
# 3. Subject Line Patterns
# ---------------------------------------------------------------------------

def analyze_subject_line(parsed_email) -> dict:
    """Analyze subject line for phishing patterns."""
    subject = parsed_email.subject or ""

    result = {
        "subject_length": len(subject),
        "subject_word_count": len(subject.split()),
        # RE:/FW: prefix abuse
        "has_re_prefix": False,
        "has_fw_prefix": False,
        "re_fw_count": 0,          # Multiple RE:RE:RE: = suspicious
        # Capitalization
        "caps_ratio": 0.0,         # Ratio of uppercase letters
        "is_all_caps": False,
        # Special characters
        "has_emoji": False,
        "special_char_count": 0,    # Non-alphanumeric, non-space
        "has_exclamation": False,
        "exclamation_count": 0,
        "has_question_mark": False,
        "has_brackets": False,      # [ACTION REQUIRED] style
        "has_dollar_sign": False,
        # Encoding tricks
        "has_unicode_chars": False,  # Non-ASCII characters in subject
    }

    if not subject:
        return result

    # RE:/FW: detection
    re_pattern = re.compile(r"^(re|fw|fwd)\s*:", re.IGNORECASE)
    prefix_count = 0
    temp_subject = subject.strip()
    while re_pattern.match(temp_subject):
        match = re_pattern.match(temp_subject)
        prefix = match.group(1).lower()
        if prefix == "re":
            result["has_re_prefix"] = True
        else:
            result["has_fw_prefix"] = True
        prefix_count += 1
        temp_subject = temp_subject[match.end():].strip()
    result["re_fw_count"] = prefix_count

    # Capitalization
    alpha_chars = [c for c in subject if c.isalpha()]
    if alpha_chars:
        upper_count = sum(1 for c in alpha_chars if c.isupper())
        result["caps_ratio"] = round(upper_count / len(alpha_chars), 4)
        result["is_all_caps"] = result["caps_ratio"] > 0.8 and len(alpha_chars) > 3

    # Special characters
    result["has_exclamation"] = "!" in subject
    result["exclamation_count"] = subject.count("!")
    result["has_question_mark"] = "?" in subject
    result["has_brackets"] = bool(re.search(r"[\[\{]", subject))
    result["has_dollar_sign"] = "$" in subject
    result["special_char_count"] = sum(
        1 for c in subject if not c.isalnum() and not c.isspace()
    )

    # Emoji detection (common emoji Unicode ranges)
    emoji_pattern = re.compile(
        "[\U0001F600-\U0001F64F"  # Emoticons
        "\U0001F300-\U0001F5FF"   # Symbols & pictographs
        "\U0001F680-\U0001F6FF"   # Transport & map
        "\U0001F1E0-\U0001F1FF"   # Flags
        "\U00002702-\U000027B0"   # Dingbats
        "\U000024C2-\U0001F251"
        "]+", flags=re.UNICODE
    )
    result["has_emoji"] = bool(emoji_pattern.search(subject))

    # Unicode detection (non-ASCII)
    result["has_unicode_chars"] = any(ord(c) > 127 for c in subject)

    return result


# ---------------------------------------------------------------------------
# 4. Obfuscation Detection
# ---------------------------------------------------------------------------

def detect_obfuscation(parsed_email) -> dict:
    """Detect obfuscation techniques in URLs, domains, and HTML."""
    result = {
        # Homoglyphs
        "homoglyph_domains": [],
        "homoglyph_count": 0,
        # Punycode / IDN
        "punycode_domains": [],
        "punycode_count": 0,
        # URL obfuscation
        "data_uri_count": 0,
        "base64_url_count": 0,
        "url_shortener_chain_count": 0,  # Shortened URL pointing to another shortener
        "hex_encoded_url_count": 0,
        "ip_based_url_count": 0,
        # HTML tricks
        "html_comment_injection": False,
        "zero_width_chars": False,
        "invisible_text": False,
        "css_obfuscation": False,
    }

    # --- Analyze URL domains for homoglyphs ---
    for domain in parsed_email.url_domains:
        if _has_homoglyphs(domain):
            result["homoglyph_domains"].append(domain)

    # Also check sender domain
    if parsed_email.from_domain and _has_homoglyphs(parsed_email.from_domain):
        result["homoglyph_domains"].append(parsed_email.from_domain)

    result["homoglyph_count"] = len(result["homoglyph_domains"])

    # --- Punycode / IDN domains ---
    for domain in parsed_email.url_domains:
        if domain.startswith("xn--") or ".xn--" in domain:
            result["punycode_domains"].append(domain)
    if parsed_email.from_domain:
        fd = parsed_email.from_domain
        if fd.startswith("xn--") or ".xn--" in fd:
            result["punycode_domains"].append(fd)

    result["punycode_count"] = len(result["punycode_domains"])

    # --- URL-level obfuscation ---
    shorteners = {
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
        "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at",
        "t.ly", "rb.gy", "short.io", "tiny.cc", "lnkd.in",
    }

    for url in parsed_email.urls:
        url_lower = url.lower()

        # data: URIs
        if url_lower.startswith("data:"):
            result["data_uri_count"] += 1

        # Base64 encoded content in URLs
        if "base64" in url_lower or re.search(r"[A-Za-z0-9+/]{40,}={0,2}", url):
            result["base64_url_count"] += 1

        # Hex-encoded characters (%xx patterns beyond normal encoding)
        hex_sequences = re.findall(r"%[0-9a-fA-F]{2}", url)
        if len(hex_sequences) > 5:
            result["hex_encoded_url_count"] += 1

        # IP-based URLs
        try:
            host = urlparse(url).netloc
            if re.match(r"\d+\.\d+\.\d+\.\d+", host.split(":")[0]):
                result["ip_based_url_count"] += 1
        except Exception:
            pass

        # URL shortener chains (a shortener URL containing another shortener)
        try:
            host = urlparse(url).netloc.lower()
            if any(host == s or host.endswith("." + s) for s in shorteners):
                decoded_path = unquote(url)
                for s2 in shorteners:
                    if s2 in decoded_path.split(host, 1)[-1]:
                        result["url_shortener_chain_count"] += 1
                        break
        except Exception:
            pass

    # --- HTML-level obfuscation ---
    html = parsed_email.body_html
    if html:
        # Comment injection between words to break filters
        # e.g., "p<!---->a<!---->y<!---->p<!---->a<!---->l"
        if re.search(r"\w<!--.*?-->\w", html):
            result["html_comment_injection"] = True

        # Zero-width characters (ZWJ, ZWNJ, ZWSP, soft hyphen)
        zero_width = "\u200b\u200c\u200d\u00ad\ufeff\u2060"
        if any(c in html for c in zero_width):
            result["zero_width_chars"] = True

        # Invisible text (font-size:0, color matching background, opacity:0)
        if re.search(
            r"font-size\s*:\s*0|"
            r"color\s*:\s*(?:white|#fff(?:fff)?|rgba?\([^)]*,\s*0\))|"
            r"opacity\s*:\s*0",
            html, re.IGNORECASE
        ):
            result["invisible_text"] = True

        # CSS tricks (direction:rtl to reverse text display)
        if re.search(r"direction\s*:\s*rtl|unicode-bidi", html, re.IGNORECASE):
            result["css_obfuscation"] = True

    return result


def _has_homoglyphs(text: str) -> bool:
    """Check if text contains Unicode homoglyph characters."""
    return any(c in _HOMOGLYPH_CHARS for c in text)


# ---------------------------------------------------------------------------
# 5. Structural Ratios
# ---------------------------------------------------------------------------

def compute_structural_ratios(parsed_email) -> dict:
    """Compute structural content ratios."""
    body_text = parsed_email.body_text
    body_html = parsed_email.body_html

    text_len = len(body_text.strip())
    html_len = len(body_html.strip())
    word_count = len(re.findall(r"[a-zA-Z]+", body_text))

    result = {
        "text_length": text_len,
        "html_length": html_len,
        "html_to_text_ratio": 0.0,
        "link_to_word_ratio": 0.0,
        "image_to_text_ratio": 0.0,
        "has_plain_text_alternative": parsed_email.has_plain_text_part,
        "has_html_part": parsed_email.has_html_part,
        "is_html_only": parsed_email.has_html_part and not parsed_email.has_plain_text_part,
        "is_text_only": parsed_email.has_plain_text_part and not parsed_email.has_html_part,
        "inline_image_count": parsed_email.image_count,
        "url_count": len(parsed_email.urls),
        "word_count": word_count,
    }

    # HTML-to-text ratio (high ratio = lots of markup relative to content)
    if text_len > 0:
        result["html_to_text_ratio"] = round(html_len / text_len, 2)

    # Link-to-word ratio
    if word_count > 0:
        result["link_to_word_ratio"] = round(len(parsed_email.urls) / word_count, 4)

    # Image-to-text ratio (high = image-heavy, possibly evasion)
    if word_count > 0:
        result["image_to_text_ratio"] = round(parsed_email.image_count / word_count, 4)
    elif parsed_email.image_count > 0:
        result["image_to_text_ratio"] = float(parsed_email.image_count)

    return result


# ---------------------------------------------------------------------------
# 6. MIME Structure Analysis
# ---------------------------------------------------------------------------

def analyze_mime_features(parsed_email) -> dict:
    """Extract MIME structure features for statistical analysis."""
    result = {
        "mime_part_count": parsed_email.mime_parts,
        "mime_max_depth": parsed_email.mime_max_depth,
        "mime_unique_content_types": len(set(parsed_email.mime_content_types)),
        "mime_content_types": parsed_email.mime_content_types,
        "has_mixed_content": (
            parsed_email.has_plain_text_part and parsed_email.has_html_part
        ),
        "has_unusual_content_type": False,
        "unusual_content_types": [],
    }

    # Standard email content types
    standard_types = {
        "text/plain", "text/html", "text/enriched",
        "multipart/mixed", "multipart/alternative", "multipart/related",
        "multipart/signed", "multipart/report",
        "message/rfc822", "message/delivery-status",
        "image/png", "image/jpeg", "image/gif", "image/bmp", "image/svg+xml",
        "application/pdf", "application/msword",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "application/vnd.ms-excel", "application/vnd.ms-powerpoint",
        "application/zip", "application/x-zip-compressed",
        "application/octet-stream", "application/pkcs7-signature",
        "application/pgp-signature", "application/x-pkcs7-signature",
    }

    unusual = []
    for ct in parsed_email.mime_content_types:
        if ct not in standard_types:
            unusual.append(ct)

    result["unusual_content_types"] = list(set(unusual))
    result["has_unusual_content_type"] = bool(unusual)

    return result


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run_advanced_checks(parsed_email) -> dict:
    """Run all advanced checks on a parsed email."""
    results = {}

    results["header_anomalies"] = check_header_anomalies(parsed_email)
    results["temporal"] = extract_temporal_features(parsed_email)
    results["subject_line"] = analyze_subject_line(parsed_email)
    results["obfuscation"] = detect_obfuscation(parsed_email)
    results["structural_ratios"] = compute_structural_ratios(parsed_email)
    results["mime_structure"] = analyze_mime_features(parsed_email)

    return results
