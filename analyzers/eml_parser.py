"""
Core EML parser — extracts headers, body text, URLs, attachments,
sender IP, and sender domain from .eml files.
"""

import email
import email.policy
import re
import base64
import quopri
from email import message_from_bytes
from email.utils import parseaddr
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import logging

logger = logging.getLogger(__name__)


class ParsedEmail:
    """Structured representation of a parsed EML file."""

    def __init__(self):
        self.filename: str = ""
        self.subject: str = ""
        self.from_header: str = ""
        self.from_display_name: str = ""
        self.from_email: str = ""
        self.from_domain: str = ""
        self.to_header: str = ""
        self.to_email: str = ""
        self.date: str = ""
        self.return_path: str = ""
        self.message_id: str = ""

        # Authentication
        self.authentication_results: str = ""
        self.received_spf: str = ""
        self.dkim_signature: str = ""

        # Received chain
        self.received_headers: list[str] = []
        self.sender_ip: Optional[str] = None

        # Body
        self.body_text: str = ""       # Plain text (stripped HTML)
        self.body_html: str = ""       # Raw HTML
        self.body_raw: str = ""        # Raw body before processing

        # Additional headers for analysis
        self.reply_to: str = ""
        self.reply_to_email: str = ""
        self.reply_to_domain: str = ""
        self.x_mailer: str = ""
        self.content_type: str = ""
        self.mime_version: str = ""
        self.x_originating_ip: str = ""

        # MIME structure
        self.mime_parts: int = 0
        self.mime_max_depth: int = 0
        self.mime_content_types: list[str] = []
        self.has_plain_text_part: bool = False
        self.has_html_part: bool = False

        # Extracted data
        self.urls: list[str] = []
        self.url_domains: list[str] = []
        self.attachments: list[dict] = []   # [{filename, content_type, size}]
        self.image_count: int = 0  # Inline/embedded images

        # All headers as dict
        self.headers: dict = {}

        # Raw message object (for MIME analysis)
        self._msg = None


def parse_eml(filepath: str) -> ParsedEmail:
    """Parse a single .eml file and return a ParsedEmail object."""
    parsed = ParsedEmail()
    parsed.filename = Path(filepath).name

    try:
        with open(filepath, "rb") as f:
            raw = f.read()

        msg = message_from_bytes(raw, policy=email.policy.default)
    except Exception as e:
        logger.error(f"Failed to parse {filepath}: {e}")
        return parsed

    # --- Extract headers ---
    parsed.headers = {k: v for k, v in msg.items()}
    parsed.subject = _decode_header(msg.get("Subject", ""))
    parsed.from_header = _decode_header(msg.get("From", ""))
    parsed.to_header = _decode_header(msg.get("To", ""))
    parsed.date = msg.get("Date", "")
    parsed.return_path = msg.get("Return-Path", "")
    parsed.message_id = msg.get("Message-ID", "")
    parsed.authentication_results = msg.get("Authentication-Results", "")
    parsed.received_spf = msg.get("Received-SPF", "")
    parsed.dkim_signature = msg.get("DKIM-Signature", "")
    parsed.reply_to = _decode_header(msg.get("Reply-To", ""))
    parsed.x_mailer = msg.get("X-Mailer", "") or msg.get("User-Agent", "")
    parsed.content_type = msg.get_content_type()
    parsed.mime_version = msg.get("MIME-Version", "")
    parsed.x_originating_ip = msg.get("X-Originating-IP", "")
    parsed._msg = msg

    # Parse Reply-To
    if parsed.reply_to:
        _, rt_addr = parseaddr(parsed.reply_to)
        parsed.reply_to_email = rt_addr
        if rt_addr and "@" in rt_addr:
            parsed.reply_to_domain = rt_addr.split("@")[1].lower()

    # Parse From
    display_name, email_addr = parseaddr(parsed.from_header)
    parsed.from_display_name = display_name
    parsed.from_email = email_addr
    if email_addr and "@" in email_addr:
        parsed.from_domain = email_addr.split("@")[1].lower()

    # Parse To
    _, to_addr = parseaddr(parsed.to_header)
    parsed.to_email = to_addr

    # Received headers
    parsed.received_headers = msg.get_all("Received", [])

    # Extract sender IP from Received headers
    parsed.sender_ip = _extract_sender_ip(parsed.received_headers)

    # --- Extract body ---
    body_parts = _extract_body(msg)
    parsed.body_text = body_parts["text"]
    parsed.body_html = body_parts["html"]
    parsed.body_raw = body_parts["raw"]

    # If no plain text, generate from HTML
    if not parsed.body_text.strip() and parsed.body_html.strip():
        parsed.body_text = _html_to_text(parsed.body_html)

    # --- Extract URLs from HTML ---
    if parsed.body_html:
        parsed.urls = _extract_urls(parsed.body_html)
    # Also extract URLs from plain text
    parsed.urls.extend(_extract_urls_from_text(parsed.body_text))
    # Deduplicate
    parsed.urls = list(dict.fromkeys(parsed.urls))

    # Extract URL domains
    for url in parsed.urls:
        try:
            domain = urlparse(url).netloc.lower()
            if domain:
                parsed.url_domains.append(domain)
        except Exception:
            pass
    parsed.url_domains = list(set(parsed.url_domains))

    # --- Extract attachments ---
    parsed.attachments = _extract_attachments(msg)

    # --- Analyze MIME structure ---
    mime_info = _analyze_mime_structure(msg)
    parsed.mime_parts = mime_info["part_count"]
    parsed.mime_max_depth = mime_info["max_depth"]
    parsed.mime_content_types = mime_info["content_types"]
    parsed.has_plain_text_part = mime_info["has_plain_text"]
    parsed.has_html_part = mime_info["has_html"]
    parsed.image_count = mime_info["image_count"]

    return parsed


def _decode_header(value: str) -> str:
    """Decode RFC 2047 encoded header values."""
    if not value:
        return ""
    try:
        # email.policy.default already handles decoding
        return str(value)
    except Exception:
        return value


def _extract_sender_ip(received_headers: list[str]) -> Optional[str]:
    """Extract the first external sender IP from Received headers."""
    ip_pattern = re.compile(
        r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"
    )
    # Received headers are in reverse order (latest first)
    # We want the IP from the *last* (earliest) external hop
    for header in reversed(received_headers):
        header_str = str(header)
        matches = ip_pattern.findall(header_str)
        for ip in matches:
            # Skip internal/private IPs
            if not _is_private_ip(ip):
                return ip
    # Fallback: check any received header
    for header in received_headers:
        header_str = str(header)
        matches = ip_pattern.findall(header_str)
        for ip in matches:
            if not _is_private_ip(ip):
                return ip
    return None


def _is_private_ip(ip: str) -> bool:
    """Check if an IP address is private/reserved."""
    parts = ip.split(".")
    if len(parts) != 4:
        return True
    try:
        octets = [int(p) for p in parts]
    except ValueError:
        return True

    # RFC 1918 + loopback + link-local
    if octets[0] == 10:
        return True
    if octets[0] == 172 and 16 <= octets[1] <= 31:
        return True
    if octets[0] == 192 and octets[1] == 168:
        return True
    if octets[0] == 127:
        return True
    if octets[0] == 169 and octets[1] == 254:
        return True
    if octets[0] == 0:
        return True
    return False


def _extract_body(msg: email.message.Message) -> dict:
    """Extract text and HTML body parts from an email message."""
    result = {"text": "", "html": "", "raw": ""}

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition", ""))

            # Skip attachments
            if "attachment" in content_disposition:
                continue

            payload = _get_decoded_payload(part)
            if not payload:
                continue

            if content_type == "text/plain":
                result["text"] += payload + "\n"
            elif content_type == "text/html":
                result["html"] += payload + "\n"
            result["raw"] += payload + "\n"
    else:
        content_type = msg.get_content_type()
        payload = _get_decoded_payload(msg)
        if payload:
            if content_type == "text/html":
                result["html"] = payload
            elif content_type == "text/plain":
                result["text"] = payload
            result["raw"] = payload

    return result


def _get_decoded_payload(part: email.message.Message) -> Optional[str]:
    """Decode email payload handling base64, quoted-printable, etc."""
    try:
        # Try using the policy-based decoding first
        payload = part.get_content()
        if isinstance(payload, str):
            return payload
        if isinstance(payload, bytes):
            return payload.decode("utf-8", errors="replace")
    except Exception:
        pass

    try:
        # Fallback to manual decoding
        raw_payload = part.get_payload(decode=False)
        if raw_payload is None:
            return None

        if isinstance(raw_payload, str):
            encoding = part.get("Content-Transfer-Encoding", "").lower()
            if encoding == "base64":
                try:
                    decoded = base64.b64decode(raw_payload)
                    charset = part.get_content_charset() or "utf-8"
                    return decoded.decode(charset, errors="replace")
                except Exception:
                    pass
            elif encoding == "quoted-printable":
                try:
                    decoded = quopri.decodestring(raw_payload.encode())
                    charset = part.get_content_charset() or "utf-8"
                    return decoded.decode(charset, errors="replace")
                except Exception:
                    pass
            return raw_payload

        if isinstance(raw_payload, bytes):
            charset = part.get_content_charset() or "utf-8"
            return raw_payload.decode(charset, errors="replace")
    except Exception:
        pass

    return None


def _html_to_text(html: str) -> str:
    """Convert HTML to plain text using BeautifulSoup."""
    try:
        soup = BeautifulSoup(html, "html.parser")
        # Remove script and style elements
        for element in soup(["script", "style"]):
            element.decompose()
        text = soup.get_text(separator=" ", strip=True)
        # Collapse whitespace
        text = re.sub(r"\s+", " ", text)
        return text.strip()
    except Exception:
        return ""


def _extract_urls(html: str) -> list[str]:
    """Extract URLs from HTML content via href attributes."""
    urls = []
    try:
        soup = BeautifulSoup(html, "html.parser")
        for tag in soup.find_all(["a", "area", "link"], href=True):
            href = tag["href"].strip()
            if href and href.startswith(("http://", "https://")):
                urls.append(href)
        # Also check src attributes for embedded resources  
        for tag in soup.find_all(["img", "iframe", "embed"], src=True):
            src = tag["src"].strip()
            if src and src.startswith(("http://", "https://")):
                urls.append(src)
    except Exception:
        pass
    return urls


def _extract_urls_from_text(text: str) -> list[str]:
    """Extract URLs from plain text using regex."""
    url_pattern = re.compile(
        r"https?://[^\s<>\"'\)\]]+",
        re.IGNORECASE
    )
    return url_pattern.findall(text)


def _extract_attachments(msg: email.message.Message) -> list[dict]:
    """Extract attachment metadata from an email message."""
    attachments = []
    if not msg.is_multipart():
        return attachments

    for part in msg.walk():
        content_disposition = str(part.get("Content-Disposition", ""))
        if "attachment" in content_disposition:
            filename = part.get_filename()
            if not filename:
                # Try to infer from content type
                filename = f"unnamed_{part.get_content_type().replace('/', '_')}"

            payload = part.get_payload(decode=True)
            size = len(payload) if payload else 0

            attachments.append({
                "filename": filename,
                "content_type": part.get_content_type(),
                "size": size,
            })

    return attachments


def _analyze_mime_structure(msg: email.message.Message) -> dict:
    """Analyze MIME structure: part count, nesting depth, content types."""
    result = {
        "part_count": 0,
        "max_depth": 0,
        "content_types": [],
        "has_plain_text": False,
        "has_html": False,
        "image_count": 0,
    }

    if not msg.is_multipart():
        result["part_count"] = 1
        result["max_depth"] = 0
        ct = msg.get_content_type()
        result["content_types"] = [ct]
        result["has_plain_text"] = ct == "text/plain"
        result["has_html"] = ct == "text/html"
        return result

    content_types = []
    image_count = 0

    def _walk_depth(part, depth):
        nonlocal image_count
        ct = part.get_content_type()
        content_types.append(ct)
        max_d = depth

        if ct.startswith("image/"):
            image_count += 1

        if part.is_multipart():
            for sub in part.get_payload():
                if hasattr(sub, "get_content_type"):
                    child_d = _walk_depth(sub, depth + 1)
                    max_d = max(max_d, child_d)
        return max_d

    max_depth = _walk_depth(msg, 0)

    result["part_count"] = len(content_types)
    result["max_depth"] = max_depth
    result["content_types"] = list(set(content_types))
    result["has_plain_text"] = "text/plain" in content_types
    result["has_html"] = "text/html" in content_types
    result["image_count"] = image_count

    return result
