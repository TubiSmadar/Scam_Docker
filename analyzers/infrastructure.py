# https://github.com/hagezi/dns-blocklists
"""
Infrastructure / Authentication analyzers:
- Authentication signatures (DMARC, DKIM, SPF)
- IP reputation (DNS blacklists)
- Sender domain WHOIS
- Typosquatting link detection
- Legitimate service abuse
- VirusTotal evaluation
- Double extension detection
- URL analysis (dots, @, subdomains, length, entropy)
"""

import re
import os
import math
import socket
import logging
import hashlib
import time
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import dns.resolver
import requests
from Levenshtein import distance as levenshtein_distance

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data file loaders
# ---------------------------------------------------------------------------
_DATA_DIR = Path(__file__).parent.parent / "data"


def _load_known_domains() -> list[str]:
    """Load list of known legitimate domains."""
    path = _DATA_DIR / "known_domains.txt"
    if path.exists():
        return [
            line.strip().lower()
            for line in path.read_text().splitlines()
            if line.strip() and not line.startswith("#")
        ]
    return []


KNOWN_DOMAINS = _load_known_domains()

LEGIT_PLATFORMS = {
    "docs.google.com",
    "drive.google.com",
    "sites.google.com",
    "forms.gle",
    "docs.google.com",
    "dropbox.com",
    "www.dropbox.com",
    "dl.dropboxusercontent.com",
    "onedrive.live.com",
    "1drv.ms",
    "sharepoint.com",
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "rebrand.ly",
    "is.gd",
    "cutt.ly",
    "shorturl.at",
    "firebase.google.com",
    "firebasestorage.googleapis.com",
    "storage.googleapis.com",
    "s3.amazonaws.com",
    "blob.core.windows.net",
    "notion.so",
    "notion.site",
    "canva.com",
    "wix.com",
    "weebly.com",
    "wordpress.com",
    "blogspot.com",
    "github.io",
    "pages.dev",
    "workers.dev",
    "netlify.app",
    "vercel.app",
    "herokuapp.com",
    "web.app",
}

DOUBLE_EXT_DANGEROUS = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".js",
    ".vbs", ".wsf", ".msi", ".jar", ".ps1", ".hta", ".cpl",
}

# ---------------------------------------------------------------------------
# 1. Authentication Signatures
# ---------------------------------------------------------------------------

def check_signatures(parsed_email) -> dict:
    """Parse authentication results for SPF, DKIM, DMARC pass/fail status."""
    result = {
        "spf": "not_found",
        "dkim": "not_found",
        "dmarc": "not_found",
        "passed": 0,
        "failed": 0,
        "total": 0,
    }

    auth_results = parsed_email.authentication_results or ""
    spf_header = parsed_email.received_spf or ""

    # SPF from Authentication-Results
    spf_match = re.search(r"\bspf\s*=\s*(\w+)", auth_results, re.IGNORECASE)
    if spf_match:
        result["spf"] = spf_match.group(1).lower()
    elif spf_header:
        spf_val = re.match(r"^\s*(\w+)", spf_header)
        if spf_val:
            result["spf"] = spf_val.group(1).lower()

    # DKIM
    dkim_match = re.search(r"\bdkim\s*=\s*(\w+)", auth_results, re.IGNORECASE)
    if dkim_match:
        result["dkim"] = dkim_match.group(1).lower()
    elif parsed_email.dkim_signature:
        result["dkim"] = "present"

    # DMARC
    dmarc_match = re.search(r"\bdmarc\s*=\s*(\w+)", auth_results, re.IGNORECASE)
    if dmarc_match:
        result["dmarc"] = dmarc_match.group(1).lower()

    # Count pass/fail
    for key in ["spf", "dkim", "dmarc"]:
        val = result[key]
        if val != "not_found":
            result["total"] += 1
            if val == "pass":
                result["passed"] += 1
            elif val in ("fail", "softfail", "temperror", "permerror", "none"):
                result["failed"] += 1

    return result


# ---------------------------------------------------------------------------
# 2. IP Reputation
# ---------------------------------------------------------------------------

DNS_BLACKLISTS = [
    "zen.spamhaus.org",
    "multi.surbl.org",
    "b.barracudacentral.org",
    "bl.spamcop.net",
    "dnsbl.sorbs.net",
]


def check_ip_reputation(sender_ip: Optional[str]) -> dict:
    """Check sender IP against DNS blacklists."""
    result = {
        "ip": sender_ip,
        "blacklisted": False,
        "blacklists_hit": [],
        "checked": 0,
    }

    if not sender_ip:
        return result

    # Reverse the IP for DNSBL query
    reversed_ip = ".".join(reversed(sender_ip.split(".")))

    for bl in DNS_BLACKLISTS:
        query = f"{reversed_ip}.{bl}"
        try:
            dns.resolver.resolve(query, "A", lifetime=3)
            result["blacklisted"] = True
            result["blacklists_hit"].append(bl)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout,
                dns.exception.DNSException):
            pass
        except Exception as e:
            logger.debug(f"DNSBL check error for {bl}: {e}")
        result["checked"] += 1

    return result


# ---------------------------------------------------------------------------
# 3. Sender Domain WHOIS
# ---------------------------------------------------------------------------

def check_whois(domain: str) -> dict:
    """Run WHOIS lookup on sender domain."""
    result = {
        "domain": domain,
        "registrar": None,
        "creation_date": None,
        "expiry_date": None,
        "error": None,
    }

    if not domain:
        result["error"] = "no_domain"
        return result

    try:
        import whois
        w = whois.whois(domain)

        result["registrar"] = w.registrar if w.registrar else None

        # Handle date fields (can be list or single value)
        if w.creation_date:
            cd = w.creation_date
            if isinstance(cd, list):
                cd = cd[0]
            result["creation_date"] = str(cd)

        if w.expiration_date:
            ed = w.expiration_date
            if isinstance(ed, list):
                ed = ed[0]
            result["expiry_date"] = str(ed)

    except Exception as e:
        result["error"] = str(e)[:200]

    return result


# ---------------------------------------------------------------------------
# 4. Typosquatting Detection
# ---------------------------------------------------------------------------

def check_typosquatting(url_domains: list[str]) -> dict:
    """Detect typosquatted domains using Levenshtein distance."""
    result = {
        "typosquatted": [],
        "count": 0,
    }

    if not url_domains or not KNOWN_DOMAINS:
        return result

    for domain in url_domains:
        domain_clean = domain.lower().lstrip("www.")
        # Skip if it's an exact match to a known domain
        if domain_clean in KNOWN_DOMAINS:
            continue

        for known in KNOWN_DOMAINS:
            dist = levenshtein_distance(domain_clean, known)
            if 0 < dist <= 2:
                result["typosquatted"].append({
                    "domain": domain,
                    "similar_to": known,
                    "distance": dist,
                })
                break  # Only flag once per domain

    result["count"] = len(result["typosquatted"])
    return result


# ---------------------------------------------------------------------------
# 5. Legitimate Service Abuse
# ---------------------------------------------------------------------------

def check_legit_service_abuse(url_domains: list[str]) -> dict:
    """Check if phishing links are hosted on legitimate platforms."""
    result = {
        "abused_services": [],
        "count": 0,
    }

    for domain in url_domains:
        domain_lower = domain.lower()
        for platform in LEGIT_PLATFORMS:
            if domain_lower == platform or domain_lower.endswith("." + platform):
                result["abused_services"].append({
                    "url_domain": domain,
                    "platform": platform,
                })
                break

    result["count"] = len(result["abused_services"])
    return result


# ---------------------------------------------------------------------------
# 6. VirusTotal Evaluation
# ---------------------------------------------------------------------------

VT_API_KEY = os.environ.get("VT_API_KEY", "")
VT_RATE_LIMIT_DELAY = 15  # seconds between requests (4/min free tier)


def check_virustotal(urls: list[str], max_urls: int = 5) -> dict:
    """Submit URLs to VirusTotal and return scan verdicts."""
    result = {
        "available": bool(VT_API_KEY),
        "scanned": [],
        "total_malicious": 0,
        "total_suspicious": 0,
    }

    if not VT_API_KEY:
        result["error"] = "VT_API_KEY not set"
        return result

    headers = {"x-apikey": VT_API_KEY}

    for url in urls[:max_urls]:
        try:
            # URL ID is base64url of the URL
            url_id = hashlib.sha256(url.encode()).hexdigest()

            # Try to get existing report first
            resp = requests.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers=headers,
                timeout=10,
            )

            if resp.status_code == 404:
                # Submit for scanning
                resp = requests.post(
                    "https://www.virustotal.com/api/v3/urls",
                    headers=headers,
                    data={"url": url},
                    timeout=10,
                )
                time.sleep(VT_RATE_LIMIT_DELAY)
                continue

            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                scan_result = {
                    "url": url[:200],
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                }
                result["scanned"].append(scan_result)
                result["total_malicious"] += scan_result["malicious"]
                result["total_suspicious"] += scan_result["suspicious"]

            time.sleep(VT_RATE_LIMIT_DELAY)

        except Exception as e:
            logger.debug(f"VT error for {url[:80]}: {e}")

    return result


# ---------------------------------------------------------------------------
# 7. Double Extension Detection
# ---------------------------------------------------------------------------

def check_double_extensions(attachments: list[dict]) -> dict:
    """Detect attachments with misleading double extensions."""
    result = {
        "suspicious_files": [],
        "count": 0,
    }

    for att in attachments:
        filename = att.get("filename", "")
        if not filename:
            continue

        # Split on dots
        parts = filename.rsplit(".", 2)
        if len(parts) >= 3:
            # e.g. "invoice.pdf.exe" → parts = ["invoice", "pdf", "exe"]
            final_ext = "." + parts[-1].lower()
            decoy_ext = "." + parts[-2].lower()

            if final_ext in DOUBLE_EXT_DANGEROUS:
                result["suspicious_files"].append({
                    "filename": filename,
                    "decoy_extension": decoy_ext,
                    "real_extension": final_ext,
                })

    result["count"] = len(result["suspicious_files"])
    return result


# ---------------------------------------------------------------------------
# 8. URL Analysis
# ---------------------------------------------------------------------------

def _shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    length = len(text)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def analyze_urls(urls: list[str]) -> dict:
    """Extract URL statistics — dots, @, subdomains, length, entropy."""
    result = {
        "total_urls": len(urls),
        "url_details": [],
        "avg_length": 0,
        "avg_entropy": 0,
        "max_dots": 0,
        "has_at_symbol": False,
    }

    if not urls:
        return result

    total_length = 0
    total_entropy = 0

    for url in urls[:50]:  # Cap analysis at 50 URLs
        try:
            parsed = urlparse(url)
            host = parsed.netloc or ""
            path = parsed.path or ""
            full = url

            num_dots = host.count(".")
            has_at = "@" in url
            subdomains = max(0, host.count(".") - 1) if host else 0
            length = len(full)
            entropy = _shannon_entropy(full)

            detail = {
                "url": url[:200],
                "dots": num_dots,
                "at_symbols": url.count("@"),
                "subdomains": subdomains,
                "length": length,
                "entropy": entropy,
                "has_ip_address": bool(re.match(r"\d+\.\d+\.\d+\.\d+", host)),
                "uses_https": parsed.scheme == "https",
            }
            result["url_details"].append(detail)

            total_length += length
            total_entropy += entropy
            result["max_dots"] = max(result["max_dots"], num_dots)
            if has_at:
                result["has_at_symbol"] = True

        except Exception:
            pass

    n = len(result["url_details"])
    if n:
        result["avg_length"] = round(total_length / n, 1)
        result["avg_entropy"] = round(total_entropy / n, 4)

    return result


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run_infrastructure_checks(parsed_email, skip_whois: bool = False, skip_dnsbl: bool = False, use_async_dns: bool = False) -> dict:
    """Run all infrastructure checks on a parsed email."""
    results = {}

    results["signatures"] = check_signatures(parsed_email)

    if skip_dnsbl:
        results["ip_reputation"] = {
            "ip": parsed_email.sender_ip,
            "blacklisted": False,
            "blacklists_hit": [],
            "checked": 0,
            "skipped": True,
        }
    else:
        results["ip_reputation"] = check_ip_reputation(parsed_email.sender_ip)

    if skip_whois:
        results["whois"] = {"skipped": True, "domain": parsed_email.from_domain}
    else:
        results["whois"] = check_whois(parsed_email.from_domain)

    results["typosquatting"] = check_typosquatting(parsed_email.url_domains)

    results["legit_service_abuse"] = check_legit_service_abuse(
        parsed_email.url_domains
    )

    results["double_extensions"] = check_double_extensions(
        parsed_email.attachments
    )

    results["url_analysis"] = analyze_urls(parsed_email.urls)

    return results
