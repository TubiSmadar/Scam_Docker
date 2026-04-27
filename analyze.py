#!/usr/bin/env python3
"""
EML Phishing Statistics Tool
==============================
Analyzes .eml files from a known phishing dataset and produces
structured statistics (JSON + CSV) for thesis research.

Usage:
    python analyze.py /data/email [--limit N] [--workers W] [--output PATH] [--skip-pdf] [--skip-whois]

Output:
    - JSON report with all raw features per email
    - CSV with flattened statistics ready for analysis
"""

import argparse
import csv
import json
import logging
import os
import sys
import time
import glob
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from analyzers.eml_parser import parse_eml
from analyzers.infrastructure import run_infrastructure_checks
from analyzers.textual import run_textual_checks
from analyzers.metadata import run_metadata_checks
from analyzers.advanced import run_advanced_checks

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


def analyze_single_email(
    filepath: str,
    skip_pdf: bool = False,
    skip_whois: bool = False,
    skip_dnsbl: bool = False,
) -> dict:
    """Analyze a single .eml file and return all extracted features."""
    filename = Path(filepath).name
    logger.debug(f"Processing: {filename}")

    try:
        # 1. Parse the EML
        parsed = parse_eml(filepath)

        # 2. Run infrastructure checks (with DNS optimization)
        infra = run_infrastructure_checks(parsed, skip_whois=skip_whois, skip_dnsbl=skip_dnsbl, use_async_dns=True)

        # 3. Run textual checks
        textual = run_textual_checks(parsed)

        # 4. Run metadata checks
        metadata = run_metadata_checks(parsed, skip_pdf=skip_pdf)

        # 5. Run advanced checks
        advanced = run_advanced_checks(parsed)

        # 6. Build report with all raw features
        report = {
            # --- Email metadata ---
            "subject": parsed.subject,
            "from_email": parsed.from_email,
            "from_domain": parsed.from_domain,
            "from_display_name": parsed.from_display_name,
            "date": parsed.date,
            "sender_ip": parsed.sender_ip,
            "num_urls": len(parsed.urls),
            "num_attachments": len(parsed.attachments),
            "body_length": len(parsed.body_text),
            # --- Infrastructure features ---
            "signatures": infra.get("signatures", {}),
            "ip_reputation": infra.get("ip_reputation", {}),
            "whois": infra.get("whois", {}),
            "typosquatting": infra.get("typosquatting", {}),
            "legit_service_abuse": infra.get("legit_service_abuse", {}),
            "double_extensions": infra.get("double_extensions", {}),
            "url_analysis": infra.get("url_analysis", {}),
            # --- Textual features ---
            "stopwords": textual.get("stopwords", {}),
            "typos": textual.get("typos", {}),
            "first_person_pronouns": textual.get("first_person_pronouns", {}),
            "urgency": textual.get("urgency", {}),
            "action_requests": textual.get("action_requests", {}),
            "financial_crypto": textual.get("financial_crypto", {}),
            "foreign_language": textual.get("foreign_language", {}),
            "char_frequency": textual.get("char_frequency", {}),
            "flesch_kincaid": textual.get("flesch_kincaid", {}),
            "gunning_fog": textual.get("gunning_fog", {}),
            "body_word_count": textual.get("body_word_count", 0),
            # --- Metadata features ---
            "name_username_correlation": metadata.get("name_username_correlation", {}),
            "brand_impersonation": metadata.get("brand_impersonation", {}),
            "phishing_words": metadata.get("unused_phishing_words", {}),
            "pdf_ocr": metadata.get("pdf_ocr", {}),
            "ptech_ptac": metadata.get("ptech_ptac", {}),
            # --- Advanced features ---
            "header_anomalies": advanced.get("header_anomalies", {}),
            "temporal": advanced.get("temporal", {}),
            "subject_line": advanced.get("subject_line", {}),
            "obfuscation": advanced.get("obfuscation", {}),
            "structural_ratios": advanced.get("structural_ratios", {}),
            "mime_structure": advanced.get("mime_structure", {}),
        }

        return report

    except Exception as e:
        logger.error(f"Error analyzing {filename}: {e}")
        return {
            "error": str(e)[:500],
        }


def write_csv(reports: list, csv_path: Path) -> None:
    """Write per-email statistics CSV with all features flattened."""
    rows = []
    for r in reports:
        if r.get("error"):
            continue

        sigs = r.get("signatures", {})
        ip_rep = r.get("ip_reputation", {})
        whois_d = r.get("whois", {})
        typo = r.get("typosquatting", {})
        legit = r.get("legit_service_abuse", {})
        dbl = r.get("double_extensions", {})
        url_a = r.get("url_analysis", {})
        stopw = r.get("stopwords", {})
        typos = r.get("typos", {})
        fp = r.get("first_person_pronouns", {})
        urg = r.get("urgency", {})
        act = r.get("action_requests", {})
        fin = r.get("financial_crypto", {})
        lang = r.get("foreign_language", {})
        char_f = r.get("char_frequency", {})
        fk = r.get("flesch_kincaid", {})
        gf = r.get("gunning_fog", {})
        name_corr = r.get("name_username_correlation", {})
        brand = r.get("brand_impersonation", {})
        pw = r.get("phishing_words", {})
        pdf_ocr = r.get("pdf_ocr", {})
        ptech = r.get("ptech_ptac", {})
        # Advanced features
        hdr = r.get("header_anomalies", {})
        temp = r.get("temporal", {})
        subj = r.get("subject_line", {})
        obf = r.get("obfuscation", {})
        struct = r.get("structural_ratios", {})
        mime = r.get("mime_structure", {})

        rows.append({
            # --- Identity ---
            "subject": r.get("subject", ""),
            "from_email": r.get("from_email", ""),
            "from_domain": r.get("from_domain", ""),
            "from_display_name": r.get("from_display_name", ""),
            "date": r.get("date", ""),
            "sender_ip": r.get("sender_ip", ""),
            "body_length": r.get("body_length", 0),
            "body_word_count": r.get("body_word_count", 0),
            "num_urls": r.get("num_urls", 0),
            "num_attachments": r.get("num_attachments", 0),

            # --- Authentication ---
            "spf": sigs.get("spf", ""),
            "dkim": sigs.get("dkim", ""),
            "dmarc": sigs.get("dmarc", ""),
            "auth_passed": sigs.get("passed", 0),
            "auth_failed": sigs.get("failed", 0),
            "auth_total": sigs.get("total", 0),

            # --- WHOIS ---
            "whois_registrar": whois_d.get("registrar", ""),
            "whois_creation_date": whois_d.get("creation_date", ""),
            "whois_expiry_date": whois_d.get("expiry_date", ""),

            # --- Typosquatting ---
            "typosquatting_count": typo.get("count", 0),

            # --- Legit Service Abuse ---
            "legit_service_abuse_count": legit.get("count", 0),

            # --- Double Extensions ---
            "double_extension_count": dbl.get("count", 0),

            # --- URL Analysis ---
            "total_urls": url_a.get("total_urls", 0),
            "avg_url_length": url_a.get("avg_length", 0),
            "avg_url_entropy": url_a.get("avg_entropy", 0),
            "max_url_dots": url_a.get("max_dots", 0),
            "url_has_at_symbol": url_a.get("has_at_symbol", False),

            # --- Stopwords ---
            "stopword_count": stopw.get("stopword_count", 0),
            "stopword_total_words": stopw.get("total_words", 0),
            "stopword_ratio": stopw.get("ratio", 0),

            # --- Typos ---
            "typo_count": typos.get("typo_count", 0),
            "typo_total_checked": typos.get("total_checked", 0),

            # --- First Person Pronouns ---
            "first_person_count": fp.get("count", 0),

            # --- Urgency ---
            "urgency_detected": urg.get("urgency_detected", False),
            "urgency_total_matches": urg.get("total_matches", 0),

            # --- Action Requests ---
            "action_requested": act.get("action_requested", False),
            "action_total_matches": act.get("total_matches", 0),

            # --- Financial / Crypto ---
            "has_crypto": fin.get("has_crypto", False),
            "has_financial_language": fin.get("has_financial_language", False),
            "bitcoin_address_count": len(fin.get("bitcoin_addresses", [])),
            "ethereum_address_count": len(fin.get("ethereum_addresses", [])),

            # --- Foreign Language ---
            "primary_language": lang.get("primary_language", ""),
            "is_multilingual": lang.get("is_multilingual", False),
            "non_english_ratio": lang.get("non_english_ratio", 0),

            # --- Character Frequency ---
            "char_chi_squared": char_f.get("chi_squared", 0),
            "char_matches_english": char_f.get("matches_english", True),

            # --- Readability ---
            "fk_grade_level": fk.get("grade_level", 0),
            "fk_reading_ease": fk.get("reading_ease", 0),
            "gunning_fog_index": gf.get("fog_index", 0),

            # --- Name-Username Correlation ---
            "name_in_username": name_corr.get("name_in_username", False),
            "name_in_to": name_corr.get("name_in_to", False),
            "name_correlation_score": name_corr.get("correlation_score", 0),

            # --- Brand Impersonation ---
            "brand_impersonated": brand.get("impersonated_brand", ""),
            "is_brand_impersonation": brand.get("is_impersonation", False),

            # --- Phishing Words ---
            "phishing_word_count": pw.get("phishing_word_count", 0),
            "phishing_coverage": pw.get("phishing_coverage", 0),

            # --- PDF/OCR ---
            "pdf_generated": pdf_ocr.get("pdf_generated", False),
            "visual_phishing_indicators": len(pdf_ocr.get("visual_phishing_indicators", [])),

            # --- Ptech/Ptac ---
            "ptech_score": ptech.get("ptech_score", 0),
            "ptech_has_form_tags": "has_form_tags" in ptech.get("content_signals", []),
            "ptech_has_input_tags": "has_input_tags" in ptech.get("content_signals", []),
            "ptech_has_script_tags": "has_script_tags" in ptech.get("content_signals", []),
            "ptech_has_hidden_elements": "hidden_elements" in ptech.get("content_signals", []),
            "ptech_return_path_mismatch": "return_path_mismatch" in ptech.get("header_anomalies", []),
            "ptech_excessive_hops": "excessive_hops" in ptech.get("header_anomalies", []),
            "ptech_scripted_mailer": "scripted_mailer" in ptech.get("header_anomalies", []),
            "html_total_tags": ptech.get("html_analysis", {}).get("total_tags", 0),
            "html_link_tags": ptech.get("html_analysis", {}).get("link_tags", 0),
            "html_img_tags": ptech.get("html_analysis", {}).get("img_tags", 0),
            "html_form_tags": ptech.get("html_analysis", {}).get("form_tags", 0),
            "html_input_tags": ptech.get("html_analysis", {}).get("input_tags", 0),
            "html_script_tags": ptech.get("html_analysis", {}).get("script_tags", 0),

            # =====================================================
            # ADVANCED FEATURES
            # =====================================================

            # --- Header Anomalies ---
            "has_reply_to": hdr.get("has_reply_to", False),
            "reply_to_mismatch": hdr.get("reply_to_mismatch", False),
            "reply_to_domain_mismatch": hdr.get("reply_to_domain_mismatch", False),
            "x_mailer_category": hdr.get("x_mailer_category", ""),
            "return_path_mismatch": hdr.get("return_path_mismatch", False),
            "received_hop_count": hdr.get("received_hop_count", 0),
            "max_hop_delay_seconds": hdr.get("max_hop_delay_seconds", 0),
            "total_transit_seconds": hdr.get("total_transit_seconds", 0),
            "has_x_originating_ip": hdr.get("has_x_originating_ip", False),

            # --- Temporal ---
            "send_hour_utc": temp.get("send_hour_utc", ""),
            "send_day_of_week": temp.get("send_day_of_week", ""),
            "send_day_name": temp.get("send_day_name", ""),
            "send_timezone_offset": temp.get("send_timezone_offset", ""),
            "is_business_hours": temp.get("is_business_hours", ""),
            "is_weekend": temp.get("is_weekend", ""),
            "is_night": temp.get("is_night", ""),
            "date_parsed": temp.get("date_parsed", False),

            # --- Subject Line ---
            "subject_length": subj.get("subject_length", 0),
            "subject_word_count": subj.get("subject_word_count", 0),
            "subject_has_re_prefix": subj.get("has_re_prefix", False),
            "subject_has_fw_prefix": subj.get("has_fw_prefix", False),
            "subject_re_fw_count": subj.get("re_fw_count", 0),
            "subject_caps_ratio": subj.get("caps_ratio", 0),
            "subject_is_all_caps": subj.get("is_all_caps", False),
            "subject_has_emoji": subj.get("has_emoji", False),
            "subject_special_char_count": subj.get("special_char_count", 0),
            "subject_has_exclamation": subj.get("has_exclamation", False),
            "subject_exclamation_count": subj.get("exclamation_count", 0),
            "subject_has_question_mark": subj.get("has_question_mark", False),
            "subject_has_brackets": subj.get("has_brackets", False),
            "subject_has_dollar_sign": subj.get("has_dollar_sign", False),
            "subject_has_unicode": subj.get("has_unicode_chars", False),

            # --- Obfuscation ---
            "homoglyph_count": obf.get("homoglyph_count", 0),
            "punycode_count": obf.get("punycode_count", 0),
            "data_uri_count": obf.get("data_uri_count", 0),
            "base64_url_count": obf.get("base64_url_count", 0),
            "url_shortener_chain_count": obf.get("url_shortener_chain_count", 0),
            "hex_encoded_url_count": obf.get("hex_encoded_url_count", 0),
            "ip_based_url_count": obf.get("ip_based_url_count", 0),
            "html_comment_injection": obf.get("html_comment_injection", False),
            "zero_width_chars": obf.get("zero_width_chars", False),
            "invisible_text": obf.get("invisible_text", False),
            "css_obfuscation": obf.get("css_obfuscation", False),

            # --- Structural Ratios ---
            "html_to_text_ratio": struct.get("html_to_text_ratio", 0),
            "link_to_word_ratio": struct.get("link_to_word_ratio", 0),
            "image_to_text_ratio": struct.get("image_to_text_ratio", 0),
            "has_plain_text_alternative": struct.get("has_plain_text_alternative", False),
            "is_html_only": struct.get("is_html_only", False),
            "is_text_only": struct.get("is_text_only", False),
            "inline_image_count": struct.get("inline_image_count", 0),

            # --- MIME Structure ---
            "mime_part_count": mime.get("mime_part_count", 0),
            "mime_max_depth": mime.get("mime_max_depth", 0),
            "mime_unique_content_types": mime.get("mime_unique_content_types", 0),
            "mime_has_mixed_content": mime.get("has_mixed_content", False),
            "mime_has_unusual_content_type": mime.get("has_unusual_content_type", False),
        })

    if not rows:
        return

    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    logger.info(f"Statistics CSV written to: {csv_path}")


def discover_eml_files(input_dir: str) -> list[str]:
    """Discover all .eml files in the input directory."""
    patterns = [
        os.path.join(input_dir, "*.eml"),
        os.path.join(input_dir, "**", "*.eml"),
    ]
    files = set()
    for pattern in patterns:
        files.update(glob.glob(pattern, recursive=True))
    return sorted(files)


def main():
    parser = argparse.ArgumentParser(
        description="EML Phishing Statistics Tool — extract features from phishing emails for research"
    )
    parser.add_argument(
        "input_dir",
        help="Directory containing .eml files",
    )
    parser.add_argument(
        "--output",
        default="/data/output/report.json",
        help="Output JSON file path (default: /data/output/report.json)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Limit number of emails to process (0 = all)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=0,
        help="Number of parallel workers (default: auto-detect CPU count)",
    )
    parser.add_argument(
        "--skip-pdf",
        action="store_true",
        help="Skip PDF conversion and OCR (faster)",
    )
    parser.add_argument(
        "--skip-whois",
        action="store_true",
        help="Skip WHOIS lookups (faster, avoids rate limits)",
    )
    parser.add_argument(
        "--no-dnsbl",
        action="store_true",
        help="Skip DNS blacklist checks (fastest, loses IP reputation feature)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable debug logging",
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Auto-detect workers if not specified
    import multiprocessing
    num_workers = args.workers
    if num_workers <= 0:
        num_workers = min(multiprocessing.cpu_count(), 16)  # Cap at 16

    # Discover files
    eml_files = discover_eml_files(args.input_dir)
    if not eml_files:
        logger.error(f"No .eml files found in {args.input_dir}")
        sys.exit(1)

    total_files = len(eml_files)
    logger.info(f"Found {total_files} .eml files in {args.input_dir}")

    if args.limit > 0:
        eml_files = eml_files[: args.limit]
        logger.info(f"Limiting to {len(eml_files)} files")

    # Ensure output directory exists
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Process files
    reports = []
    start_time = time.time()
    completed = 0
    errors = 0

    logger.info(
        f"Starting analysis with {num_workers} workers "
        f"(skip_pdf={args.skip_pdf}, skip_whois={args.skip_whois}, skip_dnsbl={args.no_dnsbl})"
    )

    with ThreadPoolExecutor(max_workers=num_workers) as executor:
        future_to_file = {
            executor.submit(
                analyze_single_email,
                fp,
                args.skip_pdf,
                args.skip_whois,
                args.no_dnsbl,
            ): fp
            for fp in eml_files
        }

        for future in as_completed(future_to_file):
            filepath = future_to_file[future]
            completed += 1

            try:
                report = future.result()
                reports.append(report)
                if report.get("error"):
                    errors += 1
            except Exception as e:
                errors += 1
                logger.error(f"Fatal error on {filepath}: {e}")
                reports.append({
                    "error": str(e)[:500],
                })

            # Progress logging every 50 files
            if completed % 50 == 0 or completed == len(eml_files):
                elapsed = time.time() - start_time
                rate = completed / max(elapsed, 0.001)
                remaining = (len(eml_files) - completed) / max(rate, 0.001)
                logger.info(
                    f"Progress: {completed}/{len(eml_files)} "
                    f"({rate:.1f} files/sec, ~{remaining:.0f}s remaining) "
                    f"| Errors: {errors}"
                )

    # Sort reports by filename for consistency
    reports.sort(key=lambda r: r.get("subject", ""))

    # Write JSON output
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(reports, f, indent=2, ensure_ascii=False, default=str)

    # Write CSV output
    csv_path = output_path.with_suffix(".csv")
    write_csv(reports, csv_path)

    elapsed_total = time.time() - start_time
    logger.info(f"\n{'='*60}")
    logger.info(f"Analysis complete!")
    logger.info(f"Files processed: {len(reports)}")
    logger.info(f"Time elapsed: {elapsed_total:.1f}s")
    logger.info(f"Errors: {errors}")
    logger.info(f"Report written to: {output_path}")
    logger.info(f"CSV written to: {csv_path}")
    logger.info(f"{'='*60}")


if __name__ == "__main__":
    main()
