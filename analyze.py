#!/usr/bin/env python3
"""
EML Phishing Analysis Tool
===========================
Analyzes .eml files and produces structured JSON reports with
phishing indicators across infrastructure, textual, and metadata dimensions.

Usage:
    python analyze.py /data/email [--limit N] [--workers W] [--output PATH] [--skip-pdf] [--skip-whois]

Output: JSON report written to /data/output/report.json (or --output path)
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
from analyzers.scoring import compute_verdict

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
) -> dict:
    """Analyze a single .eml file and return the full report."""
    filename = Path(filepath).name
    logger.debug(f"Processing: {filename}")

    try:
        # 1. Parse the EML
        parsed = parse_eml(filepath)

        # 2. Run infrastructure checks
        infra = run_infrastructure_checks(parsed, skip_whois=skip_whois)

        # 3. Run textual checks
        textual = run_textual_checks(parsed)

        # 4. Run metadata checks
        metadata = run_metadata_checks(parsed, skip_pdf=skip_pdf)

        # 5. Compute verdict
        verdict_data = compute_verdict(infra, textual, metadata)

        # 6. Build report
        report = {
            "file": filename,
            "scores": {
                # Infrastructure
                "signatures": infra.get("signatures", {}),
                "ip_reputation": infra.get("ip_reputation", {}),
                "whois": infra.get("whois", {}),
                "typosquatting": infra.get("typosquatting", {}),
                "legit_service_abuse": infra.get("legit_service_abuse", {}),
                "virustotal": infra.get("virustotal", {}),
                "double_extensions": infra.get("double_extensions", {}),
                "url_analysis": infra.get("url_analysis", {}),
                # Textual
                "stopword_count": textual.get("stopwords", {}).get(
                    "stopword_count", 0
                ),
                "typos": textual.get("typos", {}).get("typo_count", 0),
                "first_person_pronouns": textual.get(
                    "first_person_pronouns", {}
                ),
                "urgency": textual.get("urgency", {}),
                "action_requests": textual.get("action_requests", {}),
                "financial_crypto": textual.get("financial_crypto", {}),
                "foreign_language": textual.get("foreign_language", {}),
                "char_frequency": textual.get("char_frequency", {}),
                "flesch_kincaid": textual.get("flesch_kincaid", {}),
                "gunning_fog": textual.get("gunning_fog", {}),
                # Metadata
                "name_username_correlation": metadata.get(
                    "name_username_correlation", {}
                ),
                "unused_phishing_words": metadata.get(
                    "unused_phishing_words", {}
                ),
                "pdf_ocr": metadata.get("pdf_ocr", {}),
                "ptech_ptac": metadata.get("ptech_ptac", {}),
            },
            "verdict": verdict_data["verdict"],
            "confidence": verdict_data["confidence"],
            "signal_breakdown": verdict_data["signal_breakdown"],
        }

        return report

    except Exception as e:
        logger.error(f"Error analyzing {filename}: {e}")
        return {
            "file": filename,
            "scores": {},
            "verdict": "error",
            "confidence": 0.0,
            "error": str(e)[:500],
        }


def write_csv(reports: list, csv_path: Path) -> None:
    """Write per-email statistics CSV alongside the JSON report."""
    rows = []
    for email in reports:
        if email.get("verdict") == "error":
            continue
        s = email.get("scores", {})
        sb = email.get("signal_breakdown", {})
        brand = s.get("brand_impersonation", {})
        rows.append({
            "file": email["file"],
            "verdict": email["verdict"],
            "confidence": email["confidence"],
            # signal scores
            "sig_auth_failure": sb.get("auth_failure", 0),
            "sig_ip_blacklisted": sb.get("ip_blacklisted", 0),
            "sig_typosquatting": sb.get("typosquatting", 0),
            "sig_double_extension": sb.get("double_extension", 0),
            "sig_legit_service_abuse": sb.get("legit_service_abuse", 0),
            "sig_virustotal": sb.get("virustotal", 0),
            "sig_url_suspicious": sb.get("url_suspicious", 0),
            "sig_young_domain": sb.get("young_domain", 0),
            "sig_urgency_language": sb.get("urgency_language", 0),
            "sig_action_requests": sb.get("action_requests", 0),
            "sig_financial_crypto": sb.get("financial_crypto", 0),
            "sig_foreign_language": sb.get("foreign_language", 0),
            "sig_typos": sb.get("typos", 0),
            "sig_readability": sb.get("readability", 0),
            "sig_char_anomaly": sb.get("char_anomaly", 0),
            "sig_name_mismatch": sb.get("name_mismatch", 0),
            "sig_phishing_words": sb.get("phishing_words", 0),
            "sig_brand_impersonation": sb.get("brand_impersonation", 0),
            "sig_visual_analysis": sb.get("visual_analysis", 0),
            "sig_sparse_body_with_link": sb.get("sparse_body_with_link", 0),
            "sig_ptech_ptac": sb.get("ptech_ptac", 0),
            "sig_correlation_bonus": sb.get("correlation_bonus", 0),
            # raw feature values
            "spf": s.get("signatures", {}).get("spf", ""),
            "dkim": s.get("signatures", {}).get("dkim", ""),
            "dmarc": s.get("signatures", {}).get("dmarc", ""),
            "ip_blacklisted": s.get("ip_reputation", {}).get("blacklisted", False),
            "typosquatting_count": s.get("typosquatting", {}).get("count", 0),
            "double_extension_count": s.get("double_extensions", {}).get("count", 0),
            "total_urls": s.get("url_analysis", {}).get("total_urls", 0),
            "avg_url_length": s.get("url_analysis", {}).get("avg_length", 0),
            "avg_url_entropy": s.get("url_analysis", {}).get("avg_entropy", 0),
            "url_has_at": s.get("url_analysis", {}).get("has_at_symbol", False),
            "urgency_matches": s.get("urgency", {}).get("total_matches", 0),
            "action_matches": s.get("action_requests", {}).get("total_matches", 0),
            "has_crypto": s.get("financial_crypto", {}).get("has_crypto", False),
            "has_financial_language": s.get("financial_crypto", {}).get("has_financial_language", False),
            "primary_language": s.get("foreign_language", {}).get("primary_language", ""),
            "non_english_ratio": s.get("foreign_language", {}).get("non_english_ratio", 0),
            "typo_count": s.get("typos", 0),
            "stopword_count": s.get("stopword_count", 0),
            "fk_grade": s.get("flesch_kincaid", {}).get("grade_level", ""),
            "gunning_fog": s.get("gunning_fog", {}).get("fog_index", ""),
            "phishing_word_count": s.get("unused_phishing_words", {}).get("phishing_word_count", 0),
            "brand_impersonated": brand.get("impersonated_brand", "") if isinstance(brand, dict) else "",
            "ptech_score": s.get("ptech_ptac", {}).get("ptech_score", 0),
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
        description="EML Phishing Analysis Tool"
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
        default=4,
        help="Number of parallel workers (default: 4)",
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
        "--verbose", "-v",
        action="store_true",
        help="Enable debug logging",
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

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

    verdicts = {"phishing": 0, "legitimate": 0, "uncertain": 0, "error": 0}

    logger.info(
        f"Starting analysis with {args.workers} workers "
        f"(skip_pdf={args.skip_pdf}, skip_whois={args.skip_whois})"
    )

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        future_to_file = {
            executor.submit(
                analyze_single_email,
                fp,
                args.skip_pdf,
                args.skip_whois,
            ): fp
            for fp in eml_files
        }

        for future in as_completed(future_to_file):
            filepath = future_to_file[future]
            completed += 1

            try:
                report = future.result()
                reports.append(report)
                verdict = report.get("verdict", "error")
                verdicts[verdict] = verdicts.get(verdict, 0) + 1
            except Exception as e:
                errors += 1
                logger.error(f"Fatal error on {filepath}: {e}")
                reports.append({
                    "file": Path(filepath).name,
                    "scores": {},
                    "verdict": "error",
                    "confidence": 0.0,
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
                    f"| Verdicts: {verdicts}"
                )

    # Sort reports by filename for consistency
    reports.sort(key=lambda r: r.get("file", ""))

    # Write output
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(reports, f, indent=2, ensure_ascii=False, default=str)

    csv_path = output_path.with_suffix(".csv")
    write_csv(reports, csv_path)

    elapsed_total = time.time() - start_time
    logger.info(f"\n{'='*60}")
    logger.info(f"Analysis complete!")
    logger.info(f"Files processed: {len(reports)}")
    logger.info(f"Time elapsed: {elapsed_total:.1f}s")
    logger.info(f"Verdicts: {verdicts}")
    logger.info(f"Errors: {errors}")
    logger.info(f"Report written to: {output_path}")
    logger.info(f"{'='*60}")


if __name__ == "__main__":
    main()
