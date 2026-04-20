# EML Phishing Statistics Tool

A Docker-based tool that analyzes `.eml` phishing email files and extracts comprehensive statistics for academic research. Designed for gathering thesis-level feature data from large phishing email datasets without direct file access — only statistical outputs are produced.

## Features

The tool extracts **~75 features** per email across four analysis dimensions:

- **Infrastructure** — SPF/DKIM/DMARC authentication, IP blacklist reputation, WHOIS domain age, typosquatting detection, legitimate service abuse, double extension attachments, URL entropy/length/structure
- **Textual** — stopword ratio, typo count, urgency language, action request phrases, financial/crypto patterns, foreign language detection, character frequency chi-squared, Flesch-Kincaid and Gunning Fog readability scores
- **Metadata** — sender name-username correlation, brand impersonation detection, phishing keyword coverage, PDF/OCR visual analysis
- **Structural (Ptech/Ptac)** — HTML tag analysis (forms, inputs, scripts, hidden elements), header anomalies (Return-Path mismatch, excessive hops, scripted mailers), phishing template pattern matching

## Quick Start

```bash
# Build the Docker image
docker build -t phishing-stats .

# Run analysis on a folder of .eml files
docker run \
  -v /path/to/eml-folder:/data/email \
  -v /path/to/output:/data/output \
  phishing-stats
```

## Output

The tool produces two files in the output directory:

- **`report.json`** — Full detailed analysis for every email (all nested features)
- **`report.csv`** — Flattened statistics with one row per email, ready for import into pandas, R, SPSS, or Excel

## CLI Options

```
python analyze.py /data/email [OPTIONS]

Options:
  --output PATH       Output JSON path (default: /data/output/report.json)
  --limit N           Process only first N emails (0 = all)
  --workers W         Parallel worker threads (default: 4)
  --skip-pdf          Skip PDF conversion and OCR (much faster)
  --skip-whois        Skip WHOIS lookups (faster, avoids rate limits)
  --verbose / -v      Enable debug logging
```

## Docker Run Examples

```bash
# Fast run — skip slow WHOIS and PDF/OCR steps
docker run \
  -v /path/to/emails:/data/email \
  -v /path/to/output:/data/output \
  phishing-stats /data/email --skip-pdf --skip-whois

# Process only first 100 emails with 8 workers
docker run \
  -v /path/to/emails:/data/email \
  -v /path/to/output:/data/output \
  phishing-stats /data/email --limit 100 --workers 8

# Verbose logging
docker run \
  -v /path/to/emails:/data/email \
  -v /path/to/output:/data/output \
  phishing-stats /data/email -v
```

## Project Structure

See [PROJECT_STRUCTURE.md](PROJECT_STRUCTURE.md) for a detailed breakdown of every file and module.

## Requirements

All dependencies are handled inside Docker. If running locally:

```bash
pip install -r requirements.txt
```

System dependencies: `tesseract-ocr`, `wkhtmltopdf`, `whois`, `dnsutils`, `poppler-utils`
