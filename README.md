# EML Phishing Statistics Tool

A Docker-based tool that analyzes `.eml` phishing email files and extracts comprehensive statistics for academic research. Designed for gathering thesis-level feature data from large phishing email datasets without direct file access — only statistical outputs are produced.

## Features

The tool extracts **~120 features** per email across five analysis dimensions:

- **Infrastructure** — SPF/DKIM/DMARC authentication, IP blacklist reputation, WHOIS domain age, typosquatting detection (against Tranco Top 10K), legitimate service abuse (~100 platforms), double extension attachments (100+ dangerous extensions from badfiles), URL entropy/length/structure
- **Textual** — stopword ratio, typo count, urgency language (60+ multilingual phrases), action request phrases (70+ multilingual), financial/crypto patterns (40+ keywords), foreign language detection, character frequency chi-squared, Flesch-Kincaid and Gunning Fog readability scores
- **Metadata** — sender name-username correlation, brand impersonation (90+ brands), phishing keyword coverage (526 keywords), PDF/OCR visual analysis, Ptech/Ptac heuristic (HTML structure, header anomalies, template patterns)
- **Advanced Headers** — Reply-To vs From mismatch, X-Mailer categorization, Return-Path mismatch, Received hop timing analysis (delays and total transit time)
- **Advanced Analysis** — temporal features (send hour, day, timezone, business hours), subject line patterns (RE:/FW: abuse, caps ratio, emoji, special chars), obfuscation detection (Unicode homoglyphs, punycode, data: URIs, base64 URLs, zero-width chars, HTML comment injection, invisible text, CSS tricks), structural ratios (HTML-to-text, link-to-word, image-to-text), MIME structure analysis (part count, depth, unusual content types)

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

## Mounting Your Email Data

The tool never reads your emails directly after the run — it only produces statistical output files. Your `.eml` files stay on your machine.

**Step 1 — Place your `.eml` files in a folder**, for example:

```
/home/yourname/emails/        ← your .eml files go here
/home/yourname/eml-output/    ← results will be written here (create it first)
```

On Windows the paths look like `C:\Users\yourname\emails`.

**Step 2 — Build the image** (one time only):

```bash
docker build -t phishing-stats .
```

**Step 3 — Run the analysis**, replacing the paths with your actual folders:

```bash
# Linux / macOS
docker run \
  -v /home/yourname/emails:/data/email \
  -v /home/yourname/eml-output:/data/output \
  phishing-stats

# Windows (Command Prompt)
docker run ^
  -v C:\Users\yourname\emails:/data/email ^
  -v C:\Users\yourname\eml-output:/data/output ^
  phishing-stats

# Windows (PowerShell)
docker run `
  -v C:\Users\yourname\emails:/data/email `
  -v C:\Users\yourname\eml-output:/data/output `
  phishing-stats
```

The `-v` flag mounts a folder from your machine into the container:
- Left side of `:` — path on **your machine**
- Right side of `:` — path **inside the container** (do not change these)

**Step 4 — Collect the results** from your output folder:

```
/home/yourname/eml-output/report.json   ← full nested feature data
/home/yourname/eml-output/report.csv    ← flat table, one row per email
```

> **Tip:** For large datasets (tens of thousands of emails), add `--skip-whois --skip-pdf` to skip the slowest steps and get results much faster. See [CLI Options](#cli-options) below.

## MISP Integration (IP Reputation)

IP reputation is checked against a MISP threat intelligence instance. Pass your MISP credentials as environment variables using Docker's `-e` flag:

```bash
docker run --rm \
  -v /path/to/emails:/data/email \
  -v /path/to/output:/data/output \
  -e MISP_URL=https://your-misp-instance.example.com \
  -e MISP_API_KEY=your_misp_api_key_here \
  phishing-stats
```

If `MISP_URL` or `MISP_API_KEY` are not set, the IP reputation check is skipped gracefully and the field is marked with an error note in the output — all other analysis continues normally.

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
