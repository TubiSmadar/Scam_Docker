# Project Structure

```
.
├── analyze.py                  # Main entry point and orchestration
├── analyzers/                  # Core analysis modules
│   ├── __init__.py             # Package init
│   ├── eml_parser.py           # EML file parsing and header extraction
│   ├── infrastructure.py       # Authentication, IP, domain, URL checks
│   ├── textual.py              # Linguistic and content analysis
│   └── metadata.py             # Metadata, brand impersonation, OCR, Ptech/Ptac
├── data/                       # Reference data files
│   ├── english_freq.json       # English letter frequency distribution (chi-squared)
│   ├── known_domains.txt       # Tranco Top 10K domains (downloaded at build time)
│   ├── dangerous_extensions.json # badfiles extensions (downloaded at build time)
│   ├── phishing_words.txt      # 526 phishing keywords (13 categories, multilingual)
│   └── stopwords.txt           # 176 English stopwords (NLTK fallback)
├── scripts/                    # Build-time scripts
│   └── download_data.py        # Downloads Tranco + badfiles at Docker build
├── Dockerfile                  # Docker container configuration
├── .dockerignore               # Docker build exclusions
├── .gitignore                  # Git exclusions
├── requirements.txt            # Python dependencies
├── README.md                   # Project overview and usage
└── PROJECT_STRUCTURE.md        # This file
```

## File Descriptions

### analyze.py — Main Entry Point

Orchestrates the full analysis pipeline. Discovers `.eml` files in the input directory, runs them through all three analyzer modules in parallel using `ThreadPoolExecutor`, and writes the results as JSON and CSV.

Key functions:
- `analyze_single_email()` — runs one email through all analyzers, returns raw features
- `write_csv()` — flattens nested features into a ~75-column CSV row per email
- `discover_eml_files()` — recursively finds all `.eml` files
- `main()` — CLI argument parsing, parallel execution, progress logging

### analyzers/eml_parser.py — EML Parsing

Parses raw `.eml` files into a structured `ParsedEmail` object containing:
- Headers: Subject, From, To, Date, Return-Path, Message-ID
- Authentication headers: SPF, DKIM, DMARC, Authentication-Results
- Received chain and extracted sender IP (filters private IPs)
- Body: plain text, raw HTML, rendered text (HTML → text via BeautifulSoup)
- URLs: extracted from HTML `href`/`src` attributes and plain text regex
- Attachments: filename, content type, size

Handles multipart emails, base64/quoted-printable decoding, and RFC 2047 encoded headers.

### analyzers/infrastructure.py — Infrastructure Checks

7 checks covering email authentication and URL/domain analysis:

1. **Authentication Signatures** — SPF/DKIM/DMARC pass/fail status from headers
2. **IP Reputation** — Checks sender IP against 5 DNS blacklists (Spamhaus, SURBL, Barracuda, SpamCop, SORBS)
3. **WHOIS Lookup** — Domain registration date, registrar, expiry (optional, skippable)
4. **Typosquatting Detection** — Levenshtein distance ≤2 against 275 known domains
5. **Legitimate Service Abuse** — Detects phishing hosted on Google, Dropbox, Firebase, AWS, etc. (45+ platforms)
6. **Double Extension Detection** — Flags dangerous extensions (.exe, .scr, .bat, etc.) hidden behind decoy extensions
7. **URL Analysis** — Shannon entropy, length, dot count, @ symbols, IP-based URLs, HTTPS usage

### analyzers/textual.py — Linguistic Analysis

10 checks analyzing email body text:

1. **Stopword Count** — Ratio of common English words (NLTK + static fallback)
2. **Typos** — Misspelled word count using SymSpell with edit distance ≤2
3. **First-Person Pronouns** — Count of I, me, we, our, etc.
4. **Urgency Language** — 30+ phrases like "immediately", "act now", "account suspended"
5. **Action Requests** — 40+ imperative phrases like "click here", "verify your account"
6. **Financial/Crypto Patterns** — Bitcoin (P2PKH, Bech32), Ethereum addresses, 18 financial keywords
7. **Foreign Language Detection** — Language identification via langdetect, multilingual ratio
8. **Character Frequency** — Chi-squared test against standard English letter distribution
9. **Flesch-Kincaid Grade Level** — Readability metric (grade level + reading ease)
10. **Gunning Fog Index** — Years of formal education needed to understand text

### analyzers/metadata.py — Metadata & Structure

5 checks covering sender identity, brand impersonation, and HTML structure:

1. **Name-Username Correlation** — Whether sender display name matches the email username
2. **Brand Impersonation** — Detects 30+ brands (PayPal, Apple, Microsoft, banks, crypto exchanges, shipping) claimed in subject/display name but sent from non-matching domains
3. **Phishing Word Coverage** — Count of 289 phishing dictionary words present in the email
4. **PDF/OCR Visual Analysis** — Converts HTML to PDF via wkhtmltopdf, OCR with Tesseract, then checks for visual phishing indicators (optional, skippable)
5. **Ptech/Ptac Heuristic** — IEEE paper-inspired feature extraction: HTML tag ratios (forms, inputs, scripts, hidden elements), header anomalies (Return-Path mismatch, excessive hops, scripted mailers), phishing template pattern matching

### data/ — Reference Data

| File                       | Source                                          | Purpose                                            |
|----------------------------|-------------------------------------------------|----------------------------------------------------|
| `english_freq.json`        | Standard English letter frequencies              | Chi-squared character distribution test             |
| `known_domains.txt`        | [Tranco Top Sites](https://tranco-list.eu/)      | 10K legitimate domains for typosquatting detection  |
| `dangerous_extensions.json`| [badfiles](https://github.com/dobin/badfiles)    | 100+ dangerous file extensions (MIT license)       |
| `phishing_words.txt`       | APWG, Proofpoint, Cofense, Verizon DBIR          | 526 phishing keywords across 13 categories         |
| `stopwords.txt`            | NLTK fallback                                    | 176 English stopwords                              |

## Data Flow

```
.eml files
    │
    ▼
eml_parser.py  →  ParsedEmail object
    │
    ├──▶ infrastructure.py  →  auth, IP, WHOIS, URLs, typosquatting
    ├──▶ textual.py         →  language, readability, urgency, crypto
    └──▶ metadata.py        →  brand, phishing words, OCR, Ptech/Ptac
            │
            ▼
      analyze.py  →  report.json + report.csv
```
