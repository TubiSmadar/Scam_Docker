# Project Structure

```
.
├── analyze.py                  # Main entry point and orchestration
├── analyzers/                  # Core analysis modules
│   ├── __init__.py             # Package init
│   ├── eml_parser.py           # EML file parsing, header/MIME extraction
│   ├── infrastructure.py       # Authentication, IP, domain, URL checks
│   ├── textual.py              # Linguistic and content analysis
│   ├── metadata.py             # Brand impersonation, OCR, Ptech/Ptac
│   └── advanced.py             # Header anomalies, temporal, obfuscation, structure
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

Orchestrates the full analysis pipeline. Discovers `.eml` files in the input directory, runs them through all five analyzer modules in parallel using `ThreadPoolExecutor`, and writes the results as JSON and CSV.

Key functions:
- `analyze_single_email()` — runs one email through all analyzers, returns raw features
- `write_csv()` — flattens nested features into a ~120-column CSV row per email
- `discover_eml_files()` — recursively finds all `.eml` files
- `main()` — CLI argument parsing, parallel execution, progress logging

### analyzers/eml_parser.py — EML Parsing

Parses raw `.eml` files into a structured `ParsedEmail` object containing:
- Headers: Subject, From, To, Date, Return-Path, Message-ID, Reply-To, X-Mailer
- Authentication headers: SPF, DKIM, DMARC, Authentication-Results
- Received chain and extracted sender IP (filters private IPs)
- Body: plain text, raw HTML, rendered text (HTML → text via BeautifulSoup)
- URLs: extracted from HTML `href`/`src` attributes and plain text regex
- Attachments: filename, content type, size
- MIME structure: part count, nesting depth, content types, image count

Handles multipart emails, base64/quoted-printable decoding, and RFC 2047 encoded headers.

### analyzers/infrastructure.py — Infrastructure Checks

7 checks covering email authentication and URL/domain analysis:

1. **Authentication Signatures** — SPF/DKIM/DMARC pass/fail status from headers
2. **IP Reputation** — Checks sender IP against 5 DNS blacklists (Spamhaus, SURBL, Barracuda, SpamCop, SORBS)
3. **WHOIS Lookup** — Domain registration date, registrar, expiry (optional, skippable)
4. **Typosquatting Detection** — Levenshtein distance ≤2 against Tranco Top 10K domains
5. **Legitimate Service Abuse** — Detects phishing hosted on ~100 platforms (Google, Microsoft, AWS, Cloudflare, shorteners, website builders, dev platforms, file sharing)
6. **Double Extension Detection** — Flags 100+ dangerous extensions (from badfiles) hidden behind decoy extensions
7. **URL Analysis** — Shannon entropy, length, dot count, @ symbols, IP-based URLs, HTTPS usage

### analyzers/textual.py — Linguistic Analysis

10 checks analyzing email body text:

1. **Stopword Count** — Ratio of common English words (NLTK + static fallback)
2. **Typos** — Misspelled word count using SymSpell with edit distance ≤2
3. **First-Person Pronouns** — Count of I, me, we, our, etc.
4. **Urgency Language** — 60+ phrases (multilingual: EN, PT, ES, FR, DE) like "immediately", "act now", "account suspended"
5. **Action Requests** — 70+ imperative phrases (multilingual) like "click here", "verify your account"
6. **Financial/Crypto Patterns** — Bitcoin (P2PKH, Bech32), Ethereum addresses, 40+ financial/crypto keywords
7. **Foreign Language Detection** — Language identification via langdetect, multilingual ratio
8. **Character Frequency** — Chi-squared test against standard English letter distribution
9. **Flesch-Kincaid Grade Level** — Readability metric (grade level + reading ease)
10. **Gunning Fog Index** — Years of formal education needed to understand text

### analyzers/metadata.py — Metadata & Structure

5 checks covering sender identity, brand impersonation, and HTML structure:

1. **Name-Username Correlation** — Whether sender display name matches the email username
2. **Brand Impersonation** — Detects 90+ brands (tech, crypto, banks US+intl, shipping, e-commerce, government, telecom, payments) claimed in subject/display name but sent from non-matching domains
3. **Phishing Word Coverage** — Count of 526 phishing dictionary words present in the email
4. **PDF/OCR Visual Analysis** — Converts HTML to PDF via wkhtmltopdf, OCR with Tesseract, then checks for visual phishing indicators (optional, skippable)
5. **Ptech/Ptac Heuristic** — IEEE paper-inspired feature extraction: HTML tag ratios (forms, inputs, scripts, hidden elements), header anomalies (Return-Path mismatch, excessive hops, scripted mailers), phishing template pattern matching

### analyzers/advanced.py — Advanced Features (NEW)

6 analysis categories providing thesis-level statistics:

1. **Header Anomalies** — Reply-To vs From mismatch (email and domain level), X-Mailer categorization (scripted/legitimate/bulk/MTA), Return-Path vs From domain mismatch, Received hop count, hop timing delays (max and total transit seconds), X-Originating-IP presence
2. **Temporal Features** — Send hour (UTC), day of week, timezone offset, business hours flag, weekend flag, night send flag (22:00–06:00)
3. **Subject Line Patterns** — RE:/FW: prefix abuse (count of chained prefixes), subject length/word count, ALL CAPS ratio, emoji detection, special character count, exclamation/question marks, bracket usage ([ACTION REQUIRED] style), dollar signs, Unicode character presence
4. **Obfuscation Detection** — Unicode homoglyph characters (Cyrillic/Greek lookalikes using Unicode TR#36 map), punycode/IDN domains, data: URIs, base64-encoded URLs, URL shortener chains (shortener→shortener), hex-encoded URLs, IP-based URLs, HTML comment injection (word splitting), zero-width characters (ZWJ, ZWNJ, ZWSP, soft hyphen), invisible text (font-size:0, color tricks, opacity:0), CSS obfuscation (direction:rtl, unicode-bidi)
5. **Structural Ratios** — HTML-to-text length ratio, link-to-word ratio, image-to-text ratio, plain-text alternative presence, HTML-only flag, text-only flag, inline image count
6. **MIME Structure** — Part count, max nesting depth, unique content type count, mixed content flag (text+html), unusual content type detection

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
eml_parser.py  →  ParsedEmail object (headers, body, URLs, MIME, attachments)
    │
    ├──▶ infrastructure.py  →  auth, IP, WHOIS, URLs, typosquatting
    ├──▶ textual.py         →  language, readability, urgency, crypto
    ├──▶ metadata.py        →  brand, phishing words, OCR, Ptech/Ptac
    └──▶ advanced.py        →  headers, temporal, subject, obfuscation, structure, MIME
            │
            ▼
      analyze.py  →  report.json (~120 features) + report.csv (flattened)
```

## CSV Column Summary (~120 columns)

| Category | Columns | Examples |
|----------|---------|---------|
| Identity | 12 | file, subject, from_email, from_domain, date, sender_ip |
| Authentication | 6 | spf, dkim, dmarc, auth_passed, auth_failed |
| IP Reputation | 3 | ip_blacklisted, ip_blacklists_hit |
| WHOIS | 3 | whois_registrar, whois_creation_date |
| Typosquatting | 1 | typosquatting_count |
| Legit Service Abuse | 1 | legit_service_abuse_count |
| Double Extensions | 1 | double_extension_count |
| URL Analysis | 5 | total_urls, avg_url_entropy, url_has_at_symbol |
| Stopwords | 3 | stopword_count, stopword_ratio |
| Typos | 2 | typo_count, typo_total_checked |
| Pronouns | 1 | first_person_count |
| Urgency | 2 | urgency_detected, urgency_total_matches |
| Action Requests | 2 | action_requested, action_total_matches |
| Financial/Crypto | 4 | has_crypto, bitcoin_address_count |
| Language | 3 | primary_language, is_multilingual, non_english_ratio |
| Char Frequency | 2 | char_chi_squared, char_matches_english |
| Readability | 3 | fk_grade_level, fk_reading_ease, gunning_fog_index |
| Name Correlation | 3 | name_in_username, name_correlation_score |
| Brand Impersonation | 2 | brand_impersonated, is_brand_impersonation |
| Phishing Words | 2 | phishing_word_count, phishing_coverage |
| PDF/OCR | 2 | pdf_generated, visual_phishing_indicators |
| Ptech/Ptac | 13 | ptech_score, html_form_tags, html_script_tags |
| Header Anomalies | 9 | reply_to_mismatch, x_mailer_category, received_hop_count |
| Temporal | 8 | send_hour_utc, send_day_name, is_business_hours, is_night |
| Subject Line | 14 | subject_length, subject_caps_ratio, subject_has_emoji |
| Obfuscation | 11 | homoglyph_count, punycode_count, zero_width_chars |
| Structural Ratios | 7 | html_to_text_ratio, link_to_word_ratio, is_html_only |
| MIME Structure | 5 | mime_part_count, mime_max_depth, mime_has_unusual_content_type |
