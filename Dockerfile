# EML Phishing Statistics Tool
FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget \
    xz-utils \
    fontconfig \
    libfreetype6 \
    libjpeg62-turbo \
    libpng16-16 \
    libx11-6 \
    libxcb1 \
    libxext6 \
    libxrender1 \
    xfonts-75dpi \
    xfonts-base \
    tesseract-ocr \
    tesseract-ocr-eng \
    whois \
    dnsutils \
    poppler-utils \
    && rm -rf /var/lib/apt/lists/*

# Download and install wkhtmltopdf (Debian Bullseye version)
RUN wget -q https://github.com/wkhtmltopdf/packaging/releases/download/0.12.6.1-2/wkhtmltox_0.12.6.1-2.bullseye_amd64.deb \
    && dpkg -i wkhtmltox_0.12.6.1-2.bullseye_amd64.deb || true \
    && apt-get install -f -y \
    && rm wkhtmltox_0.12.6.1-2.bullseye_amd64.deb

# Set the working directory
WORKDIR /app

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Pre-download NLTK data (stopwords corpus + cmudict for textstat syllable counts)
RUN python -c "import nltk; nltk.download('stopwords', quiet=True); nltk.download('cmudict', quiet=True, force=True)"

# Copy the application
COPY analyze.py .
COPY analyzers/ ./analyzers/
COPY data/ ./data/
COPY scripts/ ./scripts/

# Download open-source data at build time:
#   - Tranco Top 10K domains (typosquatting detection)
#   - badfiles dangerous extensions list
# Falls back gracefully to bundled static files if download fails.
RUN python scripts/download_data.py

# Create output directory
RUN mkdir -p /data/output

# Entry point: analyze emails
# Mount your email folder to /data/email and output folder to /data/output
# Example: docker run -v /path/to/emails:/data/email -v /path/to/output:/data/output phishing-stats
ENTRYPOINT ["python", "analyze.py"]
CMD ["/data/email"]
