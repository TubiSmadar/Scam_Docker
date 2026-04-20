#!/usr/bin/env python3
"""
Download open-source data files at Docker build time.
Sources:
  - Tranco Top Sites (https://tranco-list.eu/) — top domains for typosquatting detection
  - badfiles (https://github.com/dobin/badfiles) — dangerous file extensions
"""

import csv
import io
import json
import urllib.request
import zipfile
import sys
from pathlib import Path

DATA_DIR = Path(__file__).parent.parent / "data"


def download_tranco(top_n: int = 10000) -> None:
    """Download Tranco top sites list and save as known_domains.txt."""
    print(f"Downloading Tranco top {top_n} domains...")

    # Tranco provides a daily list; use the latest
    # Step 1: Get the latest list ID
    try:
        url = "https://tranco-list.eu/top-1m.csv.zip"
        req = urllib.request.Request(url, headers={"User-Agent": "PhishingStatsTool/1.0"})
        response = urllib.request.urlopen(req, timeout=60)
        zip_data = response.read()
    except Exception as e:
        print(f"  Failed to download Tranco list: {e}")
        print("  Keeping existing known_domains.txt as fallback")
        return

    # Extract CSV from zip
    try:
        with zipfile.ZipFile(io.BytesIO(zip_data)) as zf:
            csv_filename = zf.namelist()[0]
            csv_data = zf.read(csv_filename).decode("utf-8")
    except Exception as e:
        print(f"  Failed to extract zip: {e}")
        return

    # Parse CSV: format is "rank,domain"
    domains = []
    reader = csv.reader(io.StringIO(csv_data))
    for row in reader:
        if len(row) >= 2:
            domain = row[1].strip().lower()
            if domain:
                domains.append(domain)
        if len(domains) >= top_n:
            break

    if not domains:
        print("  No domains parsed from Tranco list")
        return

    # Write to known_domains.txt
    output_path = DATA_DIR / "known_domains.txt"
    with open(output_path, "w") as f:
        f.write(f"# Tranco Top {top_n} Domains\n")
        f.write(f"# Source: https://tranco-list.eu/\n")
        f.write(f"# License: CC BY 3.0 / CC BY-SA 4.0\n")
        f.write(f"# Domains: {len(domains)}\n")
        f.write("#\n")
        for domain in domains:
            f.write(domain + "\n")

    print(f"  Saved {len(domains)} domains to {output_path}")


def download_badfiles() -> None:
    """Download badfiles dangerous extension list from GitHub."""
    print("Downloading badfiles dangerous extensions...")

    url = "https://raw.githubusercontent.com/dobin/badfiles/main/info.yaml"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "PhishingStatsTool/1.0"})
        response = urllib.request.urlopen(req, timeout=30)
        yaml_data = response.read().decode("utf-8")
    except Exception as e:
        print(f"  Failed to download badfiles: {e}")
        print("  Keeping hardcoded extensions as fallback")
        return

    # Parse YAML manually (avoid PyYAML dependency at build time)
    # The format has lines like "  - extension: exe"
    extensions = set()
    for line in yaml_data.splitlines():
        line = line.strip()
        if line.startswith("- extension:"):
            ext = line.split(":", 1)[1].strip().strip('"').strip("'").lower()
            if ext:
                extensions.add("." + ext if not ext.startswith(".") else ext)
        # Also catch "extension:" without the list marker
        elif line.startswith("extension:"):
            ext = line.split(":", 1)[1].strip().strip('"').strip("'").lower()
            if ext:
                extensions.add("." + ext if not ext.startswith(".") else ext)

    if not extensions:
        # Fallback: parse any line that looks like an extension definition
        import re
        for match in re.findall(r'["\']\.(\w{1,6})["\']', yaml_data):
            extensions.add("." + match.lower())

    if not extensions:
        print("  Could not parse extensions from badfiles YAML")
        return

    # Write to dangerous_extensions.json
    output_path = DATA_DIR / "dangerous_extensions.json"
    data = {
        "source": "https://github.com/dobin/badfiles",
        "license": "MIT",
        "count": len(extensions),
        "extensions": sorted(extensions),
    }
    with open(output_path, "w") as f:
        json.dump(data, f, indent=2)

    print(f"  Saved {len(extensions)} extensions to {output_path}")


if __name__ == "__main__":
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    download_tranco(top_n=10000)
    download_badfiles()

    print("\nData download complete!")
