# DNS Zone Record Scraper

A Python tool for discovering and exporting DNS records. Attempts zone transfers, enumerates 25+ record types, discovers subdomains, and exports to BIND, CSV, or TXT formats.

## Installation

### Prerequisites
- Python 3.8 or higher
- pip (usually comes with Python)

### Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/a8cteam51/DNS-Zone-Record-Scraper.git
   cd DNS-Zone-Record-Scraper
   ```

2. **Create a virtual environment:**
   
   On macOS/Linux:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```
   
   On Windows:
   ```bash
   python -m venv venv
   venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

### Deactivating the Virtual Environment

When you're done, deactivate the virtual environment:
```bash
deactivate
```

### Troubleshooting

- **Python version issues:** Ensure you're using Python 3.8+ by running `python3 --version` (or `python --version` on Windows)
- **Permission errors:** If you get permission errors, you may be installing globally. Always use a virtual environment.
- **Import errors:** Make sure the virtual environment is activated (you should see `(venv)` in your terminal prompt)

## Quick Start

```bash
python3 dns_scraper.py example.com -o export_dns_filename
```

## Options

| Flag | Description |
|------|-------------|
| `-o, --output` | Output filename (without extension) |
| `-f, --format` | Export format: `bind`, `csv`, `txt`, or `all` (default: all) |
| `-n, --nameserver` | Custom DNS server (e.g., `8.8.8.8`) |
| `-t, --timeout` | Query timeout in seconds (default: 5.0) |
| `-v, --verbose` | Show each record as discovered |
| `--no-subdomains` | Skip subdomain enumeration |

## Examples

### Basic Scans

```bash
# Display results only (no export)
python3 dns_scraper.py example.com

# Export to all formats
python3 dns_scraper.py example.com -o results

# Quick scan without subdomains
python3 dns_scraper.py example.com --no-subdomains -o quick
```

### Using Different DNS Servers

```bash
# Google DNS
python3 dns_scraper.py example.com -n 8.8.8.8 -o google_dns

# Cloudflare DNS
python3 dns_scraper.py example.com -n 1.1.1.1 -o cloudflare_dns

# Quad9 DNS
python3 dns_scraper.py example.com -n 9.9.9.9 -o quad9_dns
```

### Export Format Control

```bash
# BIND zone file only
python3 dns_scraper.py example.com -f bind -o zone

# CSV only (for spreadsheets)
python3 dns_scraper.py example.com -f csv -o records

# Text only (human-readable)
python3 dns_scraper.py example.com -f txt -o report
```

### Batch Scanning

```bash
#!/bin/bash
# scan_domains.sh - Scan multiple domains

DOMAINS="example.com example.org example.net"

for domain in $DOMAINS; do
    echo "Scanning $domain..."
    python3 dns_scraper.py "$$domain" -o "exports/$${domain}" --no-subdomains
done
```

### Compare DNS Across Resolvers

```bash
#!/bin/bash
# compare_resolvers.sh - Compare results from different DNS servers

DOMAIN=\$1
RESOLVERS="8.8.8.8 1.1.1.1 9.9.9.9"

for resolver in $RESOLVERS; do
    echo "Querying $resolver..."
    python3 dns_scraper.py "$$DOMAIN" -n "$$resolver" -f csv -o "$${DOMAIN}_$${resolver}" --no-subdomains
done

echo "Comparing results..."
diff "$${DOMAIN}_8.8.8.8.csv" "$${DOMAIN}_1.1.1.1.csv"
```

### Export and Process with jq/csvtool

```bash
# Scan and extract just A records from CSV
python3 dns_scraper.py example.com -f csv -o scan
grep ",A," scan.csv | cut -d',' -f1,4

# Count records by type
python3 dns_scraper.py example.com -f csv -o scan
tail -n +2 scan.csv | cut -d',' -f2 | sort | uniq -c | sort -rn
```

### Cron Job for Monitoring

```bash
#!/bin/bash
# dns_monitor.sh - Track DNS changes over time

DOMAIN="example.com"
DATE=$(date +%Y%m%d)
DIR="$$HOME/dns_history/$$DOMAIN"

mkdir -p "$DIR"
python3 dns_scraper.py "$$DOMAIN" -f csv -o "$$DIR/$DATE" --no-subdomains

# Alert on changes
if [ -f "$DIR/latest.csv" ]; then
    if ! diff -q "$$DIR/$$DATE.csv" "$DIR/latest.csv" > /dev/null; then
        echo "DNS changes detected for $DOMAIN"
        diff "$$DIR/latest.csv" "$$DIR/$DATE.csv"
    fi
fi

ln -sf "$$DIR/$$DATE.csv" "$DIR/latest.csv"
```

### Combine with Other Tools

```bash
#!/bin/bash
# comprehensive_scan.sh - Combine with CT logs and other sources

DOMAIN=\$1
OUTPUT_DIR="./recon_$DOMAIN"
mkdir -p "$OUTPUT_DIR"

# DNS Scraper
python3 dns_scraper.py "$$DOMAIN" -o "$$OUTPUT_DIR/dns" -v

# Certificate Transparency
curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" 2>/dev/null | \
    python3 -c "import sys,json; print('\n'.join(set(x['name_value'] for x in json.load(sys.stdin))))" | \
    sort -u > "$OUTPUT_DIR/ct_domains.txt"

# Combine subdomains
cat "$$OUTPUT_DIR/dns.csv" | tail -n +2 | cut -d',' -f1 | sort -u > "$$OUTPUT_DIR/dns_domains.txt"
cat "$$OUTPUT_DIR/ct_domains.txt" "$$OUTPUT_DIR/dns_domains.txt" | sort -u > "$OUTPUT_DIR/all_domains.txt"

echo "Found $$(wc -l < "$$OUTPUT_DIR/all_domains.txt") unique hostnames"
```

## Output Formats

**BIND (.zone)** — Standard zone file for DNS servers  
**CSV (.csv)** — `Hostname,Record Type,TTL,Value`  
**TXT (.txt)** — Human-readable report

## Limitations

This tool cannot discover:
- Randomly-named subdomains not in the wordlist
- Records behind DNS firewalls
- Internal-only records

For complete zone data, you need zone transfer access or DNS provider API access.

## License

MIT
