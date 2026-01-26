# DNS Zone Record Scraper

A Python tool for discovering and exporting DNS records. Attempts zone transfers, enumerates 25+ record types, discovers 300+ subdomains, and exports to BIND, CSV, or TXT formats.

Uses **smart record-type selection** by default to minimize unnecessary queries (~1,500 queries vs ~7,500 in exhaustive mode).

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
# Smart mode (default) - fast and efficient
python3 dns_scraper.py example.com -o example_dns

# Exhaustive mode - query all record types for all subdomains
python3 dns_scraper.py example.com --exhaustive -o full_scan
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
| `--exhaustive` | Query all 25 record types for every subdomain |

## Smart vs Exhaustive Mode

| Mode | Queries | Use Case |
|------|---------|----------|
| **Smart (default)** | ~1,500 | Daily use, quick scans |
| **Exhaustive** | ~7,500 | Thorough audits, unusual setups |
| **No subdomains** | 25 | Root domain only |

Smart mode queries only relevant record types per subdomain category:

| Category | Example Subdomains | Record Types |
|----------|-------------------|--------------|
| TXT + CNAME | `_dmarc`, `*._domainkey`, `_acme-challenge` | TXT, CNAME |
| TXT only | `_mta-sts`, `_facebook` | TXT |
| Mail | `mail`, `smtp`, `mx`, `autodiscover` | A, AAAA, CNAME, MX, TXT |
| Web | `www`, `cdn`, `static`, `mta-sts` | A, AAAA, CNAME |
| Common | `api`, `dev`, `admin` | A, AAAA, CNAME, MX, TXT, SRV |
| Root | (domain itself) | All 25 types |

### Why TXT + CNAME for DKIM/DMARC?

Many DNS records can be either direct TXT records or CNAME delegations:

```
# Direct TXT record
k1._domainkey.example.com.  TXT   "v=DKIM1; k=rsa; p=MIGf..."

# CNAME delegation (common with ESPs)
k1._domainkey.example.com.  CNAME dkim.klaviyo.com.
```

CNAME delegation lets email service providers rotate keys without requiring DNS changes.

## Examples

### Basic Scans

```bash
# Display results only (no export)
python3 dns_scraper.py example.com

# Export to all formats
python3 dns_scraper.py example.com -o results

# Quick scan - root domain only
python3 dns_scraper.py example.com --no-subdomains -o quick

# Thorough scan - all record types everywhere
python3 dns_scraper.py example.com --exhaustive -o thorough
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
    python3 dns_scraper.py "$$domain" -o "exports/$${domain}"
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

### Export and Process with Shell Tools

```bash
# Extract just A records from CSV
python3 dns_scraper.py example.com -f csv -o scan
grep ",A," scan.csv | cut -d',' -f1,4

# Count records by type
tail -n +2 scan.csv | cut -d',' -f2 | sort | uniq -c | sort -rn
```

### Cron Job for DNS Monitoring

```bash
#!/bin/bash
# dns_monitor.sh - Track DNS changes over time

DOMAIN="example.com"
DATE=$(date +%Y%m%d)
DIR="$$HOME/dns_history/$$DOMAIN"

mkdir -p "$DIR"
python3 dns_scraper.py "$$DOMAIN" -f csv -o "$$DIR/$DATE"

# Alert on changes
if [ -f "$DIR/latest.csv" ]; then
    if ! diff -q "$$DIR/$$DATE.csv" "$DIR/latest.csv" > /dev/null; then
        echo "DNS changes detected for $DOMAIN"
        diff "$$DIR/latest.csv" "$$DIR/$DATE.csv"
    fi
fi

ln -sf "$$DIR/$$DATE.csv" "$DIR/latest.csv"
```

### Combine with Certificate Transparency

```bash
#!/bin/bash
# comprehensive_scan.sh - Combine with CT logs

DOMAIN=\$1
OUTPUT_DIR="./recon_$DOMAIN"
mkdir -p "$OUTPUT_DIR"

# DNS Scraper
python3 dns_scraper.py "$$DOMAIN" -o "$$OUTPUT_DIR/dns" -v

# Certificate Transparency
curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" 2>/dev/null | \
    python3 -c "import sys,json; print('\n'.join(set(x['name_value'] for x in json.load(sys.stdin))))" | \
    sort -u > "$OUTPUT_DIR/ct_domains.txt"

# Combine results
cat "$$OUTPUT_DIR/dns.csv" | tail -n +2 | cut -d',' -f1 | sort -u > "$$OUTPUT_DIR/dns_domains.txt"
cat "$$OUTPUT_DIR/ct_domains.txt" "$$OUTPUT_DIR/dns_domains.txt" | sort -u > "$OUTPUT_DIR/all_domains.txt"

echo "Found $$(wc -l < "$$OUTPUT_DIR/all_domains.txt") unique hostnames"
```

## Subdomain Coverage

### Email Authentication Records

| Record Type | Subdomain | Valid DNS Types |
|-------------|-----------|-----------------|
| DMARC | `_dmarc` | TXT, CNAME |
| MTA-STS | `_mta-sts` | TXT only |
| MTA-STS Policy | `mta-sts` | A, AAAA, CNAME |
| TLS-RPT | `_smtp._tls` | TXT, CNAME |
| BIMI | `default._bimi` | TXT, CNAME |
| DKIM | `*._domainkey` | TXT, CNAME |

### Email Service Provider DKIM Selectors

| Provider | Selectors |
|----------|-----------|
| Klaviyo | `kl._domainkey`, `kl2._domainkey` |
| Mailchimp | `k2._domainkey`, `k3._domainkey`, `mte1._domainkey` |
| MailPoet | `mailpoet1._domainkey`, `mailpoet2._domainkey` |
| SendGrid | `s1._domainkey`, `s2._domainkey`, `smtpapi._domainkey` |
| Postmark | `pm._domainkey` |
| HubSpot | `hs1._domainkey`, `hs2._domainkey` |
| Salesforce | `sf._domainkey`, `pardot._domainkey` |
| ActiveCampaign | `acdkim1._domainkey`, `acdkim2._domainkey` |
| Google Workspace | `google._domainkey` |
| Microsoft 365 | `selector1._domainkey`, `selector2._domainkey` |
| Mailgun | `mailo._domainkey`, `mx._domainkey` |
| Brevo (Sendinblue) | `brevo._domainkey`, `sendinblue._domainkey` |
| ConvertKit | `convertkit._domainkey`, `ck._domainkey` |
| And more... | Mailjet, SparkPost, Zoho, Intercom, Customer.io, etc. |

### Verification Records (TXT or CNAME)

- `_google` - Google site verification
- `_github-challenge` - GitHub Pages
- `_stripe` - Stripe domain verification
- `_amazonses` - Amazon SES
- `_cf-custom-hostname` - Cloudflare
- `_atproto` - Bluesky
- `_domainconnect` - Domain Connect protocol
- `_acme-challenge` - Let's Encrypt / ACME

### TXT-Only Records (Strict RFC)

- `_mta-sts` - MTA-STS policy (RFC 8461)
- `_facebook` - Facebook domain verification

### Infrastructure Subdomains (200+)

- **Web**: `www`, `cdn`, `static`, `assets`, `api`
- **Mail**: `mail`, `smtp`, `mx`, `exchange`, `autodiscover`
- **Dev**: `dev`, `staging`, `test`, `beta`, `uat`
- **Admin**: `admin`, `cpanel`, `dashboard`, `portal`
- **Cloud**: `aws`, `azure`, `gcp`, `s3`, `storage`

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