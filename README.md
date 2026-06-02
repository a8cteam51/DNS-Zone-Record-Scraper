# DNS Zone Record Scraper

Python command-line utility for discovering DNS records for a domain and exporting
the results. The script checks for Cloudflare DNS, attempts an AXFR zone
transfer, then enumerates the root domain and a static set of common subdomains.

## Repository Contents

- `dns_scraper.py` - CLI entry point and `DNSScraper` implementation.
- `requirements.txt` - Python dependency list.
- `.gitignore` - ignores generated DNS exports, local output directories, virtual
  environments, Python caches, and macOS metadata.
- `LICENSE` - MIT license.

No CI workflow, deploy configuration, package manifest, lockfile, or automated
lint/test configuration is currently tracked.

## Requirements

- Python 3.8 or newer, as documented by the project.
- `pip` and a Python virtual environment.
- Network access to DNS resolvers for the domains being scanned.

Install the runtime dependency from `requirements.txt`:

```sh
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

The only tracked Python package requirement is:

```text
dnspython>=2.6.1,<3.0.0
```

## Usage

Run a scan without writing export files:

```sh
python3 dns_scraper.py example.com
```

Write all supported export formats using a shared base filename:

```sh
python3 dns_scraper.py example.com -o example_dns
```

Run a root-domain-only scan and export CSV:

```sh
python3 dns_scraper.py example.com --no-subdomains --format csv -o quick_scan
```

Run exhaustive mode, which queries every configured record type for every
configured subdomain:

```sh
python3 dns_scraper.py example.com --exhaustive -o full_scan
```

## CLI Options

| Option | Description |
| --- | --- |
| `domain` | Domain name to scan. |
| `-o, --output` | Output filename without extension. When set, exports are written after the terminal summary. |
| `-f, --format` | Export format: `bind`, `csv`, `txt`, or `all`. Defaults to `all`. |
| `-n, --nameserver` | Custom DNS server to query, such as `8.8.8.8`. |
| `-t, --timeout` | Query timeout in seconds. Defaults to `5.0`. |
| `-v, --verbose` | Print each discovered record and additional scan details. |
| `--no-subdomains` | Query only the root domain. |
| `--exhaustive` | Query all configured record types for all configured subdomains. |

## Scan Behavior

The scraper first checks the domain's NS records for Cloudflare nameserver
patterns:

- `.ns.cloudflare.com`
- `.foundationdns.com`
- `.foundationdns.net`
- `.foundationdns.org`

When Cloudflare DNS is detected, the terminal output, BIND export, TXT export,
and CSV `Warning` column note that A and AAAA records may be Cloudflare edge
addresses when the records are proxied.

After the Cloudflare check, the scraper attempts a zone transfer from discovered
nameservers. If AXFR succeeds, the transferred records are used. If it does not
succeed, the scraper builds a query plan from constants in `dns_scraper.py`.

The root domain is queried for the configured record types in `ALL_RECORD_TYPES`:

```text
A, AAAA, CNAME, MX, TXT, NS, SOA, SRV, CAA, PTR, DNSKEY, DS, NAPTR, SPF,
TLSA, SSHFP, LOC, HINFO, RP, AFSDB, CERT, DNAME, HTTPS, SVCB
```

By default, smart mode queries subdomains with category-specific record type
sets, such as TXT/CNAME records for DKIM and verification names, SRV records for
service discovery names, TLSA records for DANE names, mail-oriented records for
mail hosts, web-oriented records for web and CDN hosts, and a broader set for
common application and infrastructure names.

Exhaustive mode queries every configured root record type for every configured
subdomain. It is slower and produces more DNS traffic than smart mode.

## Output Formats

Exports are only written when `-o` or `--output` is provided.

- BIND zone-style output: `<output>.zone`
- CSV output with `Hostname,Record Type,TTL,Value,Warning`: `<output>.csv`
- Human-readable text output: `<output>.txt`

Generated `.zone`, `.csv`, and `.txt` files are ignored by `.gitignore`, except
for the tracked `requirements.txt` file.

## Maintenance Notes

- Update DNS record type coverage and subdomain coverage in the constants near
  the top of `dns_scraper.py`.
- Add Python dependencies to `requirements.txt`.
- Avoid committing generated exports, `output/`, `exports/`, `results/`, virtual
  environments, or Python cache files.
- Because no automated test or lint command is tracked, use targeted manual
  checks after code changes, such as `python3 -m py_compile dns_scraper.py`.

## Limitations

- Static subdomain enumeration cannot discover arbitrary or randomly named
  subdomains.
- AXFR usually requires explicit DNS server permission and often fails.
- DNS firewalls, split-horizon DNS, and internal-only records may hide records
  from public resolvers.
- Cloudflare-proxied A and AAAA records can return edge IP addresses rather than
  origin IP addresses.
- The scraper does not call DNS provider APIs.

## License

MIT. See `LICENSE`.
