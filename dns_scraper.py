#!/usr/bin/env python3
"""
DNS Zone Record Scraper
Discovers and exports all available DNS records for a domain.
Uses smart record-type selection by default to minimize unnecessary queries.
"""

import dns.resolver
import dns.zone
import dns.query
import dns.rdatatype
import csv
import argparse
import sys
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Set

# All DNS record types
ALL_RECORD_TYPES = [
    'A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'SRV', 'CAA',
    'PTR', 'DNSKEY', 'DS', 'NAPTR', 'SPF', 'TLSA', 'SSHFP', 'LOC',
    'HINFO', 'RP', 'AFSDB', 'CERT', 'DNAME', 'HTTPS', 'SVCB'
]

# Smart record type sets for different subdomain categories
RECORD_TYPES_TXT_CNAME = ['TXT', 'CNAME']  # Most underscore records
RECORD_TYPES_TXT_ONLY = ['TXT']  # Strict TXT-only records
RECORD_TYPES_MAIL = ['A', 'AAAA', 'CNAME', 'MX', 'TXT']
RECORD_TYPES_WEB = ['A', 'AAAA', 'CNAME', 'TXT']
RECORD_TYPES_COMMON = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'SRV']
RECORD_TYPES_ROOT = ALL_RECORD_TYPES  # Query everything for root domain

# =============================================================================
# SUBDOMAIN DEFINITIONS WITH CATEGORIES
# =============================================================================

# TXT or CNAME subdomains (DKIM, DMARC, BIMI, verification records, etc.)
# These can be either TXT records OR CNAME delegations to service providers
SUBDOMAINS_TXT_CNAME = [
    # DMARC - can be CNAME for DMARC-as-a-service
    '_dmarc',
    
    # TLS Reporting - can be CNAME for delegation
    '_smtp._tls',
    
    # BIMI - can be CNAME for BIMI services
    'default._bimi',
    '_bimi',
    
    # ACME/Let's Encrypt - CNAME delegation to acme-dns is common
    '_acme-challenge',
    
    # Domain Connect - can be TXT or CNAME
    '_domainconnect',
    
    # Generic DKIM selectors - CNAME very common for ESP key rotation
    '_domainkey',
    'default._domainkey',
    'dkim._domainkey',
    'mail._domainkey',
    'email._domainkey',
    'selector1._domainkey',
    'selector2._domainkey',
    's1._domainkey',
    's2._domainkey',
    'k1._domainkey',
    'k2._domainkey',
    'k3._domainkey',
    'key1._domainkey',
    'key2._domainkey',
    'openhosting1._domainkey',
    'openhosting2._domainkey',
    'openhosting1._domainkey.www',
    'openhosting2._domainkey.www',
    
    # Klaviyo DKIM
    'kl._domainkey',
    'kl2._domainkey',
    'kl1._domainkey',
    
    # Mailchimp / Mandrill DKIM
    'mte1._domainkey',
    'mte2._domainkey',
    'mandrill._domainkey',
    
    # MailPoet DKIM
    'mailpoet1._domainkey',
    'mailpoet2._domainkey',
    
    # SendGrid DKIM
    'smtpapi._domainkey',
    
    # Postmark DKIM
    'pm._domainkey',
    
    # Amazon SES DKIM
    'amazonses._domainkey',
    
    # Google Workspace DKIM
    'google._domainkey',
    'ga1._domainkey',
    
    # Microsoft 365 DKIM
    'selector1._domainkey',
    'selector2._domainkey',
    
    # HubSpot DKIM
    'hs1._domainkey',
    'hs2._domainkey',
    'hubspot._domainkey',
    
    # Salesforce / Pardot DKIM
    'sf._domainkey',
    'sf1._domainkey',
    'sf2._domainkey',
    'pardot._domainkey',
    'm1._domainkey',
    
    # ActiveCampaign DKIM
    'acdkim1._domainkey',
    'acdkim2._domainkey',
    'ac._domainkey',
    
    # ConvertKit DKIM
    'convertkit._domainkey',
    'ck._domainkey',
    
    # Constant Contact DKIM
    'ctct1._domainkey',
    'ctct2._domainkey',
    
    # Campaign Monitor DKIM
    'cm._domainkey',
    
    # Drip DKIM
    'drip._domainkey',
    
    # GetResponse DKIM
    'getresponse._domainkey',
    
    # AWeber DKIM
    'aweber._domainkey',
    
    # Brevo (Sendinblue) DKIM
    'brevo._domainkey',
    'sendinblue._domainkey',
    
    # Mailgun DKIM
    'mailo._domainkey',
    'mx._domainkey',
    'smtp._domainkey',
    
    # SparkPost DKIM
    'sparkpost._domainkey',
    'sp._domainkey',
    
    # Mailjet DKIM
    'mailjet._domainkey',
    
    # Elastic Email DKIM
    'elasticemail._domainkey',
    
    # Zoho DKIM
    'zoho._domainkey',
    'zmail._domainkey',
    
    # Intercom DKIM
    'intercom._domainkey',
    
    # Customer.io DKIM
    'customerio._domainkey',
    'cio._domainkey',
    
    # Iterable DKIM
    'iterable._domainkey',
    
    # Google site verification - supports TXT or CNAME
    '_google',
    
    # GitHub Pages verification
    '_github-challenge',
    '_github',
    
    # Stripe verification
    '_stripe',
    
    # Cloudflare custom hostname
    '_cf-custom-hostname',
    
    # Bluesky/AT Protocol
    '_atproto',
    
    # Discord verification
    '_discord',
    
    # Slack verification  
    '_slack',
    
    # Amazon SES verification
    '_amazonses',
    
    # SPF flattening services
    '_spf',
]

# TXT-only subdomains (strict RFC requirements)
SUBDOMAINS_TXT_ONLY = [
    # MTA-STS DNS record - RFC 8461 specifies TXT only
    '_mta-sts',
    
    # Facebook domain verification - only supports TXT
    '_facebook',
]

# MTA-STS policy hosting subdomain (serves the policy file over HTTPS)
SUBDOMAINS_MTA_STS_POLICY = [
    'mta-sts',  # A/AAAA/CNAME - points to web server hosting policy
]

# Mail infrastructure subdomains
SUBDOMAINS_MAIL = [
    'mail', 'mail1', 'mail2', 'mail3',
    'email', 'smtp', 'smtp1', 'smtp2',
    'pop', 'pop3', 'imap',
    'webmail', 'webmail2',
    'mx', 'mx1', 'mx2', 'mx3',
    'mta', 'relay', 'outbound', 'inbound',
    'postfix', 'sendmail',
    'exchange', 'owa',
    'autodiscover',
    'autoconfig',
    'lyncdiscover',
    'pm-bounces',
    'bounce', 'bounces',
    'send',  # Klaviyo sending subdomain
    'em',    # SendGrid link tracking
    'click', # Click tracking
    'track', # Tracking
    'links', # Link tracking
]

# Web/CDN subdomains (typically just A/AAAA/CNAME/TXT)
SUBDOMAINS_WEB = [
    'www', 'www2', 'www3',
    'web', 'web1', 'web2',
    'site', 'sites',
    'cdn', 'static', 'assets', 'media', 'images', 'img', 'files',
    'download', 'downloads', 'upload', 'uploads',
    'edge', 'node', 'origin',
    'us', 'eu', 'uk', 'de', 'fr', 'jp', 'au', 'ca',
    'us-east', 'us-west', 'eu-west',
    'm', 'mobile', 'mobi',
    'ios', 'android',
]

# Common subdomains (A, AAAA, CNAME, MX, TXT, SRV)
SUBDOMAINS_COMMON = [
    # Apps / Services
    'app', 'apps', 'application',
    'portal', 'my', 'account', 'accounts',
    'api', 'api1', 'api2', 'api-v1', 'api-v2',
    'graphql', 'rest', 'ws', 'wss', 'websocket',
    
    # DNS Infrastructure
    'ns', 'ns1', 'ns2', 'ns3', 'ns4',
    'dns', 'dns1', 'dns2',
    
    # Security / Auth
    'auth', 'authentication', 'authorize',
    'sso', 'login', 'signin', 'signup',
    'id', 'identity', 'idp',
    'oauth', 'oauth2',
    'secure', 'security',
    'ssl', 'tls', 'https',
    'cert', 'certs', 'certificates',
    'acme',
    
    # Development / Staging
    'dev', 'develop', 'development',
    'staging', 'stage', 'stg',
    'test', 'testing', 'qa',
    'beta', 'alpha', 'preview',
    'demo', 'sandbox', 'trial',
    'uat',
    'preprod', 'pre-prod',
    'local', 'localhost',
    
    # DevOps / CI/CD / Monitoring
    'git', 'gitlab', 'github', 'bitbucket',
    'jenkins', 'ci', 'cd', 'build', 'deploy',
    'docker', 'k8s', 'kubernetes', 'rancher',
    'terraform', 'ansible', 'puppet', 'chef',
    'monitor', 'monitoring', 'status', 'health', 'uptime',
    'grafana', 'prometheus', 'kibana', 'elastic',
    'logs', 'logging', 'sentry', 'newrelic', 'datadog',
    'metrics', 'analytics', 'stats', 'statistics',
    
    # Cloud / Infrastructure
    'cloud', 'aws', 'azure', 'gcp', 'gcloud',
    's3', 'storage', 'bucket', 'blob',
    'lb', 'loadbalancer', 'elb', 'alb',
    'proxy', 'nginx', 'apache', 'haproxy', 'traefik',
    'gateway', 'gw', 'ingress', 'egress',
    'vpn', 'remote', 'bastion', 'jump',
    'firewall', 'waf',
    
    # Database
    'db', 'db1', 'db2', 'database',
    'mysql', 'postgres', 'postgresql', 'pgsql',
    'mongo', 'mongodb', 'redis', 'memcached',
    'elasticsearch',
    'sql', 'mssql', 'oracle',
    
    # Business / Marketing
    'blog', 'news', 'press',
    'shop', 'store', 'ecommerce', 'cart', 'checkout',
    'pay', 'payment', 'payments', 'billing',
    'crm', 'erp', 'sales',
    'support', 'help', 'helpdesk', 'desk', 'ticket', 'tickets',
    'docs', 'documentation', 'wiki', 'kb', 'knowledge',
    'forum', 'forums', 'community', 'discuss',
    'chat', 'live', 'livechat',
    'marketing', 'campaign', 'campaigns',
    'newsletter', 'subscribe', 'unsubscribe',
    'tracking', 'pixel', 'beacon',
    'link', 'go', 'redirect', 'r', 'l',
    
    # Collaboration / Communication
    'meet', 'meeting', 'meetings', 'conference',
    'zoom', 'webex', 'teams',
    'slack', 'discord',
    'calendar', 'cal', 'schedule',
    'intranet', 'internal', 'corp', 'corporate',
    'hr', 'people', 'team', 'staff',
    'jobs', 'careers', 'recruit', 'hiring',
    
    # FTP / File Transfer
    'ftp', 'ftp1', 'ftp2',
    'sftp', 'ftps',
    'ssh', 'shell',
    'share', 'sharing', 'transfer',
    
    # Admin / Management
    'admin', 'administrator', 'manage', 'management',
    'panel', 'cpanel', 'whm', 'plesk', 'webmin',
    'console', 'dashboard',
    'backend', 'backoffice',
    
    # Versioning / Old
    'v1', 'v2', 'v3',
    'old', 'legacy', 'archive',
    'new', 'next',
    
    # VoIP / Telephony
    'sip', 'voip', 'phone', 'pbx', 'asterisk',
    'tel', 'voice', 'call',
    
    # WordPress / CMS
    'wp', 'wordpress',
    'woo', 'woocommerce',
    'cms', 'content',
    
    # E-commerce platforms
    'shopify', 'magento', 'bigcommerce',
]


class DNSScraper:
    def __init__(self, domain: str, nameserver: Optional[str] = None,
                 timeout: float = 5.0, verbose: bool = False,
                 check_subdomains: bool = True, exhaustive: bool = False):
        self.domain = domain.lower().strip('.')
        self.timeout = timeout
        self.verbose = verbose
        self.check_subdomains = check_subdomains
        self.exhaustive = exhaustive
        self.records: Dict[str, List[Tuple[str, str, int, str]]] = {}
        self.discovered_hosts: Set[str] = set()
        self.query_count = 0
        
        # Configure resolver
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout * 2
        
        if nameserver:
            self.resolver.nameservers = [nameserver]
    
    def log(self, message: str):
        """Print verbose output."""
        if self.verbose:
            print(f"[*] {message}")
    
    def try_zone_transfer(self) -> bool:
        """Attempt a zone transfer (AXFR) - rarely works but worth trying."""
        self.log(f"Attempting zone transfer for {self.domain}...")
        
        try:
            # First get NS records
            ns_records = self.resolver.resolve(self.domain, 'NS')
            
            for ns in ns_records:
                ns_host = str(ns.target).rstrip('.')
                self.log(f"Trying AXFR from {ns_host}...")
                
                try:
                    # Get IP of nameserver
                    ns_ip = str(self.resolver.resolve(ns_host, 'A')[0])
                    
                    # Attempt zone transfer
                    zone = dns.zone.from_xfr(
                        dns.query.xfr(ns_ip, self.domain, timeout=self.timeout)
                    )
                    
                    # If successful, parse all records
                    for name, node in zone.nodes.items():
                        for rdataset in node.rdatasets:
                            record_type = dns.rdatatype.to_text(rdataset.rdtype)
                            for rdata in rdataset:
                                hostname = str(name)
                                if hostname == '@':
                                    hostname = self.domain
                                elif not hostname.endswith(self.domain):
                                    hostname = f"{hostname}.{self.domain}"
                                
                                self._add_record(
                                    hostname, record_type,
                                    rdataset.ttl, str(rdata)
                                )
                    
                    print(f"[+] Zone transfer successful from {ns_host}!")
                    return True
                    
                except Exception as e:
                    self.log(f"AXFR failed from {ns_host}: {e}")
                    continue
                    
        except Exception as e:
            self.log(f"Could not get NS records for zone transfer: {e}")
        
        self.log("Zone transfer not available (this is normal)")
        return False
    
    def _add_record(self, hostname: str, record_type: str, ttl: int, value: str):
        """Add a record to the collection."""
        key = f"{hostname}|{record_type}|{value}"
        if key not in self.discovered_hosts:
            self.discovered_hosts.add(key)
            
            if record_type not in self.records:
                self.records[record_type] = []
            
            self.records[record_type].append((hostname, record_type, ttl, value))
            
            if self.verbose:
                print(f"  [+] {hostname} {ttl} IN {record_type} {value}")
    
    def query_record_type(self, hostname: str, record_type: str):
        """Query a specific record type for a hostname."""
        self.query_count += 1
        
        try:
            answers = self.resolver.resolve(hostname, record_type)
            
            for rdata in answers:
                value = str(rdata)
                
                # Format specific record types nicely
                if record_type == 'MX':
                    value = f"{rdata.preference} {rdata.exchange}"
                elif record_type == 'SOA':
                    value = (f"{rdata.mname} {rdata.rname} {rdata.serial} "
                            f"{rdata.refresh} {rdata.retry} {rdata.expire} "
                            f"{rdata.minimum}")
                elif record_type == 'SRV':
                    value = f"{rdata.priority} {rdata.weight} {rdata.port} {rdata.target}"
                elif record_type == 'CAA':
                    value = f'{rdata.flags} {rdata.tag} "{rdata.value}"'
                elif record_type == 'TXT':
                    # Handle TXT records with multiple strings
                    if hasattr(rdata, 'strings'):
                        value = ''.join(s.decode() if isinstance(s, bytes) else s
                                       for s in rdata.strings)
                    value = f'"{value}"'
                
                self._add_record(hostname, record_type, answers.ttl, value)
                
        except dns.resolver.NXDOMAIN:
            pass  # Domain doesn't exist
        except dns.resolver.NoAnswer:
            pass  # No records of this type
        except dns.resolver.NoNameservers:
            pass  # No nameservers available
        except dns.exception.Timeout:
            self.log(f"Timeout querying {record_type} for {hostname}")
        except Exception as e:
            self.log(f"Error querying {record_type} for {hostname}: {e}")
    
    def query_hostname(self, hostname: str, record_types: List[str]):
        """Query multiple record types for a hostname."""
        for record_type in record_types:
            self.query_record_type(hostname, record_type)
    
    def _build_query_plan(self) -> List[Tuple[str, List[str]]]:
        """Build a list of (hostname, record_types) tuples to query."""
        query_plan = []
        
        # Root domain - query all record types
        query_plan.append((self.domain, RECORD_TYPES_ROOT))
        
        if not self.check_subdomains:
            return query_plan
        
        if self.exhaustive:
            # Exhaustive mode: query all record types for all subdomains
            all_subdomains = (
                SUBDOMAINS_TXT_CNAME +
                SUBDOMAINS_TXT_ONLY +
                SUBDOMAINS_MTA_STS_POLICY +
                SUBDOMAINS_MAIL +
                SUBDOMAINS_WEB +
                SUBDOMAINS_COMMON
            )
            for subdomain in all_subdomains:
                hostname = f"{subdomain}.{self.domain}"
                query_plan.append((hostname, ALL_RECORD_TYPES))
        else:
            # Smart mode: query only relevant record types per subdomain category
            
            # TXT or CNAME records (DKIM, DMARC, BIMI, verification, etc.)
            for subdomain in SUBDOMAINS_TXT_CNAME:
                hostname = f"{subdomain}.{self.domain}"
                query_plan.append((hostname, RECORD_TYPES_TXT_CNAME))
            
            # TXT-only records (strict RFC requirements)
            for subdomain in SUBDOMAINS_TXT_ONLY:
                hostname = f"{subdomain}.{self.domain}"
                query_plan.append((hostname, RECORD_TYPES_TXT_ONLY))
            
            # MTA-STS policy hosting (web server)
            for subdomain in SUBDOMAINS_MTA_STS_POLICY:
                hostname = f"{subdomain}.{self.domain}"
                query_plan.append((hostname, RECORD_TYPES_WEB))
            
            # Mail infrastructure
            for subdomain in SUBDOMAINS_MAIL:
                hostname = f"{subdomain}.{self.domain}"
                query_plan.append((hostname, RECORD_TYPES_MAIL))
            
            # Web/CDN subdomains
            for subdomain in SUBDOMAINS_WEB:
                hostname = f"{subdomain}.{self.domain}"
                query_plan.append((hostname, RECORD_TYPES_WEB))
            
            # Common subdomains
            for subdomain in SUBDOMAINS_COMMON:
                hostname = f"{subdomain}.{self.domain}"
                query_plan.append((hostname, RECORD_TYPES_COMMON))
        
        return query_plan
    
    def scrape(self):
        """Main scraping function."""
        print(f"\n{'='*60}")
        print(f"DNS Record Scraper - Scanning: {self.domain}")
        print(f"{'='*60}")
        
        mode = "EXHAUSTIVE" if self.exhaustive else "SMART"
        print(f"Mode: {mode}")
        
        if not self.check_subdomains:
            print("Subdomain enumeration: DISABLED")
        print()
        
        # Try zone transfer first
        if self.try_zone_transfer():
            return  # Got everything from zone transfer
        
        # Build query plan
        query_plan = self._build_query_plan()
        
        # Calculate total queries
        total_queries = sum(len(record_types) for _, record_types in query_plan)
        
        print(f"[*] Performing DNS enumeration...")
        print(f"[*] Hostnames to check: {len(query_plan)}")
        print(f"[*] Total queries planned: {total_queries}")
        print()
        
        # Execute queries
        completed = 0
        for hostname, record_types in query_plan:
            for record_type in record_types:
                self.query_record_type(hostname, record_type)
                completed += 1
                
                # Progress indicator
                if completed % 50 == 0 or completed == total_queries:
                    pct = (completed / total_queries) * 100
                    print(f"\r[*] Progress: {completed}/{total_queries} ({pct:.1f}%)",
                          end='', flush=True)
        
        print(f"\r[*] Progress: {completed}/{total_queries} (100.0%)    ")
        print(f"\n[+] Found {sum(len(v) for v in self.records.values())} DNS records")
        print(f"[+] Total DNS queries made: {self.query_count}")
    
    def export_bind(self, filename: str):
        """Export records in BIND zone file format."""
        with open(filename, 'w') as f:
            f.write(f"; DNS Zone Export for {self.domain}\n")
            f.write(f"; Generated: {datetime.now().isoformat()}\n")
            f.write(f"; Tool: DNS Zone Record Scraper\n")
            f.write(f";\n")
            f.write(f"$ORIGIN {self.domain}.\n")
            f.write(f"$TTL 3600\n\n")
            
            # Sort by record type for readability
            for record_type in sorted(self.records.keys()):
                f.write(f"; {record_type} Records\n")
                for hostname, rtype, ttl, value in sorted(self.records[record_type]):
                    # Convert to relative name if possible
                    if hostname == self.domain:
                        rel_name = '@'
                    elif hostname.endswith(f'.{self.domain}'):
                        rel_name = hostname[:-len(self.domain)-1]
                    else:
                        rel_name = hostname
                    
                    f.write(f"{rel_name:<40} {ttl:<8} IN {rtype:<8} {value}\n")
                f.write("\n")
        
        print(f"[+] Exported BIND format to: {filename}")
    
    def export_csv(self, filename: str):
        """Export records in CSV format."""
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Hostname', 'Record Type', 'TTL', 'Value'])
            
            for record_type in sorted(self.records.keys()):
                for hostname, rtype, ttl, value in sorted(self.records[record_type]):
                    writer.writerow([hostname, rtype, ttl, value])
        
        print(f"[+] Exported CSV format to: {filename}")
    
    def export_txt(self, filename: str):
        """Export records in human-readable text format."""
        with open(filename, 'w') as f:
            f.write(f"DNS Records for: {self.domain}\n")
            f.write(f"Generated: {datetime.now().isoformat()}\n")
            f.write(f"{'='*70}\n\n")
            
            for record_type in sorted(self.records.keys()):
                f.write(f"\n{record_type} Records ({len(self.records[record_type])})\n")
                f.write(f"{'-'*50}\n")
                for hostname, rtype, ttl, value in sorted(self.records[record_type]):
                    f.write(f"  {hostname}\n")
                    f.write(f"    TTL: {ttl}\n")
                    f.write(f"    Value: {value}\n\n")
        
        print(f"[+] Exported text format to: {filename}")
    
    def print_summary(self):
        """Print a summary of discovered records."""
        print(f"\n{'='*60}")
        print(f"SUMMARY - {self.domain}")
        print(f"{'='*60}\n")
        
        if not self.records:
            print("No records found.")
            return
        
        # Print counts by type
        print("Records by Type:")
        print("-" * 30)
        for record_type in sorted(self.records.keys()):
            count = len(self.records[record_type])
            print(f"  {record_type:<12} {count:>5} record(s)")
        
        total = sum(len(v) for v in self.records.values())
        print("-" * 30)
        print(f"  {'TOTAL':<12} {total:>5} record(s)")
        
        # Print actual records
        print(f"\n{'='*60}")
        print("DETAILED RECORDS")
        print(f"{'='*60}\n")
        
        for record_type in sorted(self.records.keys()):
            print(f"\n[{record_type}]")
            for hostname, rtype, ttl, value in sorted(self.records[record_type]):
                print(f"  {hostname:<50} {ttl:<8} {value}")


def main():
    parser = argparse.ArgumentParser(
        description='DNS Zone Record Scraper - Discover and export DNS records',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s example.com
  %(prog)s example.com -o zone_export
  %(prog)s example.com --nameserver 8.8.8.8 --verbose
  %(prog)s example.com --exhaustive  # Query all record types for all subdomains
  %(prog)s example.com --no-subdomains --format csv
        """
    )
    
    parser.add_argument('domain', help='Domain name to scan')
    parser.add_argument('-o', '--output', help='Output filename (without extension)')
    parser.add_argument('-f', '--format', choices=['bind', 'csv', 'txt', 'all'],
                        default='all', help='Export format (default: all)')
    parser.add_argument('-n', '--nameserver', help='Custom DNS server to use')
    parser.add_argument('-t', '--timeout', type=float, default=5.0,
                        help='Query timeout in seconds (default: 5.0)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Verbose output')
    parser.add_argument('--no-subdomains', action='store_true',
                        help='Skip subdomain enumeration (faster but less complete)')
    parser.add_argument('--exhaustive', action='store_true',
                        help='Query ALL record types for ALL subdomains (slower, more thorough)')
    
    args = parser.parse_args()
    
    # Create scraper
    scraper = DNSScraper(
        domain=args.domain,
        nameserver=args.nameserver,
        timeout=args.timeout,
        verbose=args.verbose,
        check_subdomains=not args.no_subdomains,
        exhaustive=args.exhaustive
    )
    
    # Run the scan
    try:
        scraper.scrape()
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(1)
    
    # Print summary
    scraper.print_summary()
    
    # Export if output specified
    if args.output:
        base_filename = args.output
        
        if args.format in ['bind', 'all']:
            scraper.export_bind(f"{base_filename}.zone")
        if args.format in ['csv', 'all']:
            scraper.export_csv(f"{base_filename}.csv")
        if args.format in ['txt', 'all']:
            scraper.export_txt(f"{base_filename}.txt")
    
    print("\n[+] Scan complete!")


if __name__ == '__main__':
    main()