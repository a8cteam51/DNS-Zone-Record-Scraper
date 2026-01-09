#!/usr/bin/env python3
"""
DNS Zone Record Scraper
Discovers and exports all available DNS records for a domain.
"""

import dns.resolver
import dns.zone
import dns.query
import dns.rdatatype
import csv
import argparse
import sys
from datetime import datetime
from typing import Dict, List, Tuple, Optional

# All DNS record types to query
RECORD_TYPES = [
    'A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'SRV', 'CAA',
    'PTR', 'DNSKEY', 'DS', 'NAPTR', 'SPF', 'TLSA', 'SSHFP', 'LOC',
    'HINFO', 'RP', 'AFSDB', 'CERT', 'DNAME', 'HTTPS', 'SVCB'
]

# Common subdomains to check (expands discovery)
COMMON_SUBDOMAINS = [
    '', 'www', 'mail', 'email', 'webmail', 'smtp', 'pop', 'imap',
    'ftp', 'sftp', 'ssh', 'vpn', 'remote', 'api', 'dev', 'staging',
    'test', 'beta', 'app', 'mobile', 'm', 'admin', 'portal', 'shop',
    'store', 'blog', 'news', 'support', 'help', 'docs', 'cdn', 'static',
    'assets', 'img', 'images', 'media', 'video', 'ns1', 'ns2', 'ns3',
    'dns', 'dns1', 'dns2', 'mx', 'mx1', 'mx2', 'exchange', 'autodiscover',
    'autoconfig', '_dmarc', '_domainkey', 'selector1._domainkey',
    'selector2._domainkey', 'google._domainkey', 'default._domainkey',
    '_mta-sts', '_smtp._tls', 'calendar', 'cal', 'meet', 'conference',
    'git', 'gitlab', 'github', 'bitbucket', 'jenkins', 'ci', 'jira',
    'confluence', 'wiki', 'intranet', 'internal', 'secure', 'login',
    'sso', 'auth', 'id', 'identity', 'account', 'accounts', 'billing',
    'pay', 'payment', 'checkout', 'cart', 'search', 'status', 'health',
    'monitor', 'grafana', 'prometheus', 'kibana', 'elastic', 'logs',
    'sentry', 'analytics', 'tracking', 'pixel', 'ad', 'ads', 'promo',
    'marketing', 'campaign', 'newsletter', 'subscribe', 'unsubscribe',
    'feedback', 'survey', 'forum', 'community', 'social', 'connect',
    'link', 'links', 'go', 'redirect', 'r', 'url', 's', 's1', 's2', 's3',
    'db', 'database', 'mysql', 'postgres', 'redis', 'mongo', 'cache',
    'memcached', 'queue', 'rabbit', 'kafka', 'zookeeper', 'consul',
    'vault', 'terraform', 'ansible', 'puppet', 'chef', 'docker', 'k8s',
    'kubernetes', 'rancher', 'swarm', 'mesos', 'marathon', 'nomad',
    'aws', 'azure', 'gcp', 'cloud', 'hosting', 'server', 'node', 'edge',
    'lb', 'loadbalancer', 'proxy', 'nginx', 'apache', 'haproxy', 'traefik',
    'envoy', 'istio', 'ingress', 'gateway', 'firewall', 'waf', 'ddos',
    'backup', 'archive', 'storage', 'files', 'download', 'downloads',
    'upload', 'uploads', 'share', 'drive', 'sync', 'dropbox', 'box',
    'onedrive', 'gdrive', 'slack', 'teams', 'zoom', 'webex', 'meet',
    'chat', 'im', 'irc', 'xmpp', 'matrix', 'discord', 'telegram',
    'whatsapp', 'signal', 'voice', 'voip', 'sip', 'pbx', 'asterisk',
    'phone', 'tel', 'fax', 'office', 'corp', 'corporate', 'enterprise',
    'business', 'work', 'company', 'org', 'organization', 'hr', 'jobs',
    'careers', 'recruit', 'talent', 'people', 'team', 'staff', 'employee',
    'partner', 'partners', 'affiliate', 'affiliates', 'reseller', 'dealer',
    'distributor', 'vendor', 'supplier', 'client', 'clients', 'customer',
    'customers', 'user', 'users', 'member', 'members', 'guest', 'guests',
    'demo', 'trial', 'free', 'premium', 'pro', 'plus', 'enterprise',
    'starter', 'basic', 'standard', 'advanced', 'ultimate', 'vip',
    '_acme-challenge', 'acme', 'letsencrypt', 'certbot', 'ssl', 'tls',
    'https', 'http', 'www2', 'www3', 'web', 'web1', 'web2', 'site',
    'new', 'old', 'legacy', 'v1', 'v2', 'v3', 'api-v1', 'api-v2',
    'graphql', 'rest', 'soap', 'rpc', 'grpc', 'websocket', 'ws', 'wss',
    'owa', 'cpanel', 'whm', 'plesk', 'directadmin', 'webmin', 'cockpit'
]

class DNSScraper:
    def __init__(self, domain: str, nameserver: Optional[str] = None, 
                 timeout: float = 5.0, verbose: bool = False,
                 check_subdomains: bool = True):
        self.domain = domain.lower().strip('.')
        self.timeout = timeout
        self.verbose = verbose
        self.check_subdomains = check_subdomains
        self.records: Dict[str, List[Tuple[str, str, int, str]]] = {}
        self.discovered_hosts: set = set()
        
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
    
    def scrape(self):
        """Main scraping function."""
        print(f"\n{'='*60}")
        print(f"DNS Record Scraper - Scanning: {self.domain}")
        print(f"{'='*60}\n")
        
        # Try zone transfer first
        if self.try_zone_transfer():
            return  # Got everything from zone transfer
        
        # Manual enumeration
        print("[*] Performing manual DNS enumeration...")
        
        # Build list of hostnames to check
        hostnames_to_check = [self.domain]
        
        if self.check_subdomains:
            print(f"[*] Checking {len(COMMON_SUBDOMAINS)} common subdomains...")
            for subdomain in COMMON_SUBDOMAINS:
                if subdomain:
                    hostnames_to_check.append(f"{subdomain}.{self.domain}")
        
        # Query each hostname for each record type
        total_queries = len(hostnames_to_check) * len(RECORD_TYPES)
        completed = 0
        
        for hostname in hostnames_to_check:
            for record_type in RECORD_TYPES:
                self.query_record_type(hostname, record_type)
                completed += 1
                
                # Progress indicator (update every 100 queries)
                if completed % 100 == 0:
                    pct = (completed / total_queries) * 100
                    print(f"\r[*] Progress: {completed}/{total_queries} ({pct:.1f}%)", 
                          end='', flush=True)
        
        print(f"\r[*] Progress: {completed}/{total_queries} (100.0%)    ")
        print(f"\n[+] Found {sum(len(v) for v in self.records.values())} DNS records")
    
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
                    
                    f.write(f"{rel_name:<30} {ttl:<8} IN {rtype:<8} {value}\n")
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
                print(f"  {hostname:<40} {ttl:<8} {value}")


def main():
    parser = argparse.ArgumentParser(
        description='DNS Zone Record Scraper - Discover and export DNS records',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s example.com
  %(prog)s example.com -o zone_export
  %(prog)s example.com --nameserver 8.8.8.8 --verbose
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
    
    args = parser.parse_args()
    
    # Create scraper
    scraper = DNSScraper(
        domain=args.domain,
        nameserver=args.nameserver,
        timeout=args.timeout,
        verbose=args.verbose,
        check_subdomains=not args.no_subdomains
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