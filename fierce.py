#!/usr/bin/env python3

import argparse
import socket
import dns.resolver
import ipaddress
import concurrent.futures
import requests
import whois
import re
import sys
import logging
from urllib.parse import urlparse

class AdvancedNetworkReconnaissance:
    def __init__(self, verbose=False):
        self.banner = """
 ███████╗██╗███████╗██████╗  ██████╗███████╗
 ██╔════╝██║██╔════╝██╔══██╗██╔════╝██╔════╝
 █████╗  ██║█████╗  ██████╔╝██║     █████╗  
 ██╔══╝  ██║██╔══╝  ██╔══██╗██║     ██╔══╝  
 ██║     ██║███████╗██║  ██║╚██████╗███████╗
 ╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝╚══════╝ v0.1
 
 Advanced Network Reconnaissance Tool
 GitHub: https://www.github.com/Rip70022
"""
        self.verbose = verbose
        logging.basicConfig(
            level=logging.INFO if verbose else logging.WARNING,
            format='%(asctime)s - %(levelname)s: %(message)s'
        )
        self.logger = logging.getLogger(__name__)
    
    def print_banner(self):
        print(self.banner)
    
    def dns_advanced_lookup(self, domain):
        try:
            self.logger.info(f"Performing advanced DNS lookup for {domain}")
            
            results = {
                'A': [],
                'AAAA': [],
                'MX': [],
                'NS': [],
                'TXT': [],
                'CNAME': []
            }
            
            for record_type in results.keys():
                try:
                    records = dns.resolver.resolve(domain, record_type)
                    results[record_type] = [str(rdata) for rdata in records]
                except dns.resolver.NoAnswer:
                    self.logger.debug(f"No {record_type} records found")
                except dns.resolver.NXDOMAIN:
                    self.logger.warning(f"Domain {domain} does not exist")
                    return None
            
            return results
        
        except Exception as e:
            self.logger.error(f"DNS lookup error: {e}")
            return None
    
    def subdomain_enumeration(self, domain, wordlist=None):
        if not wordlist:
            wordlist = ['www', 'mail', 'ftp', 'admin', 'blog', 'dev', 'test', 'staging']
        
        discovered_subdomains = []
        
        def check_subdomain(subdomain):
            full_domain = f"{subdomain}.{domain}"
            try:
                ip_addresses = socket.gethostbyname_ex(full_domain)[2]
                if ip_addresses:
                    discovered_subdomains.append({
                        'subdomain': full_domain,
                        'ips': ip_addresses
                    })
            except (socket.gaierror, socket.herror):
                pass
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            executor.map(check_subdomain, wordlist)
        
        return discovered_subdomains
    
    def port_scan(self, target, ports=None):
        if not ports:
            ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389]
        
        open_ports = []
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except Exception:
                pass
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            executor.map(scan_port, ports)
        
        return open_ports
    
    def whois_lookup(self, domain):
        try:
            w = whois.whois(domain)
            return {
                'registrar': w.registrar,
                'creation_date': w.creation_date,
                'expiration_date': w.expiration_date,
                'name_servers': w.name_servers
            }
        except Exception as e:
            self.logger.error(f"WHOIS lookup error: {e}")
            return None
    
    def ssl_info(self, domain):
        try:
            url = f"https://{domain}"
            response = requests.get(url, timeout=5)
            cert = response.ssl_certificate
            return {
                'issuer': cert.get('issuer'),
                'subject': cert.get('subject'),
                'version': cert.get('version'),
                'serial_number': cert.get('serialNumber')
            }
        except Exception as e:
            self.logger.error(f"SSL info retrieval error: {e}")
            return None
    
    def main(self):
        parser = argparse.ArgumentParser(description="Advanced Network Recon Tool")
        parser.add_argument("-d", "--domain", help="Domain to investigate")
        parser.add_argument("-s", "--subnet", help="Subnet to scan")
        parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
        
        args = parser.parse_args()
        
        self.print_banner()
        
        if args.domain:
            self.logger.info(f"Starting reconnaissance for {args.domain}")
            
            dns_results = self.dns_advanced_lookup(args.domain)
            if dns_results:
                print("\n[+] DNS Records:")
                for record_type, records in dns_results.items():
                    if records:
                        print(f"    {record_type}: {records}")
            
            subdomains = self.subdomain_enumeration(args.domain)
            if subdomains:
                print("\n[+] Discovered Subdomains:")
                for subdomain in subdomains:
                    print(f"    {subdomain['subdomain']}: {subdomain['ips']}")
            
            whois_info = self.whois_lookup(args.domain)
            if whois_info:
                print("\n[+] WHOIS Information:")
                for key, value in whois_info.items():
                    print(f"    {key.replace('_', ' ').title()}: {value}")
            
            ssl_details = self.ssl_info(args.domain)
            if ssl_details:
                print("\n[+] SSL Certificate Details:")
                for key, value in ssl_details.items():
                    print(f"    {key.replace('_', ' ').title()}: {value}")
        
        if args.subnet:
            print(f"\n[*] Scanning subnet: {args.subnet}")
            for ip in ipaddress.IPv4Network(args.subnet, strict=False):
                open_ports = self.port_scan(str(ip))
                if open_ports:
                    print(f"[+] Open Ports on {ip}: {open_ports}")

if __name__ == "__main__":
    tool = AdvancedNetworkReconnaissance()
    tool.main()
