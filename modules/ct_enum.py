"""
PROJECT OVERSEER - Certificate Transparency Log Enumerator
============================================================
Passive subdomain enumeration via CT Logs
No packets sent to target - 100% OPSEC safe
Sources: crt.sh, CertSpotter, HackerTarget
"""

import requests
import re
import time
from typing import Set, Optional
from rich.console import Console

console = Console()


class CTLogEnumerator:
    """
    Enumerates subdomains from Certificate Transparency logs.
    Uses multiple public databases - no active scanning.
    Includes retry logic and fallback sources.
    """
    
    # Primary source
    CRT_SH_URL = "https://crt.sh/?q={domain}&output=json"
    
    # Fallback sources
    CERTSPOTTER_URL = "https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
    HACKERTARGET_URL = "https://api.hackertarget.com/hostsearch/?q={domain}"
    
    MAX_RETRIES = 3
    RETRY_DELAY = 2  # seconds
    
    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        })
    
    def enumerate(self, domain: str) -> Set[str]:
        """
        Query multiple CT log sources for subdomains.
        Uses fallback sources if primary fails.
        
        Args:
            domain: Target domain (e.g., 'tesla.com')
            
        Returns:
            Set of unique subdomains found
        """
        console.print(f"[cyan][*] Querying Certificate Transparency Logs for [bold]{domain}[/bold]...[/cyan]")
        
        subdomains: Set[str] = set()
        
        # Try crt.sh first (most comprehensive)
        crt_results = self._query_crtsh(domain)
        subdomains.update(crt_results)
        
        # Try CertSpotter as fallback/supplement
        if len(subdomains) < 10:
            console.print("[cyan][*] Trying CertSpotter as additional source...[/cyan]")
            certspotter_results = self._query_certspotter(domain)
            subdomains.update(certspotter_results)
        
        # Try HackerTarget as last resort
        if len(subdomains) < 5:
            console.print("[cyan][*] Trying HackerTarget as fallback...[/cyan]")
            hackertarget_results = self._query_hackertarget(domain)
            subdomains.update(hackertarget_results)
        
        if subdomains:
            console.print(f"[green][+] Found [bold]{len(subdomains)}[/bold] unique subdomains in CT Logs[/green]")
        else:
            console.print("[yellow][!] No subdomains found across all CT sources[/yellow]")
        
        return subdomains
    
    def _query_crtsh(self, domain: str) -> Set[str]:
        """Query crt.sh with retry logic"""
        subdomains: Set[str] = set()
        
        for attempt in range(self.MAX_RETRIES):
            try:
                response = self.session.get(
                    self.CRT_SH_URL.format(domain=domain),
                    timeout=self.timeout
                )
                
                if response.status_code == 503:
                    console.print(f"[yellow][!] crt.sh unavailable (attempt {attempt + 1}/{self.MAX_RETRIES})[/yellow]")
                    if attempt < self.MAX_RETRIES - 1:
                        time.sleep(self.RETRY_DELAY * (attempt + 1))
                    continue
                
                response.raise_for_status()
                
                if not response.text.strip():
                    return subdomains
                
                data = response.json()
                
                for entry in data:
                    name_value = entry.get('name_value', '')
                    names = name_value.split('\n')
                    
                    for name in names:
                        clean_name = self._clean_subdomain(name, domain)
                        if clean_name:
                            subdomains.add(clean_name)
                
                console.print(f"[dim][crt.sh] Found {len(subdomains)} subdomains[/dim]")
                return subdomains
                
            except requests.exceptions.Timeout:
                console.print(f"[yellow][!] crt.sh timeout (attempt {attempt + 1}/{self.MAX_RETRIES})[/yellow]")
                if attempt < self.MAX_RETRIES - 1:
                    time.sleep(self.RETRY_DELAY)
            except requests.exceptions.RequestException as e:
                console.print(f"[yellow][!] crt.sh error: {e}[/yellow]")
                break
            except ValueError:
                console.print("[yellow][!] Invalid JSON from crt.sh[/yellow]")
                break
        
        return subdomains
    
    def _query_certspotter(self, domain: str) -> Set[str]:
        """Query CertSpotter API"""
        subdomains: Set[str] = set()
        
        try:
            response = self.session.get(
                self.CERTSPOTTER_URL.format(domain=domain),
                timeout=self.timeout
            )
            response.raise_for_status()
            
            data = response.json()
            
            for entry in data:
                dns_names = entry.get('dns_names', [])
                for name in dns_names:
                    clean_name = self._clean_subdomain(name, domain)
                    if clean_name:
                        subdomains.add(clean_name)
            
            if subdomains:
                console.print(f"[dim][CertSpotter] Found {len(subdomains)} subdomains[/dim]")
                
        except Exception as e:
            console.print(f"[dim][CertSpotter] Query failed: {e}[/dim]")
        
        return subdomains
    
    def _query_hackertarget(self, domain: str) -> Set[str]:
        """Query HackerTarget API"""
        subdomains: Set[str] = set()
        
        try:
            response = self.session.get(
                self.HACKERTARGET_URL.format(domain=domain),
                timeout=self.timeout
            )
            response.raise_for_status()
            
            # HackerTarget returns plaintext: subdomain,IP
            lines = response.text.strip().split('\n')
            
            for line in lines:
                if ',' in line and 'error' not in line.lower():
                    subdomain = line.split(',')[0].strip()
                    clean_name = self._clean_subdomain(subdomain, domain)
                    if clean_name:
                        subdomains.add(clean_name)
            
            if subdomains:
                console.print(f"[dim][HackerTarget] Found {len(subdomains)} subdomains[/dim]")
                
        except Exception as e:
            console.print(f"[dim][HackerTarget] Query failed: {e}[/dim]")
        
        return subdomains
    
    def _clean_subdomain(self, name: str, domain: str) -> Optional[str]:
        """
        Clean and validate subdomain entries.
        Removes wildcards and validates domain suffix.
        """
        # Remove whitespace
        name = name.strip().lower()
        
        # Skip wildcards
        if name.startswith('*'):
            name = name.replace('*.', '')
        
        # Validate it's actually a subdomain of our target
        if not name.endswith(domain):
            return None
        
        # Skip if it's just the base domain
        if name == domain:
            return None
        
        # Basic validation - alphanumeric, hyphens, dots only
        if not re.match(r'^[a-z0-9][a-z0-9\-\.]*[a-z0-9]$', name):
            return None
        
        return name


if __name__ == "__main__":
    # Module test
    enumerator = CTLogEnumerator()
    subs = enumerator.enumerate("tesla.com")
    print(f"\nSample subdomains: {list(subs)[:10]}")
