"""
PROJECT OVERSEER - DNS Resolution Engine
==========================================
Resolves subdomains to IPv4 addresses using public DNS
Identifies live hosts vs dead domains
"""

import dns.resolver
import socket
from typing import Dict, Optional, List
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from tqdm import tqdm

console = Console()


@dataclass
class DNSResult:
    """Container for DNS resolution results"""
    subdomain: str
    ip: Optional[str]
    is_alive: bool
    cname: Optional[str] = None
    error: Optional[str] = None


class DNSResolver:
    """
    High-performance DNS resolver with threading support.
    Uses dnspython for reliable resolution.
    """
    
    def __init__(self, 
                 timeout: float = 3.0,
                 max_workers: int = 50,
                 nameservers: Optional[List[str]] = None):
        """
        Initialize DNS resolver.
        
        Args:
            timeout: DNS query timeout in seconds
            max_workers: Max concurrent DNS queries
            nameservers: Custom nameservers (default: Cloudflare + Google)
        """
        self.timeout = timeout
        self.max_workers = max_workers
        
        # Configure resolver
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
        
        # Use fast public DNS
        self.resolver.nameservers = nameservers or [
            '1.1.1.1',      # Cloudflare
            '8.8.8.8',      # Google
            '9.9.9.9',      # Quad9
        ]
    
    def resolve_single(self, subdomain: str) -> DNSResult:
        """
        Resolve a single subdomain to its IP.
        
        Args:
            subdomain: FQDN to resolve
            
        Returns:
            DNSResult with resolution details
        """
        try:
            # Try A record first
            answers = self.resolver.resolve(subdomain, 'A')
            ip = str(answers[0])
            
            # Check for CNAME (useful for CDN detection)
            cname = None
            try:
                cname_answers = self.resolver.resolve(subdomain, 'CNAME')
                cname = str(cname_answers[0])
            except:
                pass
            
            return DNSResult(
                subdomain=subdomain,
                ip=ip,
                is_alive=True,
                cname=cname
            )
            
        except dns.resolver.NXDOMAIN:
            return DNSResult(subdomain=subdomain, ip=None, is_alive=False, error='NXDOMAIN')
        except dns.resolver.NoAnswer:
            return DNSResult(subdomain=subdomain, ip=None, is_alive=False, error='NoAnswer')
        except dns.resolver.Timeout:
            return DNSResult(subdomain=subdomain, ip=None, is_alive=False, error='Timeout')
        except Exception as e:
            return DNSResult(subdomain=subdomain, ip=None, is_alive=False, error=str(e))
    
    def resolve_bulk(self, subdomains: List[str], show_progress: bool = True) -> Dict[str, DNSResult]:
        """
        Resolve multiple subdomains concurrently.
        
        Args:
            subdomains: List of FQDNs to resolve
            show_progress: Show tqdm progress bar
            
        Returns:
            Dict mapping subdomain -> DNSResult
        """
        console.print(f"[cyan][*] Resolving [bold]{len(subdomains)}[/bold] subdomains...[/cyan]")
        
        results: Dict[str, DNSResult] = {}
        
        # Progress bar setup
        pbar = tqdm(
            total=len(subdomains),
            desc="DNS Resolution",
            unit="hosts",
            disable=not show_progress,
            bar_format="{l_bar}{bar:40}{r_bar}{bar:-10b}"
        )
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all tasks
            future_to_sub = {
                executor.submit(self.resolve_single, sub): sub 
                for sub in subdomains
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_sub):
                subdomain = future_to_sub[future]
                try:
                    result = future.result()
                    results[subdomain] = result
                except Exception as e:
                    results[subdomain] = DNSResult(
                        subdomain=subdomain, 
                        ip=None, 
                        is_alive=False, 
                        error=str(e)
                    )
                pbar.update(1)
        
        pbar.close()
        
        # Stats
        alive = sum(1 for r in results.values() if r.is_alive)
        dead = len(results) - alive
        
        console.print(f"[green][+] DNS Resolution Complete: [bold]{alive}[/bold] alive, [dim]{dead} dead[/dim][/green]")
        
        return results


if __name__ == "__main__":
    # Module test
    resolver = DNSResolver()
    test_domains = ['www.google.com', 'mail.google.com', 'nonexistent.google.com']
    results = resolver.resolve_bulk(test_domains)
    for sub, result in results.items():
        print(f"{sub}: {result.ip} ({'ALIVE' if result.is_alive else 'DEAD'})")
