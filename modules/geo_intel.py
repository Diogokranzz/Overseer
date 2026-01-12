"""
PROJECT OVERSEER - Geolocation Intelligence Module
====================================================
Maps IP addresses to physical locations using ip-api.com
Provides ISP, Organization, and GPS coordinates
"""

import requests
import time
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from rich.console import Console
from tqdm import tqdm

console = Console()


@dataclass
class GeoData:
    """Geolocation intelligence data container"""
    ip: str
    country: Optional[str] = None
    country_code: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    lat: Optional[float] = None
    lon: Optional[float] = None
    isp: Optional[str] = None
    org: Optional[str] = None
    as_number: Optional[str] = None
    success: bool = False
    
    def to_dict(self) -> dict:
        return asdict(self)


class GeoIntelligence:
    """
    IP Geolocation engine using ip-api.com free tier.
    Supports batch queries for efficiency.
    """
    
    SINGLE_API = "http://ip-api.com/json/{ip}"
    BATCH_API = "http://ip-api.com/batch"
    
    # ip-api.com free tier limits
    BATCH_SIZE = 100
    RATE_LIMIT_DELAY = 1.5  # seconds between batches
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'OVERSEER-ReconTool/1.0'
        })
    
    def locate_single(self, ip: str) -> GeoData:
        """
        Geolocate a single IP address.
        
        Args:
            ip: IPv4 address to locate
            
        Returns:
            GeoData with location intelligence
        """
        try:
            response = self.session.get(
                self.SINGLE_API.format(ip=ip),
                timeout=self.timeout
            )
            response.raise_for_status()
            data = response.json()
            
            if data.get('status') == 'success':
                return GeoData(
                    ip=ip,
                    country=data.get('country'),
                    country_code=data.get('countryCode'),
                    region=data.get('regionName'),
                    city=data.get('city'),
                    lat=data.get('lat'),
                    lon=data.get('lon'),
                    isp=data.get('isp'),
                    org=data.get('org'),
                    as_number=data.get('as'),
                    success=True
                )
            else:
                return GeoData(ip=ip, success=False)
                
        except Exception as e:
            console.print(f"[yellow][!] Geo lookup failed for {ip}: {e}[/yellow]")
            return GeoData(ip=ip, success=False)
    
    def locate_batch(self, ips: List[str], show_progress: bool = True) -> Dict[str, GeoData]:
        """
        Batch geolocate multiple IP addresses.
        Uses ip-api.com batch endpoint for efficiency.
        
        Args:
            ips: List of IPv4 addresses
            show_progress: Show progress bar
            
        Returns:
            Dict mapping IP -> GeoData
        """
        # Deduplicate IPs
        unique_ips = list(set(ips))
        console.print(f"[cyan][*] Geolocating [bold]{len(unique_ips)}[/bold] unique IP addresses...[/cyan]")
        
        results: Dict[str, GeoData] = {}
        
        # Split into batches
        batches = [unique_ips[i:i+self.BATCH_SIZE] for i in range(0, len(unique_ips), self.BATCH_SIZE)]
        
        pbar = tqdm(
            total=len(unique_ips),
            desc="Geolocation",
            unit="IPs",
            disable=not show_progress,
            bar_format="{l_bar}{bar:40}{r_bar}{bar:-10b}"
        )
        
        for batch_idx, batch in enumerate(batches):
            try:
                # Prepare batch request
                payload = [{"query": ip} for ip in batch]
                
                response = self.session.post(
                    self.BATCH_API,
                    json=payload,
                    timeout=self.timeout
                )
                response.raise_for_status()
                data = response.json()
                
                # Process batch results
                for item in data:
                    ip = item.get('query', '')
                    
                    if item.get('status') == 'success':
                        results[ip] = GeoData(
                            ip=ip,
                            country=item.get('country'),
                            country_code=item.get('countryCode'),
                            region=item.get('regionName'),
                            city=item.get('city'),
                            lat=item.get('lat'),
                            lon=item.get('lon'),
                            isp=item.get('isp'),
                            org=item.get('org'),
                            as_number=item.get('as'),
                            success=True
                        )
                    else:
                        results[ip] = GeoData(ip=ip, success=False)
                    
                    pbar.update(1)
                
                # Rate limiting between batches
                if batch_idx < len(batches) - 1:
                    time.sleep(self.RATE_LIMIT_DELAY)
                    
            except Exception as e:
                console.print(f"[yellow][!] Batch geo lookup failed: {e}[/yellow]")
                # Mark failed batch
                for ip in batch:
                    if ip not in results:
                        results[ip] = GeoData(ip=ip, success=False)
                    pbar.update(1)
        
        pbar.close()
        
        # Stats
        success_count = sum(1 for r in results.values() if r.success)
        countries = set(r.country for r in results.values() if r.country)
        
        console.print(f"[green][+] Geolocation Complete: [bold]{success_count}[/bold] located across [bold]{len(countries)}[/bold] countries[/green]")
        
        return results


if __name__ == "__main__":
    # Module test
    geo = GeoIntelligence()
    test_ips = ['8.8.8.8', '1.1.1.1', '151.101.1.140']
    results = geo.locate_batch(test_ips)
    for ip, data in results.items():
        print(f"{ip}: {data.city}, {data.country} ({data.isp})")
