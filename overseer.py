#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║     ██████╗ ██╗   ██╗███████╗██████╗ ███████╗███████╗███████╗██████╗          ║
║    ██╔═══██╗██║   ██║██╔════╝██╔══██╗██╔════╝██╔════╝██╔════╝██╔══██╗         ║
║    ██║   ██║██║   ██║█████╗  ██████╔╝███████╗█████╗  █████╗  ██████╔╝         ║
║    ██║   ██║╚██╗ ██╔╝██╔══╝  ██╔══██╗╚════██║██╔══╝  ██╔══╝  ██╔══██╗         ║
║    ╚██████╔╝ ╚████╔╝ ███████╗██║  ██║███████║███████╗███████╗██║  ██║         ║
║     ╚═════╝   ╚═══╝  ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝         ║
║                                                                               ║
║                    ATTACK SURFACE MAPPER v1.0                                 ║
║                    Passive Reconnaissance Tool                                ║
║                                                                               ║
║    [!] 100% Legal - Uses only public datasets (CT Logs, Public DNS)          ║
║    [!] OSINT Phase 1 - Cyber Kill Chain: Reconnaissance                      ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝

Usage:
    python3 overseer.py --target <domain>
    python3 overseer.py --target tesla.com --output tesla_attack_surface.html
    python3 overseer.py --target nubank.com.br --threads 100 --timeout 5

Author: Red Team Operator
License: For authorized security testing only
"""

import argparse
import sys
import pandas as pd
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from modules.ct_enum import CTLogEnumerator
from modules.dns_resolver import DNSResolver, DNSResult
from modules.geo_intel import GeoIntelligence, GeoData
from modules.map_generator import TacticalMapGenerator, MapPoint

console = Console()


def print_banner():
    """Display the OVERSEER banner"""
    banner = """
[bold green]
    ██████╗ ██╗   ██╗███████╗██████╗ ███████╗███████╗███████╗██████╗ 
   ██╔═══██╗██║   ██║██╔════╝██╔══██╗██╔════╝██╔════╝██╔════╝██╔══██╗
   ██║   ██║██║   ██║█████╗  ██████╔╝███████╗█████╗  █████╗  ██████╔╝
   ██║   ██║╚██╗ ██╔╝██╔══╝  ██╔══██╗╚════██║██╔══╝  ██╔══╝  ██╔══██╗
   ╚██████╔╝ ╚████╔╝ ███████╗██║  ██║███████║███████╗███████╗██║  ██║
    ╚═════╝   ╚═══╝  ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝
[/bold green]
[dim]                 ATTACK SURFACE MAPPER v1.0[/dim]
[dim cyan]        ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/dim cyan]
[yellow]        [!] Passive Reconnaissance | 100% Legal OSINT[/yellow]
    """
    console.print(banner)


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="OVERSEER - Attack Surface Mapper (Passive Recon)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 overseer.py --target tesla.com
  python3 overseer.py --target nubank.com.br --output nubank_surface.html
  python3 overseer.py --target example.com --threads 100 --csv results.csv
        """
    )
    
    parser.add_argument(
        '-t', '--target',
        required=True,
        help='Target domain (e.g., tesla.com, nubank.com.br)'
    )
    
    parser.add_argument(
        '-o', '--output',
        default='attack_surface.html',
        help='Output HTML map file (default: attack_surface.html)'
    )
    
    parser.add_argument(
        '--csv',
        default=None,
        help='Export results to CSV file'
    )
    
    parser.add_argument(
        '--threads',
        type=int,
        default=50,
        help='Number of concurrent DNS resolution threads (default: 50)'
    )
    
    parser.add_argument(
        '--timeout',
        type=float,
        default=3.0,
        help='DNS/HTTP timeout in seconds (default: 3.0)'
    )
    
    parser.add_argument(
        '--theme',
        choices=['dark', 'light'],
        default='dark',
        help='Map theme (default: dark)'
    )
    
    parser.add_argument(
        '--no-map',
        action='store_true',
        help='Skip map generation (CLI output only)'
    )
    
    return parser.parse_args()


def run_reconnaissance(args: argparse.Namespace) -> Optional[pd.DataFrame]:
    """
    Execute the full reconnaissance pipeline.
    
    Returns:
        DataFrame with all collected intelligence
    """
    target = args.target.lower().strip()
    
    console.print(Panel(
        f"[bold white]Target Acquired:[/bold white] [cyan]{target}[/cyan]\n"
        f"[dim]Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]",
        title="[bold red]MISSION BRIEFING[/bold red]",
        border_style="red"
    ))
    
    # ═══════════════════════════════════════════════════════════════════
    # PHASE 1: Certificate Transparency Enumeration
    # ═══════════════════════════════════════════════════════════════════
    console.print("\n[bold magenta]═══ PHASE 1: CT LOG ENUMERATION ═══[/bold magenta]\n")
    
    ct_enum = CTLogEnumerator(timeout=30)
    subdomains = ct_enum.enumerate(target)
    
    if not subdomains:
        console.print("[red][!] No subdomains found. Target may have limited CT log presence.[/red]")
        return None
    
    # Add base domain to list
    subdomains.add(target)
    subdomain_list = sorted(list(subdomains))
    
    # ═══════════════════════════════════════════════════════════════════
    # PHASE 2: DNS Resolution
    # ═══════════════════════════════════════════════════════════════════
    console.print("\n[bold magenta]═══ PHASE 2: DNS RESOLUTION ═══[/bold magenta]\n")
    
    dns_resolver = DNSResolver(
        timeout=args.timeout,
        max_workers=args.threads
    )
    dns_results = dns_resolver.resolve_bulk(subdomain_list)
    
    # Filter alive hosts
    alive_hosts = {
        sub: result for sub, result in dns_results.items() 
        if result.is_alive and result.ip
    }
    
    if not alive_hosts:
        console.print("[red][!] No live hosts found. All subdomains appear to be defunct.[/red]")
        return None
    
    # ═══════════════════════════════════════════════════════════════════
    # PHASE 3: Geolocation Intelligence
    # ═══════════════════════════════════════════════════════════════════
    console.print("\n[bold magenta]═══ PHASE 3: GEOLOCATION INTEL ═══[/bold magenta]\n")
    
    geo_intel = GeoIntelligence(timeout=10)
    unique_ips = list(set(result.ip for result in alive_hosts.values()))
    geo_results = geo_intel.locate_batch(unique_ips)
    
    # ═══════════════════════════════════════════════════════════════════
    # PHASE 4: Data Aggregation
    # ═══════════════════════════════════════════════════════════════════
    console.print("\n[bold magenta]═══ PHASE 4: INTEL AGGREGATION ═══[/bold magenta]\n")
    
    # Build comprehensive dataset
    records = []
    for subdomain, dns_result in alive_hosts.items():
        ip = dns_result.ip
        geo = geo_results.get(ip, GeoData(ip=ip, success=False))
        
        records.append({
            'subdomain': subdomain,
            'ip': ip,
            'cname': dns_result.cname,
            'country': geo.country,
            'country_code': geo.country_code,
            'region': geo.region,
            'city': geo.city,
            'lat': geo.lat,
            'lon': geo.lon,
            'isp': geo.isp,
            'org': geo.org,
            'as_number': geo.as_number,
            'geo_success': geo.success
        })
    
    df = pd.DataFrame(records)
    
    # ═══════════════════════════════════════════════════════════════════
    # PHASE 5: Visualization & Output
    # ═══════════════════════════════════════════════════════════════════
    console.print("\n[bold magenta]═══ PHASE 5: TACTICAL OUTPUT ═══[/bold magenta]\n")
    
    # Print summary statistics
    print_summary(df, target)
    
    # Generate map if not disabled
    if not args.no_map:
        # Prepare map points (only those with valid coordinates)
        map_points = []
        for _, row in df.iterrows():
            if pd.notna(row['lat']) and pd.notna(row['lon']):
                map_points.append(MapPoint(
                    subdomain=row['subdomain'],
                    ip=row['ip'],
                    lat=row['lat'],
                    lon=row['lon'],
                    country=row['country'] or 'Unknown',
                    city=row['city'] or 'Unknown',
                    isp=row['isp'] or 'Unknown',
                    org=row['org'] or 'Unknown'
                ))
        
        if map_points:
            map_gen = TacticalMapGenerator(theme=args.theme)
            map_gen.generate(map_points, target, args.output)
    
    # Export CSV if requested
    if args.csv:
        df.to_csv(args.csv, index=False)
        console.print(f"[green][+] Data exported to CSV: [bold]{args.csv}[/bold][/green]")
    
    return df


def print_summary(df: pd.DataFrame, target: str):
    """Print reconnaissance summary table"""
    
    # Calculate statistics
    total_subs = len(df)
    unique_ips = df['ip'].nunique()
    countries = df['country'].dropna().unique()
    
    # Top ISPs
    top_isps = df['isp'].value_counts().head(5)
    
    # Summary panel
    summary = Table(title="RECONNAISSANCE SUMMARY", show_header=True, header_style="bold cyan")
    summary.add_column("Metric", style="cyan")
    summary.add_column("Value", style="green")
    
    summary.add_row("Target Domain", target)
    summary.add_row("Live Subdomains", str(total_subs))
    summary.add_row("Unique IP Addresses", str(unique_ips))
    summary.add_row("Countries Spanned", str(len(countries)))
    summary.add_row("Countries List", ", ".join(sorted(countries)[:10]) + ("..." if len(countries) > 10 else ""))
    
    console.print(summary)
    
    # Top ISPs table
    if not top_isps.empty:
        isp_table = Table(title="TOP INFRASTRUCTURE PROVIDERS", show_header=True, header_style="bold yellow")
        isp_table.add_column("ISP/Provider", style="yellow")
        isp_table.add_column("Hosts", style="white")
        
        for isp, count in top_isps.items():
            isp_table.add_row(str(isp)[:50], str(count))
        
        console.print(isp_table)
    
    # Sample interesting targets
    console.print("\n[bold red]SAMPLE TARGETS (Potential Shadow IT):[/bold red]")
    
    # Look for interesting patterns
    interesting_patterns = ['dev', 'test', 'stage', 'admin', 'internal', 'vpn', 'api', 'beta', 'old', 'legacy']
    interesting = df[df['subdomain'].str.contains('|'.join(interesting_patterns), case=False, na=False)]
    
    if not interesting.empty:
        sample_table = Table(show_header=True, header_style="bold red")
        sample_table.add_column("Subdomain", style="red")
        sample_table.add_column("IP", style="dim")
        sample_table.add_column("Location", style="cyan")
        
        for _, row in interesting.head(10).iterrows():
            location = f"{row['city'] or '?'}, {row['country'] or '?'}"
            sample_table.add_row(row['subdomain'], row['ip'], location)
        
        console.print(sample_table)
    else:
        console.print("[dim]No obvious shadow IT patterns detected in subdomain names.[/dim]")


def main():
    """Main entry point"""
    print_banner()
    
    args = parse_arguments()
    
    try:
        df = run_reconnaissance(args)
        
        if df is not None:
            console.print(Panel(
                "[bold green][+] RECONNAISSANCE COMPLETE[/bold green]\n"
                f"[dim]Map saved to: {args.output}[/dim]",
                border_style="green"
            ))
        else:
            console.print(Panel(
                "[bold yellow][!] RECONNAISSANCE INCOMPLETE[/bold yellow]\n"
                "[dim]Insufficient data collected[/dim]",
                border_style="yellow"
            ))
            sys.exit(1)
            
    except KeyboardInterrupt:
        console.print("\n[yellow][!] Operation cancelled by user[/yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"\n[red][!] Fatal error: {e}[/red]")
        raise


if __name__ == "__main__":
    main()
