"""
PROJECT OVERSEER - Tactical Map Generator
==========================================
Generates interactive attack surface maps using Folium
Visualizes infrastructure spread across the globe
"""

import folium
from folium.plugins import MarkerCluster, Fullscreen, MiniMap
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from rich.console import Console
import os

console = Console()


@dataclass
class MapPoint:
    """Data point for map visualization"""
    subdomain: str
    ip: str
    lat: float
    lon: float
    country: str
    city: str
    isp: str
    org: str


class TacticalMapGenerator:
    """
    Generates interactive attack surface maps.
    Professional visualization for Red Team reporting.
    """
    
    # Dark theme tile for tactical look
    DARK_TILES = "CartoDB dark_matter"
    LIGHT_TILES = "CartoDB positron"
    
    def __init__(self, theme: str = "dark"):
        """
        Initialize map generator.
        
        Args:
            theme: 'dark' or 'light' map theme
        """
        self.tiles = self.DARK_TILES if theme == "dark" else self.LIGHT_TILES
    
    def generate(self, 
                 points: List[MapPoint], 
                 target_domain: str,
                 output_path: str = "attack_surface.html") -> str:
        """
        Generate interactive attack surface map.
        
        Args:
            points: List of MapPoints to plot
            target_domain: Name of target for title
            output_path: Output HTML file path
            
        Returns:
            Absolute path to generated map
        """
        console.print(f"[cyan][*] Generating tactical attack surface map...[/cyan]")
        
        if not points:
            console.print("[yellow][!] No points to map - skipping visualization[/yellow]")
            return ""
        
        # Calculate map center (average of all points)
        avg_lat = sum(p.lat for p in points) / len(points)
        avg_lon = sum(p.lon for p in points) / len(points)
        
        # Create base map
        attack_map = folium.Map(
            location=[avg_lat, avg_lon],
            zoom_start=2,
            tiles=self.tiles,
            attr='PROJECT OVERSEER - Attack Surface Mapper'
        )
        
        # Add fullscreen control
        Fullscreen(position='topleft').add_to(attack_map)
        
        # Add mini map for context
        MiniMap(toggle_display=True, tile_layer=self.tiles).add_to(attack_map)
        
        # Create marker cluster for performance
        marker_cluster = MarkerCluster(
            name="Infrastructure Nodes",
            overlay=True,
            control=True,
            options={
                'spiderfyOnMaxZoom': True,
                'showCoverageOnHover': True,
                'zoomToBoundsOnClick': True,
                'maxClusterRadius': 50
            }
        ).add_to(attack_map)
        
        # Color coding by infrastructure type - THREAT PRIORITIZATION
        def get_marker_color(org: str, isp: str) -> str:
            """
            Color code markers by infrastructure type and threat priority.
            
            GREEN: Secure cloud providers (likely have WAF, hardened)
            ORANGE: CDN/Edge providers (cached, not direct access)
            RED: HIGH PRIORITY - Unknown/On-premise/VPS (potential Shadow IT)
            """
            org_lower = (org or '').lower() + (isp or '').lower()
            
            # GREEN - Major Cloud Providers (Usually secure, WAF protected)
            if any(cloud in org_lower for cloud in ['amazon', 'aws', 'ec2', 'amazonaws']):
                return 'green'  # AWS - Secure
            elif any(cloud in org_lower for cloud in ['google', 'gcp', 'cloud platform']):
                return 'green'  # Google Cloud - Secure
            elif any(cloud in org_lower for cloud in ['microsoft', 'azure']):
                return 'green'  # Azure - Secure
            
            # ORANGE - CDN/Edge Providers (Traffic proxied, limited attack surface)
            elif any(cdn in org_lower for cdn in ['cloudflare', 'akamai', 'fastly', 'cdn', 'edgecast', 'incapsula']):
                return 'orange'  # CDN - Proxied
            
            # BLUE - Known VPS Providers (Monitored but potentially misconfigured)
            elif any(vps in org_lower for vps in ['digitalocean', 'linode', 'vultr', 'ovh', 'hetzner', 'contabo']):
                return 'blue'  # VPS - Known provider
            
            # RED - HIGH PRIORITY TARGETS
            # Residential/Commercial ISPs (likely on-premise or forgotten servers)
            elif any(isp_br in org_lower for isp_br in ['vivo', 'claro', 'tim', 'oi ', 'net virtua', 'gvt']):
                return 'red'  # Brazilian ISP - On-premise!
            elif any(isp_us in org_lower for isp_us in ['comcast', 'verizon', 'at&t', 'spectrum', 'cox']):
                return 'red'  # US ISP - On-premise!
            
            # RED - Unknown organization (HIGHEST PRIORITY - potential Shadow IT)
            else:
                return 'red'  # Unknown - INVESTIGATE!
        
        # Add markers
        for point in points:
            color = get_marker_color(point.org, point.isp)
            
            # Create popup with Intel
            popup_html = f"""
            <div style="font-family: 'Courier New', monospace; font-size: 12px; min-width: 250px;">
                <b style="color: #ff6b6b;">TARGET INTEL</b><br>
                <hr style="border-color: #333;">
                <b>Subdomain:</b> {point.subdomain}<br>
                <b>IP Address:</b> {point.ip}<br>
                <b>Location:</b> {point.city}, {point.country}<br>
                <b>ISP:</b> {point.isp}<br>
                <b>Organization:</b> {point.org}<br>
            </div>
            """
            
            popup = folium.Popup(popup_html, max_width=400)
            
            # Create marker with icon
            folium.Marker(
                location=[point.lat, point.lon],
                popup=popup,
                tooltip=f"{point.subdomain} ({point.ip})",
                icon=folium.Icon(color=color, icon='server', prefix='fa')
            ).add_to(marker_cluster)
        
        # Add legend - THREAT PRIORITY
        legend_html = """
        <div style="position: fixed; bottom: 50px; right: 50px; z-index: 1000; 
                    background-color: rgba(0,0,0,0.9); padding: 15px; border-radius: 5px;
                    font-family: 'Courier New', monospace; font-size: 11px; color: white;
                    border: 1px solid #333;">
            <b style="font-size: 13px; color: #00ff88;">THREAT PRIORITY</b><br><br>
            <i class="fa fa-map-marker" style="color: #ff4444;"></i> <span style="color: #ff4444;">HIGH</span> - On-Premise/Unknown<br>
            <i class="fa fa-map-marker" style="color: #4a90d9;"></i> <span style="color: #4a90d9;">MED</span> - VPS Provider<br>
            <i class="fa fa-map-marker" style="color: #ffa500;"></i> <span style="color: #ffa500;">LOW</span> - CDN/Edge<br>
            <i class="fa fa-map-marker" style="color: #44ff44;"></i> <span style="color: #44ff44;">SAFE</span> - Cloud (WAF)<br>
            <hr style="border-color: #444; margin: 8px 0;">
            <span style="font-size: 10px; color: #888;">RED = Shadow IT candidates</span>
        </div>
        """
        attack_map.get_root().html.add_child(folium.Element(legend_html))
        
        # Add title
        title_html = f"""
        <div style="position: fixed; top: 10px; left: 50px; z-index: 1000;
                    background-color: rgba(0,0,0,0.9); padding: 15px 25px; border-radius: 5px;
                    font-family: 'Courier New', monospace; color: #00ff88; border: 1px solid #00ff88;">
            <span style="font-size: 18px; font-weight: bold;">PROJECT OVERSEER</span><br>
            <span style="font-size: 12px; color: #888;">Attack Surface Map: {target_domain}</span><br>
            <span style="font-size: 11px; color: #666;">{len(points)} infrastructure nodes mapped</span>
        </div>
        """
        attack_map.get_root().html.add_child(folium.Element(title_html))
        
        # Save map
        attack_map.save(output_path)
        abs_path = os.path.abspath(output_path)
        
        console.print(f"[green][+] Attack Surface Map generated: [bold]{abs_path}[/bold][/green]")
        
        return abs_path


if __name__ == "__main__":
    # Module test
    test_points = [
        MapPoint("api.example.com", "8.8.8.8", 37.751, -97.822, "USA", "Kansas City", "Google", "Google LLC"),
        MapPoint("cdn.example.com", "1.1.1.1", -33.494, 143.210, "Australia", "Sydney", "Cloudflare", "Cloudflare Inc"),
    ]
    
    gen = TacticalMapGenerator()
    gen.generate(test_points, "example.com", "test_map.html")
