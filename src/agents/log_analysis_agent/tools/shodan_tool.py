from langchain_core.tools import tool
from .base_tool import Tool
import os 
import requests

class ShodanTool(Tool):
    """Keep the existing implementation"""
    def name(self):
        return "shodan"
    
    def run(self, input_data: dict) -> dict:
        ip = input_data.get("ioc")
        if not ip:
            return {"error": "No IP address provided"}
        
        api_key = os.getenv("SHODAN_API_KEY")
        if not api_key:
            return {"error": "SHODAN_API_KEY not found"}
        url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
        try:
            resp = requests.get(url, timeout=10)
            data = resp.json()
            return {
                "ioc": ip,
                "tool": "shodan",
                "result": {
                    "ip": data.get("ip_str"),
                    "port": data.get("port",[]),
                    "hostnames": data.get("hostnames", []),
                    "org": data.get("org",[]),
                    "os": data.get("os",[]),
                    "tags": data.get("tags", [])
                }
            }
        except Exception as e:
            return {"error": str(e)}

# Create a singleton instance
_shodan_tool = ShodanTool()

@tool
def shodan_lookup(ip_address: str) -> dict:
    """Analyzes external IP addresses to reveal information about internet-facing systems.
    
    Use this tool when you need context about external IPs appearing in logs to understand:
    - Open ports and services
    - Hosting provider and organization
    - Geographic location
    - Known vulnerabilities or tags
    
    Args:
        ip_address: The IP address to analyze (e.g., "104.18.21.226")
    
    Returns:
        Dictionary containing IP information including ports, hostnames, organization, OS, and tags.
    """
    return _shodan_tool.run({"ioc": ip_address})