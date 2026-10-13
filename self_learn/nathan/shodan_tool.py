from .base_tool import Tool
import os 
import requests  
class ShodanTool(Tool):
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
            return {
                "error": str(e)
            }