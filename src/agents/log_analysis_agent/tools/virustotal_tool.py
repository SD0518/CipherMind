from langchain_core.tools import tool
import os
import requests
import base64
from .base_tool import Tool
import re

class VirusTotalTool(Tool):
    """Keep all existing implementation"""
    def name(self):
        return "virustotal"

    def run(self, input_data: dict) -> dict:
        ioc = input_data.get("ioc")
        metadata_search = input_data.get("metadata_search")
        
        if ioc and (('\\' in ioc) or ('/' in ioc)):
            metadata_search = metadata_search or {}
            metadata_search.setdefault("file_path", ioc)
            ioc = None
        
        if not ioc and not metadata_search:
            return {"error": "No IOC or metadata provided"}

        api_key = os.getenv("VT_API_KEY")
        if not api_key:
            return {"error": "VT_API_KEY not set in environment"}

        headers = {"x-apikey": api_key}

        try:
            if metadata_search:
                return self._search_by_metadata(metadata_search, headers)
            
            if self._is_ip(ioc):
                url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
            elif self._is_hash(ioc):
                url = f"https://www.virustotal.com/api/v3/files/{ioc}"
            elif self._is_url(ioc):
                url_id = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
                url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            elif self._is_domain(ioc):
                url = f"https://www.virustotal.com/api/v3/domains/{ioc}"
            else:
                return {"error": "Unsupported IOC type"}

            resp = requests.get(url, headers=headers, timeout=10)
            data = resp.json()
            return self._parse_simple_result(ioc, data)
            
        except Exception as e:
            return {"error": str(e)}

    def _search_by_metadata(self, metadata: dict, headers: dict) -> dict:
        """Search VirusTotal using metadata from logs"""
        try:
            search_terms = []
            
            if metadata.get("filename") or metadata.get("file_path"):
                filename = metadata.get("filename") or metadata.get("file_path")
                if '\\' in filename or '/' in filename:
                    filename = filename.split('\\')[-1].split('/')[-1]
                search_terms.append(f'name:"{filename}"')
            
            if metadata.get("command_line"):
                cmd = metadata["command_line"].strip()
                if cmd:
                    exe_name = cmd.split()[0]
                    if '\\' in exe_name or '/' in exe_name:
                        exe_name = exe_name.split('\\')[-1].split('/')[-1]
                    search_terms.append(f'name:"{exe_name}"')
            
            if metadata.get("parent_process"):
                parent = metadata["parent_process"]
                if '\\' in parent or '/' in parent:
                    parent = parent.split('\\')[-1].split('/')[-1]
                search_terms.append(f'parent:"{parent}"')
            
            if not search_terms:
                return {"error": "No searchable metadata provided"}
            
            search_query = " OR ".join(search_terms)
            search_url = "https://www.virustotal.com/api/v3/search"
            params = {'query': search_query, 'limit': 5}
            
            resp = requests.get(search_url, headers=headers, params=params, timeout=15)
            
            if resp.status_code != 200:
                return {"error": f"Search failed: {resp.status_code}"}
            
            search_data = resp.json()
            results = search_data.get('data', [])
            
            if not results:
                return {
                    "metadata": metadata,
                    "tool": "virustotal",
                    "result": {
                        "found": False,
                        "message": "No matches found in VirusTotal database",
                        "intelligence": "File may be new, custom, or legitimate"
                    }
                }
            
            best_match = results[0]
            attributes = best_match.get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})
            
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            total = sum(stats.values()) if stats else 0
            
            if malicious > 0:
                threat_level = "MALICIOUS"
                confidence = "HIGH" if malicious > 5 else "MEDIUM"
            elif suspicious > 0:
                threat_level = "SUSPICIOUS"
                confidence = "MEDIUM"
            else:
                threat_level = "CLEAN"
                confidence = "LOW"
            
            return {
                "metadata": metadata,
                "tool": "virustotal",
                "result": {
                    "found": True,
                    "threat_level": threat_level,
                    "confidence": confidence,
                    "detections": f"{malicious}/{total} engines flagged as malicious",
                    "file_info": {
                        "sha256": best_match.get('id', 'Unknown'),
                        "names": attributes.get('names', [])[:3],
                        "size": attributes.get('size', 0),
                        "first_seen": attributes.get('first_submission_date', 'Unknown')
                    },
                    "intelligence": self._get_simple_intelligence(threat_level, attributes)
                }
            }
            
        except Exception as e:
            return {"error": f"Metadata search failed: {str(e)}"}

    def _get_simple_intelligence(self, threat_level: str, attributes: dict) -> str:
        if threat_level == "MALICIOUS":
            tags = attributes.get('tags', [])
            if any('trojan' in tag.lower() for tag in tags):
                return "Likely trojan/backdoor - immediate containment recommended"
            elif any('ransomware' in tag.lower() for tag in tags):
                return "Potential ransomware - isolate system immediately"
            elif any('miner' in tag.lower() for tag in tags):
                return "Cryptocurrency miner detected"
            else:
                return "Confirmed malware - block and investigate"
        elif threat_level == "SUSPICIOUS":
            return "Potentially unwanted program or suspicious behavior detected"
        else:
            return "No immediate threats detected in VirusTotal database"

    def _parse_simple_result(self, ioc: str, data: dict) -> dict:
        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) if stats else 0
        
        return {
            "ioc": ioc,
            "tool": "virustotal",
            "result": {
                "malicious": malicious,
                "suspicious": suspicious,
                "total_engines": total,
                "threat_level": "HIGH" if malicious > 5 else "MEDIUM" if malicious > 0 or suspicious > 0 else "LOW",
                "tags": attributes.get("tags", [])
            }
        }

    def _is_ip(self, ioc: str) -> bool:    
        return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ioc))

    def _is_hash(self, ioc: str) -> bool:       
        return bool(re.match(r"^[A-Fa-f0-9]{32,64}$", ioc))

    def _is_url(self, ioc: str) -> bool:   
        return bool(re.match(r"^https?://[^\s/$.?#].[^\s]*$", ioc, re.IGNORECASE))
    
    def _is_domain(self, ioc: str) -> bool:
        return bool(re.match(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z]{2,})+$", ioc)) and not self._is_ip(ioc)

# Create singleton instance
_virustotal_tool = VirusTotalTool()

@tool
def virustotal_lookup(ioc: str) -> dict:
    """Analyzes IPs, file hashes, URLs, and domains against multiple security vendors.
    
    Use this tool to determine if an indicator of compromise (IOC) is malicious by checking it
    against VirusTotal's database of security vendor detections.
    
    Args:
        ioc: An IP address, file hash (MD5/SHA1/SHA256), URL, or domain to analyze
    
    Returns:
        Threat assessment with detection results from multiple security vendors and actionable intelligence.
    """
    return _virustotal_tool.run({"ioc": ioc})

@tool
def virustotal_metadata_search(filename: str = None, command_line: str = None, parent_process: str = None) -> dict:
    """Searches VirusTotal using file metadata from logs when you don't have the actual file.
    
    Use this tool when you have file metadata from logs (filename, command line, parent process)
    but not the actual file hash. This helps identify if executables or commands seen in logs
    are known malicious.
    
    Args:
        filename: Name of the file or full file path
        command_line: Command line arguments used to execute the file
        parent_process: Parent process that spawned this execution
    
    Returns:
        Threat assessment and file intelligence based on metadata matching in VirusTotal database.
    """
    metadata = {}
    if filename:
        metadata["filename"] = filename
    if command_line:
        metadata["command_line"] = command_line
    if parent_process:
        metadata["parent_process"] = parent_process
    
    return _virustotal_tool.run({"metadata_search": metadata})