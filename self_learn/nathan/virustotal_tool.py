import os
import requests
import base64
from .base_tool import Tool
import re

class VirusTotalTool(Tool):
    def name(self):
        return "virustotal"

    def run(self, input_data: dict) -> dict:
        ioc = input_data.get("ioc")
        metadata_search = input_data.get("metadata_search")  # For searching by log metadata
        
        # If caller passed a full path as ioc, convert it to metadata_search
        if ioc and (('\\' in ioc) or ('/' in ioc)):
            # user passed a file path; convert into metadata_search for filename extraction
            metadata_search = metadata_search or {}
            metadata_search.setdefault("file_path", ioc)
            # clear ioc so we don't treat path as domain / url / hash accidentally
            ioc = None
        
        if not ioc and not metadata_search:
            return {"error": "No IOC or metadata provided"}

        api_key = os.getenv("VT_API_KEY")
        if not api_key:
            return {"error": "VT_API_KEY not set in environment"}

        headers = {"x-apikey": api_key}

        try:
            # Handle metadata search (for log analysis)
            if metadata_search:
                return self._search_by_metadata(metadata_search, headers)
            
            # Handle standard IOC analysis
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
                return {"error": "Unsupported IOC type (only IPs, hashes, URLs, domains, or metadata searches supported)"}

            resp = requests.get(url, headers=headers, timeout=10)
            data = resp.json()

            return self._parse_simple_result(ioc, data)
            
        except Exception as e:
            return {"error": str(e)}

    def _search_by_metadata(self, metadata: dict, headers: dict) -> dict:
        """Search VirusTotal using metadata from logs (filename, command line, etc.)"""
        try:
            # Build search query based on available metadata
            search_terms = []
            
            # Extract filename from path if provided
            if metadata.get("filename") or metadata.get("file_path"):
                filename = metadata.get("filename") or metadata.get("file_path")
                if '\\' in filename or '/' in filename:
                    filename = filename.split('\\')[-1].split('/')[-1]
                search_terms.append(f'name:"{filename}"')
            
            # Add command line arguments if available
            if metadata.get("command_line"):
                # Extract just the executable name from command line
                cmd = metadata["command_line"].strip()
                if cmd:
                    # Get first part of command (usually the executable)
                    exe_name = cmd.split()[0]
                    if '\\' in exe_name or '/' in exe_name:
                        exe_name = exe_name.split('\\')[-1].split('/')[-1]
                    search_terms.append(f'name:"{exe_name}"')
            
            # Add parent process if available
            if metadata.get("parent_process"):
                parent = metadata["parent_process"]
                if '\\' in parent or '/' in parent:
                    parent = parent.split('\\')[-1].split('/')[-1]
                search_terms.append(f'parent:"{parent}"')
            
            if not search_terms:
                return {"error": "No searchable metadata provided (need filename, command_line, or parent_process)"}
            
            # Combine search terms
            search_query = " OR ".join(search_terms)
            
            # Search VirusTotal
            search_url = "https://www.virustotal.com/api/v3/search"
            params = {
                'query': search_query,
                'limit': 5  # Keep it simple
            }
            
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
            
            # Analyze the best match
            best_match = results[0]
            attributes = best_match.get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})
            
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            total = sum(stats.values()) if stats else 0
            
            # Simple threat assessment
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
                        "names": attributes.get('names', [])[:3],  # First 3 names
                        "size": attributes.get('size', 0),
                        "first_seen": attributes.get('first_submission_date', 'Unknown')
                    },
                    "intelligence": self._get_simple_intelligence(threat_level, attributes)
                }
            }
            
        except Exception as e:
            return {"error": f"Metadata search failed: {str(e)}"}

    def _get_simple_intelligence(self, threat_level: str, attributes: dict) -> str:
        """Get simple intelligence summary"""
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
        """Simple parsing for standard IOC analysis"""
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
        url_pattern = r"^https?://[^\s/$.?#].[^\s]*$"
        return bool(re.match(url_pattern, ioc, re.IGNORECASE))
    
    def _is_domain(self, ioc: str) -> bool:
        domain_pattern = r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z]{2,})+$"
        return bool(re.match(domain_pattern, ioc)) and not self._is_ip(ioc)