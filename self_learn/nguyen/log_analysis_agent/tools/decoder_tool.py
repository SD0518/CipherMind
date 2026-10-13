from langchain_core.tools import tool
from typing import Dict, Any
import base64
import binascii
import re
from .base_tool import Tool

class DecoderTool(Tool):
    """Decode Base64 and Hex encoded strings commonly used to hide malicious commands"""
    
    def name(self) -> str:
        return "decoder"

    def run(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        try:
            encoded_string = input_data.get("encoded_string", "")
            encoding_type = input_data.get("encoding_type", "auto")
            
            if not encoded_string:
                return {"error": "No encoded string provided"}
            
            # Auto-detect encoding if not specified
            if encoding_type == "auto":
                encoding_type = self._detect_encoding(encoded_string)
            
            # Decode the string
            decoded_text, success = self._decode_string(encoded_string, encoding_type)
            
            if not success:
                return {
                    "tool": "decoder",
                    "encoded_string": encoded_string[:100] + "..." if len(encoded_string) > 100 else encoded_string,
                    "encoding_detected": encoding_type,
                    "decoded_text": None,
                    "success": False,
                    "error": "Failed to decode - invalid encoding or corrupted data"
                }
            
            # Analyze decoded content for threats
            threat_analysis = self._analyze_decoded_content(decoded_text)
            
            return {
                "tool": "decoder",
                "encoded_string": encoded_string[:100] + "..." if len(encoded_string) > 100 else encoded_string,
                "encoding_detected": encoding_type,
                "decoded_text": decoded_text,
                "success": True,
                "threat_analysis": threat_analysis
            }
            
        except Exception as e:
            return {"error": f"{type(e).__name__}: {str(e)}"}
    
    def _detect_encoding(self, string: str) -> str:
        """Auto-detect if string is base64 or hex"""
        # Remove whitespace
        clean_string = string.strip()
        
        # Check for hex (only 0-9, A-F, a-f)
        if re.match(r'^[0-9A-Fa-f]+$', clean_string) and len(clean_string) % 2 == 0:
            # Could be hex, but also could be base64
            # Hex is more restrictive, so check if it's valid hex first
            if len(clean_string) > 10:  # Reasonable length for encoded command
                return "hex"
        
        # Check for base64 characteristics
        # Base64 uses A-Z, a-z, 0-9, +, /, and = for padding
        if re.match(r'^[A-Za-z0-9+/]+=*$', clean_string):
            return "base64"
        
        # Default to base64 as it's more common in PowerShell attacks
        return "base64"
    
    def _decode_string(self, encoded_string: str, encoding_type: str) -> tuple:
        """Decode string and return (decoded_text, success)"""
        try:
            if encoding_type == "base64":
                return self._decode_base64(encoded_string)
            elif encoding_type == "hex":
                return self._decode_hex(encoded_string)
            else:
                return None, False
        except Exception as e:
            return None, False
    
    def _decode_base64(self, encoded_string: str) -> tuple:
        """Decode base64 string, trying multiple character encodings"""
        try:
            # Clean the string
            clean_string = encoded_string.strip()
            
            # Decode base64
            decoded_bytes = base64.b64decode(clean_string)
            
            # Try different character encodings (PowerShell commonly uses UTF-16LE)
            encodings = ['utf-16le', 'utf-16be', 'utf-8', 'ascii', 'latin-1']
            
            for encoding in encodings:
                try:
                    decoded_text = decoded_bytes.decode(encoding)
                    # Filter out null bytes that sometimes appear in UTF-16
                    decoded_text = decoded_text.replace('\x00', '')
                    # If we got readable text, return it
                    if decoded_text.strip():
                        return decoded_text, True
                except (UnicodeDecodeError, AttributeError):
                    continue
            
            # If all encodings failed, return raw bytes as hex representation
            return decoded_bytes.hex(), True
            
        except Exception as e:
            return None, False
    
    def _decode_hex(self, encoded_string: str) -> tuple:
        """Decode hex string"""
        try:
            clean_string = encoded_string.strip()
            decoded_bytes = bytes.fromhex(clean_string)
            
            # Try UTF-8 first, then other encodings
            encodings = ['utf-8', 'utf-16le', 'ascii', 'latin-1']
            
            for encoding in encodings:
                try:
                    decoded_text = decoded_bytes.decode(encoding)
                    decoded_text = decoded_text.replace('\x00', '')
                    if decoded_text.strip():
                        return decoded_text, True
                except (UnicodeDecodeError, AttributeError):
                    continue
            
            return None, False
            
        except Exception as e:
            return None, False
    
    def _analyze_decoded_content(self, decoded_text: str) -> Dict[str, Any]:
        """Analyze decoded content for malicious patterns"""
        if not decoded_text:
            return {
                "is_suspicious": False,
                "threat_level": "UNKNOWN",
                "indicators": [],
                "attack_techniques": []
            }
        
        decoded_lower = decoded_text.lower()
        indicators = []
        attack_techniques = []
        
        # PowerShell execution patterns
        powershell_patterns = {
            "iex": "Invoke-Expression - executes arbitrary code",
            "invoke-expression": "Executes arbitrary PowerShell code",
            "invoke-command": "Remote command execution",
            "invoke-webrequest": "Downloads content from internet",
            "downloadstring": "Downloads and executes remote code",
            "downloadfile": "Downloads file from internet",
            "webclient": "Network client for downloading content",
            "net.webclient": "Network client object",
            "bitstransfer": "Background file transfer (potential data exfiltration)",
            "start-bitstransfer": "BITS transfer for file download"
        }
        
        # Obfuscation and evasion
        evasion_patterns = {
            "-nop": "NoProfile flag - avoids loading profile scripts",
            "-noprofile": "Skips PowerShell profile loading",
            "-w hidden": "Hidden window - runs invisibly",
            "-windowstyle hidden": "Hides PowerShell window",
            "-ep bypass": "Execution policy bypass",
            "-executionpolicy bypass": "Disables script execution restrictions",
            "-enc": "Encoded command (nested encoding)",
            "-encodedcommand": "Base64 encoded command",
            "frombase64string": "Additional decoding layer"
        }
        
        # Credential access
        credential_patterns = {
            "mimikatz": "Credential dumping tool",
            "invoke-mimikatz": "PowerShell wrapper for Mimikatz",
            "get-credential": "Prompts for credentials",
            "convertto-securestring": "Password manipulation",
            "sekurlsa": "Mimikatz module for credential extraction",
            "lsadump": "LSA secrets dumping",
            "password": "Potential credential theft",
            "sam": "Security Account Manager access"
        }
        
        # Persistence mechanisms
        persistence_patterns = {
            "schtasks": "Scheduled task creation",
            "new-scheduledtask": "Creates scheduled task for persistence",
            "register-scheduledtask": "Registers scheduled task",
            "startup": "Startup folder modification",
            "registry": "Registry modification",
            "wmi": "WMI-based persistence",
            "new-service": "Service creation"
        }
        
        # Lateral movement
        lateral_patterns = {
            "psexec": "Remote execution tool",
            "winrm": "Windows Remote Management",
            "invoke-command -computername": "Remote command execution",
            "enter-pssession": "Interactive remote session",
            "wmic": "WMI command-line tool"
        }
        
        # Command and control
        c2_patterns = {
            "http://": "HTTP connection (potential C2)",
            "https://": "HTTPS connection (potential C2)",
            "://": "URL connection",
            "tcp": "TCP network connection",
            "socket": "Network socket creation",
            "getstream": "Network stream (potential C2 channel)"
        }
        
        # Data exfiltration
        exfil_patterns = {
            "compress-archive": "File compression before exfiltration",
            "out-file": "Writing to file (staging for exfiltration)",
            "set-content": "File creation/modification",
            "send-mailmessage": "Email-based exfiltration",
            "ftp": "FTP transfer",
            "post": "HTTP POST (potential data upload)"
        }
        
        # Check all patterns
        all_patterns = [
            (powershell_patterns, "execution"),
            (evasion_patterns, "defense_evasion"),
            (credential_patterns, "credential_access"),
            (persistence_patterns, "persistence"),
            (lateral_patterns, "lateral_movement"),
            (c2_patterns, "command_and_control"),
            (exfil_patterns, "exfiltration")
        ]
        
        for pattern_dict, technique in all_patterns:
            for pattern, description in pattern_dict.items():
                if pattern in decoded_lower:
                    indicators.append(description)
                    if technique not in attack_techniques:
                        attack_techniques.append(technique)
        
        # Determine threat level
        threat_level = self._calculate_threat_level(len(indicators), attack_techniques)
        
        # Generate threat summary
        threat_summary = self._generate_threat_summary(decoded_text, indicators, attack_techniques)
        
        return {
            "is_suspicious": len(indicators) > 0,
            "threat_level": threat_level,
            "indicators": indicators[:10],  # Limit to top 10 indicators
            "indicator_count": len(indicators),
            "attack_techniques": attack_techniques,
            "threat_summary": threat_summary
        }
    
    def _calculate_threat_level(self, indicator_count: int, attack_techniques: list) -> str:
        """Calculate threat level based on indicators and techniques"""
        if indicator_count == 0:
            return "LOW"
        
        # High-risk techniques
        high_risk = ["credential_access", "command_and_control", "exfiltration"]
        has_high_risk = any(tech in attack_techniques for tech in high_risk)
        
        if has_high_risk or indicator_count >= 5:
            return "CRITICAL"
        elif indicator_count >= 3:
            return "HIGH"
        elif indicator_count >= 1:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _generate_threat_summary(self, decoded_text: str, indicators: list, attack_techniques: list) -> str:
        """Generate human-readable threat summary"""
        if not indicators:
            return "No suspicious patterns detected in decoded content"
        
        summary_parts = []
        
        # Describe what was found
        if len(indicators) == 1:
            summary_parts.append(f"Found 1 suspicious indicator: {indicators[0]}")
        else:
            summary_parts.append(f"Found {len(indicators)} suspicious indicators including: {indicators[0]}")
        
        # Describe attack techniques
        if attack_techniques:
            technique_names = {
                "execution": "arbitrary code execution",
                "defense_evasion": "defense evasion",
                "credential_access": "credential theft",
                "persistence": "persistence mechanisms",
                "lateral_movement": "lateral movement",
                "command_and_control": "C2 communication",
                "exfiltration": "data exfiltration"
            }
            
            readable_techniques = [technique_names.get(t, t) for t in attack_techniques[:3]]
            
            if len(readable_techniques) == 1:
                summary_parts.append(f"Indicates {readable_techniques[0]}.")
            else:
                summary_parts.append(f"Indicates {', '.join(readable_techniques[:-1])} and {readable_techniques[-1]}.")
        
        # Add command preview
        preview = decoded_text[:100].strip()
        if len(decoded_text) > 100:
            preview += "..."
        summary_parts.append(f"Command preview: {preview}")
        
        return " ".join(summary_parts)


# Create singleton instance
_decoder_tool = DecoderTool()

@tool
def decoder(encoded_string: str, encoding_type: str = "auto") -> dict:
    """Decodes Base64 or hex-encoded strings commonly used to hide malicious commands.
    
    Use this tool when you see:
    - PowerShell with -enc, -e, or -encodedcommand flags
    - Long strings of random-looking characters (A-Z, a-z, 0-9, +, /, =)
    - Commands that look obfuscated or unreadable
    - Hex strings (0-9, A-F only) in unusual contexts
    
    The tool automatically detects encoding type, decodes the string, and analyzes it for
    malicious patterns including code execution, credential theft, C2 communication, and more.
    
    Args:
        encoded_string: The encoded string to decode (can be base64 or hex)
        encoding_type: Type of encoding - "auto", "base64", or "hex" (default: "auto")
    
    Returns:
        Decoded content with detailed threat analysis including indicators, attack techniques,
        and threat level assessment.
    
    Examples:
        - decoder("cG93ZXJzaGVsbC5leGU=") → decodes PowerShell commands
        - decoder("496e766f6b652d576562526571756573742068747470733a2f2f6576696c2e636f6d", "hex")
    """
    return _decoder_tool.run({
        "encoded_string": encoded_string,
        "encoding_type": encoding_type
    })