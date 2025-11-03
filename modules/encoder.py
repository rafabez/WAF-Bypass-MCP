"""
Payload Encoder Module
Applies multiple encoding techniques to obfuscate payloads and bypass WAF filters.
"""

import urllib.parse
import base64
import html
from typing import List, Dict, Any


class PayloadEncoder:
    """
    Encodes payloads using various techniques to evade WAF detection.
    """
    
    def __init__(self):
        self.encoding_methods = {
            "url": self._url_encode,
            "double_url": self._double_url_encode,
            "unicode": self._unicode_encode,
            "hex": self._hex_encode,
            "html": self._html_encode,
            "base64": self._base64_encode,
            "mixed": self._mixed_encode
        }
    
    def encode(
        self,
        payload: str,
        encoding_types: List[str],
        layering: int = 1
    ) -> List[Dict[str, Any]]:
        """
        Encode a payload using specified encoding techniques.
        
        Args:
            payload: Original payload to encode
            encoding_types: List of encoding methods to apply
            layering: Number of encoding passes (1-3)
        
        Returns:
            List of encoded payload variants with explanations
        """
        
        encoded_variants = []
        
        for encoding_type in encoding_types:
            if encoding_type not in self.encoding_methods:
                continue
            
            # Apply encoding with layering
            encoded = payload
            for layer in range(layering):
                encoded = self.encoding_methods[encoding_type](encoded)
            
            encoded_variants.append({
                "encoding_type": encoding_type,
                "layering": layering,
                "encoded_payload": encoded,
                "original_payload": payload,
                "explanation": self._get_explanation(encoding_type, layering)
            })
        
        return encoded_variants
    
    def _url_encode(self, payload: str) -> str:
        """Standard URL encoding."""
        return urllib.parse.quote(payload, safe='')
    
    def _double_url_encode(self, payload: str) -> str:
        """Double URL encoding - encode twice."""
        encoded_once = urllib.parse.quote(payload, safe='')
        return urllib.parse.quote(encoded_once, safe='')
    
    def _unicode_encode(self, payload: str) -> str:
        """Unicode escape encoding."""
        return ''.join([f'\\u{ord(c):04x}' for c in payload])
    
    def _hex_encode(self, payload: str) -> str:
        """Hexadecimal encoding."""
        return ''.join([f'\\x{ord(c):02x}' for c in payload])
    
    def _html_encode(self, payload: str) -> str:
        """HTML entity encoding."""
        return html.escape(payload)
    
    def _base64_encode(self, payload: str) -> str:
        """Base64 encoding."""
        return base64.b64encode(payload.encode()).decode()
    
    def _mixed_encode(self, payload: str) -> str:
        """
        Mixed encoding - alternates between different encoding types.
        This can confuse parsers that don't normalize consistently.
        """
        result = []
        for i, char in enumerate(payload):
            if i % 3 == 0:
                result.append(f'\\x{ord(char):02x}')  # Hex
            elif i % 3 == 1:
                result.append(urllib.parse.quote(char))  # URL
            else:
                result.append(f'\\u{ord(char):04x}')  # Unicode
        return ''.join(result)
    
    def _get_explanation(self, encoding_type: str, layering: int) -> str:
        """Get explanation for encoding technique."""
        
        explanations = {
            "url": f"URL encoded {layering} time(s). Bypasses filters looking for literal characters.",
            "double_url": f"Double URL encoded. First decode reveals encoded payload, second reveals attack. {layering} layer(s) applied.",
            "unicode": f"Unicode escape sequences. Bypasses byte-pattern matching. {layering} layer(s) applied.",
            "hex": f"Hexadecimal encoding. Evades string-based detection. {layering} layer(s) applied.",
            "html": f"HTML entity encoding. Works when payload is rendered in HTML context. {layering} layer(s) applied.",
            "base64": f"Base64 encoded. Useful for binary payloads or evasion. {layering} layer(s) applied.",
            "mixed": f"Mixed encoding techniques. Confuses inconsistent parsers. {layering} layer(s) applied."
        }
        
        return explanations.get(encoding_type, f"Custom encoding with {layering} layer(s)")
    
    def encode_for_context(self, payload: str, context: str) -> List[Dict[str, Any]]:
        """
        Encode payload based on specific context (URL, JSON, XML, etc.).
        
        Args:
            payload: Original payload
            context: Target context (url_param, json_value, xml_attribute, etc.)
        
        Returns:
            Context-appropriate encoded variants
        """
        
        context_encodings = {
            "url_param": ["url", "double_url", "unicode"],
            "json_value": ["unicode", "hex", "base64"],
            "xml_attribute": ["html", "unicode"],
            "http_header": ["url", "base64"],
            "cookie": ["url", "base64"],
            "html_attribute": ["html", "unicode", "url"]
        }
        
        encodings = context_encodings.get(context, ["url", "unicode", "hex"])
        return self.encode(payload, encodings, layering=1)
