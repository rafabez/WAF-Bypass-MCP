"""
WAF Bypass MCP Server
A Model Context Protocol server for AI-powered WAF bypass testing and payload generation.

Inspired by research from esakkiammal-v on using AI to bypass AI-powered security systems.
https://infosecwriteups.com/how-i-made-chatgpt-my-personal-hacking-assistant-and-broke-their-ai-powered-security-ee37d4a725c2

Built for automated penetration testing workflows.
Developed by InterzoneSec Research Team
License: MIT
"""

from typing import Any, Dict, List, Optional
from mcp.server.fastmcp import FastMCP
import json
import os
from pathlib import Path

# Import our modules
from modules.payload_generator import PayloadGenerator
from modules.encoder import PayloadEncoder
from modules.tester import PayloadTester
from modules.adaptive_learner import AdaptiveLearner
from modules.storage import PayloadStorage

# Initialize MCP server
mcp = FastMCP("WAF-Bypass-MCP")

# Initialize components
generator = PayloadGenerator()
encoder = PayloadEncoder()
tester = PayloadTester()
learner = AdaptiveLearner()
storage = PayloadStorage()

# ===== CORE PAYLOAD GENERATION TOOLS =====

@mcp.tool()
def generate_attack_payloads(
    attack_type: str,
    technique: str = "semantic_obfuscation",
    target_context: str = "",
    count: int = 5
) -> Dict[str, Any]:
    """
    Generate AI-powered attack payloads using advanced obfuscation techniques.
    
    This tool leverages the AI assistant's intelligence to create sophisticated payloads
    that bypass WAF detection through semantic manipulation, encoding, and contextual blending.
    
    Args:
        attack_type: Type of attack (sql_injection, xss, path_traversal, command_injection, xxe, ssrf, ldap_injection, nosql_injection)
        technique: Obfuscation technique to use:
            - semantic_obfuscation: Hide malicious intent in comments/natural language
            - encoding_layering: Multiple encoding passes (URL, Unicode, hex)
            - contextual_blending: Make payload look like legitimate data
            - natural_language: Disguise as English text
            - polyglot_payloads: Multi-context attacks
        target_context: Context information (e.g., "JSON API", "web form", "HTTP header")
        count: Number of payload variants to generate (default: 5)
    
    Returns:
        Dictionary containing:
        - payloads: List of generated payloads with explanations
        - technique: Technique used
        - attack_type: Attack type
        - recommendations: Usage tips
    """
    
    # Get the AI generation prompt to guide payload creation
    generation_prompt = generator.get_generation_prompt(
        attack_type=attack_type,
        technique=technique,
        context=target_context
    )
    
    payloads = generator.generate_payloads(
        attack_type=attack_type,
        technique=technique,
        context=target_context,
        count=count
    )
    
    return {
        "attack_type": attack_type,
        "technique": technique,
        "target_context": target_context,
        "ai_generation_prompt": generation_prompt,  # ✅ PROMPT INCLUÍDO!
        "payload_count": len(payloads),
        "payloads": payloads,
        "recommendations": generator.get_recommendations(attack_type, technique)
    }


@mcp.tool()
def encode_payload(
    payload: str,
    encoding_types: List[str] = None,
    layering: int = 1
) -> Dict[str, Any]:
    """
    Apply multiple encoding techniques to obfuscate payloads.
    
    Args:
        payload: The original payload to encode
        encoding_types: List of encodings to apply. Options:
            - url: URL encoding (%20, %3C, etc.)
            - double_url: Double URL encoding
            - unicode: Unicode encoding (\\u0041)
            - hex: Hexadecimal encoding (\\x41)
            - html: HTML entity encoding (&lt;, &#60;)
            - base64: Base64 encoding
            - mixed: Mix of different encodings
        layering: Number of encoding passes (1-3)
    
    Returns:
        Dictionary with encoded variants and their explanations
    """
    
    if encoding_types is None:
        encoding_types = ["url", "unicode", "double_url", "hex", "mixed"]
    
    encoded_payloads = encoder.encode(
        payload=payload,
        encoding_types=encoding_types,
        layering=layering
    )
    
    return {
        "original_payload": payload,
        "encoding_types": encoding_types,
        "layering": layering,
        "encoded_variants": encoded_payloads
    }


@mcp.tool()
def test_payload_against_target(
    target_url: str,
    payload: str,
    method: str = "POST",
    headers: Optional[Dict[str, str]] = None,
    data_key: str = "query",
    attack_type: str = "sql_injection"
) -> Dict[str, Any]:
    """
    Test a payload against a target endpoint and analyze the response.
    
    Args:
        target_url: Full URL of the target endpoint
        payload: The payload to test
        method: HTTP method (GET, POST, PUT, etc.)
        headers: Custom HTTP headers (e.g., Authorization, Content-Type)
        data_key: JSON key or parameter name for the payload
        attack_type: Type of attack being tested
    
    Returns:
        Dictionary containing:
        - status_code: HTTP response status
        - bypassed: Whether WAF was bypassed (status != 403)
        - response_preview: First 500 chars of response
        - headers: Response headers
        - success_indicators: Signs of successful exploitation
        - recommendations: Next steps
    """
    
    result = tester.test_payload(
        url=target_url,
        payload=payload,
        method=method,
        headers=headers,
        data_key=data_key,
        attack_type=attack_type
    )
    
    # Store successful payloads
    if result.get("bypassed") or result.get("potentially_successful"):
        storage.save_successful_payload(
            payload=payload,
            attack_type=attack_type,
            target_url=target_url,
            result=result
        )
    
    return result


@mcp.tool()
def adapt_failed_payload(
    original_payload: str,
    waf_response: str,
    attack_type: str,
    block_reason: str = "",
    improvement_count: int = 3
) -> Dict[str, Any]:
    """
    Use adaptive learning to improve blocked payloads.
    
    This tool analyzes why a payload was blocked and generates improved versions
    that avoid the detected patterns while maintaining malicious intent.
    
    Args:
        original_payload: The payload that was blocked
        waf_response: Response from WAF (status, error message, etc.)
        attack_type: Type of attack
        block_reason: Optional explanation of why it was blocked
        improvement_count: Number of improved variants to generate (default: 3)
    
    Returns:
        Dictionary containing:
        - analysis: Why the payload was blocked
        - improved_payloads: List of new payload variants
        - evasion_techniques: Techniques used in improvements
        - confidence: Confidence score for success
    """
    
    # Get the adaptation prompt to guide AI assistant
    adaptation_prompt = learner.get_adaptation_prompt(
        payload=original_payload,
        waf_response=waf_response,
        attack_type=attack_type,
        count=improvement_count
    )
    
    improvements = learner.adapt_payload(
        payload=original_payload,
        waf_response=waf_response,
        attack_type=attack_type,
        block_reason=block_reason,
        count=improvement_count
    )
    
    # Include the prompt in the response
    improvements["ai_adaptation_prompt"] = adaptation_prompt
    
    return improvements


@mcp.tool()
def batch_test_attack_surface(
    target_url: str,
    attack_type: str,
    parameter_name: str = "query",
    method: str = "POST",
    headers: Optional[Dict[str, str]] = None,
    techniques: Optional[List[str]] = None,
    payload_count: int = 15
) -> Dict[str, Any]:
    """
    Comprehensive automated testing of an attack surface.
    
    This is the main automation tool that:
    1. Generates multiple payload variants
    2. Tests each against the target
    3. Adapts failed payloads
    4. Tests improvements
    5. Stores successful bypasses
    
    Args:
        target_url: Target endpoint URL
        attack_type: Type of attack to test
        parameter_name: Parameter/key to inject payload into
        method: HTTP method
        headers: Custom headers
        techniques: List of techniques to try (default: all)
        payload_count: Total number of payloads to test
    
    Returns:
        Comprehensive test results with successful bypasses and recommendations
    """
    
    if techniques is None:
        techniques = [
            "semantic_obfuscation",
            "encoding_layering",
            "contextual_blending",
            "natural_language",
            "polyglot_payloads"
        ]
    
    results = {
        "target_url": target_url,
        "attack_type": attack_type,
        "total_payloads_tested": 0,
        "successful_bypasses": [],
        "failed_attempts": [],
        "waf_fingerprint": {},
        "recommendations": []
    }
    
    payloads_per_technique = payload_count // len(techniques)
    
    for technique in techniques:
        # Generate payloads
        gen_result = generate_attack_payloads(
            attack_type=attack_type,
            technique=technique,
            target_context=f"Testing {target_url}",
            count=payloads_per_technique
        )
        
        # Test each payload
        for payload_info in gen_result["payloads"]:
            payload = payload_info["payload"]
            
            test_result = test_payload_against_target(
                target_url=target_url,
                payload=payload,
                method=method,
                headers=headers,
                data_key=parameter_name,
                attack_type=attack_type
            )
            
            results["total_payloads_tested"] += 1
            
            if test_result.get("bypassed"):
                results["successful_bypasses"].append({
                    "payload": payload,
                    "technique": technique,
                    "status_code": test_result["status_code"],
                    "explanation": payload_info.get("explanation", ""),
                    "response_preview": test_result.get("response_preview", "")
                })
            else:
                # Try to adapt failed payload
                if results["total_payloads_tested"] < payload_count * 0.7:  # Don't adapt everything
                    adaptation = adapt_failed_payload(
                        original_payload=payload,
                        waf_response=str(test_result),
                        attack_type=attack_type,
                        improvement_count=2
                    )
                    
                    # Test best improvement
                    if adaptation.get("improved_payloads"):
                        best_improvement = adaptation["improved_payloads"][0]
                        improved_test = test_payload_against_target(
                            target_url=target_url,
                            payload=best_improvement["payload"],
                            method=method,
                            headers=headers,
                            data_key=parameter_name,
                            attack_type=attack_type
                        )
                        
                        results["total_payloads_tested"] += 1
                        
                        if improved_test.get("bypassed"):
                            results["successful_bypasses"].append({
                                "payload": best_improvement["payload"],
                                "technique": f"{technique}_adapted",
                                "status_code": improved_test["status_code"],
                                "explanation": best_improvement.get("explanation", ""),
                                "original_payload": payload
                            })
    
    # Generate recommendations
    if results["successful_bypasses"]:
        results["recommendations"].append(
            f"Found {len(results['successful_bypasses'])} successful bypasses! "
            "Consider testing for data extraction or RCE capabilities."
        )
    else:
        results["recommendations"].append(
            "No bypasses found. WAF appears robust. Consider: "
            "1) Testing different attack types, "
            "2) Analyzing WAF fingerprint, "
            "3) Looking for logic flaws instead of injection attacks."
        )
    
    return results


@mcp.tool()
def analyze_waf_behavior(
    target_url: str,
    test_payloads: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Fingerprint and analyze WAF behavior using known test patterns.
    
    Args:
        target_url: Target endpoint to analyze
        test_payloads: Optional custom test payloads (uses defaults if not provided)
    
    Returns:
        WAF fingerprint including detected patterns, blocking behavior, and weaknesses
    """
    
    fingerprint = tester.fingerprint_waf(
        url=target_url,
        test_payloads=test_payloads
    )
    
    storage.save_waf_fingerprint(target_url, fingerprint)
    
    return fingerprint


@mcp.tool()
def get_successful_payloads(
    attack_type: Optional[str] = None,
    technique: Optional[str] = None,
    limit: int = 10
) -> Dict[str, Any]:
    """
    Retrieve previously successful payloads from storage.
    
    Args:
        attack_type: Filter by attack type (optional)
        technique: Filter by technique (optional)
        limit: Maximum number of results
    
    Returns:
        List of successful payloads with metadata
    """
    
    payloads = storage.get_successful_payloads(
        attack_type=attack_type,
        technique=technique,
        limit=limit
    )
    
    return {
        "count": len(payloads),
        "payloads": payloads,
        "attack_types": list(set(p.get("attack_type") for p in payloads)),
        "techniques": list(set(p.get("technique") for p in payloads if p.get("technique")))
    }


@mcp.tool()
def generate_polyglot_payload(
    attack_types: List[str],
    target_context: str = ""
) -> Dict[str, Any]:
    """
    Generate polyglot payloads that work across multiple attack contexts.
    
    Args:
        attack_types: List of attack types to combine (e.g., ["xss", "sql_injection"])
        target_context: Target context information
    
    Returns:
        Polyglot payloads that work in multiple contexts
    """
    
    polyglots = generator.generate_polyglot(
        attack_types=attack_types,
        context=target_context
    )
    
    return {
        "attack_types": attack_types,
        "polyglot_payloads": polyglots,
        "usage": "These payloads may work in multiple contexts simultaneously"
    }


@mcp.tool()
def export_results(
    format: str = "json",
    output_path: Optional[str] = None
) -> Dict[str, Any]:
    """
    Export all successful payloads and test results.
    
    Args:
        format: Export format (json, csv, markdown, burp_macro)
        output_path: Optional custom output path
    
    Returns:
        Export status and file location
    """
    
    export_result = storage.export_data(
        format=format,
        output_path=output_path
    )
    
    return export_result


# ===== MCP RESOURCES =====

@mcp.resource("payload-library://successful-bypasses")
def get_payload_library() -> str:
    """Returns the complete library of successful WAF bypass payloads."""
    payloads = storage.get_all_successful_payloads()
    return json.dumps(payloads, indent=2)


@mcp.resource("payload-library://waf-fingerprints")
def get_waf_fingerprints() -> str:
    """Returns all WAF fingerprint data collected."""
    fingerprints = storage.get_all_waf_fingerprints()
    return json.dumps(fingerprints, indent=2)


@mcp.tool()
def comprehensive_waf_scan(
    target_url: str,
    parameter_name: str = "query",
    method: str = "POST",
    headers: Optional[Dict[str, str]] = None,
    attack_types: Optional[List[str]] = None,
    payloads_per_attack: int = 5
) -> Dict[str, Any]:
    """
    Comprehensive WAF bypass testing across ALL attack types.
    
    This tool automatically tests multiple attack vectors without requiring
    the user to specify a single attack type. Perfect for reconnaissance
    and discovering which attack vectors work against a target.
    
    Args:
        target_url: Target endpoint URL
        parameter_name: Parameter/key to inject payloads into
        method: HTTP method (GET, POST, PUT, etc.)
        headers: Custom HTTP headers
        attack_types: List of attack types to test (default: all)
        payloads_per_attack: Number of payloads to test per attack type
    
    Returns:
        Dictionary containing:
        - results_by_attack_type: Results grouped by attack type
        - total_attacks_tested: Total number of attack types tested
        - successful_attack_types: List of attack types that bypassed WAF
        - overall_success_rate: Percentage of successful bypasses
        - recommendations: Next steps based on results
    """
    
    # Default to all attack types if not specified
    if attack_types is None:
        attack_types = [
            "sql_injection",
            "xss",
            "path_traversal",
            "command_injection",
            "xxe",
            "ssrf",
            "ldap_injection",
            "nosql_injection"
        ]
    
    results = {
        "target_url": target_url,
        "results_by_attack_type": {},
        "total_attacks_tested": len(attack_types),
        "successful_attack_types": [],
        "total_payloads_tested": 0,
        "total_bypasses": 0,
        "overall_success_rate": 0.0,
        "recommendations": []
    }
    
    # Test each attack type
    for attack_type in attack_types:
        print(f"[*] Testing {attack_type}...")
        
        attack_results = batch_test_attack_surface(
            target_url=target_url,
            attack_type=attack_type,
            parameter_name=parameter_name,
            method=method,
            headers=headers,
            payload_count=payloads_per_attack
        )
        
        results["results_by_attack_type"][attack_type] = attack_results
        results["total_payloads_tested"] += attack_results["total_payloads_tested"]
        
        # Track successful attack types
        if attack_results["successful_bypasses"]:
            results["successful_attack_types"].append(attack_type)
            results["total_bypasses"] += len(attack_results["successful_bypasses"])
    
    # Calculate overall success rate
    if results["total_payloads_tested"] > 0:
        results["overall_success_rate"] = (
            results["total_bypasses"] / results["total_payloads_tested"]
        ) * 100
    
    # Generate recommendations
    if results["successful_attack_types"]:
        results["recommendations"].append(
            f"✅ WAF is vulnerable to: {', '.join(results['successful_attack_types'])}"
        )
        results["recommendations"].append(
            "🎯 Focus deeper testing on successful attack types"
        )
        results["recommendations"].append(
            "📊 Use adaptive learning to improve successful payloads"
        )
    else:
        results["recommendations"].append(
            "⚠️ No bypasses found with initial payloads"
        )
        results["recommendations"].append(
            "🔄 Try WAF fingerprinting to identify specific WAF vendor"
        )
        results["recommendations"].append(
            "💡 Use adaptive learning to evolve payloads based on blocks"
        )
    
    # Store results
    storage.store_scan_results(target_url, results)
    
    return results


@mcp.tool()
def analyze_target_and_recommend(
    target_url: str,
    recon_data: str,
    auto_execute: bool = False
) -> Dict[str, Any]:
    """
    Analyze reconnaissance data and recommend optimal attack vectors.
    
    This tool helps the AI assistant analyze target information and suggest
    the most effective attack types based on technology stack, endpoints,
    and observed behavior. The AI can then use this analysis to prioritize
    testing.
    
    Args:
        target_url: Target endpoint URL
        recon_data: Reconnaissance information (technologies, behaviors, headers, etc.)
        auto_execute: If True, automatically execute recommended tests
    
    Returns:
        Dictionary containing:
        - analysis: Parsed recon data
        - recommended_attacks: Prioritized list of attack types
        - reasoning: Why each attack type was recommended
        - suggested_payloads: Specific payload suggestions
        - execution_plan: Step-by-step testing plan
    """
    
    # This tool provides structure for the AI assistant to analyze
    # The actual analysis happens through the AI's reasoning
    
    analysis = {
        "target_url": target_url,
        "recon_summary": recon_data,
        "detected_technologies": [],
        "detected_waf": None,
        "endpoint_type": None,
        "recommended_attacks": [],
        "reasoning": {},
        "suggested_payloads": {},
        "execution_plan": [],
        "confidence_scores": {}
    }
    
    # Parse common technology indicators from recon data
    recon_lower = recon_data.lower()
    
    # Database detection
    if "mongodb" in recon_lower or "mongo" in recon_lower:
        analysis["detected_technologies"].append("MongoDB")
        analysis["recommended_attacks"].append("nosql_injection")
        analysis["reasoning"]["nosql_injection"] = "MongoDB detected - NoSQL injection highly relevant"
        analysis["confidence_scores"]["nosql_injection"] = 0.9
    
    if "mysql" in recon_lower or "postgresql" in recon_lower or "sql" in recon_lower:
        analysis["detected_technologies"].append("SQL Database")
        analysis["recommended_attacks"].append("sql_injection")
        analysis["reasoning"]["sql_injection"] = "SQL database detected - SQL injection should be tested"
        analysis["confidence_scores"]["sql_injection"] = 0.85
    
    # Framework detection
    if "node" in recon_lower or "express" in recon_lower:
        analysis["detected_technologies"].append("Node.js")
        analysis["recommended_attacks"].append("command_injection")
        analysis["reasoning"]["command_injection"] = "Node.js detected - command injection possible via child_process"
        analysis["confidence_scores"]["command_injection"] = 0.6
    
    if "php" in recon_lower:
        analysis["detected_technologies"].append("PHP")
        if "command_injection" not in analysis["recommended_attacks"]:
            analysis["recommended_attacks"].append("command_injection")
        analysis["reasoning"]["command_injection"] = "PHP detected - command injection via exec/system functions"
        analysis["confidence_scores"]["command_injection"] = 0.7
    
    # API detection
    if "api" in recon_lower or "json" in recon_lower or "rest" in recon_lower:
        analysis["endpoint_type"] = "API"
        if "xss" not in analysis["recommended_attacks"]:
            analysis["recommended_attacks"].append("xss")
        analysis["reasoning"]["xss"] = "JSON API - XSS possible if data is rendered in frontend"
        analysis["confidence_scores"]["xss"] = 0.5
        
        if "ssrf" not in analysis["recommended_attacks"]:
            analysis["recommended_attacks"].append("ssrf")
        analysis["reasoning"]["ssrf"] = "API endpoint - SSRF possible via URL parameters"
        analysis["confidence_scores"]["ssrf"] = 0.65
    
    # File operations
    if "file" in recon_lower or "upload" in recon_lower or "download" in recon_lower:
        analysis["recommended_attacks"].append("path_traversal")
        analysis["reasoning"]["path_traversal"] = "File operations detected - path traversal likely"
        analysis["confidence_scores"]["path_traversal"] = 0.8
    
    # XML detection
    if "xml" in recon_lower or "soap" in recon_lower:
        analysis["detected_technologies"].append("XML")
        analysis["recommended_attacks"].append("xxe")
        analysis["reasoning"]["xxe"] = "XML processing detected - XXE injection possible"
        analysis["confidence_scores"]["xxe"] = 0.75
    
    # LDAP detection
    if "ldap" in recon_lower or "active directory" in recon_lower or "ad" in recon_lower:
        analysis["detected_technologies"].append("LDAP")
        analysis["recommended_attacks"].append("ldap_injection")
        analysis["reasoning"]["ldap_injection"] = "LDAP/AD detected - LDAP injection should be tested"
        analysis["confidence_scores"]["ldap_injection"] = 0.8
    
    # WAF detection
    if "cloudflare" in recon_lower:
        analysis["detected_waf"] = "Cloudflare"
    elif "aws" in recon_lower or "waf" in recon_lower:
        analysis["detected_waf"] = "AWS WAF"
    elif "akamai" in recon_lower:
        analysis["detected_waf"] = "Akamai"
    
    # If no specific attacks recommended, suggest comprehensive scan
    if not analysis["recommended_attacks"]:
        analysis["recommended_attacks"] = ["sql_injection", "xss", "command_injection"]
        analysis["reasoning"]["default"] = "No specific technologies detected - testing common attack vectors"
    
    # Sort by confidence score
    analysis["recommended_attacks"].sort(
        key=lambda x: analysis["confidence_scores"].get(x, 0.5),
        reverse=True
    )
    
    # Generate execution plan
    for i, attack_type in enumerate(analysis["recommended_attacks"], 1):
        confidence = analysis["confidence_scores"].get(attack_type, 0.5)
        priority = "HIGH" if confidence >= 0.7 else "MEDIUM" if confidence >= 0.5 else "LOW"
        
        analysis["execution_plan"].append({
            "step": i,
            "attack_type": attack_type,
            "priority": priority,
            "confidence": confidence,
            "reasoning": analysis["reasoning"].get(attack_type, "General testing"),
            "recommended_payload_count": 10 if confidence >= 0.7 else 5
        })
    
    # Auto-execute if requested
    if auto_execute and analysis["recommended_attacks"]:
        print(f"[*] Auto-executing recommended attacks...")
        
        scan_results = comprehensive_waf_scan(
            target_url=target_url,
            attack_types=analysis["recommended_attacks"],
            payloads_per_attack=10
        )
        
        analysis["scan_results"] = scan_results
        analysis["auto_executed"] = True
    else:
        analysis["auto_executed"] = False
    
    return analysis


@mcp.resource("payload-library://attack-templates")
def get_attack_templates() -> str:
    """Returns attack payload templates for different scenarios."""
    templates = generator.get_all_templates()
    return json.dumps(templates, indent=2)


if __name__ == "__main__":
    # Run the MCP server
    mcp.run()
