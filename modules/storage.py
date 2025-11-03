"""
Storage Module
Manages persistent storage of successful payloads, WAF fingerprints, and test results.
"""

import json
import os
import csv
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional


class PayloadStorage:
    """
    Handles storage and retrieval of successful payloads and WAF intelligence.
    """
    
    def __init__(self, storage_dir: str = None):
        """
        Initialize storage with data directory.
        
        Args:
            storage_dir: Custom storage directory (default: ./data)
        """
        if storage_dir is None:
            # Use data directory relative to the module
            base_dir = Path(__file__).parent.parent
            storage_dir = base_dir / "data"
        
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(exist_ok=True)
        
        # Storage files
        self.payloads_file = self.storage_dir / "successful_payloads.json"
        self.fingerprints_file = self.storage_dir / "waf_fingerprints.json"
        self.templates_file = self.storage_dir / "attack_templates.json"
        
        # Initialize files if they don't exist
        self._initialize_storage()
    
    def _initialize_storage(self):
        """Initialize storage files if they don't exist."""
        
        if not self.payloads_file.exists():
            self._write_json(self.payloads_file, [])
        
        if not self.fingerprints_file.exists():
            self._write_json(self.fingerprints_file, {})
        
        if not self.templates_file.exists():
            self._write_json(self.templates_file, {})
    
    def _read_json(self, filepath: Path) -> Any:
        """Read JSON file."""
        try:
            with open(filepath, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error reading {filepath}: {e}")
            return [] if filepath == self.payloads_file else {}
    
    def _write_json(self, filepath: Path, data: Any):
        """Write JSON file."""
        try:
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"Error writing {filepath}: {e}")
    
    def save_successful_payload(
        self,
        payload: str,
        attack_type: str,
        target_url: str,
        result: Dict[str, Any]
    ):
        """
        Save a successful payload to storage.
        
        Args:
            payload: The successful payload
            attack_type: Type of attack
            target_url: Target URL where it worked
            result: Test result dictionary
        """
        
        payloads = self._read_json(self.payloads_file)
        
        entry = {
            "payload": payload,
            "attack_type": attack_type,
            "target_url": target_url,
            "timestamp": datetime.now().isoformat(),
            "status_code": result.get("status_code"),
            "technique": result.get("technique", "unknown"),
            "success_indicators": result.get("success_indicators", []),
            "response_preview": result.get("response_preview", "")[:200]  # Limit size
        }
        
        payloads.append(entry)
        self._write_json(self.payloads_file, payloads)
    
    def get_successful_payloads(
        self,
        attack_type: Optional[str] = None,
        technique: Optional[str] = None,
        limit: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Retrieve successful payloads with optional filtering.
        
        Args:
            attack_type: Filter by attack type
            technique: Filter by technique
            limit: Maximum number of results
        
        Returns:
            List of matching payloads
        """
        
        payloads = self._read_json(self.payloads_file)
        
        # Apply filters
        if attack_type:
            payloads = [p for p in payloads if p.get("attack_type") == attack_type]
        
        if technique:
            payloads = [p for p in payloads if p.get("technique") == technique]
        
        # Sort by timestamp (newest first)
        payloads.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        
        return payloads[:limit]
    
    def get_all_successful_payloads(self) -> List[Dict[str, Any]]:
        """Get all successful payloads."""
        return self._read_json(self.payloads_file)
    
    def save_waf_fingerprint(self, target_url: str, fingerprint: Dict[str, Any]):
        """
        Save WAF fingerprint data.
        
        Args:
            target_url: Target URL
            fingerprint: Fingerprint dictionary
        """
        
        fingerprints = self._read_json(self.fingerprints_file)
        
        fingerprints[target_url] = {
            **fingerprint,
            "timestamp": datetime.now().isoformat()
        }
        
        self._write_json(self.fingerprints_file, fingerprints)
    
    def get_waf_fingerprint(self, target_url: str) -> Optional[Dict[str, Any]]:
        """Get WAF fingerprint for a specific target."""
        fingerprints = self._read_json(self.fingerprints_file)
        return fingerprints.get(target_url)
    
    def get_all_waf_fingerprints(self) -> Dict[str, Any]:
        """Get all WAF fingerprints."""
        return self._read_json(self.fingerprints_file)
    
    def export_data(
        self,
        format: str = "json",
        output_path: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Export all data in various formats.
        
        Args:
            format: Export format (json, csv, markdown, burp_macro)
            output_path: Custom output path
        
        Returns:
            Export status and file location
        """
        
        if output_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = self.storage_dir / f"export_{timestamp}.{format}"
        else:
            output_path = Path(output_path)
        
        payloads = self._read_json(self.payloads_file)
        
        try:
            if format == "json":
                self._export_json(payloads, output_path)
            elif format == "csv":
                self._export_csv(payloads, output_path)
            elif format == "markdown":
                self._export_markdown(payloads, output_path)
            elif format == "burp_macro":
                self._export_burp_macro(payloads, output_path)
            else:
                return {
                    "success": False,
                    "error": f"Unsupported format: {format}"
                }
            
            return {
                "success": True,
                "format": format,
                "output_path": str(output_path),
                "record_count": len(payloads)
            }
        
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    def _export_json(self, payloads: List[Dict], output_path: Path):
        """Export as JSON."""
        with open(output_path, 'w') as f:
            json.dump(payloads, f, indent=2)
    
    def _export_csv(self, payloads: List[Dict], output_path: Path):
        """Export as CSV."""
        if not payloads:
            return
        
        with open(output_path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=payloads[0].keys())
            writer.writeheader()
            writer.writerows(payloads)
    
    def _export_markdown(self, payloads: List[Dict], output_path: Path):
        """Export as Markdown report."""
        with open(output_path, 'w') as f:
            f.write("# WAF Bypass Test Results\n\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write(f"Total Successful Bypasses: {len(payloads)}\n\n")
            
            # Group by attack type
            by_type = {}
            for p in payloads:
                attack_type = p.get("attack_type", "unknown")
                if attack_type not in by_type:
                    by_type[attack_type] = []
                by_type[attack_type].append(p)
            
            for attack_type, items in by_type.items():
                f.write(f"## {attack_type.upper().replace('_', ' ')}\n\n")
                f.write(f"Count: {len(items)}\n\n")
                
                for i, item in enumerate(items, 1):
                    f.write(f"### Payload {i}\n\n")
                    f.write(f"**Payload:** `{item['payload']}`\n\n")
                    f.write(f"**Target:** {item.get('target_url', 'N/A')}\n\n")
                    f.write(f"**Technique:** {item.get('technique', 'N/A')}\n\n")
                    f.write(f"**Timestamp:** {item.get('timestamp', 'N/A')}\n\n")
                    
                    if item.get('success_indicators'):
                        f.write(f"**Success Indicators:** {', '.join(item['success_indicators'])}\n\n")
                    
                    f.write("---\n\n")
    
    def _export_burp_macro(self, payloads: List[Dict], output_path: Path):
        """Export as Burp Suite macro format."""
        # Simplified Burp macro - just the payloads in a format that can be imported
        burp_data = {
            "macros": []
        }
        
        for p in payloads:
            burp_data["macros"].append({
                "payload": p["payload"],
                "attack_type": p.get("attack_type"),
                "description": f"{p.get('technique')} - {p.get('timestamp')}"
            })
        
        with open(output_path, 'w') as f:
            json.dump(burp_data, f, indent=2)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about stored data."""
        
        payloads = self._read_json(self.payloads_file)
        fingerprints = self._read_json(self.fingerprints_file)
        
        # Count by attack type
        attack_type_counts = {}
        technique_counts = {}
        
        for p in payloads:
            attack_type = p.get("attack_type", "unknown")
            technique = p.get("technique", "unknown")
            
            attack_type_counts[attack_type] = attack_type_counts.get(attack_type, 0) + 1
            technique_counts[technique] = technique_counts.get(technique, 0) + 1
        
        return {
            "total_successful_payloads": len(payloads),
            "total_waf_fingerprints": len(fingerprints),
            "attack_type_breakdown": attack_type_counts,
            "technique_breakdown": technique_counts,
            "storage_directory": str(self.storage_dir)
        }
    
    def clear_storage(self, confirm: bool = False):
        """
        Clear all stored data. Use with caution!
        
        Args:
            confirm: Must be True to actually clear
        """
        if not confirm:
            return {
                "success": False,
                "message": "Set confirm=True to actually clear storage"
            }
        
        self._write_json(self.payloads_file, [])
        self._write_json(self.fingerprints_file, {})
        
        return {
            "success": True,
            "message": "All storage cleared"
        }
