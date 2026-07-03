#!/usr/bin/env python3
"""
Fetch CVSS data for specific CVEs from the NVD API.
"""

import argparse
import csv
import json
import sys
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
from typing import List, Dict, Any

from config import get_config
from rate_limiter import get_rate_limiter, update_rate_limit_from_response, handle_rate_limit_error

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def fetch_cvss_for_cves(cve_ids: List[str], api_key: str = None) -> Dict[str, Any]:
    """
    Fetch CVSS data for specific CVE IDs from NVD API.
    
    Args:
        cve_ids: List of CVE IDs (e.g., ['CVE-2024-1234', 'CVE-2024-5678'])
        api_key: Optional NVD API key (increases rate limit)
        
    Returns:
        Dictionary with CVE data including CVSS scores
    """
    results = {}
    
    # Get rate limiter with appropriate limits
    limiter = get_rate_limiter("nvd", has_api_key=bool(api_key))
    
    for cve_id in cve_ids:
        try:
            # Enforce rate limit before making request — shared endpoint key
            # so the local sliding window accumulates all NVD requests (not one deque per CVE)
            limiter.acquire("nvd_api")
            
            url = f"{NVD_URL}?cveId={cve_id}"
            if api_key:
                url += f"&apiKey={api_key}"
            
            request = Request(url, headers={"User-Agent": "cvss-fetcher/1.0"})
            with urlopen(request, timeout=10) as response:
                # Capture real-time rate limit info from headers
                update_rate_limit_from_response("nvd", response.headers)
                
                if response.status == 200:
                    data = json.load(response)
                    if data.get("vulnerabilities"):
                        results[cve_id] = data["vulnerabilities"][0].get("cve", {})
                    else:
                        results[cve_id] = {"error": "CVE not found"}
                else:
                    results[cve_id] = {"error": f"HTTP {response.status}"}
        except HTTPError as e:
            # Detect rate limiting (HTTP 429) - retry after waiting
            if e.code == 429:
                handle_rate_limit_error("nvd", e.code, e.headers)
                # Now acquire() will block until rate limit resets
                limiter.acquire("nvd_api")
                # Retry the request after waiting
                try:
                    url = f"{NVD_URL}?cveId={cve_id}"
                    if api_key:
                        url += f"&apiKey={api_key}"
                    request = Request(url, headers={"User-Agent": "cvss-fetcher/1.0"})
                    with urlopen(request, timeout=10) as response:
                        update_rate_limit_from_response("nvd", response.headers)
                        if response.status == 200:
                            data = json.load(response)
                            if data.get("vulnerabilities"):
                                results[cve_id] = data["vulnerabilities"][0].get("cve", {})
                            else:
                                results[cve_id] = {"error": "CVE not found"}
                        else:
                            results[cve_id] = {"error": f"HTTP {response.status}"}
                except Exception as retry_e:
                    results[cve_id] = {"error": f"Retry failed: {retry_e}"}
            else:
                results[cve_id] = {"error": f"HTTP {e.code}: {e.reason}"}
        except (URLError, Exception) as e:
            results[cve_id] = {"error": str(e)}
    
    return results


def write_json(output_path: str, data: Dict[str, Any]) -> None:
    """Write data to JSON file."""
    with open(output_path, "w", encoding="utf-8") as out_file:
        json.dump(data, out_file, indent=2)


def write_csv(output_path: str, data: Dict[str, Any]) -> None:
    """Write CVSS data to CSV file."""
    fieldnames = ["cve_id", "cvss_v3_score", "cvss_v3_severity", "cvss_v2_score", "cvss_v2_severity"]
    rows = []

    for cve_id, cve_data in data.items():
        if "error" in cve_data:
            continue
            
        # Extract CVSS v3 metrics
        cvss_v3 = cve_data.get("metrics", {}).get("cvssMetricV31", [{}])[0]
        cvss_v2 = cve_data.get("metrics", {}).get("cvssMetricV2", [{}])[0]
        
        rows.append({
            "cve_id": cve_id,
            "cvss_v3_score": cvss_v3.get("cvssData", {}).get("baseScore", ""),
            "cvss_v3_severity": cvss_v3.get("cvssData", {}).get("baseSeverity", ""),
            "cvss_v2_score": cvss_v2.get("cvssData", {}).get("baseScore", ""),
            "cvss_v2_severity": cvss_v2.get("cvssData", {}).get("baseSeverity", ""),
        })

    with open(output_path, "w", encoding="utf-8", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def parse_args():
    parser = argparse.ArgumentParser(description="Fetch CVSS data for specific CVEs.")
    parser.add_argument("--cves", nargs="+", help="List of CVE IDs (e.g., CVE-2024-1234 CVE-2024-5678)")
    parser.add_argument("--output-json", default="cvss-data.json", help="JSON output file")
    parser.add_argument("--output-csv", default="cvss-data.csv", help="CSV output file")
    return parser.parse_args()


def main():
    args = parse_args()
    
    if not args.cves:
        print("Error: No CVE IDs provided. Use --cves followed by CVE IDs.", file=sys.stderr)
        return 1
    
    # Load API key from config
    config = get_config()
    api_key = config.get_nvd_api_key()
    
    print(f"Fetching CVSS data for {len(args.cves)} CVE(s)...")
    if api_key:
        print("(Using configured NVD API key)")
    else:
        print("(No API key - rate limited to 5 requests/minute)")
    
    data = fetch_cvss_for_cves(args.cves, api_key)
    write_json(args.output_json, data)
    write_csv(args.output_csv, data)
    print(f"Fetched CVSS data and wrote to {args.output_json} and {args.output_csv}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
