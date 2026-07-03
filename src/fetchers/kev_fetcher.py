#!/usr/bin/env python3
"""Fetch CISA Known Exploited Vulnerabilities (KEV) data and check for specific CVEs."""

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import List, Dict, Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from rate_limiter import get_rate_limiter, update_rate_limit_from_response, handle_rate_limit_error

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Conditional-request cache: stores Last-Modified + ETag + cached data
# KEV is a large static file that rarely changes — a 304 costs nothing
KEV_CACHE_FILE = Path(".kev_cache.json")


def _load_kev_cache() -> dict:
    try:
        if KEV_CACHE_FILE.exists():
            return json.loads(KEV_CACHE_FILE.read_text())
    except Exception:
        pass
    return {}


def _save_kev_cache(cache: dict) -> None:
    try:
        KEV_CACHE_FILE.write_text(json.dumps(cache))
    except Exception:
        pass


def fetch_kev_data() -> Dict[str, Any]:
    """
    Fetch the complete KEV feed from CISA using conditional requests.
    If the feed hasn't changed since last fetch, returns cached data (304 = free).

    Returns:
        Dictionary containing all known exploited vulnerabilities
    """
    limiter = get_rate_limiter("kev", has_api_key=False)
    limiter.acquire("kev_data")

    cache = _load_kev_cache()
    headers = {"User-Agent": "kev-fetcher/1.0"}

    # Conditional request — if server returns 304, cached data is still valid
    if cache.get("last_modified"):
        headers["If-Modified-Since"] = cache["last_modified"]
    if cache.get("etag"):
        headers["If-None-Match"] = cache["etag"]

    req = Request(KEV_URL, headers=headers)
    try:
        with urlopen(req, timeout=30) as resp:
            update_rate_limit_from_response("kev", resp.headers)

            if resp.getcode() != 200:
                raise RuntimeError(f"HTTP {resp.getcode()}")

            data = resp.read()
            parsed = json.loads(data.decode("utf-8"))

            # Cache Last-Modified / ETag + the data for conditional requests
            new_cache = {}
            lm = resp.headers.get("Last-Modified") or resp.headers.get("last-modified")
            et = resp.headers.get("ETag") or resp.headers.get("etag")
            if lm:
                new_cache["last_modified"] = lm
            if et:
                new_cache["etag"] = et
            if lm or et:
                new_cache["data"] = parsed
                _save_kev_cache(new_cache)

            return parsed

    except HTTPError as e:
        if e.code == 304:
            # Not Modified — cached data is still current (free request, no rate cost)
            if cache.get("data"):
                return cache["data"]
            # Shouldn't happen, but fall through to re-fetch without conditions
        elif e.code == 429:
            handle_rate_limit_error("kev", e.code, e.headers)
            limiter.acquire("kev_data_retry")
            try:
                with urlopen(Request(KEV_URL, headers={"User-Agent": "kev-fetcher/1.0"}), timeout=30) as resp:
                    update_rate_limit_from_response("kev", resp.headers)
                    if resp.getcode() != 200:
                        raise RuntimeError(f"HTTP {resp.getcode()}")
                    return json.loads(resp.read().decode("utf-8"))
            except Exception as retry_e:
                raise RuntimeError(f"KEV retry failed: {retry_e}")
        else:
            raise


def filter_kev_by_cves(kev_data: Dict[str, Any], cve_ids: List[str]) -> Dict[str, Any]:
    """
    Filter KEV data for specific CVE IDs.
    
    Args:
        kev_data: Full KEV dataset from CISA
        cve_ids: List of CVE IDs to filter for
        
    Returns:
        Dictionary with filtered KEV data and lookup results
    """
    results = {
        "found": {},
        "not_found": [],
        "metadata": kev_data.get("catalogVersion", "unknown")
    }
    
    cve_set = set(cve.upper() for cve in cve_ids)
    kev_cves = {vuln.get("cveID", "").upper(): vuln for vuln in kev_data.get("vulnerabilities", [])}
    
    for cve_id in cve_ids:
        cve_upper = cve_id.upper()
        if cve_upper in kev_cves:
            results["found"][cve_upper] = kev_cves[cve_upper]
        else:
            results["not_found"].append(cve_upper)
    
    return results


def write_json(filepath: str, data: Dict[str, Any]) -> None:
    """Write KEV data to JSON file."""
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=2)
    print(f"Data saved to {filepath}")


def write_csv(filepath: str, data: Dict[str, Any]) -> None:
    """Write KEV data to CSV file."""
    fieldnames = ["cve_id", "vendor_name", "product_name", "vulnerability_name", 
                  "date_added", "short_description", "is_exploited"]
    rows = []
    
    # Add found vulnerabilities
    for cve_id, vuln_data in data.get("found", {}).items():
        rows.append({
            "cve_id": cve_id,
            "vendor_name": vuln_data.get("vendorName", ""),
            "product_name": vuln_data.get("productName", ""),
            "vulnerability_name": vuln_data.get("vulnerabilityName", ""),
            "date_added": vuln_data.get("dateAdded", ""),
            "short_description": vuln_data.get("shortDescription", ""),
            "is_exploited": "Yes",
        })
    
    # Add not found as negative results
    for cve_id in data.get("not_found", []):
        rows.append({
            "cve_id": cve_id,
            "vendor_name": "",
            "product_name": "",
            "vulnerability_name": "",
            "date_added": "",
            "short_description": "Not in KEV database",
            "is_exploited": "No",
        })
    
    with open(filepath, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    print(f"CSV data saved to {filepath}")


def parse_args():
    parser = argparse.ArgumentParser(description="Check if specific CVEs are in CISA KEV list.")
    parser.add_argument("cves", nargs="+", help="List of CVE IDs to check (e.g., CVE-2024-1234 CVE-2024-5678)")
    parser.add_argument("--output-json", default="kev_data.json", help="JSON output file")
    parser.add_argument("--output-csv", default="kev_data.csv", help="CSV output file")
    return parser.parse_args()


def main():
    args = parse_args()
    
    try:
        print("Fetching CISA KEV feed...")
        kev_data = fetch_kev_data()
        print(f"Fetched {len(kev_data.get('vulnerabilities', []))} exploited vulnerabilities from CISA")
        
        print(f"Checking {len(args.cves)} CVE(s)...")
        results = filter_kev_by_cves(kev_data, args.cves)
        
        write_json(args.output_json, results)
        write_csv(args.output_csv, results)
        
        print(f"Found: {len(results['found'])}, Not found: {len(results['not_found'])}")
        return 0
    
    except (HTTPError, URLError, RuntimeError, ValueError) as exc:
        print(f"Error fetching KEV feed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
