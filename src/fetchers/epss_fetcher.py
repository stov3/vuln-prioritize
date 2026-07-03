#!/usr/bin/env python3
"""
Fetch EPSS (Exploit Prediction Scoring System) data for specific CVEs.
"""

import csv
import json
import sys
from typing import List, Dict, Any
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from urllib.parse import urlencode

from rate_limiter import get_rate_limiter, update_rate_limit_from_response, handle_rate_limit_error


EPSS_URL = "https://api.first.org/data/v1/epss"


def fetch_epss_for_cves(cve_ids: List[str]) -> Dict[str, Any]:
    """
    Fetch EPSS scores for all CVE IDs in a single batched request.
    The EPSS API supports comma-separated CVE IDs: ?cve=CVE-A,CVE-B,...
    This reduces N API calls to 1 regardless of list size.
    """
    results = {}
    if not cve_ids:
        return results

    limiter = get_rate_limiter("epss", has_api_key=False)

    # Build a single batched URL for all CVEs
    cve_param = ",".join(cve_ids)
    batch_url = f"{EPSS_URL}?cve={cve_param}"
    request_obj = Request(batch_url, headers={"User-Agent": "epss-fetcher/1.0"})

    try:
        limiter.acquire("epss_batch")

        try:
            with urlopen(request_obj, timeout=30) as response:
                update_rate_limit_from_response("epss", response.headers)
                data = json.load(response)
        except HTTPError as e:
            if e.code == 429:
                handle_rate_limit_error("epss", e.code, e.headers)
                limiter.acquire("epss_batch_retry")
                with urlopen(request_obj, timeout=30) as response:
                    update_rate_limit_from_response("epss", response.headers)
                    data = json.load(response)
            else:
                raise

        # Index returned records by CVE ID (upper-case)
        found = {item["cve"].upper(): item for item in data.get("data", [])}

        for cve_id in cve_ids:
            upper = cve_id.upper()
            results[upper] = found.get(upper, {"error": "CVE not found in EPSS database"})

    except HTTPError as e:
        err = f"HTTP {e.code}: {e.reason}"
        for cve_id in cve_ids:
            results[cve_id.upper()] = {"error": err}
    except URLError as e:
        err = str(e.reason)
        for cve_id in cve_ids:
            results[cve_id.upper()] = {"error": err}
    except Exception as e:
        err = str(e)
        for cve_id in cve_ids:
            results[cve_id.upper()] = {"error": err}

    return results


def write_json(filepath: str, data: Dict[str, Any]) -> None:
    """Save EPSS data to JSON file."""
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=2)
    print(f"Data saved to {filepath}")


def write_csv(filepath: str, data: Dict[str, Any]) -> None:
    """Save EPSS data to CSV file."""
    fieldnames = ["cve", "epss_score", "epss_percentile", "date"]
    rows = []
    
    for cve_id, epss_data in data.items():
        if "error" in epss_data:
            rows.append({
                "cve": cve_id,
                "epss_score": "",
                "epss_percentile": "",
                "date": epss_data.get("error", ""),
            })
        else:
            rows.append({
                "cve": epss_data.get("cve", cve_id),
                "epss_score": epss_data.get("epss", ""),
                "epss_percentile": epss_data.get("percentile", ""),
                "date": epss_data.get("date", ""),
            })
    
    with open(filepath, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    print(f"CSV data saved to {filepath}")


def main():
    if len(sys.argv) < 2:
        print("Usage: epss-fetcher.py <CVE_ID> [CVE_ID2] ... [--output-json <file>] [--output-csv <file>]", file=sys.stderr)
        return 1
    
    # Parse arguments
    cve_ids = []
    output_json = "epss_vulnerabilities.json"
    output_csv = "epss_vulnerabilities.csv"
    
    i = 1
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg == "--output-json" and i + 1 < len(sys.argv):
            output_json = sys.argv[i + 1]
            i += 2
        elif arg == "--output-csv" and i + 1 < len(sys.argv):
            output_csv = sys.argv[i + 1]
            i += 2
        elif arg.startswith("--"):
            i += 1
        else:
            cve_ids.append(arg)
            i += 1
    
    if not cve_ids:
        print("Error: No CVE IDs provided.", file=sys.stderr)
        return 1
    
    print(f"Fetching EPSS data for {len(cve_ids)} CVE(s)...")
    data = fetch_epss_for_cves(cve_ids)
    write_json(output_json, data)
    write_csv(output_csv, data)
    print(f"Total CVEs fetched: {len(data)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
