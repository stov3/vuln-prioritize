#!/usr/bin/env python3
"""
API Connectivity Checker and Configuration Tool

Tests connectivity to all required APIs and allows setting up private API keys.
"""

import sys
import json
import time
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
from typing import Dict, Tuple, Any

from config import ConfigManager, get_config


def test_nvd_api(config: ConfigManager) -> Tuple[bool, str]:
    """
    Test NVD API connectivity.
    
    Returns:
        Tuple of (success, message)
    """
    try:
        # Test with a known CVE
        test_cve = "CVE-2023-44487"
        url = config.get_nvd_url(test_cve)
        
        request = Request(url, headers={"User-Agent": "api-checker/1.0"})
        with urlopen(request, timeout=10) as response:
            if response.status == 200:
                data = json.load(response)
                if data.get("vulnerabilities"):
                    status = "✓ Working"
                    if config.has_nvd_api_key():
                        status += " (with API key)"
                    else:
                        status += " (public, rate limited to 5 req/min)"
                    return True, status
                else:
                    return False, "API responded but no data returned"
            else:
                return False, f"HTTP {response.status}"
    except HTTPError as e:
        if e.code == 401:
            return False, "HTTP 401 Unauthorized (invalid API key?)"
        elif e.code == 429:
            return False, "HTTP 429 Too Many Requests (rate limited)"
        else:
            return False, f"HTTP {e.code}: {e.reason}"
    except URLError as e:
        return False, f"Connection error: {e.reason}"
    except Exception as e:
        return False, str(e)


def test_epss_api(config: ConfigManager) -> Tuple[bool, str]:
    """
    Test EPSS API connectivity.
    
    Returns:
        Tuple of (success, message)
    """
    try:
        url = f"{config.EPSS_URL}?limit=1"
        request = Request(url, headers={"User-Agent": "api-checker/1.0"})
        with urlopen(request, timeout=10) as response:
            if response.status == 200:
                data = json.load(response)
                if data.get("data"):
                    status = "✓ Working"
                    if config.has_epss_api_key():
                        status += " (with API key)"
                    else:
                        status += " (public)"
                    return True, status
                else:
                    return False, "API responded but no data returned"
            else:
                return False, f"HTTP {response.status}"
    except HTTPError as e:
        return False, f"HTTP {e.code}: {e.reason}"
    except URLError as e:
        return False, f"Connection error: {e.reason}"
    except Exception as e:
        return False, str(e)


def test_kev_api(config: ConfigManager) -> Tuple[bool, str]:
    """
    Test CISA KEV API connectivity.
    
    Returns:
        Tuple of (success, message)
    """
    try:
        request = Request(config.KEV_URL, headers={"User-Agent": "api-checker/1.0"})
        with urlopen(request, timeout=10) as response:
            if response.status == 200:
                data = json.load(response)
                if data.get("vulnerabilities"):
                    count = len(data["vulnerabilities"])
                    return True, f"✓ Working ({count} exploited vulnerabilities in database)"
                else:
                    return False, "API responded but no data returned"
            else:
                return False, f"HTTP {response.status}"
    except HTTPError as e:
        return False, f"HTTP {e.code}: {e.reason}"
    except URLError as e:
        return False, f"Connection error: {e.reason}"
    except Exception as e:
        return False, str(e)


def run_diagnostics() -> int:
    """Run API diagnostics and return exit code."""
    config = get_config()
    
    print("\n" + "=" * 70)
    print("Vulnerability Prioritization Tool - API Diagnostics")
    print("=" * 70)
    
    results = {}
    
    # Test each API
    print("\n1. Testing NVD API (CVSS)...")
    success, msg = test_nvd_api(config)
    results["NVD"] = (success, msg)
    print(f"   {msg}")
    time.sleep(0.5)  # Rate limiting
    
    print("\n2. Testing EPSS API (Exploit Prediction)...")
    success, msg = test_epss_api(config)
    results["EPSS"] = (success, msg)
    print(f"   {msg}")
    time.sleep(0.5)
    
    print("\n3. Testing CISA KEV API (Known Exploited)...")
    success, msg = test_kev_api(config)
    results["KEV"] = (success, msg)
    print(f"   {msg}")
    
    # Print summary
    print("\n" + "-" * 70)
    all_working = all(success for success, _ in results.values())
    
    if all_working:
        print("✓ All APIs are accessible!")
    else:
        print("⚠ Some APIs are not accessible:")
        for api, (success, _) in results.items():
            if not success:
                print(f"  - {api}")
    
    # Print API key status
    print("\nAPI Key Status:")
    print(f"  - NVD API Key: {'✓ Configured' if config.has_nvd_api_key() else '✗ Not configured'}")
    print(f"    (Benefit: 5 req/sec instead of 5 req/min)")
    print(f"  - EPSS API Key: {'✓ Configured' if config.has_epss_api_key() else '✗ Not configured'}")
    print(f"    (Public API available without key)")
    
    print("=" * 70)
    
    return 0 if all_working else 1


def main():
    """Main entry point."""
    if len(sys.argv) > 1 and sys.argv[1] == "--setup":
        # Run interactive setup
        config = get_config()
        config.prompt_for_keys()
        print("Running diagnostics after setup...\n")
        time.sleep(1)
        return run_diagnostics()
    else:
        # Just run diagnostics
        return run_diagnostics()


if __name__ == "__main__":
    sys.exit(main())
