#!/usr/bin/env python3
"""
Nuclei Templates Fetcher

Checks if CVEs have Nuclei detection templates.
Nuclei is a fast and customizable vulnerability scanner.
"""

import urllib.request
import urllib.error
import urllib.parse
import json
import time
from rate_limiter import get_rate_limiter, update_rate_limit_from_response, handle_rate_limit_error


def check_nuclei_template(cve_id):
    """
    Check if CVE has Nuclei templates available.
    
    Returns:
        dict: {
            "found": bool,
            "templates": [
                {
                    "name": str,
                    "severity": str,  # "critical", "high", "medium", "low", "info"
                    "type": str,  # "http", "network", "dns", etc.
                    "tags": [str],
                    "url": str,
                    "author": str
                }
            ],
            "error": str or None
        }
    """
    
    limiter = get_rate_limiter("nuclei", has_api_key=False)
    limiter.acquire(f"search_{cve_id}")
    
    try:
        # Query Nuclei templates GitHub repository
        # The official repo is: projectdiscovery/nuclei-templates
        search_url = (
            f"https://api.github.com/search/code"
            f"?q={urllib.parse.quote(cve_id)}+repo:projectdiscovery/nuclei-templates"
            f"&per_page=20"
        )
        
        req = urllib.request.Request(search_url)
        req.add_header('User-Agent', 'vuln-prioritize/1.0')
        
        with urllib.request.urlopen(req, timeout=10) as response:
            # Capture real-time rate limit info from headers
            update_rate_limit_from_response("nuclei", response.headers)
            data = json.loads(response.read().decode('utf-8'))
            
            templates = []
            
            if 'items' in data:
                for result in data['items']:
                    # Get file content to extract template metadata
                    file_path = result.get('path', '')
                    
                    if file_path.endswith('.yaml') or file_path.endswith('.yml'):
                        template = {
                            'name': file_path.split('/')[-1],
                            'severity': extract_severity_from_path(file_path),
                            'type': extract_type_from_path(file_path),
                            'tags': extract_tags_from_path(file_path),
                            'url': result.get('html_url', ''),
                            'author': 'ProjectDiscovery'
                        }
                        templates.append(template)
            
            return {
                'found': len(templates) > 0,
                'templates': templates,
                'error': None
            }
    
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {'found': False, 'templates': [], 'error': None}
        elif e.code == 429:
            handle_rate_limit_error("nuclei", 429)
            return {
                'found': False,
                'templates': [],
                'error': 'GitHub rate limit exceeded'
            }
        elif e.code == 403:
            handle_rate_limit_error("nuclei", 429)
            return {
                'found': False,
                'templates': [],
                'error': 'GitHub rate limit exceeded'
            }
        else:
            return {
                'found': False,
                'templates': [],
                'error': f'API error: {e.code}'
            }
    
    except Exception as e:
        return {
            'found': False,
            'templates': [],
            'error': f'Nuclei search failed: {str(e)}'
        }


def extract_severity_from_path(path):
    """Extract severity from Nuclei template path."""
    # Nuclei templates usually have severity in folder: critical/, high/, medium/, etc.
    path_lower = path.lower()
    
    if 'critical' in path_lower:
        return 'critical'
    elif 'high' in path_lower:
        return 'high'
    elif 'medium' in path_lower:
        return 'medium'
    elif 'low' in path_lower:
        return 'low'
    else:
        return 'info'


def extract_type_from_path(path):
    """Extract template type from path."""
    path_lower = path.lower()
    
    if 'http' in path_lower:
        return 'http'
    elif 'network' in path_lower:
        return 'network'
    elif 'dns' in path_lower:
        return 'dns'
    elif 'file' in path_lower:
        return 'file'
    else:
        return 'generic'


def extract_tags_from_path(path):
    """Extract tags from Nuclei template path."""
    # Folders in nuclei-templates: http/, network/, cves/, technologies/, etc.
    parts = path.split('/')
    tags = []
    
    # Remove 'nuclei-templates' and file name
    relevant_parts = parts[2:-1] if len(parts) > 2 else []
    
    for part in relevant_parts:
        if part and part != 'nuclei-templates':
            tags.append(part)
    
    return tags


def fetch_nuclei_templates(cve_ids):
    """
    Fetch Nuclei template information for multiple CVEs.
    
    Args:
        cve_ids (list): List of CVE IDs
    
    Returns:
        dict: {
            "CVE-XXXX-XXXXX": {
                "found": bool,
                "templates": [...],
                "error": str or None
            },
            ...
        }
    """
    results = {}
    for cve_id in cve_ids:
        results[cve_id] = check_nuclei_template(cve_id)
        time.sleep(0.2)  # Rate limiting delay
    
    return results


if __name__ == "__main__":
    # Test
    test_cves = ["CVE-2026-9999", "CVE-2023-44487"]
    results = fetch_nuclei_templates(test_cves)
    print(json.dumps(results, indent=2))
