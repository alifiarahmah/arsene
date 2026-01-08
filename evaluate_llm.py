#!/usr/bin/env python3
"""
Evaluation script untuk reasoning module output vs ground truth
Usage: python3 evaluate.py <reasoning_json> <ground_truth_csv>
"""

import json
import sys
import re
from pathlib import Path


def load_json(filepath):
    """Load JSON file"""
    with open(filepath, 'r', encoding='utf-8') as f:
        return json.load(f)


def load_csv_manual(filepath):
    """Manual CSV parsing untuk handle quoted fields dengan koma dan format markdown table"""
    data = []
    with open(filepath, 'r', encoding='utf-8') as f:
        lines = f.readlines()

        # Detect format: markdown table atau standard CSV
        is_markdown = False

        if len(lines) > 0 and '|' in lines[0]:
            is_markdown = True
            data_start_idx = 2  # Skip header and separator
        else:
            data_start_idx = 1  # Skip header only

        for line in lines[data_start_idx:]:
            if not line.strip():
                continue

            if is_markdown:
                # Parse markdown table format
                line = line.strip()
                if line.startswith('|'):
                    line = line[1:]
                if line.endswith('|'):
                    line = line[:-1]

                parts = [p.strip() for p in line.split('|')]
            else:
                # Parse standard CSV format
                parts = []
                current = ""
                in_quotes = False

                for char in line:
                    if char == '"':
                        in_quotes = not in_quotes
                    elif char == ',' and not in_quotes:
                        parts.append(current.strip())
                        current = ""
                    else:
                        current += char
                parts.append(current.strip())

            if len(parts) >= 4:
                data.append({
                    'endpoint': parts[0],
                    'vuln_type': parts[1],
                    'payload': parts[2],
                    'description': parts[3]
                })

    return data


def normalize_endpoint(endpoint):
    """Normalize endpoint untuk matching"""
    endpoint = re.sub(r'^https?://[^/]+', '', endpoint)
    endpoint = re.sub(r'\?.*$', '', endpoint)
    endpoint = re.sub(r'/\d+', '/{id}', endpoint)
    endpoint = re.sub(r'\{[^}]+\}', '{id}', endpoint)
    endpoint = re.sub(r':[a-zA-Z_]+', ':{id}', endpoint)
    endpoint = re.sub(r'\s*$$.*?$$', '', endpoint)
    endpoint = re.sub(r'sleep$$\d+$$', 'sleep', endpoint)

    # Handle special cases
    endpoint = re.sub(r'Cookies:.*', 'Cookies', endpoint)
    endpoint = re.sub(r'CORS $$global$$', 'CORS', endpoint)
    endpoint = re.sub(r'Homepage query param.*', 'Homepage', endpoint)
    endpoint = re.sub(r'Common files:.*', 'Common files', endpoint)
    endpoint = re.sub(r'Error response.*', 'Error response', endpoint)
    endpoint = re.sub(r'Static JS assets.*', 'Static JS assets', endpoint)
    endpoint = re.sub(r'Account Login.*', 'Account Login', endpoint)

    if endpoint.endswith('/'):
        endpoint = endpoint[:-1]
    return endpoint.strip()


def extract_method(endpoint_str):
    """Extract HTTP method dari string endpoint ground truth"""
    parts = endpoint_str.split()
    if len(parts) >= 2 and parts[0].upper() in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
        return parts[0].upper(), ' '.join(parts[1:])

    # Check if it's a special case
    if any(x in endpoint_str for x in ['Cookies:', 'CORS', 'Homepage', 'Common files', 'Error response', 'Static JS', 'Account Login']):
        return 'SPECIAL', endpoint_str

    return 'GET', endpoint_str


def categorize_vuln(vuln_type_str):
    """Kategorisasi vulnerability type dari ground truth"""
    vuln_lower = vuln_type_str.lower()

    # XSS variants
    if 'xss' in vuln_lower or 'cross-site scripting' in vuln_lower or \
       'template injection' in vuln_lower or 'dom-based' in vuln_lower or \
       'prototype pollution' in vuln_lower:
        return 'XSS'

    # Injection (non-XSS)
    if ('injection' in vuln_lower or 'sqli' in vuln_lower or 'nosql' in vuln_lower or \
        'xpath' in vuln_lower or 'ssti' in vuln_lower or 'command injection' in vuln_lower or \
        'xxe' in vuln_lower) and 'xss' not in vuln_lower and 'template' not in vuln_lower:
        return 'Injection'

    # Broken Access Control
    if 'broken access control' in vuln_lower or 'bola' in vuln_lower or \
       'mass assignment' in vuln_lower or 'idor' in vuln_lower or \
       'bfla' in vuln_lower or 'path traversal' in vuln_lower or \
       'open redirect' in vuln_lower or 'csrf' in vuln_lower or \
       'unrestricted access' in vuln_lower or 'link manipulation' in vuln_lower:
        return 'Broken Access Control'

    # Security Misconfiguration
    if 'security misconfiguration' in vuln_lower or 'improper assets' in vuln_lower or \
       'excessive data exposure' in vuln_lower or 'sensitive data exposure' in vuln_lower or \
       'sensitive info' in vuln_lower or 'directory listing' in vuln_lower or \
       'information leakage' in vuln_lower or 'hardcoded credentials' in vuln_lower or \
       'base64-encoded' in vuln_lower or 'unrestricted file upload' in vuln_lower or \
       'header injection' in vuln_lower:
        return 'Security Misconfiguration'

    # Authentication/Authorization
    if 'authentication' in vuln_lower or 'broken authentication' in vuln_lower:
        return 'Authentication Failures'

    # SSRF
    if 'ssrf' in vuln_lower or 'server-side request forgery' in vuln_lower:
        return 'SSRF'

    # Insecure Design
    if 'insecure design' in vuln_lower:
        return 'Insecure Design'

    # Vulnerable Components
    if 'vulnerable' in vuln_lower and 'component' in vuln_lower or \
       'outdated' in vuln_lower or 'javascript dependency' in vuln_lower:
        return 'Vulnerable Components'

    # Cryptographic Failures
    if 'cryptographic' in vuln_lower:
        return 'Cryptographic Failures'

    # Software and Data Integrity
    if 'integrity' in vuln_lower:
        return 'Software and Data Integrity Failures'

    # Combined vulnerabilities
    if 'injection + bac' in vuln_lower or 'injection+bac' in vuln_lower:
        return 'Injection+BAC'

    return 'Other'


def extract_vuln_from_tags(tags, payloads=None):
    """Extract vulnerability category dari tags dan payloads"""
    tags_lower = [t.lower() for t in tags]

    # Check tags
    if any(t in tags_lower for t in ['idor', 'bola', 'broken-access-control', 'broken_access_control', 'authz', 'bfla', 'mass_assignment', 'mass-assignment']):
        return 'Broken Access Control'
    if any(t in tags_lower for t in ['sqli', 'sql-injection', 'sql_injection', 'nosql_injection', 'nosql-injection', 'xpath', 'xxe', 'ssti', 'command_injection']):
        return 'Injection'
    if any(t in tags_lower for t in ['xss', 'dom-xss', 'dom_xss', 'reflected', 'template_injection', 'prototype_pollution']):
        return 'XSS'
    if 'ssrf' in tags_lower:
        return 'SSRF'
    if any(t in tags_lower for t in ['sensitive_data_exposure', 'sensitive-data', 'misconfiguration', 'info_disclosure']):
        return 'Security Misconfiguration'
    if any(t in tags_lower for t in ['authentication', 'broken_authentication']):
        return 'Authentication Failures'
    if any(t in tags_lower for t in ['vulnerable_component', 'outdated']):
        return 'Vulnerable Components'

    # Check payloads if available
    if payloads:
        payload_str = str(payloads).lower()
        if any(x in payload_str for x in ['select', 'union', 'sleep(', "' or", "' --", 'xpath', '<?xml']):
            return 'Injection'
        if any(x in payload_str for x in ['<script', '<iframe', 'javascript:', 'onerror=', 'alert(', '{{', '__proto__']):
            return 'XSS'

    return 'Other'


def normalize_ground_truth(gt_data):
    """Normalize ground truth data"""
    normalized = []
    unique_keys = set()

    for gt in gt_data:
        method, endpoint = extract_method(gt['endpoint'])
        norm_endpoint = normalize_endpoint(endpoint)
        vuln_cat = categorize_vuln(gt['vuln_type'])

        key_endpoint = f"{method}|{norm_endpoint}"

        # Deduplicate by endpoint only
        if key_endpoint not in unique_keys:
            unique_keys.add(key_endpoint)
            normalized.append({
                'method': method,
                'endpoint': norm_endpoint,
                'vuln_category': vuln_cat,
                'key_endpoint': key_endpoint
            })

    return normalized


def normalize_predictions(test_cases):
    """Normalize predicted test cases"""
    normalized = []
    unique_keys = set()

    for tc in test_cases:
        endpoint = normalize_endpoint(tc.get('endpoint', ''))
        method = tc.get('method', '').upper()

        key_endpoint = f"{method}|{endpoint}"

        # Deduplicate by endpoint only
        if key_endpoint not in unique_keys:
            unique_keys.add(key_endpoint)
            normalized.append({
                'method': method,
                'endpoint': endpoint,
                'key_endpoint': key_endpoint
            })

    return normalized


def calculate_metrics(tp, fp, fn):
    """Calculate precision, recall, F1"""
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    return precision, recall, f1


def evaluate_llm(reasoning_json_path: str, ground_truth_csv_path: str) -> dict:
    """
    Evaluate LLM reasoning output against ground-truth CSV.

    Args:
        reasoning_json_path: Path to reasoning JSON file
        ground_truth_csv_path: Path to ground-truth CSV file

    Returns:
        Dictionary containing:
        - tp: True positives
        - fp: False positives
        - fn: False negatives
        - precision: Precision score
        - recall: Recall score
        - f1: F1 score
        - total_gt: Total number of ground truth rows
        - total_llm_endpoints: Total number of LLM endpoints found
    """
    # Load data
    reasoning_result = load_json(reasoning_json_path)
    gt_data = load_csv_manual(ground_truth_csv_path)

    # Extract test cases
    test_cases = reasoning_result.get('test_cases', reasoning_result if isinstance(reasoning_result, list) else [])

    # Normalize
    gt_normalized = normalize_ground_truth(gt_data)
    pred_normalized = normalize_predictions(test_cases)

    # Calculate metrics (method + endpoint matching)
    gt_keys = set([gt['key_endpoint'] for gt in gt_normalized])
    pred_keys = set([pred['key_endpoint'] for pred in pred_normalized])

    tp_keys = gt_keys.intersection(pred_keys)
    fp_keys = pred_keys - gt_keys
    fn_keys = gt_keys - pred_keys

    tp = len(tp_keys)
    fp = len(fp_keys)
    fn = len(fn_keys)

    precision, recall, f1 = calculate_metrics(tp, fp, fn)

    result = {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "total_gt": int(len(gt_data)),
        "total_llm_endpoints": int(len(test_cases)),
    }

    return result


def main():
    if len(sys.argv) != 3:
        print("Usage: python3 evaluate.py <reasoning_json> <ground_truth_csv>")
        print("Example: python3 evaluate.py reasoning_result/20251203135957_juice_shop_gpt-5-mini.json csv_vuln_list/juice_shop.csv")
        sys.exit(1)

    reasoning_json = sys.argv[1]
    ground_truth_csv = sys.argv[2]

    # Construct full paths
    reasoning_json_path = 'reasoning_result/' + reasoning_json
    ground_truth_csv_path = 'csv_vuln_list/' + ground_truth_csv

    # Validate files exist
    if not Path(reasoning_json_path).exists():
        print(f"Error: File not found: {reasoning_json_path}")
        sys.exit(1)

    if not Path(ground_truth_csv_path).exists():
        print(f"Error: File not found: {ground_truth_csv_path}")
        sys.exit(1)

    result = evaluate_llm(reasoning_json_path, ground_truth_csv_path)

    # Print output
    print(f"TP: {result['tp']}")
    print(f"FP: {result['fp']}")
    print(f"FN: {result['fn']}")
    print(f"Precision: {result['precision']:.4f}")
    print(f"Recall:    {result['recall']:.4f}")
    print(f"F1-score:  {result['f1']:.4f}")
    print()
    print(f"Total GT rows:      {result['total_gt']}")
    print(f"Total reasoning result endpoints: {result['total_llm_endpoints']}")


if __name__ == "__main__":
    main()