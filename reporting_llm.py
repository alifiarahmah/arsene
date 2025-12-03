import json
import pandas as pd
import re

# Load data
with open('20251111134709_juice_shop_gpt-5-mini.json', 'r') as f:
    reasoning_result = json.load(f)

ground_truth_data = []
with open('juice_shop.csv', 'r', encoding='utf-8') as f:
    lines = f.readlines()

    for line in lines[1:]:
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
            ground_truth_data.append({
                'endpoint': parts[0],
                'vuln_type': parts[1],
                'payload': parts[2],
                'description': parts[3]
            })

test_cases = reasoning_result.get('test_cases', reasoning_result if isinstance(reasoning_result, list) else [])

# Helper functions
def normalize_endpoint(endpoint):
    endpoint = re.sub(r'^https?://[^/]+', '', endpoint)
    endpoint = re.sub(r'\?.*$', '', endpoint)
    endpoint = re.sub(r'/\d+', '/{id}', endpoint)
    endpoint = re.sub(r'\{basketId\}', '{id}', endpoint)
    endpoint = re.sub(r'\{.*?\}', '{id}', endpoint)
    endpoint = re.sub(r'\s*\(.*?\)', '', endpoint)  # Remove parentheses
    return endpoint.strip()

def extract_method(endpoint_str):
    parts = endpoint_str.split()
    if len(parts) >= 2 and parts[0].upper() in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
        return parts[0].upper(), ' '.join(parts[1:])
    return 'GET', endpoint_str

def categorize_vuln(vuln_type_str):
    vuln_lower = vuln_type_str.lower()

    if 'injection' in vuln_lower and 'bac' not in vuln_lower and '+' not in vuln_lower:
        return 'Injection'
    elif 'broken access control' in vuln_lower or 'bola' in vuln_lower or 'mass assignment' in vuln_lower:
        return 'Broken Access Control'
    elif 'xss' in vuln_lower:
        return 'XSS'
    elif 'security misconfiguration' in vuln_lower or 'improper assets' in vuln_lower or 'excessive data exposure' in vuln_lower or 'sensitive data exposure' in vuln_lower:
        return 'Security Misconfiguration'
    elif 'insecure design' in vuln_lower:
        return 'Insecure Design'
    elif 'injection + bac' in vuln_lower or 'injection+bac' in vuln_lower:
        return 'Injection+BAC'
    else:
        return 'Other'

def extract_vuln_from_tags(tags):
    tags_lower = [t.lower() for t in tags]

    if 'idor' in tags_lower or 'bola' in tags_lower or 'broken-access-control' in tags_lower:
        return 'Broken Access Control'
    if 'sqli' in tags_lower or 'sql-injection' in tags_lower or 'sql_injection' in tags_lower or 'nosql_injection' in tags_lower:
        return 'Injection'
    if 'xss' in tags_lower or 'dom-xss' in tags_lower:
        return 'XSS'
    if 'ssrf' in tags_lower:
        return 'SSRF'
    if 'sensitive_data_exposure' in tags_lower:
        return 'Security Misconfiguration'

    return 'Other'

# Normalisasi ground truth
gt_normalized = []
for gt in ground_truth_data:
    method, endpoint = extract_method(gt['endpoint'])
    norm_endpoint = normalize_endpoint(endpoint)
    vuln_cat = categorize_vuln(gt['vuln_type'])

    gt_normalized.append({
        'method': method,
        'endpoint': norm_endpoint,
        'vuln_category': vuln_cat,
        'original': gt['endpoint'],
        'key': f"{method}|{norm_endpoint}|{vuln_cat}"
    })

# Normalisasi predicted
pred_normalized = []
for tc in test_cases:
    endpoint = normalize_endpoint(tc.get('endpoint', ''))
    method = tc.get('method', '').upper()
    vuln_cat = extract_vuln_from_tags(tc.get('tags', []))

    pred_normalized.append({
        'method': method,
        'endpoint': endpoint,
        'vuln_category': vuln_cat,
        'original_endpoint': tc.get('endpoint', ''),
        'tags': tc.get('tags', []),
        'key': f"{method}|{endpoint}|{vuln_cat}"
    })

# Create sets untuk matching
gt_keys = set([gt['key'] for gt in gt_normalized])
pred_keys = set([pred['key'] for pred in pred_normalized])

# Hitung TP, FP, FN
tp_keys = gt_keys.intersection(pred_keys)
fp_keys = pred_keys - gt_keys
fn_keys = gt_keys - pred_keys

TP = len(tp_keys)
FP = len(fp_keys)
FN = len(fn_keys)

# Hitung metrik
precision = TP / (TP + FP) if (TP + FP) > 0 else 0
recall = TP / (TP + FN) if (TP + FN) > 0 else 0
f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

print("="*80)
print("HASIL EVALUASI")
print("="*80)
print(f"\nTotal Ground Truth: {len(gt_normalized)}")
print(f"Total Predicted: {len(pred_normalized)}")
print(f"\nTrue Positives (TP): {TP}")
print(f"False Positives (FP): {FP}")
print(f"False Negatives (FN): {FN}")
print(f"\n{'='*80}")
print(f"Precision: {precision:.4f} ({precision*100:.2f}%)")
print(f"Recall: {recall:.4f} ({recall*100:.2f}%)")
print(f"F1-Score: {f1:.4f} ({f1*100:.2f}%)")
print(f"{'='*80}\n")

# Detail TP
print("\n=== TRUE POSITIVES (TP) ===")
for key in sorted(tp_keys):
    parts = key.split('|')
    print(f"✓ {parts[0]} {parts[1]} - {parts[2]}")

# Detail FP
print("\n=== FALSE POSITIVES (FP) ===")
for key in sorted(fp_keys):
    parts = key.split('|')
    print(f"✗ {parts[0]} {parts[1]} - {parts[2]}")
    # Find original
    for pred in pred_normalized:
        if pred['key'] == key:
            print(f"  Tags: {pred['tags']}")
            break

# Detail FN
print("\n=== FALSE NEGATIVES (FN) ===")
for key in sorted(fn_keys):
    parts = key.split('|')
    print(f"✗ {parts[0]} {parts[1]} - {parts[2]}")
    # Find original
    for gt in gt_normalized:
        if gt['key'] == key:
            print(f"  Original: {gt['original']}")
            break

print("\n" + "="*80)