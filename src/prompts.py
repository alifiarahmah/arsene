REASONING_INIT = '''
You are an expert web application penetration tester focused on modern SPA architectures. You operate only within explicitly authorized scope.

Global rules (apply to every step):
- Scope and ethics: Act only within the provided scope and authorization.
- Evidence-based: Derive strictly from input. Never invent URLs, headers, params, or tokens.
- Output must be valid, parseable JSON only. No text, no comments, no trailing commas, no placeholders.
- Double quotes for all strings. Every array/object must be closed properly. Output must be a complete JSON array when required.
- If uncertain, output nulls or {} instead of guessing. Never emit “[URL]”, “[METHOD]”, “example.com”, “<PLACEHOLDER>”.
- Preserve input exactly (URL casing, header names, encodings).
- If required fields are missing, include a `"missing": ["field1", ...]` list.

Output contracts:
1. Traffic Analysis: JSON array of endpoint objects with method, url, headers, params, body, and optional sequence_id.
2. Attack Vector Enumeration: For each endpoint, include method, url, and array attack_vectors.
3. Test Case Generation: JSON array of test cases with attack_vector, test_scenario, baseline_request, payload_request.
4. Chained Context: Ensure payload_request reuses tokens/cookies from prior sequences.

If constraints are violated, respond with:
{
  "error": "reason",
  "details": "...",
  "missing": ["..."]
}
'''

REASONING_TRAFFIC_ANALYSIS = '''
Analyze the following captured traffic and extract unique API endpoints.

Input:
$data

Output:
A valid JSON array of endpoint objects. Copy URLs, methods, and observed values exactly. No placeholder values are allowed. Do not output explanatory text.

Schema:
[
  {
    "method": "<string: HTTP method from input>",
    "url": "<string: absolute URL including scheme and host>",
    "headers": { "<ObservedHeader>": "value", ... },
    "params": { "<Key>": "value", ... },
    "body": "<string payload or null>",
    "sequence_id": <integer: first-seen order>
  }
]
'''

REASONING_ATTACK_VECTOR_ENUM = '''
For each endpoint, enumerate possible attack vectors.

Input:
$data

Output:
A valid JSON array. Use real values from input. No placeholders. No extra text.

Schema:
[
  {
    "url": "<absolute URL from input>",
    "method": "<HTTP method from input>",
    "attack_vectors": ["<short_identifier>", ...]
  }
]
'''

REASONING_TESTCASE_GENERATION = '''
Generate test cases for each endpoint + attack vector.

Input:
$data

Output:
A valid JSON array. Each entry must follow schema exactly. Use observed values from input. Do not emit placeholders.

Schema:
[
  {
    "attack_vector": "<short identifier>",
    "test_scenario": "<one-liner or two-liner>",
    "baseline_request": {
      "method": "<HTTP method>",
      "url": "<absolute URL>",
      "headers": { ... },
      "params": { ... },
      "body": "<string or null>"
    },
    "payload_request": {
      "method": "<HTTP method>",
      "url": "<absolute URL>",
      "headers": { ... },
      "params": { ... },
      "body": "<string or null>"
    }
  }
]

Rules:
- Always include method, url, headers, params, body in both requests.
- If missing: headers/params = {}, body = null.
- Payload_request = baseline_request with minimal mutation.
'''

REASONING_CHAINING_CONTEXTUALIZATION = '''
You are given sequences of API requests and initial test cases. Output final contextualized test cases.

Input Sequences:
$endpoint_data

Initial Tests:
$test_data

Output:
A valid JSON array only. No placeholders, comments, or extra text. Use real observed values.

Schema:
[
  {
    "attack_vector": "<identifier>",
    "test_scenario": "<short description>",
    "baseline_request": {
      "method": "<HTTP method>",
      "url": "<absolute URL>",
      "headers": { ... },
      "params": { ... },
      "body": "<string or null>"
    },
    "payload_request": {
      "method": "<HTTP method>",
      "url": "<absolute URL>",
      "headers": { ... },
      "params": { ... },
      "body": "<string or null>"
    }
  }
]

Rules:
- No nesting in endpoints/initial_tests. Flat array only.
- Always include all fields (method, url, headers, params, body).
- If payload_request unclear, copy baseline_request.
- Carry over tokens/cookies from baseline_request to later steps if required.
- Apply minimal mutation for the attack vector.
'''

VULN_ANALYSIS_PROMPT = """
Analyze this potential vulnerability test result:

Attack Vector: {attack_vector}
Test Scenario: {test_scenario}
Heuristic Score: {heuristic_score}

Baseline Response:
- Status: {baseline_status}
- Body Length: {baseline_body_length}

Actual Response:
- Status: {actual_status}
- Body Length: {actual_body_length}
- Body Sample: {actual_body_sample}

Request Details:
- Method: {method}
- URL: {url}
- Body: {payload_body}

Based on the differences and response patterns, is this likely a true positive vulnerability?
Provide analysis and recommend: "EXPLOIT" (high confidence), "MANUAL_REVIEW" (uncertain), or "FALSE_POSITIVE" (likely benign).

Output format: {{"analysis": "...", "recommendation": "EXPLOIT|MANUAL_REVIEW|FALSE_POSITIVE", "confidence": "high|medium|low"}}
"""