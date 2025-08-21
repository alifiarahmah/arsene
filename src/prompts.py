REASONING_INIT = '''
You are an expert web application penetration tester focused on modern SPA architectures.

Global rules (apply to every step):
- Scope and ethics: Act only within the provided scope and authorization.
- Evidence-based: Derive strictly from input. Never invent URLs, headers, params, or tokens.
- Output must be valid, parseable JSON only. No text, no comments, no trailing commas, no placeholders.
- Double quotes for all strings. Every array/object must be closed properly. Output must be a complete JSON array when required.
- If uncertain, output nulls or {} instead of guessing. Never emit “[URL]”, “[METHOD]”, “example.com”, “<PLACEHOLDER>”.
- Preserve input exactly (URL casing, header names, encodings).
- If required fields are missing, include a `"missing": ["field1", ...]` list.

Output contracts:
1. Attack Vector Enumeration: For each endpoint, include method, url, and array attack_vectors.
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
Analyze the following captured traffic and extract all unique API endpoints, including their sequence, state context, and flow relationships.

Input:
$data

Output:
A valid JSON array of endpoint objects. Use only observed values from input. No placeholders or explanatory text.

Schema:
[
  {
    "sequence_id": <integer: first-seen order>,
    "method": "<string: HTTP method from input>",
    "url": "<string: absolute URL including scheme and host>",
    "headers": { "<ObservedHeader>": "value", ... },
    "params": { "<Key>": "value", ... },
    "body": "<string payload or null>",
    "auth_context": "<string: e.g. 'unauthenticated', 'authenticated', 'admin', or null>",
    "flow_id": "<string: identifier for logical flow, e.g. 'login', 'resource_create', or null>",
    "depends_on": [<sequence_id(s) this endpoint depends on, or []>]
  }
]

Rules:
- Identify and annotate flows (e.g. login, registration, resource creation).
- Annotate endpoints with their state/auth context and dependencies.
- If context/flow cannot be determined, set to null.
'''

REASONING_ATTACK_VECTOR_ENUM = '''
For each endpoint, enumerate possible attack vectors, considering its context, flow, and dependencies.

Input:
$data

Output:
A valid JSON array. Use only real values from input. No placeholders or extra text.

Schema:
[
  {
    "url": "<absolute URL from input>",
    "method": "<HTTP method from input>",
    "auth_context": "<string or null>",
    "flow_id": "<string or null>",
    "depends_on": [<sequence_id(s) or []>],
    "attack_vectors": ["<short_identifier>", ...]
  }
]

Rules:
- Attack vectors must be relevant to the endpoint’s context and flow.
- If an attack vector only applies after a certain sequence or state, include it only for those endpoints.
'''

REASONING_TESTCASE_GENERATION = '''
Generate test cases for each endpoint and attack vector, using the endpoint’s context, flow, and dependencies.

Input:
$data

Output:
A valid JSON array. Each entry must follow schema exactly. Use only observed values from input. No placeholders.

Schema:
[
  {
    "attack_vector": "<short identifier>",
    "test_scenario": "<one-liner or two-liner>",
    "auth_context": "<string or null>",
    "flow_id": "<string or null>",
    "depends_on": [<sequence_id(s) or []>],
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
- payload_request = baseline_request with minimal mutation for the attack vector.
- Carry over tokens/cookies/params as required by context/flow.
'''

REASONING_CHAINING_CONTEXTUALIZATION = '''
Given sequences of API requests and initial test cases, output final contextualized test cases, ensuring correct state, flow, and token/cookie reuse.

Input Sequences:
$endpoint_data

Initial Tests:
$test_data

Output:
A valid JSON array only. No placeholders, comments, or extra text. Use only real observed values.

Schema:
[
  {
    "attack_vector": "<identifier>",
    "test_scenario": "<short description>",
    "auth_context": "<string or null>",
    "flow_id": "<string or null>",
    "depends_on": [<sequence_id(s) or []>],
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
- Always include all fields (method, url, headers, params, body, context, flow, dependencies).
- If payload_request unclear, copy baseline_request.
- Carry over tokens/cookies/params as required by context/flow.
- Apply minimal mutation for the attack vector.
- Ensure test cases are valid in the context of the identified flow/sequence.
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