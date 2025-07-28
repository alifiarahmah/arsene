REASONING_PROMPT_ONLY_CURL='''
Role: Expert web application penetration tester specializing in modern SPA architectures.

Input traffic:
{data}

Task: Generate comprehensive security test cases targeting this endpoint with deep understanding of SPA communication patterns, API structures, and modern web vulnerabilities.

Instructions:
1. Analyze the endpoint for SPA-specific attack vectors including:
   - Authentication/Authorization bypass (JWT, session, CORS)
   - API injection attacks (SQL, NoSQL, LDAP, Command, Template)
   - Business logic flaws and race conditions
   - Input validation bypasses and encoding issues
   - Information disclosure and sensitive data exposure
   - Configuration vulnerabilities and security headers
   - Client-side attacks (XSS, CSRF, Clickjacking)
   - API-specific attacks (GraphQL, REST abuse, rate limiting)
   - File upload/download vulnerabilities
   - Server-side attacks (SSRF, XXE, Deserialization)

2. For each attack vector, create test cases with:
   * attack_vector: Specific vulnerability type (e.g., "sql_injection_post_param", "jwt_algorithm_confusion")
   * test_scenario: 1-2 line explanation of the attack methodology
   * baseline_request: Object with method, url, headers, params, body as seen in input traffic
   * payload_request: Object with method, url, headers, params, body mutated for the attack

   Each request object must have:
     - method: HTTP method (e.g., "POST")
     - url: Full endpoint URL
     - headers: JSON object of HTTP headers
     - params: JSON object of query parameters (if any)
     - body: String or JSON object for request body (if any)

3. Consider SPA-specific elements:
   - Dynamic API endpoints and parameter structures
   - JSON/REST API communication patterns
   - Client-side routing and state management
   - Asynchronous request handling
   - Token-based authentication mechanisms
   - CORS and preflight request behaviors

4. Include both common and advanced attack techniques:
   - Parameter pollution and HTTP verb tampering
   - Content-type confusion and encoding bypasses
   - Time-based and blind injection techniques
   - Authentication token manipulation
   - API versioning and endpoint enumeration

Output:
Return ONLY a JSON array of test case objects following the exact schema. No explanatory text, comments, or formatting outside the JSON structure.

Schema example:
[
  {{
    "attack_vector": "sql_injection_post_param",
    "test_scenario": "Injects SQL payload into POST body parameter to test for SQLi.",
    "baseline_request": {{
      "method": "POST",
      "url": "https://example.com/api/login",
      "headers": {{"Content-Type": "application/json"}},
      "params": {{}},
      "body": "{{\\"username\\": \\"admin\\", \\"password\\": \\"password\\"}}"
    }},
    "payload_request": {{
      "method": "POST",
      "url": "https://example.com/api/login",
      "headers": {{"Content-Type": "application/json"}},
      "params": {{}},
      "body": "{{\\"username\\": \\"admin' OR 1=1 --\\", \\"password\\": \\"password\\"}}"
    }}
  }}
]

IMPORTANT: Output must be valid JSON. All strings must use double quotes. No comments or extra text.
'''

VULN_ANALYSIS_LOOP = """
You are an expert hacker. Evaluate the last attempt and decide NEXT action.

== Context ==
Endpoint ID        : {endpoint_id}
Chain Depth        : {depth}/{max_depth}
Heuristic ScoreVec : {score_vector}          # [Δ, sig, refl, diff, oob]
LLM Confidence Prev: {llm_conf_prev}         # 0–1
Previous Payload   : {prev_payload}
Observed Response  :
  - status         : {status_after}
  - body_len       : {body_len_after}
  - delta_summary  : {delta_desc}            # e.g. "500 error +78 % len"
  - error_strings  : {matched_errors}        # list
  - oob_callback   : {oob_flag}

== Instructions ==
A. Decide whether a vulnerability is CONFIRMED, NEED_MORE_TEST, or STOP:
   * CONFIRMED if response matches success criteria you defined.
   * STOP if 3 consecutive attempts gave no new evidence or depth>max.
B. If NEED_MORE_TEST, output ONE new payload that best escalates or pivots.
C. Output STRICT JSON object:

{
  "decision"       : "CONFIRMED|NEED_MORE_TEST|STOP",
  "vuln_type"      : "<if confirmed>",
  "next_payload"   : "<if need_more_test else ->>",
  "tool"           : "<curl|sqlmap|...>",
  "confidence"     : <0–1>
}

Limit output ≤ 256 tokens. No commentary.

<<Respond>>"""