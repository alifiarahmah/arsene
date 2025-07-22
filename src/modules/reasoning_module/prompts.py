REASONING_PROMPT='''
You are an expert penetration tester. Given the following HTTP endpoint details, generate a list of context-aware security test scenarios and template payloads that could be used to assess the security of this endpoint. Focus on realistic attack vectors relevant to the endpoint's method, parameters, and context.

**Request/Response Data:**
{data}

**Instructions:**
1. Identify possible attack vectors based on the endpoint's characteristics (e.g., authentication, injection, logic flaws).
2. For each attack vector, generate at least one test scenario and a template payload suitable for this endpoint.
3. Output a structured list of test scenarios with given format, each with a short description and the corresponding template payload, also what tool should i use of this list:
-	curl
- ffuf
- sqlmap
- xssstrike
- ssrfmap
- linkfinder
- trufflehog
- inql/graphqlmap
- jwt-tool/autorize
4. Maximum 120 tokens total

**Output format:**
[
  {{
    "attack_vector": "<short description>",
    "test_scenario": "<scenario description>",
    "template_payload": "<payload with placeholders if needed>"
    "full_payload": "<full payload, from full_url>",
    "full_payload_with_curl": "<curl syntax of full_payload, also the request type (GET/POST/etc.)>",
    "recommended_tools": "<array of recommended tools tools from mentioned tools>"
  }},
  ...
]
'''