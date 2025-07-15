REASONING_PROMPT='''
You are an expert penetration tester. Given the following HTTP endpoint details, generate a list of context-aware security test scenarios and template payloads that could be used to assess the security of this endpoint. Focus on realistic attack vectors relevant to the endpoint's method, parameters, and context.

**Request/Response Data:**
{data}

**Instructions:**
1. Identify possible attack vectors based on the endpoint's characteristics (e.g., authentication, injection, logic flaws).
2. For each attack vector, generate at least one test scenario and a template payload suitable for this endpoint.
3. Output a structured list of test scenarios, each with a short description and the corresponding template payload.

**Output format:**
[
  {{
    "attack_vector": "<short description>",
    "test_scenario": "<scenario description>",
    "template_payload": "<payload with placeholders if needed>"
  }},
  ...
]
'''