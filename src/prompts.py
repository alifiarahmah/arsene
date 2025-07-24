REASONING_PROMPT='''
Role: Senior web penetration tester.

Input traffic:
{data}

Task: Produce context-aware security test cases for this endpoint.

Instructions
1. Identify relevant attack vectors (auth, injection, logic flaws, misconfig, info-leak, etc.).
2. For each vector create one object with:
  • attack_vector : short label
  • test_scenario : 1-2-line description
  • full_payload_with_curl : full curl command (method, URL, headers, body)
  • recommended_tools : array of tools chosen from: ["curl","ffuf","sqlmap","xssstrike","ssrfmap", "linkfinder","trufflehog","inql/graphqlmap","jwt-tool/autorize"]
  • tool_comand_payload : full bash command of recommended_tools mentioned

Output
Return ONLY a JSON array of objects in the exact schema above—no extra text.
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
   • CONFIRMED if response matches success criteria you defined.
   • STOP if 3 consecutive attempts gave no new evidence or depth>max.
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