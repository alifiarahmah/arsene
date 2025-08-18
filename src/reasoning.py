from prompts import REASONING_INIT, REASONING_TRAFFIC_ANALYSIS, REASONING_ATTACK_VECTOR_ENUM, REASONING_TESTCASE_GENERATION, REASONING_CHAINING_CONTEXTUALIZATION
from utils import call_llm, init_conversation
from string import Template
import json

class ReasoningModule():
    def __init__(self):
        # init conversation with system prompt
        init_conversation(REASONING_INIT)

    def traffic_analysis(self, json_file_path):
        with open(json_file_path, 'r', encoding='utf-8') as f:
            endpoint_data = json.load(f)

        # Extract only the data array if wrapped
        if isinstance(endpoint_data, dict) and 'data' in endpoint_data:
            endpoint_data = endpoint_data['data']

        # Clean and simplify data before sending to LLM
        cleaned = []
        for ep in endpoint_data:
            cleaned.append({
                "url": ep["url"],
                "method": ep["method"],
                "headers": ep.get("headers", {}),
                "params": ep.get("query_params", {}),
                "body": ep.get("request_body"),
                "sequence_id": len(cleaned) + 1  # Add sequence order
            })

        prompt = Template(REASONING_TRAFFIC_ANALYSIS).safe_substitute(
            data=json.dumps(cleaned, indent=2)
        )

        traffic_analysis_res = call_llm(prompt)
        print("DEBUG - Traffic analysis raw response:", traffic_analysis_res[:200])
        return traffic_analysis_res

    def attack_vector_enum(self, traffic_analysis_res):
        if isinstance(traffic_analysis_res, str):
            data_str = traffic_analysis_res
        else:
            data_str = json.dumps(traffic_analysis_res, indent=2)

        prompt = Template(REASONING_ATTACK_VECTOR_ENUM).safe_substitute(data=data_str)
        attack_vector_enum_res = call_llm(prompt)
        # print("attack_vector_enum:", attack_vector_enum_res)
        return attack_vector_enum_res

    def tc_gen(self, attack_vector_enum_res):
        if isinstance(attack_vector_enum_res, str):
            data_str = attack_vector_enum_res
        else:
            data_str = json.dumps(attack_vector_enum_res, indent=2)

        prompt = Template(REASONING_TESTCASE_GENERATION).safe_substitute(data=data_str)
        tc_gen_res = call_llm(prompt)
        # print("tc_gen_res:", tc_gen_res)
        return tc_gen_res

    def contextualization(self, json_file_path, tc_gen_res):
        with open(json_file_path, 'r', encoding='utf-8') as f:
            endpoint_data = json.load(f)

        endpoint_str = json.dumps(endpoint_data, indent=2)
        if isinstance(tc_gen_res, str):
            test_str = tc_gen_res
        else:
            test_str = json.dumps(tc_gen_res, indent=2)

        prompt = Template(REASONING_CHAINING_CONTEXTUALIZATION).safe_substitute(
            endpoint_data=endpoint_str,
            test_data=test_str
        )
        contextualization_response = call_llm(prompt)
        # print("contextualization:", contextualization_response)
        return contextualization_response

    def export_result(self, result, output_path: str):
        try:
            if isinstance(result, str):
                parsed_result = json.loads(result)
            else:
                parsed_result = result

            test_cases = []

            if isinstance(parsed_result, dict):
                # Case 1: contextualizer output: { "tests": [ ... ] }
                if "tests" in parsed_result:
                    test_cases = parsed_result["tests"]

                elif "vulnerabilities" in parsed_result:
                    test_cases = parsed_result["vulnerabilities"]

                # Case 2: initial_tests
                elif "initial_tests" in parsed_result:
                    for it in parsed_result["initial_tests"]:
                        for av in it.get("attack_vectors", []):
                            if "attack_vector" not in av and "name" in av:
                                av["attack_vector"] = av["name"]
                            if "payload_request" not in av and "baseline_request" in av:
                                av["payload_request"] = dict(av["baseline_request"])
                            test_cases.append(av)

                # Case 3: endpoints nesting
                elif "endpoints" in parsed_result:
                    for ep in parsed_result["endpoints"]:
                        for av in ep.get("attack_vectors", []):
                            if "attack_vector" not in av and "name" in av:
                                av["attack_vector"] = av["name"]
                            if "payload_request" not in av and "baseline_request" in av:
                                av["payload_request"] = dict(av["baseline_request"])
                            test_cases.append(av)

                # Case 4: single test case dict
                else:
                    expected = {"attack_vector", "baseline_request", "payload_request"}
                    if expected.issubset(parsed_result.keys()):
                        test_cases.append(parsed_result)

            elif isinstance(parsed_result, list):
                test_cases = parsed_result

            else:
                raise ValueError("Unsupported reasoning_result format")

            # Fix placeholder URLs before saving
            for tc in test_cases:
                for req_type in ["baseline_request", "payload_request"]:
                    url = tc.get(req_type, {}).get("url")
                    if url and any(ph in url for ph in ["[URL]", "<", "example.com", "[METHOD]"]):
                        # Try to find a real URL from the test case or use first available
                        real_url = None
                        for req_check in ["baseline_request", "payload_request"]:
                            check_url = tc.get(req_check, {}).get("url")
                            if check_url and not any(ph in check_url for ph in ["[URL]", "<", "example.com", "[METHOD]"]):
                                real_url = check_url
                                break
                        if real_url:
                            tc[req_type]["url"] = real_url
                        else:
                            print(f"Warning: Could not fix placeholder URL in {tc.get('attack_vector', 'unknown')}")

            # overwrite and save flat list of test_cases
            parsed_result = test_cases

            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(parsed_result, f, indent=2, ensure_ascii=False)

        except json.JSONDecodeError as e:
            print(f"Error: LLM output is not valid JSON: {e}")
            with open(f"{output_path}.raw", 'w', encoding='utf-8') as f:
                f.write(result)
            raise
        except Exception as e:
            print(f"Error exporting result: {e}")
            raise

    def reasoning_chain(self, json_file_path):
        """Execute full reasoning pipeline with context"""
        try:
            # Step 1: Traffic Analysis
            endpoints = self.traffic_analysis(json_file_path)
            print("Step 1 (Traffic Analysis) completed")
            print(f"Traffic analysis result: {endpoints[:500]}...")  # first 500 chars

            # Step 2: Attack Vector Enumeration
            vectors = self.attack_vector_enum(endpoints)
            print("Step 2 (Attack Vector Enum) completed")
            print(f"Attack vectors result: {vectors[:500]}...")

            # Step 3: Test Case Generation
            test_cases = self.tc_gen(vectors)
            print("Step 3 (Test Case Generation) completed")
            print(f"Test cases result: {test_cases[:500]}...")

            # Step 4: Contextualization
            final_tests = self.contextualization(json_file_path, test_cases)
            print("Step 4 (Contextualization) completed")
            print(f"Final tests result: {final_tests[:500]}...")

            return final_tests

        except Exception as e:
            print(f"Error in reasoning chain: {e}")
            raise

if __name__ == "__main__":
    RM = ReasoningModule()
    filename = input('Enter filename (parsed_hars/<name>.json): ')
    try:
        # Execute full pipeline
        result = RM.reasoning_chain('parsed_hars/' + filename + '.json')
        print("Pipeline completed successfully")
        RM.export_result(result, f'reasoning_result/{filename}.json')
        print(f'Result saved as reasoning_result/{filename}.json')
    except Exception as e:
        print(f"Pipeline failed: {e}")