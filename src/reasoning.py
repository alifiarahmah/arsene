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
        prompt = Template(REASONING_TRAFFIC_ANALYSIS).safe_substitute(
            data=json.dumps(endpoint_data, indent=2)
        )

        traffic_analysis_res = call_llm(prompt)
        # print("traffic analysis:", traffic_analysis_res)
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
            # if result is already a string that should be JSON, parse it first
            if isinstance(result, str):
                parsed_result = json.loads(result)
            else:
                parsed_result = result

            # write properly formatted JSON
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(parsed_result, f, indent=2, ensure_ascii=False)

        except json.JSONDecodeError as e:
            print(f"Error: LLM output is not valid JSON: {e}")
            # fallback, save raw output for debugging
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

            # Step 2: Attack Vector Enumeration
            vectors = self.attack_vector_enum(endpoints)
            print("Step 2 (Attack Vector Enum) completed")

            # Step 3: Test Case Generation
            test_cases = self.tc_gen(vectors)
            print("Step 3 (Test Case Generation) completed")

            # Step 4: Contextualization
            final_tests = self.contextualization(json_file_path, test_cases)
            print("Step 4 (Contextualization) completed")

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