
from reasoning_prompt import STEP1_SYSTEM_PROMPT, STEP2_CONTEXT_SYSTEM_PROMPT, STEP2_CONTEXT_USER_PROMPT, STEP3_VECTORS_SYSTEM_PROMPT, STEP3_VECTORS_USER_PROMPT
from utils import call_llm, fill
from string import Template
import json

class ReasoningModule():
    def __init__(self):
        self.init_messages = [
            {"role": "system", "content": STEP1_SYSTEM_PROMPT}
        ]
        call_llm(messages=self.init_messages)

    def traffic_analysis(self, json_file_path):
        with open(json_file_path, 'r', encoding='utf-8') as f:
            parsed_har_json = json.load(f)
        ta_messages = self.init_messages
        ta_messages.append({"role": "system", "content": STEP2_CONTEXT_SYSTEM_PROMPT})
        ta_messages.append({"role": "user", "content": fill(
            STEP2_CONTEXT_USER_PROMPT,
            PARSED_HAR_SUMMARY_JSON=parsed_har_json
        )})
        context_json = call_llm(ta_messages)
        return context_json

    def av_enum(self, context_json):
        av_messages = self.init_messages
        av_messages.append({"role": "system", "content": STEP3_VECTORS_SYSTEM_PROMPT})
        av_messages.append({"role": "user", "content": fill(
            STEP3_VECTORS_USER_PROMPT,
            CONTEXT_JSON=context_json
        )})
        attack_vectors_json = call_llm(av_messages)
        return attack_vectors_json

    def vuln_hypothesis(self):
        pass

    def tc_gen(self):
        pass

    def chain_tc_context(self):
        pass

    def do_reasoning_chain(self):
        pass

    def export_result(self, result, output_path):
        with open(output_path, 'w', encoding='utf-8') as f:
            if isinstance(result, str):
                # If it's a string, try to parse it first
                try:
                    parsed_result = json.loads(result)
                    json.dump(parsed_result, f, indent=2, ensure_ascii=False)
                except json.JSONDecodeError:
                    # If parsing fails, just write the raw string
                    f.write(result)
            else:
                # If it's already a Python object, dump normally
                json.dump(result, f, indent=2, ensure_ascii=False)

if __name__ == "__main__":
    RM = ReasoningModule()
    filename = "juice_shop"
    try:
        ta_result = RM.traffic_analysis('parsed_hars/' + filename + '.json')
        RM.export_result(result=ta_result, output_path='reasoning_result/traffic_analysis_result/' + filename + '.json')

        av_result = RM.av_enum(ta_result)
        RM.export_result(result=av_result, output_path='reasoning_result/av_enum_result/' + filename + '.json')
    except Exception as e:
        print(f"Pipeline failed: {e}")