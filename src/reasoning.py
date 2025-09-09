
from pydantic import BaseModel
from reasoning_prompt import STEP1_SYSTEM_PROMPT, STEP2_CONTEXT_SYSTEM_PROMPT, STEP2_CONTEXT_USER_PROMPT, STEP3_VECTORS_SYSTEM_PROMPT, STEP3_VECTORS_USER_PROMPT, STEP4_VULNS_SYSTEM_PROMPT, STEP4_VULNS_USER_PROMPT, STEP5_TESTCASES_SYSTEM_PROMPT, STEP5_TESTCASES_USER_PROMPT, STEP6_CHAIN_SYSTEM_PROMPT, STEP6_CHAIN_USER_PROMPT
from schemas import AttackVectorsContext, TestCasesContext, TrafficAnalysisContext, VulnHypothesesContext
from utils import call_llm, fill
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
        context_json = call_llm(
            messages=ta_messages, response_format=TrafficAnalysisContext)
        return context_json

    def av_enum(self, context_json):
        av_messages = self.init_messages
        av_messages.append({"role": "system", "content": STEP3_VECTORS_SYSTEM_PROMPT})
        av_messages.append({"role": "user", "content": fill(
            STEP3_VECTORS_USER_PROMPT,
            CONTEXT_JSON=context_json.model_dump_json()
        )})
        attack_vectors_json = call_llm(
            messages=av_messages,
            response_format=AttackVectorsContext)
        return attack_vectors_json

    def vuln_hypothesis(self, attack_vectors_json):
        vh_messages = self.init_messages
        vh_messages.append({"role": "system", "content": STEP4_VULNS_SYSTEM_PROMPT})
        vh_messages.append({"role": "user", "content": fill(
            STEP4_VULNS_USER_PROMPT,
            ATTACK_VECTORS_JSON=attack_vectors_json.model_dump_json()
        )})
        vuln_hypotheses_json = call_llm(
            messages=vh_messages,
            response_format=VulnHypothesesContext
            )
        return vuln_hypotheses_json

    def tc_gen(self, context_json, vuln_hypotheses_json):
        tc_gen_messages = self.init_messages
        tc_gen_messages.append({"role": "system", "content": STEP5_TESTCASES_SYSTEM_PROMPT})
        tc_gen_messages.append({"role": "user", "content": fill(
            STEP5_TESTCASES_USER_PROMPT,
            CONTEXT_JSON=context_json.model_dump_json(),
            VULN_HYPOTHESES_JSON=vuln_hypotheses_json.model_dump_json()
        )})
        testcases_json = call_llm(
            messages=tc_gen_messages,
            response_format=TestCasesContext
            )
        return testcases_json

    def chain_tc_context(self, context_json, testcases_json):
        final_plan_messages = self.init_messages
        final_plan_messages.append({"role": "system", "content": STEP6_CHAIN_SYSTEM_PROMPT})
        final_plan_messages.append({"role": "user", "content": fill(
            STEP6_CHAIN_USER_PROMPT,
            CONTEXT_JSON=context_json.model_dump_json(),
            TESTCASES_JSON=testcases_json.model_dump_json()
        )})
        final_plan_json = call_llm(
            messages=final_plan_messages, response_format=TestCasesContext)
        return final_plan_json

    def do_reasoning_chain(self, filename):
        print("STEP 1: TA")
        ta_result = self.traffic_analysis('parsed_hars/' + filename + '.json')
        self.export_result(result=ta_result, output_path='reasoning_result/traffic_analysis_result/' + filename + '.json')
        print(ta_result)

        print("STEP 2: AV")
        av_result = self.av_enum(ta_result)
        self.export_result(result=av_result, output_path='reasoning_result/av_enum_result/' + filename + '.json')
        print(av_result)

        print("STEP 3: VH")
        vh_result = self.vuln_hypothesis(ta_result)
        self.export_result(result=vh_result, output_path='reasoning_result/vuln_hypotheses_result/' + filename + '.json')
        print(vh_result)

        print("STEP 4: TC")
        tc_gen_result = self.tc_gen(ta_result, vh_result)
        self.export_result(result=tc_gen_result, output_path='reasoning_result/tc_gen_result/' + filename + '.json')
        print(tc_gen_result)

        print("STEP 5: FINAL")
        final_plan_json = self.chain_tc_context(ta_result, tc_gen_result)
        self.export_result(result=final_plan_json, output_path='reasoning_result/' + filename + '.json')
        print(final_plan_json)

    def export_result(self, result, output_path):
        with open(output_path, 'w', encoding='utf-8') as f:
            if isinstance(result, BaseModel):
                f.write(result.model_dump_json(indent=2, exclude_none=True))

if __name__ == "__main__":
    RM = ReasoningModule()
    filename = "brokencrystals"
    try:
        result = RM.do_reasoning_chain(filename)
        print(result)
    except Exception as e:
        print(f"Pipeline failed: {e}")