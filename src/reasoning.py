from pydantic import BaseModel
from reasoning_prompt import (
    STEP1_INIT_SYSTEM_PROMPT,
    STEP2_CONTEXT_SYSTEM_PROMPT, STEP2_CONTEXT_USER_PROMPT,
    STEPS1_STATIC_INIT_SYSTEM_PROMPT, STEPS1_STATIC_INIT_USER_PROMPT,
    STEPS2_STATIC_EXTRACT_SYSTEM_PROMPT, STEPS2_STATIC_EXTRACT_USER_PROMPT,
    STEPS3_STATIC_MAPPING_SYSTEM_PROMPT, STEPS3_STATIC_MAPPING_USER_PROMPT,
    STEPI1_UNIFIED_INVENTORY_SYSTEM_PROMPT, STEPI1_UNIFIED_INVENTORY_USER_PROMPT,
    STEPI2_SINK_ATTACHMENT_SYSTEM_PROMPT, STEPI2_SINK_ATTACHMENT_USER_PROMPT,
    STEP3_VECTORS_SYSTEM_PROMPT, STEP3_VECTORS_USER_PROMPT,
    STEP4_VULNS_SYSTEM_PROMPT, STEP4_VULNS_USER_PROMPT,
    STEP5_TESTCASES_SYSTEM_PROMPT, STEP5_TESTCASES_USER_PROMPT,
    STEP6_CHAIN_SYSTEM_PROMPT, STEP6_CHAIN_USER_PROMPT
)
from schemas import AttackVectorsContext, TestCasesContext, TrafficAnalysisContext, VulnHypothesesContext
from schemas_static import StaticInitOutput, StaticExtractionOutput, StaticMappingOutput, UnifiedInventoryOutput, SinkAttachmentOutput
from utils import call_llm, fill
import json
import argparse
import datetime
import os
from config import config
from typing import Union

class ReasoningModule():
    def __init__(self):
        self.init_messages = [
            {"role": "system", "content": STEP1_INIT_SYSTEM_PROMPT}
        ]
        call_llm(messages=self.init_messages)

    # ===== TRAFFIC ANALYSIS ROUTE =====
    def traffic_analysis(self, json_file_path: str) -> TrafficAnalysisContext:
        """STEP 2: Parse HAR traffic into structured context"""
        with open(json_file_path, 'r', encoding='utf-8') as f:
            parsed_har_json = json.load(f)
        ta_messages = self.init_messages.copy()
        ta_messages.append({"role": "system", "content": STEP2_CONTEXT_SYSTEM_PROMPT})
        ta_messages.append({"role": "user", "content": fill(
            STEP2_CONTEXT_USER_PROMPT,
            PARSED_HAR_SUMMARY_JSON=json.dumps(parsed_har_json, ensure_ascii=False)
        )})
        context_json: TrafficAnalysisContext = call_llm(
            messages=ta_messages, response_format=TrafficAnalysisContext)
        return context_json

    # ===== STATIC FILE ANALYSIS ROUTE =====
    def static_init(self, static_files_summary) -> StaticInitOutput:
        """STEP S1: Initialize static file index"""
        s1_messages = self.init_messages.copy()
        s1_messages.append({"role": "system", "content": STEPS1_STATIC_INIT_SYSTEM_PROMPT})
        s1_messages.append({"role": "user", "content": fill(
            STEPS1_STATIC_INIT_USER_PROMPT,
            STATIC_FILES_SUMMARY_JSON=json.dumps(static_files_summary, ensure_ascii=False)
        )})
        static_init_json: StaticInitOutput = call_llm(
            messages=s1_messages,
            response_format=StaticInitOutput
        )
        return static_init_json

    def static_extract(self, static_files_content) -> StaticExtractionOutput:
        """STEP S2: Extract endpoints, routes, sinks from static files"""
        s2_messages = self.init_messages.copy()
        s2_messages.append({"role": "system", "content": STEPS2_STATIC_EXTRACT_SYSTEM_PROMPT})
        s2_messages.append({"role": "user", "content": fill(
            STEPS2_STATIC_EXTRACT_USER_PROMPT,
            STATIC_FILES_CONTENT_JSON=json.dumps(static_files_content, ensure_ascii=False)
        )})
        static_extract_json: StaticExtractionOutput = call_llm(
            messages=s2_messages,
            response_format=StaticExtractionOutput
        )
        return static_extract_json

    def static_mapping(self, static_artifacts: str, traffic_endpoints: str) -> StaticMappingOutput:
        """STEP S3: Map static artifacts to traffic endpoints"""
        s3_messages = self.init_messages.copy()
        s3_messages.append({"role": "system", "content": STEPS3_STATIC_MAPPING_SYSTEM_PROMPT})
        s3_messages.append({"role": "user", "content": fill(
            STEPS3_STATIC_MAPPING_USER_PROMPT,
            STATIC_ARTIFACTS_JSON=static_artifacts,
            TRAFFIC_ENDPOINTS_JSON=traffic_endpoints
        )})
        static_mapping_json: StaticMappingOutput = call_llm(
            messages=s3_messages,
            response_format=StaticMappingOutput
        )
        return static_mapping_json

    # ===== INTEGRATION ROUTE =====
    def unified_inventory(self, enriched_static: str, traffic_context: str) -> UnifiedInventoryOutput:
        """STEP I1: Build unified endpoint inventory"""
        i1_messages = self.init_messages.copy()
        i1_messages.append({"role": "system", "content": STEPI1_UNIFIED_INVENTORY_SYSTEM_PROMPT})
        i1_messages.append({"role": "user", "content": fill(
            STEPI1_UNIFIED_INVENTORY_USER_PROMPT,
            ENRICHED_STATIC_JSON=enriched_static,
            TRAFFIC_CONTEXT_JSON=traffic_context
        )})
        unified_inventory_json: UnifiedInventoryOutput = call_llm(
            messages=i1_messages,
            response_format=UnifiedInventoryOutput
        )
        return unified_inventory_json

    def sink_attachment(self, unified_inventory: str, static_sinks: dict, traffic_bodies=None) -> SinkAttachmentOutput:
        """STEP I2: Attach XSS sinks to endpoints"""
        i2_messages = self.init_messages.copy()
        i2_messages.append({"role": "system", "content": STEPI2_SINK_ATTACHMENT_SYSTEM_PROMPT})
        i2_messages.append({"role": "user", "content": fill(
            STEPI2_SINK_ATTACHMENT_USER_PROMPT,
            UNIFIED_INVENTORY_JSON=unified_inventory,
            STATIC_SINKS_JSON=json.dumps(static_sinks, ensure_ascii=False),
            TRAFFIC_BODIES_JSON=json.dumps(traffic_bodies or {}, ensure_ascii=False)
        )})
        sink_attachment_json: SinkAttachmentOutput = call_llm(
            messages=i2_messages,
            response_format=SinkAttachmentOutput
        )
        return sink_attachment_json

    # ===== ATTACK VECTOR & VULN ROUTE =====
    def av_enum(self, context_json: Union[TrafficAnalysisContext, UnifiedInventoryOutput]) -> AttackVectorsContext:
        """STEP 3: Enumerate attack vectors"""
        av_messages = self.init_messages.copy()
        av_messages.append({"role": "system", "content": STEP3_VECTORS_SYSTEM_PROMPT})

        # Handle both TrafficAnalysisContext and UnifiedInventoryOutput
        if isinstance(context_json, (TrafficAnalysisContext, UnifiedInventoryOutput)):
            context_data = context_json.model_dump_json()
        else:
            context_data = json.dumps(context_json, ensure_ascii=False)

        av_messages.append({"role": "user", "content": fill(
            STEP3_VECTORS_USER_PROMPT,
            CONTEXT_JSON=context_data
        )})
        attack_vectors_json: AttackVectorsContext = call_llm(
            messages=av_messages,
            response_format=AttackVectorsContext)
        return attack_vectors_json

    def vuln_hypothesis(self, attack_vectors_json: AttackVectorsContext) -> VulnHypothesesContext:
        """STEP 4: Generate vulnerability hypotheses"""
        vh_messages = self.init_messages.copy()
        vh_messages.append({"role": "system", "content": STEP4_VULNS_SYSTEM_PROMPT})
        vh_messages.append({"role": "user", "content": fill(
            STEP4_VULNS_USER_PROMPT,
            ATTACK_VECTORS_JSON=attack_vectors_json.model_dump_json()
        )})
        vuln_hypotheses_json: VulnHypothesesContext = call_llm(
            messages=vh_messages,
            response_format=VulnHypothesesContext
        )
        return vuln_hypotheses_json

    def tc_gen(self, context_json: Union[TrafficAnalysisContext, UnifiedInventoryOutput], vuln_hypotheses_json: VulnHypothesesContext) -> TestCasesContext:
        """STEP 5: Generate test cases"""
        tc_gen_messages = self.init_messages.copy()
        tc_gen_messages.append({"role": "system", "content": STEP5_TESTCASES_SYSTEM_PROMPT})

        # Handle both TrafficAnalysisContext and UnifiedInventoryOutput
        if isinstance(context_json, (TrafficAnalysisContext, UnifiedInventoryOutput)):
            context_data = context_json.model_dump_json()
        else:
            context_data = json.dumps(context_json, ensure_ascii=False)

        tc_gen_messages.append({"role": "user", "content": fill(
            STEP5_TESTCASES_USER_PROMPT,
            CONTEXT_JSON=context_data,
            VULN_HYPOTHESES_JSON=vuln_hypotheses_json.model_dump_json()
        )})
        testcases_json: TestCasesContext = call_llm(
            messages=tc_gen_messages,
            response_format=TestCasesContext
        )
        return testcases_json

    def chain_tc_context(self, context_json: Union[TrafficAnalysisContext, UnifiedInventoryOutput], testcases_json: TestCasesContext) -> TestCasesContext:
        """STEP 6: Chain and prioritize test cases"""
        final_plan_messages = self.init_messages.copy()
        final_plan_messages.append({"role": "system", "content": STEP6_CHAIN_SYSTEM_PROMPT})

        # Handle both TrafficAnalysisContext and UnifiedInventoryOutput
        if isinstance(context_json, (TrafficAnalysisContext, UnifiedInventoryOutput)):
            context_data = context_json.model_dump_json()
        else:
            context_data = json.dumps(context_json, ensure_ascii=False)

        final_plan_messages.append({"role": "user", "content": fill(
            STEP6_CHAIN_USER_PROMPT,
            CONTEXT_JSON=context_data,
            TESTCASES_JSON=testcases_json.model_dump_json()
        )})
        final_plan_json: TestCasesContext = call_llm(
            messages=final_plan_messages, response_format=TestCasesContext)
        return final_plan_json

    # ===== FULL REASONING CHAIN =====
    def do_reasoning_chain(self, filename: str, static_files_path: str) -> TestCasesContext:
        """
        Execute full reasoning chain with optional static file analysis.

        Args:
            filename: Base filename (without extension) for HAR file
            static_files_path: Optional path to static files JSON (if None, skips static analysis)
        """
        print("=" * 60)
        print("STARTING REASONING CHAIN")
        print("=" * 60)

        # STEP 2: Traffic Analysis
        print("\n[STEP 2] Traffic Analysis...")
        ta_result = self.traffic_analysis('parsed_hars/' + filename + '.json')
        self.export_result(result=ta_result, filename = filename, output_path='reasoning_result/traffic_analysis_result/')
        print(f"✓ Extracted {len(ta_result.endpoints)} endpoints from traffic")

        # STATIC FILE BRANCH
        unified_context: Union[TrafficAnalysisContext, UnifiedInventoryOutput] = ta_result
        if static_files_path:
            print("\n" + "=" * 60)
            print("STATIC FILE ANALYSIS BRANCH")
            print("=" * 60)

            with open(static_files_path, 'r', encoding='utf-8') as f:
                static_files_data = json.load(f)

            # STEP S1: Static Init
            print("\n[STEP S1] Static File Init...")
            static_init_result = self.static_init(static_files_data.get('summary', []))
            self.export_result(result=static_init_result, filename = filename, output_path='reasoning_result/static_init_result/')
            print(f"✓ Indexed {len(static_init_result.file_index)} static files")

            # STEP S2: Static Extract
            print("\n[STEP S2] Static Extraction...")
            static_extract_result = self.static_extract(static_files_data.get('content', []))
            self.export_result(result=static_extract_result, filename = filename, output_path='reasoning_result/static_extract_result/')
            print(f"✓ Found {len(static_extract_result.candidate_endpoints)} candidate endpoints")
            print(f"✓ Found {len(static_extract_result.client_routes)} client routes")
            print(f"✓ Found {len(static_extract_result.xss_sinks)} XSS sinks")

            # STEP S3: Static Mapping
            print("\n[STEP S3] Static->Traffic Mapping...")
            static_mapping_result = self.static_mapping(
                static_artifacts=static_extract_result.model_dump_json(),
                traffic_endpoints=ta_result.model_dump_json()
            )
            self.export_result(result=static_mapping_result, filename = filename, output_path='reasoning_result/static_mapping_result/')
            print(f"✓ Enriched {len(static_mapping_result.enriched_endpoints)} endpoints")
            print(f"✓ Found {len(static_mapping_result.hidden_candidates)} hidden candidates")

            # STEP I1: Unified Inventory
            print("\n[STEP I1] Building Unified Inventory...")
            unified_inventory_result = self.unified_inventory(
                enriched_static=static_mapping_result.model_dump_json(),
                traffic_context=ta_result.model_dump_json()
            )
            self.export_result(result=unified_inventory_result, filename = filename, output_path='reasoning_result/unified_inventory_result/')
            print(f"✓ Unified inventory: {len(unified_inventory_result.endpoints)} total endpoints")

            # STEP I2: Sink Attachment (optional)
            print("\n[STEP I2] Attaching XSS Sinks...")
            # Serialize xss_sinks and interesting_patterns properly
            static_sinks_data = {
                "xss_sinks": [sink.model_dump() for sink in static_extract_result.xss_sinks],
                "interesting_patterns": [pattern.model_dump() for pattern in static_extract_result.interesting_patterns]
            }
            sink_attachment_result = self.sink_attachment(
                unified_inventory=unified_inventory_result.model_dump_json(),
                static_sinks=static_sinks_data
            )
            self.export_result(result=sink_attachment_result, filename = filename, output_path='reasoning_result/sink_attachment_result/')
            print(f"✓ Attached sinks to {len(sink_attachment_result.endpoint_sinks)} endpoints")

            # Use unified inventory as context for attack vectors
            unified_context = unified_inventory_result

        # STEP 3: Attack Vector Enumeration
        print("\n" + "=" * 60)
        print("ATTACK SURFACE ANALYSIS")
        print("=" * 60)
        print("\n[STEP 3] Attack Vector Enumeration...")
        av_result = self.av_enum(unified_context)
        self.export_result(result=av_result, filename = filename, output_path='reasoning_result/av_enum_result/')
        print(f"✓ Identified {len(av_result.attack_vectors)} attack vectors")

        # STEP 4: Vulnerability Hypotheses
        print("\n[STEP 4] Vulnerability Hypothesis Generation...")
        vh_result = self.vuln_hypothesis(av_result)
        self.export_result(result=vh_result, filename = filename, output_path='reasoning_result/vuln_hypotheses_result/')
        print(f"✓ Generated {len(vh_result.hypotheses)} vulnerability hypotheses")

        # STEP 5: Test Case Generation
        print("\n[STEP 5] Test Case Generation...")
        tc_gen_result = self.tc_gen(unified_context, vh_result)
        self.export_result(result=tc_gen_result, filename = filename, output_path='reasoning_result/tc_gen_result/')
        print(f"✓ Generated {len(tc_gen_result.test_cases)} test cases")

        # STEP 6: Chaining & Final Plan
        print("\n[STEP 6] Test Case Chaining & Prioritization...")
        final_plan_json = self.chain_tc_context(unified_context, tc_gen_result)
        self.export_result(result=final_plan_json, filename = filename, output_path='reasoning_result/')
        print(f"✓ Final execution plan ready with {len(final_plan_json.test_cases)} chained tests")

        print("\n" + "=" * 60)
        print("REASONING CHAIN COMPLETE")
        print("=" * 60)
        return final_plan_json

    def export_result(self, result, filename: str, output_path: str):
        """Export result to JSON file"""
        current_datetime = datetime.datetime.now()
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        export_filename = current_datetime.strftime('%Y%m%d%H%M%S_') + filename + '_' + config['MODEL'] + '.json'
        with open(output_path + export_filename, 'w', encoding='utf-8') as f:
            if isinstance(result, BaseModel):
                f.write(result.model_dump_json(indent=2, exclude_none=True))
            else:
                json.dump(result, f, indent=2, ensure_ascii=False)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Do reasoning from parsed HAR file')
    parser.add_argument('filename', help='Filename without .har extension (e.g., "example" for parsed_hars/example.har)')
    parser.add_argument('--static', help='Path to static files JSON (optional)', default=None)
    args = parser.parse_args()
    filename = args.filename

    RM = ReasoningModule()
    try:
        result = RM.do_reasoning_chain(filename, static_files_path=args.static)
        print("\n✓ Pipeline completed successfully")
    except Exception as e:
        print(f"\n✗ Pipeline failed: {e}")
        import traceback
        traceback.print_exc()