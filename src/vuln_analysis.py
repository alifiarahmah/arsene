from dataclasses import dataclass
from typing import List, Dict, Any, Optional
from utils import call_llm
from prompts import VULN_ANALYSIS_PROMPT

import json
import re
import requests
import time
import hashlib

@dataclass
class BaselineMetrics:
    """baseline metrics for every endpoint"""
    status_code: int
    body_length: int
    body_hash: str  # hash dari response body
    headers: Dict[str, str]
    response_time: float

@dataclass
class VulnTestResult:
    test_case: Dict[str, Any]
    baseline: BaselineMetrics
    actual_response: Dict[str, Any]
    heuristic_score: float
    llm_analysis: Optional[str] = None
    confidence_level: str = "low"  # low, medium, high
    requires_exploitation: bool = False

class VulnerabilityAnalysisModule:
    def __init__(self):
          self.baselines = {}
          self.T_low = 0.3
          self.T_high = 0.7

    def read_reasoning_result(self, path):
        """read reasoning module output (test cases)"""
        try:
            with open(path, 'r') as f:
                file = f.read()
        except FileNotFoundError:
            with open(path + '.raw', 'r') as f:
                file = f.read()
        try:
            reasoning_output = json.loads(file)
            return reasoning_output
        except json.JSONDecodeError as e:
            print(f"JSON parsing error: {e}")
            return None
        except Exception as e:
            print(f"Other error: {e}")
            return None

    def establish_baseline(self, request_config: Dict[str, Any]) -> Optional[BaselineMetrics]:
        """establish baseline metrics for an endpoint"""
        try:
            start_time = time.time()
            response = requests.request(
                method=request_config['method'],
                url=request_config['url'],
                headers=request_config.get('headers', {}),
                params=request_config.get('params', {}),
                data=request_config.get('body'),
                timeout=10,
                allow_redirects=False
            )
            response_time = time.time() - start_time

            body_text = response.text
            body_hash = hashlib.md5(body_text.encode()).hexdigest()

            baseline = BaselineMetrics(
                status_code=response.status_code,
                body_length=len(body_text),
                body_hash=body_hash,
                headers=dict(response.headers),
                response_time=response_time
            )

            # cache baseline for this endpoint
            endpoint_key = f"{request_config['method']}:{request_config['url']}"
            self.baselines[endpoint_key] = baseline

            return baseline

        except Exception as e:
            print(f"Failed to establish baseline for {request_config.get('url', 'unknown')}: {e}")
            return None

    def execute_test_case(self, test_case: Dict[str, Any]) -> Optional[VulnTestResult]:
        """execute a single test case and return results"""
        try:
            # get or establish baseline
            baseline_req = test_case['baseline_request']
            endpoint_key = f"{baseline_req['method']}:{baseline_req['url']}"

            baseline = self.baselines.get(endpoint_key)
            if not baseline:
                baseline = self.establish_baseline(baseline_req)
                if not baseline:
                    return None

            # execute payload request
            payload_req = test_case['payload_request']
            start_time = time.time()

            response = requests.request(
                method=payload_req['method'],
                url=payload_req['url'],
                headers=payload_req.get('headers', {}),
                params=payload_req.get('params', {}),
                data=payload_req.get('body'),
                timeout=10,
                allow_redirects=False
            )
            response_time = time.time() - start_time

            # prepare response data
            actual_response = {
                'status_code': response.status_code,
                'body_length': len(response.text),
                'body': response.text,
                'headers': dict(response.headers),
                'response_time': response_time
            }

            # calculate heuristic score
            heuristic_score = self.calculate_heuristic_score(baseline, actual_response, test_case)

            # determine confidence level based on thresholds
            if heuristic_score < self.T_low:
                confidence_level = "low"
                requires_exploitation = False
            elif heuristic_score > self.T_high:
                confidence_level = "high"
                requires_exploitation = True
            else:
                confidence_level = "medium"
                requires_exploitation = False

            return VulnTestResult(
                test_case=test_case,
                baseline=baseline,
                actual_response=actual_response,
                heuristic_score=heuristic_score,
                confidence_level=confidence_level,
                requires_exploitation=requires_exploitation
            )

        except Exception as e:
            print(f"Failed to execute test case {test_case.get('attack_vector', 'unknown')}: {e}")
            return None


    def calculate_heuristic_score(self, baseline: BaselineMetrics, response: Dict[str, Any], test_case: Dict[str, Any]) -> float:
        """calculate heuristic score based on changes from baseline"""
        score = 0.0

        # status code
        if response.get('status_code') != baseline.status_code:
            score += 0.15

        # body length > 30%
        current_length = response.get('body_length', 0)
        if baseline.body_length > 0:
            length_diff = abs(current_length - baseline.body_length) / baseline.body_length
            if length_diff > 0.3:
                score += 0.15

        # response time change (> 2x baseline)
        current_time = response.get('response_time', 0)
        if current_time > baseline.response_time * 2:
            score += 0.15

        # error signature detection
        body = response.get('body', '')
        error_patterns = [
            r'error|exception|stack trace|warning',
            r'sql.*error|mysql|postgresql|oracle',
            r'php.*error|fatal.*error|parse.*error',
            r'500.*internal.*server.*error',
            r'syntax.*error|parse.*error',
            r'database.*error|connection.*failed'
        ]

        for pattern in error_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                score += 0.20
                break

        # payload reflection detection
        payload_body = test_case.get('payload_request', {}).get('body', '')
        if payload_body and isinstance(payload_body, str):
            # extract potential payloads from request body
            payload_indicators = re.findall(r'[<>\'";(){}]|script|alert|union|select', payload_body, re.IGNORECASE)
            for indicator in payload_indicators:
                if indicator.lower() in body.lower():
                    score += 0.10
                    break

        # TODO: Out-of-bound interaction detection
        # requires monitoring DNS/HTTP callbacks
        # score += 0.30

        return min(score, 1.0)  # cap at 1.0

    def llm_deep_analysis(self, test_result: VulnTestResult) -> str:
        """Use LLM for deep analysis of medium-confidence cases"""
        prompt = VULN_ANALYSIS_PROMPT.format(
            attack_vector=test_result.test_case.get('attack_vector'),
            test_scenario=test_result.test_case.get('test_scenario'),
            heuristic_score=test_result.heuristic_score,
            baseline_status=(test_result.baseline.status_code if test_result.baseline else 'N/A'),
            baseline_body_length=(test_result.baseline.body_length if test_result.baseline else 'N/A'),
            actual_status=test_result.actual_response.get('status_code'),
            actual_body_length=test_result.actual_response.get('body_length'),
            actual_body_sample=(test_result.actual_response.get('body', '')[:500]),
            method=test_result.test_case['payload_request']['method'],
            url=test_result.test_case['payload_request']['url'],
            payload_body=test_result.test_case['payload_request'].get('body', '')[:200]
        )

        try:
            llm_response = call_llm(prompt, format_json=True)
            return llm_response
        except Exception as e:
            print(f"LLM analysis failed: {e}")
            return '{"analysis": "LLM analysis failed", "recommendation": "MANUAL_REVIEW", "confidence": "low"}'

    def analyze_test_cases(self, reasoning_output: List[Dict[str, Any]]) -> 'VulnerabilityAnalysisModuleOutput':
        """Main analysis pipeline: execute tests, apply heuristics, and LLM analysis"""
        results = []

        print(f"Analyzing {len(reasoning_output)} test cases...")

        for i, test_case in enumerate(reasoning_output):
            print(f"Executing test case {i+1}/{len(reasoning_output)}: {test_case.get('attack_vector', 'unknown')}")

            test_result = self.execute_test_case(test_case)
            if not test_result:
                continue

            # For medium confidence cases, use LLM analysis
            if test_result.confidence_level == "medium":
                print(f"Running LLM analysis for borderline case: {test_case.get('attack_vector')}")
                llm_analysis = self.llm_deep_analysis(test_result)
                test_result.llm_analysis = llm_analysis

                # Parse LLM recommendation to adjust confidence
                try:
                    llm_result = json.loads(llm_analysis)
                    recommendation = llm_result.get('recommendation', 'MANUAL_REVIEW')

                    if recommendation == "EXPLOIT":
                        test_result.confidence_level = "high"
                        test_result.requires_exploitation = True
                    elif recommendation == "FALSE_POSITIVE":
                        test_result.confidence_level = "low"
                        test_result.requires_exploitation = False
                    # MANUAL_REVIEW keeps medium confidence

                except json.JSONDecodeError:
                    print(f"Failed to parse LLM analysis for {test_case.get('attack_vector')}")

            results.append(test_result)

        return VulnerabilityAnalysisModuleOutput(results)

class VulnerabilityAnalysisModuleOutput:
    def __init__(self, results):
        self.results = results
        self.high_confidence = [r for r in results if r.confidence_level == "high"]
        self.medium_confidence = [r for r in results if r.confidence_level == "medium"]
        self.low_confidence = [r for r in results if r.confidence_level == "low"]

    def get_exploitation_queue(self):
        """test case to be transferred to ExploitationModule"""
        return self.high_confidence

    def get_llm_analysis_queue(self):
        """test case to analyzed using LLM again"""
        return self.medium_confidence

    def to_dict(self):
        """convert to dictionary for serialization"""
        return {
            'total_tests': len(self.results),
            'high_confidence_count': len(self.high_confidence),
            'medium_confidence_count': len(self.medium_confidence),
            'low_confidence_count': len(self.low_confidence),
            'exploitation_queue': [
                {
                    'attack_vector': r.test_case['attack_vector'],
                    'test_scenario': r.test_case['test_scenario'],
                    'heuristic_score': r.heuristic_score,
                    'response_status': r.actual_response.get('status_code'),
                    'response_body': r.actual_response.get('body', '')[:200],
                    'baseline_status': r.baseline.status_code if r.baseline else None,
                    'url': r.test_case['payload_request']['url'],
                    'method': r.test_case['payload_request']['method'],
                    'payload': r.test_case['payload_request'].get('body', ''),
                    'llm_analysis': r.llm_analysis
                }
                for r in self.high_confidence
            ],
            'manual_review_queue': [
                {
                    'attack_vector': r.test_case['attack_vector'],
                    'test_scenario': r.test_case['test_scenario'],
                    'heuristic_score': r.heuristic_score,
                    'baseline_status': r.baseline.status_code if r.baseline else None,
                    'actual_status': r.actual_response.get('status_code'),
                    'baseline_body_length': r.baseline.body_length if r.baseline else None,
                    'actual_body_length': r.actual_response.get('body_length'),
                    'response_body': r.actual_response.get('body', '')[:300],
                    'url': r.test_case['payload_request']['url'],
                    'method': r.test_case['payload_request']['method'],
                    'payload': r.test_case['payload_request'].get('body', ''),
                    'llm_analysis': r.llm_analysis
                }
                for r in self.medium_confidence
            ]
        }

    def export_results(self, output_path: str):
        """Export analysis results to JSON file"""
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(self.to_dict(), f, indent=2, ensure_ascii=False)
            print(f"Analysis results exported to {output_path}")
        except Exception as e:
            print(f"Failed to export results: {e}")

if __name__ == "__main__":
    filename = input('Enter filename (reasoning_result/<name>.json): ')
    VA = VulnerabilityAnalysisModule()

    # read reasoning output (test cases)
    reasoning_output = VA.read_reasoning_result(f'reasoning_result/{filename}.json')
    if not reasoning_output:
        print("Failed to read reasoning results")
        exit(1)

    # run full analysis pipeline
    analysis_results = VA.analyze_test_cases(reasoning_output)

    # export results
    analysis_results.export_results(f'vuln_analysis_result/{filename}.json')

    # print summary
    print(f"\n=== ANALYSIS SUMMARY ===")
    print(f"Total tests executed: {len(analysis_results.results)}")
    print(f"High confidence (exploitation queue): {len(analysis_results.high_confidence)}")
    print(f"Medium confidence (manual review): {len(analysis_results.medium_confidence)}")
    print(f"Low confidence (likely false positives): {len(analysis_results.low_confidence)}")

    if analysis_results.high_confidence:
        print(f"\nHigh confidence findings:")
        for result in analysis_results.high_confidence:
            print(f"  - {result.test_case['attack_vector']}: {result.heuristic_score:.2f}")