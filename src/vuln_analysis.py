import json
import re
import subprocess
from dataclasses import dataclass
from typing import List, Dict, Any, Optional

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
        with open(path, 'r') as f:
            file = f.read()
        try:
            reasoning_output_new = json.loads(file)
            return reasoning_output_new
        except json.JSONDecodeError as e:
            print(f"JSON parsing error: {e}")
        except Exception as e:
            print(f"Other error: {e}")

    def calculate_heuristic_score(self, baseline: BaselineMetrics, response: Dict[str, Any]) -> float:
        """Hitung skor heuristik berdasarkan perubahan dari baseline"""
        score = 0.0

        # Perubahan status code
        if response.get('status_code') != baseline.status_code:
            score += 0.15

        # Perubahan body length > 30%
        current_length = response.get('body_length', 0)
        if baseline.body_length > 0:
            length_diff = abs(current_length - baseline.body_length) / baseline.body_length
            if length_diff > 0.3:
                score += 0.15

        # Lonjakan response time (asumsi > 2x baseline)
        current_time = response.get('response_time', 0)
        if current_time > baseline.response_time * 2:
            score += 0.15

        # Error signature detection
        body = response.get('body', '')
        error_patterns = [
            r'error|exception|stack trace|warning',
            r'sql.*error|mysql|postgresql|oracle',
            r'php.*error|fatal.*error|parse.*error',
            r'500.*internal.*server.*error'
        ]

        for pattern in error_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                score += 0.20
                break

        # TODO: Payload reflection
        # score += 0.10

        # TODO: Out-of-bound interaction
        # score += 0.30

        return min(score, 1.0)  # cap at 1.0

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
        """Convert ke dictionary untuk serialization"""
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
                    'recommended_tools': r.test_case.get('recommended_tools', []),
                    'tool_command': r.test_case.get('tool_command_payload', '')
                }
                for r in self.high_confidence
            ],
            'llm_analysis_queue': [
                {
                    'attack_vector': r.test_case['attack_vector'],
                    'test_scenario': r.test_case['test_scenario'],
                    'heuristic_score': r.heuristic_score,
                    'baseline_status': r.baseline.status_code if r.baseline else None,
                    'actual_status': r.actual_response.get('status_code'),
                    'baseline_body_length': r.baseline.body_length if r.baseline else None,
                    'actual_body_length': r.actual_response.get('body_length'),
                    'response_body': r.actual_response.get('body', '')[:300],
                    'request_details': {
                        'method': r.test_case.get('parsed_request', {}).get('method'),
                        'path': r.test_case.get('parsed_request', {}).get('path'),
                        'query': r.test_case.get('parsed_request', {}).get('query'),
                        'body': r.test_case.get('parsed_request', {}).get('body', '')[:200]
                    }
                }
                for r in self.medium_confidence
            ]
        }

if __name__ == "__main__":
    filename = input('Enter filename (reasoning_result/<name>.txt): ')
    VA = VulnerabilityAnalysisModule()

    result = VA.read_reasoning_result(f'reasoning_result/{filename}.txt')

    for res in result: # type: ignore

        print(res['curl_baseline'])
        result = subprocess.run(res['curl_baseline'], shell=True, capture_output=True, text=True)
        print("STDOUT:", result.stdout)
        print("STDERR:", result.stderr)
        print("Return code:", result.returncode)

        print(res['curl_payload'])
        result = subprocess.run(res['curl_payload'], shell=True, capture_output=True, text=True)
        print("STDOUT:", result.stdout)
        print("STDERR:", result.stderr)
        print("Return code:", result.returncode)