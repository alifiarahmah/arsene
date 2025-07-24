import json

with open('reasoning_result/sample.txt', 'r') as f:
    sample_data = f.read()

try:
    reasoning_output_new = json.loads(sample_data)
    print(f"Successfully parsed! Type: {type(reasoning_output_new)}")
    print(f"Total test cases: {len(reasoning_output_new)}")

    print("\n=== PARSED DATA STRUCTURE ===")
    for i, test_case in enumerate(reasoning_output_new):
        print(f"\nTest Case {i+1}:")
        print(f"  Attack Vector: {test_case['attack_vector']}")
        print(f"  Test Scenario: {test_case['test_scenario']}")
        print(f"  Recommended Tools: {test_case['recommended_tools']}")
        print(f"  Full Payload: {test_case['full_payload_with_curl'][:80]}...")
        print(f"  Tool Command: {test_case['tool_command_payload']}")

    print(f"\n=== VERIFICATION ===")
    print(f"Is list: {isinstance(reasoning_output_new, list)}")
    print(f"First item is dict: {isinstance(reasoning_output_new[0], dict)}")
    print(f"Keys in first item: {list(reasoning_output_new[0].keys())}")

except json.JSONDecodeError as e:
    print(f"JSON parsing error: {e}")
except Exception as e:
    print(f"Other error: {e}")