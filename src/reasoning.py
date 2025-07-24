from prompts import REASONING_PROMPT
from utils import call_llm
import json

def analyze_endpoint(json_file_path):
    with open(json_file_path, 'r') as f:
        endpoint_data = json.load(f)

    formatted_prompt = REASONING_PROMPT.format(
        data=json.dumps(endpoint_data, indent=2)
    )

    response = call_llm(formatted_prompt)
    return response

def export_result(result, output_path: str):
        """Export endpoints to JSON file"""
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(result)

if __name__ == "__main__":
    print('requesting...')
    try:
      res = analyze_endpoint('json/har_example.json')
      print(res)
      export_result(res, 'reasoning_result/reasoning.txt')
    except BaseException as e:
      print(e)