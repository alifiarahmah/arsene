import json
import requests
from prompts import REASONING_PROMPT

def analyze_endpoint(json_file_path):
    with open(json_file_path, 'r') as f:
        endpoint_data = json.load(f)

    formatted_prompt = REASONING_PROMPT.format(
        data=json.dumps(endpoint_data, indent=2)
    )

    # Send to your LLM here
    r = requests.post(
        url='http://localhost:11434/api/generate',
        data=json.dumps({
            "model": "phi3:mini",
            "prompt": formatted_prompt,
            "stream": False
        })
    )

    response = r.json()['response']
    return response

def export_result(result, output_path: str):
        """Export endpoints to JSON file"""
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(result)

if __name__ == "__main__":
    print('requesting...')
    try:
      res = analyze_endpoint('../../json/har_example.json')
      print(res)
      export_result(res, 'output/a.txt')
    except BaseException as e:
      print(e)