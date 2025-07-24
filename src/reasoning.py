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
        headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer be77fef88ddb58dbe9b3f94e5a9b300101da1b8a51ece515c17cd2de058bab9e"
        },
        data=json.dumps({
          "model": "mistral:7b-instruct-v0.2-q8_0",
          "prompt": formatted_prompt,
          "stream": False,
          "max_tokens": 128,
          "temperature": 0.1
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
      res = analyze_endpoint('../json/har_example.json')
      print(res)
      export_result(res, '../reasoning_result/reasoning.txt')
    except BaseException as e:
      print(e)