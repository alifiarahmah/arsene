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
        url='http://61.71.33.195:54012/v1/completions',
        headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer cd4744b1831ee7a580c7e5fe38a2e2a9d9c777d65608bb36745d6f6fd9910dfe"
        },
        data=json.dumps({
            "model": "mixtral:8x7b",
            "prompt": formatted_prompt,
            "stream": False,
            "temperature": 0.1
        })
    )

    response = r.json()['choices'][0]['text']
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
      export_result(res, 'a.txt')
    except BaseException as e:
      print(e)