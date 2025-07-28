from prompts import REASONING_PROMPT_ONLY_CURL
from utils import call_llm
import json

class ReasoningModule():
  def analyze_endpoint(self, json_file_path):
      with open(json_file_path, 'r') as f:
          endpoint_data = json.load(f)

      # TODO: integrate with another tools if time suffices
      formatted_prompt = REASONING_PROMPT_ONLY_CURL.format(
          data=json.dumps(endpoint_data, indent=2)
      )

      response = call_llm(formatted_prompt)
      return response

  def export_result(self, result, output_path: str):
          """Export endpoints to JSON file"""
          with open(output_path, 'w', encoding='utf-8') as f:
              f.write(result)

if __name__ == "__main__":
    RM = ReasoningModule()
    filename = input('Enter filename (json/name.json): ')
    try:
      res = RM.analyze_endpoint('json/' + filename + '.json')
      print(res)
      RM.export_result(res, f'reasoning_result/{filename}.txt')
      print(f'Result saved as reasoning_result/{filename}.txt')
    except BaseException as e:
      print(e)