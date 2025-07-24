from config import config
import json
import requests

def call_llm(prompt: str):
  r = requests.post(
      url=f'{config['URI']}/api/generate',
      headers={
          "Content-Type": "application/json",
          "Authorization": f"Bearer {config['BEARER_TOKEN']}"
      },
      data=json.dumps({
        "model": config['MODEL'],
        "prompt": prompt,
        "stream": False,
        "max_tokens": 512,
        "temperature": 0.1
    })
  )

  response = r.json()['response']
  return response