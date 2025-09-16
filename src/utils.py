from config import config
import requests
import json
from openai import OpenAI
from pydantic import BaseModel

openai_client = OpenAI(
    api_key=config['OPENAI_KEY']
)

class GenericResponse(BaseModel):
    content: str

def call_llm(model=config['MODEL'], messages=[], response_format=None, format_json=True, temperature=0.2, seed=42, num_ctx=4096):
    if model.startswith('gpt-'):
        if response_format is None:
          response_format = GenericResponse
          
        completion = openai_client.chat.completions.parse(
            model=model,
            messages=messages,
            response_format=response_format,
            reasoning_effort='minimal'
        )
        result = completion.choices[0].message.parsed
        print('call_llm result:', result)
        return result

    payload = {
        "model": config['MODEL'],
        "messages": messages,
        "options": {"temperature": temperature, "seed": seed, "num_ctx": num_ctx},
        "stream": False
    }
    if format_json:
        payload["format"] = "json"

    r = requests.post(
        url=f'{config['URI']}/api/chat',
        timeout=600,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {config['BEARER_TOKEN']}"
        },
        json=payload,
    )
    r.raise_for_status()
    data = r.json()
    print(data)
    content = data["message"]["content"]
    return content

def fill(template, **kwargs):
    out = template
    for k, v in kwargs.items():
        if not isinstance(v, str):
            v = json.dumps(v, ensure_ascii=False)
        out = out.replace(f"<<{k}>>", v)
    return out