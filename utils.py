from config import config
import requests
import json
from openai import OpenAI
from typing import TypeVar, Type, Union, Optional, overload, Any, List, Dict, cast
from pydantic import BaseModel

openai_client = OpenAI(
    api_key=config['OPENAI_KEY']
)

class GenericResponse(BaseModel):
    content: str
T = TypeVar('T', bound=BaseModel)

@overload
def call_llm(
    model: str = ...,
    messages: list = ...,
    response_format: Type[T] = ...,
    format_json: bool = ...,
    temperature: float = ...,
    seed: int = ...,
    num_ctx: int = ...
) -> T: ...

@overload
def call_llm(
    model: str = ...,
    messages: list = ...,
    response_format: None = ...,
    format_json: bool = ...,
    temperature: float = ...,
    seed: int = ...,
    num_ctx: int = ...
) -> str: ...

def call_llm(
    model: str = config['MODEL'],
    messages: list = [],
    response_format: Optional[Type[T]] = None,
    format_json: bool = True,
    temperature: float = 0.2,
    seed: int = 42,
    num_ctx: int = 4096
) -> Union[T, str]:
    """
    Call LLM with optional structured output.

    Args:
        model: Model name
        messages: Chat messages
        response_format: Pydantic model class for structured output
        format_json: Request JSON format from non-OpenAI models
        temperature: Sampling temperature
        seed: Random seed
        num_ctx: Context window size

    Returns:
        Parsed Pydantic model if response_format provided, otherwise raw string
    """
    # OpenAI models with native structured output
    if model.startswith('gpt-'):
        actual_format: Type[BaseModel] = response_format if response_format is not None else GenericResponse

        completion = openai_client.chat.completions.parse(
            model=model,
            messages=messages,
            response_format=actual_format,
            reasoning_effort='minimal'
        )
        result = completion.choices[0].message.parsed
        return result  # type: ignore[return-value]

    # Non-OpenAI models (Ollama, etc.)
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
    content = data["message"]["content"]

    # Parse JSON response to Pydantic model if requested
    if response_format is not None and format_json:
        try:
            json_data = json.loads(content)
            parsed = response_format.model_validate(json_data)
            return parsed  # type: ignore[return-value]
        except Exception as e:
            print(f"Warning: Failed to parse response to {response_format.__name__}: {e}")
            print(f"Raw content: {content}")
            raise

    return content  # type: ignore[return-value]

def fill(template, **kwargs):
    out = template
    for k, v in kwargs.items():
        if not isinstance(v, str):
            v = json.dumps(v, ensure_ascii=False)
        out = out.replace(f"<<{k}>>", v)
    return out