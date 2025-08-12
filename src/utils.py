from config import config
import json
import requests

context_cache = None
conversation_history = []

def call_llm(prompt: str, use_chat_api=True, format_json=True):
    global context_cache, conversation_history

    if use_chat_api:
        # conversation context
        payload = {
            "model": config['MODEL'],
            "messages": conversation_history + [{"role": "user", "content": prompt}],
            "options": {"temperature": 0.2, "seed": 42},
            "stream": False
        }
        if format_json:
            payload["format"] = "json"
        if context_cache:
            payload["context"] = context_cache

        r = requests.post(
            url=f'{config['URI']}/api/chat',
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {config['BEARER_TOKEN']}"
            },
            json=payload
        )

        data = r.json()
        context_cache = data.get("context", context_cache)
        response = data["message"]["content"]

        # update conversation history
        conversation_history.append({"role": "user", "content": prompt})
        conversation_history.append({"role": "assistant", "content": response})

    else:
        # fallback (no context)
        r = requests.post(
            url=f'{config['URI']}/api/generate',
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {config['BEARER_TOKEN']}"
            },
            json={
                "model": config['MODEL'],
                "prompt": prompt,
                "stream": False,
                "max_tokens": 512,
                "temperature": 0.2
            }
        )
        response = r.json()['response']

    return response

def init_conversation(system_prompt: str):
    # init conversation with system prompt
    global conversation_history, context_cache
    conversation_history = [{"role": "system", "content": system_prompt}]
    context_cache = None