from pydantic import BaseModel
from openai import OpenAI

client = OpenAI(
    api_key='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'
)

class CalendarEvent(BaseModel):
    name: str
    date: str
    participants: list[str]

completion = client.chat.completions.parse(
    model="gpt-4o-2024-08-06",
    messages=[
        {"role": "system", "content": "Extract the event information."},
        {"role": "user", "content": "Alice and Bob are going to a science fair on Friday."},
    ],
    response_format=CalendarEvent,
)

event = completion.choices[0].message.parsed

print(event)