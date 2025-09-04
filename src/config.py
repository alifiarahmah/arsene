import os
from dotenv import load_dotenv, dotenv_values

# Load environment variables from .env file
load_dotenv()

config = {
    'URI': os.getenv('URI', 'http://localhost:11434'),
    'MODEL': os.getenv('MODEL', 'gpt-5-mini'),
    'BEARER_TOKEN': os.getenv('BEARER_TOKEN', 'be77fef88ddb58dbe9b3f94e5a9b300101da1b8a51ece515c17cd2de058bab9e'),
    'OPENAI_KEY': os.getenv('OPENAI_KEY', 'xxx')
}