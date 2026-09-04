import os

from dotenv import load_dotenv
from langchain_openai import ChatOpenAI


load_dotenv(dotenv_path=".env")


llm = ChatOpenAI(
    model=os.getenv("FEATHERLESS_MODEL"),
    temperature=0.7,
    max_tokens=512,
    api_key=os.getenv("FEATHERLESS_API_KEY"),
    base_url="https://api.featherless.ai/v1",

    # Disable Qwen thinking mode for fast security analysis
    extra_body={
        "chat_template_kwargs": {
            "enable_thinking": False
        }
    }
)