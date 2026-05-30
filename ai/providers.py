"""
Multi-provider AI abstraction layer.

Supported providers:
  - openai   : OpenAI GPT models
  - gemini   : Google Gemini models
  - claude   : Anthropic Claude models
"""

import json

PROVIDER_CONFIG = {
    "openai": {
        "name": "OpenAI",
        "models": ["gpt-4o", "gpt-4-turbo", "gpt-3.5-turbo"],
        "default_model": "gpt-4o",
    },
    "gemini": {
        "name": "Google Gemini",
        "models": ["gemini-2.0-flash", "gemini-1.5-pro", "gemini-1.5-flash"],
        "default_model": "gemini-2.0-flash",
    },
    "claude": {
        "name": "Anthropic Claude",
        "models": ["claude-opus-4-8", "claude-sonnet-4-6", "claude-haiku-4-5-20251001"],
        "default_model": "claude-sonnet-4-6",
    },
}

SYSTEM_PROMPT = """You are a professional network security analyst specializing in public Wi-Fi security risks.
The user will provide JSON data from a network security scan. You must:
1. Interpret the security risks in plain, non-technical English
2. Provide an overall security assessment
3. Give 3-5 specific, actionable recommendations

Reply ONLY in this exact JSON format (no markdown, no extra text):
{
  "overall_assessment": "Brief overall assessment (1-2 sentences)",
  "risk_summary": "Detailed risk explanation (3-4 sentences)",
  "recommendations": ["recommendation 1", "recommendation 2", "recommendation 3"],
  "safe_to_use": true
}"""


def call_openai(api_key: str, model: str, user_message: str) -> str:
    from openai import OpenAI
    client = OpenAI(api_key=api_key)
    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_message},
        ],
        max_tokens=1024,
        temperature=0.3,
    )
    return response.choices[0].message.content.strip()


def call_gemini(api_key: str, model: str, user_message: str) -> str:
    import google.generativeai as genai
    genai.configure(api_key=api_key)
    gemini_model = genai.GenerativeModel(
        model_name=model,
        system_instruction=SYSTEM_PROMPT,
    )
    response = gemini_model.generate_content(user_message)
    return response.text.strip()


def call_claude(api_key: str, model: str, user_message: str) -> str:
    import anthropic
    client = anthropic.Anthropic(api_key=api_key)
    message = client.messages.create(
        model=model,
        max_tokens=1024,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_message}],
    )
    return message.content[0].text.strip()


def call_provider(provider: str, api_key: str, model: str, user_message: str) -> str:
    """Dispatch to the correct provider and return raw response text."""
    if provider == "openai":
        return call_openai(api_key, model, user_message)
    elif provider == "gemini":
        return call_gemini(api_key, model, user_message)
    elif provider == "claude":
        return call_claude(api_key, model, user_message)
    else:
        raise ValueError(f"Unknown provider: {provider}")


def parse_response(raw: str) -> dict:
    """Strip markdown fences and parse JSON response from any provider."""
    text = raw.strip()
    if text.startswith("```"):
        parts = text.split("```")
        text = parts[1] if len(parts) > 1 else text
        if text.startswith("json"):
            text = text[4:]
    text = text.strip()
    return json.loads(text)
