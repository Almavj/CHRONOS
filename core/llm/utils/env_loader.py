"""
Environment Variable Loader
"""

import os
from typing import Optional
from chronos.core.llm.models import LLMConfig

NO_API_KEY_PROVIDERS = {"ollama", "lmstudio", "lm"}  # Local providers


def load_llm_config() -> Optional[LLMConfig]:
    """Load LLM configuration from environment variables."""
    api_key = os.getenv("LLM_API_KEY", "").strip()
    provider = os.getenv("LLM_PROVIDER", "openai").lower()

    # Local providers don't require API keys
    if not api_key and provider not in NO_API_KEY_PROVIDERS:
        return None

    api_url_map = {
        "openai": "https://api.openai.com/v1",
        "anthropic": "https://api.anthropic.com/v1",
        "azure": os.getenv("AZURE_OPENAI_ENDPOINT", ""),
        "ollama": os.getenv("OLLAMA_API_URL", "http://localhost:11434"),
        "deepseek": "https://api.deepseek.com/v1",
    }

    api_url = os.getenv("LLM_API_URL", "").strip()
    if not api_url:
        api_url = api_url_map.get(provider, "https://api.openai.com/v1")

    model = os.getenv("LLM_MODEL", "llama2")
    if provider == "ollama" and model.startswith(("gpt-", "claude-", "deepseek")):
        model = "llama2"  # Default for ollama

    return LLMConfig(
        provider=provider,
        api_key=api_key,
        api_url=api_url,
        model=model,
        max_tokens=int(os.getenv("LLM_MAX_TOKENS", "2048")),
        temperature=float(os.getenv("LLM_TEMPERATURE", "0.7")),
        timeout=int(os.getenv("LLM_TIMEOUT", "120")),  # Higher timeout for local
        max_retries=int(os.getenv("LLM_MAX_RETRIES", "3")),
        cache_enabled=os.getenv("LLM_CACHE_ENABLED", "true").lower() == "true",
        cache_ttl=int(os.getenv("LLM_CACHE_TTL", "3600")),
        rate_limit_requests=int(os.getenv("LLM_RATE_LIMIT_REQUESTS", "60")),
        rate_limit_period=int(os.getenv("LLM_RATE_LIMIT_PERIOD", "60")),
    )


def load_dotenv() -> None:
    """Load .env file if it exists."""
    try:
        from dotenv import load_dotenv as _load_dotenv

        _load_dotenv()
    except ImportError:
        pass
