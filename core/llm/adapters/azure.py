"""
Azure OpenAI Adapter
"""

import logging
import requests
from typing import Dict, Any
from chronos.core.llm.adapters.base import BaseLLMAdapter

logger = logging.getLogger(__name__)


class AzureOpenAIAdapter(BaseLLMAdapter):
    """Azure OpenAI API adapter."""

    def validate_config(self, config: Dict[str, Any]) -> bool:
        """Validate Azure configuration."""
        required = ["api_key", "api_url", "model", "api_version"]
        return all(config.get(k) for k in required)

    def call(self, prompt: str, config: Dict[str, Any]) -> str:
        """Make an API call to Azure OpenAI."""
        headers = {"api-key": config["api_key"], "Content-Type": "application/json"}

        payload = {
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": config.get("max_tokens", 2048),
            "temperature": config.get("temperature", 0.7),
        }

        api_version = config.get("api_version", "2024-02-01")
        url = f"{config['api_url'].rstrip('/')}/openai/deployments/{config['model']}/chat/completions?api-version={api_version}"

        response = requests.post(
            url, headers=headers, json=payload, timeout=config.get("timeout", 30)
        )

        if response.status_code == 200:
            return response.json()["choices"][0]["message"]["content"]
        elif response.status_code == 429:
            raise Exception("Rate limit exceeded")
        elif response.status_code == 401:
            raise Exception("Invalid API key")
        else:
            raise Exception(
                f"Azure OpenAI API error: {response.status_code} - {response.text}"
            )
