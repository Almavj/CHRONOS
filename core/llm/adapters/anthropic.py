"""
Anthropic Adapter
"""

import logging
import requests
from typing import Dict, Any
from chronos.core.llm.adapters.base import BaseLLMAdapter

logger = logging.getLogger(__name__)


class AnthropicAdapter(BaseLLMAdapter):
    """Anthropic API adapter for Claude models."""

    API_VERSION = "2023-06-01"

    def validate_config(self, config: Dict[str, Any]) -> bool:
        """Validate Anthropic configuration."""
        required = ["api_key", "model"]
        return all(config.get(k) for k in required)

    def call(self, prompt: str, config: Dict[str, Any]) -> str:
        """Make an API call to Anthropic."""
        headers = {
            "x-api-key": config["api_key"],
            "anthropic-version": self.API_VERSION,
            "Content-Type": "application/json",
        }

        payload = {
            "model": config["model"],
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": config.get("max_tokens", 2048),
            "temperature": config.get("temperature", 0.7),
        }

        url = f"https://api.anthropic.com/v1/messages"

        response = requests.post(
            url, headers=headers, json=payload, timeout=config.get("timeout", 30)
        )

        if response.status_code == 200:
            data = response.json()
            return data["content"][0]["text"]
        elif response.status_code == 429:
            raise Exception("Rate limit exceeded")
        elif response.status_code == 401:
            raise Exception("Invalid API key")
        else:
            raise Exception(
                f"Anthropic API error: {response.status_code} - {response.text}"
            )
