"""
Ollama Adapter for local models
"""

import logging
import requests
from typing import Dict, Any
from chronos.core.llm.adapters.base import BaseLLMAdapter

logger = logging.getLogger(__name__)


class OllamaAdapter(BaseLLMAdapter):
    """Ollama API adapter for local LLM models."""

    def validate_config(self, config: Dict[str, Any]) -> bool:
        """Validate Ollama configuration."""
        required = ["api_url", "model"]
        return all(config.get(k) for k in required)

    def call(self, prompt: str, config: Dict[str, Any]) -> str:
        """Make an API call to Ollama."""
        headers = {"Content-Type": "application/json"}

        payload = {
            "model": config["model"],
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": config.get("temperature", 0.7),
                "num_predict": config.get("max_tokens", 2048),
            },
        }

        url = f"{config['api_url'].rstrip('/')}/api/generate"

        response = requests.post(
            url, headers=headers, json=payload, timeout=config.get("timeout", 120)
        )

        if response.status_code == 200:
            return response.json()["response"]
        else:
            raise Exception(
                f"Ollama API error: {response.status_code} - {response.text}"
            )

    def list_models(self, config: Dict[str, Any]) -> list:
        """List available Ollama models."""
        url = f"{config['api_url'].rstrip('/')}/api/tags"
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                return [m["name"] for m in response.json().get("models", [])]
        except Exception as e:
            logger.error(f"Failed to list Ollama models: {e}")
        return []
