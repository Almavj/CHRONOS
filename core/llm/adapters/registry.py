"""
Adapter registry and factory
"""

from typing import Dict, Type
from chronos.core.llm.adapters.base import BaseLLMAdapter
from chronos.core.llm.adapters.openai import OpenAIAdapter
from chronos.core.llm.adapters.anthropic import AnthropicAdapter
from chronos.core.llm.adapters.azure import AzureOpenAIAdapter
from chronos.core.llm.adapters.ollama import OllamaAdapter
from chronos.core.llm.adapters.deepseek import DeepSeekAdapter


ADAPTER_REGISTRY: Dict[str, Type[BaseLLMAdapter]] = {
    "openai": OpenAIAdapter,
    "anthropic": AnthropicAdapter,
    "azure": AzureOpenAIAdapter,
    "ollama": OllamaAdapter,
    "deepseek": DeepSeekAdapter,
}


def get_adapter(provider: str) -> BaseLLMAdapter:
    """Get adapter instance for provider."""
    adapter_class = ADAPTER_REGISTRY.get(provider.lower())
    if not adapter_class:
        raise ValueError(f"Unsupported LLM provider: {provider}")
    return adapter_class()


def register_adapter(provider: str, adapter_class: Type[BaseLLMAdapter]) -> None:
    """Register a new adapter."""
    ADAPTER_REGISTRY[provider.lower()] = adapter_class


def list_providers() -> list:
    """List available providers."""
    return list(ADAPTER_REGISTRY.keys())
