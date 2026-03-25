"""
Base adapter interface for LLM providers
"""

from abc import ABC, abstractmethod
from typing import Dict, Any


class BaseLLMAdapter(ABC):
    """Abstract base class for LLM adapters."""

    @abstractmethod
    def call(self, prompt: str, config: Dict[str, Any]) -> str:
        """Make an API call to the LLM provider."""
        pass

    @abstractmethod
    def validate_config(self, config: Dict[str, Any]) -> bool:
        """Validate the adapter configuration."""
        pass
