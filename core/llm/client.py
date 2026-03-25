"""
LLM Client with retry logic
"""

import time
import logging
from typing import Dict, Any, Optional
from chronos.core.llm.models import LLMConfig, ThreatAnalysis, LLMMetrics
from chronos.core.llm.adapters.registry import get_adapter
from chronos.core.llm.parsers import ResponseParser
from chronos.core.llm.prompts import PromptBuilder
from chronos.core.llm.utils.rate_limiter import RateLimiter
from chronos.core.llm.utils.cache import LRUCache, generate_cache_key

logger = logging.getLogger(__name__)


class RetryHandler:
    """Handle retry logic with exponential backoff."""

    def __init__(
        self, max_retries: int = 3, base_delay: float = 1.0, max_delay: float = 30.0
    ):
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.max_delay = max_delay

    def execute(self, func, *args, **kwargs):
        """Execute function with retry logic."""
        last_exception = None

        for attempt in range(self.max_retries):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                last_exception = e
                if attempt < self.max_retries - 1:
                    delay = min(self.base_delay * (2**attempt), self.max_delay)
                    logger.warning(
                        f"Attempt {attempt + 1} failed: {e}. Retrying in {delay}s..."
                    )
                    time.sleep(delay)
                else:
                    logger.error(f"All {self.max_retries} attempts failed")

        raise last_exception


NO_API_KEY_PROVIDERS = {"ollama", "lmstudio", "lm"}


class LLMClient:
    """LLM Client with caching, rate limiting, and retry logic."""

    def __init__(self, config: Optional[LLMConfig] = None):
        self.config = config
        # Local providers don't need API key
        self.enabled = config is not None and (
            bool(config.api_key) or config.provider.lower() in NO_API_KEY_PROVIDERS
        )
        self.metrics = LLMMetrics()
        self.cache = LRUCache(max_size=1000, default_ttl=3600)
        self.rate_limiter = RateLimiter(max_calls=60, period=60)
        self.retry_handler = RetryHandler(
            max_retries=config.max_retries if config else 3,
            base_delay=2.0,
            max_delay=30.0,
        )
        self.adapter = None
        self.parser = ResponseParser()

        if self.enabled:
            try:
                self.adapter = get_adapter(config.provider)
            except Exception as e:
                logger.error(f"Failed to initialize LLM adapter: {e}")
                self.enabled = False

    def analyze_threat(self, alert_data: Dict[str, Any]) -> ThreatAnalysis:
        """Analyze an alert with caching."""
        if not self.enabled:
            raise RuntimeError(
                "LLM not configured. Please configure API key and provider in settings."
            )

        cache_key = generate_cache_key(alert_data)
        cached = self.cache.get(cache_key)
        if cached:
            self.metrics.record_request(success=True, response_time=0, cached=True)
            logger.debug("Returning cached analysis")
            return ThreatAnalysis.from_dict(cached)

        try:
            return self._analyze_with_retry(alert_data, cache_key)
        except Exception as e:
            logger.error(f"LLM analysis failed: {e}")
            raise RuntimeError(f"LLM analysis failed: {str(e)}")

    def _analyze_with_retry(
        self, alert_data: Dict[str, Any], cache_key: str
    ) -> ThreatAnalysis:
        """Analyze with retry and rate limiting."""
        start_time = time.time()

        if not self.rate_limiter.can_call():
            wait_time = self.rate_limiter.time_until_next_slot()
            logger.warning(f"Rate limit reached. Waiting {wait_time:.1f}s")
            time.sleep(wait_time)

        prompt = PromptBuilder.build_analysis_prompt(alert_data)

        def make_call():
            self.rate_limiter.add_call()
            config_dict = {
                "api_key": self.config.api_key,
                "api_url": self.config.api_url,
                "model": self.config.model,
                "max_tokens": self.config.max_tokens,
                "temperature": self.config.temperature,
                "timeout": self.config.timeout,
            }
            return self.adapter.call(prompt, config_dict)

        response = self.retry_handler.execute(make_call)
        response_time = time.time() - start_time

        analysis = self.parser.parse_response(response)
        self.cache.set(cache_key, analysis.to_dict())
        self.metrics.record_request(success=True, response_time=response_time)

        return analysis

    def _mock_analysis(self, alert_data: Dict[str, Any]) -> ThreatAnalysis:
        """Return mock analysis when LLM is not configured."""
        severity = alert_data.get("severity", "medium")

        return ThreatAnalysis(
            threat_type=f"Threat detected: {alert_data.get('technique', 'Unknown')}",
            confidence=0.65,
            description=f"Analysis of {alert_data.get('title', 'alert')}: {alert_data.get('description', 'No description')}",
            mitre_tactics=self._infer_tactics(alert_data),
            mitre_techniques=[alert_data.get("technique", "T0000")],
            severity=severity,
            recommendations=[
                "Review alert details",
                "Check related logs",
                "Consider isolating affected host",
            ],
        )

    def _infer_tactics(self, alert_data: Dict[str, Any]) -> list:
        """Infer MITRE tactics from alert data."""
        technique = str(alert_data.get("technique", "")).lower()

        if "login" in technique or "auth" in technique:
            return ["initial-access", "credential-access"]
        elif "lateral" in technique or "smb" in technique:
            return ["lateral-movement"]
        elif "c2" in technique or "beacon" in technique:
            return ["command-and-control"]
        elif "exfil" in technique:
            return ["exfiltration"]
        return ["initial-access"]

    def get_stats(self) -> Dict[str, Any]:
        """Get LLM client statistics."""
        return {
            "enabled": self.enabled,
            "provider": self.config.provider if self.config else None,
            "model": self.config.model if self.config else None,
            "cache_stats": self.cache.stats(),
            "metrics": self.metrics.to_dict(),
        }
