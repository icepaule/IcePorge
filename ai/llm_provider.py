#!/usr/bin/env python3
"""
IcePorge LLM Provider Abstraction
Supports: Ollama (on-premise), AWS Bedrock
"""

import os
import json
import logging
from abc import ABC, abstractmethod
from typing import Optional

logger = logging.getLogger(__name__)


class LLMProvider(ABC):
    """Abstract base class for LLM providers."""

    @abstractmethod
    def analyze(self, prompt: str, context: str = "") -> str:
        """Analyze content using LLM."""
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Check if provider is available."""
        pass


class OllamaProvider(LLMProvider):
    """Ollama LLM provider (on-premise via WireGuard)."""

    def __init__(self, api_url: str, model: str = "llama3.1:8b", timeout: int = 120):
        self.api_url = api_url.rstrip('/')
        self.model = model
        self.timeout = timeout

    def analyze(self, prompt: str, context: str = "") -> str:
        import requests

        full_prompt = f"{context}\n\n{prompt}" if context else prompt

        try:
            response = requests.post(
                f"{self.api_url}/api/generate",
                json={
                    "model": self.model,
                    "prompt": full_prompt,
                    "stream": False
                },
                timeout=self.timeout
            )
            response.raise_for_status()
            return response.json().get("response", "")
        except Exception as e:
            logger.error(f"Ollama error: {e}")
            raise

    def is_available(self) -> bool:
        import requests
        try:
            response = requests.get(f"{self.api_url}/api/tags", timeout=5)
            return response.status_code == 200
        except:
            return False


class BedrockProvider(LLMProvider):
    """AWS Bedrock LLM provider."""

    def __init__(self, region: str, model_id: str, max_tokens: int = 4096):
        self.region = region
        self.model_id = model_id
        self.max_tokens = max_tokens
        self._client = None

    @property
    def client(self):
        if self._client is None:
            import boto3
            from botocore.config import Config as BotocoreConfig
            self._client = boto3.client(
                'bedrock-runtime',
                region_name=self.region,
                config=BotocoreConfig(
                    read_timeout=300,
                    connect_timeout=10,
                    retries={'max_attempts': 2},
                ),
            )
        return self._client

    def analyze(self, prompt: str, context: str = "") -> str:
        full_prompt = f"{context}\n\n{prompt}" if context else prompt

        # Claude model format (auch eu./us. cross-region inference prefix)
        if "anthropic.claude" in self.model_id or "anthropic/claude" in self.model_id:
            body = {
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": self.max_tokens,
                "messages": [
                    {"role": "user", "content": full_prompt}
                ]
            }
        else:
            body = {
                "prompt": full_prompt,
                "max_tokens": self.max_tokens
            }

        try:
            response = self.client.invoke_model(
                modelId=self.model_id,
                body=json.dumps(body),
                contentType="application/json",
                accept="application/json"
            )

            response_body = json.loads(response['body'].read())

            if "anthropic.claude" in self.model_id or "anthropic/claude" in self.model_id:
                text = response_body.get("content", [{}])[0].get("text", "")
                stop_reason = response_body.get("stop_reason", "")
                if stop_reason == "max_tokens":
                    text += "\n\n---\n*[Analyse wurde durch Token-Limit abgeschnitten — für vollständige Ausgabe max_tokens erhöhen]*"
                return text
            else:
                return response_body.get("completion", response_body.get("generated_text", ""))

        except Exception as e:
            logger.error(f"Bedrock error: {e}")
            raise

    def is_available(self) -> bool:
        try:
            # Simple connectivity check
            self.client.list_foundation_models(maxResults=1)
            return True
        except:
            return False


class LLMProviderFactory:
    """Factory to create and manage LLM providers."""

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._providers = {}
            cls._instance._primary = None
        return cls._instance

    def register_ollama(self, api_url: str, model: str = "llama3.1:8b",
                        timeout: int = 120, primary: bool = False):
        """Register Ollama provider."""
        provider = OllamaProvider(api_url, model, timeout)
        self._providers['ollama'] = provider
        if primary or self._primary is None:
            self._primary = 'ollama'
        logger.info(f"Registered Ollama provider: {api_url}")

    def register_bedrock(self, region: str, model_id: str,
                         max_tokens: int = 4096, primary: bool = False):
        """Register AWS Bedrock provider."""
        provider = BedrockProvider(region, model_id, max_tokens)
        self._providers['bedrock'] = provider
        if primary or self._primary is None:
            self._primary = 'bedrock'
        logger.info(f"Registered Bedrock provider: {model_id}")

    def get_provider(self, name: Optional[str] = None) -> LLMProvider:
        """Get a specific or primary provider."""
        if name:
            return self._providers.get(name)
        return self._providers.get(self._primary)

    def analyze(self, prompt: str, context: str = "",
                provider: Optional[str] = None) -> str:
        """Analyze using specified or primary provider with fallback."""
        providers_to_try = []

        if provider:
            providers_to_try.append(provider)

        if self._primary and self._primary not in providers_to_try:
            providers_to_try.append(self._primary)

        for name in self._providers:
            if name not in providers_to_try:
                providers_to_try.append(name)

        for name in providers_to_try:
            p = self._providers.get(name)
            if p and p.is_available():
                try:
                    logger.info(f"Using {name} provider for analysis")
                    return p.analyze(prompt, context)
                except Exception as e:
                    logger.warning(f"{name} failed: {e}, trying next...")

        raise RuntimeError("No LLM provider available")


# Convenience function
def get_llm() -> LLMProviderFactory:
    """Get the LLM provider factory instance."""
    return LLMProviderFactory()


if __name__ == "__main__":
    # Test
    factory = get_llm()

    # Example registration (use environment variables in production)
    ollama_url = os.getenv("OLLAMA_API_URL", "http://10.10.0.210:11434")
    factory.register_ollama(ollama_url, primary=True)

    if os.getenv("AWS_REGION"):
        factory.register_bedrock(
            os.getenv("AWS_REGION"),
            os.getenv("BEDROCK_MODEL_ID", "anthropic.claude-3-sonnet-20240229-v1:0")
        )

    print(f"Ollama available: {factory.get_provider('ollama').is_available()}")
