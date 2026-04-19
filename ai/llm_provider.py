#!/usr/bin/env python3
"""
IcePorge LLM Provider Abstraction
Supports: Ollama (on-premise), AWS Bedrock

Usage:
    from llm_provider import get_llm

    llm = get_llm()
    llm.register_ollama("http://10.10.0.210:11434", primary=True)
    llm.register_bedrock("eu-central-1", "anthropic.claude-3-sonnet-20240229-v1:0")

    result = llm.analyze("Analyze this malware sample", context="...")
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
            self._client = boto3.client(
                'bedrock-runtime',
                region_name=self.region
            )
        return self._client

    def analyze(self, prompt: str, context: str = "") -> str:
        full_prompt = f"{context}\n\n{prompt}" if context else prompt

        # Claude model format
        if "anthropic.claude" in self.model_id:
            body = {
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": self.max_tokens,
                "messages": [
                    {"role": "user", "content": full_prompt}
                ]
            }
        else:
            # Generic format for other models
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

            # Extract response based on model type
            if "anthropic.claude" in self.model_id:
                return response_body.get("content", [{}])[0].get("text", "")
            else:
                return response_body.get("completion", response_body.get("generated_text", ""))

        except Exception as e:
            logger.error(f"Bedrock error: {e}")
            raise

    def is_available(self) -> bool:
        try:
            import boto3
            client = boto3.client('bedrock', region_name=self.region)
            client.list_foundation_models(maxResults=1)
            return True
        except:
            return False


class LLMProviderFactory:
    """Factory to create and manage LLM providers with fallback."""

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
        """Analyze using specified or primary provider with automatic fallback."""
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

    def list_providers(self) -> dict:
        """List all registered providers and their status."""
        return {
            name: {
                "available": p.is_available(),
                "primary": name == self._primary
            }
            for name, p in self._providers.items()
        }


# Convenience function
def get_llm() -> LLMProviderFactory:
    """Get the LLM provider factory singleton."""
    return LLMProviderFactory()


def init_from_env():
    """Initialize providers from environment variables."""
    factory = get_llm()

    # Ollama
    ollama_url = os.getenv("OLLAMA_API_URL")
    if ollama_url:
        factory.register_ollama(
            ollama_url,
            model=os.getenv("OLLAMA_MODEL", "llama3.1:8b"),
            timeout=int(os.getenv("OLLAMA_TIMEOUT", "120")),
            primary=os.getenv("AI_BACKEND", "ollama") in ["ollama", "both"]
        )

    # Bedrock
    aws_region = os.getenv("AWS_REGION")
    bedrock_model = os.getenv("BEDROCK_MODEL_ID")
    if aws_region and bedrock_model:
        factory.register_bedrock(
            aws_region,
            bedrock_model,
            max_tokens=int(os.getenv("BEDROCK_MAX_TOKENS", "4096")),
            primary=os.getenv("AI_BACKEND") == "bedrock"
        )

    return factory


if __name__ == "__main__":
    # Test
    logging.basicConfig(level=logging.INFO)

    factory = init_from_env()

    print("Registered providers:")
    for name, status in factory.list_providers().items():
        print(f"  {name}: available={status['available']}, primary={status['primary']}")
