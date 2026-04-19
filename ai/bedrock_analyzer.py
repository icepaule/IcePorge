#!/usr/bin/env python3
"""
IcePorge AWS Bedrock Analyzer
Malware and Phishing Analysis using AWS Bedrock Claude Models

Usage:
    from bedrock_analyzer import BedrockAnalyzer
    analyzer = BedrockAnalyzer()
    result = analyzer.analyze_phishing_email(email_content, headers)
"""

import os
import json
import logging
from typing import Optional, Dict, Any
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class AnalysisResult:
    """Structured analysis result."""
    verdict: str  # malicious, suspicious, clean
    confidence: float  # 0.0 - 1.0
    score: int  # 0-100
    summary: str
    indicators: list
    recommendations: list
    raw_response: str


class BedrockAnalyzer:
    """AWS Bedrock-based malware/phishing analyzer."""

    PHISHING_PROMPT = """You are a cybersecurity expert specializing in phishing email analysis.
Analyze the following email and provide a structured assessment.

Email Headers:
{headers}

Email Content:
{content}

Provide your analysis in the following JSON format:
{{
    "verdict": "malicious|suspicious|clean",
    "confidence": 0.0-1.0,
    "score": 0-100,
    "summary": "Brief summary of findings",
    "indicators": [
        {{"type": "indicator_type", "value": "indicator_value", "severity": "high|medium|low"}}
    ],
    "brand_impersonation": "detected brand name or null",
    "recommendations": ["list of security recommendations"],
    "technical_details": {{
        "sender_analysis": "analysis of sender legitimacy",
        "link_analysis": "analysis of URLs in email",
        "attachment_analysis": "analysis of attachments",
        "header_anomalies": "suspicious header patterns"
    }}
}}

Focus on:
1. Sender legitimacy (SPF, DKIM, DMARC results)
2. Brand impersonation attempts
3. Malicious URLs or domains
4. Social engineering tactics
5. Urgency/pressure language
6. Technical indicators (IP geolocation, mail routing anomalies)
"""

    MALWARE_PROMPT = """You are a malware reverse engineer analyzing suspicious code.
Analyze the following and provide a structured assessment.

File Information:
{file_info}

Code/Strings:
{content}

Provide your analysis in the following JSON format:
{{
    "verdict": "malicious|suspicious|clean",
    "confidence": 0.0-1.0,
    "malware_family": "identified family or unknown",
    "capabilities": ["list of malware capabilities"],
    "iocs": [
        {{"type": "domain|ip|hash|mutex|registry", "value": "indicator_value"}}
    ],
    "techniques": [
        {{"mitre_id": "T1xxx", "name": "technique name", "description": "how it's used"}}
    ],
    "summary": "Brief summary of findings",
    "recommendations": ["containment and remediation steps"]
}}
"""

    def __init__(
        self,
        region: str = None,
        model_id: str = None,
        max_tokens: int = 4096
    ):
        """Initialize Bedrock analyzer.

        Args:
            region: AWS region (default: from env or eu-central-1)
            model_id: Bedrock model ID (default: Claude 3 Sonnet)
            max_tokens: Maximum response tokens
        """
        self.region = region or os.getenv('AWS_REGION', 'eu-central-1')
        self.model_id = model_id or os.getenv(
            'BEDROCK_MODEL_ID',
            'anthropic.claude-3-sonnet-20240229-v1:0'
        )
        self.max_tokens = max_tokens
        self._client = None

    @property
    def client(self):
        """Lazy-load Bedrock client."""
        if self._client is None:
            try:
                import boto3
                self._client = boto3.client(
                    'bedrock-runtime',
                    region_name=self.region
                )
                logger.info(f"Bedrock client initialized for {self.region}")
            except Exception as e:
                logger.error(f"Failed to initialize Bedrock client: {e}")
                raise
        return self._client

    def _invoke_model(self, prompt: str) -> str:
        """Invoke Bedrock model with prompt."""
        body = {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": self.max_tokens,
            "messages": [
                {"role": "user", "content": prompt}
            ]
        }

        try:
            response = self.client.invoke_model(
                modelId=self.model_id,
                body=json.dumps(body),
                contentType="application/json",
                accept="application/json"
            )

            response_body = json.loads(response['body'].read())
            return response_body.get("content", [{}])[0].get("text", "")

        except Exception as e:
            logger.error(f"Bedrock invocation failed: {e}")
            raise

    def analyze_phishing_email(
        self,
        content: str,
        headers: Dict[str, str] = None
    ) -> AnalysisResult:
        """Analyze email for phishing indicators.

        Args:
            content: Email body content
            headers: Email headers dict

        Returns:
            AnalysisResult with verdict and details
        """
        headers_str = ""
        if headers:
            headers_str = "\n".join(f"{k}: {v}" for k, v in headers.items())

        prompt = self.PHISHING_PROMPT.format(
            headers=headers_str or "Not provided",
            content=content[:10000]  # Limit content size
        )

        raw_response = self._invoke_model(prompt)

        # Parse JSON from response
        try:
            # Find JSON in response
            json_start = raw_response.find('{')
            json_end = raw_response.rfind('}') + 1
            if json_start >= 0 and json_end > json_start:
                data = json.loads(raw_response[json_start:json_end])
            else:
                data = {}
        except json.JSONDecodeError:
            logger.warning("Failed to parse JSON response")
            data = {}

        return AnalysisResult(
            verdict=data.get('verdict', 'unknown'),
            confidence=float(data.get('confidence', 0.5)),
            score=int(data.get('score', 50)),
            summary=data.get('summary', raw_response[:500]),
            indicators=data.get('indicators', []),
            recommendations=data.get('recommendations', []),
            raw_response=raw_response
        )

    def analyze_malware(
        self,
        content: str,
        file_info: Dict[str, Any] = None
    ) -> AnalysisResult:
        """Analyze code/strings for malware indicators.

        Args:
            content: Code or extracted strings
            file_info: File metadata (name, size, type, hashes)

        Returns:
            AnalysisResult with verdict and details
        """
        file_info_str = ""
        if file_info:
            file_info_str = json.dumps(file_info, indent=2)

        prompt = self.MALWARE_PROMPT.format(
            file_info=file_info_str or "Not provided",
            content=content[:15000]  # Limit content size
        )

        raw_response = self._invoke_model(prompt)

        # Parse JSON from response
        try:
            json_start = raw_response.find('{')
            json_end = raw_response.rfind('}') + 1
            if json_start >= 0 and json_end > json_start:
                data = json.loads(raw_response[json_start:json_end])
            else:
                data = {}
        except json.JSONDecodeError:
            logger.warning("Failed to parse JSON response")
            data = {}

        return AnalysisResult(
            verdict=data.get('verdict', 'unknown'),
            confidence=float(data.get('confidence', 0.5)),
            score=int(data.get('score', 50)),
            summary=data.get('summary', raw_response[:500]),
            indicators=data.get('iocs', []),
            recommendations=data.get('recommendations', []),
            raw_response=raw_response
        )

    def is_available(self) -> bool:
        """Check if Bedrock is accessible."""
        try:
            import boto3
            client = boto3.client('bedrock', region_name=self.region)
            client.list_foundation_models(maxResults=1)
            return True
        except Exception as e:
            logger.debug(f"Bedrock not available: {e}")
            return False


# Convenience functions
def analyze_email(content: str, headers: dict = None) -> AnalysisResult:
    """Quick email analysis."""
    return BedrockAnalyzer().analyze_phishing_email(content, headers)


def analyze_file(content: str, file_info: dict = None) -> AnalysisResult:
    """Quick file/malware analysis."""
    return BedrockAnalyzer().analyze_malware(content, file_info)


if __name__ == "__main__":
    # Test
    logging.basicConfig(level=logging.INFO)

    analyzer = BedrockAnalyzer()

    if analyzer.is_available():
        print("Bedrock is available")

        # Test phishing analysis
        test_email = """
        Subject: URGENT: Your account will be suspended

        Dear Customer,

        We detected suspicious activity on your account. Click here immediately
        to verify your identity: http://secure-bank-login.suspicious-domain.com/verify

        If you don't act within 24 hours, your account will be permanently closed.

        Best regards,
        Security Team
        """

        result = analyzer.analyze_phishing_email(test_email)
        print(f"Verdict: {result.verdict}")
        print(f"Score: {result.score}")
        print(f"Summary: {result.summary}")
    else:
        print("Bedrock not available - check AWS credentials and region")
