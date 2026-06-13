"""
Test suite for llm_enricher.py
Tests the enrich_findings function with mocked API calls
"""

import sys
import json
from unittest.mock import Mock, patch, MagicMock
import pytest

# Add backend to path
sys.path.insert(0, '../backend')

from llm_enricher import enrich_findings, CACHE


class TestLLMEnricher:
    """Test cases for LLM enricher module"""
    
    def setup_method(self):
        """Clear cache before each test"""
        CACHE.clear()
    
    @patch('llm_enricher.client')
    def test_enrich_findings_basic(self, mock_client):
        """Test basic enrichment with valid findings"""
        # Mock response
        mock_response = MagicMock()
        mock_response.choices[0].message.content = json.dumps({
            "risk_explanation": "RSA is vulnerable to quantum attacks. Migration is urgent.",
            "migration_recommendation": "Use ML-KEM (Kyber) as replacement.",
            "nist_standard": "ML-KEM",
            "urgency": "high"
        })
        mock_client.chat.completions.create.return_value = mock_response
        
        # Test input
        findings = [
            {"algorithm": "RSA", "classification": "asymmetric"},
            {"algorithm": "RSA", "classification": "asymmetric"}
        ]
        
        result = enrich_findings(findings)
        
        # Assertions
        assert "RSA" in result
        assert result["RSA"]["urgency"] == "high"
        assert "ML-KEM" in result["RSA"]["nist_standard"]
        assert mock_client.chat.completions.create.call_count == 1  # Should only call once
    
    @patch('llm_enricher.client')
    def test_enrich_findings_multiple_algorithms(self, mock_client):
        """Test enrichment with multiple different algorithms"""
        mock_response1 = MagicMock()
        mock_response1.choices[0].message.content = json.dumps({
            "risk_explanation": "Test RSA",
            "migration_recommendation": "Use ML-KEM",
            "nist_standard": "ML-KEM",
            "urgency": "high"
        })
        
        mock_response2 = MagicMock()
        mock_response2.choices[0].message.content = json.dumps({
            "risk_explanation": "Test SHA1",
            "migration_recommendation": "Use SHA-256",
            "nist_standard": "SHA-256",
            "urgency": "critical"
        })
        
        mock_client.chat.completions.create.side_effect = [mock_response1, mock_response2]
        
        findings = [
            {"algorithm": "RSA", "classification": "asymmetric"},
            {"algorithm": "SHA1", "classification": "hash"}
        ]
        
        result = enrich_findings(findings)
        
        assert "RSA" in result
        assert "SHA1" in result
        assert result["RSA"]["urgency"] == "high"
        assert result["SHA1"]["urgency"] == "critical"
        assert mock_client.chat.completions.create.call_count == 2
    
    @patch('llm_enricher.client')
    def test_enrich_findings_with_markdown(self, mock_client):
        """Test that markdown formatting is stripped from API response"""
        mock_response = MagicMock()
        # Simulate API response with markdown code blocks
        mock_response.choices[0].message.content = "```json\n" + json.dumps({
            "risk_explanation": "Test",
            "migration_recommendation": "Test recommendation",
            "nist_standard": "Test standard",
            "urgency": "medium"
        }) + "\n```"
        mock_client.chat.completions.create.return_value = mock_response
        
        findings = [{"algorithm": "ECC", "classification": "asymmetric"}]
        
        result = enrich_findings(findings)
        
        assert "ECC" in result
        assert result["ECC"]["urgency"] == "medium"
    
    @patch('llm_enricher.client')
    def test_enrich_findings_api_error(self, mock_client):
        """Test fallback when API call fails"""
        mock_client.chat.completions.create.side_effect = Exception("API Error")
        
        findings = [{"algorithm": "RSA", "classification": "asymmetric"}]
        
        result = enrich_findings(findings)
        
        # Should return fallback values
        assert "RSA" in result
        assert result["RSA"]["risk_explanation"] == "Analysis unavailable."
        assert result["RSA"]["urgency"] == "high"
    
    @patch('llm_enricher.client')
    def test_cache_functionality(self, mock_client):
        """Test that caching prevents redundant API calls"""
        mock_response = MagicMock()
        mock_response.choices[0].message.content = json.dumps({
            "risk_explanation": "Cached result",
            "migration_recommendation": "Use new algo",
            "nist_standard": "NewAlgo",
            "urgency": "high"
        })
        mock_client.chat.completions.create.return_value = mock_response
        
        # First call
        findings1 = [{"algorithm": "AES", "classification": "symmetric"}]
        result1 = enrich_findings(findings1)
        
        # Second call with same algorithm
        findings2 = [{"algorithm": "AES", "classification": "symmetric"}]
        result2 = enrich_findings(findings2)
        
        # Should use cache on second call
        assert mock_client.chat.completions.create.call_count == 1
        assert result1["AES"] == result2["AES"]
    
    def test_enrich_findings_empty_findings(self):
        """Test with empty findings list"""
        result = enrich_findings([])
        assert result == {}
    
    def test_enrich_findings_missing_algorithm(self):
        """Test with findings missing algorithm field"""
        findings = [
            {"classification": "symmetric"},  # Missing algorithm
            {"algorithm": "AES", "classification": "symmetric"}
        ]
        
        result = enrich_findings(findings)
        
        # Should only include findings with algorithm
        assert "AES" not in result  # AES won't be enriched without mocking
    
    @patch('llm_enricher.client')
    def test_enrich_findings_invalid_json_response(self, mock_client):
        """Test handling of invalid JSON from API"""
        mock_response = MagicMock()
        mock_response.choices[0].message.content = "Not valid JSON"
        mock_client.chat.completions.create.return_value = mock_response
        
        findings = [{"algorithm": "RSA", "classification": "asymmetric"}]
        
        result = enrich_findings(findings)
        
        # Should use fallback
        assert "RSA" in result
        assert result["RSA"]["risk_explanation"] == "Analysis unavailable."


if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v", "--tb=short"])
